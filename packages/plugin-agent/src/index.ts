/**
 * @dsh-ops/plugin-agent —— gestion du corps des Agents (plan §5).
 *
 * Basé sur le socle resource-core : la table d'attributs schema + la machine à états du cycle de vie + le graphe de dépendances sont tous réutilisés,
 * ce plugin ne déclare que le schema propre aux Agents et la logique de supervision opérationnelle.
 * Enregistrer = gouverner : la création d'un Agent émet un ID unique et un identifiant machine (authn, incluant usage.write,
 * l'Agent peut auto-déclarer la mesure de sa consommation en direct) ; la mise en ligne passe par l'approbation L4, la mise hors ligne entraîne la révocation des identifiants, la notification des utilisateurs liés, la conservation des données d'audit.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { createHash } from 'node:crypto'
import {
  PlatformEvents, newId,
  type Collection, type RecordBase, type ResourceTypeSpec,
} from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { AppRegistryService, type AppRegistryServiceSsoCaller } from '../../plugin-app/src/index.ts'
import { OidcService } from '../../plugin-authn/src/oidc.ts'
import { PermissionCatalog } from '../../plugin-iam/src/index.ts'
import * as agentTools from './tools.ts'
import { AGENT_TYPE_SPEC } from './schema.ts'
import { buildAgentOnboardingPrompt, type AgentOnboardingCredential } from './onboarding.ts'

// ---------------------------------------------------------------------------
// Modèle de données (enregistrements d'extension propres aux Agents)
// ---------------------------------------------------------------------------

export interface AgentBindingRecord extends RecordBase {
  agentId: string
  userId: string
  userName: string
  boundAt: string
  boundBy: string
}

export interface AgentUsageRecord extends RecordBase {
  agentId: string
  date: string
  sessions: number
  calls: number
  okCalls: number
  tokens: number
  totalLatencyMs: number
  /** Dimension source : nombre d'appels consolidés par réinjection usage.recorded (passerelle de modèles etc., données sans latence) ; calls inclut cette part. */
  gwCalls?: number
  /** Nombre d'utilisateurs actifs journaliers (sémantique de déclaration : maximum sur plusieurs remontées du même jour ; la consolidation passerelle ne produit pas ce champ). */
  dau?: number
  /** Statistique dédupliquée des utilisateurs en conversation (le côté déclaration transmet userIds, la plateforme hache et anonymise immédiatement, union sur le même jour ; jamais en clair). */
  userHashes?: string[]
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class AgentRegistryService extends Service {
  static readonly provide = 'agentRegistry'

  private usageCounter = new Map<string, number[]>()

  constructor(ctx: Context) {
    super(ctx, 'agentRegistry')
    ctx.resourceCore.registerType(AGENT_TYPE_SPEC)

    // Supervision des appels : la passerelle MCP consolide automatiquement les métriques d'exécution quand un Agent est le sujet de l'appel
    ctx.platformBus.on(PlatformEvents.McpInvoked, (payload) => {
      const p = payload as { callerType: string; callerId: string; ok: boolean; tokens: number; latencyMs: number }
      if (p.callerType !== 'agent') return
      this.recordUsage(p.callerId, { calls: 1, okCalls: p.ok ? 1 : 0, tokens: p.tokens, latencyMs: p.latencyMs }, 'mcp')
      // Supervision comportementale : détection de pic de fréquence (fenêtre de 10 minutes dépassant 120 appels)
      const nowMs = Date.now()
      const times = (this.usageCounter.get(p.callerId) ?? []).filter((t) => nowMs - t < 10 * 60_000)
      times.push(nowMs)
      this.usageCounter.set(p.callerId, times)
      if (times.length === 120) {
        const agent = ctx.resourceCore.collection('agent').get(p.callerId)
        ctx.audit.fire({
          severity: 'warning',
          title: t('Agent「{name}」调用频次突增', { name: agent?.name ?? p.callerId }),
          message: t('10 分钟内调用 {count} 次，超过异常阈值 120，请检查是否存在死循环或滥用。', { count: times.length }),
          resourceType: 'agent',
          resourceId: p.callerId,
        })
      }
    })

    // Complément du périmètre de statistiques d'appels : abonnement à usage.recorded pour réinjecter les appels non MCP comme ceux de la passerelle de modèles (McpInvoked ne couvre que la passerelle MCP).
    // Règles anti-double-compte (trois, il en manque une = double compte/compte sale) :
    //   1. n'admettre que les événements subject=agent:<id> avec Agent existant — les données historiques seed et les sujets orphelins ne comptent pas ;
    //   2. resource mcp:* toujours sauté — la passerelle MCP émet en double McpInvoked pour le même appel (le listener ci-dessus l'a déjà compté),
    //      l'auto-déclaration de mesure signalant à tort mcp:* est sautée pareillement (la passerelle l'a compté, mieux vaut manquer que dupliquer) ;
    //   3. meters contenant les clés d'observation downloads/installs → sauté — le téléchargement/l'installation de Skill sont des événements de cycle de vie, pas des appels.
    // Idempotence de consommation : via le niveau de consommation usage.consume (INSERT OR IGNORE), replay/reprise de lettres mortes ne réinjecte pas en double ;
    // Obligation de projection : tous les consommateurs doivent projeter (usage.reconcile compare en intégralité, l'absence de projection déclenche l'alerte « réconciliation déséquilibrée »).
    ctx.usage.consume('agent-registry', (event) => {
      ctx.usage.project('agent-registry', event)
      if (!event.subject.startsWith('agent:')) return
      const agentId = event.subject.slice('agent:'.length)
      if (!ctx.resourceCore.collection('agent').get(agentId)) return
      if (event.resource.startsWith('mcp:')) return
      if (event.meters.some((meter) => meter.key === 'downloads' || meter.key === 'installs')) return
      // La passerelle ne mesure qu'après un retour en succès : les événements réinjectés comptent comme appels réussis ; l'absence de données de latence ne dilue pas la moyenne (voir metrics)
      const tokens = event.meters
        .filter((meter) => meter.key === 'input_tokens' || meter.key === 'output_tokens' || meter.key === 'tokens')
        .reduce((sum, meter) => sum + meter.value, 0)
      this.recordUsage(agentId, { calls: 1, okCalls: 1, tokens, latencyMs: 0 }, 'gateway')
    })

    // Dépréciation d'un Skill → notification des responsables des Agents qui le référencent (alerte sur références existantes)
    ctx.platformBus.on(PlatformEvents.SkillDeprecated, (payload) => {
      const p = payload as { skillId: string; name: string }
      for (const record of ctx.resourceCore.dependencies().find((item) => item.kind === 'skill' && item.toId === p.skillId)) {
        const agent = ctx.resourceCore.collection('agent').get(record.fromId)
        if (!agent) continue
        ctx.audit.fire({
          severity: 'info',
          title: t('Agent「{name}」引用的 Skill 已弃用', { name: agent.name }),
          message: t('Skill「{name}」已弃用，请尽快迁移至替代版本，避免下次构建失败。', { name: p.name }),
          resourceType: 'agent',
          resourceId: agent.id,
        })
      }
    })
  }

  bindings(): Collection<AgentBindingRecord> {
    return this.ctx.opsStorage.collection<AgentBindingRecord>('agent:bindings')
  }

  usage(): Collection<AgentUsageRecord> {
    return this.ctx.opsStorage.collection<AgentUsageRecord>('agent:usage')
  }

  // -- Source de vérité unique du catalogue de modèles (issue #8) -------------------------------------
  // attrs.model ne maintient plus d'énumération statique : valeurs possibles = catalogue de la passerelle de modèles (modelgw:models).
  // Enregistrement / PATCH (quand model est fourni) / porte de mise en ligne : trois endroits valident en fail-fast « présent dans le catalogue » ;
  // le statut online du canal et la disponibilité de l'endpoint sont des faits d'exécution, appliqués avec autorité par modelgw invoke
  // (une déconnexion après mise en ligne n'est pas interceptable par les portes de la phase de configuration).

  /** slugs du catalogue de modèles (null si modelgw n'est pas assemblé — validation sautée, comportement legacy conservé).
   *  Sous injection stricte cordis, l'accès direct à ctx.modelGateway lève dur via le get trap « without inject »,
   *  il faut passer par une lecture douce ctx.reflect.get (même périmètre que le softRead dsh-bridge d'exec_claim). */
  private modelCatalogSlugs(): string[] | null {
    try {
      const ctxAny = this.ctx as unknown as { reflect?: { get?: (key: string, optional?: boolean) => unknown } }
      const gateway = (typeof ctxAny.reflect?.get === 'function'
        ? ctxAny.reflect.get('modelGateway', true)
        : (this.ctx as unknown as Record<string, unknown>)['modelGateway']) as
        { models?: () => { all(): Array<{ slug: string }> } } | undefined
      const all = gateway?.models?.().all()
      if (!Array.isArray(all)) return null
      return all.map((item) => item.slug)
    } catch {
      return null
    }
  }

  /** Valide que attrs.model existe dans le catalogue de modèles (sans vérifier le statut online) ; sinon lève une erreur en français listant les slugs disponibles.
   *  Catalogue vide = passage (exemption de période d'amorçage) : sur un déploiement neuf où aucun modèle n'est enregistré, l'enregistrement d'Agent ne doit pas être verrouillé —
   *  dès que le catalogue contient au moins une entrée (devenant la surface réellement optionnelle), tout slug non enregistré est refusé. Absence de modelgw (assemblage anormal) : saut pareillement. */
  assertModelInCatalog(model: unknown): void {
    const slug = String(model ?? '').trim()
    if (!slug) return
    const slugs = this.modelCatalogSlugs()
    if (slugs === null || slugs.length === 0) return
    if (!slugs.includes(slug)) {
      throw new Error(t('底层模型「{slug}」不在模型目录：请先在模型网关登记（当前可用：{values}）', { slug, values: slugs.join(' / ') }))
    }
  }

  // -- Enregistrement -------------------------------------------------------------

  /**
   * Organigramme R7 : validation de cycles de la ligne de reporting (appelée quand create/update touche managerId, garantit que l'organisation est une forêt enracinée).
   * managerId vide → passe directement (hors ligne de reporting) ; pointant vers soi-même → lève (« la ligne de reporting ne peut pas pointer vers soi ») ;
   * pointant vers un Agent inexistant → lève ; remontée le long de managerId (plafond de 100 pas), retour à soi-même → lève (« cycle dans la ligne de reporting »).
   */
  assertOrgChartAcyclic(agentId: string, managerId: string | undefined): void {
    const manager = String(managerId ?? '').trim()
    if (!manager) return
    if (manager === agentId) throw new Error(t('汇报线不得指向自己'))
    const collection = this.ctx.resourceCore.collection('agent')
    let current = manager
    for (let steps = 0; steps < 100; steps++) {
      if (current === agentId) throw new Error(t('汇报线成环：沿汇报上级回溯会回到该 Agent，请修正 managerId'))
      const node = collection.get(current)
      if (!node) throw new Error(t('汇报上级 Agent 不存在：{id}', { id: current }))
      const next = String(node.attrs['managerId'] ?? '').trim()
      if (!next) return // remontée jusqu'au sommet (pas de cycle sur la chaîne)
      current = next
    }
    // Filet du plafond de pas : les données de cycles préexistants sans soi-même ou les chaînes trop profondes sont tronquées ici, refus pareillement
    throw new Error(t('汇报线成环（或层级超过 100 级）：请修正 managerId'))
  }

  register(input: {
    name: string
    slug?: string
    attrs?: Record<string, unknown>
    ownerId: string
    ownerName: string
    orgId: string
    withCredential?: boolean
  }): { agent: import('../../platform-core/src/index.ts').RecordBase & Record<string, unknown>; credential?: { principalId: string; clientId: string; clientSecret: string } } {
    const attrs = {
      ownerName: input.ownerName,
      ...(input.attrs ?? {}),
    }
    this.assertModelInCatalog(attrs['model'])
    const agent = this.ctx.resourceCore.create('agent', { ...input, attrs })
    // R7 organigramme : validation de cycles de managerId. L'id est généré en interne par create, impossible de s'auto-référencer avant création, d'où validation après création,
    // échec = rollback immédiat (à cet instant, aucun identifiant émis ni événement d'enregistrement émis ; la suppression de la collection suffit à un rollback propre).
    if (String(attrs['managerId'] ?? '').trim()) {
      try {
        this.assertOrgChartAcyclic(agent.id, String(attrs['managerId']))
      } catch (error) {
        this.ctx.resourceCore.collection('agent').remove(agent.id)
        throw error
      }
    }
    let credential
    if (input.withCredential !== false) {
      // usage.write : quand l'Agent contourne la passerelle plateforme pour se connecter en direct à des ressources externes, il doit auto-déclarer sa mesure (POST /api/usage/record)
      credential = this.ctx.authn.createMachineCredential({
        name: `agent:${(agent as any).slug}`,
        refType: 'agent',
        refId: agent.id,
      // connector.invoke : point de permission d'appel autonome au même niveau que mcp.invoke (intégration open-connector)
      // agent.write : après enregistrement, l'Agent met à jour lui-même ses informations déclarées avec son propre identifiant (PATCH /api/agents/:id)
      // modelgw.invoke : appel de la passerelle de modèles (le LLM est le premier consommable de l'Agent ; la mesure réinjecte ce registre via usage.recorded)
      // exec.read/exec.write : outils exec_* du centre d'exécution (réveils heartbeat R10/tirage de tâches ; entrées de catalogue complétées au démarrage par apply())
      // agent.a2a.invoke : appels de collaboration A2A (confier un travail entre employés/poursuite/annulation). scope du jeton OBO = humain ∩ cet identifiant,
      //   l'absence de ce point sur l'identifiant empêchait « un humain d'initier une collaboration en tant que représentant » (E-2/Q-6), d'où son inclusion dans le périmètre par défaut.
      scopes: ['mcp.invoke', 'skill.read', 'agent.read', 'agent.write', 'agent.a2a.invoke', 'usage.write', 'connector.invoke', 'modelgw.invoke', 'exec.read', 'exec.write'],
      })
    }
    this.ctx.platformBus.emit(PlatformEvents.AgentRegistered, {
      id: agent.id, name: agent.name, slug: agent.slug, actor: input.ownerId, type: 'agent',
    })
    return { agent, credential }
  }

  machinePrincipal(agentId: string) {
    return this.ctx.authn.principals().findOne((item) => item.refType === 'agent' && item.refId === agentId)
  }

  /**
   * Génère le prompt d'intégration de l'Agent (même gabarit qu'à l'enregistrement, source de vérité unique côté plateforme, isomorphe à app) :
   * rotate=true renouvelle le secret de l'identifiant machine (l'ancienne valeur est invalidée immédiatement) et le renvoie avec le prompt ; rotate=false n'inclut que client_id.
   */
  buildOnboardingPrompt(agentId: string, origin: string, opts: { rotate?: boolean } = {}): {
    agentName: string
    prompt: string
    credential: AgentOnboardingCredential
    rotated: boolean
  } {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    const principal = this.machinePrincipal(agentId)
    if (!principal) throw new Error(t('Agent 机器凭证不存在（可能已被禁用或删除），无法生成接入提示词'))
    let credential: AgentOnboardingCredential
    let rotated = false
    if (opts.rotate) {
      const next = this.ctx.authn.rotateMachineCredential(principal.id)
      credential = { clientId: next.principal.clientId, clientSecret: next.clientSecret }
      rotated = true
    } else {
      credential = { clientId: principal.clientId }
    }
    return { agentName: agent.name, prompt: buildAgentOnboardingPrompt(agent, credential, origin), credential, rotated }
  }

  /** Liaison utilisateurs : enregistre « quels utilisateurs peuvent utiliser cet Agent », chaque usage trace l'autorisation. */
  bindUser(agentId: string, userId: string, actor: string): AgentBindingRecord {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    const user = this.ctx.iam.users().get(userId)
    if (!user) throw new Error(t('用户不存在：{id}', { id: userId }))
    if (this.bindings().findOne((item) => item.agentId === agentId && item.userId === userId)) {
      throw new Error(t('{name} 已绑定该 Agent', { name: user.displayName }))
    }
    return this.bindings().insert({
      id: newId('agb'),
      agentId,
      userId,
      userName: user.displayName,
      boundAt: new Date().toISOString(),
      boundBy: actor,
    })
  }

  unbindUser(agentId: string, userId: string): boolean {
    const binding = this.bindings().findOne((item) => item.agentId === agentId && item.userId === userId)
    if (!binding) return false
    return this.bindings().remove(binding.id)
  }

  boundUsers(agentId: string): AgentBindingRecord[] {
    return this.bindings().find((item) => item.agentId === agentId)
  }

  /** on-behalf-of : quand un utilisateur agit via un Agent, émission d'un jeton de transmission d'identité. */
  issueOnBehalfOfToken(agentId: string, verifiedUser: import('../../plugin-authn/src/index.ts').VerifiedPrincipal): { token: string; actChain: unknown[] } {
    const principal = this.machinePrincipal(agentId)
    if (!principal) throw new Error(t('该 Agent 尚未注册机器身份，请先在注册时勾选颁发凭证'))
    const { token, record } = this.ctx.authn.issueOnBehalfOf(verifiedUser, principal.id)
    return { token, actChain: record.actChain }
  }

  // -- Client SSO (branchement Agent ↔ source d'identité plateforme ; auto-émission par le owner, dev-plan-agent-host-unification M2) --

  /**
   * Mode de la porte de mise en ligne (AGENT_SSO_ENFORCE) :
   *   '1' (défaut) = refus d'examen sans gouvernance — exige un client OIDC associé, une entryUrl de canal sans login enregistrée, ou une déclaration headless (pur backend, identifiant machine déjà émis obligatoire) ;
   *   'oidc'    = émission d'un client OIDC associé obligatoire (le plus strict, la déclaration headless ne s'applique pas) ;
   *   '0'       = porte désactivée (déconseillé hors développement).
   */
  static ssoEnforceMode(): '1' | 'oidc' | '0' {
    const raw = String(process.env.AGENT_SSO_ENFORCE ?? '1').trim().toLowerCase()
    if (raw === 'oidc') return 'oidc'
    if (raw === '0' || raw === '' || raw === 'false' || raw === 'off') return '0'
    return '1'
  }

  /**
   * Autorisation owner-based (alignée côté app) + exception d'auto-service en boucle locale machine : périmètre unifié dans AppRegistryService.ssoManageDecision
   * (human = owner / authn.oidc.write ; une machine liée à cet Agent peut s'auto-servir, mais l'ensemble de callbacks doit être intégralement en boucle locale).
   * La couche de routes console appelle déjà la même garde et renvoie 403 ; cette couche service est le filet anti-contournement.
   */
  assertSsoManage(
    agent: { id: string; name: string; ownerId: string },
    caller: AppRegistryServiceSsoCaller,
    effective?: { redirectUris: string[]; postLogoutUris: string[] },
    op: 'create' | 'update' | 'rotate' | 'enable' | 'disable' = 'update',
  ): void {
    const decision = AppRegistryService.ssoManageDecision(agent, caller, effective ?? { redirectUris: [], postLogoutUris: [] }, op)
    if (!decision.allowed) throw new Error(decision.reason)
  }

  activeSsoClient(agentId: string) {
    return this.ctx.oidc.clientsForAgent(agentId).find((client) => OidcService.isClientActive(client))
  }

  /** Émet le client OIDC associé à l'Agent (name=nom de l'Agent, refType='agent'/refId renseigné en retour) ; le secret n'est renvoyé qu'une fois. */
  createSsoClient(agentId: string, input: {
    redirectUris: string[]
    clientType?: 'confidential' | 'public'
    consentRequired?: boolean
    postLogoutUris?: string[]
    description?: string
  }): { client: ReturnType<OidcService['clientsForAgent']>[number]; clientSecret: string } {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    AppRegistryService.assertRedirectUris(input.redirectUris)
    const existing = this.ctx.oidc.clientsForAgent(agentId)
    if (existing.length > 0) throw new Error(t('该 Agent 已签发 SSO 客户端（{clientId}），请直接管理或先禁用后重新签发', { clientId: existing[0]!.clientId }))
    const created = this.ctx.oidc.createClient({
      name: agent.name,
      redirectUris: input.redirectUris,
      ...(input.clientType !== undefined ? { clientType: input.clientType } : {}),
      ...(input.consentRequired !== undefined ? { consentRequired: input.consentRequired } : {}),
      ...(input.postLogoutUris !== undefined ? { postLogoutUris: input.postLogoutUris } : {}),
      ...(input.description !== undefined ? { description: input.description } : {}),
      refType: 'agent',
      refId: agentId,
    })
    return created
  }

  updateSsoClient(agentId: string, patch: { redirectUris?: string[]; description?: string; consentRequired?: boolean; postLogoutUris?: string[] }) {
    if (patch.redirectUris !== undefined) AppRegistryService.assertRedirectUris(patch.redirectUris)
    return this.ctx.oidc.updateClient(this.requireSsoClient(agentId).id, patch)
  }

  rotateSsoSecret(agentId: string) {
    return this.ctx.oidc.rotateSecret(this.requireSsoClient(agentId).id)
  }

  disableSsoClient(agentId: string, reason: string) {
    return this.ctx.oidc.disableClient(this.requireSsoClient(agentId).id, reason)
  }

  enableSsoClient(agentId: string) {
    return this.ctx.oidc.enableClient(this.requireSsoClient(agentId).id)
  }

  private requireSsoClient(agentId: string) {
    const clients = this.ctx.oidc.clientsForAgent(agentId)
    if (clients.length === 0) throw new Error(t('该 Agent 尚未签发 SSO 客户端'))
    return clients[0]!
  }

  // -- Cycle de vie (flux d'approbation L4)----------------------------------------------

  /**
   * Contrôle de la porte SSO (gouvernance d'identité avant mise en ligne) : renvoie le clientId du client active (pour l'instantané du dossier d'approbation), lève en indiquant la voie en cas d'infraction.
   * Double revérification au point d'entrée (dépôt de dossier requestOnline) et au point d'exécution (exécuteur d'approbation), alignée sur la sémantique de porte côté app.
   */
  assertOnlineGate(agent: { id: string; name: string; attrs: Record<string, unknown> }): string | undefined {
    const mode = AgentRegistryService.ssoEnforceMode()
    if (mode === '0') return this.activeSsoClient(agent.id)?.clientId
    const active = this.activeSsoClient(agent.id)
    if (active) return active.clientId
    if (mode === 'oidc') {
      throw new Error(t('上线门禁：Agent 上线前必须完成身份纳管——请在「Agent 本体 → 详情 → SSO 配置」签发 OIDC 客户端（当前 AGENT_SSO_ENFORCE=oidc）'))
    }
    const entryUrl = String(agent.attrs['entryUrl'] ?? '').trim()
    if (entryUrl) return undefined
    // Troisième canal de gouvernance headless : les corps d'exécution purement backend comme Work Body n'ont aucune interface (aucune entryUrl à enregistrer),
    // ni besoin de callbacks navigateur (pas de flux de code d'autorisation OIDC) — après déclaration explicite, passage autorisé sur la foi de l'identifiant machine déjà émis.
    // L'identifiant est l'ancre d'identité : autoriser une déclaration headless sans identifiant équivaut à une mise en ligne sans sujet, d'où le blocage conjoint.
    if (agent.attrs['headless'] === true) {
      if (!this.machinePrincipal(agent.id)) {
        throw new Error(t('上线门禁：headless（无交互界面）声明要求 Agent 已颁发机器身份凭证（当前未颁发）——请先颁发凭证再重试'))
      }
      return undefined
    }
    throw new Error(t('上线门禁：Agent 上线前必须完成身份纳管——签发 OIDC 客户端、登记交互界面地址 entryUrl（免登通道），或声明无交互界面（headless，纯后台执行）后重试'))
  }

  requestOnline(agentId: string, requester: { id: string; name: string }) {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    const errors = this.ctx.resourceCore.validateAttrs('agent', agent.attrs, 'online')
    if (errors.length > 0) throw new Error(t('上线条件不满足：{errors}', { errors: errors.join('；') }))
    // Porte de mise en ligne : le modèle sous-jacent doit être un slug enregistré dans le catalogue de modèles (issue #8 — « mise en ligne réussie, erreur modèle inexistant à la distribution » interceptée ici)
    this.assertModelInCatalog(agent.attrs['model'])
    const ssoClientId = this.assertOnlineGate(agent)
    return this.ctx.audit.createApproval({
      kind: 'agent.online',
      // WP-10/L1 : les opérations L4 à haut risque sont uniformément à haut risque — validation exige une double confirmation, l'approbation inscrit la marque de revue finale au niveau entreprise
      riskLevel: 'high',
      title: t('Agent 上线：{name}', { name: agent.name }),
      payload: { agentId, requesterId: requester.id, ...(ssoClientId ? { ssoClientId } : {}) },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  requestOffline(agentId: string, requester: { id: string; name: string }, reason: string) {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    if (!reason?.trim()) throw new Error(t('下线必须填写原因（护栏要求）'))
    // REL-02 : pré-contrôle de l'état avant l'ouverture du dossier (garde d'entrée dans le style du validateAttrs de requestOnline, périmètre lu directement sur la machine à états du cycle de vie) :
    // seuls les états où la machine autorise la transition vers offline (trial/online) peuvent ouvrir un dossier d'approbation de mise hors ligne, sinon l'exécuteur échouerait après approbation,
    // et la révocation des identifiants ne se déclencherait pas (dossier L4 blanc). La revérification de transition en exécution est conservée (double filet inchangé).
    const canOffline = this.ctx.resourceCore.availableTransitions('agent', agentId).some((item) => item.action === 'offline')
    if (!canOffline) {
      const stateLabel = this.ctx.resourceCore.stateLabel('agent', agent.status).label
      throw new Error(t('当前状态「{state}」不允许申请「下线」审批：仅试运行/已上线的 Agent 可开下线审批单（REL-02 预检）', { state: stateLabel }))
    }
    const impact = this.ctx.resourceCore.impact('agent', agentId)
    return this.ctx.audit.createApproval({
      kind: 'agent.offline',
      // WP-10/L1 : les opérations L4 à haut risque sont uniformément à haut risque — validation exige une double confirmation, l'approbation inscrit la marque de revue finale au niveau entreprise
      riskLevel: 'high',
      title: t('Agent 下线：{name}', { name: agent.name }),
      payload: { agentId, reason, impact: impact.map((item) => `${item.name}（${item.type}）`) },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  online(agentId: string, actor: string) {
    const result = this.ctx.resourceCore.transition('agent', agentId, 'online', actor)
    this.ctx.platformBus.emit(PlatformEvents.AgentOnlined, { id: agentId, name: result.entity.name, actor, type: 'agent', slug: result.entity.slug })
    return result.entity
  }

  offline(agentId: string, actor: string, reason: string) {
    const result = this.ctx.resourceCore.transition('agent', agentId, 'offline', actor, reason)
    this.ctx.platformBus.emit(PlatformEvents.AgentOfflined, { id: agentId, name: result.entity.name, actor, reason, type: 'agent', slug: result.entity.slug })
    // Liaison de mise hors ligne : révocation des identifiants machine (exécutée par l'écoute d'événements authn), notification des utilisateurs liés
    const principal = this.machinePrincipal(agentId)
    if (principal) this.ctx.authn.disablePrincipal(principal.id, 'Agent 下线联动')
    for (const binding of this.boundUsers(agentId)) {
      this.ctx.audit.fire({
        severity: 'info',
        title: t('你绑定的 Agent「{name}」已下线', { name: result.entity.name }),
        message: t('绑定关系保留，恢复上线后可继续使用。原因：{reason}', { reason }),
        resourceType: 'agent',
        resourceId: agentId,
      })
      void binding
    }
    return result.entity
  }

  archive(agentId: string, actor: string) {
    return this.ctx.resourceCore.transition('agent', agentId, 'archive', actor).entity
  }

  trial(agentId: string, actor: string, groups: string[]) {
    void groups
    return this.ctx.resourceCore.transition('agent', agentId, 'submit_trial', actor).entity
  }

  /** Nettoyage des liens après suppression : liaisons utilisateurs, arêtes de dépendance et identifiants machine (désactiver = révoquer tous les jetons) ; enregistrements d'usage et données d'audit conservés. */
  purge(agentId: string): void {
    for (const binding of this.bindings().find((item) => item.agentId === agentId)) this.bindings().remove(binding.id)
    for (const record of this.ctx.resourceCore.dependencies().find((item) => item.fromId === agentId || item.toId === agentId)) {
      this.ctx.resourceCore.dependencies().remove(record.id)
    }
    const principal = this.machinePrincipal(agentId)
    if (principal && principal.status === 'active') this.ctx.authn.disablePrincipal(principal.id, 'Agent 删除联动')
  }

  // -- Gel (R10 : liaison budget du centre d'exécution)---------------------------------------

  /** Requête de l'état de gel : attrs.frozenAt non vide = gelé (critère partagé par l'entrée d'ordonnancement du centre d'exécution et la liaison budget). */
  isFrozen(agentId: string): boolean {
    return Boolean(this.ctx.resourceCore.collection('agent').get(agentId)?.attrs['frozenAt'])
  }

  /**
   * Gèle un Agent (liaison dépassement de budget) : état soft au niveau attrs — ni le cycle de vie ni les identifiants ne sont touchés ;
   * pose frozenAt/frozenReason, inscrit l'audit, diffuse agent.frozen, et crée un dossier d'approbation à haut risque agent.unfreeze
   * (canal de dégel humain), renvoie l'id du dossier. Protection idempotente : lève si déjà gelé (un gel répété signale souvent un déclenchement en double de la liaison,
   * il faut échouer explicitement plutôt qu'écraser silencieusement le motif de gel existant).
   * Note : frozenAt/frozenReason ne figurent pas dans la table des champs du schema (pas d'édition par formulaire console), d'où l'écriture directe dans la collection —
   * resourceCore.update ne fusionne que les champs du schema, mais sur la base de l'attrs entier, les PATCH suivants conservent ces deux clés d'état soft.
   */
  freezeAgent(agentId: string, reason: string, actor?: string): string {
    const collection = this.ctx.resourceCore.collection('agent')
    const agent = collection.get(agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    if (agent.attrs['frozenAt']) {
      const frozenReason = agent.attrs['frozenReason'] !== undefined ? String(agent.attrs['frozenReason']) : t('原因未登记')
      throw new Error(t('Agent「{name}」已冻结（{reason}），请走解冻审批单解冻', { name: agent.name, reason: frozenReason }))
    }
    collection.update(agentId, { attrs: { ...agent.attrs, frozenAt: new Date().toISOString(), frozenReason: reason } })
    this.ctx.audit.record({
      type: 'change', actorType: 'system', actorId: actor ?? 'exec-hub', actorName: '执行中枢（预算联动）',
      action: 'agent.frozen', resourceType: 'agent', resourceId: agentId, resourceName: agent.name,
      result: 'ok', detail: reason,
    })
    // Le nom d'événement est enregistré côté plateforme, émission directe par chaîne (même style que audit.authz.denied)
    this.ctx.platformBus.emit('agent.frozen', { agentId, reason, actor })
    const approval = this.ctx.audit.createApproval({
      kind: 'agent.unfreeze',
      title: t('Agent「{name}」预算超限冻结，申请解冻', { name: agent.name }),
      // La disjonction de budget est une action de gouvernance à haut risque ; le dégel suit pareillement le périmètre L4 à haut risque (approve exige une double confirmation)
      riskLevel: 'high',
      payload: { agentId, reason },
      requesterId: actor ?? 'exec-hub',
      requesterName: t('执行中枢（预算联动，系统发起）'),
    })
    return approval.id
  }

  /** Dégèle un Agent : vide frozenAt/frozenReason, inscrit l'audit et diffuse agent.unfrozen. */
  unfreezeAgent(agentId: string, by?: string): void {
    const collection = this.ctx.resourceCore.collection('agent')
    const agent = collection.get(agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    const frozenReason = String(agent.attrs['frozenReason'] ?? '')
    const restAttrs: Record<string, unknown> = { ...agent.attrs }
    delete restAttrs['frozenAt']
    delete restAttrs['frozenReason']
    collection.update(agentId, { attrs: restAttrs })
    this.ctx.audit.record({
      type: 'change', actorType: 'system', actorId: by ?? 'approval-center', actorName: '解冻审批',
      action: 'agent.unfreeze', resourceType: 'agent', resourceId: agentId, resourceName: agent.name,
      result: 'ok', detail: frozenReason ? `解除预算超限冻结（冻结原因：${frozenReason}）` : '解除冻结',
    })
    this.ctx.platformBus.emit('agent.unfrozen', { agentId, by })
  }

  // -- Supervision -------------------------------------------------------------

  /** Entrée de consolidation/réinjection : source=mcp (McpInvoked, avec latence) | gateway (réinjection usage.recorded, sans latence). */
  recordUsage(agentId: string, usage: { sessions?: number; calls: number; okCalls: number; tokens: number; latencyMs: number }, source: 'mcp' | 'gateway' = 'mcp'): void {
    const date = new Date().toISOString().slice(0, 10)
    const gwDelta = source === 'gateway' ? usage.calls : 0
    const existing = this.usage().findOne((item) => item.agentId === agentId && item.date === date)
    if (existing) {
      this.usage().update(existing.id, {
        sessions: existing.sessions + (usage.sessions ?? 0),
        calls: existing.calls + usage.calls,
        okCalls: existing.okCalls + usage.okCalls,
        tokens: existing.tokens + usage.tokens,
        totalLatencyMs: existing.totalLatencyMs + usage.latencyMs,
        gwCalls: (existing.gwCalls ?? 0) + gwDelta,
      })
    } else {
      this.usage().insert({
        id: newId('agu'),
        agentId,
        date,
        sessions: usage.sessions ?? 0,
        calls: usage.calls,
        okCalls: usage.okCalls,
        tokens: usage.tokens,
        totalLatencyMs: usage.latencyMs,
        gwCalls: gwDelta,
      })
    }
    if (usage.tokens > 0) {
      this.ctx.audit.addCost({
        date,
        agentId,
        llmTokens: usage.tokens,
        toolCalls: usage.calls,
        costYuan: Math.round(usage.tokens * 0.0000015 * 1000) / 1000,
      })
    }
  }

  /**
   * Auto-déclaration par l'Agent de ses métriques opérationnelles (REST /api/agents/:id/metrics-report, convergé par l'outil agent_metrics_report).
   * Obligation d'intégration (au même niveau que metrics-report des Applications IA) : alignement sémantique — dau du même jour = maximum, sessions cumulées,
   * ensemble dédupliqué d'utilisateurs = union ; userIds sont hachés et anonymisés côté plateforme avant stockage, jamais en clair ; date possible pour compléter l'historique (YYYY-MM-DD).
   */
  reportUsage(agentId: string, report: { dau?: number; sessions?: number; userIds?: string[]; uniqueUsers?: number; date?: string }): void {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    const date = report.date ?? new Date().toISOString().slice(0, 10)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(t('date 格式非法：{date}（应为 YYYY-MM-DD）', { date }))
    for (const [key, value] of [['dau', report.dau], ['sessions', report.sessions], ['uniqueUsers', report.uniqueUsers]] as const) {
      if (value !== undefined && (!Number.isInteger(value) || value < 0)) throw new Error(t('{key} 必须是非负整数（收到：{value}）', { key, value }))
    }
    const hashes = (report.userIds ?? []).map((id) => createHash('sha256').update(String(id)).digest('hex').slice(0, 16))
    if (report.uniqueUsers !== undefined && hashes.length > report.uniqueUsers) {
      throw new Error(t('userIds 数量（{count}）不应大于 uniqueUsers（{unique}）', { count: hashes.length, unique: report.uniqueUsers }))
    }
    const existing = this.usage().findOne((item) => item.agentId === agentId && item.date === date)
    let mergedSessions: number
    if (existing) {
      const merged = new Set([...(existing.userHashes ?? []), ...hashes])
      mergedSessions = existing.sessions + (report.sessions ?? 0)
      this.usage().update(existing.id, {
        dau: Math.max(existing.dau ?? 0, report.dau ?? 0, merged.size),
        sessions: mergedSessions,
        ...(merged.size > 0 ? { userHashes: [...merged] } : {}),
      })
    } else {
      mergedSessions = report.sessions ?? 0
      this.usage().insert({
        id: newId('agu'),
        agentId,
        date,
        sessions: mergedSessions,
        calls: 0,
        okCalls: 0,
        tokens: 0,
        totalLatencyMs: 0,
        dau: Math.max(report.dau ?? 0, hashes.length),
        ...(hashes.length > 0 ? { userHashes: hashes } : {}),
      })
    }
    // Comptabilisation de mesure R10 : après fusion en base, inscrit les sessions du jour dans la fenêtre de budget usage (ligne de ressource agent:<slug>)
    this.meterDailySessions(agent, date, mergedSessions)
  }

  /**
   * Comptabilisation de mesure R10 (spécifique metrics-report) : enregistre les « sessions du jour après fusion » comme événement usage,
   * pour faire apparaître une ligne agent:<slug> dans le byResource de /api/usage/summary et permettre à la liaison budget du centre d'exécution de disjoncter.
   * - Conclusion sur le comportement du livre de prix : sans règle correspondante, priceOf lève directement (ressource X sans règle de tarification), et la règle par défaut du préfixe agent:*
   *   a pour clé de tarification calls (périmètre de retour WP-07), différent des sessions d'ici — donc avant la première comptabilisation, on sème pour cet Agent une règle sessions à coût zéro
   *   selon « pattern exact prioritaire au préfixe » (complète seulement l'absence, n'écrase pas,
   *   pour ne pas annuler les retarifications opérationnelles des entrées exactes), garantissant que la déclaration n'échoue jamais faute de prix ;
   * - Idempotence : idempotency_key=agent-metrics:<agentId>:<date>, usage.record passe par insertOrIgnore,
   *   mais une même clé avec un contenu différent est refusée — on sonde donc d'abord l'événement de même clé ; un complément du même jour ne compte que le premier instantané (comptabilisations suivantes sautées) ;
   * - org manquant (org obligatoire sur l'événement usage) → comptabilisation sautée ; tout autre échec inattendu alerte sans bloquer le flux principal de déclaration
   *   (la mesure est un attribut d'observation, cohérent avec le précédent « l'échec de mesure ne bloque pas » de panel/skillhub).
   */
  private meterDailySessions(agent: { id: string; slug: string; orgId: string }, date: string, sessions: number): void {
    try {
      const idempotencyKey = `agent-metrics:${agent.id}:${date}`
      // Déjà comptabilisé le jour même (périmètre du premier instantané) : le registre local fusionne quand même, l'événement usage ne compte pas en double
      if (this.ctx.txnStore.one('usage_events', { idempotency_key: idempotencyKey })) return
      if (!agent.orgId) return // org obligatoire sur l'événement usage ; sans org, on renonce à comptabiliser (sans bloquer la déclaration)
      const pattern = `agent:${agent.slug}`
      if (!this.ctx.usage.priceBook().findOne((item) => item.pattern === pattern)) {
        this.ctx.usage.upsertPrice({
          pattern, meter_key: 'sessions',
          list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1,
          tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.10',
        })
      }
      this.ctx.usage.record({
        org: agent.orgId,
        subject: `agent:${agent.id}`,
        principal: `org:${agent.orgId}`,
        resource: pattern,
        meters: [{ key: 'sessions', value: sessions, unit: '次' }],
        idempotency_key: idempotencyKey,
      })
    } catch (error) {
      this.ctx.logger('agent').warn('metrics-report 用量入账失败（不阻塞提报主流程）', error)
    }
  }

  metrics(agentId: string): {
    sessions: number
    calls: number
    successRate: number
    tokens: number
    avgLatencyMs: number
    lastActiveAt: string
    dau: number
    uniqueUsers: number
    gwCalls: number
    series: Array<{ date: string; calls: number; tokens: number; sessions: number; dau: number }>
  } {
    const rows = this.usage().find((item) => item.agentId === agentId).sort((a, b) => a.date.localeCompare(b.date))
    const today = rows.at(-1)
    const calls = rows.reduce((sum, row) => sum + row.calls, 0)
    const okCalls = rows.reduce((sum, row) => sum + row.okCalls, 0)
    const tokens = rows.reduce((sum, row) => sum + row.tokens, 0)
    const latency = rows.reduce((sum, row) => sum + row.totalLatencyMs, 0)
    const gwCalls = rows.reduce((sum, row) => sum + (row.gwCalls ?? 0), 0)
    // Le dénominateur de la moyenne ne prend que les appels avec données de latence (périmètre passerelle MCP) : les événements réinjectés par la passerelle n'ont pas de latence, les diluer fausserait
    const latencyCalls = Math.max(calls - gwCalls, 0)
    return {
      sessions: rows.reduce((sum, row) => sum + row.sessions, 0),
      calls,
      successRate: calls === 0 ? 1 : Math.round((okCalls / calls) * 1000) / 1000,
      tokens,
      avgLatencyMs: latencyCalls === 0 ? 0 : Math.round(latency / latencyCalls),
      lastActiveAt: rows.at(-1)?.updatedAt ?? '',
      // Périmètre opérationnel (déclaration) : DAU du jour et nombre d'utilisateurs en conversation dédupliqué du jour
      dau: today?.dau ?? 0,
      uniqueUsers: today?.userHashes?.length ?? 0,
      gwCalls,
      series: rows.slice(-14).map((row) => ({ date: row.date, calls: row.calls, tokens: row.tokens, sessions: row.sessions, dau: row.dau ?? 0 })),
    }
  }

  overview(): { total: number; online: number; trial: number; draft: number; offline: number } {
    const agents = this.ctx.resourceCore.list('agent')
    return {
      total: agents.length,
      online: agents.filter((item) => item.status === 'online').length,
      trial: agents.filter((item) => item.status === 'trial').length,
      draft: agents.filter((item) => item.status === 'draft').length,
      offline: agents.filter((item) => ['offline', 'archived'].includes(item.status)).length,
    }
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    agentRegistry: AgentRegistryService
  }
}

export const name = 'agent'
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'authn', 'oidc', 'iam', 'audit', 'usage', 'httpServer']

export function apply(ctx: Context) {
  const registry = new AgentRegistryService(ctx)
  ctx.plugin(agentTools)
  // Garde REL-05 : le rotate=true d'onboarding-prompt invalide immédiatement l'ancien secret de l'identifiant machine et renvoie le nouveau en clair une seule
  // fois — même convergence de périmètre que obo-token du même plugin (QA A-07) : seul owner / utilisateur lié / administrateur plateforme ('*') peut renouveler ;
  // on autorise aussi l'auto-renouvellement par l'identifiant machine de l'Agent lui-même (même philosophie que ssoManage « une machine liée à cet Agent peut s'auto-servir », dont dépend
  // le flux d'intégration existant). Le handler de route est dans console (hors propriété de ce plugin), d'où une interception en point unique à la frontière HTTP par un middleware httpServer
  // dans ce plugin ; rotate=false (client_id seul) n'est pas affecté, l'échec de validation de jeton est traité en 401 unifié par le middleware d'authentification console.
  ctx.httpServer.use((exchange) => {
    if (exchange.method !== 'POST' || !/^\/api\/agents\/[^/]+\/onboarding-prompt$/.test(exchange.path)) return
    if ((exchange.body ?? {}).rotate !== true) return
    const agentId = exchange.path.split('/')[3]!
    const agent = ctx.resourceCore.get('agent', agentId)
    if (!agent) return // l'inexistence de l'Agent est signalée par le handler de route d'origine, ici sans interférence
    let verified: import('../../plugin-authn/src/index.ts').VerifiedPrincipal
    try {
      const header = String(exchange.headers['authorization'] ?? '')
      verified = ctx.authn.verify(header.startsWith('Bearer ') ? header.slice(7) : header)
    } catch {
      return
    }
    const userId = verified.principal.type === 'human' ? verified.principal.refId : undefined
    const isOwner = userId !== undefined && agent.ownerId === userId
    const isBound = userId !== undefined && registry.boundUsers(agentId).some((item) => item.userId === userId)
    const isAdmin = verified.scopes.includes('*')
    const isSelfMachine = verified.principal.type === 'machine'
      && verified.principal.refType === 'agent' && verified.principal.refId === agentId
    if (isOwner || isBound || isAdmin || isSelfMachine) return
    ctx.platformBus.emit('audit.authz.denied', {
      actorId: userId ?? verified.principal.id,
      actorName: verified.principal.name,
      point: `agent.onboarding-rotate(owner:${agentId})`,
      path: exchange.path,
    })
    exchange.fail(403, 'FORBIDDEN', t('仅 Agent 负责人、绑定用户或平台管理员可轮换「{name}」的机器凭证 secret（对齐 obo-token 守卫口径，REL-05）', { name: agent.name }))
    return true
  })
  // Décision du point de montage de la validation de cycles R7 : le PATCH /api/agents/:id de console appelle directement resourceCore.update('agent')
  // en contournant la couche service de ce plugin (resourceCore n'émet pas d'événement plateforme sur update, et les exceptions des listeners Collection.onChange
  // ne sont qu'avalées, incapables de faire échouer la requête), d'où la reprise de l'approche REL-05 ci-dessus — interception en point unique à la frontière HTTP par middleware :
  // seulement si l'attrs de ce PATCH contient managerId, on rejoue la validation de cycle selon la sémantique de fusion d'update() (ce champ prend la valeur soumise),
  // 400 en cas d'infraction ; les autres PATCH (sans managerId) passent tels quels, sans toucher au comportement existant.
  ctx.httpServer.use((exchange) => {
    if (exchange.method !== 'PATCH' || !/^\/api\/agents\/[^/]+$/.test(exchange.path)) return
    const patchAttrs = ((exchange.body ?? {}) as { attrs?: Record<string, unknown> }).attrs
    if (!patchAttrs || patchAttrs['managerId'] === undefined) return
    const agentId = exchange.path.split('/')[3]!
    if (!ctx.resourceCore.get('agent', agentId)) return // l'inexistence de l'Agent est signalée par le handler de route d'origine, ici sans interférence
    try {
      registry.assertOrgChartAcyclic(agentId, String(patchAttrs['managerId'] ?? ''))
    } catch (error) {
      exchange.fail(400, 'BAD_REQUEST', error instanceof Error ? error.message : String(error))
      return true
    }
  })
  // Exécuteur d'approbation L4 (l'instance est tenue par la fermeture, évite l'attente circulaire d'auto-injection du plugin)
  ctx.effect(() => ctx.audit.registerExecutor('agent.online', async (payload) => {
    // Revérification en exécution de la porte de mise en ligne : pendant l'examen du dossier, le client SSO peut être désactivé/entryUrl vidée —
    // on rejoue la porte complète, tout échec fait échouer l'exécution avec trace (aligné sur la sémantique de filet du point 2 côté app)
    const agent = ctx.resourceCore.get('agent', String(payload.agentId))
    if (agent) registry.assertOnlineGate(agent)
    return registry.online(String(payload.agentId), 'approval-center')
  }))
  ctx.effect(() => ctx.audit.registerExecutor('agent.offline', async (payload) => {
    return registry.offline(String(payload.agentId), 'approval-center', String(payload.reason ?? '审批通过下线'))
  }))
  // R10 : exécuteur d'approbation de dégel — une fois le dossier à haut risque agent.unfreeze validé, l'état de gel est levé (approve = dégel, approverId inscrit à l'audit)
  ctx.effect(() => ctx.audit.registerExecutor('agent.unfreeze', async (payload, approverId) => {
    registry.unfreezeAgent(String(payload.agentId ?? ''), approverId || 'approval-center')
    return { unfrozen: true }
  }))
  // R10 : complétion des points de permission du centre d'exécution — l'identifiant machine par défaut doit porter exec.read/exec.write, or le
  // createMachineCredential de plugin-authn valide les scopes contre la liste blanche du catalogue de permissions (anti-faute de frappe) ; l'absence de ces deux points ferait échouer l'enregistrement d'Agent
  // directement. Ce plugin ne peut modifier les fichiers d'iam, d'où au démarrage un complément idempotent de deux entrées vers le PermissionCatalog d'iam (autorité d'enregistrement RBAC à l'exécution,
  // même source que l'éditeur de rôles de la console) ; iam est chargé avant ce plugin, l'instance de tableau est la même.
  for (const entry of [
    { point: 'exec.read', label: '读取执行中枢待办与心跳', group: '执行中枢' },
    { point: 'exec.write', label: '执行中枢待办领取与回写', group: '执行中枢' },
  ]) {
    if (!PermissionCatalog.some((item) => item.point === entry.point)) PermissionCatalog.push(entry)
  }
  migrateAgentCredentialScopes(ctx)
  migrateAgentCredentialConnectorInvoke(ctx)
  migrateAgentCredentialAgentWrite(ctx)
  migrateAgentCredentialModelgwInvoke(ctx)
  migrateAgentCredentialExecScopes(ctx)
  migrateAgentCredentialA2aInvoke(ctx)
}

/** Migration unique : complète agent.a2a.invoke sur les identifiants machine des Agents existants (facette d'appel de collaboration OBO ; précédent agent-scopes-exec-rw-v1). */
function migrateAgentCredentialA2aInvoke(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-a2a-invoke-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('agent.a2a.invoke'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'agent.a2a.invoke'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.a2a-invoke-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 agent.a2a.invoke（OBO 令牌 scope=人类∩凭证；缺此点则人类无法代表员工发起 A2A 协作）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 agent.a2a.invoke`)
}

/** Migration unique : complète connector.invoke sur les identifiants machine des Agents existants (marque d'idempotence, précédent agent-scopes-usage-write-v1). */
function migrateAgentCredentialConnectorInvoke(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-connector-invoke-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('connector.invoke'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'connector.invoke'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.connector-invoke-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 connector.invoke（连接器纳管数据面对齐）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 connector.invoke`)
}

/** Migration unique : complète usage.write sur les identifiants machine des Agents existants (marque d'idempotence, évite d'écraser des scopes ajustés manuellement ensuite). */
function migrateAgentCredentialScopes(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-usage-write-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('usage.write'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'usage.write'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.scopes-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 usage.write（Agent 自推计量能力对齐）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 usage.write`)
}

/** Migration unique : complète agent.write sur les identifiants machine des Agents existants (mise à jour des informations déclarées avec son propre identifiant après enregistrement, précédent agent-scopes-usage-write-v1). */
function migrateAgentCredentialAgentWrite(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-agent-write-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('agent.write'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'agent.write'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.agent-write-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 agent.write（注册后自主提报更新能力对齐）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 agent.write`)
}

/** Migration unique : complète modelgw.invoke sur les identifiants machine des Agents existants (précédent agent-scopes-connector-invoke-v1). */
function migrateAgentCredentialModelgwInvoke(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-modelgw-invoke-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('modelgw.invoke'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'modelgw.invoke'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.modelgw-invoke-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 modelgw.invoke（模型网关调用 + usage.recorded 回灌口径补全）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 modelgw.invoke`)
}

/** Migration unique : complète exec.read/exec.write sur les identifiants machine des Agents existants (requis par les outils exec_* du centre d'exécution, précédent agent-scopes-modelgw-invoke-v1). */
function migrateAgentCredentialExecScopes(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-exec-rw-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active'
      && !(item.scopes.includes('exec.read') && item.scopes.includes('exec.write')),
  )) {
    // Complétion fusionnée des deux points (déduplication par Set : quand un seul manque, l'autre n'est pas ajouté en double)
    ctx.authn.principals().update(principal.id, { scopes: [...new Set([...principal.scopes, 'exec.read', 'exec.write'])] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.exec-rw-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 exec.read/exec.write（执行中枢 exec_* 工具所需）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 exec.read/exec.write`)
}
