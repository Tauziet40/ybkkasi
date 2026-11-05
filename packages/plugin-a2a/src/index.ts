/**
 * @dsh-ops/plugin-a2a —— plan de collaboration A2A (plan de collaboration intranet des employés numériques d'entreprise §5/§6).
 *
 * Boucle de collaboration complète, montée au-dessus du contract-c3 gelé v1 (appel nominatif direct + exposition des niveaux) :
 *   - génération/signature/publication de l'Agent Card (projection depuis l'ensemble d'autorisations, déclaration ≤ autorisation ; vérification JWS Ed25519) ;
 *   - découverte inter-runtimes (annuaire interne à la plateforme, comble l'absence 2 de contract-c3) ;
 *   - facette de méthodes JSON-RPC (message/send·stream, tasks/get·list·cancel, cycle de vie de Task à huit états) ;
 *   - cinq contrôles de gouvernance avant acceptation de la Task (point de permission/en ligne et couverture permit/plafond de confidentialité/quotas de budget/règles d'approbation) ;
 *   - moteur de stratégie de négociation A0-A3 (comble l'absence 3 ; l'arbitrage multi-parties de l'absence 4 est porté par flow-core) ;
 *   - inspection de cohérence déclaration-autorisation (gouvernance de la dérive des capacités) ; vue de performance de collaboration et boucle de recette des livrables.
 *
 * Discipline (plan de collaboration §11) :
 *   - avec plugin-uhp, uniquement via ctx.platformBus (a2a.task.dispatch / a2a.task.progress / a2a.task.cancel),
 *     interdiction de se connecter directement aux données du plugin voisin ;
 *   - compatibilité par défaut avec les Agents existants (sans champ a2aProfile, repli sur le comportement v1 d'appel nominatif) ;
 *   - les états d'interruption sont des signaux de gouvernance : input_required se poursuit par l'appelant avec le taskId ; auth_required passe obligatoirement par une clôture humaine au centre d'approbations,
 *     la reprise d'exécution utilise une clé d'idempotence anti-doublon (a2a:<agentId>:<principal>:<taskId>:a<attempt>) ;
 *   - la recette ne fait pas confiance à l'auto-déclaration : Task completed ≠ clôture métier ; les tâches critiques ne sont réputées acquittées qu'après la recette de livraison (humaine).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  newId,
  createRestGate,
  PlatformEvents,
  normalizeAssetCategory,
  type Collection,
  type HttpExchange,
  type RecordBase,
} from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { PermissionCatalog } from '../../plugin-iam/src/index.ts'
import type { VerifiedPrincipal } from '../../plugin-authn/src/index.ts'
import { DATA_CLASS_RANK, type DataClass } from '../../plugin-modelgw/src/index.ts'
import { nonbillableUsage } from '../../plugin-usage/src/index.ts'
import { generateEd25519KeyPair } from '../../platform-core/src/signature.ts'
import { createPublicKey } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { signAgentCard, type AgentCardBody, type AgentCardSkill, type SignedAgentCard } from './card.ts'
import {
  NEGOTIATION_MAX_ROUNDS,
  negotiateMode,
  normalizeAutonomy,
  parseNegotiationDecision,
  type Autonomy,
  type NegotiationMode,
} from './negotiate.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

export type A2aTaskState =
  | 'submitted' | 'working' | 'input_required' | 'auth_required'
  | 'completed' | 'failed' | 'canceled' | 'rejected'

export const A2A_TERMINAL_STATES: A2aTaskState[] = ['completed', 'failed', 'canceled', 'rejected']

export interface A2aArtifact {
  artifactId: string
  name: string
  mimeType: string
  kind: 'text' | 'file'
  content?: string
  sizeBytes: number
}

export interface A2aHistoryEntry {
  at: string
  from: 'caller' | 'target' | 'system'
  type: 'message' | 'status' | 'offer'
  text?: string
  state?: A2aTaskState
  note?: string
}

export interface A2aOffer {
  round: number
  from: 'caller' | 'target'
  proposal: unknown
  note?: string
  at: string
}

export interface A2aTaskRecord extends RecordBase {
  taskId: string
  contextId: string
  agentId: string
  agentSlug: string
  callerPrincipalId: string
  callerUserId?: string
  callerAgentId?: string
  callerSubject: string
  callerAutonomy: Autonomy
  targetAutonomy: Autonomy
  mode: NegotiationMode
  state: A2aTaskState
  stateReason: string
  message: string
  dataClass: DataClass
  negotiation?: { round: number; maxRounds: number; status: 'open' | 'accepted' | 'rejected' | 'expired'; offers: A2aOffer[] }
  artifacts: A2aArtifact[]
  history: A2aHistoryEntry[]
  responseId?: string
  attempts: number
  inputTokens?: number
  outputTokens?: number
  model?: string
  approvalId?: string
  acceptance?: { status: 'accepted' | 'rejected'; by: string; at: string; reason: string }
  /** Chaîne d'identité OBO (Q-6) : quand un humain initie une collaboration pour le compte de cet employé via un jeton OBO, le vrai initiateur est transmis dans la chaîne jusqu'à l'audit. */
  onBehalfUser?: string
  actChain?: Array<{ principalId: string; name: string; type: string }>
  startedAt?: string
  finishedAt?: string
}

/** Règles d'approbation des opérations sensibles (contrôle de gouvernance n° 5 ; en cas de correspondance, auth_required crée un dossier d'approbation au lieu d'un refus direct). */
export interface A2aRuleRecord extends RecordBase {
  name: string
  /** Se déclenche si la confidentialité de la tâche ≥ ce niveau (internal/secret). */
  matchDataClassAtLeast?: 'internal' | 'secret'
  /** Se déclenche si le message de la tâche contient ce mot-clé. */
  matchKeyword?: string
  enabled: boolean
  createdBy: string
}

/** Rapport d'inspection de cohérence déclaration-autorisation (gouvernance de la dérive des capacités). */
export interface A2aPatrolRecord extends RecordBase {
  at: string
  actor: string
  checkedAgents: number
  driftAgents: number
  findings: Array<{ agentId: string; agentName: string; findings: string[] }>
}

interface CardKeyRecord extends RecordBase {
  keyId: string
  publicKeyBase64: string
  algorithm: string
  createdAt: string
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class A2aCollabService extends Service {
  static readonly provide = 'a2aCollab'

  constructor(ctx: Context) {
    super(ctx, 'a2aCollab')
    // Progression UHP → avancement de la machine à états à huit états (discipline : uniquement par le bus d'événements)
    ctx.platformBus.on('a2a.task.progress', (payload) => {
      try {
        this.onProgress(payload as UhpProgressLike)
      } catch (error) {
        this.ctx.logger('a2a').error('a2a.task.progress 处理异常', error)
      }
    })
    // Liaison de rejet d'approbation : dossier a2a.task.authorize rejeté → état final de la tâche rejected (clôture de gouvernance de l'état d'interruption)
    ctx.platformBus.on(PlatformEvents.ApprovalDecided, (payload) => {
      const p = payload as { approvalId: string; approved: boolean }
      if (p.approved) return
      const approval = this.ctx.audit.approvals().get(p.approvalId)
      const taskId = String((approval?.payload as Record<string, unknown> | undefined)?.['taskId'] ?? '')
      if (!approval || approval.kind !== 'a2a.task.authorize' || !taskId) return
      const task = this.tasks().get(taskId)
      if (!task || task.state !== 'auth_required') return
      this.transition(task.taskId, 'rejected', t('授权审批被驳回（{approver}）', { approver: String((payload as { approverName?: string }).approverName ?? '审批人') }))
    })
  }

  // -- Collections -----------------------------------------------------------------

  tasks(): Collection<A2aTaskRecord> {
    return this.ctx.opsStorage.collection<A2aTaskRecord>('a2a:tasks', { durability: 'durable' })
  }

  rules(): Collection<A2aRuleRecord> {
    return this.ctx.opsStorage.collection<A2aRuleRecord>('a2a:rules', { durability: 'durable' })
  }

  patrols(): Collection<A2aPatrolRecord> {
    return this.ctx.opsStorage.collection<A2aPatrolRecord>('a2a:patrols', { durability: 'durable' })
  }

  private cardKeys(): Collection<CardKeyRecord> {
    return this.ctx.opsStorage.collection<CardKeyRecord>('a2a:cardKeys', { durability: 'durable' })
  }

  // -- Clés de signature de carte (la clé privée ne touche que le disque dataDir en 0600, les collections ne stockent que la clé publique — aligné sur la sémantique authn/market)---------

  private signingCache: { keyId: string; privateKeyPem: string; publicKeyBase64: string } | undefined

  signing(): { keyId: string; privateKeyPem: string; publicKeyBase64: string } {
    if (this.signingCache) return this.signingCache
    const keyFile = join(this.ctx.opsStorage.dataDirPath, 'a2a-card-signing-key.pem')
    let privateKeyPem: string
    try {
      privateKeyPem = readFileSync(keyFile, 'utf8')
    } catch {
      const generated = generateEd25519KeyPair()
      writeFileSync(keyFile, generated.privateKeyPem, { mode: 0o600 })
      privateKeyPem = generated.privateKeyPem
      this.ctx.logger('a2a').info('已生成 A2A Agent Card 签名密钥（Ed25519，私钥落盘 dataDir 0600）')
    }
    let entry = this.cardKeys().all()[0]
    if (!entry) {
      entry = this.cardKeys().insert({
        id: newId('key'),
        keyId: 'a2a-card-key-1',
        publicKeyBase64: createPublicKey(privateKeyPem).export({ format: 'der', type: 'spki' }).toString('base64'),
        algorithm: 'Ed25519',
        createdAt: new Date().toISOString(),
      })
    }
    this.signingCache = { keyId: entry.keyId, privateKeyPem, publicKeyBase64: entry.publicKeyBase64 }
    return this.signingCache
  }

  // -- Agent Card : projection de l'ensemble d'autorisations + signature (la déclaration a l'autorisation pour autorité, pas de remplissage libre)----------------------

  /** Projection des compétences : Skills mis en avant (agent.attrs.skills) + groupes de permissions MCP (subjects touchant cet Agent). */
  private projectSkills(agentId: string, attrs: Record<string, unknown>): AgentCardSkill[] {
    const skills: AgentCardSkill[] = []
    const slugs = Array.isArray(attrs['skills']) ? (attrs['skills'] as unknown[]).map(String) : []
    for (const slug of slugs) {
      const skill = this.ctx.skillHub.skills().find((item) => item.slug === slug && item.status === 'published')[0]
      if (!skill) continue // les Skills non mis en avant ou retirés de force ne sont pas projetés (déclaration ≤ autorisation)
      skills.push({ id: `skill:${skill.slug}`, name: skill.name, description: skill.summary, tags: skill.tags.slice(0, 6) })
    }
    for (const group of this.ctx.mcpRegistry.permGroups().all()) {
      if (!group.subjects.some((subject) => subject.type === 'agent' && subject.id === agentId)) continue
      skills.push({ id: `mcp:${group.id}`, name: group.name, description: group.description || t('MCP 工具权限组'), tags: ['mcp'] })
    }
    return skills
  }

  /** Plafond de confidentialité (périmètre de canal public/internal/secret ; défaut internal — les niveaux métier D14 ne sont pas traduits mot à mot par leur nom). */
  dataClassCeilingOf(attrs: Record<string, unknown>): DataClass {
    const raw = String(attrs['a2aDataClassCeiling'] ?? '').trim()
    return raw === 'public' || raw === 'secret' ? (raw as DataClass) : 'internal'
  }

  autonomyOf(attrs: Record<string, unknown>): Autonomy {
    return normalizeAutonomy(attrs['autonomy'])
  }

  /**
   * Auto-description de l'Agent Card (Q-31/Q-32/E-7) : complète toute la facette de contrat nécessaire à la collaboration « avec la seule carte » d'un Agent externe —
   * adresse des événements SSE, points de permission requis, version du protocole A2A et facette de méthodes, périmètre de mesure à double sujet.
   * La carte est le plafond d'extensibilité de l'écosystème A2A : un champ manquant = une adaptation manuelle de plus pour chaque Agent de fournisseur externe intégré.
   */
  cardBodyFor(agent: { id: string; slug: string; name: string; attrs: Record<string, unknown> }): AgentCardBody {
    const attrs = agent.attrs
    const base = String(process.env.PLATFORM_PUBLIC_BASE ?? '').replace(/\/+$/, '')
    return {
      name: agent.name,
      description: String(attrs['description'] ?? ''),
      url: `${base}/api/agents/${agent.slug}/a2a`,
      version: '1.3.0',
      capabilities: { streaming: true, pushNotifications: false, stateTransitionHistory: true },
      defaultInputModes: ['text/plain', 'application/json'],
      defaultOutputModes: ['text/plain', 'application/json'],
      skills: this.projectSkills(agent.id, attrs),
      // Q-31 : déclare les points de permission requis pour l'appel (auparavant pas de scopes, les clients externes devaient deviner)
      securitySchemes: {
        ybkMachineCredential: {
          type: 'http',
          scheme: 'bearer',
          description: t('机器凭证令牌（POST /api/auth/client-credentials 换取，有效期 2 小时）'),
          scopes: { 'agent.a2a.invoke': t('A2A 协作调用（派活/续答/取消/查询）') },
        },
      },
      // Q-31/Q-32/E-7 : adresse des événements + périmètre de mesure à double sujet + version du protocole et facette de méthodes
      eventsUrl: `${base}/v1/a2a/tasks/{taskId}/events`,
      extensions: [
        {
          uri: 'urn:ybk:ext:governance:v1',
          params: {
            autonomy: this.autonomyOf(attrs),
            runtime: String(attrs['runtime'] ?? 'dsh'),
            dataClassCeiling: this.dataClassCeilingOf(attrs),
            // Périmètre à double sujet (Q-32/E-7) : la mesure des appels de collaboration est comptée côté initiateur, la consommation de modèle côté employé
            meteringSubject: `agent:${agent.id}`,
            callerMeteringSubject: 'agent:<callerAgentId>',
          },
        },
        {
          uri: 'urn:ybk:ext:protocol:v1',
          params: {
            protocol: 'a2a-jsonrpc',
            protocolVersion: '1.3.0',
            transport: 'json-rpc-2.0/http',
            methods: 'message/send,message/stream,tasks/get,tasks/list,tasks/cancel',
            streamingTransport: 'sse',
            sseAuth: 'query-token',
            wellKnown: `${base}/.well-known/agents/${agent.slug}/agent-card.json`,
            directory: `${base}/api/a2a/directory`,
            uhpDiscovery: `${base}/v1/uhp`,
            uhpVersion: '2026-08-11',
            envelope: 'jsonrpc',
          },
        },
      ],
    }
  }

  cardFor(agent: { id: string; slug: string; name: string; attrs: Record<string, unknown> }): SignedAgentCard {
    const { keyId, privateKeyPem } = this.signing()
    return signAgentCard(this.cardBodyFor(agent), privateKeyPem, keyId)
  }

  /** Carte d'annuaire au niveau plateforme (avec la clé publique de vérification — l'appelant vérifie la signature avant de faire confiance) + facette protocole et entrée d'annuaire (Q-31). */
  platformCard() {
    const { keyId, publicKeyBase64 } = this.signing()
    const base = String(process.env.PLATFORM_PUBLIC_BASE ?? '').replace(/\/+$/, '')
    const agents = this.ctx.resourceCore.list('agent').filter((item) => item.status === 'online')
    return {
      name: t('ybkkasi 企业数字员工协作目录'),
      version: '1.3.0',
      capabilities: { directory: true, streaming: true },
      signingKeys: [{ keyId, publicKeyBase64, algorithm: 'Ed25519' }],
      extensions: [{
        uri: 'urn:ybk:ext:protocol:v1',
        params: {
          protocol: 'a2a-jsonrpc',
          protocolVersion: '1.3.0',
          transport: 'json-rpc-2.0/http',
          methods: 'message/send,message/stream,tasks/get,tasks/list,tasks/cancel',
          streamingTransport: 'sse',
          sseAuth: 'query-token',
          directory: `${base}/api/a2a/directory`,
          uhpDiscovery: `${base}/v1/uhp`,
          uhpVersion: '2026-08-11',
          envelope: 'jsonrpc',
        },
      }],
      agents: agents.map((agent) => ({
        slug: agent.slug,
        name: agent.name,
        autonomy: this.autonomyOf(agent.attrs),
        runtime: String(agent.attrs['runtime'] ?? 'dsh'),
        cardUrl: `${base}/.well-known/agents/${agent.slug}/agent-card.json`,
      })),
    }
  }

  /** Recherche d'annuaire (découverte inter-runtimes) : employés en ligne + projection des champs d'extension de gouvernance de carte. */
  /**
   * Recherche d'annuaire (découverte inter-runtimes) : employés en ligne + projection des champs d'extension de gouvernance de carte.
   * Isolation organisationnelle (Q-4) : convergence sur le sous-arbre organisationnel visible par l'appelant — même périmètre que /api/agents selon R11,
   * une organisation inférieure détenant a2a.directory.read ne voit que les objets de collaboration de son sous-arbre organisationnel.
   */
  directory(filter: { skill?: string; q?: string; runtime?: string; autonomy?: string; dataClass?: string; category?: string }, caller?: CallerRefLike) {
    const orgScope = caller ? this.visibleOrgIds(caller) : null
    const entries = this.ctx.resourceCore.list('agent')
      .filter((agent) => agent.status === 'online')
      .filter((agent) => (orgScope === null || !caller ? true : this.canSeeOrg(caller, agent.id)))
      .map((agent) => {
        const card = this.cardBodyFor(agent)
        return {
          agentId: agent.id,
          slug: agent.slug,
          name: agent.name,
          description: card.description,
          avatar: String(agent.attrs['avatar'] ?? '🤖'),
          // Classification métier (périmètre unifié de tous les volets d'actifs) : les enregistrements existants sans cet attribut sont rangés sous « autres »
          category: normalizeAssetCategory(agent.attrs['category']),
          url: card.url,
          skills: card.skills,
          autonomy: card.extensions[0]!.params.autonomy,
          runtime: card.extensions[0]!.params.runtime,
          dataClassCeiling: card.extensions[0]!.params.dataClassCeiling,
          meteringSubject: card.extensions[0]!.params.meteringSubject,
          updatedAt: agent.updatedAt,
        }
      })
    return entries
      .filter((entry) => (filter.category ? entry.category === filter.category : true))
      .filter((entry) => (filter.runtime ? entry.runtime === filter.runtime : true))
      .filter((entry) => (filter.autonomy ? entry.autonomy === filter.autonomy : true))
      .filter((entry) => {
        if (!filter.dataClass) return true
        const wanted = filter.dataClass === 'public' || filter.dataClass === 'secret' ? filter.dataClass : 'internal'
        return DATA_CLASS_RANK[wanted] <= (DATA_CLASS_RANK[entry.dataClassCeiling as DataClass] ?? 1)
      })
      .filter((entry) => {
        if (!filter.skill) return true
        const needle = filter.skill.toLowerCase()
        return entry.skills.some((skill) => skill.id.toLowerCase().includes(needle) || skill.name.toLowerCase().includes(needle) || skill.tags.some((tag) => tag.toLowerCase().includes(needle)))
      })
      .filter((entry) => {
        if (!filter.q) return true
        const needle = filter.q.toLowerCase()
        return entry.name.toLowerCase().includes(needle) || entry.description.toLowerCase().includes(needle) || entry.slug.toLowerCase().includes(needle)
      })
  }

  // -- Cinq contrôles de gouvernance (après acceptation, avant traduction UHP ; un seul échec = rejected avec trace)-------------------------

  private async governanceCheck(input: {
    agent: { id: string; name: string; slug: string; status: string; orgId: string; attrs: Record<string, unknown> }
    dataClass: DataClass
    message: string
    callerAutonomy: Autonomy
  }): Promise<{ ok: true; approvalRequired: boolean } | { ok: false; code: string; message: string }> {
    const { agent } = input
    // 1. Point de permission : forcé à la frontière HTTP par la route /api guarded('agent.a2a.invoke') (fail-closed) ; ici, enregistrement de la position sémantique.
    if (agent.status !== 'online') return { ok: false, code: 'TARGET_NOT_ONLINE', message: t('被调员工未上线（{status}），A2A 仅对 online 开放', { status: agent.status }) }
    // 2. En ligne + non gelé + couverture permit workforce
    //    Employé géré (liaison workforce active + employé en poste + affectation effective) : la couverture permit est satisfaite ;
    //    liaison présente mais invalide (parti/retrait d'affectation/liaison désactivée) → refus (Q-22/D-4) ;
    //    les Agents legacy jamais gouvernés passent selon la sémantique v1, sans blocage pour cause de non-gouvernance.
    if (this.ctx.agentRegistry.isFrozen(agent.id)) return { ok: false, code: 'TARGET_FROZEN', message: t('被调员工已冻结（预算超限联动），暂不可承接协作任务') }
    // P2-01 : workforceIdentity est désormais dans inject (auparavant absent → le proxy Service cordis levait en lisant une clé non injectée,
    // l'exception était avalée par le catch et le passage se faisait en legacy, la couverture permit était en réalité une no-op). Le jugement passe par la méthode de contrat inspectAgent —
    // sans toucher à la structure interne de resolver.store (couplage fragile), en distinguant « non gouverné » et « gouverné mais invalide ».
    // Périmètre de repli : workforceIdentity est une dépendance déclarée (inject + plugin.yaml) ; si l'hôte manque de fournisseur, le plugin entier
// passe INACTIVE (sémantique cordis) et n'arrive jamais ici ; si le jugement **lève**, refus fail-closed —
// il est interdit de considérer un « échec du jugement de gouvernance » comme un motif de passage (la cause racine de P2-01 était justement l'exception avalée puis passage en legacy).
    const resolver = this.ctx.workforceIdentity
    let state: Awaited<ReturnType<typeof resolver.inspectAgent>>
    try {
      state = await resolver.inspectAgent(agent.id)
    } catch (error) {
      this.ctx.audit.fire({
        severity: 'warning',
        title: t('workforce permit 覆盖判定失败：{agent}', { agent: agent.slug }),
        message: error instanceof Error ? error.message : String(error),
        resourceType: 'agent',
        resourceId: agent.id,
      })
      return {
        ok: false,
        code: 'PERMIT_NOT_EFFECTIVE',
        message: t('无法确认被调员工的 permit 覆盖状态（判定异常），按 fail-closed 拒绝本次协作'),
      }
    }
    if (state.bound && !state.permitEffective) {
      const reason = state.reason === 'EMPLOYEE_NOT_ACTIVE'
        ? t('员工已离岗/停职（{employeeId}）', { employeeId: state.employeeId ?? '' })
        : t('任用未生效（{employeeId}）', { employeeId: state.employeeId ?? '' })
      return {
        ok: false,
        code: 'PERMIT_NOT_EFFECTIVE',
        message: t('被调员工已绑定数字员工身份但 permit 未生效：{reason}，请先恢复员工在岗与任用后重试', { reason }),
      }
    }
    // 3. Plafond de confidentialité (dépassement de niveau : refus verrouillé par le périmètre de canal, sémantique du contrat c1)
    const ceiling = this.dataClassCeilingOf(agent.attrs)
    if (DATA_CLASS_RANK[input.dataClass] > DATA_CLASS_RANK[ceiling]) {
      return { ok: false, code: 'DATA_CLASS_EXCEEDED', message: t('数据密级越级：任务密级 {requested} 高于该员工天花板 {ceiling}（拒绝并留痕）', { requested: input.dataClass, ceiling }) }
    }
    // 4. Budget et quotas (périmètre de disjonction de budget de modelgw)
    try {
      const statuses = this.ctx.modelGateway.budgetStatusForSubject(`agent:${agent.id}`, agent.orgId)
      for (const item of statuses) {
        const breached = (item.daily?.breached || item.monthly?.breached)
        if (breached && item.budget.action === 'block') {
          return { ok: false, code: 'BUDGET_EXCEEDED', message: t('被调员工预算熔断中（预算 {budget}），本次任务拒绝', { budget: item.budget.id }) }
        }
      }
    } catch { /* facette budget modelgw absente : pas de blocage (la disjonction côté appel de modèle reste le filet) */ }
    // 5. Règles d'approbation des opérations sensibles (correspondance → dossier d'approbation auth_required, plutôt qu'un refus direct)
    const approvalRequired = this.rules().all().some((rule) => {
      if (!rule.enabled) return false
      if (rule.matchDataClassAtLeast && DATA_CLASS_RANK[input.dataClass] >= DATA_CLASS_RANK[rule.matchDataClassAtLeast]) return true
      if (rule.matchKeyword && input.message.includes(rule.matchKeyword)) return true
      return false
    })
    return { ok: true, approvalRequired }
  }

  /**
   * Jugement du niveau d'autonomie de l'appelant : identifiant machine lié à un Agent → niveau enregistré de celui-ci (contract-c3) ;
   * appelant humain → mappé en A1 — dans la matrice de négociation, la colonne A1 correspond justement à la sémantique de délégation humaine :
   * objectif A0 → Q&R en un tour ; objectif A1 → exécution avec humain dans la boucle ; objectif A2 → exécution avec rapport a posteriori ; objectif A3 → exécution.
   */
  private callerAutonomyOf(caller: CallerRefLike, verified?: VerifiedPrincipal): Autonomy {
    if (caller.refType === 'agent' && caller.refId) {
      const agent = this.ctx.resourceCore.get('agent', caller.refId)
      if (agent) return this.autonomyOf(agent.attrs)
    }
    void verified
    return 'A1'
  }

  // -- Facette tâches ---------------------------------------------------------------

  private resolveAgent(ref: string) {
    return this.ctx.resourceCore.get('agent', ref) ?? this.ctx.resourceCore.bySlug('agent', ref)
  }

  private callerRefOf(exchange: HttpExchange): CallerRefLike {
    const info = exchange.principal as CallerRefLike
    return info
  }

  private orgOf(caller: CallerRefLike, agent: { orgId: string }): string {
    return (caller.userId ? this.ctx.iam.users().get(caller.userId)?.orgId : undefined) ?? agent.orgId ?? ''
  }

  private subjectOf(caller: CallerRefLike): string {
    return caller.refType === 'agent' && caller.refId
      ? `agent:${caller.refId}`
      : caller.userId ? `user:${caller.userId}` : `a2a:${caller.principalId}`
  }

  private appendHistory(task: A2aTaskRecord, entry: A2aHistoryEntry): A2aTaskRecord {
    const history = [...task.history, entry].slice(-200)
    return this.tasks().update(task.id, { history })
  }

  private transition(taskId: string, state: A2aTaskState, reason: string): A2aTaskRecord {
    const task = this.tasks().findOne((item) => item.taskId === taskId)
    if (!task) throw new Error(t('A2A 任务不存在：{id}', { id: taskId }))
    if (task.state === state && A2A_TERMINAL_STATES.includes(state)) return task
    const patch: Partial<A2aTaskRecord> = { state, stateReason: reason }
    if (A2A_TERMINAL_STATES.includes(state)) patch.finishedAt = new Date().toISOString()
    if (state === 'working' && !task.startedAt) patch.startedAt = new Date().toISOString()
    const updated = this.tasks().update(task.id, patch)
    this.appendHistory(updated, { at: new Date().toISOString(), from: 'system', type: 'status', state, note: reason })
    this.ctx.platformBus.emit('a2a.task.changed', { taskId, state, reason, contextId: updated.contextId, agentId: updated.agentId })
    return updated
  }

  /**
   * Entrée principale message/send : création ou poursuite de tâche → cinq contrôles de gouvernance → moteur de négociation → distribution d'exécution.
   * Renvoie l'instantané de la tâche (attente synchrone jusqu'à l'état final ou dépassement — les tâches longues continuent via tasks/get ou SSE).
   */
  async sendMessage(input: {
    caller: CallerRefLike
    agentRef: string
    message: string
    dataClass?: string
    contextId?: string
    taskId?: string
    negotiation?: unknown
  }): Promise<A2aTaskRecord> {
    if (!input.message?.trim()) throw new Error(t('message 必填（A2A 协作任务内容）'))
    const agent = this.resolveAgent(input.agentRef)
    if (!agent) throw new NotFoundError(t('Agent 不存在：{ref}', { ref: input.agentRef }))
    const requested: DataClass = input.dataClass === 'public' || input.dataClass === 'secret' ? input.dataClass : 'internal'
    const caller = input.caller
    const callerAutonomy = this.callerAutonomyOf(caller)
    const targetAutonomy = this.autonomyOf(agent.attrs)

    // Chemin de poursuite : tour de négociation supplémentaire / entrée complémentaire pour une tâche input_required
    if (input.taskId) {
      const task = this.tasks().findOne((item) => item.taskId === input.taskId)
      if (!task) throw new NotFoundError(t('A2A 任务不存在：{id}', { id: input.taskId }))
      if (task.callerPrincipalId !== caller.principalId && !caller.permissions.includes('*')) {
        throw new Error(t('仅任务发起方可续答该任务'))
      }
      if (task.state !== 'input_required') {
        throw new Error(t('任务当前状态为 {state}，仅 input_required 可续答', { state: task.state }))
      }
      this.appendHistory(task, { at: new Date().toISOString(), from: 'caller', type: 'message', text: input.message })
      if (task.negotiation?.status === 'open') return this.advanceNegotiation(task, input.message, caller)
      // Interruption hors négociation : redistribution de l'exécution après entrée complémentaire
      return this.dispatchTask(task, input.message)
    }

    // Chemin de nouvelle tâche
    const governance = await this.governanceCheck({
      agent, dataClass: requested, message: input.message, callerAutonomy,
    })
    if (!governance.ok) {
      const task = this.createTaskRecord({ caller, agent, message: input.message, dataClass: requested, callerAutonomy, targetAutonomy })
      this.transition(task.taskId, 'rejected', governance.message)
      this.auditTask(this.tasks().findOne((item) => item.taskId === task.taskId)!, 'a2a.task.rejected', 'denied', governance.message)
      throw new GovernanceError(governance.code, governance.message)
    }

    // Moteur de négociation : la matrice A0-A3 ne contraint que les « appels entre employés numériques » (lignes et colonnes de la matrice = niveaux d'autonomie des employés) ;
    // les appelants humains/services externes n'entrent pas dans la matrice — jugement direct par niveau d'objectif : objectif A0 = Q&R en un tour, objectif A1+ = sémantique de la colonne A1
    // (A1 → exécution avec humain dans la boucle, A2/A3 → exécution avec rapport a posteriori) ; la profondeur d'exécution reste toujours contrainte par les cinq contrôles de gouvernance.
    const isAgentCaller = Boolean(caller.refType === 'agent' && caller.refId && this.ctx.resourceCore.get('agent', caller.refId))
    const mode: NegotiationMode = isAgentCaller
      ? negotiateMode(callerAutonomy, targetAutonomy)
      : (targetAutonomy === 'A0' ? 'single_turn' : negotiateMode('A1', targetAutonomy))
    if (mode === 'rejected') {
      // Q-10 : mode enregistre le jugement réel (rejected), plus de repli en single_turn — les consommateurs qui statistiquent par mode
      // (vue de performance/classement audit/filtres console) ne doivent pas compter un « refus de matrice » comme une « Q&R en un tour »
      const task = this.createTaskRecord({ caller, agent, message: input.message, dataClass: requested, callerAutonomy, targetAutonomy, mode: 'rejected' })
      const reason = t('协商矩阵拒绝：调用方 {caller} × 被调方 {target} 不允许执行类交互（A0 提示型员工不可被驱动执行）', { caller: callerAutonomy, target: targetAutonomy })
      this.transition(task.taskId, 'rejected', reason)
      this.auditTask(this.tasks().findOne((item) => item.taskId === task.taskId)!, 'a2a.task.rejected', 'denied', reason)
      throw new GovernanceError('NEGOTIATION_REJECTED', reason)
    }

    const task = this.createTaskRecord({
      caller, agent, message: input.message, dataClass: requested, callerAutonomy, targetAutonomy, mode,
      // Q-21 : l'appelant peut spécifier l'ID de chaîne de collaboration (metadata.contextId) ; seule une même chaîne permet la consolidation de mesure
      ...(input.contextId ? { contextId: input.contextId } : {}),
    })
    this.auditTask(task, 'a2a.task.accepted', 'ok', t('治理检查五项通过，协商引擎判定 {mode}', { mode }))

    if (mode === 'single_turn') return this.runSingleTurn(this.tasks().findOne((item) => item.taskId === task.taskId)!)
    // Règle d'approbation des opérations sensibles satisfaite (une Q&R en un tour ne constitue pas une opération, exemption) : les tâches d'exécution/négociation créent d'abord un dossier d'approbation
    if (governance.approvalRequired) {
      return this.requestAuthorize(this.tasks().findOne((item) => item.taskId === task.taskId)!, t('命中敏感操作审批规则，人在环确认后恢复执行'))
    }
    if (mode === 'execute_confirm') return this.requestAuthorize(this.tasks().findOne((item) => item.taskId === task.taskId)!, t('协商矩阵要求人在环确认（{caller} × {target}）', { caller: callerAutonomy, target: targetAutonomy }))
    if (mode === 'negotiate') {
      const proposal = input.negotiation ?? { task: input.message }
      return this.startNegotiation(this.tasks().findOne((item) => item.taskId === task.taskId)!, proposal)
    }
    return this.dispatchTask(this.tasks().findOne((item) => item.taskId === task.taskId)!)
  }

  private createTaskRecord(input: {
    caller: CallerRefLike
    agent: { id: string; slug: string; name: string }
    message: string
    dataClass: DataClass
    callerAutonomy: Autonomy
    targetAutonomy: Autonomy
    mode?: NegotiationMode
    /** ID de chaîne de collaboration spécifié par l'appelant (Q-21) ; généré par la plateforme par défaut. */
    contextId?: string
  }): A2aTaskRecord {
    const now = new Date().toISOString()
    return this.tasks().insert({
      id: newId('a2at'),
      taskId: newId('task'),
      // Q-21 : la chaîne de collaboration spécifiée par l'appelant est transmise telle quelle (condition préalable à la consolidation de mesure par chaîne) ; sinon la plateforme la génère toujours
      contextId: input.contextId?.trim() || newId('a2actx'),
      agentId: input.agent.id,
      agentSlug: input.agent.slug,
      callerPrincipalId: input.caller.principalId,
      ...(input.caller.userId ? { callerUserId: input.caller.userId } : {}),
      ...(input.caller.refType === 'agent' && input.caller.refId ? { callerAgentId: input.caller.refId } : {}),
      callerSubject: this.subjectOf(input.caller),
      callerAutonomy: input.callerAutonomy,
      targetAutonomy: input.targetAutonomy,
      mode: input.mode ?? 'single_turn',
      state: 'submitted',
      stateReason: t('任务受理（治理检查中）'),
      message: input.message,
      dataClass: input.dataClass,
      artifacts: [],
      history: [{ at: now, from: 'caller', type: 'message', text: input.message.slice(0, 2000) }],
      attempts: 0,
      // Chaîne d'identité OBO (Q-6) : quand un humain initie en tant que représentant, le vrai initiateur de la chaîne act accompagne la tâche et l'audit
      ...(input.caller.onBehalfOfUser ? { onBehalfUser: input.caller.onBehalfOfUser } : {}),
      ...(input.caller.oboActChain && input.caller.oboActChain.length > 0 ? { actChain: input.caller.oboActChain } : {}),
    })
  }

  /** Q&R en un tour (single_turn) : sémantique v1 de réponse par la plateforme, appel de modèle réel + mesure d'instantané à prix zéro (avec contextId de chaîne de collaboration). */
  private async runSingleTurn(task: A2aTaskRecord): Promise<A2aTaskRecord> {
    const agent = this.resolveAgent(task.agentId)
    if (!agent) return this.transition(task.taskId, 'failed', t('Agent 资产不存在'))
    const model = String(agent.attrs['model'] ?? '')
    if (!model) {
      this.transition(task.taskId, 'failed', t('Agent 未配置模型（model 属性为空），诚实降级'))
      return this.tasks().findOne((item) => item.taskId === task.taskId)!
    }
    const systemPrompt = String(agent.attrs['systemPrompt'] ?? t('你是企业数字同事「{name}」。{description}', { name: agent.name, description: String(agent.attrs['description'] ?? '') }))
    this.transition(task.taskId, 'working', t('单轮问答执行中（平台代答）'))
    try {
      const org = (task.callerUserId ? this.ctx.iam.users().get(task.callerUserId)?.orgId : undefined) ?? agent.orgId ?? ''
      const result = await this.ctx.modelGateway.invoke({
        model,
        orgId: org,
        subject: task.callerSubject,
        dataClass: task.dataClass,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: task.message },
        ],
      })
      const updated = this.tasks().update(task.id, {
        inputTokens: result.inputTokens,
        outputTokens: result.outputTokens,
        model: result.model,
        responseId: result.usageEventId,
      })
      this.completeTask(updated, result.content)
      this.emitInvoked(agent, result.model)
      return this.tasks().findOne((item) => item.taskId === task.taskId)!
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      this.transition(task.taskId, 'failed', reason)
      this.auditTask(this.tasks().findOne((item) => item.taskId === task.taskId)!, 'agent.a2a.invoke', 'error', reason)
      return this.tasks().findOne((item) => item.taskId === task.taskId)!
    }
  }

  /** Distribution d'exécution : traduit en appel UHP (clé d'idempotence alignée sur la Task ; uniquement par le bus d'événements). */
  private dispatchTask(task: A2aTaskRecord, resumeMessage?: string): A2aTaskRecord {
    const agent = this.resolveAgent(task.agentId)
    if (!agent) return this.transition(task.taskId, 'failed', t('Agent 资产不存在'))
    const attempts = task.attempts + 1
    this.tasks().update(task.id, { attempts })
    if (resumeMessage) this.tasks().update(task.id, { message: resumeMessage })
    this.transition(task.taskId, 'working', t('UHP 执行中（第 {n} 次派发）', { n: attempts }))
    this.ctx.platformBus.emit('a2a.task.dispatch', {
      taskId: task.taskId,
      contextId: task.contextId,
      agentId: task.agentId,
      harnessRef: String(agent.attrs['uhpHarnessRef'] ?? '') || undefined,
      input: resumeMessage ?? task.message,
      dataClass: task.dataClass,
      // Alignement de la clé d'idempotence (plan de collaboration §7.2) : a2a:<agentId>:<principal>:<taskId>:a<attempt>
      idempotencyKey: this.dispatchKey(task, attempts),
      sessionPolicy: String(agent.attrs['uhpSessionPolicy'] ?? 'task-bound') === 'employee-bound' ? 'employee-bound' : 'task-bound',
      callerPrincipalId: task.callerPrincipalId,
      // Chaîne d'identité OBO (Q-6) : la plateforme transmet en interne le vrai initiateur ; le côté UHP l'inscrit à l'audit (aucune auto-déclaration externe n'est admise)
      ...(task.onBehalfUser ? { onBehalfUser: task.onBehalfUser } : {}),
      ...(task.actChain?.length ? { actChain: task.actChain } : {}),
    })
    this.emitInvoked(agent, String(agent.attrs['model'] ?? ''))
    return this.tasks().findOne((item) => item.taskId === task.taskId)!
  }

  /** Négociation A3×A3 : émission de l'offre (round 1). */
  private async startNegotiation(task: A2aTaskRecord, proposal: unknown): Promise<A2aTaskRecord> {
    const negotiation = { round: 1, maxRounds: NEGOTIATION_MAX_ROUNDS, status: 'open' as const, offers: [{
      round: 1, from: 'caller' as const, proposal, at: new Date().toISOString(),
    }] }
    const withNegotiation = this.tasks().update(task.id, { negotiation })
    this.appendHistory(withNegotiation, { at: new Date().toISOString(), from: 'caller', type: 'offer', note: t('发起协商要约（第 1 轮）') })
    return this.evaluateNegotiation(this.tasks().findOne((item) => item.taskId === task.taskId)!)
  }

  /** Tour de négociation suivant : réponse de l'appelant à la contre-offre. */
  private async advanceNegotiation(task: A2aTaskRecord, message: string, _caller: CallerRefLike): Promise<A2aTaskRecord> {
    void _caller
    const negotiation = task.negotiation!
    if (negotiation.round >= negotiation.maxRounds) {
      this.tasks().update(task.id, { negotiation: { ...negotiation, status: 'expired' } })
      const reason = t('协商轮次超限（{max} 轮），任务拒绝', { max: negotiation.maxRounds })
      this.transition(task.taskId, 'rejected', reason)
      this.auditTask(this.tasks().findOne((item) => item.taskId === task.taskId)!, 'a2a.task.rejected', 'denied', reason)
      return this.tasks().findOne((item) => item.taskId === task.taskId)!
    }
    const offers = [...negotiation.offers, { round: negotiation.round + 1, from: 'caller' as const, proposal: message, at: new Date().toISOString() }]
    this.tasks().update(task.id, { negotiation: { ...negotiation, round: negotiation.round + 1, offers } })
    const updated = this.tasks().findOne((item) => item.taskId === task.taskId)!
    this.appendHistory(updated, { at: new Date().toISOString(), from: 'caller', type: 'offer', note: t('协商回应（第 {n} 轮）', { n: negotiation.round + 1 }) })
    return this.evaluateNegotiation(this.tasks().findOne((item) => item.taskId === task.taskId)!)
  }

  /** Le côté appelé évalue l'offre courante : accept → passage à l'exécution ; counter → suspension input_required en attendant la réponse de l'appelant. */
  private async evaluateNegotiation(task: A2aTaskRecord): Promise<A2aTaskRecord> {
    const agent = this.resolveAgent(task.agentId)
    if (!agent) return this.transition(task.taskId, 'failed', t('Agent 资产不存在'))
    const model = String(agent.attrs['model'] ?? '')
    if (!model) return this.transition(task.taskId, 'failed', t('Agent 未配置模型（model 属性为空），协商无法评估'))
    const systemPrompt = String(agent.attrs['systemPrompt'] ?? t('你是企业数字同事「{name}」。{description}', { name: agent.name, description: String(agent.attrs['description'] ?? '') }))
    const negotiation = task.negotiation!
    const latestOffer = negotiation.offers.at(-1)!
    this.transition(task.taskId, 'working', t('被调方评估协商要约（第 {n} 轮）', { n: negotiation.round }))
    let raw = ''
    try {
      const result = await this.ctx.modelGateway.invoke({
        model,
        orgId: agent.orgId ?? '',
        subject: `agent:${agent.id}`,
        dataClass: task.dataClass,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: t(
            '收到另一数字员工的协作要约（JSON）：{proposal}\n任务背景消息：{message}\n请评估你能否承接该任务边界、时限与交付格式。只回复 JSON：能承接 → {"decision":"accept","note":"…"}；需修订 → {"decision":"counter","proposal":{…修订要约…},"note":"…"}',
            { proposal: JSON.stringify(latestOffer.proposal).slice(0, 3000), message: task.message.slice(0, 1000) },
          ) },
        ],
      })
      raw = result.content
      this.tasks().update(task.id, { inputTokens: (task.inputTokens ?? 0) + result.inputTokens, outputTokens: (task.outputTokens ?? 0) + result.outputTokens, model: result.model })
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      this.transition(task.taskId, 'failed', t('协商评估失败：{reason}', { reason }))
      return this.tasks().findOne((item) => item.taskId === task.taskId)!
    }
    const decision = parseNegotiationDecision(raw)
    const current = this.tasks().findOne((item) => item.taskId === task.taskId)!
    if (decision.decision === 'accept') {
      this.tasks().update(current.id, { negotiation: { ...(current.negotiation ?? negotiation), status: 'accepted' } })
      this.appendHistory(this.tasks().get(current.id)!, { at: new Date().toISOString(), from: 'target', type: 'offer', note: t('被调方接受要约：{note}', { note: decision.note ?? '-' }) })
      const accepted = this.tasks().findOne((item) => item.taskId === task.taskId)!
      return this.dispatchTask(accepted)
    }
    const offers = [...(current.negotiation ?? negotiation).offers, { round: (current.negotiation ?? negotiation).round, from: 'target' as const, proposal: decision.proposal ?? null, note: decision.note, at: new Date().toISOString() }]
    this.tasks().update(current.id, { state: 'input_required', stateReason: t('被调方还价（第 {n} 轮），等待调用方回应', { n: (current.negotiation ?? negotiation).round }), negotiation: { ...(current.negotiation ?? negotiation), offers } })
    this.appendHistory(this.tasks().get(current.id)!, { at: new Date().toISOString(), from: 'target', type: 'offer', note: t('还价：{note}', { note: decision.note ?? '-' }) })
    this.ctx.platformBus.emit('a2a.task.changed', { taskId: task.taskId, state: 'input_required', reason: t('协商还价'), contextId: task.contextId, agentId: task.agentId })
    return this.tasks().findOne((item) => item.taskId === task.taskId)!
  }

  /** Confirmation humaine dans la boucle (execute_confirm / règle d'approbation satisfaite) : auth_required + dossier au centre d'approbations. */
  private requestAuthorize(task: A2aTaskRecord, reason: string): A2aTaskRecord {
    const approval = this.ctx.audit.createApproval({
      kind: 'a2a.task.authorize',
      riskLevel: 'medium',
      title: t('A2A 协作任务授权：{taskId}（{slug}）', { taskId: task.taskId, slug: task.agentSlug }),
      payload: {
        taskId: task.taskId,
        agentId: task.agentId,
        agentSlug: task.agentSlug,
        dataClass: task.dataClass,
        messagePreview: task.message.slice(0, 500),
        reason,
      },
      requesterId: task.callerUserId ?? task.callerPrincipalId,
      requesterName: task.callerSubject,
    })
    this.tasks().update(task.id, { approvalId: approval.id })
    this.transition(task.taskId, 'auth_required', reason)
    this.auditTask(this.tasks().findOne((item) => item.taskId === task.taskId)!, 'a2a.task.auth_required', 'ok', t('命中人在环确认，审批工单 {id}', { id: approval.id }))
    return this.tasks().findOne((item) => item.taskId === task.taskId)!
  }

  /**
   * Progression UHP → machine à états.
   *
   * Défense en profondeur P0 (Q-1) : progress ne peut faire avancer l'état que s'il porte le responseId **généré par la plateforme lors de la distribution** de cette tâche.
   * la facette protocole interdit l'injection externe de taskId et le côté UHP n'émet de progress que pour les enregistrements distribués par la plateforme ; ici s'ajoute une vérification d'appariement —
   * même si les deux premières couches sont contournées, un responseId non issu de la distribution de cette tâche ne peut pas faire avancer la tâche.
   */
  private onProgress(payload: UhpProgressLike): void {
    if (!payload.taskId) return
    const task = this.tasks().findOne((item) => item.taskId === payload.taskId)
    if (!task) return
    if (payload.phase === 'started') {
      if (task.state !== 'working') this.transition(task.taskId, 'working', t('UHP 执行已启动'))
      if (payload.responseId) this.tasks().update(task.id, { responseId: payload.responseId })
      return
    }
    // Les progress de type état final vérifient leur source : la tâche doit avoir enregistré un responseId de distribution, identique à celui du progress courant
    const bound = task.responseId
    if (!bound || !payload.responseId || bound !== payload.responseId) {
      this.ctx.audit.record({
        type: 'authz', actorType: 'system', actorId: 'a2a-guard', actorName: t('A2A 来源校验'),
        action: 'a2a.task.progress_rejected', resourceType: 'agent', resourceId: task.agentId, resourceName: task.agentSlug,
        result: 'denied',
        detail: t('拒绝非本任务派发的执行进度（task={taskId} bound={bound} incoming={incoming} phase={phase}）——防任务劫持', {
          taskId: task.taskId, bound: bound ?? '-', incoming: payload.responseId ?? '-', phase: payload.phase,
        }),
      })
      return
    }
    if (payload.phase === 'completed') {
      const updated = this.tasks().update(task.id, {
        inputTokens: payload.inputTokens ?? task.inputTokens,
        outputTokens: payload.outputTokens ?? task.outputTokens,
        ...(payload.model ? { model: payload.model } : {}),
        ...(payload.responseId ? { responseId: payload.responseId } : {}),
      })
      this.completeTask(updated, payload.text ?? '')
      return
    }
    if (payload.phase === 'failed') {
      this.transition(task.taskId, 'failed', payload.error ?? t('UHP 执行失败'))
      this.auditTask(this.tasks().findOne((item) => item.taskId === task.taskId)!, 'agent.a2a.invoke', 'error', payload.error ?? 'UHP failed')
      return
    }
    if (payload.phase === 'canceled') {
      if (!A2A_TERMINAL_STATES.includes(task.state)) this.transition(task.taskId, 'canceled', t('UHP 执行取消，结果不交付'))
    }
  }

  /** Clôture de tâche accomplie : comptabilisation de l'artifact + mesure d'instantané à prix zéro (consolidation par chaîne contextId) + audit. */
  private completeTask(task: A2aTaskRecord, text: string): void {
    const artifact: A2aArtifact = {
      artifactId: newId('art'),
      name: 'reply.txt',
      mimeType: 'text/plain',
      kind: 'text',
      content: text,
      sizeBytes: Buffer.byteLength(text, 'utf8'),
    }
    this.tasks().update(task.id, { artifacts: [artifact] })
    this.transition(task.taskId, 'completed', t('任务完成（含交付物 {n} 项）', { n: 1 }))
    try {
      const agent = this.resolveAgent(task.agentId)
      const org = this.orgOf({ principalId: task.callerPrincipalId, userId: task.callerUserId } as CallerRefLike, agent ?? { orgId: '' })
      this.ctx.usage.record({
        ...nonbillableUsage({
          org,
          subject: task.callerSubject,
          principal: org ? `org:${org}` : 'platform',
          resource: `agent:${task.agentId}`,
          // Q-20 : la clé de comptabilisation a la même forme que la clé de distribution de la couche d'exécution (attempt inclus) — à la redistribution, les deux couches comptent en synchronisation,
          // plus de faille de périmètre du type « couche d'exécution compte 2 fois, mesure de chaîne de collaboration compte 1 fois »
          idempotency_key: this.dispatchKey(task, task.attempts),
        }),
        meters: [
          { key: 'calls', value: 1, unit: 'call' },
          { key: 'input_tokens', value: task.inputTokens ?? 0, unit: 'token' },
          { key: 'output_tokens', value: task.outputTokens ?? 0, unit: 'token' },
        ],
        // Consolidation par chaîne de collaboration (C4) : la mesure des multiples Tasks d'un même contextId s'agrège par chaîne
        contextId: task.contextId,
      })
    } catch (error) {
      // Q-20 : un échec de mesure n'est plus avalé en silence — alerte inscrite à l'audit, pour que « tâche accomplie mais non comptabilisée » puisse être découvert
      this.ctx.audit.fire({
        severity: 'warning',
        title: t('A2A 协作任务计量入账失败：{taskId}', { taskId: task.taskId }),
        message: error instanceof Error ? error.message : String(error),
        resourceType: 'agent',
        resourceId: task.agentId,
      })
    }
    this.auditTask(this.tasks().findOne((item) => item.taskId === task.taskId)!, 'agent.a2a.invoke', 'ok', t('UHP 任务完成：tokens {in}/{out}', { in: task.inputTokens ?? 0, out: task.outputTokens ?? 0 }))
  }

  /** Clé d'idempotence partagée par exécution/mesure : a2a:<agentId>:<principal>:<taskId>:a<attempt> (même forme sur les deux couches, voir Q-20). */
  private dispatchKey(task: A2aTaskRecord, attempt: number): string {
    return `a2a:${task.agentId}:${task.callerPrincipalId}:${task.taskId}:a${Math.max(attempt, 1)}`
  }

  private emitInvoked(agent: { id: string; slug: string; attrs: Record<string, unknown> }, model: string): void {
    this.ctx.platformBus.emit(PlatformEvents.AgentA2aInvoked, {
      agentId: agent.id, slug: agent.slug, from: 'a2a-collab', model,
      autonomy: this.autonomyOf(agent.attrs), runtime: String(agent.attrs['runtime'] ?? 'dsh'),
    })
  }

  private auditTask(task: A2aTaskRecord, action: string, result: 'ok' | 'denied' | 'error', detail: string): void {
    this.ctx.audit.record({
      type: 'invoke',
      actorType: task.callerUserId ? 'human' : 'machine',
      actorId: task.onBehalfUser ?? task.callerSubject,
      actorName: task.onBehalfUser ?? task.callerSubject,
      action,
      resourceType: 'agent',
      resourceId: task.agentId,
      resourceName: task.agentSlug,
      result,
      detail: `task=${task.taskId} context=${task.contextId} state=${task.state} ${detail}`.trim(),
    })
  }

  // -- Requête / annulation / recette / performance / inspection ---------------------------------------

  /**
   * Vue de tâche (anonymisation du corps Q-5) : la permission de lecture de gouvernance (a2a.directory.read) donne accès aux métadonnées,
   * mais le corps de la tâche (message / contenu des artifacts / texte des offres de négociation / historique des flux) exige
   * l'initiateur lui-même, le réceptionnaire (a2a.task.accept) ou un administrateur plateforme ; sinon contentRedacted est marqué et le texte omis.
   */
  taskView(task: A2aTaskRecord, caller?: CallerRefLike) {
    const privileged = !caller
      || caller.permissions.includes('*')
      || task.callerPrincipalId === caller.principalId
      || caller.permissions.includes('a2a.task.accept')
    if (privileged) {
      return {
        taskId: task.taskId, contextId: task.contextId, agentId: task.agentId, agentSlug: task.agentSlug,
        callerSubject: task.callerSubject, callerAutonomy: task.callerAutonomy, targetAutonomy: task.targetAutonomy,
        mode: task.mode, state: task.state, stateReason: task.stateReason, message: task.message,
        dataClass: task.dataClass, negotiation: task.negotiation, artifacts: task.artifacts, history: task.history,
        responseId: task.responseId, attempts: task.attempts, inputTokens: task.inputTokens, outputTokens: task.outputTokens,
        model: task.model, approvalId: task.approvalId, acceptance: task.acceptance,
        ...(task.onBehalfUser ? { onBehalfUser: task.onBehalfUser } : {}),
        createdAt: task.createdAt, startedAt: task.startedAt, finishedAt: task.finishedAt,
      }
    }
    return {
      taskId: task.taskId, contextId: task.contextId, agentId: task.agentId, agentSlug: task.agentSlug,
      callerSubject: task.callerSubject, callerAutonomy: task.callerAutonomy, targetAutonomy: task.targetAutonomy,
      mode: task.mode, state: task.state, stateReason: task.stateReason, dataClass: task.dataClass,
      contentRedacted: true,
      redactionHint: t('正文已按权限脱敏（需任务发起方、验收员或平台管理员权限查看任务正文与交付物）'),
      // Négociation et historique ne conservent que le squelette d'état, sans le texte des offres ni celui des flux
      negotiation: task.negotiation
        ? { round: task.negotiation.round, maxRounds: task.negotiation.maxRounds, status: task.negotiation.status, offers: [] }
        : undefined,
      artifacts: task.artifacts.map((artifact) => ({ ...artifact, content: undefined, redacted: true })),
      history: task.history.map((entry) => ({ ...entry, text: undefined })),
      responseId: task.responseId, attempts: task.attempts, inputTokens: task.inputTokens, outputTokens: task.outputTokens,
      model: task.model, approvalId: task.approvalId, acceptance: task.acceptance,
      ...(task.onBehalfUser ? { onBehalfUser: task.onBehalfUser } : {}),
      createdAt: task.createdAt, startedAt: task.startedAt, finishedAt: task.finishedAt,
    }
  }

  /**
   * Lecture de tâche (vue de gouvernance) : visible par l'initiateur lui-même, `*` ou le détenteur de a2a.directory.read, mais **corps anonymisé selon les permissions** (Q-5).
   * Un point de lecture de gouvernance ne doit pas équivaloir à « droit de lecture du texte intégral de toutes les tâches de la plateforme » — message/artifacts/texte de négociation/historique
   * sont le corps métier : visibles uniquement par l'initiateur lui-même, le réceptionnaire (a2a.task.accept) ou un administrateur plateforme.
   */
  getTask(caller: CallerRefLike, taskId: string): A2aTaskRecord {
    const task = this.tasks().findOne((item) => item.taskId === taskId)
    if (!task) throw new NotFoundError(t('A2A 任务不存在：{id}', { id: taskId }))
    // L'appartenance prime sur la convergence organisationnelle (P1-01) : l'initiateur lit toujours ses propres tâches — les identifiants d'intégration externes
    // (refType=external) n'ont pas d'appartenance organisationnelle, le jugement organisationnel est donc toujours false pour eux ; si l'organisation était testée en premier, le court-circuit
    // d'appartenance serait inatteignable et la boucle tierce « confier un travail → tasks/get/list/cancel/SSE » se casserait.
    // L'isolation organisationnelle (Q-4) ne contraint que la lecture de gouvernance des **non-initiateurs**, sans changer la sémantique existante « l'initiateur voit les siennes ».
    const isOwner = task.callerPrincipalId === caller.principalId
    if (!isOwner) {
      // Isolation organisationnelle (Q-4) : un compte d'organisation inférieure, même détenteur d'une permission de lecture de gouvernance, ne lit que les ressources de son sous-arbre organisationnel
      if (!this.canSeeOrg(caller, task.agentId)) {
        throw new ForbiddenError(t('无权查看该任务（超出你的组织可见范围）'))
      }
      if (!caller.permissions.includes('*') && !caller.permissions.includes('a2a.directory.read')) {
        throw new ForbiddenError(t('无权查看该任务（仅发起方或治理视图持有者）'))
      }
    }
    return task
  }

  /**
   * Visibilité organisationnelle (même périmètre que R11) : `*` = tout ; humain = sous-arbre de son propre orgId ; machine = sous-arbre de l'orgId de l'Agent auquel elle est liée ;
   * sans appartenance = fail-closed, ensemble vide. Pour une tâche de collaboration inter-organisations (appelant et appelé d'organisations différentes), le jugement se fait sur l'organisation de l'employé appelé.
   */
  private canSeeOrg(caller: CallerRefLike, targetAgentId: string): boolean {
    if (caller.permissions.includes('*')) return true
    let orgId = caller.userId ? this.ctx.iam.users().get(caller.userId)?.orgId : undefined
    if (!orgId && caller.kind === 'machine' && caller.refType === 'agent' && caller.refId) {
      orgId = this.ctx.resourceCore.collection('agent').get(caller.refId)?.orgId
    }
    if (!orgId) return false
    const targetOrg = this.ctx.resourceCore.collection('agent').get(targetAgentId)?.orgId
    if (!targetOrg) return true // les ressources sans appartenance organisationnelle (données existantes) ne disparaissent pas à cause du filtre organisationnel
    return this.ctx.iam.orgSubtreeIds(orgId).includes(targetOrg)
  }

  /** Ensemble des organisations visibles (pour le filtrage unifié des vues de gouvernance en liste). */
  private visibleOrgIds(caller: CallerRefLike): Set<string> | null {
    if (caller.permissions.includes('*')) return null
    let orgId = caller.userId ? this.ctx.iam.users().get(caller.userId)?.orgId : undefined
    if (!orgId && caller.kind === 'machine' && caller.refType === 'agent' && caller.refId) {
      orgId = this.ctx.resourceCore.collection('agent').get(caller.refId)?.orgId
    }
    if (!orgId) return new Set<string>() // fail-closed : sans appartenance = ensemble vide
    return new Set(this.ctx.iam.orgSubtreeIds(orgId))
  }

  /** Jugement strict de propriété des opérations en écriture sur les tâches (annulation/poursuite/retour de recette) (Q-2). */
  private assertTaskOwner(task: A2aTaskRecord, caller: CallerRefLike, action: string): void {
    if (task.callerPrincipalId === caller.principalId || caller.permissions.includes('*')) return
    throw new ForbiddenError(t('仅任务发起方可{action}该任务（治理读权限不含写语义）', { action }))
  }

  listTasks(filter: { agentId?: string; contextId?: string; state?: string; callerPrincipalId?: string; limit?: number }, caller?: CallerRefLike): A2aTaskRecord[] {
    // Sans caller (appel de gouvernance interne à la plateforme) ou `*` → pas de convergence ; sinon filtre « tâches propres ∪ organisations visibles ».
    const unrestricted = !caller || caller.permissions.includes('*')
    return this.tasks().all()
      .filter((task) => (filter.agentId ? task.agentId === filter.agentId : true))
      .filter((task) => (filter.contextId ? task.contextId === filter.contextId : true))
      .filter((task) => (filter.state ? task.state === filter.state : true))
      .filter((task) => (filter.callerPrincipalId ? task.callerPrincipalId === filter.callerPrincipalId : true))
      // L'appartenance prime (P1-01) : l'initiateur voit toujours ses propres tâches ; l'isolation organisationnelle (Q-4) ne converge que la lecture de gouvernance des non-initiateurs.
      // Les identifiants d'intégration externes (refType=external) n'ont pas d'appartenance organisationnelle : avec un filtre purement organisationnel, tasks/list serait toujours vide pour eux.
      .filter((task) => {
        if (unrestricted) return true
        if (task.callerPrincipalId === caller.principalId) return true
        return this.canSeeOrg(caller, task.agentId)
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, Math.min(filter.limit ?? 100, 500))
  }

  /** Annulation (opération en écriture) : jugement strict de propriété — le point de lecture de gouvernance n'emporte pas de sémantique d'écriture inter-sujets (Q-2). */
  cancelTask(caller: CallerRefLike, taskId: string, reason: string): A2aTaskRecord {
    const task = this.getTask(caller, taskId)
    this.assertTaskOwner(task, caller, '取消')
    if (A2A_TERMINAL_STATES.includes(task.state)) throw new Error(t('任务已终态（{state}），不可取消', { state: task.state }))
    this.transition(taskId, 'canceled', reason || t('调用方主动取消'))
    this.ctx.platformBus.emit('a2a.task.cancel', { taskId, reason })
    this.auditTask(this.tasks().findOne((item) => item.taskId === taskId)!, 'a2a.task.canceled', 'ok', reason)
    return this.tasks().findOne((item) => item.taskId === taskId)!
  }

  /**
   * Recette de livraison (humaine) : Task completed ≠ clôture métier, l'archivage n'a lieu qu'après recette validée (plan de collaboration §6.3, la recette ne fait pas confiance à l'auto-déclaration).
   * Séparation des responsabilités (Q-30) : l'initiateur ne peut pas recetter la tâche qu'il a initiée — sinon le taux de recette pourrait être gonflé par auto-recette.
   */
  acceptTask(actor: { userId: string; name: string }, taskId: string, decision: 'accepted' | 'rejected', reason: string): A2aTaskRecord {
    const task = this.tasks().findOne((item) => item.taskId === taskId)
    if (!task) throw new NotFoundError(t('A2A 任务不存在：{id}', { id: taskId }))
    if (task.state !== 'completed') throw new Error(t('仅 completed 任务可验收（当前 {state}）——不轻信自报，未完成不进验收', { state: task.state }))
    if (!reason.trim()) throw new Error(t('验收必须填写理由（护栏要求）'))
    if (task.callerUserId === actor.userId) {
      throw new ForbiddenError(t('职责分离：任务发起人不可验收自己发起的任务（请由其他验收人复核）'))
    }
    this.tasks().update(task.id, { acceptance: { status: decision, by: actor.userId, at: new Date().toISOString(), reason } })
    this.ctx.audit.record({
      type: 'change', actorType: 'human', actorId: actor.userId, actorName: actor.name,
      action: 'a2a.task.acceptance', resourceType: 'agent', resourceId: task.agentId, resourceName: task.agentSlug,
      result: 'ok', detail: `task=${taskId} decision=${decision} reason=${reason}`,
    })
    return this.tasks().findOne((item) => item.taskId === taskId)!
  }

  /** Vue de performance de collaboration (reçus/taux d'achèvement/durées/nombre d'interruptions/taux de recette). */
  fulfillment(caller?: CallerRefLike) {
    const all = this.listTasks({}, caller)
    const byAgent = new Map<string, A2aTaskRecord[]>()
    for (const task of all) {
      const list = byAgent.get(task.agentId) ?? []
      list.push(task)
      byAgent.set(task.agentId, list)
    }
    const durations = (tasks: A2aTaskRecord[]) => tasks
      .filter((task) => task.startedAt && task.finishedAt)
      .map((task) => new Date(task.finishedAt!).getTime() - new Date(task.startedAt!).getTime())
      .sort((a, b) => a - b)
    const p95 = (values: number[]) => values.length === 0 ? 0 : values[Math.min(values.length - 1, Math.max(0, Math.ceil(values.length * 0.95) - 1))]!
    return [...byAgent.entries()].map(([agentId, tasks]) => {
      const completed = tasks.filter((task) => task.state === 'completed')
      const accepted = tasks.filter((task) => task.acceptance?.status === 'accepted')
      const agent = this.ctx.resourceCore.get('agent', agentId)
      const avg = durations(tasks)
      return {
        agentId,
        agentSlug: agent?.slug ?? tasks[0]?.agentSlug ?? agentId,
        agentName: agent?.name ?? tasks[0]?.agentSlug ?? agentId,
        received: tasks.length,
        completed: completed.length,
        failed: tasks.filter((task) => task.state === 'failed').length,
        canceled: tasks.filter((task) => task.state === 'canceled').length,
        rejected: tasks.filter((task) => task.state === 'rejected').length,
        interrupted: tasks.filter((task) => task.state === 'input_required' || task.state === 'auth_required').length,
        acceptanceAccepted: accepted.length,
        acceptanceRejected: tasks.filter((task) => task.acceptance?.status === 'rejected').length,
        completionRate: tasks.length === 0 ? 0 : Math.round((completed.length / tasks.length) * 1000) / 1000,
        acceptancePassRate: completed.length === 0 ? 0 : Math.round((accepted.length / completed.length) * 1000) / 1000,
        avgDurationMs: avg.length === 0 ? 0 : Math.round(avg.reduce((sum, value) => sum + value, 0) / avg.length),
        p95DurationMs: p95(avg),
        inputTokens: tasks.reduce((sum, task) => sum + (task.inputTokens ?? 0), 0),
        outputTokens: tasks.reduce((sum, task) => sum + (task.outputTokens ?? 0), 0),
      }
    }).sort((a, b) => b.received - a.received)
  }

  /** Inspection de cohérence déclaration-autorisation (gouvernance de la dérive des capacités) : déclaration de carte ∩ ensemble d'autorisations vs auto-déclaration du harness/registre. */
  runPatrol(actor: string): A2aPatrolRecord {
    const findings: A2aPatrolRecord['findings'] = []
    const online = this.ctx.resourceCore.list('agent').filter((item) => item.status === 'online')
    for (const agent of online) {
      const issues: string[] = []
      const attrs = agent.attrs
      // ① Dérive de déclaration de compétences : attrs.skills référence un Skill non published (retrait/dépréciation non synchronisés)
      const slugs = Array.isArray(attrs['skills']) ? (attrs['skills'] as unknown[]).map(String) : []
      for (const slug of slugs) {
        const skill = this.ctx.skillHub.skills().find((item) => item.slug === slug)[0]
        if (!skill || skill.status !== 'published') issues.push(t('声明漂移：引用的 Skill「{slug}」已不在架（发布状态 {status}），卡片不会投影（声明≤授权已兜底），请清理 attrs.skills', { slug, status: skill?.status ?? '不存在' }))
      }
      // ② Dérive de groupe de permissions MCP : le groupe de permissions référencé a été supprimé
      for (const group of this.ctx.mcpRegistry.permGroups().all()) {
        void group
      }
      const groupSubjects = this.ctx.mcpRegistry.permGroups().all().filter((group) => group.subjects.some((subject) => subject.type === 'agent' && subject.id === agent.id))
      for (const permGroupId of Array.isArray(attrs['mcpPermGroupIds']) ? (attrs['mcpPermGroupIds'] as unknown[]).map(String) : []) {
        if (!this.ctx.mcpRegistry.permGroups().get(permGroupId)) issues.push(t('授权漂移：登记的 MCP 权限组 {id} 已不存在，请清理 mcpPermGroupIds', { id: permGroupId }))
      }
      // ③ Dérive du registre harness : uhpHarnessRef pointe vers un harness absent/désactivé/au modèle hors ligne (uhpGateway est désormais dans inject —
      //    sonde de gouvernance en lecture seule ; le flux d'états de collaboration de tâches passe toujours par le bus ; l'exception de discipline est enregistrée dans les notes de publication contract-c3 v2)
      const harnessRef = String(attrs['uhpHarnessRef'] ?? '').trim()
      if (harnessRef) {
        const harness = this.ctx.uhpGateway.harnesses().get(harnessRef)
        if (!harness) issues.push(t('harness 漂移：uhpHarnessRef 指向的 {id} 不存在，执行将诚实失败', { id: harnessRef }))
        else if (!harness.enabled) issues.push(t('harness 漂移：{id} 已停用', { id: harnessRef }))
        else {
          const model = this.ctx.modelGateway.models().find((item) => item.slug === harness.model)[0]
          if (!model || model.status !== 'online') issues.push(t('harness 漂移：{id} 绑定模型 {model} 不在线', { id: harnessRef, model: harness.model }))
        }
      }
      // ④ Cohérence du plafond : le plafond A2A ne doit pas dépasser le mapping de niveau confidentiel atteignable par le canal modelgw (rappel du mapping explicite D14)
      if (attrs['a2aDataClassCeiling'] === 'secret' && String(attrs['dataClass'] ?? '') === 'secret') {
        issues.push(t('密级口径提示：A2A 天花板=secret 且业务密级=secret（绝密禁止 Agent 处理口径），执行面将按渠道锁死拒绝——请确认口径'))
      }
      if (issues.length > 0) {
        findings.push({ agentId: agent.id, agentName: agent.name, findings: issues })
        this.ctx.audit.fire({
          severity: 'warning',
          title: t('数字员工「{name}」声明-授权一致性巡检发现 {n} 项漂移', { name: agent.name, n: issues.length }),
          message: issues.join('；'),
          resourceType: 'agent',
          resourceId: agent.id,
        })
      }
      void groupSubjects
    }
    const report: A2aPatrolRecord = {
      id: newId('a2ap'),
      at: new Date().toISOString(),
      actor,
      checkedAgents: online.length,
      driftAgents: findings.length,
      findings,
    }
    this.patrols().insert(report)
    this.ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'a2a-patrol', actorName: 'A2A 一致性巡检',
      action: 'a2a.patrol.run', resourceType: 'platform', resourceId: 'a2a', resourceName: t('协作平面'),
      result: 'ok', detail: t('巡检 {checked} 名在线员工，{drift} 名存在漂移', { checked: online.length, drift: findings.length }),
    })
    return report
  }

  /** Reprise d'exécution (callback de l'exécuteur après approbation) : auth_required → submitted → distribution (l'anti-doublon est garanti par la clé attempts). */
  resumeFromApproval(taskId: string): void {
    const task = this.tasks().findOne((item) => item.taskId === taskId)
    if (!task || task.state !== 'auth_required') return
    this.dispatchTask(task)
  }
}

// ---------------------------------------------------------------------------
// Types internes et erreurs
// ---------------------------------------------------------------------------

interface CallerRefLike {
  kind: 'human' | 'machine'
  principalId: string
  userId?: string
  refType?: string
  refId?: string
  name: string
  permissions: string[]
  actChain?: Array<{ name: string; type: string }>
  /** Vrai initiateur OBO (Q-6) : quand un humain initie une collaboration pour le compte d'un employé via un jeton OBO, résolu depuis la chaîne act du jeton. */
  onBehalfOfUser?: string
  /** Chaîne d'identité OBO complète (transmise à la facette d'exécution UHP ; l'audit peut reconstituer « qui au nom de qui »). */
  oboActChain?: Array<{ principalId: string; name: string; type: string }>
}

interface UhpProgressLike {
  taskId?: string
  responseId?: string
  phase: 'started' | 'delta' | 'completed' | 'failed' | 'canceled'
  text?: string
  error?: string
  inputTokens?: number
  outputTokens?: number
  model?: string
}

export class NotFoundError extends Error {}
export class ForbiddenError extends Error {}
export class GovernanceError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    a2aCollab: A2aCollabService
  }
}

export const name = 'a2a'
// uhpGateway : sonde de gouvernance en lecture seule du registre harness pour l'inspection de cohérence déclaration-autorisation (inject cordis force la déclaration explicite ;
// lecture du registre seule, le flux d'états de collaboration de tâches passe toujours par ctx.platformBus — exception de discipline enregistrée dans les notes de publication contract-c3 v2).
// workforceIdentity : source de jugement **unique** pour la couverture permit du contrôle de gouvernance n° 2 (P2-01 : l'omission de déclaration faisait
// lever le proxy Service en lisant une clé non injectée, l'exception était avalée par le catch et le passage se faisait en legacy, le contrôle n° 2 était une no-op).
export const inject = ['opsStorage', 'platformBus', 'httpServer', 'resourceCore', 'authn', 'iam', 'audit', 'usage', 'modelGateway', 'skillHub', 'mcpRegistry', 'agentRegistry', 'uhpGateway', 'workforceIdentity']

export function apply(ctx: Context) {
  const collab = new A2aCollabService(ctx)
  const gate = createRestGate(ctx)
  // Convention de nommage : l'alias http permet au scanner de littéraux de routes de contract-lint de reconnaître la surface déclarée http.register
  const http = ctx.httpServer

  // Au démarrage, enregistrement idempotent des points de permission A2A dans le PermissionCatalog d'iam (précédent : enregistrement des exec.read/exec.write de plugin-agent)
  for (const entry of [
    { point: 'a2a.directory.read', label: '读取 A2A 协作目录与任务治理视图', group: 'A2A 协作' },
    { point: 'a2a.task.accept', label: 'A2A 协作任务交付验收', group: 'A2A 协作' },
    { point: 'a2a.admin', label: '管理 A2A 审批规则与一致性巡检', group: 'A2A 协作' },
  ]) {
    if (!PermissionCatalog.some((item) => item.point === entry.point)) PermissionCatalog.push(entry)
  }

  // -- Découverte de l'Agent Card (well-known de la spécification A2A ; JSON nu — consommable directement par un analyseur générique externe, voir Q-31) ----
  const sendRawJson = (exchange: HttpExchange, payload: unknown): void => {
    if (exchange.res.headersSent) return
    exchange.res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
    exchange.res.end(JSON.stringify(payload))
  }
  const wellKnownCard = (exchange: HttpExchange, slug: string) => {
    const agent = collab.resolveAgent(slug)
    if (!agent || agent.status !== 'online') {
      exchange.fail(404, 'NOT_FOUND', t('数字员工不存在或未上线：{slug}', { slug }))
      return
    }
    // La spécification A2A exige que well-known renvoie le corps de carte nu (auparavant enveloppé dans l'enveloppe plateforme {ok,data}, inexploitable par les analyseurs externes)
    sendRawJson(exchange, collab.cardFor(agent))
  }
  http.register('GET', '/.well-known/agent-card.json', (exchange) => {
    sendRawJson(exchange, collab.platformCard())
  })
  http.register('GET', '/.well-known/agents/:slug/agent-card.json', (exchange) => {
    wellKnownCard(exchange, exchange.params['slug'] ?? '')
  })

  // -- Recherche d'annuaire (découverte inter-runtimes, point de permission a2a.directory.read) -----------------------------------
  gate.guarded('GET', '/api/a2a/directory', 'a2a.directory.read', (exchange) => {
    const caller = gate.caller(exchange)
    return {
      agents: collab.directory({
        skill: exchange.query.get('skill') ?? undefined,
        q: exchange.query.get('q') ?? undefined,
        runtime: exchange.query.get('runtime') ?? undefined,
        autonomy: exchange.query.get('autonomy') ?? undefined,
        dataClass: exchange.query.get('dataClass') ?? undefined,
        category: exchange.query.get('category') ?? undefined,
      }, caller),
    }
  })

  // -- Point d'accès principal A2A (JSON-RPC 2.0 ; réutilise le point de permission v1 agent.a2a.invoke) ---------------------------
  const jsonRpcError = (exchange: HttpExchange, id: unknown, code: number, message: string, data?: Record<string, unknown>) => {
    exchange.ok({ jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data ? { data } : {}) } })
  }
  gate.guarded('POST', '/api/agents/:slug/a2a', 'agent.a2a.invoke', async (exchange) => {
    const body = gate.body<{ jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> }>(exchange)
    const id = body.id ?? null
    const method = String(body.method ?? '')
    const params = (body.params ?? {}) as {
      message?: string | { parts?: Array<{ kind?: string; text?: string }>; text?: string }
      metadata?: Record<string, unknown>
      taskId?: string
      contextId?: string
      state?: string
      limit?: number
      reason?: string
    }
    const caller = gate.caller(exchange)
    const extractText = (): string => {
      if (typeof params.message === 'string') return params.message
      if (typeof params.message?.text === 'string') return params.message.text
      const parts = params.message?.parts ?? []
      return parts.map((part) => part.text ?? '').filter(Boolean).join('\n')
    }
    const metadata = params.metadata ?? {}
    // Chaîne d'identité OBO (Q-6) : quand la chaîne act du jeton contient un humain (jeton OBO), le vrai initiateur est écrit dans la tâche et l'audit —
    // l'identité vient toujours du résultat de résolution du jeton, interdiction de l'auto-déclarer dans metadata (même discipline que la ligne rouge NAS X-On-Behalf-User).
    const obo = actChainOf(ctx, exchange)
    const effectiveCaller: CallerRefLike = obo ? { ...caller, onBehalfOfUser: obo.principalId, oboActChain: obo.actChain } : caller
    try {
      if (method === 'message/send' || method === 'message/stream') {
        const task = await collab.sendMessage({
          caller: effectiveCaller,
          agentRef: exchange.params['slug'] ?? '',
          message: extractText(),
          ...(typeof metadata['dataClass'] === 'string' ? { dataClass: metadata['dataClass'] } : {}),
          ...(typeof metadata['contextId'] === 'string' ? { contextId: metadata['contextId'] } : {}),
          ...(typeof metadata['taskId'] === 'string' ? { taskId: metadata['taskId'] } : {}),
          negotiation: metadata['negotiation'],
        })
        // Isomorphisme de protocole Q-8 : message/send et message/stream renvoient tous deux la Task dans l'enveloppe JSON-RPC ;
        // la progression en flux est portée par le point SSE dédié (/v1/a2a/tasks/:taskId/events, déclaré dans l'Agent Card) —
        // le même point ne renvoie plus de SSE nu, les clients externes n'écrivent plus deux branches d'analyse pour la même URL.
        // Attente synchrone jusqu'à l'état final ou dépassement (les tâches longues continuent via tasks/get / SSE)
        const settled = await waitForTerminal(collab, task.taskId, Number(process.env.A2A_SYNC_WAIT_MS ?? 12000))
        return { jsonrpc: '2.0', id, result: { task: collab.taskView(settled, caller) } }
      }
      if (method === 'tasks/get') {
        const task = collab.getTask(caller, String(params.taskId ?? ''))
        return { jsonrpc: '2.0', id, result: { task: collab.taskView(task, caller) } }
      }
      if (method === 'tasks/list') {
        const tasks = collab.listTasks({
          ...(typeof metadata['agentId'] === 'string' ? { agentId: metadata['agentId'] } : {}),
          ...(typeof params.contextId === 'string' ? { contextId: params.contextId } : {}),
          ...(typeof params.state === 'string' ? { state: params.state } : {}),
          callerPrincipalId: caller.permissions.includes('*') || caller.permissions.includes('a2a.directory.read') ? undefined : caller.principalId,
          limit: typeof params.limit === 'number' ? params.limit : 50,
        }, effectiveCaller)
        return { jsonrpc: '2.0', id, result: { tasks: tasks.map((task) => collab.taskView(task, caller)) } }
      }
      if (method === 'tasks/cancel') {
        const task = collab.cancelTask(caller, String(params.taskId ?? ''), String(params.reason ?? ''))
        return { jsonrpc: '2.0', id, result: { task: collab.taskView(task, caller) } }
      }
      jsonRpcError(exchange, id, -32601, t('未知 A2A 方法：{method}（支持 message/send·stream、tasks/get·list·cancel）', { method }))
    } catch (error) {
      if (error instanceof NotFoundError) return jsonRpcError(exchange, id, -32001, error.message)
      if (error instanceof GovernanceError) return jsonRpcError(exchange, id, -32002, error.message, { code: error.code })
      // Les refus de propriété/portes d'écriture utilisent le code réservé -32003 (distingué de l'erreur de paramètre -32000, pour faciliter le tri côté client et audit)
      if (error instanceof ForbiddenError) return jsonRpcError(exchange, id, -32003, error.message, { code: 'FORBIDDEN' })
      return jsonRpcError(exchange, id, -32000, error instanceof Error ? error.message : String(error))
    }
  })

  // -- Événements de tâches en flux (SSE ; facette protocole /v1 auto-validée ?token=, EventSource ne peut pas porter de Bearer) ----------------
  http.register('GET', '/v1/a2a/tasks/:taskId/events', (exchange) => {
    const token = exchange.query.get('token') ?? ''
    if (!token) {
      ctx.platformBus.emit('audit.authz.denied', { actorId: '(anon)', actorName: t('匿名请求'), point: 'a2a.task.events', path: exchange.path, detail: t('缺少 token 参数') })
      exchange.fail(401, 'UNAUTHORIZED', t('缺少 token 参数（SSE 端点自校验，fail-closed）'))
      return
    }
    let verified: VerifiedPrincipal
    try {
      verified = ctx.authn.verify(token)
    } catch (error) {
      // Q-28 : jeton invalide/expiré mappé en 401 (même périmètre que l'authentification du domaine /api), plus de mélange avec les erreurs 400 de paramètre ; le chemin de refus laisse une trace (Q-27)
      ctx.platformBus.emit('audit.authz.denied', { actorId: '(anon)', actorName: t('匿名请求'), point: 'a2a.task.events', path: exchange.path, detail: t('令牌校验失败') })
      exchange.fail(401, 'TOKEN_INVALID', error instanceof Error ? error.message : String(error))
      return
    }
    try {
      if (!verified.scopes.includes('agent.a2a.invoke') && !verified.scopes.includes('*') && !verified.scopes.includes('a2a.directory.read')) {
        ctx.platformBus.emit('audit.authz.denied', { actorId: verified.principal.id, actorName: verified.principal.name, point: 'a2a.task.events', path: exchange.path })
        exchange.fail(403, 'FORBIDDEN', t('缺少权限点 agent.a2a.invoke / a2a.directory.read'))
        return
      }
      const caller: CallerRefLike = {
        kind: verified.principal.type, principalId: verified.principal.id, name: verified.principal.name,
        permissions: verified.scopes,
        ...(verified.principal.refType ? { refType: verified.principal.refType } : {}),
        ...(verified.principal.refId ? { refId: verified.principal.refId } : {}),
      }
      const task = collab.getTask(caller, exchange.params['taskId'] ?? '')
      streamTaskEvents(exchange, ctx, collab, task.taskId, caller)
    } catch (error) {
      // Q-28 : tri sémantique — inexistant 404 / sans droit 403 / le reste 400
      if (error instanceof NotFoundError) { exchange.fail(404, 'NOT_FOUND', error.message); return }
      if (error instanceof ForbiddenError) { exchange.fail(403, 'FORBIDDEN', error.message); return }
      exchange.fail(400, 'BAD_REQUEST', error instanceof Error ? error.message : String(error))
    }
  })

  // -- REST des vues de gouvernance (source de données console ; permission de lecture d'annuaire suffit pour lire, la recette a son point de permission propre) ------------------------
  gate.guarded('GET', '/api/a2a/tasks', 'a2a.directory.read', (exchange) => {
    const caller = gate.caller(exchange)
    return {
      tasks: collab.listTasks({
        agentId: exchange.query.get('agentId') ?? undefined,
        contextId: exchange.query.get('contextId') ?? undefined,
        state: exchange.query.get('state') ?? undefined,
        limit: Number(exchange.query.get('limit') ?? 100) || 100,
      }, caller).map((task) => collab.taskView(task, caller)),
    }
  })
  gate.guarded('GET', '/api/a2a/tasks/:taskId', 'a2a.directory.read', (exchange) => {
    const caller = gate.caller(exchange)
    // Q-29 : le détail REST et le RPC tasks/get partagent la même implémentation (getTask), élimine deux périmètres d'appartenance
    try {
      return { task: collab.taskView(collab.getTask(caller, exchange.params['taskId'] ?? ''), caller) }
    } catch (error) {
      if (error instanceof NotFoundError) { exchange.fail(404, 'NOT_FOUND', error.message); return }
      if (error instanceof ForbiddenError) { exchange.fail(403, 'FORBIDDEN', error.message); return }
      throw error
    }
  })
  gate.guarded('POST', '/api/a2a/tasks/:taskId/acceptance', 'a2a.task.accept', (exchange) => {
    const input = gate.body<{ decision?: string; reason?: string }>(exchange)
    const info = gate.caller(exchange)
    if (info.kind !== 'human' || !info.userId) {
      exchange.fail(403, 'FORBIDDEN', t('交付验收仅限人类用户（验收不轻信自报，人在环收口）'))
      return
    }
    const decision = input.decision === 'rejected' ? 'rejected' : input.decision === 'accepted' ? 'accepted' : ''
    if (!decision) {
      exchange.fail(400, 'BAD_REQUEST', t('decision 必须为 accepted / rejected'))
      return
    }
    try {
      const task = collab.acceptTask({ userId: info.userId, name: info.name }, exchange.params['taskId'] ?? '', decision, String(input.reason ?? ''))
      return { task: collab.taskView(task, info) }
    } catch (error) {
      if (error instanceof ForbiddenError) { exchange.fail(403, 'FORBIDDEN', error.message); return }
      throw error
    }
  })
  gate.guarded('GET', '/api/a2a/fulfillment', 'a2a.directory.read', (exchange) => ({ fulfillment: collab.fulfillment(gate.caller(exchange)) }))

  // -- Règles d'approbation et inspection (a2a.admin) ----------------------------------------------------------
  gate.guarded('GET', '/api/a2a/rules', 'a2a.directory.read', () => ({ rules: collab.rules().all() }))
  gate.guarded('POST', '/api/a2a/rules', 'a2a.admin', (exchange) => {
    const input = gate.body<{ name?: string; matchDataClassAtLeast?: string; matchKeyword?: string; enabled?: boolean }>(exchange)
    if (!input.name?.trim()) throw new Error(t('规则名称必填'))
    if (!input.matchDataClassAtLeast && !input.matchKeyword) throw new Error(t('至少配置一个匹配条件（matchDataClassAtLeast / matchKeyword）'))
    if (input.matchDataClassAtLeast && input.matchDataClassAtLeast !== 'internal' && input.matchDataClassAtLeast !== 'secret') {
      throw new Error(t('matchDataClassAtLeast 仅支持 internal / secret'))
    }
    const rule = collab.rules().insert({
      id: newId('a2ar'),
      name: input.name,
      ...(input.matchDataClassAtLeast ? { matchDataClassAtLeast: input.matchDataClassAtLeast as 'internal' | 'secret' } : {}),
      ...(input.matchKeyword ? { matchKeyword: input.matchKeyword } : {}),
      enabled: input.enabled ?? true,
      createdBy: gate.actorOf(exchange),
    })
    gate.changeLog(exchange, 'a2a.rule.create', 'a2a_rule', rule.id, rule.name)
    return { rule }
  })
  gate.guarded('DELETE', '/api/a2a/rules/:id', 'a2a.admin', (exchange) => {
    const removed = collab.rules().remove(exchange.params['id'] ?? '')
    if (!removed) {
      exchange.fail(404, 'NOT_FOUND', t('规则不存在：{id}', { id: exchange.params['id'] ?? '' }))
      return
    }
    gate.changeLog(exchange, 'a2a.rule.delete', 'a2a_rule', exchange.params['id'] ?? '', exchange.params['id'] ?? '')
    return { deleted: true }
  })
  gate.guarded('POST', '/api/a2a/patrol/run', 'a2a.admin', (exchange) => {
    const report = collab.runPatrol(gate.actorOf(exchange))
    return { report }
  })
  gate.guarded('GET', '/api/a2a/patrols', 'a2a.directory.read', (exchange) => ({
    patrols: collab.patrols().all().sort((a, b) => b.at.localeCompare(a.at)).slice(0, Math.min(Number(exchange.query.get('limit') ?? 20) || 20, 100)),
  }))

  // -- Exécuteur d'approbation : a2a.task.authorize validé → reprise d'exécution (anti-doublon idempotent) ------------------------------
  ctx.effect(() => ctx.audit.registerExecutor('a2a.task.authorize', async (payload) => {
    collab.resumeFromApproval(String(payload.taskId ?? ''))
    return { resumed: true }
  }))

  // -- Inspection de cohérence récurrente (gouvernance de la dérive des capacités ; A2A_PATROL_INTERVAL_MINUTES, défaut 60, 0=désactivé) -------------
  const intervalMinutes = Number(process.env.A2A_PATROL_INTERVAL_MINUTES ?? 60)
  if (Number.isFinite(intervalMinutes) && intervalMinutes > 0) {
    const first = setTimeout(() => {
      try { collab.runPatrol('system-routine') } catch (error) { ctx.logger('a2a').warn('例行一致性巡检失败', error) }
    }, 60_000)
    first.unref?.()
    const timer = setInterval(() => {
      try { collab.runPatrol('system-routine') } catch (error) { ctx.logger('a2a').warn('例行一致性巡检失败', error) }
    }, intervalMinutes * 60_000)
    timer.unref?.()
    ctx.effect(() => () => {
      clearTimeout(first)
      clearInterval(timer)
    })
  }
}

// ---------------------------------------------------------------------------
// Outils partagés (attente synchrone + flux SSE)
// ---------------------------------------------------------------------------

/**
 * Résolution de la chaîne d'identité OBO (Q-6) : une entrée type=human dans la chaîne act du jeton signifie « agit au nom de cet humain » —
 * renvoie le principalId du vrai initiateur et la chaîne complète, pour les enregistrements de tâche/l'audit/la transmission dispatch ; renvoie undefined pour un jeton non OBO.
 * Gouvernance MCP (contrat §2/§4, 2026-10-22) : sémantique alignée sur humanDelegatorOf de platform-core — l'entrée human de tête
 * (premier élément du tableau, initiateur selon la sémantique issueOnBehalfOf « chaîne parentale + sujet parent ») est le vrai initiateur ; les faits d'identité
 * ne viennent que du résultat de résolution du jeton (verify auto-validé), interdiction de déclarer depuis les paramètres/headers de la requête. Comportement externe inchangé.
 */
function actChainOf(ctx: Context, exchange: HttpExchange): { principalId: string; actChain: Array<{ principalId: string; name: string; type: string }> } | undefined {
  const header = String(exchange.headers['authorization'] ?? '')
  const token = header.startsWith('Bearer ') ? header.slice(7) : header
  if (!token) return undefined
  try {
    const verified = ctx.authn.verify(token)
    const human = verified.actChain.find((entry) => entry.type === 'human')
    if (!human) return undefined
    return {
      principalId: human.principalId,
      actChain: verified.actChain.map((entry) => ({ principalId: entry.principalId, name: entry.name, type: entry.type })),
    }
  } catch {
    return undefined // le jeton a déjà été validé par le middleware d'authentification ; ici on ne fait qu'extraire l'identité, sans redemander d'erreur
  }
}

async function waitForTerminal(collab: A2aCollabService, taskId: string, timeoutMs: number) {
  const deadline = Date.now() + Math.max(timeoutMs, 0)
  for (;;) {
    const task = collab.tasks().findOne((item) => item.taskId === taskId)
    if (!task) throw new Error(t('A2A 任务不存在：{id}', { id: taskId }))
    if (A2A_TERMINAL_STATES.includes(task.state) || Date.now() >= deadline) return task
    await new Promise((resolve) => setTimeout(resolve, 200))
  }
}

/** SSE : rejeu de l'historique + abonnement a2a.task.changed / a2a.task.progress jusqu'à l'état final. */
function streamTaskEvents(exchange: HttpExchange, ctx: Context, collab: A2aCollabService, taskId: string, caller?: CallerRefLike): undefined {
  const task = collab.tasks().findOne((item) => item.taskId === taskId)
  if (!task) {
    exchange.fail(404, 'NOT_FOUND', t('A2A 任务不存在：{id}', { id: taskId }))
    return
  }
  const res = exchange.res
  if (res.headersSent) return
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' })
  res.write('retry: 5000\n\n')
  const send = (event: string, data: unknown) => {
    if (!res.writableEnded) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }
  send('task.snapshot', collab.taskView(collab.tasks().findOne((item) => item.taskId === taskId)!, caller))
  if (A2A_TERMINAL_STATES.includes(task.state)) {
    send('task.terminal', { taskId, state: task.state })
    res.end()
    return
  }
  const onProgress = ctx.platformBus.on('a2a.task.progress', (payload) => {
    const p = payload as { taskId?: string; phase: string; text?: string; error?: string }
    if (p.taskId !== taskId) return
    send('task.progress', p)
    if (p.phase === 'completed' || p.phase === 'failed' || p.phase === 'canceled') {
      const latest = collab.tasks().findOne((item) => item.taskId === taskId)
      if (latest) send('task.snapshot', collab.taskView(latest, caller))
      send('task.terminal', { taskId, state: latest?.state ?? p.phase })
      cleanup()
      res.end()
    }
  })
  const onChanged = ctx.platformBus.on('a2a.task.changed', (payload) => {
    const p = payload as { taskId?: string; state: string }
    if (p.taskId !== taskId) return
    const latest = collab.tasks().findOne((item) => item.taskId === taskId)
    if (latest) send('task.snapshot', collab.taskView(latest, caller))
    if (A2A_TERMINAL_STATES.includes(p.state as never) || p.state === 'input_required' || p.state === 'auth_required') {
      send('task.terminal', { taskId, state: p.state })
      cleanup()
      res.end()
    }
  })
  const heartbeat = setInterval(() => {
    if (!res.writableEnded) res.write(': ping\n\n')
  }, 15_000)
  heartbeat.unref?.()
  const cleanup = () => {
    clearInterval(heartbeat)
    onProgress()
    onChanged()
  }
  exchange.raw.on('close', cleanup)
}
