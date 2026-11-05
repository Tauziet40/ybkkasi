/**
 * @dsh-ops/plugin-app —— gestion du corps des Applications IA (plan §6).
 *
 * Réutilise le socle et le cycle de vie de resource-core ; les différences sont portées par un schema d'extension :
 * forme d'application/points d'accès/canaux de publication/topologie d'orchestration d'Agents (application → Agent → MCP/Skill, un graphe traversable).
 * Métriques de la couche application : DAU/MAU, profondeur de session, rétention ; chaîne de coûts : application → Agent → MCP/modèle, consolidation traversante.
 *
 * W2-T4 (contrat de gouvernance MCP §10) : liaison des capacités d'application — montage App ↔ services MCP (app:capabilities),
 * portes de mise en ligne des capacités (CAPABILITY_GATE_FAILED), cascades de retrait/suppression du cycle de vie, arêtes de dépendance capability
 * resource-core (app→mcp), rendant la topologie app→agent→mcp traversable.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { createHash } from 'node:crypto'
import {
  PlatformEvents, newId,
  type Collection, type RecordBase, type ResourceTypeSpec, type TopologyNode,
} from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { OidcService } from '../../plugin-authn/src/oidc.ts'
// W2-T4 (contrat §10) : les enregistrements de services MCP sont importés en type-only (aucun couplage à l'exécution, pour les assertions de type de l'écriture
// des champs additifs de restauration/archivage) ; sensitiveHeaderKeys est une aide en fonction pure (même périmètre que maskServiceHeaders de console,
// /authorization|token|secret|key/i), le contrat partagé autorise explicitement l'import de fonctions pures entre paquets.
import type { McpServiceRecord } from '../../plugin-mcp/src/index.ts'
import { sensitiveHeaderKeys } from '../../plugin-mcp/src/secret-broker.ts'
import * as appTools from './tools.ts'
import { APP_TYPE_SPEC } from './schema.ts'
import { buildAppOnboardingPrompt, type AppOnboardingCredential } from './onboarding.ts'
import { AppCredentialService } from './credentials.ts'
// Consommation du mappage 404 par la couche REST (console routes/apps.ts) : transduction par la sortie unique embarquée
export { AppCredentialMissingError } from './credentials.ts'

export interface AppUsageRecord extends RecordBase {
  appId: string
  date: string
  dau: number
  sessions: number
  avgDepth: number
  retention7: number
  /** Pages vues (cumul sur plusieurs remontées du même jour ; périmètre de remontée proactive de l'intégrateur). */
  pv?: number
  /** Visiteurs uniques du jour (maximum sur plusieurs remontées du même jour, périmètre UV de même sémantique que DAU). */
  uv?: number
}

/**
 * Registre de visiteurs du jour calculé automatiquement côté plateforme (tenu par trackVisit, séparé des lignes usage remontées proactivement par l'intégrateur) :
 * DAU/UV du même jour = taille de l'ensemble (croissant seulement), PV = +1 par visite ; la fusion dans la ligne usage se fait naturellement via les sémantiques max/cumul.
 */
export interface AppVisitRecord extends RecordBase {
  appId: string
  date: string
  /** Utilisateurs dédupliqués ayant visité le jour même sous identité plateforme (conversion échange entry-ticket / émission de code OIDC en DAU). */
  userIds: string[]
  /** Identifiants de visiteurs anonymes du navigateur du jour (conversion beacon en UV ; en cas d'absence, la plateforme retombe sur un hash IP+UA). */
  vids: string[]
}

/** Instantané de l'appelant autorisé à la gestion SSO (utilisateur humain ou identifiant machine ; surface minimale alignée sur le CallerInfo console). */
export interface AppRegistryServiceSsoCaller {
  kind: 'human' | 'machine'
  /** Spécifique machine : id du sujet d'identifiant (ownerId enregistré avec cette valeur = lié). */
  principalId?: string
  /** Spécifique machine : ressource liée à l'identifiant (refType='app'|'agent' avec refId correspondant = lié). */
  refType?: string
  refId?: string
  /** Spécifique human : id d'utilisateur plateforme (comparé au ownerId de la ressource). */
  userId?: string
  permissions: string[]
}

/**
 * Enregistrements de liaison des capacités d'application (W2-T4, contrat de gouvernance MCP §10, collection app:capabilities) :
 * relation de montage App ↔ services MCP. Les capacités required=true participent aux portes de mise en ligne et à la revérification en exécution ;
 * exposure est verrouillé sur gateway (forme d'exposition de fait du plan de données au niveau service §7 ; c'est exposureMode côté service qui porte la configuration d'exposition).
 */
export interface AppCapabilityLink extends RecordBase {
  appId: string
  serviceId: string
  /** Participe aux portes de mise en ligne (true) / montage et affichage seulement (false). */
  required: boolean
  /** Forme d'exposition (verrouillée sur gateway par le contrat §10). */
  exposure: 'gateway'
  /** État de la liaison (délier = supprimer l'enregistrement ; seul active actuellement). */
  status: string
  boundAt: string
  boundBy: string
  /** Trace de la cascade de retrait W2-T4 : état préalable enregistré lors de l'arrêt en cascade, restauré à la remise en ligne de l'application. */
  offlineRestore?: { status: string; grayPercent: number; at: string }
}

/** Conflit de propriété d'une liaison de capacité (ownerEntity du service déjà attribué à un autre sujet) : mappé en 409 OWNER_CONFLICT à la couche REST. */
export class CapabilityOwnerConflictError extends Error {}

export class AppRegistryService extends Service {
  static readonly provide = 'appRegistry'

  constructor(ctx: Context) {
    super(ctx, 'appRegistry')
    ctx.resourceCore.registerType(APP_TYPE_SPEC)
  }

  usage(): Collection<AppUsageRecord> {
    return this.ctx.opsStorage.collection<AppUsageRecord>('app:usage')
  }

  visits(): Collection<AppVisitRecord> {
    return this.ctx.opsStorage.collection<AppVisitRecord>('app:visits')
  }

  register(input: {
    name: string
    slug?: string
    attrs?: Record<string, unknown>
    ownerId: string
    ownerName: string
    orgId: string
    agentIds?: string[]
    withCredential?: boolean
  }) {
    const agentIds = input.agentIds ?? (Array.isArray(input.attrs?.['agentIds']) ? input.attrs!['agentIds'] as string[] : [])
    for (const agentId of agentIds) {
      const agent = this.ctx.resourceCore.get('agent', agentId)
      if (!agent) throw new Error(t('编排的 Agent 不存在：{id}', { id: agentId }))
      if (agent.status !== 'online') throw new Error(t('Agent「{name}」未上线，不能被应用编排', { name: agent.name }))
    }
    const attrs = { ownerName: input.ownerName, ...(input.attrs ?? {}) }
    const app = this.ctx.resourceCore.create('app', { ...input, attrs })
    this.syncAgentDependencies(app.id, agentIds)
    let credential
    if (input.withCredential !== false) {
      credential = this.ctx.authn.createMachineCredential({
        name: `app:${(app as any).slug}`,
        refType: 'app',
        refId: app.id,
        // app.read/app.write : après enregistrement, l'application vérifie son intégration avec son propre identifiant (lecture de soi) et remonte métriques/informations
        //   (metrics-report et PATCH /api/apps/:id exigent tous deux app.write) ; usage.write : consommation en direct auto-déclarée en mesure
        scopes: ['mcp.invoke', 'agent.read', 'skill.read', 'app.read', 'app.write', 'usage.write'],
      })
    }
    this.ctx.platformBus.emit(PlatformEvents.AppRegistered, { id: app.id, name: app.name, actor: input.ownerId, type: 'app', slug: app.slug })
    return { app, credential }
  }

  updateApp(appId: string, patch: { name?: string; attrs?: Record<string, unknown> }) {
    const updated = this.ctx.resourceCore.update('app', appId, patch)
    const agentIds = Array.isArray(updated.attrs['agentIds']) ? updated.attrs['agentIds'] as string[] : []
    this.syncAgentDependencies(appId, agentIds)
    this.ctx.platformBus.emit(PlatformEvents.AppUpdated, { id: appId, name: updated.name, actor: 'console' })
    return updated
  }

  /**
   * Génère le prompt d'intégration (même gabarit qu'à l'enregistrement, source de vérité unique côté plateforme) :
   * rotate=true renouvelle le secret de l'identifiant machine (ancienne valeur invalidée, jetons existants révoqués) et le renvoie avec le prompt ;
   * rotate=false n'inclut que client_id, le secret apparaît en placeholder (en cas de perte de clé, il faut rotate pour obtenir des identifiants utilisables).
   */
  buildOnboardingPrompt(appId: string, origin: string, opts: { rotate?: boolean } = {}): {
    appName: string
    prompt: string
    credential: AppOnboardingCredential
    rotated: boolean
  } {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(t('应用不存在：{id}', { id: appId }))
    const principal = this.ctx.authn.principals().findOne((item) => item.refType === 'app' && item.refId === appId)
    if (!principal) throw new Error(t('应用机器凭证不存在（可能已被禁用或删除），无法生成接入提示词'))
    let credential: AppOnboardingCredential
    let rotated = false
    if (opts.rotate) {
      const next = this.ctx.authn.rotateMachineCredential(principal.id)
      credential = { clientId: next.principal.clientId, clientSecret: next.clientSecret }
      rotated = true
    } else {
      credential = { clientId: principal.clientId }
    }
    return { appName: app.name, prompt: buildAppOnboardingPrompt(app, credential, origin), credential, rotated }
  }

  /** Maintenance du graphe de dépendances application → Agent (source de données de la topologie d'orchestration). */
  private syncAgentDependencies(appId: string, agentIds: string[]): void {
    const existing = this.ctx.resourceCore.dependencies().find((record) => record.fromType === 'app' && record.fromId === appId && record.kind === 'agent')
    const keep = new Set(agentIds)
    for (const record of existing) {
      if (!keep.has(record.toId)) {
        this.ctx.resourceCore.removeDependency({ fromType: 'app', fromId: appId, toType: 'agent', toId: record.toId })
      } else {
        keep.delete(record.toId)
      }
    }
    for (const agentId of keep) {
      this.ctx.resourceCore.addDependency({ fromType: 'app', fromId: appId, toType: 'agent', toId: agentId, kind: 'agent' })
    }
  }

  /** Visualisation de la topologie de dépendances : application → Agent → MCP/Skill, un graphe traversable, nœuds anormaux annotables. */
  topology(appId: string): TopologyNode {
    return this.ctx.resourceCore.topology('app', appId, 3)
  }

  // -- Liaison des capacités (W2-T4, contrat de gouvernance MCP §10) ----------------------------------

  /** Collection des liaisons de capacités d'application (montages App ↔ services MCP, même modèle que les collections existantes app:usage etc.). */
  capabilities(): Collection<AppCapabilityLink> {
    return this.ctx.opsStorage.collection<AppCapabilityLink>('app:capabilities')
  }

  /** Toutes les liaisons de capacités de cet app (tri stable par date de liaison). */
  listCapabilities(appId: string): AppCapabilityLink[] {
    return this.capabilities().find((item) => item.appId === appId)
      .sort((a, b) => a.boundAt.localeCompare(b.boundAt) || a.id.localeCompare(b.id))
  }

  /**
   * Lie un service de capacité : le service doit exister ; la liaison réécrit en synchronie l'ownerEntity du service en {type:'app', id:appId} —
   * la réécriture n'est permise que si le service appartient actuellement au placeholder platform (sans id, tâche de gouvernance unowned) ou déjà à cet app ;
   * toute propriété d'un autre sujet lève CapabilityOwnerConflictError (mappé en 409 OWNER_CONFLICT à la couche REST).
   * Reliaison idempotente renvoyant l'état courant (valeur required inchangée) ; maintenance en synchronie de l'arête de dépendance resource-core
   * {app→mcp, kind:'capability'} (contrat §10, topologie app→agent→mcp traversable).
   */
  bindCapability(appId: string, input: { serviceId: string; required?: boolean; boundBy: string }): { link: AppCapabilityLink; created: boolean } {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(t('应用不存在：{id}', { id: appId }))
    const service = this.ctx.mcpRegistry.services().get(input.serviceId)
    if (!service) throw new Error(t('MCP 服务不存在：{id}', { id: input.serviceId }))
    const existing = this.capabilities().findOne((item) => item.appId === appId && item.serviceId === input.serviceId)
    if (existing) return { link: existing, created: false } // idempotence : reliaison renvoie l'état courant
    // Porte de réécriture de propriété (fail-closed) : le placeholder platform (sans id) peut être revendiqué ; revendiqué par un autre sujet = conflit
    const owner = service.ownerEntity
    const claimable = !owner || (owner.type === 'platform' && !owner.id) || (owner.type === 'app' && owner.id === appId)
    if (!claimable) {
      throw new CapabilityOwnerConflictError(t('服务「{name}」已归属其他主体（ownerEntity={type}:{id}），不能重复绑定到本应用', { name: service.name, type: owner.type, id: owner.id ?? '-' }))
    }
    this.ctx.mcpRegistry.setOwnerEntity(input.serviceId, { type: 'app', id: appId })
    const link = this.capabilities().insert({
      id: newId('apc'),
      appId,
      serviceId: input.serviceId,
      required: input.required === true,
      exposure: 'gateway',
      status: 'active',
      boundAt: new Date().toISOString(),
      boundBy: input.boundBy,
    })
    this.ctx.resourceCore.addDependency({ fromType: 'app', fromId: appId, toType: 'mcp', toId: input.serviceId, kind: 'capability' })
    return { link, created: true }
  }

  /**
   * Délie un service de capacité : supprime l'enregistrement de liaison et l'arête capability ; si la propriété du service avait été réécrite à cet app,
   * restauration en cascade du placeholder {type:'platform'} (retour à la tâche de gouvernance unowned ; la cascade de déliaison est notée par le changeLog de la couche REST).
   */
  unbindCapability(appId: string, serviceId: string): { removed: boolean; ownerRestored: boolean } {
    const link = this.capabilities().findOne((item) => item.appId === appId && item.serviceId === serviceId)
    if (!link) return { removed: false, ownerRestored: false }
    this.capabilities().remove(link.id)
    this.ctx.resourceCore.removeDependency({ fromType: 'app', fromId: appId, toType: 'mcp', toId: serviceId })
    let ownerRestored = false
    const service = this.ctx.mcpRegistry.services().get(serviceId)
    if (service && service.ownerEntity.type === 'app' && service.ownerEntity.id === appId) {
      this.ctx.mcpRegistry.setOwnerEntity(serviceId, { type: 'platform' })
      ownerRestored = true
    }
    return { removed: true, ownerRestored }
  }

  /**
   * Portes de mise en ligne des capacités (W2-T4, contrat §10) : vérifie une à une toutes les capacités required de cet app, renvoie la liste des motifs d'insatisfaction
   * (tableau vide = passage ; libellés destinés aux administrateurs, nom du service + motif). Périmètre point par point :
   *   ① status du service ∈ {online, gray} ; ② verify achevé (health ≠ unknown ou lastProbeAt présent) ;
   *   ③ liste d'outils non vide ; ④ aucun haut risque en attente (write/admin et risque pending dans le registre — registre de risques
   *   absent (hôte de test unitaire autonome, même périmètre d'assemblage en direct que le apply() du plugin) → ce point est sauté) ;
   *   ⑤ credential configuré ou aucune exigence d'en-têtes sensibles (même jugement que sensitiveHeaderKeys et maskServiceHeaders).
   */
  capabilityGateFailures(appId: string): string[] {
    const failures: string[] = []
    const riskRegistry = this.ctx.mcpRegistry.riskRegistry()
    for (const link of this.listCapabilities(appId)) {
      if (!link.required) continue
      const service = this.ctx.mcpRegistry.services().get(link.serviceId)
      const label = service ? t('「{name}」', { name: service.name }) : t('「{id}」（已删除）', { id: link.serviceId })
      if (!service) {
        failures.push(t('{label}：能力服务不存在，请解绑后重新绑定', { label }))
        continue
      }
      if (!['online', 'gray'].includes(service.status)) {
        failures.push(t('{label}：服务未在线（当前 {status}），required 能力要求 online/gray', { label, status: service.status }))
      }
      if (service.health.status === 'unknown' && !service.health.lastProbeAt) {
        failures.push(t('{label}：尚未完成测试验证（verify），请先在 MCP 服务页执行验证', { label }))
      }
      if (service.tools.length === 0) {
        failures.push(t('{label}：工具清单为空，请先完成工具发现/登记', { label }))
      }
      // ④ Accès au registre de risques (même accès structuré que W1/V11 ; hôte de test unitaire autonome absent = aucun registre effectif consultable, saut)
      if (riskRegistry) {
        // findOne : le find de la collection renvoie un tableau (un tableau vide est truthy), pour prendre une seule entrée il faut findOne
        const pendingHigh = riskRegistry.records().findOne((item) => item.serviceId === service.id
          && (item.status === 'pending_domain' || item.status === 'pending_security')
          && (item.risk === 'write' || item.risk === 'admin'))
        if (pendingHigh) {
          failures.push(t('{label}：工具 {tool} 存在未决高危风险登记（{stage}），请先完成两级审批', { label, tool: pendingHigh.toolName, stage: pendingHigh.status }))
        }
      }
      if (!service.credentialRef && sensitiveHeaderKeys(service.headers).length > 0) {
        failures.push(t('{label}：存在明文敏感认证头且未配置下游凭证，请经 PUT /api/mcp/services/:id/credential 走 Secret Broker 下发', { label }))
      }
    }
    return failures
  }

  // -- Cycle de vie (comme Agent : approbation L4) --------------------------------------

  requestOnline(appId: string, requester: { id: string; name: string }) {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(t('应用不存在：{id}', { id: appId }))
    const errors = this.ctx.resourceCore.validateAttrs('app', app.attrs, 'online')
    if (errors.length > 0) throw new Error(t('上线条件不满足：{errors}', { errors: errors.join('；') }))
    // Porte de mise en ligne (point 1, retour anticipé) : la forme sous porte (défaut web,h5) doit avoir un client SSO active
    const ssoClientId = this.checkSsoGate(app)
    // Portes de capacités W2-T4 (contrat §10, après validateAttrs/SSO gate) : vérification une à une des capacités required —
    // en ligne / vérifié / outils non vides / aucun haut risque en attente / identifiants prêts ; un seul manquement = refus avec nom du service + motif
    const capabilityFailures = this.capabilityGateFailures(appId)
    if (capabilityFailures.length > 0) {
      throw new Error(t('CAPABILITY_GATE_FAILED：能力门禁未通过（{count} 项）——{reasons}', { count: capabilityFailures.length, reasons: capabilityFailures.join('；') }))
    }
    return this.ctx.audit.createApproval({
      kind: 'app.online',
      // WP-10/L1 : les opérations L4 à haut risque sont uniformément à haut risque — validation exige une double confirmation, l'approbation inscrit la marque de revue finale au niveau entreprise
      riskLevel: 'high',
      title: t('AI 应用上线：{name}', { name: app.name }),
      payload: { appId, requesterId: requester.id, ...(ssoClientId !== undefined ? { ssoClientId } : {}) },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  /** Contrôle de la porte SSO : renvoie le clientId du client active (pour l'instantané du dossier d'approbation), lève en indiquant la voie en cas d'infraction. */
  private checkSsoGate(app: { id: string; name: string; attrs: Record<string, unknown> }): string | undefined {
    const enforce = AppRegistryService.ssoEnforceTypes()
    if (enforce.length === 0) return this.activeSsoClient(app.id)?.clientId
    const appType = String(app.attrs['appType'] ?? '')
    if (!enforce.includes(appType)) return this.activeSsoClient(app.id)?.clientId
    const active = this.activeSsoClient(app.id)
    if (!active) {
      throw new Error(t('上线门禁：{appType} 形态应用上线前必须完成身份纳管——请在「AI 应用 → 应用详情 → SSO 配置」签发 OIDC 客户端（当前门禁形态：{enforce}）；回调地址为本机环回（127.0.0.1 / localhost / 0.0.0.0）时，应用可凭自身机器凭证直接调 POST /api/apps/:id/sso-client 自助签发', { appType, enforce: enforce.join('/') }))
    }
    return active.clientId
  }

  requestOffline(appId: string, requester: { id: string; name: string }, reason: string) {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(t('应用不存在：{id}', { id: appId }))
    if (!reason?.trim()) throw new Error(t('下架必须填写原因（护栏要求）'))
    return this.ctx.audit.createApproval({
      kind: 'app.offline',
      // WP-10/L1 : les opérations L4 à haut risque sont uniformément à haut risque — validation exige une double confirmation, l'approbation inscrit la marque de revue finale au niveau entreprise
      riskLevel: 'high',
      title: t('AI 应用下架：{name}', { name: app.name }),
      payload: { appId, reason },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  online(appId: string, actor: string) {
    const result = this.ctx.resourceCore.transition('app', appId, 'online', actor)
    this.ctx.platformBus.emit(PlatformEvents.AppOnlined, { id: appId, name: result.entity.name, actor, type: 'app', slug: result.entity.slug })
    return result.entity
  }

  offline(appId: string, actor: string, reason: string) {
    const result = this.ctx.resourceCore.transition('app', appId, 'offline', actor, reason)
    // Cascade de retrait W2-T4 (contrat §10) : les services de capacités quittent le service avec l'application — l'exécuteur app.offline et
    // le chemin d'achèvement de requestOffline convergent tous deux vers cette méthode, l'implémentation de cascade est en point unique
    this.linkageOfflineCapabilityServices(appId)
    this.ctx.platformBus.emit(PlatformEvents.AppOfflined, { id: appId, name: result.entity.name, actor, reason, type: 'app', slug: result.entity.slug })
    return result.entity
  }

  /**
   * Cascade de retrait (W2-T4, contrat §10) : met hors ligne les services correspondant à toutes les capacités de cet app (ceux dont ownerEntity a été réécrit à cet app,
   * non required inclus). La cascade système passe par l'arrêt direct (appel direct d'offlineService — la sémantique d'approbation ne s'applique qu'aux
   * opérations humaines), actor marqué app-offline-linkage ; la mise hors ligne du service émet McpOfflined via le pipeline existant de plugin-mcp,
   * changeLog/audit suivent automatiquement. L'état préalable de restauration est conservé dans offlineRestore de l'enregistrement de liaison pour la remise en ligne.
   * L'échec d'un seul service ne bloque pas le retrait principal de l'application (trace warn, découvrable via le résumé de gouvernance/vue des capacités).
   */
  private linkageOfflineCapabilityServices(appId: string): void {
    const app = this.ctx.resourceCore.get('app', appId)
    for (const link of this.listCapabilities(appId)) {
      const service = this.ctx.mcpRegistry.services().get(link.serviceId)
      if (!service) continue
      const owner = service.ownerEntity
      if (!(owner.type === 'app' && owner.id === appId) || service.status === 'offline') continue
      try {
        this.ctx.mcpRegistry.offlineService(service.id, 'app-offline-linkage', t('应用「{name}」下架联动下线能力服务', { name: app?.name ?? appId }))
        this.capabilities().update(link.id, {
          offlineRestore: { status: service.status, grayPercent: service.grayPercent, at: new Date().toISOString() },
        })
      } catch (error) {
        this.ctx.logger('app').warn(t('能力服务联动下线失败：{service}（{serviceId}）', { service: service.name, serviceId: service.id }), error)
      }
    }
  }

  /**
   * Restauration à la remise en ligne (W2-T4) : après une remise en ligne réussie de l'application, les services de capacités arrêtés en cascade reviennent à leur état préalable.
   * deployService de plugin-mcp n'accepte pas le point de départ offline (seulement draft/verifying/gray/online/unhealthy,
   * voir sa liste blanche d'états), d'où l'écriture directe du status/grayPercent préalables via le getter public services(),
   * avec trace d'audit change ; version/versions intacts (la restauration n'est pas une publication de nouvelle version, pas d'événement McpDeployed).
   */
  restoreCapabilityServices(appId: string): void {
    for (const link of this.listCapabilities(appId)) {
      if (!link.offlineRestore) continue
      const restore = link.offlineRestore
      const service = this.ctx.mcpRegistry.services().get(link.serviceId)
      if (service && service.status === 'offline') {
        // Restauration à la remise en ligne W2-T4 : deployService refuse le départ offline, écriture directe de l'état préalable (assertion de resserrement de type)
        this.ctx.mcpRegistry.services().update(link.serviceId, {
          status: restore.status as McpServiceRecord['status'],
          grayPercent: restore.grayPercent,
        })
        try {
          this.ctx.audit.record({
            type: 'change', actorType: 'system', actorId: 'app-online-linkage', actorName: '应用重上线联动',
            action: 'mcp.service.online-restore', resourceType: 'mcp_service', resourceId: link.serviceId,
            resourceName: service.name, result: 'ok',
            detail: t('应用重上线联动恢复能力服务：status={status} gray={gray}%', { status: restore.status, gray: restore.grayPercent }),
          })
        } catch { /* sans service d'audit chez l'hôte minimal, la restauration n'est pas bloquée */ }
      }
      this.capabilities().update(link.id, { offlineRestore: undefined })
    }
  }

  /** Archivage (état final) : l'application retirée quitte définitivement l'exploitation ; le client SSO associé est désactivé en cascade via l'événement app.archived. */
  archive(appId: string, actor: string) {
    const result = this.ctx.resourceCore.transition('app', appId, 'archive', actor)
    this.ctx.platformBus.emit(PlatformEvents.AppArchived, { id: appId, name: result.entity.name, actor, type: 'app', slug: result.entity.slug })
    return result.entity
  }

  /** Nettoyage des liens après suppression : arêtes d'orchestration effacées, client SSO et identifiants machine désactivés ; enregistrements clients et données d'usage/audit conservés. */
  purge(appId: string): void {
    for (const record of this.ctx.resourceCore.dependencies().find((item) => item.fromType === 'app' && item.fromId === appId)) {
      this.ctx.resourceCore.dependencies().remove(record.id)
    }
    for (const client of this.ctx.oidc.clientsForApp(appId)) {
      if (OidcService.isClientActive(client)) this.ctx.oidc.disableClient(client.id, '应用删除联动')
    }
    const principal = this.ctx.authn.principals().findOne((item) => item.refType === 'app' && item.refId === appId)
    if (principal && principal.status === 'active') this.ctx.authn.disablePrincipal(principal.id, '应用删除联动')
    // Hébergement d'identifiants externes (issue #19) effacement en cascade : sans application, les identifiants n'ont plus de propriétaire, fichier de clés entier supprimé (supprimer = détruire)
    this.ctx.appCredentials.purge(appId)
    // Cascade d'archivage W2-T4 (contrat §10) : les services de capacités restent offline (état intact, pas de résurrection), marquage archivedBy
    // (champ additif, lisible par la topologie/gouvernance W3) ; la propriété, si elle est à cet app, retourne au placeholder platform
    // (anti-référence pendante, même sémantique que la déliaison) ; effacement des enregistrements de liaison — arêtes capability/fichiers d'identifiants/OIDC/identifiants machine
    // les cascades sont déjà couvertes par la logique existante ci-dessus, pas de duplication ici.
    for (const link of this.listCapabilities(appId)) {
      const service = this.ctx.mcpRegistry.services().get(link.serviceId)
      if (service) {
        const owner = service.ownerEntity
        this.ctx.mcpRegistry.services().update(link.serviceId, {
          archivedBy: appId, // cascade d'archivage W2-T4
          ...(owner.type === 'app' && owner.id === appId ? { ownerEntity: { type: 'platform' as const } } : {}),
        } as unknown as Partial<McpServiceRecord>)
      }
      this.capabilities().remove(link.id)
    }
  }

  // -- Clients SSO (branchement application ↔ source d'identité plateforme ; auto-émission par le owner) ----------------------

  /** Formes d'application couvertes par la porte de mise en ligne (APP_SSO_ENFORCE, défaut web,h5 ; chaîne vide = porte désactivée). */
  static ssoEnforceTypes(): string[] {
    return String(process.env.APP_SSO_ENFORCE ?? 'web,h5').split(',').map((item) => item.trim()).filter(Boolean)
  }

  /**
   * Autorisation owner-based (première du dépôt, hors système de points de permission) :
   * human et app.ownerId === userId, ou détention d'authn.oidc.write (filet administrateur) ; tout principal machine → 403.
   */
  assertSsoManage(app: { id: string; name: string; ownerId: string }, caller: { kind: string; userId?: string; permissions: string[] }): void {
    if (caller.kind !== 'human' || !caller.userId) {
      throw new Error(t('SSO 客户端管理仅限用户身份（owner 校验），机器身份不可操作'))
    }
    const isOwner = app.ownerId === caller.userId
    const hasAdmin = caller.permissions.includes('*') || caller.permissions.includes('authn.oidc.write')
    if (!isOwner && !hasAdmin) {
      throw new Error(t('仅应用 owner 或持有 authn.oidc.write 的管理员可管理「{name}」的 SSO 客户端', { name: app.name }))
    }
  }

  /**
   * Garde des adresses de retour : https toute machine ; http réservé à l'intranet (boucle locale / RFC1918 privé / lien local / IPv6 ULA).
   * Un déploiement purement intranet peut ouvrir toutes les machines http avec APP_SSO_ALLOW_HTTP=1 (retours en clair sur Internet : https recommandé).
   * Statique public : les routes de gestion des clients OIDC de plugin-console réutilisent le même périmètre.
   */
  static assertRedirectUris(uris: string[]): void {
    if (!Array.isArray(uris) || uris.length === 0) throw new Error(t('redirectUris 必填（至少一个回调地址）'))
    const allowAnyHttp = String(process.env.APP_SSO_ALLOW_HTTP ?? '') === '1'
    for (const uri of uris) {
      let parsed: URL
      try { parsed = new URL(uri) } catch { throw new Error(t('回调地址非法：{uri}', { uri })) }
      if (parsed.protocol === 'https:') continue
      if (parsed.protocol === 'http:' && (allowAnyHttp || AppRegistryService.isIntranetHost(parsed.hostname))) continue
      throw new Error(t('回调地址必须为 https://，或 http:// 的内网地址（localhost / 127.0.0.1 / 0.0.0.0 / 10.x / 172.16-31.x / 192.168.x）（收到：{uri}）', { uri }))
    }
  }

  /** Jugement d'hôte intranet : boucle locale, privé RFC1918, lien local, IPv6 ULA. */
  private static isIntranetHost(hostname: string): boolean {
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
    if (host === 'localhost' || host === '::1' || host === '0.0.0.0') return true
    if (host.includes(':')) return host.startsWith('f') || host.startsWith('fd') // fc00::/7 ULA
    const parts = host.split('.')
    if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part))) return false // tout ce qui n'est pas un IPv4 pointé est traité comme public
    const [a, b] = parts.map(Number) as [number, number]
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)
  }

  /** Jugement d'hôte en boucle locale (retours locaux) : localhost / *.localhost / 127.0.0.0/8 / ::1 / 0.0.0.0. */
  static isLoopbackHost(hostname: string): boolean {
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
    if (host === 'localhost' || host === '::1' || host === '0.0.0.0' || host.endsWith('.localhost')) return true
    if (host.startsWith('127.')) return true
    return false
  }

  /** L'ensemble des adresses de callback est-il entièrement en boucle locale (ensemble vide exclu — l'auto-service machine doit enregistrer explicitement des callbacks en boucle locale). */
  static isLoopbackOnlyCallback(uris: string[] | undefined): boolean {
    if (!Array.isArray(uris) || uris.length === 0) return false
    return uris.every((uri) => {
      try { return AppRegistryService.isLoopbackHost(new URL(uri).hostname) } catch { return false }
    })
  }

  /**
   * Interrupteur d'auto-service en boucle locale des identités machine (ouvert par défaut, APP_SSO_MACHINE_LOOPBACK=0 pour fermer) :
   * l'identifiant machine d'une application/d'un Agent (ou le principal owner enregistré) peut s'auto-émettre/gérer un client SSO dont les callbacks sont tous en boucle locale —
   * un callback local ne traverse pas de machine, avec code d'autorisation + PKCE forcé l'interception par un tiers n'a aucun intérêt (périmètre loopback RFC 8252) ;
   * les callbacks hors boucle locale (IP intranet / domaine public) exigent toujours un owner humain ou un administrateur.
   */
  static machineSsoSelfServiceEnabled(): boolean {
    return String(process.env.APP_SSO_MACHINE_LOOPBACK ?? '1') !== '0'
  }

  /**
   * Décision d'autorisation de gestion SSO (périmètre partagé par les routes console des côtés app/agent) :
   * - human : owner de la ressource (ownerId === userId) ou détenteur d'authn.oidc.write (filet administrateur) → passage ;
   * - machine : interrupteur ouvert, l'identifiant lié à cette ressource (refType/refId correspondant ou ownerId === principalId) peut passer —
   *   create/update jugent sur l'ensemble de callbacks effectif de la requête, rotate/enable sur l'ensemble existant, disable (pure réduction de risque) passe toujours ;
   *   l'ensemble de callbacks doit être intégralement en boucle locale (isLoopbackOnlyCallback), sinon seul human peut opérer.
   */
  static ssoManageDecision(
    resource: { id: string; name: string; ownerId: string },
    caller: AppRegistryServiceSsoCaller,
    effective: { redirectUris: string[]; postLogoutUris: string[] },
    op: 'create' | 'update' | 'rotate' | 'enable' | 'disable',
  ): { allowed: true } | { allowed: false; reason: string } {
    if (caller.kind !== 'human') {
      if (!AppRegistryService.machineSsoSelfServiceEnabled()) {
        return { allowed: false, reason: t('SSO 客户端管理仅限用户身份（owner 校验），机器身份不可操作') }
      }
      const bound = (caller.refType !== undefined && caller.refId === resource.id)
        || resource.ownerId === caller.principalId
      if (!bound) {
        return { allowed: false, reason: t('机器身份仅可管理自身绑定资源的 SSO 客户端（「{name}」须为凭证 refType/refId 命中或登记 owner）', { name: resource.name }) }
      }
      if (op === 'disable') return { allowed: true } // la désactivation ne fait que réduire le risque, passage toujours
      if (!AppRegistryService.isLoopbackOnlyCallback([...effective.redirectUris, ...effective.postLogoutUris])) {
        return { allowed: false, reason: t('机器身份自助仅限环回回调地址（http://127.0.0.1:PORT、http://localhost:PORT、0.0.0.0）；非环回回调请由应用 owner 或管理员在控制台操作') }
      }
      return { allowed: true }
    }
    const isOwner = Boolean(caller.userId) && resource.ownerId === caller.userId
    const hasAdmin = caller.permissions.includes('*') || caller.permissions.includes('authn.oidc.write')
    if (!isOwner && !hasAdmin) {
      return { allowed: false, reason: t('仅资源 owner 或持有 authn.oidc.write 的管理员可管理「{name}」的 SSO 客户端', { name: resource.name }) }
    }
    return { allowed: true }
  }

  /**
   * Autorisation owner-based (première du dépôt, hors système de points de permission) + exception d'auto-service en boucle locale machine (ssoManageDecision).
   * Validation filet en couche service : la couche de routes console a déjà appelé ssoManageDecision et renvoyé 403 ; ici même périmètre anti-contournement.
   */
  static assertSsoManage(
    app: { id: string; name: string; ownerId: string },
    caller: AppRegistryServiceSsoCaller,
    effective?: { redirectUris: string[]; postLogoutUris: string[] },
    op: 'create' | 'update' | 'rotate' | 'enable' | 'disable' = 'update',
  ): void {
    const decision = AppRegistryService.ssoManageDecision(app, caller, effective ?? { redirectUris: [], postLogoutUris: [] }, op)
    if (!decision.allowed) throw new Error(decision.reason)
  }

  activeSsoClient(appId: string) {
    return this.ctx.oidc.clientsForApp(appId).find((client) => OidcService.isClientActive(client))
  }

  /** Émet le client OIDC associé à l'application (name=nom de l'application, refType/refId renseignés en retour) ; le secret n'est renvoyé qu'une fois. */
  createSsoClient(appId: string, input: {
    redirectUris: string[]
    clientType?: 'confidential' | 'public'
    consentRequired?: boolean
    postLogoutUris?: string[]
    description?: string
  }): { client: ReturnType<OidcService['clientsForApp']>[number]; clientSecret: string } {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(t('应用不存在：{id}', { id: appId }))
    AppRegistryService.assertRedirectUris(input.redirectUris)
    const existing = this.ctx.oidc.clientsForApp(appId)
    if (existing.length > 0) throw new Error(t('该应用已签发 SSO 客户端（{clientId}），请直接管理或先禁用后重新签发', { clientId: existing[0]!.clientId }))
    const created = this.ctx.oidc.createClient({
      name: app.name,
      redirectUris: input.redirectUris,
      ...(input.clientType !== undefined ? { clientType: input.clientType } : {}),
      ...(input.consentRequired !== undefined ? { consentRequired: input.consentRequired } : {}),
      ...(input.postLogoutUris !== undefined ? { postLogoutUris: input.postLogoutUris } : {}),
      ...(input.description !== undefined ? { description: input.description } : {}),
      refType: 'app',
      refId: appId,
    })
    return created
  }

  updateSsoClient(appId: string, patch: { redirectUris?: string[]; description?: string; consentRequired?: boolean; postLogoutUris?: string[] }) {
    this.requireSsoClient(appId)
    if (patch.redirectUris !== undefined) AppRegistryService.assertRedirectUris(patch.redirectUris)
    return this.ctx.oidc.updateClient(this.requireSsoClient(appId).id, patch)
  }

  rotateSsoSecret(appId: string) {
    return this.ctx.oidc.rotateSecret(this.requireSsoClient(appId).id)
  }

  disableSsoClient(appId: string, reason: string) {
    return this.ctx.oidc.disableClient(this.requireSsoClient(appId).id, reason)
  }

  enableSsoClient(appId: string) {
    return this.ctx.oidc.enableClient(this.requireSsoClient(appId).id)
  }

  private requireSsoClient(appId: string) {
    const clients = this.ctx.oidc.clientsForApp(appId)
    if (clients.length === 0) throw new Error(t('该应用尚未签发 SSO 客户端'))
    return clients[0]!
  }

  // -- Synchronisation d'organigramme (auto-service des applications via le module organisation de la plateforme) -----------------------------

  /**
   * Instantané d'organigramme (REST /api/apps/:id/org-sync, canal en libre-service de l'application) :
   * l'application intégrée tire avec son propre identifiant machine lié (ou l'identité owner) l'arbre organisationnel de la plateforme et les membres en poste,
   * pour répliquer/associer la fonction d'organigramme plateforme dans l'application (arbre d'organisation, membres par département, identification des responsables).
   * Clé d'association : users[].id est le sub du userinfo OIDC, l'identité de connexion s'accroche directement au département/au responsable.
   * Minimisation PII : sans téléphone/e-mail/rôles/liens tiers (champs plus complets via /api/iam/roster,
   * exigeant l'ajout administrateur d'iam.roster.read) ; les comptes désactivés (deactivated) n'apparaissent pas.
   * version = hash de contenu (stable après tri) : tout changement d'organisation/membre le change,
   * l'intégrateur implémente la détection de changement à charge nulle par polling ?ifNoneMatch= ; l'instantané fait foi, après changement on réaligne intégralement la copie locale.
   */
  orgSnapshot(appId: string, opts: { ifNoneMatch?: string } = {}): {
    unchanged: boolean
    version: string
    generatedAt?: string
    orgs?: Array<{ id: string; name: string; parentId: string | null; order: number; status: string; leaderUserIds: string[]; updatedAt: string }>
    users?: Array<{ id: string; username: string; displayName: string; title: string; jobNumber: string; orgId: string; orgName: string; primaryOrgId?: string; status: string; accountType?: string; updatedAt: string }>
  } {
    if (!this.ctx.resourceCore.get('app', appId)) throw new Error(t('应用不存在：{id}', { id: appId }))
    const orgNames = new Map(this.ctx.iam.orgs().all().map((org) => [org.id, org.name]))
    const orgs = this.ctx.iam.orgs().all()
      .map((org) => ({
        id: org.id,
        name: org.name,
        parentId: org.parentId,
        order: org.order,
        status: org.status,
        leaderUserIds: this.ctx.iam.leadersOf(org.id),
        updatedAt: org.updatedAt,
      }))
      .sort((a, b) => a.order - b.order || a.name.localeCompare(b.name, 'zh-Hans-CN') || a.id.localeCompare(b.id))
    const users = this.ctx.iam.users().all()
      .filter((user) => user.status !== 'deactivated')
      .map((user) => ({
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        title: user.title,
        jobNumber: user.jobNumber ?? '',
        orgId: user.orgId,
        orgName: orgNames.get(user.orgId) ?? '',
        ...(user.primaryOrgId !== undefined ? { primaryOrgId: user.primaryOrgId } : {}),
        status: user.status,
        ...(user.accountType !== undefined ? { accountType: user.accountType } : {}),
        updatedAt: user.updatedAt,
      }))
      .sort((a, b) => a.displayName.localeCompare(b.displayName, 'zh-Hans-CN') || a.id.localeCompare(b.id))
    // Hash de contenu (16 caractères suffisent, collisions improbables à l'échelle intranet) : inclut tous les champs exposés et updatedAt, l'ordre d'insertion n'intervient pas
    const version = createHash('sha256')
      .update(JSON.stringify({ orgs, users }))
      .digest('hex')
      .slice(0, 16)
    if (opts.ifNoneMatch && opts.ifNoneMatch === version) return { unchanged: true, version }
    return { unchanged: false, version, generatedAt: new Date().toISOString(), orgs, users }
  }

  // -- Métriques de la couche application ---------------------------------------------------------

  /**
   * Enregistre les métriques de la couche application (canal de remontée proactive des applications externes : REST /api/apps/:id/metrics-report,
   * outil app_metrics_report et CLI app report convergent tous vers cette méthode).
   * Sémantique : même jour, DAU/UV au maximum, sessions/PV cumulés ; date possible pour compléter l'historique (YYYY-MM-DD).
   */
  recordUsage(appId: string, usage: { dau?: number; sessions?: number; avgDepth?: number; retention7?: number; pv?: number; uv?: number; date?: string }): void {
    if (!this.ctx.resourceCore.get('app', appId)) throw new Error(t('应用不存在：{id}', { id: appId }))
    const date = usage.date ?? new Date().toISOString().slice(0, 10)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(t('date 格式非法：{date}（应为 YYYY-MM-DD）', { date }))
    // REL-04 : validation des entrées de métriques (même périmètre d'écrêtage des non-négatifs que trackVisit côté beacon) — pv/uv/dau/sessions négatifs
    // peuvent fausser les cumuls/les maxima, un retention7 hors bornes pollue le périmètre de rétention → 400 refus systématique
    for (const [key, value] of [['pv', usage.pv], ['uv', usage.uv], ['dau', usage.dau], ['sessions', usage.sessions]] as const) {
      if (value !== undefined && (!Number.isInteger(value) || value < 0)) throw new Error(t('{key} 必须是非负整数（收到：{value}）', { key, value }))
    }
    if (usage.retention7 !== undefined && (!Number.isFinite(usage.retention7) || usage.retention7 < 0 || usage.retention7 > 1)) {
      throw new Error(t('retention7 必须是 0..1 之间的数值（收到：{value}）', { value: usage.retention7 }))
    }
    const existing = this.usage().findOne((item) => item.appId === appId && item.date === date)
    if (existing) {
      this.usage().update(existing.id, {
        dau: Math.max(existing.dau, usage.dau ?? existing.dau),
        sessions: existing.sessions + (usage.sessions ?? 0),
        avgDepth: usage.avgDepth ?? existing.avgDepth,
        retention7: usage.retention7 ?? existing.retention7,
        pv: (existing.pv ?? 0) + (usage.pv ?? 0),
        uv: Math.max(existing.uv ?? 0, usage.uv ?? 0),
      })
    } else {
      this.usage().insert({
        id: newId('apu'),
        appId,
        date,
        dau: usage.dau ?? 0,
        sessions: usage.sessions ?? 0,
        avgDepth: usage.avgDepth ?? 0,
        retention7: usage.retention7 ?? 0,
        pv: usage.pv ?? 0,
        uv: usage.uv ?? 0,
      })
    }
  }

  /**
   * Calcul automatique côté plateforme des métriques visiteurs (distinct de la remontée proactive recordUsage des intégrateurs) :
   *   - échange entry-ticket / émission de code OIDC → visiteur sous identité plateforme (dédupliqué par userId, converti en DAU) ;
   *   - beacon navigateur → visiteur anonyme (dédupliqué par vid, converti en UV) + PV cumulé à chaque visite.
   * L'ensemble du même jour ne fait que croître ; DAU/UV entrent via la sémantique max de recordUsage selon la taille de l'ensemble, PV en cumul ;
   * application inconnue ignorée silencieusement (le point beacon public ne doit pas divulguer l'existence d'une application à l'appelant).
   */
  trackVisit(appId: string, visitor: { userId?: string; vid?: string; pv?: number }): void {
    if (!this.ctx.resourceCore.get('app', appId)) return
    const userId = visitor.userId === undefined ? undefined : String(visitor.userId).trim().slice(0, 128)
    const vid = visitor.vid === undefined ? undefined : String(visitor.vid).trim().slice(0, 128)
    const pv = Math.max(0, Math.min(10, Math.floor(Number(visitor.pv ?? 0)) || 0))
    if (!userId && !vid && pv === 0) return
    const date = new Date().toISOString().slice(0, 10)
    const record = this.visits().findOne((item) => item.appId === appId && item.date === date)
      ?? this.visits().insert({ id: newId('apv'), appId, date, userIds: [], vids: [] })
    // Plafond du registre par application et par jour (surface d'écriture de point public, anti-gonflement anormal ; le trafic intranet normal en est très loin)
    const CAP = 10_000
    const userIds = record.userIds ?? []
    const vids = record.vids ?? []
    if (userId && !userIds.includes(userId) && userIds.length < CAP) userIds.push(userId)
    if (vid && !vids.includes(vid) && vids.length < CAP) vids.push(vid)
    this.visits().update(record.id, { userIds, vids })
    this.pruneVisits()
    this.recordUsage(appId, {
      ...(pv > 0 ? { pv } : {}),
      dau: userIds.length,
      uv: userIds.length + vids.length,
    })
  }

  /** Registre des visiteurs conservé 31 jours (sert seulement à la conversion du jour et à la réconciliation, sans valeur au-delà). */
  private pruneVisits(): void {
    const cutoff = new Date(Date.now() - 31 * 86_400_000).toISOString().slice(0, 10)
    for (const record of this.visits().find((item) => item.date < cutoff)) this.visits().remove(record.id)
  }

  metrics(appId: string): {
    dau: number
    mau: number
    pv: number
    uv: number
    sessions: number
    avgDepth: number
    retention7: number
    series: Array<{ date: string; dau: number; pv: number; uv: number; sessions: number }>
  } {
    const rows = this.usage().find((item) => item.appId === appId).sort((a, b) => a.date.localeCompare(b.date))
    const today = rows.at(-1)
    const last30 = rows.slice(-30)
    return {
      dau: today?.dau ?? 0,
      mau: last30.reduce((sum, row) => sum + row.dau, 0),
      pv: today?.pv ?? 0,
      uv: today?.uv ?? 0,
      sessions: rows.reduce((sum, row) => sum + row.sessions, 0),
      avgDepth: Math.round((rows.reduce((sum, row) => sum + row.avgDepth, 0) / Math.max(1, rows.length)) * 10) / 10,
      retention7: today?.retention7 ?? 0,
      series: rows.slice(-14).map((row) => ({ date: row.date, dau: row.dau, pv: row.pv ?? 0, uv: row.uv ?? 0, sessions: row.sessions })),
    }
  }

  overview(): { total: number; online: number; trial: number } {
    const apps = this.ctx.resourceCore.list('app')
    return {
      total: apps.length,
      online: apps.filter((item) => item.status === 'online').length,
      trial: apps.filter((item) => item.status === 'trial').length,
    }
  }

  /** Traversée des coûts : application → Agent → MCP/modèle. */
  costBreakdown(appId: string): Array<{ agentName: string; llmTokens: number; toolCalls: number; costYuan: number }> {
    const rows: Array<{ agentName: string; llmTokens: number; toolCalls: number; costYuan: number }> = []
    const deps = this.ctx.resourceCore.dependencies().find((record) => record.fromType === 'app' && record.fromId === appId && record.kind === 'agent')
    for (const dep of deps) {
      const agent = this.ctx.resourceCore.get('agent', dep.toId)
      const costs = this.ctx.audit.costs().find((cost) => cost.agentId === dep.toId)
      rows.push({
        agentName: agent?.name ?? dep.toId,
        llmTokens: costs.reduce((sum, cost) => sum + cost.llmTokens, 0),
        toolCalls: costs.reduce((sum, cost) => sum + cost.toolCalls, 0),
        costYuan: Math.round(costs.reduce((sum, cost) => sum + cost.costYuan, 0) * 1000) / 1000,
      })
    }
    return rows.sort((a, b) => b.costYuan - a.costYuan)
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    appRegistry: AppRegistryService
  }
}

export const name = 'app'
// W2-T4 : accès direct au mcpRegistry injecté — dans les deux séquences d'assemblage hôte, plugin-mcp est assemblé avant ce plugin
// (boot-all.ts mcp→app, cordis.yml ops-mcp→ops-app), vérifiable machine par check-boot-order [A] ;
// liaison des capacités/portes/cascades passent donc par l'accès ctx direct (fail-closed), sans callback injecté par console.
// appCredentials est un service auto-fourni par ce plugin (assemblé avant consommation dans apply, purge en cascade via registry).
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'authn', 'oidc', 'audit', 'iam', 'mcpRegistry']

export function apply(ctx: Context) {
  const registry = new AppRegistryService(ctx)
  // Hébergement d'identifiants externes (issue #19 direction A, boucle minimale) : fichier de clés chiffré au repos AES-256-GCM,
  // lecture via le point de permission dédié app.credential.fetch + audit à chaque occurrence ; purge efface en cascade via la suppression registry
  new AppCredentialService(ctx)
  ctx.plugin(appTools)
  // Calcul automatique côté plateforme (complément du périmètre de métriques) : visite sous identité SSO → DAU d'application, découplé par le bus d'événements (pas de connexion directe authn/console).
  // L'échange entry-ticket (émis par console) et l'émission de code OIDC (émise par OidcService authn) signifient tous deux que l'utilisateur est entré dans l'application sous identité plateforme.
  ctx.platformBus.on(PlatformEvents.EntryTicketRedeemed, (payload) => {
    const p = payload as { refType?: string; refId?: string; userId?: string }
    if (p.refType === 'app' && p.refId && p.userId) {
      try { registry.trackVisit(p.refId, { userId: p.userId }) } catch (error) { ctx.logger('app').warn('entry-ticket 兑换折算 DAU 失败', error) }
    }
  })
  ctx.platformBus.on(PlatformEvents.OidcAuthorizeGranted, (payload) => {
    const p = payload as { clientId?: string; userId?: string }
    const client = p.clientId !== undefined ? ctx.oidc.clientByClientId(p.clientId) : undefined
    if (client?.refType === 'app' && client.refId && p.userId) {
      try { registry.trackVisit(client.refId, { userId: p.userId }) } catch (error) { ctx.logger('app').warn('OIDC 发码折算 DAU 失败', error) }
    }
  })
  ctx.effect(() => ctx.audit.registerExecutor('app.online', async (payload) => {
    // Porte de mise en ligne (point 2, filet) : pendant l'examen du dossier, le client peut être désactivé — revérification avant exécution, échec = échec d'exécution avec trace
    const appId = String(payload['appId'])
    const app = ctx.resourceCore.get('app', appId)
    if (app) {
      const enforce = AppRegistryService.ssoEnforceTypes()
      const appType = String(app.attrs['appType'] ?? '')
      if (enforce.includes(appType) && !registry.activeSsoClient(app.id)) {
        throw new Error(t('执行期复核失败：审批期间 SSO 客户端已失效（{appType} 形态门禁），请重新签发后再发起上线', { appType }))
      }
    }
    // Revérification en exécution W2-T4 (contrat §10) : pendant l'examen du dossier, les capacités required peuvent avoir été mises hors ligne/dégradées —
    // revérification une à une (en ligne/vérifié/outils non vides/aucun haut risque en attente/identifiants prêts), échec = échec d'exécution avec trace
    const capabilityFailures = registry.capabilityGateFailures(appId)
    if (capabilityFailures.length > 0) {
      throw new Error(t('执行期复核失败：审批期间能力服务状态变化（CAPABILITY_GATE_FAILED）——{reasons}', { reasons: capabilityFailures.join('；') }))
    }
    const entity = registry.online(appId, 'approval-center')
    // Restauration à la remise en ligne W2-T4 : les services de capacités arrêtés en cascade avec l'application retrouvent leur état préalable automatiquement
    registry.restoreCapabilityServices(appId)
    return entity
  }))
  ctx.effect(() => ctx.audit.registerExecutor('app.offline', async (payload) => {
    return registry.offline(String(payload['appId']), 'approval-center', String(payload['reason'] ?? '审批通过下架'))
  }))
  migrateAppCredentialScopes(ctx)
}

/** Migration unique : complète app.read/app.write/usage.write sur les identifiants machine des applications existantes (alignement de la vérification d'intégration et de la remontée de métriques/informations). */
function migrateAppCredentialScopes(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('app:migrations')
  const MARK = 'app-scopes-self-serve-v1'
  if (markers.get(MARK)) return
  const ADDITIONS = ['app.read', 'app.write', 'usage.write']
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'app' && item.status === 'active' && ADDITIONS.some((scope) => !item.scopes.includes(scope)),
  )) {
    const merged = [...principal.scopes, ...ADDITIONS.filter((scope) => !principal.scopes.includes(scope))]
    ctx.authn.principals().update(principal.id, { scopes: merged })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'app-migration', actorName: '凭证范围迁移',
      action: 'app.credential.scopes-backfill', resourceType: 'app',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: `补入 ${ADDITIONS.filter((scope) => !principal.scopes.includes(scope)).join('/')}（应用自主接入与提报更新能力对齐）`,
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('app').info(`存量应用凭证迁移完成：${patched} 条补入 ${ADDITIONS.join('/')}`)
}
