/**
 * @dsh-ops/plugin-audit —— sécurité et audit (transversal à tous les modules, plan §7).
 *
 * - Quatre familles de journaux d'audit : authentification / autorisation / appels / modifications, schema unifié, append-only.
 * - Moteur de règles d'alerte : configuration déclarative des seuils/motifs d'anomalie, évaluation pilotée par événements.
 * - Consolidation des coûts : agrégation de la consommation de jetons par chaîne de jetons, traversée par application/organisation.
 * - Centre d'approbations : convergence des opérations L4 à haut risque de toute la plateforme (mise en avant de Skills, mise en ligne d'Agents, retrait/révocation/suppression).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, newId, sha256Hex, scanSensitiveKeys, maskSensitivePayload, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import * as auditTools from './tools.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

export type AuditType = 'auth' | 'authz' | 'invoke' | 'change'

/**
 * Ancres de preuve au niveau conclusion (IAW passation 5-1, additif) : unité de liaison entre les conclusions d'un Agent et les faits de données.
 * Domaine de kind : dataset jeu de données / field champ / window fenêtre temporelle / query lignes trouvées / doc document.
 */
export interface EvidenceAnchor {
  kind: 'dataset' | 'field' | 'window' | 'query' | 'doc'
  /** Identifiant de référence : numéro de jeu de données / chemin de champ / id de requête etc. (contrat du producteur). */
  id: string
  name?: string
  /** Ancre de fenêtre temporelle (types window/query) : intervalle de données sur lequel la conclusion repose. */
  timeWindow?: { from: string; to: string }
  /** Nombre de lignes trouvées (type query). */
  hitRows?: number
  /** Score de qualité à la date de référence 0-100 (types dataset/field, l'instantané enregistré n'est pas réécrit). */
  qualityScore?: number
}

export interface AuditLogRecord extends RecordBase {
  type: AuditType
  actorType: 'human' | 'machine' | 'system'
  actorId: string
  actorName: string
  action: string
  resourceType: string
  resourceId: string
  resourceName: string
  result: 'ok' | 'denied' | 'error'
  detail: string
  actChain?: Array<{ name: string; type: string }>
  /** Dimension scénario (IAW passation 5-2, additif) : les actions portant un numéro de scénario comme tâches/diagnostics de panneau atterrissent ici, pour la recherche inverse dans la chronologie d'audit. */
  sceneCode?: string
  /** Ancres de preuve (IAW passation 5-1, additif) : inlinées directement (événements de conclusion de type invoke) ou référence à l'id d'un enregistrement de preuve. */
  evidence?: EvidenceAnchor[]
  evidenceIds?: string[]
  // -- Stratification froide/chaude et chaîne de hachage (W3-T5, contrat §14, additif) --
  /** trace id de bout en bout (optionnel) : les événements portant un trace comme les appels de la passerelle MCP atterrissent ici, recherche exacte via GET /api/audit/logs?traceId=. */
  traceId?: string
  /** Prédécesseur de la chaîne de hachage (calculé en point unique dans record()) : chaîne vide pour la tête de chaîne. */
  prevHash?: string
  /** Hash de cet enregistrement : sha256(prevHash + canonicalJSON(champs métier de cet enregistrement)) — canonicalJSON a un ordre de clés stable,
   *  et exclut createdAt/updatedAt (injectés à l'insertion, hors faits métier) ainsi que prevHash/hash eux-mêmes ; périmètre de validation voir record(). */
  hash?: string
  /** id de décision de stratégie (contrat W3-T5 §11/§16, additif) : id d'arbitrage du PDP (préfixe pd_) — répond à « pourquoi cela a été permis ».
   *  Même source que les données chaudes de mcp:calls ; après le nettoyage glissant des données chaudes, l'audit peut toujours reconsulter les motifs de décision. */
  decisionId?: string
  /** Motif de décision de stratégie (texte structuré, additif) : motifs deny consultables (p. ex. ORG_SCOPE_DENIED / RISK_UNREGISTERED). */
  decisionReasons?: string[]
}

/** Enregistrement de preuve (IAW passation 5-1) : le paquet d'ancres est validé puis stocké avec émission d'un id ; messages de session/événements d'audit le référencent par evidenceId. */
export interface EvidenceRecord extends RecordBase {
  sceneCode?: string
  /** Message de session lié (id de message dsh) et canal (optionnels). */
  messageId?: string
  sessionId?: string
  /** Sujet de la conclusion (user:<id> / agent:<id>). */
  subject?: string
  anchors: EvidenceAnchor[]
  note?: string
}

export interface AlertRuleRecord extends RecordBase {
  name: string
  /** mcp_error_rate | mcp_latency | token_burst | agent_anomaly | permission_denied */
  metric: string
  operator: 'gt'
  threshold: number
  windowMinutes: number
  severity: 'critical' | 'warning' | 'info'
  channels: string[]
  enabled: boolean
  description?: string
}

export interface AlertEventRecord extends RecordBase {
  ruleId?: string
  severity: 'critical' | 'warning' | 'info'
  title: string
  message: string
  resourceType?: string
  resourceId?: string
  read: boolean
}

export interface CostRecord extends RecordBase {
  date: string
  appId?: string
  agentId?: string
  mcpServiceId?: string
  /** Dimension de consolidation des ressources de gouvernance des connecteurs (segment service de connector:<service>). */
  connectorService?: string
  llmTokens: number
  toolCalls: number
  costYuan: number
  /**
   * Taux de couverture de tarification (#14 additif) : priced = événements dont le tarif est en vigueur ; notPriced = événements à coût zéro
   * pour cause de tarif non configuré ou tarif entièrement nul. L'aval ne doit pas lire 0 comme « pas de consommation » — la couverture fonde le jugement des portes sur « le coût est-il consolidable ».
   * Les enregistrements existants n'ont pas ces deux champs (comptés 0 par défaut, hors dénominateur de couverture).
   */
  pricedEvents?: number
  notPricedEvents?: number
  /**
   * Marque d'existence non comptée (#14 relecture, additif) : buckets agrégés avant l'introduction des champs de couverture, dont le
   * priced/notPriced de la portion existante est inconnu (le périmètre d'autorité au niveau événement : identification d'instantané à tarif zéro de /api/usage/summary).
   * costReport marque la ligne coverage=legacy/mixed en conséquence ; les portes ne lisent plus « existant inconnu » comme « 0 enregistré ».
   */
  legacyUncounted?: boolean
}

export interface ApprovalRecord extends RecordBase {
  kind: string
  title: string
  payload: Record<string, unknown>
  requesterId: string
  requesterName: string
  /** superseded (clôture même objectif 2026-11-02) : l'objectif de ce dossier a été exécuté par un autre dossier de même objectif, clôture automatique, rien à traiter. */
  status: 'pending' | 'approved' | 'rejected' | 'executed' | 'failed' | 'superseded'
  approverId?: string
  approverName?: string
  opinion?: string
  createdAt: string
  decidedAt?: string
  execution?: { result: string; error?: string; at: string }
  /** Fondement de la clôture même objectif : id du dossier d'approbation déjà exécuté qui a privé celui-ci d'objet (toujours présent si status=superseded). */
  supersededBy?: string
  /** Niveau de risque (WP-10/L1) : l'approbation d'un dossier de niveau high exige une double confirmation (forcée côté serveur) et pose par défaut la marque de revue finale au niveau entreprise. */
  riskLevel?: 'high' | 'medium' | 'low'
  /** Marque de revue finale au niveau entreprise (WP-10/L1, additif) : relecteur et horodatage traçables dans l'audit (action=approval.final_review). */
  finalReview?: { approverId: string; approverName: string; at: string }
  /** Appartenance organisationnelle (clôture multi-entreprises R11, 2026-10-14) : source de données du filtrage des dossiers d'approbation par sous-arbre organisationnel.
   *  Les dossiers agent.* sont déduits automatiquement par createApproval depuis payload.agentId ; les dossiers existants sans ce champ sont invisibles aux non `*`. */
  orgId?: string
}

export type ApprovalExecutor = (payload: Record<string, unknown>, approverId: string) => Promise<unknown>

// ---------------------------------------------------------------------------
// Chaîne de hachage (W3-T5, contrat §14) : canonicalJSON (sérialisation à ordre de clés stable)
// ---------------------------------------------------------------------------

/**
 * canonicalJSON : sérialisation stable à clés triées récursivement (le recalcul du même enregistrement à tout instant est identique octet par octet).
 * Les tableaux conservent leur ordre ; les clés exclude (comme hash lui-même) sont retirées au niveau objet.
 */
export function canonicalJson(value: unknown, exclude: string[] = []): string {
  const skip = new Set(exclude)
  const walk = (input: unknown): string => {
    if (input === null) return 'null'
    if (input === undefined) return 'null'
    if (typeof input !== 'object') return JSON.stringify(input) ?? 'null'
    if (Array.isArray(input)) return `[${input.map(walk).join(',')}]`
    // Ordre de clés stable + aligné sur la sémantique de JSON.stringify : les clés à valeur undefined sont directement sautées (la sérialisation JSON les abandonne
    // pareillement). Si on les rendait null, « le hash recalculé sur l'objet en mémoire » et « le hash recalculé sur l'enregistrement stocké » divergeraient —
    // la chaîne de hachage deviendrait invérifiable pour les enregistrements d'appels MCP, les plus critiques (cause racine de l'audit sécurité W4 P0-1).
    const keys = Object.keys(input as Record<string, unknown>)
      .filter((key) => !skip.has(key) && (input as Record<string, unknown>)[key] !== undefined)
      .sort()
    return `{${keys.map((key) => `${JSON.stringify(key)}:${walk((input as Record<string, unknown>)[key])}`).join(',')}}`
  }
  return walk(value)
}

/** Périmètre des champs participant au hash d'un enregistrement de la chaîne d'audit : tous les champs métier, hors createdAt/updatedAt injectés au stockage et les champs de chaîne eux-mêmes. */
const AUDIT_HASH_EXCLUDE = ['createdAt', 'updatedAt', 'prevHash', 'hash']

/** Recalcule le hash d'un enregistrement (validation et écriture partagent la même source en point unique) : sha256(prevHash + canonicalJSON(champs métier)). */
export function auditHashOf(record: { prevHash?: string; hash?: string; [key: string]: unknown }, prevHash: string): string {
  return sha256Hex(prevHash + canonicalJson(record, AUDIT_HASH_EXCLUDE))
}

// ---------------------------------------------------------------------------
// Hygiène des charges d'approbation et source de règles indépendante (OPT-P2-02, 2026-09-12)
// ---------------------------------------------------------------------------

/**
 * Source de règles minimale indépendante (OPT-P2-02) : les contraintes d'exécution des approbations sont indépendantes du jugement d'autorisation principal.
 * ⚠ Déclaration de domaine de défaillance partagé : même processus, mêmes permissions, même code — cette table ne constitue pas une « protection indépendante » de niveau cryptographique,
 *   elle ne fait qu'extraire des périmètres de double confirmation/facette sensible des implémentations d'exécuteurs vers un artefact statique exposable en revue et en diff
 *   (déclaration complète : docs/shared-failure-domain-declaration.md).
 */
export interface ApprovalKindRule {
  /** Le passage d'un haut risque exige-t-il une double confirmation explicite (défaut : périmètre existant riskLevel==='high'). */
  requiresConfirmed?: boolean
  /** Facette d'entrées sensibles : mask = masquage puis stockage ; reject = refus direct d'ouvrir le dossier (pour les kind dont l'exécution exige le texte original). */
  sensitiveInputPolicy: 'mask' | 'reject'
}

const APPROVAL_KIND_RULES: Record<string, ApprovalKindRule> = {
  // La relance admin des connecteurs exige l'input original pour exécuter — les entrées sensibles ne peuvent pas être masquées (elles partiraient en *** vers le plan de données), seul le refus d'ouvrir le dossier est possible
  'connector.action.admin': { sensitiveInputPolicy: 'reject' },
  'connector.connect': { sensitiveInputPolicy: 'mask' },
  'connector.offline': { sensitiveInputPolicy: 'mask' },
}

export function approvalKindRule(kind: string): ApprovalKindRule {
  return { sensitiveInputPolicy: 'mask', ...APPROVAL_KIND_RULES[kind] }
}

/**
 * Les approbations L4 à haut risque sont high par défaut (QA A-06) : mise hors ligne de la passerelle de connecteurs/établissement de lien/relance admin, mise hors ligne MCP, partage NAS,
 * actions de cartes du panneau et activations sectorielles ne portaient pas riskLevel:'high' — un approve suffisait à exécuter, sans double confirmation,
 * en conflit avec le périmètre WP-10 « les opérations à haut risque exigent une double confirmation explicite ». Filet central : si l'appelant ne déclare pas explicitement, stockage en high.
 */
const HIGH_RISK_APPROVAL_KINDS = new Set([
  'connector.offline', 'connector.connect', 'connector.action.admin',
  'mcp.offline', 'nas.share', 'panel.card-action', 'industry.activation',
])

/**
 * Clôture des dossiers en cours sur un même objectif (2026-11-02) : pour les approbations de cycle de vie, il ne doit y avoir qu'un seul dossier en cours par « même ressource + même action ».
 * Contexte : après le dépôt humain d'un dossier de mise en ligne d'Agent, l'Agent de gouvernance en ouvrait un autre sur le même agentId et le validait — la ressource est online,
 * mais le dossier humain restait suspendu en attente pour toujours (une validation ultérieure serait refusée par la machine à états et tomberait failed), la console donnait l'impression d'un « défaut de synchronisation des données ».
 * Deux portes : au dépôt, une correspondance avec un dossier en cours du même objectif réutilise directement ce dossier (idempotent, pas de nouveau dossier, trace approval.reuse) ; après l'exécution réussie d'un dossier,
 * les autres dossiers en cours du même objectif passent automatiquement superseded (trace approval.superseded). Ne sont enregistrés que les kind dont
 * « l'effet d'exécution ne dépend que de l'id de ressource » — les dossiers d'action à paramètres propres comme connector.action.admin n'y participent pas (des paramètres différents sont des actions différentes, pas de fusion).
 */
const APPROVAL_TARGET_FIELD: Record<string, string> = {
  'agent.online': 'agentId', 'agent.offline': 'agentId', 'agent.unfreeze': 'agentId',
  'app.online': 'appId', 'app.offline': 'appId',
  'mcp.offline': 'serviceId',
}

/** Clé de même objectif : kind + id de ressource cible ; kind non enregistré ou charge sans id de cible → undefined (hors clôture). */
export function approvalTargetKey(kind: string, payload: Record<string, unknown> | undefined): string | undefined {
  const field = APPROVAL_TARGET_FIELD[kind]
  const value = field ? payload?.[field] : undefined
  return typeof value === 'string' && value ? `${kind}:${value}` : undefined
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class AuditService extends Service {
  static readonly provide = 'audit'

  private executors = new Map<string, ApprovalExecutor>()
  /** Registre des compensations (OPT-P2-02) : kind → orchestration de compensation après l'échec d'une action irréversible. */
  private compensations = new Map<string, (payload: Record<string, unknown>, error: Error) => Promise<unknown>>()
  private deniedCounter = new Map<string, number[]>()
  /** Durcissement de la lecture REL-11 : ressources à coûts sales déjà alertées (déduplication dans le processus, anti-tempête d'alertes). */
  private warnedDirtyCostResources = new Set<string>()
  /** Tête de la chaîne de hachage (W3-T5 §14) : au démarrage, le hash de la dernière entrée de la collection prolonge la chaîne (le redémarrage ne la brise pas). */
  private chainTip = ''
  private chainReady = false

  constructor(ctx: Context) {
    super(ctx, 'audit')

    // Instrumentation d'audit pilotée par événements : les changements d'état de chaque module atterrissent automatiquement dans les journaux d'audit
    const auditOf = (type: AuditType, action: string, result: AuditLogRecord['result'] = 'ok') =>
      (payload: unknown): void => {
        const p = payload as Record<string, any>
        this.record({
          type,
          actorType: p.actorType ?? 'system',
          actorId: p.actor ?? 'system',
          actorName: p.actorName ?? 'system',
          action,
          resourceType: p.type ?? action.split('.')[0],
          resourceId: p.id ?? p.jti ?? p.serviceId ?? '',
          resourceName: p.name ?? p.slug ?? p.title ?? '',
          result,
          detail: p.reason ?? p.note ?? JSON.stringify(payload).slice(0, 300),
        })
      }

    ctx.platformBus.on(PlatformEvents.TokenIssued, auditOf('auth', 'authn.token.issue'))
    ctx.platformBus.on(PlatformEvents.TokenRevoked, auditOf('auth', 'authn.token.revoke'))
    ctx.platformBus.on(PlatformEvents.UserFrozen, (payload) => {
      const p = payload as { userId: string; username: string; reason: string }
      this.record({
        type: 'change', actorType: 'system', actorId: 'iam-sync', actorName: 'IAM 联动',
        action: 'iam.user.freeze', resourceType: 'user', resourceId: p.userId, resourceName: p.username,
        result: 'ok', detail: p.reason,
      })
    })
    ctx.platformBus.on(PlatformEvents.McpDeployed, auditOf('change', 'mcp.service.deploy'))
    ctx.platformBus.on(PlatformEvents.McpOfflined, auditOf('change', 'mcp.service.offline'))
    // W1-T2 (gouvernance MCP §6) : traçabilité des lectures d'identifiants du Secret Broker (payload en métadonnées seules serviceId/credentialRef, zéro clair)
    ctx.platformBus.on(PlatformEvents.McpSecretAccess, auditOf('change', 'mcp.credential.access'))
    // Hébergement d'identifiants externes d'application (issue #19) : trace à chaque lecture (payload en métadonnées seules appId/key/result, zéro clair)
    ctx.platformBus.on(PlatformEvents.AppSecretAccess, auditOf('change', 'app.credential.access'))
    // Identifiants d'utilisation d'actifs (2026-10-31) : trace à chaque déclaration de faits d'utilisation par l'Agent (l'identifiant d'usage = preuve importante côté exploitation des actifs)
    ctx.platformBus.on(PlatformEvents.UsageAssetReported, auditOf('invoke', 'asset.usage.report'))
    // Traçabilité des appels d'outils plateforme (2026-11-02) : chaque appel via /mcp et le pont d'outils REST est comptabilisé individuellement (actorId = userId du membre,
    // un appel PAT humain est directement rattaché au membre) ; actorType mappé selon le même périmètre que ConnectorInvoked
    ctx.platformBus.on(PlatformEvents.ToolInvoked, (payload) => {
      const p = payload as { name: string; isError: boolean; durationMs?: number; surface?: string; error?: string; actorType?: string; actorId?: string; actorName?: string; actChain?: Array<{ name: string; type: string }> }
      this.record({
        type: 'invoke',
        actorType: p.actorType === 'human' ? 'human' : p.actorType === 'machine' ? 'machine' : 'system',
        actorId: p.actorId ?? '',
        actorName: p.actorName ?? '',
        action: 'tool.invoke',
        resourceType: 'tool',
        resourceId: p.name,
        resourceName: p.name,
        result: p.isError ? 'error' : 'ok',
        detail: `${p.surface ?? 'tool'} 调用${p.isError ? '失败' : '成功'} · ${p.durationMs ?? 0}ms${p.error ? ` · ${p.error}` : ''}`,
        ...(p.actChain && p.actChain.length > 0 ? { actChain: p.actChain } : {}),
      })
    })
    ctx.platformBus.on(PlatformEvents.McpUnhealthy, (payload) => {
      const p = payload as { serviceId: string; name: string; consecutiveFails: number }
      this.record({
        type: 'invoke', actorType: 'system', actorId: 'health-probe', actorName: '健康探活',
        action: 'mcp.service.unhealthy', resourceType: 'mcp_service', resourceId: p.serviceId, resourceName: p.name,
        result: 'error', detail: `连续失败 ${p.consecutiveFails} 次，触发熔断`,
      })
      this.evaluateAlerts('mcp_unhealthy', p)
    })
    ctx.platformBus.on(PlatformEvents.McpInvoked, (payload) => {
      const p = payload as { ok: boolean; latencyMs: number; serviceId: string; name: string; callerName: string; errorRate?: number; traceId?: string; decisionId?: string; decisionReasons?: string[]; status?: string }
      // Classement des résultats (audit sécurité W4 P0-4) : refus de stratégie (denied) et panne amont (error) doivent rester distinguables —
      // sinon « pourquoi permis/refusé » se dégrade dans l'audit en un seul type d'échec.
      const result: 'ok' | 'denied' | 'error' = p.ok ? 'ok' : p.status === 'denied' ? 'denied' : 'error'
      this.record({
        type: 'invoke', actorType: p.callerType ?? 'machine', actorId: p.callerId ?? '', actorName: p.callerName ?? '',
        action: 'mcp.gateway.invoke', resourceType: 'mcp_service', resourceId: p.serviceId, resourceName: p.name,
        result,
        detail: `latency=${p.latencyMs}ms${p.ok ? '' : result === 'denied' ? ' 策略拒绝' : ' 调用失败'}`,
        actChain: p.actChain,
        // Trace de bout en bout (W3-T5 §14, dimension optionnelle) : atterrit dans l'audit avec le payload v2 de mcp.invoked, reconstitution de la chaîne d'appel via ?traceId=
        ...(p.traceId ? { traceId: p.traceId } : {}),
        // Motifs de décision (W3-T5 §11/§16) : allow comme deny permettent de reconsulter « pourquoi permis/refusé »
        ...(p.decisionId ? { decisionId: p.decisionId } : {}),
        ...(p.decisionReasons?.length ? { decisionReasons: p.decisionReasons } : {}),
      })
    })
    // Gouvernance des connecteurs (fusion open-connector) : le journal d'invoke transmet actChain + runId (runId sans champ dédié, dans resourceId)
    ctx.platformBus.on(PlatformEvents.ConnectorInvoked, (payload) => {
      const p = payload as {
        ok?: boolean; service?: string; actionId?: string; runId?: string
        callerType?: string; callerId?: string; callerName?: string
        latencyMs?: number; error?: string; actChain?: Array<{ name: string; type: string }>
        auditPersisted?: boolean
      }
      this.record({
        type: 'invoke', actorType: p.callerType === 'user' ? 'human' : 'machine', actorId: p.callerId ?? '', actorName: p.callerName ?? '',
        action: 'connector.invoke', resourceType: 'connector_action', resourceId: p.runId ?? '', resourceName: `${p.service ?? ''}/${p.actionId ?? ''}`,
        result: p.ok ? 'ok' : 'error',
        detail: `run=${p.runId ?? ''} latency=${p.latencyMs ?? 0}ms${p.ok ? '' : ` 调用失败：${p.error ?? ''}`}${p.auditPersisted === false ? '（sidecar 审计未落库，平台已补记）' : ''}`,
        ...(p.actChain?.length ? { actChain: p.actChain } : {}),
      })
    })
    ctx.platformBus.on(PlatformEvents.ConnectorGatewayChanged, auditOf('change', 'connector.gateway.changed'))
    ctx.platformBus.on(PlatformEvents.ConnectorGatewayUnhealthy, (payload) => {
      const p = payload as { baseUrl?: string; consecutiveFails?: number; reason?: string }
      this.record({
        type: 'invoke', actorType: 'system', actorId: 'connector-probe', actorName: '连接器探活',
        action: 'connector.gateway.unhealthy', resourceType: 'connector_gateway', resourceId: 'gateway', resourceName: p.baseUrl ?? '',
        result: 'error', detail: `连续失败 ${p.consecutiveFails ?? 0} 次（fail-closed）：${p.reason ?? ''}`,
      })
    })
    ctx.platformBus.on(PlatformEvents.ConnectorConnected, auditOf('change', 'connector.connected'))
    ctx.platformBus.on(PlatformEvents.ConnectorDisconnected, auditOf('change', 'connector.disconnected'))
    ctx.platformBus.on(PlatformEvents.ConnectorPermGroupChanged, auditOf('change', 'connector.permgroup.changed'))
    // QA E-03 : les événements de type échec miroir ne parcouraient auparavant que la moitié du bus (pas d'abonnement audit, pas d'alerte) — compléter la trace d'audit + le câblage des alertes
    ctx.platformBus.on(PlatformEvents.ConnectorPolicyMirrorFailed, (payload) => {
      const p = payload as { groupId?: string; groupName?: string; reason?: string }
      this.record({
        type: 'invoke', actorType: 'system', actorId: 'connector-patrol', actorName: '连接器巡检',
        action: 'connector.policy_mirror_failed', resourceType: 'connector_permgroup',
        resourceId: String(p.groupId ?? ''), resourceName: String(p.groupName ?? ''),
        result: 'error', detail: `策略镜像失败（fail-closed，旧运行时令牌已吊销）：${p.reason ?? ''}`,
      })
      this.fire({
        severity: 'critical',
        title: t('[连接器] 权限组策略镜像失败'),
        message: t('权限组「{name}」策略镜像至网关失败，已 fail-closed 并吊销旧运行时令牌：{reason}', { name: p.groupName ?? p.groupId ?? '?', reason: p.reason ?? '' }),
        resourceType: 'connector_permgroup', ...(p.groupId !== undefined ? { resourceId: p.groupId } : {}),
      })
    })
    ctx.platformBus.on(PlatformEvents.ConnectorPolicySnapshotDrifted, (payload) => {
      const p = payload as { groupId?: string; groupName?: string; reason?: string }
      this.record({
        type: 'invoke', actorType: 'system', actorId: 'connector-patrol', actorName: '连接器巡检',
        action: 'connector.policy_snapshot_drifted', resourceType: 'connector_permgroup',
        resourceId: String(p.groupId ?? ''), resourceName: String(p.groupName ?? ''),
        result: 'error', detail: `策略快照漂移（拒绝按旧快照执行）：${p.reason ?? ''}`,
      })
      this.fire({
        severity: 'warning',
        title: t('[连接器] 权限组策略快照漂移'),
        message: t('权限组「{name}」调用时检出策略快照漂移，本次调用已拒绝（重试即按新快照走授权）：{reason}', { name: p.groupName ?? p.groupId ?? '?', reason: p.reason ?? '' }),
        resourceType: 'connector_permgroup', ...(p.groupId !== undefined ? { resourceId: p.groupId } : {}),
      })
    })
    ctx.platformBus.on(PlatformEvents.ConnectorGatewaySynced, (payload) => {
      const p = payload as { kind?: string; violations?: unknown[] }
      this.record({
        type: 'change', actorType: 'system', actorId: 'connector-patrol', actorName: '连接器巡检',
        action: 'connector.gateway.synced', resourceType: 'connector_gateway', resourceId: String(p.kind ?? ''), resourceName: '',
        result: (p.violations?.length ?? 0) > 0 ? 'error' : 'ok',
        detail: JSON.stringify(payload).slice(0, 300),
      })
    })
    ctx.platformBus.on(PlatformEvents.SkillPublished, auditOf('change', 'skill.publish'))
    ctx.platformBus.on(PlatformEvents.SkillDeprecated, auditOf('change', 'skill.deprecate'))
    ctx.platformBus.on(PlatformEvents.SkillInstalled, auditOf('change', 'skill.install'))
    ctx.platformBus.on(PlatformEvents.AgentRegistered, auditOf('change', 'agent.register'))
    ctx.platformBus.on(PlatformEvents.AgentOnlined, auditOf('change', 'agent.online'))
    ctx.platformBus.on(PlatformEvents.AgentOfflined, auditOf('change', 'agent.offline'))
    ctx.platformBus.on(PlatformEvents.AppOnlined, auditOf('change', 'app.online'))
    ctx.platformBus.on(PlatformEvents.AppOfflined, auditOf('change', 'app.offline'))
    ctx.platformBus.on(PlatformEvents.AppArchived, auditOf('change', 'app.archive'))
    ctx.platformBus.on(PlatformEvents.OidcAuthorizeGranted, (payload) => {
      const p = payload as { reqId: string; clientId: string; clientName: string; userId: string; userName: string; scope: string }
      this.record({
        type: 'auth', actorType: 'human', actorId: p.userId, actorName: p.userName,
        action: 'oidc.authorize.granted', resourceType: 'oidc_client', resourceId: p.clientId, resourceName: p.clientName,
        result: 'ok', detail: `授权通过（scope：${p.scope}，req：${p.reqId.slice(0, 8)}…）`,
      })
    })
    ctx.platformBus.on(PlatformEvents.OidcAuthorizeDenied, (payload) => {
      const p = payload as { reqId: string; clientId: string; clientName: string; userId: string; userName: string }
      this.record({
        type: 'auth', actorType: 'human', actorId: p.userId, actorName: p.userName,
        action: 'oidc.authorize.denied', resourceType: 'oidc_client', resourceId: p.clientId, resourceName: p.clientName,
        result: 'denied', detail: `用户拒绝授权（req：${p.reqId.slice(0, 8)}…）`,
      })
    })
    ctx.platformBus.on(PlatformEvents.UpdateAvailable, (payload) => {
      const p = payload as { currentVersion: string; latestVersion: string; behindBy: number }
      this.record({
        type: 'change', actorType: 'system', actorId: 'update-checker', actorName: '平台更新检查',
        action: 'platform.update.available', resourceType: 'platform', resourceId: 'self', resourceName: '平台升级',
        result: 'ok', detail: `上游新版本 ${p.currentVersion} → ${p.latestVersion}${p.behindBy > 0 ? `（落后 ${p.behindBy} 提交）` : ''}`,
      })
    })
    ctx.platformBus.on(PlatformEvents.UpdateApplied, (payload) => {
      const p = payload as { from: string; to: string; reason: string; actor: string }
      this.record({
        type: 'change', actorType: 'human', actorId: 'update-apply', actorName: p.actor,
        action: 'platform.update.applied', resourceType: 'platform', resourceId: 'self', resourceName: '平台升级',
        result: 'ok', detail: `${p.from} → ${p.to}，原因：${p.reason}`,
      })
    })
    ctx.platformBus.on(PlatformEvents.ApprovalCreated, auditOf('change', 'approval.create'))
    ctx.platformBus.on(PlatformEvents.ApprovalDecided, (payload) => {
      const p = payload as { approvalId: string; title: string; approved: boolean; approverName: string }
      this.record({
        type: 'authz', actorType: 'human', actorId: p.approverId ?? '', actorName: p.approverName ?? '',
        action: 'approval.decide', resourceType: 'approval', resourceId: p.approvalId, resourceName: p.title,
        result: 'ok', detail: p.approved ? t('审批通过') : t('审批驳回'),
      })
    })
    ctx.platformBus.on('audit.authz.denied', (payload) => {
      const p = payload as { actorId: string; actorName: string; point: string; path: string }
      this.record({
        type: 'authz', actorType: 'human', actorId: p.actorId, actorName: p.actorName,
        action: 'console.authz.denied', resourceType: 'api', resourceId: p.path, resourceName: p.path,
        result: 'denied', detail: t('缺少权限点 {point}', { point: p.point }),
      })
      const key = `denied:${p.actorId}`
      const now = Date.now()
      const times = (this.deniedCounter.get(key) ?? []).filter((t) => now - t < 10 * 60_000)
      times.push(now)
      this.deniedCounter.set(key, times)
      this.evaluateAlerts('permission_denied', { actorId: p.actorId, actorName: p.actorName, count: times.length, point: p.point })
    })
    ctx.platformBus.on(PlatformEvents.AlertFired, (payload) => {
      const p = payload as AlertEventRecord
      this.alerts().insert({
        id: p.id, ruleId: p.ruleId, severity: p.severity, title: p.title, message: p.message,
        ...(p.resourceType !== undefined ? { resourceType: p.resourceType } : {}),
        ...(p.resourceId !== undefined ? { resourceId: p.resourceId } : {}),
        read: false,
      })
    })

    // Clôture T2 (M2) : les événements de dégradation de l'accès distant atterrissent dans l'audit — auparavant connect.degraded s'arrêtait au bus,
    // sans abonnement audit ; les dérives sémantiques du type « croire gérer le distant alors qu'on gère le local » étaient invisibles dans la chaîne d'audit (la dégradation doit laisser une trace explicite).
    ctx.platformBus.on('connect.degraded', (payload) => {
      const p = payload as { reason?: string; tool?: string; detail?: string; at?: string }
      this.record({
        type: 'change', actorType: 'system', actorId: 'connect', actorName: '远程接入',
        action: 'connect.degraded', resourceType: 'connect', resourceId: p.tool ?? '-', resourceName: p.tool ?? '工具远程代理',
        result: 'error',
        detail: `reason=${p.reason ?? 'unknown'}${p.detail ? `；${p.detail}` : ''}`,
      })
    })

    // Consommation du pipeline de mesure (v1.2 étape 2) : usage.recorded → projection au périmètre financier + consolidation des coûts réels.
    // L'idempotence de consommation est garantie par l'idempotency_key des événements usage (livraison at-least-once + consommation idempotente).
    ctx.usage.consume('audit', (event) => {
      ctx.usage.project('audit', event)
      const agentId = event.subject.startsWith('agent:') ? event.subject.slice(6) : undefined
      const appId = event.principal.startsWith('app:') ? event.principal.slice(4) : undefined
      const mcpServiceId = event.resource.startsWith('mcp:') ? event.resource.slice(4) : undefined
      const connectorService = event.resource.startsWith('connector:') ? event.resource.slice('connector:'.length) : undefined
      const tokens = event.meters
        .filter((meter) => meter.key === 'input_tokens' || meter.key === 'output_tokens' || meter.key === 'tokens')
        .reduce((sum, meter) => sum + meter.value, 0)
      // Durcissement de la lecture REL-11 : pour les événements sales existants (le livre de prix avait écrit des tarifs non numériques), un cost_cents non fini est consolidé à 0,
      // contre la pollution NaN du registre de coûts ; une seule alerte warning par ressource
      const rawCostCents = event.pricing.cost_cents
      const safeCostCents = Number.isFinite(rawCostCents) ? rawCostCents : 0
      if (!Number.isFinite(rawCostCents) && !this.warnedDirtyCostResources.has(event.resource)) {
        this.warnedDirtyCostResources.add(event.resource)
        this.fire({
          severity: 'warning', title: t('[计量] 脏事件成本按 0 归集（REL-11 加固）'),
          message: t('资源 {resource} 的事件 {id} pricing.cost_cents={value} 为非有限值，成本归集按 0 处理；请修正价格簿后按时间窗重放', { resource: event.resource, id: event.event_id, value: String(rawCostCents) }),
          resourceType: 'usage_event', resourceId: event.resource,
        })
      }
      // #14 (2026-10-29) : jugement de non-tarification — coût zéro et (instantané à tarif zéro ou cost_status='not_priced' explicite).
      // Un événement au tarif en vigueur mais de faible volume arrondi à 0 reste compté priced, sans polluer la couverture.
      const notPricedEvent = safeCostCents === 0
        && ((event.pricing as { cost_status?: string }).cost_status === 'not_priced' || event.pricing.rate?.nonbillable === true)
      this.addCost({
        date: event.occurred_at.slice(0, 10),
        ...(agentId !== undefined ? { agentId } : {}),
        ...(appId !== undefined ? { appId } : {}),
        ...(mcpServiceId !== undefined ? { mcpServiceId } : {}),
        ...(connectorService !== undefined ? { connectorService } : {}),
        llmTokens: event.resource.startsWith('model:') ? tokens : 0,
        toolCalls: event.resource.startsWith('mcp:') || connectorService !== undefined ? 1 : 0,
        // QA B-06 : le périmètre de coût prend cost_cents (coût interne) — auparavant charge_cents (périmètre à facturer) jouait le rôle de coût,
        // dès qu'un prix passait non nul, le montant à facturer était présenté comme coût (résidu de sémantique de règlement interdit par M0) ; charge toujours 0, compatibilité instantané seulement
        costYuan: Math.round(safeCostCents * 100) / 10_000,
        // #14 : taux de couverture de tarification — coût zéro et (instantané à tarif zéro ou mention not_priced explicite) = non tarifié, pas de confusion avec le vrai coût zéro
        ...(notPricedEvent ? { pricedEvents: 0, notPricedEvents: 1 } : { pricedEvents: 1, notPricedEvents: 0 }),
      })
    })
  }

  // -- Collections ---------------------------------------------------------------

  logs(): Collection<AuditLogRecord> {
    return this.ctx.opsStorage.collection<AuditLogRecord>('audit:logs')
  }

  alertRules(): Collection<AlertRuleRecord> {
    return this.ctx.opsStorage.collection<AlertRuleRecord>('audit:alertRules')
  }

  alerts(): Collection<AlertEventRecord> {
    return this.ctx.opsStorage.collection<AlertEventRecord>('audit:alerts')
  }

  costs(): Collection<CostRecord> {
    return this.ctx.opsStorage.collection<CostRecord>('audit:costs')
  }

  approvals(): Collection<ApprovalRecord> {
    return this.ctx.opsStorage.collection<ApprovalRecord>('audit:approvals')
  }

  evidence(): Collection<EvidenceRecord> {
    return this.ctx.opsStorage.collection<EvidenceRecord>('audit:evidence')
  }

  // -- Journaux d'audit -----------------------------------------------------------

  /**
   * Point d'écriture unique (append-only) : calcul de la chaîne de hachage en point unique — hash = sha256(prevHash + canonicalJSON(champs métier)),
   * prevHash='' en tête de chaîne. Prolongation au démarrage : avant la première écriture, le hash de la dernière entrée de la collection devient la tête (redémarrage/changement de processus sans rupture,
   * la collection n'a pas de logique de purge, ordre total naturel). Périmètre de validation : pour les enregistrements existants, retirer prevHash/hash, recalculer et comparer au hash
   * (auditHashOf exporté ; la recette W4 et l'analyse externe partagent la même implémentation).
   */
  record(entry: Omit<AuditLogRecord, 'id' | 'createdAt' | 'updatedAt'>): AuditLogRecord {
    if (!this.chainReady) {
      const all = this.logs().all()
      this.chainTip = all.length > 0 ? String(all[all.length - 1]!.hash ?? '') : ''
      this.chainReady = true
    }
    const prevHash = this.chainTip
    const record = { id: newId('log'), ...entry }
    const hash = auditHashOf(record, prevHash)
    this.chainTip = hash
    return this.logs().insert({ ...record, prevHash, hash } as AuditLogRecord)
  }

  /** Hash courant de la queue de chaîne (l'export ndjson ajoute une ligne finale _chainTip ; entrée de réconciliation externe). */
  chainTipHash(): string {
    if (!this.chainReady) {
      const all = this.logs().all()
      return all.length > 0 ? String(all[all.length - 1]!.hash ?? '') : ''
    }
    return this.chainTip
  }

  /**
   * Export ndjson en flux (contrat §14, export append-only) : ordre des lignes = ordre chronologique (createdAt ascendant),
   * une ligne = un enregistrement d'audit complet (avec prevHash/hash vérifiables), dernière ligne {"_chainTip": "<lastHash>"}.
   * Écriture directe dans la réponse (Content-Type application/x-ndjson), point de permission identique au audit.read existant.
   */
  exportNdjson(exchange: { res: { writeHead(status: number, headers: Record<string, string>): unknown; end(text?: string): unknown } }, filter: { since?: string; until?: string } = {}): void {
    const rows = this.logs().find((log) => {
      if (filter.since && log.createdAt < filter.since) return false
      if (filter.until && log.createdAt > filter.until) return false
      return true
    }).sort((a, b) => a.createdAt.localeCompare(b.createdAt))
    const lines = rows.map((row) => JSON.stringify(row))
    lines.push(JSON.stringify({ _chainTip: this.chainTipHash() }))
    exchange.res.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8' })
    exchange.res.end(`${lines.join('\n')}\n`)
  }

  // -- Ancres de preuve (IAW passation 5-1) ---------------------------------------------

  /**
   * Enregistrement de preuve : le paquet d'ancres est validé puis stocké avec émission d'un id. La validation est structurelle (domaine de kind / id obligatoire / forme des fenêtres et lignes),
   * sans vérifier l'existence réelle du jeu de données référencé — cela relève de la réconciliation du domaine des données (resource datasets).
   */
  recordEvidence(input: {
    anchors: EvidenceAnchor[]
    sceneCode?: string
    messageId?: string
    sessionId?: string
    subject?: string
    note?: string
  }): EvidenceRecord {
    if (!Array.isArray(input.anchors) || input.anchors.length === 0) throw new Error(t('证据锚点至少一项（anchors）'))
    if (input.anchors.length > 20) throw new Error(t('证据锚点过多（≤20）：结论级证据应引用事实，不是搬运数据'))
    for (const anchor of input.anchors) {
      if (!['dataset', 'field', 'window', 'query', 'doc'].includes(anchor.kind)) throw new Error(t('证据锚点 kind 非法：{kind}（dataset/field/window/query/doc）', { kind: anchor.kind }))
      if (!anchor.id?.trim()) throw new Error(t('证据锚点 id 必填（数据集编号/字段路径/查询 id 等）'))
      if (anchor.timeWindow && (!anchor.timeWindow.from || !anchor.timeWindow.to)) throw new Error(t('证据锚点 timeWindow 需要 from/to'))
      if (anchor.hitRows !== undefined && (!Number.isFinite(anchor.hitRows) || anchor.hitRows < 0)) throw new Error(t('证据锚点 hitRows 应为非负数'))
      if (anchor.qualityScore !== undefined && (!Number.isFinite(anchor.qualityScore) || anchor.qualityScore < 0 || anchor.qualityScore > 100)) throw new Error(t('证据锚点 qualityScore 应为 0-100'))
    }
    return this.evidence().insert({
      id: newId('evd'),
      anchors: input.anchors,
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}),
      ...(input.messageId ? { messageId: input.messageId } : {}),
      ...(input.sessionId ? { sessionId: input.sessionId } : {}),
      ...(input.subject ? { subject: input.subject } : {}),
      ...(input.note ? { note: input.note } : {}),
    })
  }

  getEvidence(id: string): EvidenceRecord | undefined {
    return this.evidence().get(id)
  }

  // -- Chronologie de scénarios (IAW passation 5-2) -------------------------------------------

  /**
   * Chronologie d'audit par dimension scénario/tâche : chronologie inversée des journaux d'audit portant la dimension sceneCode (source de données du « récent »
   * du panneau et du tiroir de scénario ; l'audit intégral sans dimension sceneCode passe toujours par query()/logs).
   * REL-10 : les enregistrements de preuve (audit:evidence) portent aussi sceneCode, mais la timeline ne consultait qu'audit:logs —
   * après un enregistrement de preuve 200, la chronologie du scénario ne le voyait pas (rupture de chaîne, IAW 5-1→5-2). Désormais les enregistrements de preuve touchant sceneCode
   * sont fusionnés dans la chronologie comme entrées entryType='evidence' (tri temporel unifié) ; quand une ancre de preuve référence un id de log, evidenceIds est rétrorempli
   * de façon calculée sur l'entrée de log correspondante (modification de la réponse seule, schema de persistance inchangé). Champs existants : croissance seule.
   */
  timeline(filter: { sceneCode?: string; since?: string; limit?: number } = {}): { total: number; items: Array<{
    id: string; at: string
    /** Marque de type d'entrée (REL-10, additif) : 'log' = journal d'audit / 'evidence' = enregistrement d'ancre de preuve (IAW 5-1). */
    entryType: 'log' | 'evidence'
    /** Les quatre familles d'audit ; les entrées evidence n'ont pas de sémantique de type d'audit, défaut. */
    type?: AuditType
    action: string; actorName: string
    resourceType: string; resourceId: string; resourceName: string
    result: AuditLogRecord['result']; detail: string; sceneCode?: string; evidenceIds: string[]
    /** Propre aux entrées evidence (additif) : paquet d'ancres et note d'enregistrement. */
    anchors?: EvidenceAnchor[]; note?: string
  }> } {
    const all = this.logs().find((log) => {
      if (filter.sceneCode && log.sceneCode !== filter.sceneCode) return false
      if (filter.since && log.createdAt < filter.since) return false
      return true
    })
    const evidences = this.evidence().find((evd) => {
      if (filter.sceneCode && evd.sceneCode !== filter.sceneCode) return false
      if (filter.since && evd.createdAt < filter.since) return false
      return true
    })
    // Quand une ancre référence un id de log, evidenceIds est rétrorempli de façon calculée (fusion et déduplication à la couche réponse, sans stockage)
    const anchorRefs = new Map<string, string[]>()
    if (evidences.length > 0) {
      const logIds = new Set(all.map((log) => log.id))
      for (const evd of evidences) {
        for (const anchor of evd.anchors) {
          if (anchor.id && logIds.has(anchor.id)) {
            const refs = anchorRefs.get(anchor.id) ?? []
            if (!refs.includes(evd.id)) refs.push(evd.id)
            anchorRefs.set(anchor.id, refs)
          }
        }
      }
    }
    const items = [
      ...all.map((log) => ({
        id: log.id, at: log.createdAt, entryType: 'log' as const,
        type: log.type, action: log.action, actorName: log.actorName,
        resourceType: log.resourceType, resourceId: log.resourceId, resourceName: log.resourceName,
        result: log.result, detail: log.detail,
        ...(log.sceneCode ? { sceneCode: log.sceneCode } : {}),
        evidenceIds: [...(log.evidenceIds ?? []), ...(anchorRefs.get(log.id) ?? [])],
      })),
      ...evidences.map((evd) => ({
        id: evd.id, at: evd.createdAt, entryType: 'evidence' as const,
        action: 'audit.evidence', actorName: evd.subject ?? '',
        resourceType: 'evidence', resourceId: evd.id,
        resourceName: evd.note?.slice(0, 50) || `证据锚点×${evd.anchors.length}`,
        result: 'ok' as const,
        detail: evd.note ?? evd.anchors.map((anchor) => `${anchor.kind}:${anchor.id}`).join(', ').slice(0, 300),
        ...(evd.sceneCode ? { sceneCode: evd.sceneCode } : {}),
        evidenceIds: [evd.id],
        anchors: evd.anchors, ...(evd.note ? { note: evd.note } : {}),
      })),
    ]
      .sort((a, b) => b.at.localeCompare(a.at))
      .slice(0, Math.min(filter.limit ?? 50, 200))
    return { total: all.length + evidences.length, items }
  }

  query(filter: {
    type?: AuditType
    actorId?: string
    resourceType?: string
    resourceId?: string
    result?: string
    q?: string
    since?: string
    sceneCode?: string
    /** Correspondance exacte du trace de bout en bout (W3-T5 §14) : alignée sur la dimension traceId des mcp.invoked inscrits à l'audit. */
    traceId?: string
    limit?: number
  }): { total: number; items: AuditLogRecord[] } {
    const all = this.logs().find((log) => {
      if (filter.type && log.type !== filter.type) return false
      if (filter.actorId && log.actorId !== filter.actorId) return false
      if (filter.resourceType && log.resourceType !== filter.resourceType) return false
      if (filter.resourceId && log.resourceId !== filter.resourceId) return false
      if (filter.result && log.result !== filter.result) return false
      if (filter.since && log.createdAt < filter.since) return false
      if (filter.sceneCode && log.sceneCode !== filter.sceneCode) return false
      if (filter.traceId && log.traceId !== filter.traceId) return false
      if (filter.q && !`${log.action} ${log.actorName} ${log.resourceName} ${log.detail}`.toLowerCase().includes(filter.q.toLowerCase())) return false
      return true
    })
    const items = all.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    const limit = filter.limit ?? 100
    return { total: all.length, items: items.slice(0, limit) }
  }

  summary(): Record<string, number> {
    const result: Record<string, number> = { auth: 0, authz: 0, invoke: 0, change: 0, denied: 0, error: 0 }
    for (const log of this.logs().all()) {
      result[log.type] = (result[log.type] ?? 0) + 1
      if (log.result === 'denied') result.denied!++
      if (log.result === 'error') result.error!++
    }
    return result
  }

  // -- Alertes ---------------------------------------------------------------

  createAlertRule(input: Omit<AlertRuleRecord, 'id' | 'createdAt' | 'updatedAt'>): AlertRuleRecord {
    // REL-12 : convergence de la validation des entrées du point de création — auparavant, un 200 archivait sans name ni threshold fini (une règle
    // sans name rend l'alerte illisible, un seuil illégal fausse la comparaison « > seuil »). Toute illégalité lève (la route guarded mappe uniformément en 400 BAD_REQUEST)
    if (typeof input.name !== 'string' || input.name.trim() === '') throw new Error(t('告警规则 name 必填（非空字符串）'))
    if (typeof input.metric !== 'string' || input.metric.trim() === '') throw new Error(t('告警规则 metric 必填（非空字符串）'))
    if (!Number.isFinite(input.threshold)) throw new Error(t('告警规则 threshold 必须为有限数值，收到：{value}', { value: String(input.threshold) }))
    if (input.operator !== undefined && input.operator !== 'gt') throw new Error(t('告警规则 operator 非法：{value}（当前仅支持 gt）', { value: String(input.operator) }))
    return this.alertRules().insert({ id: newId('rule'), ...input })
  }

  /** Entrée d'évaluation des alertes : appelée par chaque source d'événements, déclenche une alerte en cas de correspondance de règle. */
  evaluateAlerts(metric: string, context: Record<string, unknown>): void {
    for (const rule of this.alertRules().find((item) => item.enabled && item.metric === metric)) {
      const value = Number(context[metric === 'permission_denied' ? 'count' : metric === 'mcp_unhealthy' ? 'consecutiveFails' : 'value'] ?? 0)
      if (!(value > rule.threshold)) continue
      this.fire({
        ruleId: rule.id,
        severity: rule.severity,
        title: t('[{name}] 触发', { name: rule.name }),
        message: t('{metric} = {value}（阈值 {threshold}），上下文：{context}', { metric: rule.metric, value, threshold: rule.threshold, context: JSON.stringify(context).slice(0, 200) }),
        ...(context.resourceType !== undefined ? { resourceType: String(context.resourceType) } : {}),
        ...(context.resourceId !== undefined ? { resourceId: String(context.resourceId) } : {}),
      })
    }
  }

  /** Déclenche directement une alerte (alertes système sans règle). */
  fire(input: Omit<AlertEventRecord, 'id' | 'createdAt' | 'updatedAt' | 'read'>): void {
    this.ctx.platformBus.emit(PlatformEvents.AlertFired, {
      id: newId('alt'), read: false, ...input,
    })
  }

  markAlertRead(id: string): void {
    this.alerts().update(id, { read: true })
  }

  /** Tout marquer lu : passe toutes les alertes non lues en lues, renvoie le nombre traité cette fois. */
  markAllAlertsRead(): number {
    const unread = this.alerts().find((alert) => !alert.read)
    for (const alert of unread) this.alerts().update(alert.id, { read: true })
    return unread.length
  }

  // -- Coûts ---------------------------------------------------------------

  addCost(input: Omit<CostRecord, 'id' | 'createdAt' | 'updatedAt'>): void {
    const existing = this.costs().findOne((cost) =>
      cost.date === input.date
      && (cost.appId ?? '') === (input.appId ?? '')
      && (cost.agentId ?? '') === (input.agentId ?? '')
      && (cost.mcpServiceId ?? '') === (input.mcpServiceId ?? '')
      && (cost.connectorService ?? '') === (input.connectorService ?? ''))
    if (existing) {
      this.costs().update(existing.id, {
        llmTokens: existing.llmTokens + input.llmTokens,
        toolCalls: existing.toolCalls + input.toolCalls,
        costYuan: Math.round((existing.costYuan + input.costYuan) * 1000) / 1000,
        // #14 : fusion incrémentale de la couverture (buckets existants sans champ partent de 0, additif sans migration)
        pricedEvents: (existing.pricedEvents ?? 0) + (input.pricedEvents ?? 0),
        notPricedEvents: (existing.notPricedEvents ?? 0) + (input.notPricedEvents ?? 0),
        // #14 relecture : les buckets agrégés avant l'introduction des champs de couverture sont fusionnés par de nouveaux événements — la couverture de la portion existante est inconnue,
        // marquage du périmètre mixte ; le coverage de costReport signale mixed au lieu de mentir avec un live 100% couvert
        ...(existing.pricedEvents === undefined && existing.notPricedEvents === undefined ? { legacyUncounted: true } : {}),
      })
    } else {
      this.costs().insert({ id: newId('cost'), ...input })
    }
  }

  costReport(groupBy: 'app' | 'agent' | 'org' | 'date', from?: string, to?: string): Array<{ key: string; llmTokens: number; toolCalls: number; costYuan: number; priced: number; notPriced: number; coverage: 'live' | 'legacy' | 'mixed' }> {
    const buckets = new Map<string, { key: string; llmTokens: number; toolCalls: number; costYuan: number; priced: number; notPriced: number; liveRecords: number; legacyRecords: number }>()
    for (const cost of this.costs().all()) {
      if (from && cost.date < from) continue
      if (to && cost.date > to) continue
      let key = cost.date
      if (groupBy === 'app') key = cost.appId ? this.ctx.resourceCore?.collection('app').get(cost.appId)?.name ?? cost.appId : t('（未归集应用）')
      if (groupBy === 'agent') key = cost.agentId ? this.ctx.resourceCore?.collection('agent').get(cost.agentId)?.name ?? cost.agentId : t('（未归集 Agent）')
      if (groupBy === 'org') {
        const entity = cost.agentId ? this.ctx.resourceCore?.collection('agent').get(cost.agentId) : undefined
        key = entity ? this.ctx.iam?.orgs().get(entity.orgId)?.name ?? entity.orgId : t('（未归集组织）')
      }
      const bucket = buckets.get(key) ?? { key, llmTokens: 0, toolCalls: 0, costYuan: 0, priced: 0, notPriced: 0, liveRecords: 0, legacyRecords: 0 }
      bucket.llmTokens += cost.llmTokens
      bucket.toolCalls += cost.toolCalls
      bucket.costYuan += cost.costYuan
      // #14 : couverture (les enregistrements existants sans champ sont hors dénominateur — les portes jugent la fiabilité de consolidation par priced+notPriced>0)
      bucket.priced += cost.pricedEvents ?? 0
      bucket.notPriced += cost.notPricedEvents ?? 0
      // #14 relecture : coverage permet aux portes de distinguer « 0 enregistré » et « existant inconnu » — legacy = tous les enregistrements antérieurs aux champs
      // de couverture (priced/notPriced toujours 0 : inconnu, pas un vrai 0) ; mixed = une partie de l'existant non comptée ; live = tout est enregistré
      const hasCoverage = cost.pricedEvents !== undefined || cost.notPricedEvents !== undefined
      if (hasCoverage && !cost.legacyUncounted) bucket.liveRecords += 1
      else bucket.legacyRecords += 1
      buckets.set(key, bucket)
    }
    return [...buckets.values()].map((bucket) => ({
      key: bucket.key,
      llmTokens: bucket.llmTokens,
      toolCalls: bucket.toolCalls,
      costYuan: Math.round(bucket.costYuan * 1000) / 1000,
      priced: bucket.priced,
      notPriced: bucket.notPriced,
      coverage: bucket.liveRecords > 0 && bucket.legacyRecords === 0 ? 'live' as const : bucket.liveRecords === 0 ? 'legacy' as const : 'mixed' as const,
    }))
      .sort((a, b) => b.costYuan - a.costYuan)
  }

  // -- Centre d'approbations -----------------------------------------------------------

  /** Enregistre l'exécuteur d'une classe d'approbation (exécuté automatiquement après validation). */
  registerExecutor(kind: string, executor: ApprovalExecutor): () => void {
    this.executors.set(kind, executor)
    return () => this.executors.delete(kind)
  }

  /**
   * Enregistre un compensateur (OPT-P2-02) : quand l'exécuteur d'une action irréversible échoue, l'orchestration de compensation du registre s'applique et le dossier est réécrit.
   * Le compensateur reçoit (payload, erreur d'origine) ; la valeur de retour est tracée dans execution.result.
   */
  registerCompensation(kind: string, compensation: (payload: Record<string, unknown>, error: Error) => Promise<unknown>): () => void {
    this.compensations.set(kind, compensation)
    return () => this.compensations.delete(kind)
  }

  createApproval(input: {
    kind: string
    title: string
    payload: Record<string, unknown>
    requesterId: string
    requesterName: string
    riskLevel?: 'high' | 'medium' | 'low'
    orgId?: string
  }): ApprovalRecord {
    // OPT-P2-02 : traitement de la facette sensible avant le stockage d'approbation — les kind de type reject voient le dossier refusé ; les autres sont profondément masqués avant stockage
    const rule = approvalKindRule(input.kind)
    const sensitivePaths = scanSensitiveKeys(input.payload)
    if (rule.sensitiveInputPolicy === 'reject' && sensitivePaths.length > 0) {
      throw new Error(t('审批拒绝：该类审批以原文入参执行，检出敏感命名入参（{paths}）。敏感值不得进入审批存储，请调整入参后重试（OPT-P2-02）', { paths: sensitivePaths.join('、') }))
    }
    // Réutilisation idempotente des dossiers en cours de même objectif (APPROVAL_TARGET_FIELD) : un dossier pending du même objectif existant → renvoyer ce dossier directement, sans en créer un nouveau —
    // la trace approval.reuse consigne l'intention du second demandeur ; le approval_decide suivant converge naturellement vers le même dossier
    const targetKey = approvalTargetKey(input.kind, input.payload)
    const existing = targetKey
      ? this.approvals().findOne((item) => item.status === 'pending' && approvalTargetKey(item.kind, item.payload) === targetKey)
      : undefined
    if (existing) {
      this.record({
        type: 'change', actorType: input.requesterId.startsWith('pri_') ? 'machine' : 'human',
        actorId: input.requesterId, actorName: input.requesterName,
        action: 'approval.reuse', resourceType: 'approval', resourceId: existing.id, resourceName: existing.title,
        result: 'ok', detail: `同目标在途审批单复用（${targetKey}）：${input.requesterName} 再次发起，沿用 ${existing.requesterName} 提交的 ${existing.id}，未新增审批单`,
      })
      return existing
    }
    const { masked, maskedKeys } = maskSensitivePayload(input.payload)
    const riskLevel = input.riskLevel ?? (HIGH_RISK_APPROVAL_KINDS.has(input.kind) ? 'high' as const : undefined)
    // R11 : appartenance organisationnelle — l'argument explicite prime ; pour les dossiers agent.* sans argument, repli sur l'orgId de l'Agent lu par la clé stable plateforme
    // (l'appelant plugin-agent obtient l'appartenance sans aucun changement ; la lecture inter-plugins entity:agent suit la même convention que dashboard)
    let orgId = input.orgId
    if (!orgId && input.kind.startsWith('agent.') && input.payload['agentId']) {
      try {
        orgId = this.ctx.opsStorage.collection<{ orgId?: string }>('entity:agent').get(String(input.payload['agentId']))?.orgId
      } catch { /* un échec de déduction ne bloque pas l'ouverture du dossier (un dossier sans appartenance est invisible aux non `*`) */ }
    }
    const record = this.approvals().insert({
      id: newId('apr'),
      ...input,
      ...(orgId ? { orgId } : {}),
      ...(riskLevel !== undefined ? { riskLevel } : {}),
      ...(maskedKeys.length > 0 ? { payload: { ...(masked as Record<string, unknown>), maskedKeys } } : {}),
      status: 'pending',
      createdAt: new Date().toISOString(),
    })
    this.ctx.platformBus.emit(PlatformEvents.ApprovalCreated, {
      approvalId: record.id, kind: record.kind, title: record.title,
      requesterId: record.requesterId, requesterName: record.requesterName,
    })
    return record
  }

  /**
   * Décision d'approbation (renforcement WP-10) : la validation d'un haut risque exige une double confirmation explicite (forcée côté serveur, confirmed=true) ;
   * après validation d'un haut risque (ou finalReview explicite), pose la « marque de revue finale au niveau entreprise » et l'écrit dans l'audit (action=approval.final_review,
   * marque de revue finale L1 traçable dans l'audit).
   */
  async decideApproval(
    id: string,
    decision: 'approve' | 'reject',
    approverId: string,
    approverName: string,
    opinion?: string,
    options: { confirmed?: boolean; finalReview?: boolean } = {},
  ): Promise<ApprovalRecord> {
    // REL-01 : convergence de l'entrée decision — seuls approve/reject sont acceptés. Auparavant, toute autre valeur (p. ex. "maybe") tombait
    // dans la branche approve et s'exécutait réellement ; interception en point unique en couche service (la route guarded mappe uniformément en 400).
    if (decision !== 'approve' && decision !== 'reject') {
      throw new Error(t('非法的审批决策：{decision}（只允许 approve 或 reject）', { decision: String(decision) }))
    }
    const approval = this.approvals().get(id)
    if (!approval) throw new Error(t('审批单不存在：{id}', { id }))
    if (approval.status !== 'pending') throw new Error(t('审批单已处理（{status}）', { status: approval.status }))
    // Auto-approbation ouverte pour tous les types (arbitrage métier 2026-11-02) : les organisations natives IA ont peu de personnel, l'administrateur peut
    // approuver directement ses propres dossiers (y compris la sémantique d'embauche agent.online) — déjà ouvert le 2026-09-15, puis resserré le 2026-10-14
    // par la relecture R12 qui ne gardait la séparation des responsabilités que pour agent.online ; cette fois, la dernière restriction est levée selon l'arbitrage le plus récent ;
    // le point de permission (approval.decide) et la sémantique de double confirmation confirmed pour les hauts risques restent inchangés.
    const isHighRisk = approval.riskLevel === 'high'
    if (decision === 'approve' && isHighRisk && options.confirmed !== true) {
      throw new Error(t('高风险审批通过需二次确认（confirmed=true），请在前端确认弹窗中复核后提交'))
    }
    if (decision === 'reject') {
      const updated = this.approvals().update(id, {
        status: 'rejected', approverId, approverName,
        ...(opinion !== undefined ? { opinion } : {}),
        decidedAt: new Date().toISOString(),
      })
      this.ctx.platformBus.emit(PlatformEvents.ApprovalDecided, {
        approvalId: id, title: approval.title, approved: false, approverId, approverName,
      })
      return updated
    }
    const executor = this.executors.get(approval.kind)
    let execution: ApprovalRecord['execution']
    if (executor) {
      try {
        const result = await executor(approval.payload, approverId)
        execution = { result: JSON.stringify(result ?? { ok: true }).slice(0, 500), at: new Date().toISOString() }
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error))
        execution = { result: t('执行失败'), error: err.message, at: new Date().toISOString() }
        // OPT-P2-02 : l'échec de l'exécuteur ne produit plus seulement approval.execution.error — l'orchestration de compensation du registre s'applique et réécrit
        const compensation = this.compensations.get(approval.kind)
        if (compensation) {
          try {
            const compResult = await compensation(approval.payload, err)
            execution = {
              result: t('执行失败，已完成补偿：{result}', { result: JSON.stringify(compResult ?? { ok: true }).slice(0, 200) }),
              error: err.message, at: new Date().toISOString(),
            }
          } catch (compError) {
            const compMessage = compError instanceof Error ? compError.message : String(compError)
            execution = { result: t('执行失败且补偿失败（需人工介入）'), error: t('{message}；补偿失败：{compensation}', { message: err.message, compensation: compMessage }), at: new Date().toISOString() }
          }
          this.record({
            type: 'change', actorType: 'machine', actorId: 'approval-engine', actorName: '审批引擎',
            action: 'approval.compensated', resourceType: 'approval', resourceId: id, resourceName: approval.title,
            result: 'ok', detail: `执行器失败已按注册表编排补偿（kind=${approval.kind}，审批单 ${id}）`,
          })
        }
      }
    } else {
      execution = { result: t('（无注册执行器，仅记录审批结果）'), at: new Date().toISOString() }
    }
    const status: ApprovalRecord['status'] = execution.error ? 'failed' : 'executed'
    const needsFinalReview = isHighRisk || options.finalReview === true
    const updated = this.approvals().update(id, {
      status, approverId, approverName,
      ...(opinion !== undefined ? { opinion } : {}),
      decidedAt: new Date().toISOString(),
      execution,
      ...(needsFinalReview ? { finalReview: { approverId, approverName, at: new Date().toISOString() } } : {}),
    })
    if (needsFinalReview) {
      // Marque de revue finale au niveau entreprise L1 → trace d'audit (recherche rétrospective par action=approval.final_review)
      this.record({
        type: 'change', actorType: 'human', actorId: approverId, actorName: approverName,
        action: 'approval.final_review', resourceType: 'approval', resourceId: id, resourceName: approval.title,
        result: 'ok', detail: `公司级终审标记（风险级 ${approval.riskLevel ?? 'medium'}），审批单 ${id} 终审通过`,
      })
    }
    // Clôture même objectif : l'exécution de ce dossier réussit → les demandes des autres dossiers en cours du même objectif sont satisfaites, passage automatique en superseded (pas de clôture en échec, surface de reprise conservée)
    if (status === 'executed') this.supersedeSiblings(updated)
    this.ctx.platformBus.emit(PlatformEvents.ApprovalDecided, {
      approvalId: id, title: approval.title, approved: true, approverId, approverName,
    })
    return updated
  }

  /**
   * Supprime un dossier d'approbation (nettoyage des dossiers rejetés) : seul l'état final « rejeté » est supprimable — un dossier rejeté n'a exécuté aucune action, la suppression ne sert
   * qu'à nettoyer la liste des tâches ; les dossiers pending/approved/executed/failed contiennent des faits d'exécution, jamais supprimables (la trace d'audit n'est pas affectée).
   */
  deleteApproval(id: string): void {
    const approval = this.approvals().get(id)
    if (!approval) throw new Error(t('审批单不存在：{id}', { id }))
    if (approval.status !== 'rejected') {
      throw new Error(t('仅已驳回的审批单可删除，当前状态：{status}', { status: approval.status }))
    }
    this.approvals().remove(id)
  }

  /**
   * Clôture même objectif (APPROVAL_TARGET_FIELD) : après l'exécution réussie d'un dossier, les dossiers pending du même objectif déposés avant
   * son instant de décision sont satisfaits (une validation ultérieure serait refusée par la machine à états et tomberait failed) → passage automatique en superseded avec trace.
   * Pas d'émission d'ApprovalDecided — la clôture n'est ni une validation ni un rejet, pour éviter que l'aval la prenne pour un rejet et notifie le demandeur.
   * La frontière « déposé avant l'instant de décision » permet à l'auto-réparation de démarrage de réutiliser cette méthode : un dossier du même objectif ouvert après l'exécution
   * est une demande légitime nouvelle (p. ex. mise en ligne → retrait → remise en ligne), à ne pas clôturer à tort. Renvoie le nombre de dossiers clôturés.
   */
  supersedeSiblings(executed: Pick<ApprovalRecord, 'id' | 'kind' | 'payload' | 'decidedAt'>): number {
    const targetKey = approvalTargetKey(executed.kind, executed.payload)
    if (!targetKey) return 0
    const bound = executed.decidedAt ?? new Date().toISOString()
    const siblings = this.approvals().find((item) => item.id !== executed.id && item.status === 'pending'
      && item.createdAt <= bound && approvalTargetKey(item.kind, item.payload) === targetKey)
    const now = new Date().toISOString()
    for (const sibling of siblings) {
      this.approvals().update(sibling.id, {
        status: 'superseded', supersededBy: executed.id, decidedAt: now,
        approverId: 'approval-engine', approverName: '审批引擎',
        opinion: t('同目标审批单 {id} 已执行，本单诉求已满足，自动收口（无需处理）', { id: executed.id }),
      })
      this.record({
        type: 'change', actorType: 'machine', actorId: 'approval-engine', actorName: '审批引擎',
        action: 'approval.superseded', resourceType: 'approval', resourceId: sibling.id, resourceName: sibling.title,
        result: 'ok', detail: `同目标在途单收口（${targetKey}）：${executed.id} 已执行，${sibling.id}（${sibling.requesterName} 提交）自动置 superseded`,
      })
    }
    return siblings.length
  }

  /**
   * Auto-réparation de l'existant au démarrage (2026-11-02) : dossiers orphelins créés avant la mise en service de la clôture — un dossier du même objectif déjà executed et déposé
   * avant sa décision, toujours pending aujourd'hui — passe en superseded selon le même périmètre. Pour chaque objectif, le dossier exécuté le plus tard sert de référence ; idempotent
   * (zéro écriture sans orphelin). Renvoie le nombre de dossiers clôturés.
   */
  reconcileSupersededApprovals(): number {
    const latestExecuted = new Map<string, ApprovalRecord>()
    for (const item of this.approvals().find((item) => item.status === 'executed' && Boolean(item.decidedAt))) {
      const key = approvalTargetKey(item.kind, item.payload)
      if (!key) continue
      const prev = latestExecuted.get(key)
      if (!prev || item.decidedAt! > prev.decidedAt!) latestExecuted.set(key, item)
    }
    let count = 0
    for (const executed of latestExecuted.values()) count += this.supersedeSiblings(executed)
    return count
  }

  /**
   * Rapport SLA des approbations (WP-10) : taux de respect « ≤ 2 jours ouvrés » et détail des décisions dans la fenêtre.
   * Périmètre de jour ouvré : après exclusion des samedis/dimanches, cumul par jours calendaires (pas de calendrier des jours fériés — périmètre v1 déclaré dans la réponse).
   */
  slaReport(windowDays = 30): {
    windowDays: number
    total: number
    decided: number
    withinSla: number
    achievementRate: number
    breached: Array<{ id: string; kind: string; title: string; businessDays: number; decidedAt: string }>
    calendarNote: string
  } {
    const since = new Date(Date.now() - windowDays * 24 * 3600_000).toISOString()
    // superseded est une clôture automatique du moteur (pas une décision humaine), hors dénominateur SLA
    const decidedRecords = this.approvals().all()
      .filter((item) => item.decidedAt && item.decidedAt >= since && item.status !== 'superseded')
    const businessDaysBetween = (fromIso: string, toIso: string): number => {
      let days = 0
      const cursor = new Date(fromIso)
      const end = new Date(toIso)
      while (cursor < end) {
        const day = cursor.getUTCDay()
        if (day !== 0 && day !== 6) days++
        cursor.setUTCDate(cursor.getUTCDate() + 1)
      }
      return days
    }
    const breached: Array<{ id: string; kind: string; title: string; businessDays: number; decidedAt: string }> = []
    let withinSla = 0
    for (const item of decidedRecords) {
      const days = businessDaysBetween(item.createdAt, item.decidedAt!)
      if (days <= 2) withinSla++
      else breached.push({ id: item.id, kind: item.kind, title: item.title, businessDays: days, decidedAt: item.decidedAt! })
    }
    return {
      windowDays,
      total: this.approvals().all().filter((item) => item.createdAt >= since).length,
      decided: decidedRecords.length,
      withinSla,
      achievementRate: decidedRecords.length === 0 ? 1 : Math.round((withinSla / decidedRecords.length) * 1000) / 1000,
      breached: breached.sort((a, b) => b.businessDays - a.businessDays),
      calendarNote: t('工作日=跳过周六/周日（未扣法定节假日，v1 口径）'),
    }
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    audit: AuditService
  }
}

export const name = 'audit'
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'iam', 'usage']

export function apply(ctx: Context) {
  ctx.plugin(AuditService)
  ctx.plugin(auditTools)
  // Auto-réparation de l'existant au démarrage : dossiers orphelins de même objectif créés avant la mise en service de la clôture (2026-11-02). Ce plugin ne peut pas s'injecter son propre service
  // (attente circulaire) ; un sous-plugin déclare inject et exécute une fois audit prêt
  ctx.plugin({
    name: 'audit-approval-reconcile',
    inject: ['audit'],
    apply(child: Context) {
      const count = child.audit.reconcileSupersededApprovals()
      if (count > 0) child.logger('audit').info(`存量审批单自愈：${count} 张同目标孤儿单已收口（superseded）`)
    },
  })
}
