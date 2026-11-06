/**
 * @dsh-ops/plugin-connector — gestion des connecteurs SaaS (fusion open-connector v1.4.0, 2e volet de données de l'étape 9 du plan de route).
 *
 * Répartition contrôle/données : method = plan de contrôle de gouvernance (RBAC + groupes de permissions connecteur + approbation haut risque + metering/facturation + audit) ;
 * open-connector sidecar = passerelle du plan de données + coffre d'identifiants (AES-256-GCM, les identifiants ne reviennent jamais sur la plateforme).
 * Cette extension ne fait que mise en correspondance et câblage : pas de catalogue provider maison, pas d'OAuth maison, pas de coffre de clés maison.
 *
 * Trois lignes rouges :
 *   1. zéro identifiant côté plateforme — les références de connexion n'ont aucun champ d'identifiant ; les formulaires API Key passent par le proxy direct vers le sidecar sans persistance ;
 *       les valeurs de jetons d'exécution oct_ ne vivent qu'en mémoire de processus (le registre ne conserve que ocTokenId/policySnapshotHash) ;
 *   2. double validation des autorisations — la chaîne d'autorisation des groupes de permissions de la plateforme et le miroir de politique des jetons oct_ refusent chacun indépendamment ;
 *   3. audit actChain de bout en bout + réconciliation du metering — usage.record est la source de fait de facturation, les runs sont recoupés par runtimeTokenId.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, newId, sha256Hex, scanSensitiveKeys, wrapPolicyDecision, type Collection, type RecordBase, type ToolPrincipal } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { OcClient, OC_VERSION_PIN, type OcConnectionSummary, type OcRunLog, type OcTokenPolicy } from './client.ts'
import { OcError } from './errors.ts'
import { rankOf, resolveRiskLevel, riskTierOf, type RiskLevel, type RiskTier } from './risk.ts'
import { inOdd, normalizeOdd, type OddDeclaration } from './odd.ts'
import {
  WORK_DENY_CODE_LABELS,
  gateManagedWork,
  type WorkCallerRef,
  type WorkRefIndex,
  type WorkforcePolicyRegistry,
} from '../../platform-core/src/workforce-port.ts'
import * as connectorTools from './tools.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

export interface GatewayRecord extends RecordBase {
  baseUrl: string
  /** Mise hors ligne de maintenance (sémantique d'approbation connector.offline) : si vrai, le sondage de santé est directement sauté pour éviter une résurrection automatique par le minuteur. */
  maintOffline?: boolean
  /** Bearer du plan de gestion : référence indirecte `env:VAR` (obligatoire en production) ; les tests peuvent renseigner directement un mot de passe stub. */
  adminToken: string
  status: 'unconfigured' | 'healthy' | 'unavailable'
  health: { lastProbeAt?: string; latencyMs?: number; consecutiveFails: number }
  /** Raison d'indisponibilité (écrite pour les opérateurs en cas de fail-closed). */
  unavailableReason?: string
  versionPin: string
  /** Période de synchronisation automatique du catalogue en minutes ; 0 = déclenchement manuel. */
  autoCatalogSyncMinutes: number
}

export interface CatalogActionRecord {
  id: string
  service: string
  name?: string
  description?: string
  riskLevel: RiskLevel
  /** Étage provider du catalogue déclaratif de risques R6 (S1 = conventionnel à bas risque / S2 = haute sensibilité) ; valeur par défaut sans déclaration, affichage seul, couplage approbation à venir. */
  riskTier?: RiskTier
  requiredScopes: string[]
  providerPermissions: string[]
  inputSchema: Record<string, unknown>
}

export interface CatalogRecord extends RecordBase {
  providers: Array<Record<string, unknown>>
  actions: CatalogActionRecord[]
  skippedServices: Array<{ service: string; reason: string }>
  syncedAt?: string
}

/** Référence de connexion au préfixe d'alias `org:<orgId>:` imposé — aucun champ d'identifiant (ligne rouge 1). */
export interface ConnectionReferenceRecord extends RecordBase {
  provider: string
  alias: string
  authType: 'oauth' | 'api_key' | 'custom_credential' | 'no_auth'
  ocConnectionId?: string
  status: 'pending' | 'active' | 'error'
  ownerOrgId: string
  createdBy: string
  maskedProfile?: Record<string, string>
  bridge: boolean
  lastSyncedAt?: string
  requestId?: string
  approvalId?: string
  errorReason?: string
  /** Mise hors ligne de maintenance au niveau connexion (connector.offline) : si non vide, le rafraîchissement ne l'écrase pas et la chaîne d'autorisation refuse les appels passant par cette connexion. */
  offlinedAt?: string
  offlinedBy?: string
  /** État d'origine avant mise hors ligne (référence de retour arrière à la restauration ; active par défaut). */
  offlinedStatusFrom?: 'pending' | 'active' | 'error'
}

export interface ProviderPolicy {
  allowedActions: '*' | string[]
  riskCap: RiskLevel
  connections?: string[]
  constraints?: { readOnly?: boolean; denyParams?: string[] }
}

export interface ConnectorPermGroupRecord extends RecordBase {
  name: string
  description: string
  orgId: string
  policies: Record<string, ProviderPolicy>
  subjects: Array<{ type: 'user_group' | 'agent' | 'app'; id: string; name?: string }>
  rateLimitPerMin: number
  /** OPT-P2-01 : déclaration du domaine de conception opérationnelle (liste blanche provider/actions exclues/fraîcheur du catalogue/fenêtre temporelle), non déclarée = tout le domaine. */
  odd?: OddDeclaration
  /** Abrogé (retrait de M0-2 billing, 2026-09-09) : champ legacy des lignes préexistantes, conservé pour compatibilité, plus lu à l'exécution. */
  precheckCents?: number
}

export interface TokenLedgerRecord extends RecordBase {
  permGroupId: string
  ocTokenId: string
  policySnapshotHash: string
  createdAt: string
  lastSyncedAt: string
}

export interface InvokeCaller {
  type: 'user' | 'agent' | 'app'
  id: string
  name: string
  actChain?: Array<{ name: string; type: string }>
  /** additive (D10) : ID de principal vérifié côté entrée (voire outils via exec.principal) ; à défaut, résolu par recherche sur l'id. */
  principalId?: string
}

export type ConnectorInvokeStatus =
  | 'ok' | 'denied' | 'rate_limited' | 'quota_exceeded' | 'approval_required' | 'error' | 'dry_run'

export type InvokeOutcome =
  | { ok: true; status: 'ok'; runId: string; latencyMs: number; data: unknown; meta: Record<string, unknown>; metered: boolean }
  | { ok: true; status: 'dry_run'; preview: Record<string, unknown> }
  | { ok: false; status: 'denied' | 'rate_limited' | 'quota_exceeded' | 'error'; error: string; latencyMs: number; code?: string }
  | { ok: false; status: 'approval_required'; approvalId: string; actionId: string; message: string }

export interface ApprovalLike {
  id: string
  kind: string
  status: string
  payload: Record<string, unknown>
}

const RESOURCE_PATTERN = /^[a-z]+:[A-Za-z0-9._-]+$/
const HEALTH_INTERVAL_MS = 30_000
const PATROL_INTERVAL_MS = 10 * 60_000
const RECONCILE_INTERVAL_MS = 5 * 60_000
/** Plafond circulaire de déduplication du curseur de réconciliation des contournements (avec la fenêtre rotative RUN_LIMIT 5000). */
const PROCESSED_RUN_CAP = 4000

function nowIso(): string {
  return new Date().toISOString()
}

/**
 * Sérialisation normalisée des paramètres (§11.5) : tri stable des noms de clés d'objet par ordre lexicographique, suppression des undefined,
 * garantissant que « mêmes paramètres avec ordre de clés/champs transitoires différents » produisent le même résumé — la clé d'idempotence stable et le gate argsHash partagent ce référentiel.
 */
function canonicalArgsJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null)
  if (Array.isArray(value)) return `[${value.map(canonicalArgsJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalArgsJson(item)}`).join(',')}}`
}

/**
 * InvokeCaller → référence d'appelant de travail vérifié (D10/annexe D.5) : ne porte que des champs vérifiés côté serveur ;
 * la détermination « géré » est faite par le port workforce via refType/refId (ressources agent/app) ou recherche sur userId, indépendamment des paramètres de requête.
 */
function workCallerOf(caller: InvokeCaller): WorkCallerRef {
  if (caller.type === 'user') {
    const principalId = caller.principalId ?? caller.id
    return { kind: 'human', principalId, userId: caller.id, name: caller.name }
  }
  return {
    kind: 'machine',
    principalId: caller.principalId ?? caller.id,
    refType: caller.type === 'agent' ? 'agent' : 'app',
    refId: caller.id,
    name: caller.name,
  }
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

/**
 * Jeton de capacité d'exécution d'approbation (OPT-P1-02) : unique identifiant légitime de relance haut risque admin, remplaçant l'ancien booléen ordinaire « seul l'exécuteur d'approbation interne peut le positionner »
 * (protection par simple convention — tout plugin in-process disposant de ctx.connectorHub pouvait se positionner à vrai pour contourner l'approbation,
 * soit se faire passer pour l'exécuteur d'approbation ; point de montée en grade de la vérification d'audit #9).
 * Trois propriétés infalsifiables : jeton aléatoire de 128 bits (indevinable) + à usage unique (détruit à la consommation) + vérification de liaison (action+principal, TTL 30 s).
 * La frappe est confinée dans la fermeture de l'exécuteur au sein de la classe via un coffre module (approvalCapabilityVault, détenu par fermeture, non exporté), inatteignable des façades REST/outils au sens des types comme à l'exécution ;
 * Falsifié/expiré/mésapparié = traité comme sans jeton → passage par le chemin d'ouverture de fiche d'approbation (fail-closed).
 */
export interface ApprovalExecutionCapability {
  token: string
  actionId: string
  callerId: string
  expiresAt: number
}

/**
 * Coffre des jetons de capacité (OPT-P1-02) : registre détenu par une fermeture module — non exporté, non rattaché à la classe, inatteignable des autres modules du processus
 * (plus robuste qu'un champ #privé : le proxy traçable de cordis ferait échouer la vérification de marque sur this, alors que la frontière de module est insensible au proxy).
 * La frappe n'a lieu que dans la fermeture de l'exécuteur bindAdminActionExecutor de la classe ; consommation à usage unique détruite + vérification de liaison (TTL 30 s).
 */
const approvalCapabilityVault = (() => {
  const tokens = new Map<string, { actionId: string; callerId: string; expiresAt: number }>()
  return {
    mint(actionId: string, caller: InvokeCaller): ApprovalExecutionCapability {
      const token = crypto.randomUUID()
      const expiresAt = Date.now() + 30_000
      tokens.set(token, { actionId, callerId: caller.id, expiresAt })
      return { token, actionId, callerId: caller.id, expiresAt }
    },
    consume(capability: ApprovalExecutionCapability | undefined, actionId: string, caller: InvokeCaller): boolean {
      if (!capability || typeof capability.token !== 'string' || capability.token === '') return false
      const record = tokens.get(capability.token)
      if (!record) return false
      tokens.delete(capability.token)
      return record.actionId === actionId && record.callerId === caller.id && record.expiresAt > Date.now()
    },
  }
})()

export class ConnectorHubService extends Service {
  static readonly provide = 'connectorHub'

  private rateBuckets = new Map<string, number[]>()
  /** Cache mémoire des valeurs de jetons oct_ : permGroupId → valeur du jeton. Jamais persisté (ligne rouge 1, décision de conception journal ①). */
  private tokenValueCache = new Map<string, string>()
  private healthTimer: ReturnType<typeof setInterval> | undefined
  private patrolTimer: ReturnType<typeof setInterval> | undefined
  private reconcileTimer: ReturnType<typeof setInterval> | undefined
  /** État de throttling des événements unhealthy : gatewayId → { seuil déjà émis, raison déjà émise } (test DEF-02 : éviter de noyer l'audit). */
  private unhealthyEmitState = new Map<string, { threshold: number; reason?: string }>()
  /** Ensemble de groupes en fail-closed pour échec de miroir (OPT-P1-05) : retiré dès que le miroir réussit ; pendant ce temps tout invoke de ces groupes est refusé. */
  private mirrorFailureGroups = new Set<string>()

  constructor(ctx: Context) {
    super(ctx, 'connectorHub')
    ctx.effect(() => () => {
      for (const timer of [this.healthTimer, this.patrolTimer, this.reconcileTimer]) {
        if (timer) clearInterval(timer)
      }
    })
    // OPT-P3-02 : tous les minuteurs de construction en unref — la sémantique de maintien ne retient plus implicitement la boucle d'événements (dispose nettoie toujours explicitement)
    this.healthTimer = setInterval(() => void this.probeGateway(), HEALTH_INTERVAL_MS)
    this.healthTimer.unref?.()
    this.patrolTimer = setInterval(() => void this.runPatrols(), PATROL_INTERVAL_MS)
    this.patrolTimer.unref?.()
    this.reconcileTimer = setInterval(() => void this.reconcileRuns().catch(() => undefined), RECONCILE_INTERVAL_MS)
    this.reconcileTimer.unref?.()
  }

  // -- Identité et resserrement organisationnel de la couche outils (REST et chemin outils partagent la même norme, revue d'architecture P0-1/P0-2) ---------

  /**
   * Périmètre de visibilité organisationnelle : permission `*` → undefined (tout) ; human → organisation de rattachement ; machine → organisation de rattachement de la ressource
   * agent/app liée ; machine externe sans rattachement → null (fail-closed, aucune donnée d'aucune organisation visible).
   * Contexte d'identité absent → erreur immédiate, pas de dégradation.
   */
  orgScopeFor(principal?: ToolPrincipal): string | null | undefined {
    if (!principal) throw new Error(t('工具执行缺少身份上下文（fail-closed）'))
    if (principal.permissions.includes('*')) return undefined
    if (principal.kind === 'human' && principal.userId) {
      const user = this.ctx.iam.users().get(principal.userId)
      if (!user) throw new Error(t('账号不存在：{id}', { id: principal.userId }))
      return user.orgId
    }
    return this.boundResourceOrg(principal.principalId) ?? null
  }

  /** Résout l'InvokeCaller depuis l'identité du contexte d'exécution (même règle que REST /api/connector/execute), en transmettant actChain. */
  callerFromPrincipal(principal?: ToolPrincipal): InvokeCaller {
    if (!principal) throw new Error(t('工具执行缺少身份上下文（fail-closed）'))
    const act = principal.actChain?.length ? { actChain: principal.actChain } : {}
    const verified = { principalId: principal.principalId, ...act }
    if (principal.kind === 'human') return { type: 'user', id: principal.userId ?? principal.principalId, name: principal.name, ...verified }
    const record = this.ctx.authn.principals().get(principal.principalId)
    if (record?.refType === 'agent' && record.refId) return { type: 'agent', id: record.refId, name: principal.name, ...verified }
    if (record?.refType === 'app' && record.refId) return { type: 'app', id: record.refId, name: principal.name, ...verified }
    return { type: 'app', id: principal.principalId, name: principal.name, ...verified }
  }

  private boundResourceOrg(principalId: string): string | undefined {
    const record = this.ctx.authn.principals().get(principalId)
    if (!record?.refId || (record.refType !== 'agent' && record.refType !== 'app')) return undefined
    const resource = this.ctx.resourceCore.get(record.refType, record.refId) as { orgId?: string } | undefined
    return resource && typeof resource.orgId === 'string' ? resource.orgId : undefined
  }

  // -- Collections -----------------------------------------------------------------

  gateways(): Collection<GatewayRecord> {
    const collection = this.ctx.opsStorage.collection<GatewayRecord>('connector:gateway')
    collection.uniqueOn('gateway_singleton', () => 'singleton')
    return collection
  }

  connections(): Collection<ConnectionReferenceRecord> {
    const collection = this.ctx.opsStorage.collection<ConnectionReferenceRecord>('connector:connections')
    collection.uniqueOn('alias_unique', (item) => item.alias)
    return collection
  }

  catalogs(): Collection<CatalogRecord> {
    const collection = this.ctx.opsStorage.collection<CatalogRecord>('connector:catalog')
    collection.uniqueOn('catalog_singleton', () => 'singleton')
    return collection
  }

  permGroups(): Collection<ConnectorPermGroupRecord> {
    return this.ctx.opsStorage.collection<ConnectorPermGroupRecord>('connector:permGroups')
  }

  tokens(): Collection<TokenLedgerRecord> {
    const collection = this.ctx.opsStorage.collection<TokenLedgerRecord>('connector:tokens')
    collection.uniqueOn('ledger_group_unique', (item) => item.permGroupId)
    return collection
  }

  runsState(): Collection<RecordBase & { key: string; cursor?: string; processedIds?: string[]; lastRunAt?: string }> {
    const collection = this.ctx.opsStorage.collection<RecordBase & { key: string; cursor?: string; processedIds?: string[]; lastRunAt?: string }>('connector:runs')
    collection.uniqueOn('runs_state_unique', (item) => item.key)
    return collection
  }

  // -- Configuration de la passerelle et fail-closed (#2) ------------------------------------------

  /** Résolution d'adminToken : référence indirecte `env:VAR` ; envProbe sert de sonde de simulation en lecture seule (toujours undefined sur le chemin de production). */
  resolveAdminToken(record: GatewayRecord | undefined, envProbe?: Record<string, boolean | undefined>): string | undefined {
    const value = record?.adminToken ?? ''
    if (!value) return undefined
    if (!value.startsWith('env:')) return value
    const name = value.slice(4)
    if (envProbe && name in envProbe) return envProbe[name] ? process.env[name] : undefined
    return process.env[name]
  }

  gatewayStatus(envProbe?: Record<string, boolean | undefined>): { available: boolean; reason?: string; baseUrl?: string; envChecks?: Record<string, boolean>; status?: GatewayRecord['status']; latencyMs?: number; lastProbeAt?: string } {
    // envProbe : « sonde de simulation » en lecture seule — la console/l'auto-test évalue, sans modifier le véritable environnement du processus,
    // la sémantique fail-closed des branches du verrou env obligatoire (correctif P0 ①) ; le chemin de production passe toujours undefined.
    const envOf = (name: string): boolean =>
      envProbe && name in envProbe ? Boolean(envProbe[name]) : Boolean(process.env[name])
    const record = this.gateways().all()[0]
    const envChecks = {
      OOMOL_CONNECT_ENCRYPTION_KEY: envOf('OOMOL_CONNECT_ENCRYPTION_KEY'),
      OOMOL_CONNECT_ADMIN_TOKEN: envOf('OOMOL_CONNECT_ADMIN_TOKEN'),
    }
    if (!record || !record.baseUrl.trim()) {
      return { available: false, reason: t('connector:gateway 未配置（baseUrl/adminToken）'), envChecks, status: 'unconfigured' }
    }
    const hasLiteralToken = this.resolveAdminToken(record, envProbe) !== undefined
    if (!hasLiteralToken && (!envChecks.OOMOL_CONNECT_ADMIN_TOKEN)) {
      return { available: false, reason: t('管理口令未解析（adminToken 需为 env: 引用且 OOMOL_CONNECT_ADMIN_TOKEN 已设置）'), envChecks, ...(record ? { status: record.status, lastProbeAt: record.health.lastProbeAt } : {}) }
    }
    if (!envChecks.OOMOL_CONNECT_ENCRYPTION_KEY) {
      return { available: false, reason: t('OOMOL_CONNECT_ENCRYPTION_KEY 未设置：sidecar 将凭证明文落盘，平台 fail-closed 拒绝一切 invoke'), envChecks, ...(record ? { status: record.status, lastProbeAt: record.health.lastProbeAt } : {}) }
    }
    if (record.status === 'unconfigured') {
      return { available: false, reason: t('网关尚未探活'), envChecks, status: record.status }
    }
    if (record.status !== 'healthy') {
      return { available: false, reason: record.unavailableReason ?? t('网关探活失败（fail-closed）'), envChecks, status: record.status, lastProbeAt: record.health.lastProbeAt }
    }
    return {
      available: true,
      baseUrl: record.baseUrl,
      envChecks,
      status: record.status,
      ...(record.health.latencyMs !== undefined ? { latencyMs: record.health.latencyMs } : {}),
      ...(record.health.lastProbeAt !== undefined ? { lastProbeAt: record.health.lastProbeAt } : {}),
    }
  }

  /** Affirme la disponibilité et renvoie le client (barrière préalable à toute action du plan de données, refus immédiat par erreur si non satisfaite). */
  requireClient(): { client: OcClient; record: GatewayRecord } {
    const status = this.gatewayStatus()
    if (!status.available || !status.baseUrl) {
      this.noteFailureSignal(status.reason ?? t('网关不可用'))
      throw new OcError('gateway_unavailable', status.reason ?? t('连接器网关不可用（fail-closed）'), undefined, 503)
    }
    const record = this.gateways().all()[0]!
    const client = new OcClient(status.baseUrl, this.resolveAdminToken(record)!, OC_DEFAULT_TIMEOUT)
    return { client, record }
  }

  async configureGateway(input: { baseUrl: string; adminToken?: string; autoCatalogSyncMinutes?: number }, actor: string): Promise<GatewayRecord> {
    const baseUrl = input.baseUrl.replace(/\/$/, '')
    if (!baseUrl) throw new Error(t('baseUrl 必填'))
    const existing = this.gateways().all()[0]
    const next: Partial<GatewayRecord> = {
      baseUrl,
      ...(input.adminToken !== undefined ? { adminToken: input.adminToken } : {}),
      ...(input.autoCatalogSyncMinutes !== undefined ? { autoCatalogSyncMinutes: input.autoCatalogSyncMinutes } : {}),
      versionPin: OC_VERSION_PIN,
    }
    let record: GatewayRecord
    if (existing) {
      record = this.gateways().update(existing.id, next)
    } else {
      record = this.gateways().insert({
        id: newId('cgw'), baseUrl,
        adminToken: input.adminToken ?? 'env:OOMOL_CONNECT_ADMIN_TOKEN',
        status: 'unconfigured',
        health: { consecutiveFails: 0 },
        versionPin: OC_VERSION_PIN,
        autoCatalogSyncMinutes: input.autoCatalogSyncMinutes ?? 0,
        createdAt: nowIso(), updatedAt: nowIso(),
      })
    }
    void actor
    this.ctx.platformBus.emit(PlatformEvents.ConnectorGatewayChanged, { baseUrl: record.baseUrl, versionPin: record.versionPin })
    await this.probeGateway()
    return this.gateways().get(record.id)!
  }

  /** Sondage de santé : échecs consécutifs → globalement unavailable (invoke refusé) ; retour à la santé = refermeture automatique à moitié. */
  async probeGateway(): Promise<{ ok: boolean; latencyMs: number; reason?: string }> {
    const record = this.gateways().all()[0]
    if (!record) return { ok: false, latencyMs: 0, reason: t('未配置') }
    if (record.maintOffline) {
      // État de mise hors ligne de maintenance : sondage directement sauté (le minuteur ne ressuscite pas), simple rafraîchissement de l'horodatage
      this.gateways().update(record.id, { health: { ...record.health, lastProbeAt: nowIso() } })
      return { ok: false, latencyMs: 0, reason: record.unavailableReason ?? t('审批下线（维护态，探活跳过）') }
    }
    // Verrou env obligatoire avant la sonde réseau (correctif P0 ①) : clé de chiffrement manquante ou mot de passe d'administration non résolvable → unavailable +
    // compteur d'alerte — ce sont deux problèmes bloquants du déploiement ; en revanche « pas encore sondé » est un état transitoire normal, la vraie sonde doit continuer.
    const encryptionMissing = process.env.OOMOL_CONNECT_ENCRYPTION_KEY === undefined
    const adminUnresolvable = this.resolveAdminToken(record) === undefined
    if (encryptionMissing || adminUnresolvable) {
      const fails = record.health.consecutiveFails + 1
      const rawReason = this.gatewayStatus().reason
      const reason = rawReason && /(OOMOL|管理口令)/.test(rawReason) ? rawReason : t('强制配置缺失：无法安全访问连接器网关（fail-closed）')
      this.gateways().update(record.id, {
        status: 'unavailable', unavailableReason: reason,
        health: { lastProbeAt: nowIso(), consecutiveFails: fails },
      })
      this.emitUnhealthyThrottled(record, fails, reason)
      return { ok: false, latencyMs: 0, reason }
    }
    const started = Date.now()
    try {
      const client = new OcClient(record.baseUrl, this.resolveAdminToken(record) ?? 'probe-probe', 5_000)
      await client.health()
      const latencyMs = Date.now() - started
      const previous = record.status
      this.gateways().update(record.id, {
        status: 'healthy', unavailableReason: undefined,
        health: { lastProbeAt: nowIso(), latencyMs, consecutiveFails: 0 },
      })
      this.unhealthyEmitState.delete(record.id)
      if (previous !== 'healthy') {
        this.ctx.platformBus.emit(PlatformEvents.ConnectorGatewayChanged, { baseUrl: record.baseUrl, status: 'healthy', recoveredFrom: previous })
      }
      return { ok: true, latencyMs }
    } catch (error) {
      const fails = record.health.consecutiveFails + 1
      const reason = error instanceof Error ? error.message : String(error)
      const latencyMs = Date.now() - started
      this.gateways().update(record.id, {
        status: 'unavailable', unavailableReason: reason,
        health: { lastProbeAt: nowIso(), latencyMs, consecutiveFails: fails },
      })
      this.emitUnhealthyThrottled(record, fails, reason)
      return { ok: false, latencyMs, reason }
    }
  }

  /** Signal d'échec métier : pas d'alerte avant trois occurrences (même idée que le disjoncteur consécutif de mcp), mais rafraîchit immédiatement le référentiel de sondage. */
  private noteFailureSignal(reason: string): void {
    const record = this.gateways().all()[0]
    if (!record) return
    const fails = record.health.consecutiveFails + 1
    this.gateways().update(record.id, {
      status: 'unavailable', unavailableReason: reason,
      health: { ...record.health, lastProbeAt: nowIso(), consecutiveFails: fails },
    })
    this.emitUnhealthyThrottled(record, fails, reason)
  }

  private noteSuccessSignal(): void {
    const record = this.gateways().all()[0]
    if (!record) return
    this.unhealthyEmitState.delete(record.id)
    if (record.health.consecutiveFails === 0 && record.status === 'healthy') return
    this.gateways().update(record.id, { status: 'healthy', unavailableReason: undefined, health: { ...record.health, consecutiveFails: 0 } })
  }

  /**
   * Les événements de passerelle dégradée sont throttlés par seuils croissants (3→10→30→100…), avec émission immédiate d'un complément si la raison d'échec change ;
   * retour à la santé = remise à zéro. Test DEF-02 : sondage toutes les 30 s, l'implémentation d'origine émettait un événement à chaque tour dès fails≥3,
   * une longue panne (ex. env de déploiement manquant non corrigé) pouvait produire près de 3000 audits dupliqués par jour et noyer le flux d'événements de l'espace de travail.
   */
  private emitUnhealthyThrottled(record: GatewayRecord, fails: number, reason: string): void {
    const state = this.unhealthyEmitState.get(record.id)
    const thresholds = [3, 10, 30, 100, 300, 1000, 3000, 10000]
    const next = thresholds.find((t) => t > (state?.threshold ?? 0))
    const reasonChanged = state !== undefined && state.reason !== reason
    if (!reasonChanged && (next === undefined || fails < next)) return
    this.unhealthyEmitState.set(record.id, { threshold: next ?? state!.threshold, reason })
    this.ctx.platformBus.emit(PlatformEvents.ConnectorGatewayUnhealthy, {
      baseUrl: record.baseUrl, consecutiveFails: fails, reason, resourceType: 'connector_gateway', resourceId: record.id,
    })
  }

  /** Sémantique ① de l'exécuteur connector.offline : mise hors ligne de maintenance de la passerelle (fail-closed à effet immédiat, sondage sauté pour empêcher la résurrection automatique). */
  async offlineGateway(reason: string): Promise<GatewayRecord | undefined> {
    const record = this.gateways().all()[0]
    if (!record) return undefined
    const updated = this.gateways().update(record.id, {
      maintOffline: true,
      status: 'unavailable',
      unavailableReason: t('审批下线：{reason}', { reason }),
    })
    this.ctx.platformBus.emit(PlatformEvents.ConnectorGatewayChanged, { baseUrl: updated.baseUrl, action: 'gateway_offline', reason })
    this.ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'connector-offline', actorName: t('审批执行'),
      action: 'connector.gateway.offline', resourceType: 'connector_gateway', resourceId: updated.id,
      resourceName: updated.baseUrl, result: 'ok', detail: reason,
    })
    return updated
  }

  /** Retour en ligne : lève le marqueur de maintenance et sonde immédiatement pour de vrai. */
  async onlineGateway(): Promise<{ ok: boolean; latencyMs: number; reason?: string }> {
    const record = this.gateways().all()[0]
    if (record && record.maintOffline) {
      this.gateways().update(record.id, { maintOffline: false, unavailableReason: undefined })
    }
    return await this.probeGateway()
  }

  /** Sémantique ② de l'exécuteur connector.offline : mise hors ligne de la référence de connexion (la plateforme refuse les appels la traversant ; les identifiants du sidecar ne sont pas affectés). */
  async offlineConnection(id: string, options: { actorName: string; reason: string }): Promise<ConnectionReferenceRecord> {
    const ref = this.connections().get(id)
    if (!ref) throw new Error(t('连接引用不存在：{id}', { id }))
    if (ref.status === 'offlined') return ref
    const updated = this.connections().update(id, {
      offlinedStatusFrom: ref.status,
      status: 'offlined',
      offlinedAt: nowIso(),
      offlinedBy: options.actorName,
      errorReason: t('审批下线：{reason}', { reason: options.reason }),
    } as Partial<ConnectionReferenceRecord>)
    this.ctx.platformBus.emit(PlatformEvents.ConnectorDisconnected, {
      connectionId: id, alias: ref.alias, provider: ref.provider, orgId: ref.ownerOrgId,
      actor: options.actorName, action: 'offline', reason: options.reason,
    })
    return updated
  }

  /** Restauration de la connexion : lève le marqueur de hors ligne et revérifie l'état sidecar (reste pending si la passerelle est injoignable, convergence au prochain passage). */
  async onlineConnection(id: string): Promise<ConnectionReferenceRecord> {
    const ref = this.connections().get(id)
    if (!ref) throw new Error(t('连接引用不存在：{id}', { id }))
    this.connections().update(id, {
      offlinedStatusFrom: undefined, offlinedAt: undefined, offlinedBy: undefined,
      errorReason: undefined, status: ref.offlinedStatusFrom === 'pending' ? 'pending' : 'active',
    } as Partial<ConnectionReferenceRecord>)
    try {
      return await this.confirmConnectionStatus({ connectionId: id }) ?? this.connections().get(id)!
    } catch {
      return this.connections().get(id)!
    }
  }

  // -- Synchronisation du catalogue (#3) ---------------------------------------------------------

  async catalog(): Promise<CatalogRecord | undefined> {
    return this.catalogs().all()[0]
  }

  /** Horodatage de la dernière synchronisation du catalogue (pour le jugement de fraîcheur ODD d'OPT-P2-01 ; lecture de la collection de synchronisation). */
  private catalogSnapshotSyncedAt(): string | undefined {
    return this.catalogs().all()[0]?.syncedAt
  }

  requireAction(actionId: string): CatalogActionRecord {
    const entry = this.catalogs().all()[0]?.actions.find((item) => item.id === actionId)
    if (!entry) {
      throw new OcError('unknown_action', t('action 不在纳管目录中：{action}（先执行目录同步）', { action: actionId }), undefined, 404)
    }
    return entry
  }

  async syncCatalog(actor: string): Promise<{ providers: number; actions: number; added: string[]; removed: string[]; skippedServices: Array<{ service: string; reason: string }> }> {
    const { client } = this.requireClient()
    const [providers, actions] = await Promise.all([client.listProviders(), client.listActions()])
    const skipped: Array<{ service: string; reason: string }> = []
    const validServices = new Set<string>()
    const normalized: Array<Record<string, unknown>> = []
    for (const provider of providers) {
      const service = String((provider.service ?? provider.name ?? '') ).trim()
      if (!service) continue
      // Contrainte regex de la ressource usage (correctif P2 ⑮) : le segment provider doit satisfaire /^[a-z]+:[A-Za-z0-9._-]+$/
      if (!RESOURCE_PATTERN.test(`connector:${service}`)) {
        skipped.push({ service, reason: t('service 标识不满足计量资源正则 {pattern}', { pattern: RESOURCE_PATTERN.source }) })
        continue
      }
      validServices.add(service)
      normalized.push(provider)
    }
    const mapped: CatalogActionRecord[] = []
    for (const action of actions) {
      const service = String(action.service ?? '').trim()
      if (!service || !validServices.has(service)) continue
      const scopes = (Array.isArray(action.requiredScopes) ? action.requiredScopes : []).map(String)
      const perms = (Array.isArray(action.providerPermissions) ? action.providerPermissions : []).map(String)
      // R6 : le niveau de risque passe par le catalogue déclaratif (resolveRiskLevel : explicite > actions déclarées > defaultRisk déclaré > heuristique),
      // en présence d'une déclaration provider le riskTier accompagne l'enregistrement (S1/S2, affichage seul, couplage approbation à venir).
      const riskTier = riskTierOf(service)
      mapped.push({
        id: action.id,
        service,
        ...(action.name !== undefined ? { name: String(action.name) } : {}),
        ...(action.description !== undefined ? { description: String(action.description) } : {}),
        riskLevel: resolveRiskLevel(action, service),
        ...(riskTier ? { riskTier } : {}),
        requiredScopes: scopes,
        providerPermissions: perms,
        inputSchema: action.inputSchema && typeof action.inputSchema === 'object' ? action.inputSchema : { type: 'object', properties: {} },
      })
    }
    const previous = this.catalogs().all()[0]
    const previousIds = new Set(previous?.actions.map((item) => item.id) ?? [])
    const added = mapped.filter((item) => !previousIds.has(item.id)).map((item) => item.id)
    const newIds = new Set(mapped.map((item) => item.id))
    const removed = (previous?.actions ?? []).filter((item) => !newIds.has(item.id)).map((item) => item.id)
    // Couplage aux changements de catalogue (T-04) : les groupes de permissions touchés par le retrait d'une action d'une liste explicite sont d'abord élagués en base,
    // puis uniformément reflétés — l'empreinte de l'instantané change donc, et le PUT intégral des quatre tableaux survient naturellement.
    let prunedGroups = 0
    if (removed.length > 0) {
      for (const group of this.permGroups().all()) {
        let touched = false
        const nextPolicies = Object.fromEntries(Object.entries(group.policies).map(([service, policy]) => {
          if (policy.allowedActions === '*') return [service, policy]
          const kept = policy.allowedActions.filter((entry) => !removed.includes(entry))
          if (kept.length === policy.allowedActions.length) return [service, policy]
          touched = true
          return [service, { ...policy, allowedActions: kept }]
        }))
        if (touched) {
          this.permGroups().update(group.id, { policies: nextPolicies as typeof group.policies })
          prunedGroups++
        }
      }
    }
    const createdRecord = previous
      ? this.catalogs().update(previous.id, { providers: normalized, actions: mapped, skippedServices: skipped, syncedAt: nowIso() })
      : this.catalogs().insert({ id: newId('cat'), providers: normalized, actions: mapped, skippedServices: skipped, syncedAt: nowIso(), createdAt: nowIso(), updatedAt: nowIso() })
    void createdRecord
    if (added.length > 0 || removed.length > 0) {
      this.ctx.platformBus.emit(PlatformEvents.ConnectorGatewaySynced, {
        kind: 'catalog', providers: normalized.length, actions: mapped.length, added, removed, actor, prunedGroups,
      })
      for (const group of this.permGroups().all()) {
        await this.mirrorTokenPolicySafe(group)
      }
    }
    return { providers: normalized.length, actions: mapped.length, added, removed, skippedServices: skipped }
  }

  // -- Gestion des connexions (#4) ---------------------------------------------------------

  assertAliasPrefix(alias: string, orgId: string): string {
    const prefix = `org:${orgId}:`
    if (!alias.startsWith(prefix) || alias.length <= prefix.length) {
      throw new OcError('invalid_alias_prefix', t('连接别名必须以 {prefix} 开头（org 隔离三件套①）', { prefix }), undefined, 400)
    }
    return alias
  }

  buildAlias(orgId: string, suffix: string): string {
    const clean = suffix.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-|-$/g, '')
    if (!clean) throw new Error(t('连接别名后缀不能为空'))
    return this.assertAliasPrefix(`org:${orgId}:${clean}`, orgId)
  }

  maskValue(value: unknown): string {
    const text = String(value ?? '')
    if (text.length > 8) return `${text.slice(0, 6)}…`
    return '****'
  }

  private summarize(sidecarSummary: OcConnectionSummary | undefined, ref: Partial<ConnectionReferenceRecord>): Partial<ConnectionReferenceRecord> {
    const masked: Record<string, string> = {}
    const profile = sidecarSummary?.profile
    if (profile && typeof profile === 'object') {
      for (const [key, value] of Object.entries(profile)) {
        masked[key] = typeof value === 'string' && /(secret|token|key|password)/i.test(key) ? this.maskValue(value) : String(value)
      }
    }
    return {
      ...(sidecarSummary?.id ? { ocConnectionId: sidecarSummary.id } : {}),
      ...(sidecarSummary?.authType ? { authType: normalizeAuthType(sidecarSummary.authType) } : {}),
      status: sidecarSummary?.configured ? 'active' : (ref.status ?? 'pending'),
      ...(Object.keys(masked).length > 0 ? { maskedProfile: masked } : {}),
      lastSyncedAt: nowIso(),
    }
  }

  /**
   * Entrée unifiée de création de connexion : no_auth enregistre directement ; api_key/custom_credential transite du formulaire vers le sidecar sans persistance ;
   * OAuth passe d'abord par l'approbation. requireApproval=true ou exigence d'approbation du provider → processus en deux phases (décision de conception journal ②).
   */
  async createConnection(input: {
    orgId: string
    actor: { id: string; name: string }
    provider: string
    aliasSuffix: string
    authType: 'oauth' | 'api_key' | 'custom_credential' | 'no_auth'
    values?: Record<string, unknown>
    requestedScopes?: string[]
    requireApproval?: boolean
    approvalId?: string
  }): Promise<{ reference?: ConnectionReferenceRecord; approvalRequired?: boolean; approvalId?: string; authorizationUrl?: string; state?: string; guidance?: string }> {
    const alias = this.buildAlias(input.orgId, input.aliasSuffix)
    const approvalDecided = input.approvalId ? this.verifyConnectApproval(input.approvalId, input.provider, input.orgId, input.actor.id) : false
    if (input.authType === 'no_auth') {
      // no_auth sans identifiant, sans toucher le sidecar : enregistrement virtuel purement local (possible même avec graines de démo/passerelle non configurée)
      const existingNoAuth = this.connections().findOne((item) => item.alias === alias)
      const reference = existingNoAuth
        ? this.connections().update(existingNoAuth.id, { status: 'active', provider: input.provider, ownerOrgId: input.orgId, errorReason: undefined, updatedAt: nowIso() })
        : this.connections().insert({
            id: newId('ocn'), provider: input.provider, alias, authType: 'no_auth',
            status: 'active', ownerOrgId: input.orgId, createdBy: input.actor.name,
            bridge: false, createdAt: nowIso(), updatedAt: nowIso(),
          })
      this.ctx.platformBus.emit(PlatformEvents.ConnectorConnected, { connectionId: reference.id, alias, provider: input.provider, orgId: input.orgId, authType: 'no_auth' })
      return { reference }
    }
    const { client } = this.requireClient()
    if (!RESOURCE_PATTERN.test(`connector:${input.provider}`)) {
      throw new OcError('invalid_service', t('provider 标识不满足计量资源正则：{provider}', { provider: input.provider }), undefined, 400)
    }
    const needsApproval = input.requireApproval === true
    if (needsApproval && !approvalDecided) {
      const approval = this.ctx.audit.createApproval({
        kind: 'connector.connect',
        // WP-10/L1 (QA A-06) : L4 haut risque unifié — l'approbation exige double confirmation + marqueur de revue finale société
        riskLevel: 'high',
        title: t('新建 SaaS 连接：{provider}', { provider: input.provider }),
        payload: {
          // La charge d'approbation ne doit contenir aucun champ d'identifiant (ligne rouge 1) : seulement provider/org/alias et le demandeur
          provider: input.provider, orgId: input.orgId, alias, authType: input.authType,
          requesterId: input.actor.id, requesterName: input.actor.name, stage: 'pre_submit',
        },
        requesterId: input.actor.id,
        requesterName: input.actor.name,
      })
      return { approvalRequired: true, approvalId: approval.id }
    }
    if (input.approvalId && !approvalDecided) {
      throw new OcError('approval_required', t('该 provider 配置了连接审批：请先提交审批并通过后再携带 approvalId 创建连接'), undefined, 403)
    }
    const existingRef = this.connections().findOne((item) => item.alias === alias)
    if (input.authType === 'oauth') {
      let authorization: Awaited<ReturnType<OcClient['createOAuthAuthorization']>>
      try {
        authorization = await client.createOAuthAuthorization({
          service: input.provider,
          connectionName: alias,
          ...(input.requestedScopes?.length ? { requestedScopes: input.requestedScopes } : {}),
        })
      } catch (error) {
        if (error instanceof OcError && error.code === 'oauth_client_config_required') {
          // Correctif P1 ⑩ : le coût de l'App apportée par le client est transmis à l'assistant (l'entreprise doit d'abord enregistrer le client côté provider et l'écrire dans le sidecar)
          throw new OcError(
            'oauth_client_config_required',
            t('{provider} 的 OAuth 需要「自备 App」：请先在企业侧注册 OAuth App，并把 client 配置写入连接器网关（PUT /api/oauth/configs/:service），再重试', { provider: input.provider }),
            t('向导提示：在 {provider} 开发者后台创建 OAuth App；回调地址使用 OOMOL_CONNECT_ORIGIN 对应的 /oauth/callback；随后由管理员保存 client 配置。指南详见 docs/connector-integration.md', { provider: input.provider }),
          )
        }
        throw error
      }
      const reference = existingRef
        ? this.connections().update(existingRef.id, {
            status: 'pending', provider: input.provider,
            ownerOrgId: input.orgId, requestId: authorization.state,
            errorReason: undefined, updatedAt: nowIso(),
            createdBy: input.actor.name,
          })
        : this.connections().insert({
            id: newId('ocn'), provider: input.provider, alias,
            authType: 'oauth', status: 'pending', ownerOrgId: input.orgId,
            createdBy: input.actor.name, bridge: false,
            requestId: authorization.state, createdAt: nowIso(), updatedAt: nowIso(),
          })
      return { reference, authorizationUrl: authorization.authorizationUrl, state: authorization.state }
    }
    // api_key / custom_credential : transit du formulaire direct vers le sidecar (corps de requête envoyé immédiatement, écrit dans aucune collection, aucun log)
    const summary = await client.upsertConnection(input.provider, {
      authType: input.authType === 'custom_credential' ? 'custom_credential' : 'api_key',
      connectionName: alias,
      values: input.values ?? {},
    })
    const base = existingRef ?? {}
    const merged: Partial<ConnectionReferenceRecord> = {
      provider: input.provider, alias, ownerOrgId: input.orgId,
      authType: normalizeAuthType(summary.authType ?? input.authType),
      createdBy: input.actor.name, bridge: false, errorReason: undefined,
      ...this.summarize(summary, base),
      updatedAt: nowIso(),
    }
    const reference = existingRef
      ? this.connections().update(existingRef.id, merged)
      : this.connections().insert({
          id: newId('ocn'), createdAt: nowIso(), ...merged,
        } as ConnectionReferenceRecord)
    this.ctx.platformBus.emit(PlatformEvents.ConnectorConnected, {
      connectionId: reference.id, alias, provider: input.provider, orgId: input.orgId, authType: reference.authType,
    })
    return { reference }
  }

  /** Deuxième phase de l'approbation en deux temps : vérifie que la fiche est approuvée et que principal/provider/org concordent avant d'autoriser la soumission réelle des identifiants. */
  verifyConnectApproval(approvalId: string, provider: string, orgId: string, requesterId: string): boolean {
    const approval = this.ctx.audit.approvals().get(approvalId) as ApprovalLike | undefined
    if (!approval) throw new OcError('approval_invalid', t('审批单不存在：{id}', { id: approvalId }), undefined, 400)
    if (approval.kind !== 'connector.connect') throw new OcError('approval_invalid', t('审批单类型不符：{kind}', { kind: approval.kind }), undefined, 400)
    const payload = approval.payload as Record<string, unknown>
    if (String(payload.requesterId ?? '') !== String(requesterId)) {
      throw new OcError('approval_actor_mismatch', t('审批单发起人与当前操作人不一致，拒绝以此单放行'), undefined, 403)
    }
    if (String(payload.provider ?? '') !== provider || String(payload.orgId ?? '') !== orgId) {
      throw new OcError('approval_target_mismatch', t('审批单的 provider/org 与本次创建不一致'), undefined, 403)
    }
    if (!['approved', 'executed'].includes(approval.status)) {
      throw new OcError('approval_pending', t('审批单未通过（{status}）', { status: approval.status }), undefined, 403)
    }
    return true
  }

  /** Confirmation d'état après rappel OAuth : comparaison avec la liste de connexions sidecar pour remplir la référence (réutilisée par le polling du front et l'inspection). */
  async confirmConnectionStatus(filter: { requestId?: string; connectionId?: string }): Promise<ConnectionReferenceRecord | undefined> {
    const { client } = this.requireClient()
    const ref = filter.connectionId
      ? this.connections().get(filter.connectionId)
      : this.connections().findOne((item) => item.requestId === filter.requestId)
    if (!ref) return undefined
    if (ref.offlinedAt) return ref // état hors ligne pour maintenance : le sondage d'état ne ressuscite pas la connexion
    const summaries = await client.listConnections()
    const match = summaries.find((item) => item.connectionName === ref.alias && item.service === ref.provider)
    if (!match) {
      return this.connections().update(ref.id, { status: ref.status === 'active' ? 'active' : 'pending', lastSyncedAt: nowIso() })
    }
    const updated = this.connections().update(ref.id, {
      ...this.summarize(match, ref),
      updatedAt: nowIso(),
    } as Partial<ConnectionReferenceRecord>)
    if (updated.status === 'active' && ref.status !== 'active') {
      this.ctx.platformBus.emit(PlatformEvents.ConnectorConnected, {
        connectionId: updated.id, alias: updated.alias, provider: updated.provider, orgId: updated.ownerOrgId, authType: updated.authType,
      })
    }
    return updated
  }

  /** Suppression de connexion : vérification en cascade des références par groupes de permissions ; avec force, délie les références et reflète les jetons affectés (PUT intégral des quatre tableaux). */
  async deleteConnection(id: string, options: { actor: string; force?: boolean }): Promise<{ deleted: boolean; releasedGroups: string[] }> {
    const { client } = this.requireClient()
    const ref = this.connections().get(id)
    if (!ref) throw new Error(t('连接引用不存在：{id}', { id }))
    const referencingGroups = this.permGroups().find((group) =>
      group.orgId === ref.ownerOrgId && Object.values(group.policies).some((policy) => (policy.connections ?? []).includes(ref.alias)))
    if (referencingGroups.length > 0 && !options.force) {
      throw new OcError('connection_in_use', t('连接仍被 {groups} 权限组引用，请先解绑或携带 force 解除', { groups: referencingGroups.map((group) => group.name).join('、') }), undefined, 409)
    }
    if (ref.authType !== 'no_auth') {
      try {
        await client.deleteConnection(ref.provider, ref.alias)
      } catch (error) {
        if (!(error instanceof OcError && error.code === 'unknown_connection')) throw error
      }
    }
    this.connections().remove(id)
    for (const group of referencingGroups) {
      const nextPolicies = Object.fromEntries(Object.entries(group.policies).map(([service, policy]) => [
        service,
        { ...policy, connections: (policy.connections ?? []).filter((alias) => alias !== ref.alias) },
      ]))
      const updatedGroup = this.permGroups().update(group.id, { policies: nextPolicies })
      await this.mirrorTokenPolicySafe(updatedGroup)
    }
    if (referencingGroups.length === 0) {
      const affected = this.tokens().find((item) => item.permGroupId && this.permGroups().get(item.permGroupId)?.orgId === ref.ownerOrgId)
      for (const ledger of affected) {
        const group = this.permGroups().get(ledger.permGroupId)
        if (group) await this.mirrorTokenPolicySafe(group)
      }
    }
    this.ctx.platformBus.emit(PlatformEvents.ConnectorDisconnected, { connectionId: id, alias: ref.alias, provider: ref.provider, orgId: ref.ownerOrgId, actor: options.actor })
    return { deleted: true, releasedGroups: referencingGroups.map((group) => group.id) }
  }

  /** Synchronisation complète de l'état des références de connexion (entrée de polling de la page liste de la console). */
  async refreshConnections(orgId?: string): Promise<{ refreshed: number; sidecarTotal: number }> {
    const { client } = this.requireClient()
    const summaries = await client.listConnections()
    const scope = orgId ? this.connections().find((item) => item.ownerOrgId === orgId) : this.connections().all()
    for (const ref of scope) {
      if (ref.offlinedAt) continue // état hors ligne pour maintenance : le rafraîchissement ne remplace pas (le référentiel audit conserve le motif de mise hors ligne)
      const match = summaries.find((item) => item.connectionName === ref.alias)
      if (!match) continue
      this.connections().update(ref.id, { ...this.summarize(match, ref), updatedAt: nowIso() } as Partial<ConnectionReferenceRecord>)
    }
    return { refreshed: scope.length, sidecarTotal: summaries.length }
  }

  // -- Groupes de permissions (#2.4 première couche) ---------------------------------------------------

  createPermGroup(input: {
    name: string
    description?: string
    orgId: string
    policies: Record<string, ProviderPolicy>
    subjects: ConnectorPermGroupRecord['subjects']
    rateLimitPerMin?: number
    odd?: OddDeclaration
  }): ConnectorPermGroupRecord {
    if (!input.name?.trim()) throw new Error(t('权限组名称不能为空'))
    if (this.permGroups().findOne((group) => group.name === input.name)) throw new Error(t('权限组已存在：{name}', { name: input.name }))
    if (!this.ctx.iam.orgs().get(input.orgId)) throw new Error(t('组织不存在：{id}', { id: input.orgId }))
    this.validatePolicies(input.orgId, input.policies)
    const group = this.permGroups().insert({
      id: newId('cpg'), name: input.name,
      description: input.description ?? '', orgId: input.orgId,
      policies: this.normalizePolicies(input.policies),
      subjects: input.subjects,
      rateLimitPerMin: Math.max(1, input.rateLimitPerMin ?? 60),
      ...(input.odd !== undefined ? { odd: normalizeOdd(input.odd) } : {}),
      createdAt: nowIso(), updatedAt: nowIso(),
    })
    this.afterPermGroupChange(group)
    return group
  }

  updatePermGroup(id: string, patch: Partial<Pick<ConnectorPermGroupRecord, 'name' | 'description' | 'policies' | 'subjects' | 'rateLimitPerMin' | 'odd'>>): ConnectorPermGroupRecord {
    const group = this.requirePermGroup(id)
    if (patch.policies) this.validatePolicies(group.orgId, patch.policies)
    const normalizedPatch: Partial<ConnectorPermGroupRecord> = {
      ...patch,
      ...(patch.policies ? { policies: this.normalizePolicies(patch.policies) } : {}),
      ...(patch.odd !== undefined ? { odd: normalizeOdd(patch.odd) } : {}),
    }
    const updated = this.permGroups().update(id, normalizedPatch)
    this.afterPermGroupChange(updated)
    return updated
  }

  deletePermGroup(id: string): boolean {
    this.requirePermGroup(id)
    const removed = this.permGroups().remove(id)
    if (removed) this.deleteTokenForGroup(id).catch(() => undefined)
    this.ctx.platformBus.emit(PlatformEvents.ConnectorPermGroupChanged, { groupId: id, change: 'deleted' })
    return removed
  }

  /** Aperçu de l'impact d'un changement (revue 2.2-3 : N jetons / M connexions, aligné sur l'usage dry-run de la plateforme). */
  permGroupImpact(id: string): { tokens: number; connections: number; subjects: number } {
    const group = this.requirePermGroup(id)
    const referencedAliases = new Set(Object.values(group.policies).flatMap((policy) => policy.connections ?? []))
    return {
      tokens: this.tokens().find((item) => item.permGroupId === id).length,
      connections: this.connections().find((item) => item.ownerOrgId === group.orgId && referencedAliases.has(item.alias)).length,
      subjects: group.subjects.length,
    }
  }

  private requirePermGroup(id: string): ConnectorPermGroupRecord {
    const group = this.permGroups().get(id)
    if (!group) throw new Error(t('连接器权限组不存在：{id}', { id }))
    return group
  }

  private validatePolicies(orgId: string, policies: Record<string, ProviderPolicy>): void {
    for (const [service, policy] of Object.entries(policies)) {
      if (!RESOURCE_PATTERN.test(`connector:${service}`)) {
        throw new Error(t('provider 段不满足计量资源正则：{service}', { service }))
      }
      if (policy.riskCap && !(policy.riskCap in { read: 1, write: 1, admin: 1 })) {
        throw new Error(t('riskCap 非法：{value}（read|write|admin）', { value: String(policy.riskCap) }))
      }
      for (const alias of policy.connections ?? []) {
        this.assertAliasPrefix(alias, orgId)
        if (!this.connections().findOne((item) => item.alias === alias && item.ownerOrgId === orgId)) {
          throw new Error(t('引用的连接不存在或不在本组织：{alias}', { alias }))
        }
      }
    }
  }

  private normalizePolicies(policies: Record<string, ProviderPolicy>): Record<string, ProviderPolicy> {
    return Object.fromEntries(Object.entries(policies).map(([service, policy]) => [
      service,
      {
        // Normalisation des trois formes : joker chaîne '*' / motif simple 'service.*' / tableau (sémantique pattern au plan §2.4)
        allowedActions: policy.allowedActions === '*'
          ? '*'
          : Array.isArray(policy.allowedActions)
            ? policy.allowedActions
            : (typeof policy.allowedActions === 'string' && policy.allowedActions.endsWith('.*') ? [policy.allowedActions] : ['*']),
        riskCap: policy.riskCap ?? 'read',
        ...(policy.connections?.length ? { connections: [...new Set(policy.connections)] } : {}),
        constraints: {
          ...(policy.constraints?.readOnly !== undefined ? { readOnly: policy.constraints.readOnly } : {}),
          ...(policy.constraints?.denyParams?.length ? { denyParams: policy.constraints.denyParams } : {}),
        },
      },
    ]))
  }

  private afterPermGroupChange(group: ConnectorPermGroupRecord): void {
    this.ctx.platformBus.emit(PlatformEvents.ConnectorPermGroupChanged, { groupId: group.id, name: group.name, change: 'upserted' })
    // OPT-P1-05 : ordonnancement explicite (les erreurs sont observables via handleMirrorFailure, plus d'engloutissement silencieux)
    void this.mirrorTokenPolicySafe(group)
  }

  // -- Deuxième couche : miroir de politique des jetons oct_ (#7) -----------------------------------------

  private clientForMirror(): OcClient {
    return this.requireClient().client
  }

  /** Instantané du groupe de permissions (pattern transmis tel quel + liste des IDs stables des connexions visibles du groupe ; frontière org liée par nature, trio ②). */
  policySnapshot(group: ConnectorPermGroupRecord): OcTokenPolicy & { snapshotHash: string } {
    const allowed: string[] = []
    let wildcard = false
    for (const policy of Object.values(group.policies)) {
      if (policy.allowedActions === '*') {
        wildcard = true
        continue
      }
      allowed.push(...policy.allowedActions)
    }
    const referencedAliases = [...new Set(Object.values(group.policies).flatMap((policy) => policy.connections ?? []))]
    const allowedConnections = referencedAliases.length === 0
      ? []
      : this.connections()
          .find((item) => item.ownerOrgId === group.orgId && referencedAliases.includes(item.alias))
          .map((item) => item.ocConnectionId)
          .filter((id): id is string => Boolean(id))
    // Court-circuit joker : n'importe quelle politique du groupe déclarant '*' vaut ['*'] pour tout (sous sémantique union, plus de mélange avec les entrées explicites)
    const sortedAllowed = wildcard ? ['*'] : [...new Set(allowed)].sort()
    const snapshot = {
      allowedActions: sortedAllowed,
      blockedActions: [] as string[],
      allowedProxies: [] as string[],
      allowedConnections: [...allowedConnections].sort(),
    }
    return { ...snapshot, snapshotHash: sha256Hex(JSON.stringify(snapshot)) }
  }

  /** Convergence du registre : frappe à la création / PUT intégral seulement si l'empreinte d'instantané change (quatre tableaux complets) / DELETE pour la suppression. */
  /**
   * Enveloppe de sécurité du miroir (OPT-P1-05) : miroir réussi = levée du fail-closed du groupe ;
   * échec traité explicitement (révocation des anciens jetons + événement d'alerte + fail-closed du groupe), fini le catch(() => undefined) silencieux.
   */
  private async mirrorTokenPolicySafe(group: ConnectorPermGroupRecord): Promise<void> {
    try {
      await this.mirrorTokenPolicy(group)
      this.mirrorFailureGroups.delete(group.id)
    } catch (error) {
      await this.handleMirrorFailure(group, error)
    }
  }

  /**
   * Traitement d'un échec de miroir (OPT-P1-05, montée en grade de la vérification d'audit #10) : après un resserrement de permissions, des jetons oct_ anciens encore valides à court terme
   * amplifieraient la fenêtre TOCTOU — à l'échec : révocation immédiate des anciens jetons d'exécution du groupe + émission de l'alerte connector.policy_mirror_failed
   * + invoke du groupe en fail-closed jusqu'à réussite du miroir (l'inspection/le prochain changement retente la récupération automatiquement).
   */
  private async handleMirrorFailure(group: ConnectorPermGroupRecord, error: unknown): Promise<void> {
    const message = error instanceof Error ? error.message : String(error)
    this.mirrorFailureGroups.add(group.id)
    this.tokenValueCache.delete(group.id)
    await this.deleteTokenForGroup(group.id).catch(() => undefined)
    this.ctx.platformBus.emit(PlatformEvents.ConnectorPolicyMirrorFailed, {
      groupId: group.id, groupName: group.name, orgId: group.orgId, error: message, at: nowIso(),
    })
  }

  async mirrorTokenPolicy(group: ConnectorPermGroupRecord): Promise<{ tokenId: string; hash: string; changed: boolean }> {
    const client = this.clientForMirror()
    const snapshot = this.policySnapshot(group)
    const ledger = this.tokens().findOne((item) => item.permGroupId === group.id)
    if (!ledger) {
      const minted = await client.createRuntimeToken({
        name: `dsh-${group.id}`,
        allowedActions: snapshot.allowedActions,
        blockedActions: snapshot.blockedActions,
        allowedProxies: snapshot.allowedProxies,
        allowedConnections: snapshot.allowedConnections,
      })
      if (!minted.id) throw new OcError('runtime_token_invalid', t('open-connector 未返回运行时令牌 id'), undefined, 502)
      // OPT-P1-05 : déduplication des miroirs concurrents — pendant l'await de frappe, un autre miroir a pu établir le registre, upsert par groupe plutôt qu'insert aveugle
      const concurrentLedger = this.tokens().findOne((item) => item.permGroupId === group.id)
      if (concurrentLedger) {
        this.tokens().update(concurrentLedger.id, { ocTokenId: minted.id, policySnapshotHash: snapshot.snapshotHash, lastSyncedAt: nowIso() })
      } else {
        this.tokens().insert({
          id: newId('ctk'), permGroupId: group.id, ocTokenId: minted.id,
          policySnapshotHash: snapshot.snapshotHash, createdAt: nowIso(), lastSyncedAt: nowIso(),
        })
      }
      if (minted.token) this.tokenValueCache.set(group.id, minted.token)
      return { tokenId: minted.id, hash: snapshot.snapshotHash, changed: true }
    }
    if (ledger.policySnapshotHash !== snapshot.snapshotHash) {
      // PUT intégral des quatre tableaux — l'amont ne perd pas pour autant ses allowedConnections existants (point confirmé du correctif P1 ⑤)
      await client.updateRuntimeToken(ledger.ocTokenId, {
        allowedActions: snapshot.allowedActions,
        blockedActions: snapshot.blockedActions,
        allowedProxies: snapshot.allowedProxies,
        allowedConnections: snapshot.allowedConnections,
      })
      this.tokens().update(ledger.id, { policySnapshotHash: snapshot.snapshotHash, lastSyncedAt: nowIso() })
      return { tokenId: ledger.ocTokenId, hash: snapshot.snapshotHash, changed: true }
    }
    this.tokens().update(ledger.id, { lastSyncedAt: nowIso() })
    return { tokenId: ledger.ocTokenId, hash: snapshot.snapshotHash, changed: false }
  }

  async deleteTokenForGroup(groupId: string): Promise<void> {
    const ledger = this.tokens().findOne((item) => item.permGroupId === groupId)
    if (!ledger) return
    try {
      await this.clientForMirror().deleteRuntimeToken(ledger.ocTokenId)
    } catch { /* déjà supprimé en amont : objectif atteint */ }
    this.tokens().remove(ledger.id)
    this.tokenValueCache.delete(groupId)
  }

  /** Obtention de la valeur du jeton : succès en mémoire → sinon refrappe paresseuse après redémarrage (sémantique de refrappe et non de récupération, décision journal ①). */
  private async obtainOctToken(group: ConnectorPermGroupRecord): Promise<string> {
    const cached = this.tokenValueCache.get(group.id)
    if (cached) return cached
    const client = this.clientForMirror()
    const ledger = this.tokens().findOne((item) => item.permGroupId === group.id)
    const snapshot = this.policySnapshot(group)
    const minted = await client.createRuntimeToken({
      name: `dsh-${group.id}`,
      allowedActions: snapshot.allowedActions,
      blockedActions: snapshot.blockedActions,
      allowedProxies: snapshot.allowedProxies,
      allowedConnections: snapshot.allowedConnections,
    })
    if (ledger) {
      // Perte intra-processus (redémarrage) : l'ancien token est immédiatement détruit pour éviter la survie
      await client.deleteRuntimeToken(ledger.ocTokenId).catch(() => undefined)
      this.tokens().update(ledger.id, { ocTokenId: minted.id, policySnapshotHash: snapshot.snapshotHash, lastSyncedAt: nowIso() })
    } else {
      // OPT-P1-05 : pendant l'await de frappe, un autre miroir a pu établir le registre, upsert par groupe plutôt qu'insert aveugle
      const racedLedger = this.tokens().findOne((item) => item.permGroupId === group.id)
      if (racedLedger) {
        this.tokens().update(racedLedger.id, { ocTokenId: minted.id, policySnapshotHash: snapshot.snapshotHash, lastSyncedAt: nowIso() })
      } else {
        this.tokens().insert({
          id: newId('ctk'), permGroupId: group.id, ocTokenId: minted.id,
          policySnapshotHash: snapshot.snapshotHash, createdAt: nowIso(), lastSyncedAt: nowIso(),
        })
      }
    }
    if (!minted.token) throw new OcError('runtime_token_invalid', t('运行时令牌未返回一次性 token 值'), undefined, 502)
    this.tokenValueCache.set(group.id, minted.token)
    return minted.token
  }

  // -- Décision d'autorisation (cœur de la première couche) ---------------------------------------------------

  /** Trouve les groupes candidats dont le sujet correspond (user_group étendu via iam.resolveGroupMembers ; agent/app comparés directement par id). */
  candidateGroups(caller: InvokeCaller): ConnectorPermGroupRecord[] {
    return this.permGroups().all().filter((group) =>
      group.subjects.some((subject) => {
        if (subject.type === 'user_group' && caller.type === 'user') {
          return this.ctx.iam.resolveGroupMembers(subject.id).some((user) => user.id === caller.id)
        }
        return subject.type === caller.type && subject.id === caller.id
      }))
  }

  /** Plan §2.4 : correspondance pattern + riskCap ≥ niveau de risque (R6 : entrée unifiée resolveRiskLevel, catalogue déclaratif prioritaire) + readOnly/denyParams imposés (comble le manque côté mcp). */
  authorizeAgainst(group: ConnectorPermGroupRecord, action: CatalogActionRecord, input: Record<string, unknown>): { ok: true; policy: ProviderPolicy } | { ok: false; reason: string } {
    const policy = group.policies[action.service]
    if (!policy) return { ok: false, reason: t('权限组 {group} 未配置 provider {service} 的策略', { group: group.name, service: action.service }) }
    // '*' peut être un joker chaîne ou un élément de tableau (le schéma admet les deux formes), normalisé avant correspondance pattern uniforme
    const rawAllowed: unknown = policy.allowedActions
    const patterns = rawAllowed === '*' ? ['*'] : Array.isArray(rawAllowed) ? rawAllowed : undefined
    if (!patterns) {
      return { ok: false, reason: t('权限组 {group} 的 allowedActions 形态非法：{value}（应为 \'*\' 或字符串数组）', { group: group.name, value: JSON.stringify(rawAllowed)?.slice(0, 80) ?? '' }) }
    }
    const patternHit = patterns.some((pattern) => pattern === '*' || pattern === action.id
      || (pattern.endsWith('.*') && action.service === pattern.slice(0, -2)))
    if (!patternHit) return { ok: false, reason: t('action {action} 不在权限组 {group} 的允许模式内', { action: action.id, group: group.name }) }
    const riskLevel = resolveRiskLevel(action, action.service)
    if (rankOf(policy.riskCap) < rankOf(riskLevel)) {
      return { ok: false, reason: t('action 风险级 {risk} 超出权限组 {group} 的 riskCap {cap}', { risk: riskLevel, group: group.name, cap: policy.riskCap }) }
    }
    if (policy.constraints?.readOnly && riskLevel !== 'read') {
      return { ok: false, reason: t('权限组 {group} 为只读模式，action {action}（{risk}）被拒绝', { group: group.name, action: action.id, risk: riskLevel }) }
    }
    for (const deniedKey of policy.constraints?.denyParams ?? []) {
      if (hasInputKey(input, deniedKey)) {
        return { ok: false, reason: t('参数 {key} 在权限组 {group} 的 denyParams 内，已拦截', { key: deniedKey, group: group.name }) }
      }
    }
    return { ok: true, policy }
  }

  /** Entrée indépendante de vérification d'autorisation (partagée tools/REST ; l'ancienne lecture « étapes ③⑤ de la chaîne en sept maillons fusionnées » est abrogée avec le retrait de billing, OPT-P0-02). */
  authorize(caller: InvokeCaller, actionId: string, input: Record<string, unknown>, groups?: ConnectorPermGroupRecord[]): { ok: true; group: ConnectorPermGroupRecord; policy: ProviderPolicy; action: CatalogActionRecord } | { ok: false; reason: string } {
    const action = (() => {
      try {
        return this.requireAction(actionId)
      } catch {
        return undefined
      }
    })()
    if (!action) return { ok: false, reason: t('action 不在纳管目录中：{action}', { action: actionId }) }
    const candidates = groups ?? this.candidateGroups(caller)
    if (candidates.length === 0) return { ok: false, reason: t('主体 {name} 未被任何连接器权限组授权', { name: caller.name }) }
    for (const group of candidates) {
      const verdict = this.authorizeAgainst(group, action, input)
      if (verdict.ok) return { ok: true, group, policy: verdict.policy, action }
    }
    return { ok: false, reason: candidates
      .map((group) => this.authorizeAgainst(group, action, input))
      .filter((verdict): verdict is Exclude<typeof verdict, { ok: true }> => !verdict.ok)
      .map((verdict) => verdict.reason)[0] ?? t('action {action} 不在任何命中组的授权范围', { action: actionId }) }
  }

  // -- Jetons de capacité d'exécution d'approbation (OPT-P1-02) -------------------------------------------

  /**
   * Enregistrement de l'exécuteur d'approbation haut risque admin (OPT-P1-02) : la fermeture de l'exécuteur est définie dans la classe via cette méthode,
   * la frappe du jeton de capacité (approvalCapabilityVault.mint, détenu par une fermeture module) n'a lieu qu'à l'instant de la relance après approbation —
   * un plugin externe, même doté de ctx.connectorHub, ne peut ni frapper ni deviner le jeton ; la valeur de retour réutilise la fonction de désactivation de registerExecutor.
   */
  bindAdminActionExecutor(audit: {
    registerExecutor: (kind: string, executor: (payload: Record<string, unknown>, approverId: string) => Promise<unknown>) => () => void
  }): () => void {
    return audit.registerExecutor('connector.action.admin', async (payload) => {
      const callerPayload = (payload['caller'] ?? {}) as { type?: InvokeCaller['type']; id?: string; name?: string; actChain?: InvokeCaller['actChain'] }
      const caller: InvokeCaller = {
        type: callerPayload.type ?? 'user',
        id: callerPayload.id ?? '',
        name: callerPayload.name ?? '',
        ...(callerPayload.actChain?.length ? { actChain: callerPayload.actChain } : {}),
      }
      const actionId = String(payload['actionId'])
      const result = await this.invokeAction(caller, {
        actionId,
        input: (payload['input'] ?? {}) as Record<string, unknown>,
        ...(typeof payload['alias'] === 'string' && payload['alias'] ? { alias: payload['alias'] } : {}),
        approvalCapability: approvalCapabilityVault.mint(actionId, caller),
      })
      if (!result.ok) throw new Error(result.status === 'approval_required' ? t('递归审批异常：不应再次生成审批单') : result.error)
      return { runId: result.runId, status: result.status, latencyMs: result.latencyMs }
    })
  }

  // -- Passerelle invoke (#5, chaîne en six maillons) ------------------------------------------------

  async invokeAction(caller: InvokeCaller, params: {
    actionId: string
    input?: Record<string, unknown>
    alias?: string
    dryRun?: boolean
    /** Jeton de capacité d'exécution d'approbation (OPT-P1-02) : seule la fermeture de l'exécuteur interne à la classe peut frapper ; inatteignable des façades REST/outils, falsification = fail-closed. */
    approvalCapability?: ApprovalExecutionCapability
    /** additive (D10/§10.4) : index de référence d'autorisation de travail, simple transmissif d'index ; le fait d'autorisation est toujours revérifié côté serveur par le port workforce. */
    workRef?: WorkRefIndex
  }): Promise<InvokeOutcome> {
    const started = Date.now()
    const input = params.input ?? {}

    // ②′ Admission au niveau travail (D10/blueprint §4.3+annexe D.5) : ajouté avant la chaîne de contrôle existante, sans remplacer ni supprimer l'ancienne chaîne en sept maillons.
    // La détermination « géré » ne s'appuie que sur la recherche inverse du caller de confiance (indépendante de la présence d'un workRef — la suppression d'une référence par l'employé ne doit pas rouvrir une branche permissive) ;
    // port non prêt ou caller non géré → l'ancienne chaîne s'applique telle quelle. Les faits d'action (provider/risque) sont lus dans la définition existante, aucune autodéclaration.
    const actionDef = (() => {
      try {
        return this.requireAction(params.actionId)
      } catch {
        return undefined
      }
    })()
    const argsHash = sha256Hex(canonicalArgsJson(input))
    const gate = actionDef
      ? await gateManagedWork(
          (this.ctx as { workforcePolicy?: WorkforcePolicyRegistry }).workforcePolicy,
          workCallerOf(caller),
          {
            facts: {
              kind: 'connector',
              registryId: actionDef.service,
              action: params.actionId,
              risk: actionDef.riskLevel === 'read' ? 'read' : 'write',
            },
            ...(params.workRef ? { ref: params.workRef } : {}),
            argsHash,
          },
        )
      : { mode: 'legacy' as const }
    if (gate.mode === 'denied') {
      // Style de refus aligné sur la sortie denied existante : motif en chinois + code de domaine (§13.3)
      const reason = `${WORK_DENY_CODE_LABELS[gate.code]}：${gate.message}`
      this.emitDeniedEvent(caller, params.actionId, reason, started)
      return { ok: false, status: 'denied', error: reason, latencyMs: Date.now() - started, code: gate.code }
    }

    // ③ Autorisation de première couche (correspondance sujet + vérification policy ; orgId décidé par le groupe atteint — décision journal ③)
    const verdict = this.authorize(caller, params.actionId, input)
    if (!verdict.ok) {
      this.emitDeniedEvent(caller, params.actionId, verdict.reason, started)
      return { ok: false, status: 'denied', error: verdict.reason, latencyMs: Date.now() - started }
    }
    const { group, policy, action } = verdict
    const authorizedHash = this.policySnapshot(group).snapshotHash // OPT-P1-05 : référence de l'instantané au moment de l'autorisation
    // OPT-P2-01 : jugement dans le domaine ODD — pour les groupes ayant déclaré un odd, l'appel hors domaine est refusé et tracé (connector.odd_exit vers l'audit)
    if (group.odd) {
      const catalogSyncedAt = this.catalogSnapshotSyncedAt()
      const oddVerdict = inOdd(group.odd, { id: action.id, service: action.service }, { now: new Date(), catalogSyncedAt })
      if (!oddVerdict.in) {
        this.ctx.platformBus.emit(PlatformEvents.ConnectorOddExit, {
          groupId: group.id, groupName: group.name, orgId: group.orgId, actionId: action.id,
          callerId: caller.id, reasons: oddVerdict.reasons, at: nowIso(),
        })
        this.emitDeniedEvent(caller, params.actionId, t('ODD 离域：{reasons}', { reasons: oddVerdict.reasons.join('；') }), started)
        return { ok: false, status: 'denied', error: t('调用超出该权限组的运营设计域（ODD）：{reasons}', { reasons: oddVerdict.reasons.join('；') }), latencyMs: Date.now() - started }
      }
    }
    // Fail-closed au niveau groupe (OPT-P1-05) : pendant un échec de miroir, l'ancienne face d'autorisation est indisponible jusqu'à réussite du miroir
    if (this.mirrorFailureGroups.has(group.id)) {
      const reason = t('该权限组 oct_ 令牌策略镜像失败，fail-closed 直至镜像成功（connector.policy_mirror_failed 已告警）')
      this.emitDeniedEvent(caller, params.actionId, reason, started)
      return { ok: false, status: 'denied', error: reason, latencyMs: Date.now() - started }
    }

    // dry-run : l'aperçu d'impact est délivré dès l'autorisation passée (partagé par le smoke CLI et la simulation UI)
    if (params.dryRun) {
      return {
        ok: true, status: 'dry_run',
        preview: {
          actionId: action.id, service: action.service, riskLevel: action.riskLevel,
          permGroup: group.name, orgId: group.orgId,
          connections: policy.connections ?? [],
          readOnlyConstraint: Boolean(policy.constraints?.readOnly),
          note: t('授权链前五步全部通过，dry-run 不执行真实调用'),
        },
      }
    }

    // ④ Barrière d'approbation haut risque : le niveau admin passe obligatoirement par l'approbation connector.action.admin, après approve l'exécuteur relance avec le jeton de capacité
    // à usage unique (OPT-P1-02). Sans jeton/falsifié/expiré/mésapparié → ouverture de fiche systématique (fail-closed).
    // Une fiche pending identique (action+groupe+sujet+empreinte d'entrée) est réutilisée telle quelle, pas de création en double.
    if (action.riskLevel === 'admin' && !approvalCapabilityVault.consume(params.approvalCapability, action.id, caller)) {
      // OPT-P2-02 : les paramètres nommés sensibles n'entrent pas dans le stockage d'approbation — l'approbation admin exécute l'input original, un masque serait envoyé en *** au plan de données,
      // donc les appels portant des clés sensibles sont directement refusés (fail-closed), avec invitation à ajuster les paramètres.
      const sensitivePaths = scanSensitiveKeys(input)
      if (sensitivePaths.length > 0) {
        const reason = t('入参携带敏感命名参数（{keys}）：admin 审批通道禁止敏感值入审批存储，请调整入参后重试（OPT-P2-02）', { keys: sensitivePaths.join('、') })
        this.emitDeniedEvent(caller, params.actionId, reason, started)
        return { ok: false, status: 'denied', error: reason, latencyMs: Date.now() - started }
      }
      const reused = this.dedupeAdminApproval(group, action, caller, input)
      if (reused) {
        return { ok: false, status: 'approval_required', approvalId: reused.id, actionId: action.id, message: t('已有待审的高危调用单：{id}（批准后自动完成调用）', { id: reused.id }) }
      }
      const approval = this.ctx.audit.createApproval({
        kind: 'connector.action.admin',
        // WP-10/L1 (QA A-06) : L4 haut risque unifié — l'approbation exige double confirmation + marqueur de revue finale société
        riskLevel: 'high',
        title: t('高危调用：{service}/{action}', { service: action.service, action: action.id }),
        payload: {
          // Les données d'opération (paramètres d'action) peuvent entrer dans la charge d'approbation ; les identifiants provider jamais — de même pour l'approbation de connexion en deux phases
          actionId: action.id, service: action.service,
          inputHash: sha256Hex(JSON.stringify(input)),
          input,
          permGroupId: group.id, permGroupName: group.name, orgId: group.orgId,
          ...(params.alias ? { alias: params.alias } : {}),
          caller: { type: caller.type, id: caller.id, name: caller.name, actChain: caller.actChain },
        },
        requesterId: caller.id,
        requesterName: caller.name,
      })
      return {
        ok: false, status: 'approval_required', approvalId: approval.id, actionId: action.id,
        message: t('action {action} 为 admin 风险级，已生成审批单，批准后自动完成调用', { action: action.id }),
      }
    }

    // ⑤ Limitation à fenêtre glissante : key=<permGroupId>:<callerType>:<callerId>
    const bucketKey = `${group.id}:${caller.type}:${caller.id}`
    const minuteMark = Date.now()
    const bucket = (this.rateBuckets.get(bucketKey) ?? []).filter((mark) => minuteMark - mark < 60_000)
    if (bucket.length >= group.rateLimitPerMin) {
      this.rateBuckets.set(bucketKey, bucket)
      this.countErrors(`限流触发：${bucketKey}`)
      return { ok: false, status: 'rate_limited', error: t('触发限流：{limit} 次/分钟', { limit: group.rateLimitPerMin }), latencyMs: Date.now() - started }
    }
    bucket.push(minuteMark)
    this.rateBuckets.set(bucketKey, bucket)

    // Barrière de hors ligne au niveau connexion : alias désigné ou connexion unique liée à une politique en état de maintenance hors ligne → refus direct côté plateforme
    const effectiveAlias = params.alias ?? (policy.connections?.length === 1 ? policy.connections[0]! : undefined)
    if (effectiveAlias) {
      const boundRef = this.connections().findOne((item) => item.alias === effectiveAlias && item.ownerOrgId === group.orgId)
      if (!boundRef) {
        this.emitDeniedEvent(caller, params.actionId, t('连接不存在或不属于本组织：{alias}', { alias: effectiveAlias }), started)
        return { ok: false, status: 'denied', error: t('连接不存在或不属于本组织：{alias}', { alias: effectiveAlias }), latencyMs: Date.now() - started }
      }
      if (boundRef.offlinedAt) {
        this.emitDeniedEvent(caller, params.actionId, t('连接已下线：{alias}（{reason}）', { alias: effectiveAlias, reason: boundRef.errorReason ?? '' }), started)
        return { ok: false, status: 'denied', error: t('连接已下线：{alias}', { alias: effectiveAlias }), latencyMs: Date.now() - started }
      }
    }

    // ⑦ Obtention/frappe du jeton oct_ + exécution du plan de données (avec récupération automatique 401/connection_not_allowed, correctif P1 ⑥)
    try {
      const octToken = await this.obtainOctToken(group)
      // Vérification d'empreinte d'instantané côté exécution (OPT-P1-05, deux phases légères) : si le groupe de permissions est resserré ou la politique dérive entre autorisation et exécution
      // → refus d'exécuter sur l'ancien instantané et émission de connector.policy_snapshot_drifted ; une nouvelle tentative de l'appelant repasse l'autorisation sur le nouvel instantané.
      const freshGroup = this.permGroups().get(group.id)
      const currentHash = freshGroup ? this.policySnapshot(freshGroup).snapshotHash : undefined
      const ledgerHash = this.tokens().findOne((item) => item.permGroupId === group.id)?.policySnapshotHash
      if (!freshGroup || currentHash !== authorizedHash || (ledgerHash !== undefined && ledgerHash !== currentHash)) {
        this.ctx.platformBus.emit(PlatformEvents.ConnectorPolicySnapshotDrifted, {
          groupId: group.id, groupName: group.name, actionId: action.id,
          authorizedHash, currentHash, ledgerHash, callerId: caller.id, at: nowIso(),
        })
        this.emitDeniedEvent(caller, params.actionId, t('权限组策略在授权后变更（快照漂移 {from}→{to}），拒绝按旧快照执行', { from: authorizedHash.slice(0, 8), to: currentHash ? currentHash.slice(0, 8) : 'deleted' }), started)
        return { ok: false, status: 'denied', error: t('权限组策略在授权后发生变更（快照漂移），已拒绝执行：请重试以按最新策略重新授权'), latencyMs: Date.now() - started }
      }
      // Clé d'idempotence métier stable (§4.3/§11.5, V19/V20) : pour les appels gérés autorisés avec run déjà lié, on emploie la clé stable
      // sha256(`wf:<runId>:<stepKey>:<actionId>:<résumé des paramètres>`) (tronquée à 48 caractères, longueur sûre), réutilisée entre requêtes —
      // renvoyer la même étape ne génère plus une seconde écriture métier ; le chemin non géré conserve la clé aléatoire d'origine (statu quo).
      const managedRunId = gate.mode === 'managed' ? (gate.work.runId ?? params.workRef?.runId ?? '') : ''
      const idempotencyKey = action.riskLevel === 'read'
        ? undefined
        : gate.mode === 'managed' && managedRunId
          ? sha256Hex(`wf:${managedRunId}:${params.workRef?.stepKey ?? ''}:${action.id}:${argsHash}`).slice(0, 48)
          : crypto.randomUUID()
      const chosenAlias = effectiveAlias
      const outcome = await this.executeWithRecovery(group, action, {
        input, alias: chosenAlias, idempotencyKey,
      }, octToken)

      // Enveloppe du plan de données : l'audit de la plateforme note rétroactivement les cas marginaux (meta.auditPersisted=false, correctif P1 ⑧)
      const auditPersisted = outcome.meta['auditPersisted'] !== false
      const runId = typeof outcome.meta['executionId'] === 'string' ? outcome.meta['executionId'] as string : newId('run')

      // Clôture : usage.record est la source de fait de facturation (clé d'idempotence=connector:<runId>, trace_id=executionId)
      let metered = true
      try {
        this.ctx.usage.record({
          org: group.orgId,
          subject: `${caller.type}:${caller.id}`,
          principal: `org:${group.orgId}`,
          resource: `connector:${action.service}`,
          meters: [{ key: 'calls', value: 1, unit: '次' }],
          idempotency_key: `connector:${runId}`,
          trace_id: runId,
        })
      } catch (error) {
        metered = false
        this.ctx.logger('connector').warn('usage 计量登记失败', error)
      }
      if (!metered) {
        this.countErrors(`计量失败：connector:${action.service}`)
      }
      this.noteSuccessSignal()

      // Complément rétroactif + alerte à seuil bas (T-28)
      if (!auditPersisted) {
        this.ctx.audit.record({
          type: 'invoke', actorType: caller.type === 'user' ? 'human' : 'machine',
          actorId: caller.id, actorName: caller.name,
          action: 'connector.invoke.recovered-audit', resourceType: 'connector_action',
          resourceId: runId, resourceName: `${action.service}/${action.id}`,
          result: 'ok',
          detail: t('sidecar 报 auditPersisted=false，结果有效但上游审计未落库——平台补记本条（runId={runId}）', { runId }),
          ...(caller.actChain?.length ? { actChain: caller.actChain } : {}),
        })
        this.countErrors(`auditPersisted=false 补记：${runId}`)
      }

      // Événement d'audit invoke (le plugin audit y souscrit pour écrire le journal invoke, en transmettant actChain + runId)
      const finalLatencyMs = Date.now() - started
      // Expression de décision unifiée (contrat W3-T5 §11) : les sorties d'autorisation existantes sont enveloppées par wrapPolicyDecision, l'id de décision est journalisé avec l'événement
      const allowDecision = wrapPolicyDecision(true, [`权限组 ${group.name} 授权命中（${action.service}/${action.id}）`])
      this.ctx.platformBus.emit(PlatformEvents.ConnectorInvoked, {
        ok: true, service: action.service, actionId: action.id, runId,
        serviceRisk: action.riskLevel, permGroupId: group.id,
        callerType: caller.type, callerId: caller.id, callerName: caller.name,
        latencyMs: finalLatencyMs, actChain: caller.actChain,
        auditPersisted, metered,
        decisionId: allowDecision.decisionId, decisionReasons: allowDecision.reasons,
      })
      // Référentiel d'alerte de latence : évaluation directe sur la durée unitaire (ensemencement des règles : voir l'entrée connector_latency de seedConnectorDemo)
      this.ctx.audit.evaluateAlerts('connector_latency', {
        value: finalLatencyMs,
        resourceType: 'connector_action',
        resourceId: action.id,
        service: action.service,
        permGroupId: group.id,
      })

      return {
        ok: true, status: 'ok', runId, latencyMs: Date.now() - started,
        data: outcome.data, meta: outcome.meta, metered,
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.noteBusinessFailure(message)
      this.emitDeniedEvent(caller, params.actionId, message, started, true)
      const code = error instanceof OcError ? error.code : 'execute_failed'
      return { ok: false, status: 'error', error: message, latencyMs: Date.now() - started, code }
    }
  }

  /** Réutilise une fiche d'approbation pending de même intention, pour éviter de bombarder le centre d'approbation de doublons. */
  private dedupeAdminApproval(group: ConnectorPermGroupRecord, action: CatalogActionRecord, caller: InvokeCaller, input: Record<string, unknown>): ApprovalLike | undefined {
    const inputHash = sha256Hex(JSON.stringify(input))
    return this.ctx.audit.approvals().find((item) =>
      item.kind === 'connector.action.admin' && item.status === 'pending'
      && (item as { requesterId?: string }).requesterId === caller.id
      && String((item.payload as Record<string, unknown>)['actionId'] ?? '') === action.id
      && String((item.payload as Record<string, unknown>)['permGroupId'] ?? '') === group.id
      && String((item.payload as Record<string, unknown>)['inputHash'] ?? '') === inputHash)[0]
  }

  /** Enveloppe d'exécution : 401/connection_not_allowed → une nouvelle tentative après mise à jour du jeton sur le dernier instantané (correctif P1 ⑥). */
  private async executeWithRecovery(
    group: ConnectorPermGroupRecord,
    action: CatalogActionRecord,
    options: { input: Record<string, unknown>; alias?: string; idempotencyKey?: string },
    octToken: string,
  ): Promise<{ data: unknown; meta: Record<string, unknown> }> {
    const attempt = async (token: string) => {
      const { client } = this.requireClient()
      return await client.executeAction(action.id, options, token)
    }
    try {
      const outcome = await attempt(octToken)
      return { data: outcome.data, meta: outcome.meta }
    } catch (error) {
      const recoverable = error instanceof OcError && (error.code === 'connection_not_allowed' || error.code === 'unauthorized' || error.status === 401)
      if (!recoverable) throw error
      // Récupération automatique : reflète le dernier instantané (nouvelles connexions incorporées dans allowedConnections, etc.) puis prend le dernier jeton et réessaie une fois
      await this.mirrorTokenPolicySafe(group)
      if (this.mirrorFailureGroups.has(group.id)) throw error // miroir toujours en échec : fail-closed, pas de nouvelle tentative avec l'ancienne face d'autorisation (OPT-P1-05)
      this.tokenValueCache.delete(group.id)
      const freshToken = await this.obtainOctToken(group)
      try {
        const retried = await attempt(freshToken)
        return { data: retried.data, meta: retried.meta }
      } catch (retryError) {
        const message = retryError instanceof Error ? retryError.message : String(retryError)
        this.countErrors(`自动恢复重试仍失败：${message}`)
        throw retryError
      }
    }
  }

  private emitDeniedEvent(caller: InvokeCaller, actionId: string, reason: string, startedAt: number, isError = false): void {
    // Expression de décision unifiée (contrat W3-T5 §11) : les sorties de refus existantes sont enveloppées par wrapPolicyDecision, decisionId/reasons
    // ajoutés de façon additive dans l'événement d'audit connector.invoked (la souscription audit est insensible aux champs inconnus) — la décision est traçable, le moteur ne réécrit pas
    const policyDecision = wrapPolicyDecision(false, [reason])
    this.ctx.platformBus.emit(PlatformEvents.ConnectorInvoked, {
      ok: false, actionId, service: actionId.split('.')[0] ?? '',
      callerType: caller.type, callerId: caller.id, callerName: caller.name,
      error: reason, latencyMs: Date.now() - startedAt, actChain: caller.actChain, failed: isError,
      decisionId: policyDecision.decisionId, decisionReasons: policyDecision.reasons,
    })
  }

  /** Comptage des taux d'échec + évaluation d'alerte (evaluateAlerts lit context.value). */
  private errorCounter = new Map<string, number[]>()

  private countErrors(label: string): void {
    const key = 'connector_error_rate'
    const times = (this.errorCounter.get(key) ?? []).filter((mark) => Date.now() - mark < 10 * 60_000)
    times.push(Date.now())
    this.errorCounter.set(key, times)
    this.ctx.audit.evaluateAlerts(key, {
      value: times.length, label,
      resourceType: 'connector_hub',
      resourceId: 'gateway',
    })
  }

  /** Un échec d'appel réel alimente le taux d'échec au-delà du sondage de latence (metricsOnly, sans ouvrir le disjoncteur). */
  private noteBusinessFailure(message: string): void {
    this.countErrors(message.slice(0, 120))
  }

  // -- Tâches planifiées (#7 inspection / #11 réconciliation) -------------------------------------------

  /** Inspection organisationnelle + synchronisation automatique optionnelle de la dérive du catalogue (PATROL_INTERVAL). */
  async runPatrols(autoCatalog: boolean | undefined): Promise<{ violations: Array<Record<string, unknown>>; catalogDrift?: Record<string, unknown> }> {
    const violations: Array<Array<Record<string, unknown>>> = []
    const groupViolations: Array<Record<string, unknown>> = []
    void violations
    const status = this.gatewayStatus()
    if (!status.available) return { violations: groupViolations }
    const { client } = this.requireClient()
    const [remoteTokens, remoteConnections] = await Promise.all([client.listRuntimeTokens(), client.listConnections()])
    const remoteById = new Map(remoteTokens.filter((token) => token.id).map((token) => [token.id, token]))
    const connectionsById = new Map(remoteConnections.filter((item) => item.id).map((item) => [item.id, item]))
    for (const group of this.permGroups().all()) {
      const ledger = this.tokens().findOne((item) => item.permGroupId === group.id)
      if (!ledger) continue
      const token = remoteById.get(ledger.ocTokenId)
      if (!token) {
        groupViolations.push({ kind: 'token_missing_on_sidecar', groupId: group.id, name: group.name, ocTokenId: ledger.ocTokenId })
        continue
      }
      const bound = Array.isArray(token.policy && (token.policy as Record<string, unknown>)['allowedConnections'])
        ? ((token.policy as Record<string, unknown>)['allowedConnections'] as string[])
        : []
      for (const connectionId of bound) {
        const conn = connectionsById.get(connectionId)
        const belongsToOrg = conn
          ? this.connections().findOne((item) => item.ocConnectionId === connectionId && item.ownerOrgId === group.orgId) !== undefined
            || (conn.connectionName ?? '').startsWith(`org:${group.orgId}:`)
          : this.connections().findOne((item) => item.ocConnectionId === connectionId && item.ownerOrgId === group.orgId) !== undefined
        if (!belongsToOrg) {
          groupViolations.push({
            kind: 'token_binds_foreign_connection', groupId: group.id, name: group.name,
            ocTokenId: ledger.ocTokenId, connectionId,
            alias: conn?.connectionName ?? '',
            expectedPrefix: `org:${group.orgId}:`,
          })
        }
      }
    }
    if (groupViolations.length > 0) {
      this.ctx.platformBus.emit(PlatformEvents.ConnectorGatewaySynced, {
        kind: 'org_patrol', violations: groupViolations, at: nowIso(),
      })
      this.ctx.audit.fire({
        severity: 'warning',
        title: t('[连接器 org 巡检] 令牌绑定越界'),
        message: t('发现 {count} 处「令牌绑定连接 ∉ 组内 org」不一致：{detail}', { count: groupViolations.length, detail: JSON.stringify(groupViolations).slice(0, 220) }),
        resourceType: 'connector_gateway',
      })
    }
    let catalogDrift: Record<string, unknown> | undefined
    const record = this.gateways().all()[0]
    const shouldSyncCatalog = autoCatalog ?? ((record?.autoCatalogSyncMinutes ?? 0) > 0)
    if (shouldSyncCatalog) {
      try {
        const syncResult = await this.syncCatalog('patrol')
        catalogDrift = { added: syncResult.added, removed: syncResult.removed, skippedServices: syncResult.skippedServices }
      } catch (error) {
        catalogDrift = { error: error instanceof Error ? error.message : String(error) }
      }
    }
    return { violations: groupViolations, ...(catalogDrift !== undefined ? { catalogDrift } : {}) }
  }

  /**
   * Réconciliation des runs (#11, correctif P1 ⑦) : usage.record est la source de fait de facturation ; cette tâche recoupe les totaux par runtimeTokenId
   * + détection de détournement — un run sans meter égale une alerte de contournement (critical, revue humaine sans disposition automatique).
   * Curseur incrémental + déduplication par id de run (fenêtre chevauchante sûre) ; période de réconciliation par défaut 5 min ≪ fenêtre rotative RUN_LIMIT.
   */
  async reconcileRuns(options: { maxPages?: number } = {}): Promise<{ checkedRuns: number; bypassRuns: string[]; knownTokens: number; matchedMeters: number; cursor?: string }> {
    const status = this.gatewayStatus()
    if (!status.available) return { checkedRuns: 0, bypassRuns: [], knownTokens: 0, matchedMeters: 0 }
    const { client } = this.requireClient()
    const stateCollection = this.runsState()
    let state = stateCollection.findOne((item) => item.key === 'reconcile')
    if (!state) {
      state = stateCollection.insert({ id: newId('crn'), key: 'reconcile', processedIds: [], createdAt: nowIso(), updatedAt: nowIso() })
    }
    const processed = new Set(state.processedIds ?? [])
    const ledgers = this.tokens().all()
    const managedTokenIds = new Set(ledgers.map((item) => item.ocTokenId))
    const bypassRuns: string[] = []
    let checked = 0
    let matched = 0
    let cursor = state.cursor
    const maxPages = options.maxPages ?? 10
    for (let page = 0; page < maxPages; page++) {
      const response = await client.listRuns({ limit: 200, ...(cursor ? { cursor } : {}) })
      for (const run of response.items) {
        if (!run.id || processed.has(run.id)) continue
        processed.add(run.id)
        if (run.runtimeTokenId && managedTokenIds.has(run.runtimeTokenId)) {
          checked++
          const meterCount = countUsageByTrace(this.ctx, run.id)
          if (meterCount > 0) matched++
          else bypassRuns.push(run.id)
        }
      }
      cursor = response.nextCursor
      if (!response.nextCursor || response.items.length === 0) break
    }
    const trimmed = [...processed].slice(-PROCESSED_RUN_CAP)
    stateCollection.update(state.id, { cursor, processedIds: trimmed, lastRunAt: nowIso(), updatedAt: nowIso() })
    if (bypassRuns.length > 0) {
      this.ctx.audit.fire({
        severity: 'critical',
        title: t('[连接器对账] 绕行调用（有 run 无 meter）'),
        message: t('检测到 {count} 条经平台铸造令牌的 sidecar run 无对应 usage 计量：{runs}', { count: bypassRuns.length, runs: bypassRuns.slice(0, 20).join(', ') }),
        resourceType: 'connector_reconcile',
      })
    }
    return { checkedRuns: checked, bypassRuns, knownTokens: managedTokenIds.size, matchedMeters: matched, ...(cursor ? { cursor } : {}) }
  }

  /** Vue runs (affichage en lecture seule console/CLI ; aucune suggestion de disposition, revue humaine). */
  async listRunsView(params: { limit?: number; service?: string; ok?: boolean } = {}): Promise<{ items: OcRunLog[]; knownTokens: number }> {
    if (!this.gatewayStatus().available) return { items: [], knownTokens: 0 }
    const { client } = this.requireClient()
    const page = await client.listRuns({ limit: Math.min(params.limit ?? 100, 500), ...(params.service ? { service: params.service } : {}), ...(params.ok !== undefined ? { ok: params.ok } : {}) })
    return { items: page.items, knownTokens: this.tokens().count() }
  }
}

// ---------------------------------------------------------------------------
// Aides module
// ---------------------------------------------------------------------------

const OC_DEFAULT_TIMEOUT = 15_000

/** Interception denyParams couvrant aussi bien les clés de premier niveau que les chemins pointés. */
function hasInputKey(input: Record<string, unknown>, deniedKey: string): boolean {
  if (Object.hasOwn(input, deniedKey)) return true
  if (!deniedKey.includes('.')) return false
  let node: unknown = input
  for (const segment of deniedKey.split('.')) {
    if (node === null || typeof node !== 'object' || !Object.hasOwn(node as Record<string, unknown>, segment)) return false
    node = (node as Record<string, unknown>)[segment]
  }
  return true
}

function countUsageByTrace(ctx: Context, traceId: string): number {
  const rows = ctx.txnStore.sql<{ n: number }>('SELECT COUNT(*) AS n FROM usage_events WHERE trace_id = ?', [traceId])
  return Number(rows[0]?.n ?? 0)
}

function normalizeAuthType(value: string): ConnectionReferenceRecord['authType'] {
  if (value === 'oauth' || value === 'oauth2' || value === 'bearer_config') return 'oauth'
  if (value === 'custom_credential') return 'custom_credential'
  if (value === 'no_auth' || value === 'none') return 'no_auth'
  return 'api_key'
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    connectorHub: ConnectorHubService
  }
}

export const name = 'connector'
export const inject = ['opsStorage', 'platformBus', 'iam', 'audit', 'usage', 'txnStore', 'authn', 'resourceCore', 'workforcePolicy']

export function apply(ctx: Context) {
  // Même forme d'assemblage que plugin-mcp : l'enregistrement se fait à la construction (provide='connectorHub'),
  // la fermeture de l'exécuteur d'approbation détient directement la référence d'instance — évite le problème de contrôle d'injection d'un exécuteur accédant à ctx.connectorHub entre plugins.
  const hub = new ConnectorHubService(ctx)
  // Préambule de migration post-déploiement : les rôles préexistants en production n'obtiennent pas les points de permission connector.* du seul fait que BuiltinRoles insère sans modifier,
  // l'assemblage de l'extension exécute une migration idempotente unique (côté iam, précédent : approche agent-scopes-usage-write-v1).
  try {
    ctx.iam.ensureConnectorPermissionsMigration()
  } catch (error) {
    ctx.logger('connector').warn('角色权限迁移暂缓（iam 未就绪时宿主会重新依赖解析）', error)
  }
  ctx.effect(() => ctx.audit.registerExecutor('connector.offline', async (payload) => {
    // Plan §2.7 : hors ligne de connexion/passerelle via approbation L4, l'exécuteur applique après approbation
    const scope = String(payload['scope'] ?? 'gateway')
    const reason = String(payload['reason'] ?? t('审批通过下线'))
    if (scope === 'connection') {
      const ref = await hub.offlineConnection(String(payload['connectionId'] ?? ''), { actorName: 'approval-center', reason })
      return { scope, connectionId: ref.id, alias: ref.alias, status: ref.status }
    }
    const record = await hub.offlineGateway(reason)
    return { scope: 'gateway', status: record?.status, baseUrl: record?.baseUrl }
  }))
  ctx.effect(() => ctx.audit.registerExecutor('connector.connect', async (payload) => {
    // Conception en deux phases (décision journal ②) : les identifiants n'entrent jamais dans la charge d'approbation — approbation = enregistrement, la création réelle est faite par le demandeur avec approvalId
    return { acknowledged: true, note: t('审批通过：发起人现在可以提交实际连接凭证（POST /api/connector/connections/* 带 approvalId）'), provider: payload['provider'] ?? '' }
  }))
  // Exécuteur d'approbation haut risque admin (OPT-P1-02) : l'enregistrement est confiné dans bindAdminActionExecutor interne à la classe,
  // la frappe du jeton de capacité est privatisée # — inatteignable des plugins externes (l'ancien paramètre booléen de contournement a été supprimé, 0 occurrence au grep du dépôt comme critère d'acceptation)
  ctx.effect(() => hub.bindAdminActionExecutor(ctx.audit))
  ctx.plugin(connectorTools)
}
