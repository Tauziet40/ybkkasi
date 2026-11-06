/**
 * @dsh-ops/plugin-mcp — gestion des services déployés MCP (plan §3).
 *
 * Plan de gestion (cette extension) : enregistrement des services, processus de déploiement, version/gradation/retour arrière, sondage de santé,
 *                   groupes de permissions (granularité outil + contraintes au niveau paramètre), supervision des appels.
 * Plan de données (passerelle MCP) : invoke() avec authentification unifiée, limitation/disjoncteur, instrumentation de métriques, remontée d'audit.
 * Environnement de démonstration : couche de transport d'exécution mock intégrée — latence/taux de succès/consommation de jetons simulés de façon déterministe.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  PlatformEvents, newId, sha256Hex,
  gateManagedWork, WORK_DENY_CODE_LABELS,
  newTraceId, formatTraceparent,
  PolicyDecisionPoint, wrapPolicyDecision,
  normalizeAssetCategory,
  type Collection, type RecordBase,
  type PolicyDecision, type PolicyModule, type PolicyRequest,
  type UnifiedPrincipal,
  type WorkCallerRef, type WorkDenyCode, type WorkExecutionContext, type WorkRefIndex, type WorkforcePolicyRegistry,
} from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import * as mcpTools from './tools.ts'
import { McpToolRiskRegistry } from './risk-registry.ts'
import { SecretBroker, sensitiveHeaderKeys } from './secret-broker.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

// -- Champs de gouvernance (W1-T2, contrat §5, additive) ---------------------------------------------------

export type McpOwnerEntityType = 'platform' | 'app' | 'agent' | 'connector'

/** Entité propriétaire du service : défaut {type:'platform'} (placeholder plateforme = dette de gouvernance unowned, en attente de réécriture par la liaison de capacités W2-T4). */
export interface McpOwnerEntity {
  type: McpOwnerEntityType
  id?: string
}

export type McpExposureMode = 'gateway' | 'direct' | 'internal'
export type McpDataClass = 'public' | 'internal' | 'confidential'
export type McpEnvironment = 'dev' | 'staging' | 'prod'
export type McpVisibility = 'org' | 'tenant' | 'cross-org'

const OWNER_ENTITY_TYPES: readonly McpOwnerEntityType[] = ['platform', 'app', 'agent', 'connector']
const EXPOSURE_MODES: readonly McpExposureMode[] = ['gateway', 'direct', 'internal']
const DATA_CLASSES: readonly McpDataClass[] = ['public', 'internal', 'confidential']
const ENVIRONMENTS: readonly McpEnvironment[] = ['dev', 'staging', 'prod']
const VISIBILITIES: readonly McpVisibility[] = ['org', 'tenant', 'cross-org']

/** Paramètres optionnels des champs de gouvernance (surface de validation commune create/update). */
export interface McpGovernanceInput {
  ownerEntity?: McpOwnerEntity
  exposureMode?: McpExposureMode
  dataClass?: McpDataClass
  environment?: McpEnvironment
  visibility?: McpVisibility
}

/**
 * Validation et normalisation des champs de gouvernance (contrat §5) : toute valeur d'énumération illégale donne une erreur explicite (ni engloutie, ni repli silencieux sur défaut),
 * ownerEntity.id blanc = non assigné (normalisé en type seul).
 */
export function normalizeGovernanceInput(input: McpGovernanceInput): McpGovernanceInput {
  const out: McpGovernanceInput = {}
  if (input.ownerEntity !== undefined) {
    const candidate = input.ownerEntity as McpOwnerEntity | undefined
    if (!candidate || typeof candidate !== 'object' || !OWNER_ENTITY_TYPES.includes(candidate.type)) {
      throw new Error(t('ownerEntity.type 须为 {values}，收到 {value}', { values: OWNER_ENTITY_TYPES.join('/'), value: String((candidate as McpOwnerEntity | undefined)?.type ?? candidate) }))
    }
    const id = typeof candidate.id === 'string' ? candidate.id.trim() : ''
    out.ownerEntity = id ? { type: candidate.type, id } : { type: candidate.type }
  }
  if (input.exposureMode !== undefined) {
    if (!EXPOSURE_MODES.includes(input.exposureMode)) {
      throw new Error(t('exposureMode 须为 {values}，收到 {value}', { values: EXPOSURE_MODES.join('/'), value: String(input.exposureMode) }))
    }
    out.exposureMode = input.exposureMode
  }
  if (input.dataClass !== undefined) {
    if (!DATA_CLASSES.includes(input.dataClass)) {
      throw new Error(t('dataClass 须为 {values}，收到 {value}', { values: DATA_CLASSES.join('/'), value: String(input.dataClass) }))
    }
    out.dataClass = input.dataClass
  }
  if (input.environment !== undefined) {
    if (!ENVIRONMENTS.includes(input.environment)) {
      throw new Error(t('environment 须为 {values}，收到 {value}', { values: ENVIRONMENTS.join('/'), value: String(input.environment) }))
    }
    out.environment = input.environment
  }
  if (input.visibility !== undefined) {
    if (!VISIBILITIES.includes(input.visibility)) {
      throw new Error(t('visibility 须为 {values}，收到 {value}', { values: VISIBILITIES.join('/'), value: String(input.visibility) }))
    }
    out.visibility = input.visibility
  }
  return out
}

/**
 * Valeur déclarée du risque d'outil. Le lot W, W1 (correction de racine V11) étend 'unknown' : les outils synchronisés depuis tools/list distant ne peuvent pas prouver leur risque,
 * ils tombent tous en 'unknown' (plus de mise en correspondance implicite avec read) — l'arbitrage de 'unknown' est dans la barrière et le port de politique de travail (contexte lecture = passage,
 * contexte écrit = refus RISK_UNREGISTERED), une capacité d'écriture doit d'abord passer l'approbation d'enregistrement de risque (risk-registry.ts).
 */
export interface McpToolSpec {
  name: string
  description: string
  inputSchema: Record<string, unknown>
  riskLevel: 'read' | 'write' | 'admin' | 'unknown'
}

export interface McpVersion {
  version: string
  changelog: string
  publishedAt: string
  status: 'current' | 'previous' | 'rolled-back'
}

export interface McpServiceRecord extends RecordBase {
  name: string
  slug: string
  description: string
  icon: string
  /** Catégorie métier (référentiel unifié ASSET_CATEGORIES des panneaux d'actifs ; défaut « autre », repli à la lecture pour les enregistrements existants). */
  category?: string
  endpoint: string
  transport: 'stdio' | 'sse' | 'http'
  mode: 'hosted' | 'external'
  /** En-têtes de requête personnalisés du service externe (ex. Authorization), transmis à l'appel/au sondage/à la découverte d'outils. */
  headers?: Record<string, string>
  orgId: string
  owner: string
  // -- Champs de gouvernance (W1-T2, contrat §5, additive ; les enregistrements existants reçoivent les valeurs par défaut au démarrage par ensureGovernanceMigration) --
  /** Entité propriétaire : défaut {type:'platform'} (placeholder plateforme, dette de gouvernance unowned ; l'assignation passe par l'endpoint REST owner-entity). */
  ownerEntity: McpOwnerEntity
  /** ID de déclaration de capacité (consommé par la liaison de capacités app W2-T4, réserve additive). */
  capabilityId?: string
  /** Forme d'exposition : défaut 'gateway' (face passerelle) ; direct/internal doivent être explicitement posés. */
  exposureMode: McpExposureMode
  /** Classification des données (consommée par le PDP ABAC W3-T5) : défaut 'internal'. */
  dataClass: McpDataClass
  /** Environnement : défaut 'prod'. */
  environment: McpEnvironment
  /** Périmètre de visibilité (consommé par la contrainte dure d'organisation W3-T5) : défaut 'org'. */
  visibility: McpVisibility
  /** Référence d'identifiants aval (forme local:/env:, la valeur elle-même vit dans le fichier de clés/variables d'environnement du SecretBroker, jamais dans les collections métier). */
  credentialRef?: string
  /** Marque de source de pontage (ex. open-connector) : marque de dégradation de gouvernance du pontage du plan de données M0 — granularité service uniquement,
   *  pas d'autorisation au niveau action/liaison au niveau connexion/miroir de jeton (dev-plan-connector §2.11). La console affiche un badge. */
  bridgeFrom?: string
  /** Marqueur de revue finale société (WP-10/L1) : les appels d'un service passé en revue finale portent un filigrane (traçable dans l'audit). */
  finalReview?: { approverId: string; approverName: string; at: string; approvalId?: string }
  status: 'draft' | 'verifying' | 'online' | 'gray' | 'unhealthy' | 'offline'
  grayPercent: number
  currentVersion: string
  versions: McpVersion[]
  tools: McpToolSpec[]
  health: {
    lastProbeAt?: string
    status: 'unknown' | 'healthy' | 'degraded' | 'down'
    latencyMs?: number
    consecutiveFails: number
    breakerOpen: boolean
  }
  /** Stabilité simulée 0-1 (pour les données de démonstration). */
  stability: number
  rateLimitPerMin: number
  /** Couche d'exécution : real = transport HTTP réel ; demo = simulation déterministe (repli explicite, hors SLO/facturation). */
  exec: 'real' | 'demo'
}

export interface ToolPolicy {
  allowedTools: '*' | string[]
  constraints: { readOnly?: boolean; denyParams?: string[] }
}

export interface McpPermGroupRecord extends RecordBase {
  name: string
  description: string
  /** serviceId → politique d'outils. */
  policies: Record<string, ToolPolicy>
  subjects: Array<{ type: 'user_group' | 'agent' | 'app'; id: string; name?: string }>
}

export interface McpCallRecord {
  id: string
  at: string
  serviceId: string
  serviceName: string
  tool: string
  callerType: 'user' | 'agent' | 'app'
  callerId: string
  callerName: string
  onBehalfOf?: string
  actChain?: Array<{ name: string; type: string }>
  version: string
  ok: boolean
  status: 'ok' | 'error' | 'denied' | 'rate_limited' | 'breaker_open'
  latencyMs: number
  tokens: number
  error?: string
  /** Si l'appel passe par le transport réel ou la simulation de démonstration (rapports SLO/facturation ne comptent que real). */
  exec: 'real' | 'demo'
  /** Filigrane d'appel (WP-10/L1) : après revue finale société du service, tous ses appels portent un filigrane, traçable dans l'audit. */
  watermark?: { finalReview: true; at: string }
  /** Code de refus de domaine (consigné en cas de refus d'autorisation au niveau travail de l'employé numérique, l'audit distingue le niveau de refus). */
  code?: WorkDenyCode
  /** Liaison de travail (additive D11) : référence traversante vers le registre workforce lors d'appels d'employé numérique géré. */
  work?: McpCallWorkRef
  // -- trace de bout en bout et expression de décision (W3-T5, contrats §14/§11, additive) --
  /** trace id de l'appel (32 hex ; généré à l'entrée si absent, relie transferts aval/audit/metering pour reconstituer la chaîne d'appel). */
  traceId?: string
  /** Empreinte de hachage des paramètres (sha256(args JSON)) ; même source et même valeur que l'argsHash de la barrière workforce. */
  argsHash?: string
  /** Code de statut HTTP amont (renseigné quand le transport real répond ; pas de valeur par défaut pour demo/refus). */
  upstreamStatus?: number
  /** id de décision PDP (préfixe pd_ ; consigné quand l'arbitrage principal passe par PolicyDecisionPoint, consultable par audit/réponse de refus). */
  decisionId?: string
  /** Agrégat des raisons de décision PDP (sous priorité deny, la raison du premier module deny est la cause principale, même source que le libellé d'erreur). */
  decisionReasons?: string[]
}

/** Champs de liaison de travail de l'enregistrement d'appel (additive, collection JSON sans schéma strict ; association incrémentale §11.3). */
export interface McpCallWorkRef {
  /** ID d'appel du registre des appels contrôlés workforce (renseigné quand le côté production le fournit). */
  invocationId?: string
  /** ID de l'autorisation de travail (permit) fondant le passage (résultat de la vérification du gate côté serveur). */
  permitId?: string
  /** ID de run métier. */
  runId?: string
  /** ID de l'employé exécutant (résultat de la recherche inverse serveur). */
  employeeId?: string
}

export interface InvokeCaller {
  type: 'user' | 'agent' | 'app'
  id: string
  name: string
  onBehalfOf?: string
  actChain?: Array<{ name: string; type: string }>
  // -- Faits additionnels du Principal unifié (W3-T5, contrats §11/§12/§14, additive ; défaut = fail-open du module PDP correspondant,
  //    les appelants existants (face outils mcp_invoke, etc.) y sont insensibles ; entrées REST/plan de données projetées depuis exchange.principal.unified) --
  /** Rattachement organisationnel de l'appelant (unified.orgId) : consommé par le module org-constraint ; absent = passage au référentiel même organisation. */
  orgId?: string
  /** Tenant de l'appelant (unified.tenantId) : consommé par le jugement trois états de visibility='tenant'. */
  tenantId?: string
  /** Utilisateur réel de la chaîne de délégation (unified.subjectUserId) : consommé par la vérification de cohérence org de la chaîne avec le service cible. */
  subjectUserId?: string
  /** Scopes du jeton (unified.scopes) : consommés par la première couche iam-permission (mcp.invoke / scope de limitation de ressource). */
  scopes?: string[]
  /** trace id de la chaîne d'appel (pris à l'entrée depuis les en-têtes X-Trace-Id / mcp-session-id ou l'invocation gérée ; sinon généré à l'entrée). */
  traceId?: string
  /** Référence d'approbation inter-organisation (context.approvalId) : id d'une fiche d'approbation valide pour un service visibility='cross-org'. */
  approvalId?: string
  /**
   * Ensemble de principaux appariables par les groupes de permissions (additive, audit de sécurité W4 P0-3) : le principal lui-même (type/id) + les acteurs
   * app/agent de la chaîne de délégation (par id de ressource). Défaut = le principal seul (appelants existants insensibles).
   * Sémantique de délégation : lors de User → App/Agent → MCP, c'est l'acteur de la chaîne qui exécute réellement l'action ; le groupe de permissions qui lui est accordé doit s'appliquer à lui.
   */
  subjects?: Array<{ type: 'user' | 'agent' | 'app'; id: string }>
}

/**
 * Codes de refus de la passerelle (additive W3-T5) : au-delà des codes de refus de domaine workforce, codes de domaine des nouveaux modules PDP —
 * ORG_SCOPE_DENIED (contrainte dure organisation/tenant), SCOPE_DENIED (première couche iam-permission),
 * SCENE_DENIED (ABAC de scénario). Comme le WorkDenyCode existant, ils passent par InvokeResult.code / data de réponse de refus
 * .code, l'audit distingue le niveau de refus.
 */
export type McpDenyCode = WorkDenyCode | 'ORG_SCOPE_DENIED' | 'SCOPE_DENIED' | 'SCENE_DENIED'

export interface InvokeResult {
  ok: boolean
  status: McpCallRecord['status']
  latencyMs: number
  version: string
  result?: unknown
  error?: string
  /** Code de refus de domaine (additive) : porté quand status='denied' pour un refus d'autorisation au niveau travail, guide l'arrêt/la demande/l'attente/la retry. */
  code?: McpDenyCode
  // -- Expression de décision et trace de bout en bout (W3-T5, contrats §11/§14, additive) --
  /** id de décision PDP : exposé avec le résultat quand l'arbitrage principal passe par PolicyDecisionPoint (ajouté à côté de data.code de la réponse de refus). */
  decisionId?: string
  /** Agrégat des raisons de décision PDP (même source que error, error prend la première raison deny). */
  decisionReasons?: string[]
  /** trace id de l'appel (associé à l'enregistrement d'appel/à l'événement d'audit). */
  traceId?: string
}

/** Entrée de service unique d'une configuration mcpServers (résultat d'analyse). */
export interface McpConfigEntry {
  name: string
  url: string
  transport: 'http' | 'sse'
  headers?: Record<string, string>
  description?: string
  /** Raison de non-importabilité de l'entrée (ex. forme stdio, url absente). */
  error?: string
}

/** Résultat d'import d'une entrée. */
export interface McpImportResult {
  name: string
  ok: boolean
  slug?: string
  serviceId?: string
  tools?: number
  reachable?: boolean
  status?: string
  /** Les en-têtes sensibles en clair portés par l'import ont été migrés automatiquement dans SecretBroker (enregistrement de service sans clair, sémantique de gouvernance W1). */
  brokered?: boolean
  error?: string
}

/**
 * Analyse un JSON mcpServers (la forme en vigueur chez Claude Desktop / Cursor / Cherry Studio, etc.).
 * Trois entrées prises en charge : l'enveloppe standard {"mcpServers": {...}}, la carte nue {nom: {url, ...}}, l'objet isolé {url, type}.
 * http / streamableHttp / streamable-http normalisés en http ; les formes stdio/command marquées non importables.
 */
export function parseMcpServersConfig(raw: string | object): McpConfigEntry[] {
  let config: unknown
  if (typeof raw === 'string') {
    try {
      config = JSON.parse(raw)
    } catch {
      throw new Error(t('配置不是合法 JSON，请粘贴完整的 mcpServers 配置文本'))
    }
  } else {
    config = raw
  }
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error(t('配置须为 JSON 对象，形如 {"mcpServers": {"服务名": {"type": "streamableHttp", "url": "https://…"}}}'))
  }
  const obj = config as Record<string, unknown>
  let map: Record<string, unknown> | undefined
  if (obj.mcpServers && typeof obj.mcpServers === 'object' && !Array.isArray(obj.mcpServers)) {
    map = obj.mcpServers as Record<string, unknown>
  } else if (typeof obj.url === 'string') {
    const host = (() => { try { return new URL(obj.url).hostname } catch { return 'mcp' } })()
    map = { [host]: obj }
  } else {
    const values = Object.values(obj)
    if (values.length > 0 && values.every((value) => value && typeof value === 'object' && !Array.isArray(value)
      && (typeof (value as Record<string, unknown>).url === 'string' || typeof (value as Record<string, unknown>).command === 'string'))) {
      map = obj
    }
  }
  if (!map || Object.keys(map).length === 0) {
    throw new Error(t('未识别出任何服务条目：需要 {"mcpServers": {"服务名": {"type": "...", "url": "..."}}} 形态'))
  }
  return Object.entries(map).map(([name, server]) => normalizeServerEntry(name, server))
}

function normalizeServerEntry(name: string, server: unknown): McpConfigEntry {
  const record = (server && typeof server === 'object' ? server : {}) as Record<string, unknown>
  const type = String(record.type ?? '').toLowerCase()
  const url = typeof record.url === 'string' ? record.url.trim() : ''
  const headers = normalizeConfigHeaders(record.headers)
  const base = {
    name,
    url,
    transport: 'http' as const,
    ...(headers ? { headers } : {}),
    ...(typeof record.description === 'string' && record.description ? { description: record.description } : {}),
  }
  if (!url) {
    const localProcess = type === 'stdio' || type === 'command' || typeof record.command === 'string'
    return { ...base, error: localProcess
      ? t('stdio/command 形态需在本地拉起进程，平台仅支持 http(streamableHttp)/sse 远程地址接入')
      : t('缺少 url 字段') }
  }
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return { ...base, error: t('url 不是合法地址：{url}', { url }) }
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ...base, error: t('仅支持 http(s) 地址，收到 {protocol}', { protocol: parsed.protocol }) }
  }
  return { ...base, transport: type === 'sse' ? 'sse' : 'http' }
}

function normalizeConfigHeaders(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  const out: Record<string, string> = {}
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    out[key] = String(val)
  }
  return Object.keys(out).length ? out : undefined
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class McpService extends Service {
  static readonly provide = 'mcpRegistry'

  private probeTimer: ReturnType<typeof setInterval> | undefined
  private rateBuckets = new Map<string, number[]>()
  /** Cache de sessions HTTP streamable distantes : endpoint → { sessionId ('' pour un service sans état), expiration }. */
  private mcpSessions = new Map<string, { sessionId: string; expiresAt: number }>()
  /** Référence du service d'enregistrement des risques (assemblage direct dans le apply du même plugin ; hôte de tests unitaires autonomes absent = référentiel d'enregistrement sans effet). */
  private riskRegistryRef: McpToolRiskRegistry | undefined
  /** Référence du Secret Broker (W1-T2 §6 ; assemblage direct dans le apply du même plugin, hôte de tests autonomes absent = pas d'injection d'identifiants). */
  private secretBrokerRef: SecretBroker | undefined

  constructor(ctx: Context) {
    super(ctx, 'mcpRegistry')
    ctx.effect(() => () => {
      if (this.probeTimer) clearInterval(this.probeTimer)
    })
    // Sondage de santé : un tour de 30 s, 3 échecs consécutifs = disjoncteur ouvert
    this.probeTimer = setInterval(() => {
      void this.probeAll()
    }, 30_000)
    this.probeTimer.unref?.() // OPT-P3-02
  }

  services(): Collection<McpServiceRecord> {
    return this.ctx.opsStorage.collection<McpServiceRecord>('mcp:services')
  }

  permGroups(): Collection<McpPermGroupRecord> {
    return this.ctx.opsStorage.collection<McpPermGroupRecord>('mcp:permGroups')
  }

  calls(): Collection<McpCallRecord> {
    return this.ctx.opsStorage.collection<McpCallRecord>('mcp:calls')
  }

  /**
   * Accès au service d'enregistrement des risques (W1/V11). La liste inject de console ne contient pas mcpToolRisks — sous l'injection stricte cordis,
   * l'accès inter-fiber à une clé non déclarée est bloqué (cannot get property without inject) ; la face REST passe donc uniformément par cette méthode
   * (accès structuré, assemblage direct dans le apply du même plugin, sans nouvelle déclaration de dépendance console) ; l'invoke() de la passerelle passe par la même référence.
   */
  riskRegistry(): McpToolRiskRegistry | undefined {
    return this.riskRegistryRef
  }

  /** Connexion directe au service d'enregistrement des risques lors de l'assemblage apply() (pas de dépendance circulaire dans le plugin : le service d'enregistrement ne lit en retour que la collection services()). */
  attachRiskRegistry(registry: McpToolRiskRegistry): void {
    this.riskRegistryRef = registry
  }

  /**
   * Accès au Secret Broker (W1-T2 §6) : même accès structuré que riskRegistry() — la liste inject de console
   * ne contient pas secretBroker ; sous l'injection stricte cordis, l'accès direct inter-fiber à ctx.secretBroker est bloqué (without inject),
   * la face REST passe uniformément par cette méthode.
   */
  secretBroker(): SecretBroker | undefined {
    return this.secretBrokerRef
  }

  /** Connexion directe au Secret Broker lors de l'assemblage apply() (resolveCallHeaders de la passerelle et la face identifiants REST partagent la même instance). */
  attachSecretBroker(broker: SecretBroker): void {
    this.secretBrokerRef = broker
  }

  // -- Enregistrement et déploiement ---------------------------------------------------------

  createService(input: {
    name: string
    slug?: string
    description?: string
    icon?: string
    /** Catégorie métier (référentiel unifié des panneaux d'actifs) ; valeur illégale/défaut normalisée en « autre ». */
    category?: string
    endpoint?: string
    transport?: McpServiceRecord['transport']
    mode?: McpServiceRecord['mode']
    orgId: string
    owner: string
    tools?: McpToolSpec[]
    headers?: Record<string, string>
    stability?: number
    /** La couche d'exécution simulée n'est utilisée que si demo est explicitement déclaré ; sinon toujours real (conception écosystème v1.2 étape 0). */
    exec?: 'real' | 'demo'
    /** Marque de source de pontage du plan de données M0 (open-connector, etc.), la console affiche le badge « transition par pont ». */
    bridgeFrom?: string
    /** Champs de gouvernance (contrat §5, paramètres optionnels ; valeurs par défaut voir l'insert ci-dessous — les enregistrements existants sont rattrapés par la migration au démarrage). */
    ownerEntity?: McpOwnerEntity
    capabilityId?: string
    exposureMode?: McpExposureMode
    dataClass?: McpDataClass
    environment?: McpEnvironment
    visibility?: McpVisibility
    /** Référence d'identifiants aval (forme local:/env: ; la valeur vit dans SecretBroker, jamais dans le présent enregistrement). */
    credentialRef?: string
  }): McpServiceRecord {
    if (!input.name?.trim()) throw new Error(t('服务名称不能为空'))
    const slug = input.slug ?? input.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
    if (this.services().findOne((item) => item.slug === slug)) throw new Error(t('服务标识已存在：{slug}', { slug }))
    // Validation des énumérations des champs de gouvernance (contrat §5) : valeur illégale = erreur explicite
    const governance = normalizeGovernanceInput(input)
    if (input.mode !== 'external' && !input.endpoint) input.endpoint = `mcp+${input.transport ?? 'http'}://platform-hosted/${slug}`
    const toolSpecs = input.tools?.length ? input.tools : defaultToolsFor(slug)
    return this.services().insert({
      id: newId('mcp'),
      name: input.name,
      slug,
      description: input.description ?? '',
      icon: input.icon ?? 'mcp',
      category: normalizeAssetCategory(input.category),
      endpoint: input.endpoint ?? '',
      transport: input.transport ?? 'http',
      mode: input.mode ?? 'hosted',
      ...(input.headers ? { headers: input.headers } : {}),
      orgId: input.orgId,
      owner: input.owner,
      // Les valeurs par défaut du contrat §5 sont complétées une fois côté écriture (résumé de gouvernance/migration jugent sur la présence des champs, sans dépendre d'un repli à la lecture)
      ownerEntity: governance.ownerEntity ?? { type: 'platform' },
      exposureMode: governance.exposureMode ?? 'gateway',
      dataClass: governance.dataClass ?? 'internal',
      environment: governance.environment ?? 'prod',
      visibility: governance.visibility ?? 'org',
      ...(input.capabilityId ? { capabilityId: input.capabilityId } : {}),
      ...(input.credentialRef ? { credentialRef: input.credentialRef } : {}),
      status: 'draft',
      grayPercent: 0,
      currentVersion: '0.1.0',
      versions: [],
      tools: toolSpecs,
      health: { status: 'unknown', consecutiveFails: 0, breakerOpen: false },
      stability: input.stability ?? 0.97,
      rateLimitPerMin: 60,
      exec: input.exec ?? 'real',
      ...(input.bridgeFrom ? { bridgeFrom: input.bridgeFrom } : {}),
    })
  }

  /** Champs modifiables directement par un PATCH générique (la propriété de gouvernance ownerEntity en est exclue — passe par l'endpoint dédié d'assignation avec validation de ressource). */
  private static readonly UPDATABLE_KEYS = [
    'name', 'description', 'icon', 'endpoint', 'tools', 'headers', 'rateLimitPerMin', 'category',
  ] as const

  updateService(id: string, patch: Partial<Pick<McpServiceRecord,
    'name' | 'description' | 'icon' | 'endpoint' | 'tools' | 'headers' | 'rateLimitPerMin' | 'category'
    | 'capabilityId' | 'exposureMode' | 'dataClass' | 'environment' | 'visibility' | 'credentialRef'
  >>): McpServiceRecord {
    const service = this.requireService(id)
    if (service.status === 'online' && patch.tools) {
      throw new Error(t('在线服务修改 Tool Schema 需先灰度新版本（版本不可变原则）'))
    }
    // Validation des énumérations des champs de gouvernance (contrat §5) ; convergence en liste blanche des clés écrites — sous le comportement historique du PATCH REST
    // transmettant le body brut, des clés inconnues seraient écrites aveuglément ; les champs de gouvernance doivent passer par le chemin validé (ownerEntity par endpoint dédié, contre le contournement de la validation de ressource)
    const governance = normalizeGovernanceInput(patch)
    const next: Record<string, unknown> = {}
    for (const key of McpService.UPDATABLE_KEYS) {
      if (patch[key] !== undefined) next[key] = patch[key]
    }
    if (next['category'] !== undefined) next['category'] = normalizeAssetCategory(next['category'])
    for (const [key, value] of Object.entries(governance)) next[key] = value
    if (patch.capabilityId !== undefined) next.capabilityId = patch.capabilityId
    if (patch.credentialRef !== undefined) next.credentialRef = patch.credentialRef
    return this.services().update(id, next as Partial<McpServiceRecord>)
  }

  // -- Gouvernance : assignation de propriété / dette de gouvernance / migration des préexistants (W1-T2, contrat §5) --------------------------------

  /**
   * Assignation de propriété : simple validation de forme et écriture ; la validation d'existence des ressources type=app/agent est faite dans la couche REST
   * via resourceCore (plugin-mcp ne dépend pas de resource-core, surface d'assemblage minimale).
   */
  setOwnerEntity(id: string, ownerEntity: McpOwnerEntity): McpServiceRecord {
    const normalized = normalizeGovernanceInput({ ownerEntity })
    return this.services().update(id, { ownerEntity: normalized.ownerEntity! })
  }

  /** Résumé de dette de gouvernance (lecture seule, contrat §5) : trois classes unowned / en-têtes sensibles en clair / exposition non gateway + volume total. */
  governanceSummary(): {
    unowned: Array<{ serviceId: string; serviceName: string; reason: string }>
    plainHeaderServices: Array<{ serviceId: string; serviceName: string; keys: string[] }>
    nonGateway: Array<{ serviceId: string; serviceName: string; exposureMode: string }>
    totals: { services: number; unowned: number; plainHeader: number; nonGateway: number }
  } {
    const services = this.services().all()
    const unowned = services
      .filter((service) => !service.ownerEntity || service.ownerEntity.type === 'platform' || !service.ownerEntity.id)
      .map((service) => ({
        serviceId: service.id,
        serviceName: service.name,
        reason: !service.ownerEntity || service.ownerEntity.type === 'platform'
          ? t('归属未指派（platform 占位，待能力绑定/指派）')
          : t('ownerEntity.type={type} 缺少资源 id', { type: service.ownerEntity.type }),
      }))
    const plainHeaderServices = services
      .map((service) => ({ service, keys: sensitiveHeaderKeys(service.headers) }))
      .filter((item) => item.keys.length > 0)
      .map(({ service, keys }) => ({ serviceId: service.id, serviceName: service.name, keys }))
    const nonGateway = services
      .filter((service) => (service.exposureMode ?? 'gateway') !== 'gateway')
      .map((service) => ({ serviceId: service.id, serviceName: service.name, exposureMode: service.exposureMode ?? 'gateway' }))
    return {
      unowned,
      plainHeaderServices,
      nonGateway,
      totals: {
        services: services.length,
        unowned: unowned.length,
        plainHeader: plainHeaderServices.length,
        nonGateway: nonGateway.length,
      },
    }
  }

  /**
   * Migration idempotente au démarrage (sur le modèle d'iam ensureConnectorPermissionsMigration) : complète les enregistrements de services existants
   * avec les valeurs par défaut de gouvernance (compléter les manques, jamais supprimer/modifier) ; la marque de migration entre dans la collection mcp:migrations pour observation.
   * Re-exécutable à chaque démarrage : zéro écriture pour les enregistrements déjà complets ; le marqueur n'est qu'observation, ne bloque pas la re-exécution.
   */
  ensureGovernanceMigration(): { applied: boolean; touched: string[] } {
    const collection = this.ctx.opsStorage.collection<RecordBase & { key: string; note?: string }>('mcp:migrations')
    const marker = collection.findOne((item) => item.key === 'mcp-governance-v1')
    const touched: string[] = []
    for (const service of this.services().all()) {
      const patch: Partial<McpServiceRecord> = {}
      if (!service.ownerEntity) patch.ownerEntity = { type: 'platform' }
      if (!service.exposureMode) patch.exposureMode = 'gateway'
      if (!service.dataClass) patch.dataClass = 'internal'
      if (!service.environment) patch.environment = 'prod'
      if (!service.visibility) patch.visibility = 'org'
      if (Object.keys(patch).length === 0) continue
      this.services().update(service.id, patch)
      touched.push(service.id)
    }
    if (!marker) {
      collection.insert({
        id: newId('mig'),
        key: 'mcp-governance-v1',
        ...(touched.length > 0 ? { note: t('存量服务补治理默认值 ×{count}', { count: touched.length }) } : {}),
      })
    }
    return { applied: marker === undefined || touched.length > 0, touched }
  }

  /**
   * Migration des en-têtes sensibles en clair (contrat §6) : scanne les clés sensibles des headers de tous les services (même référentiel que maskServiceHeaders) →
   * rapport de pré-vérification dryRun ; sinon, service par service, migre les clés sensibles dans SecretBroker (headerName prend le nom de la clé),
   * supprime les clés sensibles de service.headers, réécrit credentialRef. Le clair préexistant ne sort que sous cette action explicite,
   * la migration au démarrage (ensureGovernanceMigration) ne supprime jamais les headers existants.
   */
  migratePlainHeaders(options: { dryRun?: boolean } = {}): {
    dryRun: boolean
    candidates: Array<{ serviceId: string; serviceName: string; keys: string[] }>
    migrated: number
  } {
    const candidates = this.services().all()
      .map((service) => ({ service, keys: sensitiveHeaderKeys(service.headers) }))
      .filter((item) => item.keys.length > 0)
      .map(({ service, keys }) => ({ serviceId: service.id, serviceName: service.name, keys }))
    if (options.dryRun) return { dryRun: true, candidates, migrated: 0 }
    const broker = this.secretBrokerRef
    if (!broker) throw new Error(t('Secret Broker 未装配，无法迁移明文凭证头'))
    for (const item of candidates) {
      const service = this.requireService(item.serviceId)
      for (const key of item.keys) {
        const value = service.headers?.[key]
        if (value) broker.put({ serviceId: service.id, headerName: key, secret: value })
      }
      const description = broker.describe(service.id)
      const remaining: Record<string, string> = { ...(service.headers ?? {}) }
      for (const key of item.keys) delete remaining[key]
      this.services().update(service.id, {
        headers: Object.keys(remaining).length > 0 ? remaining : undefined,
        ...(description?.credentialRef ? { credentialRef: description.credentialRef } : {}),
      })
    }
    return { dryRun: false, candidates, migrated: candidates.length }
  }

  /** Connecte le service MCP distant pour tirer la liste d'outils (initialize → tools/list) ; partagé par import et synchronisation. */
  async listRemoteTools(endpoint: string, headers?: Record<string, string>): Promise<McpToolSpec[]> {
    const sessionId = await this.ensureSession(endpoint, headers)
    const { payload } = await this.mcpRequest(endpoint, headers, {
      jsonrpc: '2.0',
      id: `dsh-list-${Date.now()}`,
      method: 'tools/list',
      params: {},
    }, REAL_TRANSPORT_TIMEOUT_MS, sessionId)
    if (payload?.error) throw new Error(t('tools/list 失败：{reason}', { reason: payload.error.message ?? t('未知错误') }))
    const tools = Array.isArray(payload?.result?.tools) ? payload.result.tools : []
    return tools
      .map((tool: { name?: unknown; description?: unknown; inputSchema?: unknown }) => ({
        name: String(tool.name ?? ''),
        description: String(tool.description ?? ''),
        inputSchema: tool.inputSchema && typeof tool.inputSchema === 'object' && !Array.isArray(tool.inputSchema)
          ? tool.inputSchema as Record<string, unknown>
          : { type: 'object', properties: {} },
        // Cœur de la correction V11 : tools/list distant ne se mappe plus implicitement à read — la liste distante ne peut pas prouver le risque,
        // tout tombe en 'unknown' en comptabilité ; une capacité d'écriture ne passe qu'après approbation de l'enregistrement de risque (mcpToolRisks).
        riskLevel: 'unknown' as const,
      }))
      .filter((tool: McpToolSpec) => tool.name)
  }

  /**
   * Synchronisation des outils d'un service externe : rafraîchit la liste locale en prenant tools/list distant pour référence.
   * Contourne la validation d'immuabilité de version d'updateService — la liste d'outils d'un service externe est l'image synchronisée d'un fait distant,
   * pas un changement de version côté plateforme (le processus de version continue de concerner les services gérés).
   */
  async syncTools(serviceId: string): Promise<McpServiceRecord> {
    const service = this.requireService(serviceId)
    if (service.mode !== 'external') throw new Error(t('仅外部注册服务支持工具同步'))
    if (service.exec !== 'real') throw new Error(t('演示传输层服务不支持工具同步'))
    // Point d'injection W1-T2 §6 : avant transmission, les en-têtes d'identifiants sont assemblés via SecretBroker (les headers préexistants non sensibles inchangés)
    const tools = await this.listRemoteTools(service.endpoint, await this.resolveCallHeaders(service))
    if (!tools.length) throw new Error(t('远端服务未返回任何工具'))
    const updated = this.services().update(serviceId, { tools })
    this.noteBusinessSuccess(updated)
    return updated
  }

  /**
   * Import en un clic d'un JSON mcpServers (forme de configuration en vigueur chez Claude Desktop / Cursor / Cherry Studio, etc.) :
   * analyse → enregistrement des services externes (exec=real) → initialize+tools/list découverte automatique → (optionnel) validation et mise en ligne.
   * L'échec d'une entrée n'arrête pas les autres ; injoignable = conserve le brouillon et renvoie la raison.
   */
  async importServices(input: { config: string | object; orgId: string; owner: string; autoDeploy?: boolean }): Promise<{
    imported: number
    results: McpImportResult[]
  }> {
    const entries = parseMcpServersConfig(input.config)
    const results: McpImportResult[] = []
    for (const entry of entries) {
      if (entry.error) {
        results.push({ name: entry.name, ok: false, error: entry.error })
        continue
      }
      try {
        const entryHeaders = entry.headers ?? {}
        const bridgedFrom = Object.entries(entryHeaders)
          .find(([key]) => key.toLowerCase() === 'x-bridged-from')?.[1]
        // Gouvernance W1 (contrat §6, arbitrage CTO 2026-10-22) : l'entrée d'import entre automatiquement au coffre — les clés/valeurs sensibles ne tombent pas
        // dans les collections métier, elles passent par l'enregistrement SecretBroker (l'enregistrement du service ne garde que les en-têtes non sensibles + credentialRef).
        // Différent de la barrière 400 de create/PATCH : l'import est le plus souvent un flux machine de pontage de connecteur, un refus casserait la chaîne,
        // d'où la sémantique « importer = migrer » ; SecretBroker non assemblé = repli sur le comportement clair historique (compatibilité dégradée).
        const plainKeys = sensitiveHeaderKeys(entryHeaders)
        const keptHeaders = plainKeys.length > 0
          ? Object.fromEntries(Object.entries(entryHeaders).filter(([key]) => !plainKeys.includes(key)))
          : entryHeaders
        let brokered = false
        const service = this.createService({
          name: entry.name,
          endpoint: entry.url,
          transport: entry.transport,
          mode: 'external',
          exec: 'real',
          orgId: input.orgId,
          owner: input.owner,
          ...(Object.keys(keptHeaders).length > 0 ? { headers: keptHeaders } : {}),
          // Marque de pontage du plan de données M0 : les services MCP importés par la passerelle du connecteur portent le badge de dégradation de gouvernance (§2.11)
          ...(bridgedFrom ? { bridgeFrom: String(bridgedFrom) } : {}),
          ...(entry.description ? { description: entry.description } : {}),
          tools: [],
        })
        if (plainKeys.length > 0 && this.secretBrokerRef) {
          for (const key of plainKeys) {
            this.secretBrokerRef.put({ serviceId: service.id, credentialRef: 'local:', headerName: key, secret: entryHeaders[key] })
          }
          this.services().update(service.id, { credentialRef: 'local:' })
          brokered = true
        }
        let tools: McpToolSpec[] = []
        let reachable = false
        let message = ''
        try {
          // Point d'injection W1-T2 §6 : la découverte automatique assemble aussi les en-têtes d'identifiants via SecretBroker (un nouveau service n'a généralement pas d'enregistrement à cet instant, miss = repli)
          tools = await this.listRemoteTools(service.endpoint, await this.resolveCallHeaders(service))
          reachable = true
        } catch (error) {
          message = t('工具自动发现失败：{reason}', { reason: error instanceof Error ? error.message : String(error) })
        }
        this.services().update(service.id, {
          // Injoignable : vide le trio par défaut, pour éviter qu'une fausse liste d'outils entre dans les groupes de permissions
          ...(reachable ? { tools } : { tools: [] as McpToolSpec[] }),
          health: { lastProbeAt: now(), status: reachable ? 'healthy' : 'unknown', latencyMs: 0, consecutiveFails: 0, breakerOpen: false },
        })
        let status = service.status
        if (reachable && input.autoDeploy !== false) {
          try {
            await this.verifyService(service.id)
            const deployed = await this.deployService(service.id, { grayPercent: 100, changelog: 'mcpServers 配置导入自动发布', actor: input.owner })
            status = deployed.status
          } catch (error) {
            message = `${message ? `${message}；` : ''}${t('自动发布失败：{reason}', { reason: error instanceof Error ? error.message : String(error) })}`
          }
        }
        results.push({
          name: entry.name, ok: true, slug: service.slug, serviceId: service.id,
          tools: tools.length, reachable, status,
          ...(brokered ? { brokered: true } : {}),
          ...(message ? { error: message } : {}),
        })
      } catch (error) {
        results.push({ name: entry.name, ok: false, error: error instanceof Error ? error.message : String(error) })
      }
    }
    return { imported: results.filter((item) => item.ok).length, results }
  }

  /** Validation d'environnement de test : un service real fait une vraie sonde initialize ; un service demo simule la sonde. */
  async verifyService(id: string): Promise<McpServiceRecord> {
    const service = this.requireService(id)
    if (service.status !== 'draft') throw new Error(t('仅草稿状态可执行测试验证'))
    this.services().update(id, { status: 'verifying' })
    const latency = service.exec === 'real' ? await this.realProbe(service) : 200
    if (latency < 0) {
      this.services().update(id, { status: 'draft' })
      throw new Error(t('测试验证失败：endpoint {endpoint} 不可达', { endpoint: service.endpoint }))
    }
    return this.services().update(id, { health: { lastProbeAt: now(), status: 'healthy', latencyMs: latency, consecutiveFails: 0, breakerOpen: false } })
  }

  /** Publication en ligne (pourcentage de gradation optionnel), enregistre la version. */
  async deployService(id: string, options: { grayPercent?: number; version?: string; changelog?: string; actor: string }): Promise<McpServiceRecord> {
    const service = this.requireService(id)
    if (!['draft', 'verifying', 'gray', 'online', 'unhealthy'].includes(service.status)) {
      throw new Error(t('当前状态 {status} 不允许发布', { status: service.status }))
    }
    const version = options.version ?? bumpVersion(service.currentVersion)
    const gray = Math.min(100, Math.max(0, options.grayPercent ?? 100))
    await sleep(200)
    const updated = this.services().update(id, {
      status: gray >= 100 ? 'online' : 'gray',
      grayPercent: gray,
      currentVersion: version,
      versions: [
        ...service.versions.map((item) => ({ ...item, status: item.status === 'current' ? 'previous' : item.status })),
        { version, changelog: options.changelog ?? t('例行更新'), publishedAt: now(), status: 'current' },
      ],
      health: { ...service.health, status: 'healthy', consecutiveFails: 0, breakerOpen: false },
    })
    this.ctx.platformBus.emit(PlatformEvents.McpDeployed, {
      serviceId: id, name: updated.name, version, grayPercent: gray, actor: options.actor, type: 'mcp_service', slug: updated.slug,
    })
    return updated
  }

  async rollbackService(id: string, targetVersion: string, actor: string): Promise<McpServiceRecord> {
    const service = this.requireService(id)
    const target = service.versions.find((item) => item.version === targetVersion)
    if (!target) throw new Error(t('目标版本不存在：{version}', { version: targetVersion }))
    if (target.status === 'current') throw new Error(t('目标版本 {version} 即当前版本，无需回滚', { version: targetVersion }))
    if (target.status === 'rolled-back') throw new Error(t('目标版本 {version} 已被回滚过，不允许作为回滚目标（版本不可变原则）', { version: targetVersion }))
    const updated = this.services().update(id, {
      currentVersion: targetVersion,
      versions: service.versions.map((item) => ({
        ...item,
        status: item.version === targetVersion ? 'current' : item.status === 'current' ? 'rolled-back' : item.status,
      })),
    })
    this.ctx.platformBus.emit(PlatformEvents.McpDeployed, {
      serviceId: id, name: updated.name, version: targetVersion, rollback: true, actor, type: 'mcp_service', slug: updated.slug,
    })
    return updated
  }

  offlineService(id: string, actor: string, reason: string): McpServiceRecord {
    const service = this.requireService(id)
    if (service.status === 'offline') throw new Error(t('服务已是下线状态'))
    const updated = this.services().update(id, { status: 'offline', grayPercent: 0 })
    this.ctx.platformBus.emit(PlatformEvents.McpOfflined, { serviceId: id, name: updated.name, actor, reason, type: 'mcp_service', slug: updated.slug })
    return updated
  }

  /** La mise hors ligne L4 passe par l'approbation : crée la fiche, exécution automatique après approbation. */
  requestOfflineApproval(id: string, requester: { id: string; name: string }, reason: string, impactPreview: string[]) {
    return this.ctx.audit.createApproval({
      kind: 'mcp.offline',
      // WP-10/L1 (QA A-06) : L4 haut risque unifié — l'approbation exige double confirmation + marqueur de revue finale société
      riskLevel: 'high',
      title: t('下线 MCP 服务：{name}', { name: this.requireService(id).name }),
      payload: { serviceId: id, reason, impactPreview },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  /** Nettoyage des liaisons après suppression : sessions distantes et caches de limitation, fichiers de clés du Broker supprimés ensemble ; détails d'appels et données d'audit conservés. */
  purgeService(id: string): void {
    const service = this.requireService(id)
    this.mcpSessions.delete(service.endpoint)
    for (const key of [...this.rateBuckets.keys()]) {
      if (key.startsWith(`${id}:`)) this.rateBuckets.delete(key)
    }
    // W1-T2 §6 : la suppression du service efface en cascade le fichier d'identifiants aval (pas de clé orpheline)
    try {
      this.secretBrokerRef?.delete(id)
    } catch { /* scénarios comme l'hôte de test unitaire sans répertoire de données : n'interrompt pas le flux principal de suppression */ }
    this.services().remove(id)
  }

  // -- Sondage de santé -----------------------------------------------------------

  async probeService(id: string): Promise<{ status: string; latencyMs: number }> {
    const service = this.requireService(id)
    if (service.status === 'offline' || service.status === 'draft') {
      return { status: 'unknown', latencyMs: 0 }
    }
    // real : vraie sonde HTTP (POST initialize, mesure aller-retour et latence) ; demo (y compris préexistants sans marque) : simulation déterministe
    let latency: number
    if (service.exec === 'real') {
      latency = await this.realProbe(service)
    } else {
      latency = probeLatency(service)
    }
    const ok = latency > 0
    const fails = ok ? 0 : service.health.consecutiveFails + 1
    const breakerOpen = fails >= 3
    const status = ok ? (latency > 800 ? 'degraded' : 'healthy') : 'down'
    const update: McpServiceRecord = this.services().update(id, {
      health: { lastProbeAt: now(), status, latencyMs: Math.max(0, latency), consecutiveFails: fails, breakerOpen },
      ...(breakerOpen && service.status !== 'unhealthy' ? { status: 'unhealthy' } : {}),
      ...(ok && service.status === 'unhealthy' ? { status: service.grayPercent >= 100 ? 'online' : 'gray' } : {}),
    })
    if (breakerOpen && service.status !== 'unhealthy') {
      this.ctx.platformBus.emit(PlatformEvents.McpUnhealthy, {
        serviceId: id, name: service.name, consecutiveFails: fails, latencyMs: latency,
      })
    }
    return { status: update.health.status, latencyMs: latency }
  }

  private async probeAll(): Promise<void> {
    for (const service of this.services().all()) {
      if (service.status === 'offline' || service.status === 'draft') continue
      try {
        await this.probeService(service.id)
      } catch (error) {
        this.ctx.logger('mcp').warn('探活失败', service.id, error)
      }
    }
  }

  /** L'échec métier compte dans le disjoncteur : l'échec d'appel réel et l'échec de sondage partagent le compteur d'échecs consécutifs (3 consécutifs = disjoncteur ouvert). */
  private noteBusinessFailure(service: McpServiceRecord, reason: string): void {
    const fails = service.health.consecutiveFails + 1
    const breakerOpen = fails >= 3
    this.services().update(service.id, {
      health: { ...service.health, lastProbeAt: now(), status: breakerOpen ? 'down' : 'degraded', consecutiveFails: fails, breakerOpen },
      ...(breakerOpen && service.status !== 'unhealthy' ? { status: 'unhealthy' } : {}),
    })
    if (breakerOpen && service.status !== 'unhealthy') {
      this.ctx.platformBus.emit(PlatformEvents.McpUnhealthy, {
        serviceId: service.id, name: service.name, consecutiveFails: fails, latencyMs: 0,
        reason: t('业务调用连续失败 {fails} 次：{reason}', { fails, reason }),
      })
    }
  }

  /** Un succès métier referme à moitié : remet le compteur d'échecs à zéro, lève le disjoncteur (le sondage suivant revérifie quand même). */
  private noteBusinessSuccess(service: McpServiceRecord): void {
    if (service.health.consecutiveFails === 0 && !service.health.breakerOpen) return
    this.services().update(service.id, {
      health: { ...service.health, status: 'healthy', consecutiveFails: 0, breakerOpen: false },
      ...(service.status === 'unhealthy' ? { status: service.grayPercent >= 100 ? 'online' : 'gray' } : {}),
    })
  }

  async healthCheck(id: string): Promise<{ status: string; latencyMs: number }> {
    return this.probeService(id)
  }

  /** Vraie sonde de santé : poignée de main MCP initialize, renvoie la latence (ms) ; échec = -1. */
  private async realProbe(service: McpServiceRecord): Promise<number> {
    const started = Date.now()
    try {
      // Point d'injection W1-T2 §6 : le sondage et l'appel partagent la même source d'identifiants (assemblés par SecretBroker, headers préexistants inchangés) ;
      // W3-T5 §14 : le sondage est une source périodique de bruit (service longue durée ~3k/jour/service), les traces d'accès sont dédupliquées par fenêtre
      const { payload } = await this.mcpRequest(service.endpoint, await this.resolveCallHeaders(service, { dedupKey: 'probe' }), {
        jsonrpc: '2.0',
        id: `probe-${Date.now()}`,
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'dsh-ops-probe', version: '1.0' } },
      }, REAL_PROBE_TIMEOUT_MS)
      if (payload?.error) return -1
      return Date.now() - started
    } catch {
      return -1
    }
  }

  /**
   * Socle de requête MCP streamable HTTP : un POST JSON-RPC unique, compatible avec deux formes de réponse — JSON pur et
   * flux SSE (text/event-stream, prend la première trame data) ; transmet les en-têtes personnalisés du service (ex. Authorization),
   * renvoie le Mcp-Session-Id délivré par le serveur pour que les services avec état le réutilisent.
   */
  private async mcpRequest(endpoint: string, headers: Record<string, string> | undefined, message: Record<string, unknown>, timeoutMs: number, sessionId?: string): Promise<{ payload: any; sessionId?: string; status?: number }> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
          ...(headers ?? {}),
        },
        body: JSON.stringify(message),
        signal: controller.signal,
      })
      if (!response.ok) {
        throw new Error(t('MCP 服务 HTTP {status}：{body}', { status: response.status, body: (await response.text().catch(() => '')).slice(0, 200) }))
      }
      // Statut HTTP amont (source du renseignement upstreamStatus W3-T5 §14 ; additive, appelants existants insensibles)
      const status = response.status
      const sessionIdHeader = response.headers.get('mcp-session-id') ?? undefined
      const contentType = String(response.headers.get('content-type') ?? '')
      const text = await response.text()
      if (contentType.includes('text/event-stream')) {
        for (const line of text.split('\n')) {
          if (!line.startsWith('data:')) continue
          const frame = line.slice(5).trim()
          if (!frame || frame === '[DONE]') continue
          try { return { payload: JSON.parse(frame), sessionId: sessionIdHeader, status } } catch { /* ignore les trames non JSON */ }
        }
        throw new Error(t('MCP 服务 SSE 响应中未找到 JSON-RPC 帧'))
      }
      if (!text) return { payload: null, sessionId: sessionIdHeader, status } // réponse à corps vide type 202 Accepted (messages de notification)
      try {
        return { payload: JSON.parse(text), sessionId: sessionIdHeader, status }
      } catch {
        throw new Error(t('MCP 服务响应不是合法 JSON：{body}', { body: text.slice(0, 200) }))
      }
    } finally {
      clearTimeout(timer)
    }
  }

  /** Établit la session distante : poignée de main initialize et mise en cache du sessionId (service sans état cache '', évite de refaire la poignée à chaque fois). */
  private async ensureSession(endpoint: string, headers?: Record<string, string>): Promise<string | undefined> {
    const cached = this.mcpSessions.get(endpoint)
    if (cached && cached.expiresAt > Date.now()) return cached.sessionId || undefined
    const { payload, sessionId } = await this.mcpRequest(endpoint, headers, {
      jsonrpc: '2.0',
      id: `dsh-init-${Date.now()}`,
      method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'dsh-ops-gateway', version: '1.0' } },
    }, REAL_PROBE_TIMEOUT_MS)
    if (payload?.error) throw new Error(t('initialize 失败：{reason}', { reason: payload.error.message ?? t('未知错误') }))
    const effective = sessionId ?? ''
    this.mcpSessions.set(endpoint, { sessionId: effective, expiresAt: Date.now() + MCP_SESSION_TTL_MS })
    if (effective) {
      // Un service avec état exige l'envoi de la notification initialized ; un service sans état l'ignore, un échec n'interrompt pas.
      await this.mcpRequest(endpoint, headers, { jsonrpc: '2.0', method: 'notifications/initialized' }, REAL_PROBE_TIMEOUT_MS, effective).catch(() => undefined)
    }
    return effective || undefined
  }

  // -- Groupes de permissions -------------------------------------------------------------

  createPermGroup(input: {
    name: string
    description?: string
    policies: Record<string, ToolPolicy>
    subjects: McpPermGroupRecord['subjects']
  }): McpPermGroupRecord {
    if (!input.name?.trim()) throw new Error(t('权限组名称不能为空'))
    if (this.permGroups().findOne((group) => group.name === input.name)) throw new Error(t('权限组已存在：{name}', { name: input.name }))
    for (const serviceId of Object.keys(input.policies)) {
      this.requireService(serviceId)
    }
    return this.permGroups().insert({
      id: newId('mpg'),
      name: input.name,
      description: input.description ?? '',
      policies: input.policies,
      subjects: input.subjects,
    })
  }

  updatePermGroup(id: string, patch: Partial<Pick<McpPermGroupRecord, 'name' | 'description' | 'policies' | 'subjects'>>): McpPermGroupRecord {
    return this.permGroups().update(id, patch)
  }

  deletePermGroup(id: string): boolean {
    return this.permGroups().remove(id)
  }

  /** Accorde l'accès à un principal : l'ajoute au groupe de permissions. */
  grantSubject(groupId: string, subject: McpPermGroupRecord['subjects'][number]): McpPermGroupRecord {
    const group = this.permGroups().get(groupId)
    if (!group) throw new Error(t('权限组不存在：{id}', { id: groupId }))
    if (group.subjects.some((item) => item.type === subject.type && item.id === subject.id)) return group
    return this.permGroups().update(groupId, { subjects: [...group.subjects, subject] })
  }

  // -- Gabarit de scope de limitation de ressource / simulation de politique (W3-T5, contrats §12/§14) ---------------------------------

  /**
   * Gabarit de scope (contrat §12) : génère depuis les policies du groupe de permissions un jeu de scopes de limitation de ressource suggérés —
   *   - allowedTools='*' (tout le service) → suggère le scope service `mcp.service:<slug>.invoke` ;
   *   - allowedTools en liste blanche → par outil `mcp.tool:<slug>:<tool>.invoke` (un groupe readOnly ne produit pas
   *     de scope pour les outils write/admin, le gabarit et la face d'arbitrage jugent pareil) ; références de service inexistant/d'outil hors liste sautées.
   * Sémantique dry : dérivation en lecture seule, pas d'écriture ni d'effet de bord ; consommé par la console (W3-T6) et « toute nouvelle autorisation produit par défaut un gabarit de scope ».
   */
  scopeTemplate(groupId: string): {
    scopes: string[]
    byService: Array<{ serviceId: string; slug: string; scopes: string[] }>
  } {
    const group = this.permGroups().get(groupId)
    if (!group) throw new Error(t('权限组不存在：{id}', { id: groupId }))
    const byService: Array<{ serviceId: string; slug: string; scopes: string[] }> = []
    const all = new Set<string>()
    for (const [serviceId, policy] of Object.entries(group.policies)) {
      const service = this.services().get(serviceId)
      if (!service) continue
      const scopes: string[] = []
      if (policy.allowedTools === '*') {
        scopes.push(`mcp.service:${service.slug}.invoke`)
      } else {
        for (const toolName of policy.allowedTools) {
          const tool = service.tools.find((item) => item.name === toolName)
          if (!tool) continue
          // Groupe à contrainte lecture seule : pas de scope pour les outils write/admin (gabarit = référentiel de la face d'arbitrage, pour éviter qu'un gabarit induise en erreur par excès)
          if (policy.constraints.readOnly && (tool.riskLevel === 'write' || tool.riskLevel === 'admin')) continue
          scopes.push(`mcp.tool:${service.slug}:${tool.name}.invoke`)
        }
      }
      if (scopes.length === 0) continue
      for (const scope of scopes) all.add(scope)
      byService.push({ serviceId, slug: service.slug, scopes })
    }
    return { scopes: [...all], byService }
  }

  /**
   * Simulation de politique / analyse d'impact (contrat §14) : body = brouillon intégral de groupe de permissions, sans écriture — rapport d'impact en quatre dimensions :
   *   - newServices : services couverts par policies (référence de service inexistant sautée) ;
   *   - writeTools : outils riskLevel write/admin atteints par allowedTools dans les services couverts ;
   *   - confidential : services dataClass=confidential parmi les couverts ;
   *   - crossOrg : org du service et org atteignable par subjects tous deux connus et divergents (user_group étendu via les membres,
   *     agent/app via le rattachement resourceCore ; org manquant = indécidable → non compté) ;
   *   - affectedSubjects : subjects étendus tels quels.
   */
  dryRunPermGroup(draft: {
    name?: string
    policies?: Record<string, ToolPolicy>
    subjects?: McpPermGroupRecord['subjects']
  }): {
    newServices: Array<{ serviceId: string; slug: string; name: string }>
    writeTools: Array<{ serviceId: string; slug: string; tool: string }>
    confidential: Array<{ serviceId: string; slug: string; dataClass: string }>
    crossOrg: boolean
    affectedSubjects: McpPermGroupRecord['subjects']
  } {
    const policies = draft.policies ?? {}
    const subjects = draft.subjects ?? []
    const newServices: Array<{ serviceId: string; slug: string; name: string }> = []
    const writeTools: Array<{ serviceId: string; slug: string; tool: string }> = []
    const confidential: Array<{ serviceId: string; slug: string; dataClass: string }> = []
    const serviceOrgs = new Set<string>()
    for (const [serviceId, policy] of Object.entries(policies)) {
      const service = this.services().get(serviceId)
      if (!service) continue
      newServices.push({ serviceId, slug: service.slug, name: service.name })
      if (service.orgId) serviceOrgs.add(service.orgId)
      if ((service.dataClass ?? 'internal') === 'confidential') {
        confidential.push({ serviceId, slug: service.slug, dataClass: service.dataClass })
      }
      for (const tool of service.tools) {
        if (tool.riskLevel !== 'write' && tool.riskLevel !== 'admin') continue
        const granted = policy.allowedTools === '*' || policy.allowedTools.includes(tool.name)
        if (granted) writeTools.push({ serviceId, slug: service.slug, tool: tool.name })
      }
    }
    // Organisations atteignables par les sujets : une quelconque (org service × org sujet) connue et différente → crossOrg
    let crossOrg = false
    for (const subject of subjects) {
      const orgs = this.subjectReachableOrgs(subject)
      if (orgs.size === 0) continue
      for (const serviceOrg of serviceOrgs) {
        if (!orgs.has(serviceOrg)) crossOrg = true
      }
    }
    return { newServices, writeTools, confidential, crossOrg, affectedSubjects: subjects }
  }

  /** Ensemble d'organisations atteignables par les sujets (jugement crossOrg du dry-run) : user_group étendu via les membres iam ; agent/app via le rattachement resourceCore ; irrésoluble = ensemble vide (non compté). */
  private subjectReachableOrgs(subject: McpPermGroupRecord['subjects'][number]): Set<string> {
    const orgs = new Set<string>()
    try {
      if (subject.type === 'user_group') {
        for (const member of this.ctx.iam.resolveGroupMembers(subject.id)) {
          const orgId = (member as { orgId?: string }).orgId
            ?? (this.ctx.iam as { users?: () => { get: (id: string) => { orgId?: string } | undefined } }).users?.().get(member.id)?.orgId
          if (orgId) orgs.add(orgId)
        }
        return orgs
      }
      const core = (this.ctx as unknown as { resourceCore?: { get: (kind: string, id: string) => { orgId?: string } | undefined } }).resourceCore
      const orgId = core?.get(subject.type, subject.id)?.orgId
      if (orgId) orgs.add(orgId)
    } catch { /* échec d'analyse : ensemble vide (ce qui est indécidable n'est pas compté) */ }
    return orgs
  }

  /**
   * Appariement des sujets d'un groupe de permissions (extraction W2-T3 contrat §8) : renvoie toutes les politiques de services atteignant ce caller.
   * Trois classes de sujets : user_group (human résolu via les groupes iam) / agent / app ; en cas de groupes multiples atteints, decideTool
   * arbitre un à un dans l'ordre des grants (cohérent avec le comportement authorize existant, extraction et non copie).
   */
  private matchedPolicies(caller: InvokeCaller, serviceId: string): ToolPolicy[] {
    const grants: ToolPolicy[] = []
    // Ensemble de principaux appariables : caller.subjects (sujet + acteurs de la chaîne de délégation, additive) ; à défaut repli sur le sujet lui-même
    const subjectPool: Array<{ type: 'user' | 'agent' | 'app'; id: string }> = caller.subjects?.length
      ? caller.subjects
      : [{ type: caller.type, id: caller.id }]
    for (const group of this.permGroups().all()) {
      const policy = group.policies[serviceId]
      if (!policy) continue
      const hit = group.subjects.some((subject) => {
        if (subject.type === 'user_group') {
          // Sujet groupe d'utilisateurs : n'importe quelle personne réelle du pool atteinte comme membre du groupe = correspondance
          return subjectPool.some((candidate) => candidate.type === 'user'
            && this.ctx.iam.resolveGroupMembers(subject.id).some((user) => user.id === candidate.id))
        }
        return subjectPool.some((candidate) => subject.type === candidate.type && subject.id === candidate.id)
      })
      if (hit) grants.push(policy)
    }
    return grants
  }

  /**
   * Arbitrage d'outil isolé (extraction W2-T3 contrat §8) : authorize() et authorizedToolsFor() partagent le même jugement —
   * prend dans l'ordre des grants la première politique dont allowedTools atteint l'outil ; un contexte lecture seule intercepte write/admin.
   * Référentiel de contrainte lecture seule W1/V11 (même jugement que le port de politique de travail) : unknown passe en contexte lecture (un outil non enregistré y
   * est traité comme read — la capacité d'écriture est déjà couverte par la face de refus du contexte écrit, le risque résiduel est convergé par la liste de ré-examen reviewList,
   * plus de « inconnu = refus » blessant la consommation en lecture).
   */
  private decideTool(grants: ToolPolicy[], tool: McpToolSpec): { ok: true; readOnly: boolean } | { ok: false; reason: string } {
    for (const policy of grants) {
      const allowed = policy.allowedTools === '*' || policy.allowedTools.includes(tool.name)
      if (!allowed) continue
      if (policy.constraints.readOnly && (tool.riskLevel === 'write' || tool.riskLevel === 'admin')) {
        return { ok: false, reason: t('权限组约束为只读模式，工具 {tool}（{risk}）被拒绝', { tool: tool.name, risk: tool.riskLevel }) }
      }
      return { ok: true, readOnly: Boolean(policy.constraints.readOnly) }
    }
    return { ok: false, reason: t('工具 {tool} 不在授权列表中', { tool: tool.name }) }
  }

  /** Contrôle d'autorisation : renvoie le contexte de politique utilisable ou la raison du refus. */
  authorize(caller: InvokeCaller, serviceId: string, toolName: string): { ok: true; readOnly: boolean } | { ok: false; reason: string } {
    const service = this.requireService(serviceId)
    const tool = service.tools.find((item) => item.name === toolName)
    if (!tool) return { ok: false, reason: t('服务 {service} 不存在工具 {tool}', { service: service.name, tool: toolName }) }
    const grants = this.matchedPolicies(caller, serviceId)
    if (grants.length === 0) {
      return { ok: false, reason: t('主体 {name} 未被任何 MCP 权限组授权访问 {service}', { name: caller.name, service: service.name }) }
    }
    return this.decideTool(grants, tool)
  }

  /**
   * Ensemble d'outils appelables (nouvel export W2-T3 contrat §8) : liste des noms d'outils appelables sur ce service par l'identité courante —
   * appariement des sujets du groupe de permissions + intersection allowedTools + filtre readOnly retirant les outils write/admin, même source exacte que le jugement
   * d'outil isolé de authorize() (matchedPolicies/decideTool partagés, comportement équivalent).
   * Sans groupe de permissions/sans correspondance → tableau vide (l'endpoint service tools/list renvoie ainsi un ensemble vide, les outils non autorisés n'apparaissent jamais ;
   * la convergence ABAC des classes de données sensibles atterrit dans le PDP W3-T5 ; le présent ensemble, déjà fail-closed par groupe de permissions, satisfait
   * le référentiel d'acceptation « sans autorisation, pas d'apparition »). L'endpoint service tools/list et tools/call ont tous deux ceci pour frontière.
   */
  authorizedToolsFor(caller: InvokeCaller, service: McpServiceRecord): string[] {
    const grants = this.matchedPolicies(caller, service.id)
    if (grants.length === 0) return []
    return service.tools.filter((tool) => this.decideTool(grants, tool).ok).map((tool) => tool.name)
  }

  // -- PDP d'arbitrage principal (W3-T5, contrats §11/§12/§13) ---------------------------------
  //
  // L'arbitrage principal du MCP invoke converge dans PolicyDecisionPoint : le jugement par groupes de permissions d'authorize() migre dans
  // le module mcp-permgroup (faces de jugement matchedPolicies/decideTool partagées telles quelles, comportement équivalent —
  // authorize()/authorizedToolsFor() et le module lisent la même paire de méthodes privées, il n'existe pas de deuxième logique d'arbitrage),
  // s'ajoutent les modules iam-permission (première couche scope de limitation de ressource) / scene (ABAC de scénario) / org-constraint
  // (contrainte dure organisation/tenant) / risk-gate (refus unknown en contexte écrit). L'ordre des modules est l'ordre des barrières
  // existantes : scope → groupes de permissions → scénario → organisation → risque ; la raison du premier module deny est la cause principale
  // (les libellés de refus de domaine existants ne dérivent pas), le code deny passe par denyCodeOf pour mapper le code de domaine.

  /** Instance PDP de la passerelle (construction paresseuse ; l'ordre d'enregistrement des modules est l'ordre d'arbitrage, voir les commentaires de chaque module). */
  private gatewayPdp: PolicyDecisionPoint | undefined

  private pdp(): PolicyDecisionPoint {
    if (this.gatewayPdp) return this.gatewayPdp
    const pdp = new PolicyDecisionPoint()
    pdp.register(this.iamPermissionModule())
    pdp.register(this.mcpPermGroupModule())
    pdp.register(this.sceneModule())
    pdp.register(this.orgConstraintModule())
    pdp.register(this.riskGateModule())
    this.gatewayPdp = pdp
    return pdp
  }

  /** Projection du principal sur la face de jugement : InvokeCaller → forme minimale UnifiedPrincipal (exigence du type de contrat PDP ; les faits scopes/organisation etc. voyagent via req.context). */
  private subjectOf(caller: InvokeCaller): UnifiedPrincipal {
    const kind = caller.type === 'user' ? 'human' as const : caller.type === 'agent' ? 'agent' as const : 'app' as const
    return {
      principalId: caller.id,
      kind,
      ...(caller.type === 'user' ? { userId: caller.id } : caller.type === 'agent' ? { agentId: caller.id } : { appId: caller.id }),
      ...(caller.orgId !== undefined ? { orgId: caller.orgId } : {}),
      ...(caller.tenantId !== undefined ? { tenantId: caller.tenantId } : {}),
      ...(caller.subjectUserId !== undefined ? { subjectUserId: caller.subjectUserId } : {}),
      authMethod: 'client-credentials',
      tokenId: '',
      scopes: [...(caller.scopes ?? [])],
      actChain: (caller.actChain ?? []).map((entry, index) => ({ kind: entry.type === 'human' ? 'user' as const : 'platform-service' as const, id: `${caller.id}#${index}`, name: entry.name })),
      name: caller.name,
      permissions: [...(caller.scopes ?? [])],
    }
  }

  /**
   * Première couche iam-permission (contrat §12) : unified.scopes contenant mcp.invoke (global) ou
   * mcp.service:<ce service>.invoke / mcp.tool:<ce service>:<cet outil>.invoke quelconque = passe la première couche ;
   * principal plateforme '*' passe direct. Scopes non portés par l'appel (appelant legacy de la face outils) = fail-open — la première couche
   * ne protège pas, la deuxième couche groupes de permissions reste obligatoire ; scopes portés ayant déclaré une face MCP (un préfixe mcp. quelconque)
   * sans couvrir la cible = fail-closed (SCOPE_DENIED) — un jeton de limitation de ressource restreint à un autre service/outil
   * est refusé explicitement, plutôt qu'un passage au libellé confus de la deuxième couche. Le passage du scope ne contourne pas le groupe de permissions (deuxième couche toujours obligatoire).
   */
  private iamPermissionModule(): PolicyModule {
    return {
      id: 'iam-permission',
      decide: (req) => {
        const scopes = req.context.scopes as string[] | undefined
        if (!scopes || scopes.length === 0) {
          return { allow: true, reasons: ['令牌 scopes 未随调用携带（legacy 调用方），第一层不设防'], decisionId: newId('pd'), obligations: [] }
        }
        if (scopes.includes('*') || scopes.includes('mcp.invoke')) {
          return { allow: true, reasons: ['令牌 scopes 含 MCP 调用授权'], decisionId: newId('pd'), obligations: [] }
        }
        const serviceSlug = String(req.context.serviceSlug ?? '')
        const toolName = String(req.tool?.name ?? '')
        const serviceScope = `mcp.service:${serviceSlug}.invoke`
        const toolScope = `mcp.tool:${serviceSlug}:${toolName}.invoke`
        if (scopes.includes(serviceScope) || scopes.includes(toolScope)) {
          return { allow: true, reasons: [`令牌含资源限定 scope（${scopes.includes(serviceScope) ? serviceScope : toolScope}）`], decisionId: newId('pd'), obligations: [] }
        }
        // Face MCP de scopes déclarée sans couvrir la cible : fail-closed (la face de refus correcte de la sémantique de limitation de ressource)
        const declaredMcp = scopes.filter((scope) => scope.startsWith('mcp.'))
        if (declaredMcp.length === 0) {
          return { allow: true, reasons: ['令牌未声明 MCP scope 面（legacy scopes），第一层不设防'], decisionId: newId('pd'), obligations: [] }
        }
        return this.denyDecision('SCOPE_DENIED', t('令牌 scopes 未授权调用本服务/工具：须含 mcp.invoke 或 mcp.service:{slug}.invoke / mcp.tool:{slug}:{tool}.invoke', { slug: serviceSlug, tool: toolName }))
      },
    }
  }

  /**
   * Deuxième couche mcp-permgroup (contrat §11 : la logique authorize() existante migre, comportement équivalent) : la face de jugement
   * est exactement de même source qu'authorize()/authorizedToolsFor() (appariement de sujets matchedPolicies +
   * arbitrage d'outil isolé decideTool), les libellés de refus conservent mot pour mot les libellés de domaine existants ; le passage produit l'obligation
   * lecture seule (pour affichage d'audit, cette vague n'ajoute pas de sémantique d'exécution).
   */
  private mcpPermGroupModule(): PolicyModule {
    return {
      id: 'mcp-permgroup',
      decide: (req) => {
        const caller = req.context.caller as InvokeCaller
        const service = req.context.service as McpServiceRecord
        const toolName = String(req.tool?.name ?? '')
        // Existence de l'outil : même libellé que la première vérification d'authorize() (la liste du service est la frontière de l'arbitrage, un outil inconnu n'est pas divulgué)
        const tool = service.tools.find((item) => item.name === toolName)
        if (!tool) {
          return { allow: false, reasons: [t('服务 {service} 不存在工具 {tool}', { service: service.name, tool: toolName })], decisionId: newId('pd'), obligations: [] }
        }
        const grants = this.matchedPolicies(caller, service.id)
        if (grants.length === 0) {
          return { allow: false, reasons: [t('主体 {name} 未被任何 MCP 权限组授权访问 {service}', { name: caller.name, service: service.name })], decisionId: newId('pd'), obligations: [] }
        }
        const verdict = this.decideTool(grants, tool)
        if (!verdict.ok) {
          return { allow: false, reasons: [verdict.reason], decisionId: newId('pd'), obligations: [] }
        }
        return {
          allow: true,
          reasons: ['MCP 权限组授权命中'],
          decisionId: newId('pd'),
          // La contrainte lecture seule devient obligation structurée (contrat §11 obligations ; pour affichage d'audit)
          obligations: verdict.readOnly ? [{ type: 'read-only' }] : [],
        }
      },
    }
  }

  /**
   * Module ABAC de scénario (contrat §11 scene-ABAC) : ne s'insère que si le contexte d'appel porte explicitement un sceneCode et
   * que ctx.iam.checkScene est atteignable (deny prioritaire fail-closed, même source que le jugement iam) ;
   * l'un des deux absent = saut (référentiel en commentaire : hôte de tests autonomes/appelants legacy sans sémantique de scénario, zéro dérive de comportement).
   */
  private sceneModule(): PolicyModule {
    return {
      id: 'scene',
      decide: (req) => {
        const sceneCode = req.context.sceneCode as string | undefined
        const iam = this.ctx.iam as { checkScene?: (userId: string, sceneCode: string, action: string) => { decision: string; reason: string } } | undefined
        if (!sceneCode || typeof iam?.checkScene !== 'function') {
          return { allow: true, reasons: ['未指定场景码或 iam.checkScene 不可达，场景 ABAC 跳过'], decisionId: newId('pd'), obligations: [] }
        }
        const caller = req.context.caller as InvokeCaller
        const userId = caller.type === 'user' ? caller.id : caller.subjectUserId ?? caller.id
        const verdict = iam.checkScene(userId, sceneCode, String(req.action))
        if (verdict.decision === 'deny') {
          return this.denyDecision('SCENE_DENIED', verdict.reason)
        }
        return { allow: true, reasons: [`场景 ABAC ${verdict.decision}`], decisionId: newId('pd'), obligations: [] }
      },
    }
  }

  /** Port étroit de résolution du tenant iam (hôte de tests autonomes sans iam : défaut undefined = considéré même tenant). */
  private tenantOfOrg(orgId: string): string | undefined {
    try {
      const iam = this.ctx.iam as { tenantOfOrg?: (orgId: string) => string } | undefined
      return typeof iam?.tenantOfOrg === 'function' ? iam.tenantOfOrg(orgId) : undefined
    } catch {
      return undefined
    }
  }

  /** Si les tenants des deux côtés sont connus et différents (un inconnu quelconque = considéré même tenant — référentiel par défaut, clé de l'équivalence de comportement). */
  private crossTenant(orgA: string, orgB: string): boolean {
    const tenantA = this.tenantOfOrg(orgA)
    const tenantB = this.tenantOfOrg(orgB)
    return tenantA !== undefined && tenantB !== undefined && tenantA !== tenantB
  }

  /** Organisation de rattachement de l'entité propriétaire de la ressource (ownerEntity=app/agent avec id) ; resourceCore absent ou échec de résolution = undefined (non jugé). */
  private ownerEntityOrg(service: McpServiceRecord): string | undefined {
    const entity = service.ownerEntity
    if (!entity || (entity.type !== 'app' && entity.type !== 'agent') || !entity.id) return undefined
    try {
      const core = (this.ctx as unknown as { resourceCore?: { get: (kind: string, id: string) => { orgId?: string } | undefined } }).resourceCore
      return core?.get(entity.type, entity.id)?.orgId
    } catch {
      return undefined
    }
  }

  /** Organisation de rattachement de l'utilisateur réel de la chaîne de délégation (l'org du human vient d'iam ; échec de résolution = undefined, non jugé). */
  private subjectUserOrg(userId: string): string | undefined {
    try {
      const iam = this.ctx.iam as { users?: () => { get: (id: string) => { orgId?: string } | undefined } } | undefined
      return iam?.users?.().get(userId)?.orgId
    } catch {
      return undefined
    }
  }

  /**
   * Vérification de référence d'approbation valide (contrat §13) : context.approvalId pointe une fiche d'approbation plugin-audit,
   * status ∈ {approved, executed} et non expirée. ApprovalRecord n'a pas de champ d'expiration — fenêtre
   * decidedAt + 24 h (référentiel en commentaire, l'acceptation W4 s'aligne dessus) ; decidedAt absent (théoriquement inaccessible :
   * approved/executed passe nécessairement par decide) = considéré expirée. La requête d'approbation passe par le ctx.audit injecté (dépendance
   * existante de plugin-mcp, même source que l'exécuteur d'approbation mcp.offline), absent (hôte de tests autonomes) = pas de référence valide.
   */
  private validApprovalRef(approvalId: unknown): boolean {
    if (typeof approvalId !== 'string' || approvalId.trim() === '') return false
    try {
      const approval = this.ctx.audit?.approvals().get(approvalId)
      if (!approval) return false
      if (approval.status !== 'approved' && approval.status !== 'executed') return false
      if (!approval.decidedAt) return false
      // Pas de champ d'expiration : fenêtre de validité decidedAt + 24 h (référentiel de validité temporelle de l'autorisation inter-organisation)
      return Date.now() - Date.parse(approval.decidedAt) < 24 * 60 * 60_000
    } catch {
      return false
    }
  }

  /** Sortie unifiée des refus inter-organisation/tenant : le code de domaine voyage avec la décision via l'obligation deny-code (pour le mapping data.code de la réponse de refus). */
  private orgScopeDenied(reason: string): PolicyDecision {
    return { allow: false, reasons: [reason], decisionId: newId('pd'), obligations: [{ type: 'deny-code', code: 'ORG_SCOPE_DENIED' }] }
  }

  /** Constructeur générique de décision deny : code de domaine (optionnel) via l'obligation deny-code, reasons = libellés de domaine existants. */
  private denyDecision(code: McpDenyCode | undefined, reason: string): PolicyDecision {
    return { allow: false, reasons: [reason], decisionId: newId('pd'), obligations: code ? [{ type: 'deny-code', code }] : [] }
  }

  /**
   * Module org-constraint (contrat §13, contraintes dures organisation et tenant) : cohérence caller.org / service.org /
   * org de la ressource ownerEntity. Référentiel par défaut (clé de l'équivalence de comportement, arbitrage d'atterrissage du contrat §13) :
   * orgId absent ou même org des deux côtés = passage (toutes les données de démonstration/seed existantes sont dans l'organisation par défaut, le mode strict
   * 'org' ne doit pas casser les assertions existantes) — la face de blocage dur converge sur « inter-tenant » (référentiel tenantOfOrg, vraie
   * frontière d'isolement) et la face des déclarations explicites de visibility :
   *   - 'org' (défaut) : inter-tenant → ORG_SCOPE_DENIED ; inter-organisation dans un même tenant exige un fait d'autorisation explicite
   *     ('*' principal plateforme, ou groupe de permissions atteignant ce service — l'expression dans le même tenant de « l'inter-organisation exige une autorisation explicite ») ;
   *   - 'tenant' : même tenant = passage (inter-organisation dans le même tenant passe aussi), inter-tenant = ORG_SCOPE_DENIED ;
   *   - 'cross-org' : doit porter une référence d'approbation valide (validApprovalRef), sinon ORG_SCOPE_DENIED.
   * La vérification de l'org du subjectUserId de la chaîne de délégation avec l'org du service cible suit le même principe (même revue trois états).
   */
  private orgConstraintModule(): PolicyModule {
    return {
      id: 'org-constraint',
      decide: (req) => {
        const caller = req.context.caller as InvokeCaller
        const service = req.context.service as McpServiceRecord
        const resourceOrg = service.orgId || this.ownerEntityOrg(service) || ''
        const visibility = service.visibility ?? 'org'
        const scopes = (req.context.scopes as string[] | undefined) ?? []

        const checkPair = (callerOrg: string | undefined, label: string): PolicyDecision | undefined => {
          // orgId absent (d'un côté quelconque) → passage : référentiel par défaut même organisation, zéro dérive des données existantes
          if (!callerOrg || !resourceOrg) return undefined
          if (callerOrg === resourceOrg) return undefined
          if (visibility === 'org') {
            // Même tenant + fait d'autorisation explicite ('*' principal plateforme / groupe de permissions atteignant ce service) → passage explicite ;
            // sinon blocage dur (sans groupe atteint, mcp-permgroup refuse aussi, la cause principale reste le libellé du groupe de permissions — le module est devant)
            if (!this.crossTenant(callerOrg, resourceOrg)) {
              const explicit = scopes.includes('*') || this.matchedPolicies(caller, service.id).length > 0
              if (explicit) return undefined
              return this.orgScopeDenied(t('跨组织调用 {label} 未获显式授权（ORG_SCOPE_DENIED）', { label }))
            }
            return this.orgScopeDenied(t('{label} 与目标服务分属不同租户，跨组织调用被拒绝（ORG_SCOPE_DENIED）', { label }))
          }
          if (visibility === 'tenant') {
            if (this.crossTenant(callerOrg, resourceOrg)) {
              return this.orgScopeDenied(t('{label} 与目标服务分属不同租户（visibility=tenant），跨租户调用被拒绝（ORG_SCOPE_DENIED）', { label }))
            }
            return undefined
          }
          // cross-org : doit porter une référence d'approbation valide
          if (!this.validApprovalRef(req.context.approvalId)) {
            return this.orgScopeDenied(t('跨组织服务（visibility=cross-org）调用必须携带有效审批引用（approved/executed 且 24h 窗内）'))
          }
          return undefined
        }

        const callerVerdict = checkPair(caller.orgId, '调用者组织')
        if (callerVerdict) return callerVerdict
        // L'org de l'utilisateur réel de la chaîne de délégation suit le même principe (revu seulement si subjectUserId connu)
        if (caller.subjectUserId) {
          const subjectVerdict = checkPair(this.subjectUserOrg(caller.subjectUserId), '委托链用户组织')
          if (subjectVerdict) return subjectVerdict
        }
        return { allow: true, reasons: [`组织约束通过（visibility=${visibility}）`], decisionId: newId('pd'), obligations: [] }
      },
    }
  }

  /**
   * Module risk-gate (contrat §11 : refus unknown en contexte écrit, la sémantique existante migre) : équivalent mot pour mot
   * du chemin de refus existant — sur la chaîne legacy, un outil unknown doit être en contexte lecture (contrainte readOnly du groupe de permissions)
   * pour passer ; un contexte non lecture = refus RISK_UNREGISTERED ; la chaîne gérée est déjà arbitrée au port de politique de travail, sautée.
   * Le contexte lecture réutilise la face de jugement matchedPolicies/decideTool (même source que auth.readOnly d'authorize).
   */
  private riskGateModule(): PolicyModule {
    return {
      id: 'risk-gate',
      decide: (req) => {
        const gateMode = req.context.gateMode as string | undefined
        const gateRisk = req.context.gateRisk as string | undefined
        if (gateMode === 'managed') {
          return { allow: true, reasons: ['受管链风险已在工作策略端口裁决'], decisionId: newId('pd'), obligations: [] }
        }
        if (gateRisk !== 'unknown') {
          return { allow: true, reasons: [`工具风险已登记生效（${gateRisk ?? 'read'}）`], decisionId: newId('pd'), obligations: [] }
        }
        const caller = req.context.caller as InvokeCaller
        const service = req.context.service as McpServiceRecord
        const toolName = String(req.tool?.name ?? '')
        const tool = service.tools.find((item) => item.name === toolName)
        const grants = this.matchedPolicies(caller, service.id)
        const verdict = tool && grants.length > 0 ? this.decideTool(grants, tool) : undefined
        if (!verdict || !verdict.ok) {
          // Couche groupes de permissions sans passage : la barrière de risque n'évalue pas en plus (mot pour mot l'ordre des barrières existantes — quand authorize refuse,
          // le risque unknown n'est plus évalué, la cause principale/le code de domaine restent le référentiel existant de la couche groupes, zéro dérive)
          return { allow: true, reasons: ['权限组层未放行，风险闸跳过'], decisionId: newId('pd'), obligations: [] }
        }
        if (!verdict.readOnly) {
          return this.denyDecision('RISK_UNREGISTERED', t('工具 {tool} 风险未登记生效：{reason}', { tool: toolName, reason: WORK_DENY_CODE_LABELS.RISK_UNREGISTERED }))
        }
        return { allow: true, reasons: ['unknown 工具处于只读语境（权限组 readOnly 约束）'], decisionId: newId('pd'), obligations: [{ type: 'read-only' }] }
      },
    }
  }

  /** Premier module deny → code de refus de domaine (le module deny porte via l'obligation deny-code ; les obligations s'agrègent dans l'ordre des modules, la première est le module causal). */
  private static denyCodeOf(decision: PolicyDecision): McpDenyCode | undefined {
    const obligation = decision.obligations.find((item) => item.type === 'deny-code') as { code?: McpDenyCode } | undefined
    return obligation?.code
  }

  /**
   * Arbitrage principal (W3-T5) : construit la PolicyRequest et arbitrage agrégé via le PDP.
   * Les faits sont toujours pris côté serveur (caller/scopes/enregistrement de service/mode de barrière), le context ne fait que transporter des faits.
   */
  private async decideViaPdp(input: {
    caller: InvokeCaller
    service: McpServiceRecord
    toolName: string
    gateRisk: 'read' | 'write' | 'admin' | 'unknown'
    gateMode: string
    traceId: string
  }): Promise<PolicyDecision> {
    const { caller, service, toolName, gateRisk, gateMode, traceId } = input
    const request: PolicyRequest = {
      subject: this.subjectOf(caller),
      action: `mcp.invoke:${service.slug}:${toolName}`,
      resource: { type: 'mcp_service', id: service.id, orgId: service.orgId, dataClass: service.dataClass, slug: service.slug },
      tool: { name: toolName },
      context: {
        traceId,
        serviceSlug: service.slug,
        service,
        caller,
        scopes: caller.scopes,
        gateMode,
        gateRisk,
        ...(caller.approvalId !== undefined ? { approvalId: caller.approvalId } : {}),
      },
    }
    return await this.pdp().decide(request)
  }

  // -- Passerelle d'appel -----------------------------------------------------------

  async invoke(caller: InvokeCaller, serviceId: string, toolName: string, args: Record<string, unknown> = {}, workRef?: WorkRefIndex): Promise<InvokeResult> {
    const service = this.services().get(serviceId)
    if (!service) throw new Error(t('MCP 服务不存在：{id}', { id: serviceId }))
    const started = Date.now()
    // trace de bout en bout (W3-T5 contrat §14) : généré à l'entrée si absent (l'appelant peut le transmettre via InvokeCaller.traceId,
    // REST/plan de données le prennent des en-têtes X-Trace-Id / mcp-session-id) ; l'empreinte de hachage des paramètres partage la même source que la barrière workforce
    const traceId = caller.traceId ?? newTraceId()
    const argsHash = sha256Hex(JSON.stringify(args ?? {}))

    const fail = (status: McpCallRecord['status'], error: string, work?: McpCallWorkRef, decision?: PolicyDecision): InvokeResult => {
      this.recordCall(service, toolName, caller, {
        ok: false, status, latencyMs: Date.now() - started, version: service.currentVersion, error,
        traceId, argsHash,
        ...(gateRiskLevel !== undefined ? { riskLevel: gateRiskLevel } : {}),
        ...(decision ? { decisionId: decision.decisionId, decisionReasons: decision.reasons } : {}),
      }, work)
      return {
        ok: false, status, latencyMs: Date.now() - started, version: service.currentVersion, error,
        traceId,
        ...(decision ? { decisionId: decision.decisionId, decisionReasons: decision.reasons } : {}),
      }
    }
    // Le risque de barrière transparaît avec l'enregistrement/l'événement d'appel (déclaré avant gateRisk, toujours affecté à l'instant de l'appel)
    let gateRiskLevel: 'read' | 'write' | 'admin' | 'unknown' | undefined

    // -- Barrière d'autorisation au niveau travail (blueprint §9.5 / annexe D.5 : la détermination « géré » ne fait que rechercher le caller de confiance) ----------------
    // Point d'insertion avant le transport réel (realTransport) et avant la chaîne d'autorisation d'origine ; port non prêt ou caller non géré →
    // legacy, la chaîne d'autorisation d'origine sans y perdre une marche (intersection des deux autorisations). workRef n'est qu'un transmissif d'index (§10.4),
    // les faits d'autorisation (permit/bail/liste de capacités/périmètre de paramètres) sont toujours revérifiés côté workforce.
    const callerRef = workCallerRefFromInvokeCaller(caller)
    const toolSpec = service.tools.find((item) => item.name === toolName)
    // Correction de racine W1/V11 : le risque de barrière prend toujours « la valeur d'enregistrement de risque de confiance en vigueur » (effectiveRisk) ;
    // sans enregistrement en vigueur — la liste d'outils a explicitement déclaré un risque précis (read/write/admin) → la valeur déclarée (la face de déclaration explicite préexistante ne recule pas) ;
    // non déclaré/déclaré unknown → 'unknown' (plus de mapping implicite read). L'arbitrage de 'unknown' :
    //   chaîne gérée au port de politique de travail (le descripteur de liste n'accorde que read → passage en contexte lecture ; descripteur accordant write/admin → refus RISK_UNREGISTERED) ;
    //   chaîne legacy dans la présente passerelle, contexte lecture (voir le module risk-gate du PDP ci-dessous).
    const registeredRisk = this.riskRegistryRef?.effectiveRisk(serviceId, toolName)
    const gateRisk: 'read' | 'write' | 'admin' | 'unknown' = registeredRisk
      ?? (toolSpec?.riskLevel && toolSpec.riskLevel !== 'unknown' ? toolSpec.riskLevel : 'unknown')
    gateRiskLevel = gateRisk
    const gate = await gateManagedWork(workforcePolicyOf(this.ctx), callerRef, {
      facts: { kind: 'mcp', registryId: serviceId, action: toolName, risk: gateRisk },
      ...(workRef ? { ref: workRef } : {}),
      // Empreinte de hachage des paramètres (peu coûteuse à calculer) : pour le jugement de conflit d'étapes workforce et l'audit (même source que l'argsHash de l'enregistrement d'appel)
      argsHash,
    })
    if (gate.mode === 'denied') {
      const message = t('数字员工调用被拒绝：{detail}', { detail: `${WORK_DENY_CODE_LABELS[gate.code]}${gate.message ? `（${gate.message}）` : ''}` })
      const latencyMs = Date.now() - started
      // Le refus tombe aussi dans l'enregistrement d'appel (V07 : le refus est un fait, conservé au référentiel status='denied' avec code de refus de domaine ;
      // le contexte de travail n'est produit par vérification serveur qu'au passage, le chemin de refus n'a pas de fait work associable)
      this.recordCall(service, toolName, caller, {
        ok: false, status: 'denied', latencyMs, version: service.currentVersion, error: message, code: gate.code,
        traceId, argsHash, riskLevel: gateRisk,
      })
      return { ok: false, status: 'denied', latencyMs, version: service.currentVersion, error: message, code: gate.code }
    }
    // managed : porte dans l'association d'enregistrement de cet appel le contexte de travail vérifié côté serveur (D11)
    const work: WorkExecutionContext | undefined = gate.mode === 'managed' ? gate.work : undefined
    const workRefForRecord: McpCallWorkRef | undefined = work
      ? {
          permitId: work.permitId,
          ...(work.runId ? { runId: work.runId } : {}),
          employeeId: work.employeeId,
        }
      : undefined

    if (service.status === 'offline') return fail('denied', t('服务已下线'), workRefForRecord)
    if (service.status === 'draft' || service.status === 'verifying') return fail('denied', t('服务尚未发布'), workRefForRecord)
    if (service.health.breakerOpen) return fail('breaker_open', t('熔断器开启：服务连续失败，暂拒绝调用'), workRefForRecord)

    // Limitation : seau de jetons par service et par minute
    const key = `${serviceId}:${caller.type}:${caller.id}`
    const nowMs = Date.now()
    const bucket = (this.rateBuckets.get(key) ?? []).filter((t) => nowMs - t < 60_000)
    if (bucket.length >= service.rateLimitPerMin) {
      this.rateBuckets.set(key, bucket)
      return fail('rate_limited', t('触发限流：{limit} 次/分钟', { limit: service.rateLimitPerMin }), workRefForRecord)
    }
    bucket.push(nowMs)
    this.rateBuckets.set(key, bucket)

    // Autorisation au niveau ressource + contrainte dure d'organisation + barrière de risque (W3-T5 contrat §11 : l'arbitrage principal migre dans le PDP) —
    // ordre des modules : iam-permission (première couche scope de limitation de ressource) → mcp-permgroup (face de jugement authorize existante,
    // libellés/codes de domaine équivalents mot pour mot) → scene (ABAC de scénario optionnel) → org-constraint (§13 trois états) →
    // risk-gate (refus unknown en contexte écrit). deny prioritaire, raisons agrégées : la raison du premier module deny est
    // la cause principale (libellé d'erreur strictement identique à l'existant), le code de domaine prend l'obligation deny-code du premier module deny.
    const decision = await this.decideViaPdp({
      caller, service, toolName, gateRisk,
      gateMode: gate.mode,
      traceId,
    })
    if (!decision.allow) {
      const reason = decision.reasons[0] ?? t('调用被策略拒绝（PDP）')
      const denyCode = McpService.denyCodeOf(decision)
      const latencyMs = Date.now() - started
      // Le refus tombe aussi dans l'enregistrement d'appel (référentiel V07 : le refus est un fait, conservé status='denied' avec code de refus de domaine et expression de décision)
      this.recordCall(service, toolName, caller, {
        ok: false, status: 'denied', latencyMs, version: service.currentVersion, error: reason,
        ...(denyCode !== undefined ? { code: denyCode } : {}),
        traceId, argsHash, riskLevel: gateRisk,
        decisionId: decision.decisionId, decisionReasons: decision.reasons,
      }, workRefForRecord)
      return {
        ok: false, status: 'denied', latencyMs, version: service.currentVersion, error: reason,
        ...(denyCode !== undefined ? { code: denyCode } : {}),
        traceId, decisionId: decision.decisionId, decisionReasons: decision.reasons,
      }
    }
    // Passage : le fait de contexte lecture seule est conservé dans decision.obligations ({type:'read-only'}, pour affichage d'audit et consommation sémantique ultérieure)

    // Routage de gradation : les appels hors pourcentage de gradation passent par la version stable
    const hash = Number.parseInt(sha256Hex(`${caller.id}:${serviceId}`).slice(0, 8), 16) % 100
    const version = service.grayPercent < 100 && hash >= service.grayPercent
      ? (service.versions.find((item) => item.status === 'previous')?.version ?? service.currentVersion)
      : service.currentVersion

    // Couche d'exécution du transport : real = JSON-RPC HTTP réel ; demo = simulation déterministe (repli explicite, succès constant, résultat reproductible).
    // Les données de démonstration préexistantes (sans champ exec) sont rattrapées par demo — un nouveau service est toujours real par défaut.
    let tokens = 0
    let result: unknown
    let upstreamStatus: number | undefined
    if (service.exec !== 'real') {
      await sleep(simulateLatency(service, toolName))
      tokens = 200 + (Number.parseInt(sha256Hex(JSON.stringify(args)).slice(0, 6), 16) % 1800)
      result = mockToolResult(service, toolName, args)
    } else {
      // W3-T5 §14 : le transfert aval porte l'en-tête traceparent (W3C Trace Context, version 00)
      const transportResult = await this.realTransport(service, toolName, args, traceId)
      if (!transportResult.ok) {
        // L'échec métier compte dans le disjoncteur (correctif de revue : le disjoncteur ne doit pas dépendre du seul sondage 30 s, l'échec d'appel réel cumule aussi)
        this.noteBusinessFailure(service, transportResult.error ?? t('MCP 服务调用失败'))
        return fail('error', transportResult.error ?? t('MCP 服务调用失败'), workRefForRecord)
      }
      this.noteBusinessSuccess(service)
      result = transportResult.result
      tokens = transportResult.tokens
      upstreamStatus = transportResult.upstreamStatus
    }
    const latencyMs = Date.now() - started
    this.recordCall(service, toolName, caller, {
      ok: true, status: 'ok', latencyMs, version, tokens,
      traceId, argsHash, riskLevel: gateRisk,
      decisionId: decision.decisionId, decisionReasons: decision.reasons,
      ...(upstreamStatus !== undefined ? { upstreamStatus } : {}),
    }, workRefForRecord)
    return { ok: true, status: 'ok', latencyMs, version, result, traceId, decisionId: decision.decisionId, decisionReasons: decision.reasons }
  }

  /**
   * Assemble les en-têtes de requête sortante (point d'injection W1-T2 §6, trois endroits y passent uniformément : realTransport/sondage/découverte d'outils) :
   * les service.headers préexistants sont transmis tels quels ; ceux dont SecretBroker a enregistré les identifiants sont injectés/surchargés selon headerName
   * (à nom égal, l'identifiant gagne — après migration complète du clair, service.headers n'a plus de clé sensible, la sémantique de surcharge n'est que de transition).
   * Le Broker jette CREDENTIAL_BROKER_UNSUPPORTED sur les formes non supportées vault:/external: etc.,
   * présenté comme échec d'appel/sondage par le try/catch existant de la chaîne (fail-closed, pas de sortie à découvert silencieuse).
   */
  private async resolveCallHeaders(service: McpServiceRecord, options: { dedupKey?: string } = {}): Promise<Record<string, string>> {
    const headers: Record<string, string> = { ...(service.headers ?? {}) }
    const broker = this.secretBrokerRef
    if (broker) {
      // dedupKey (agrégation d'audit de sondage W3-T5 §14) : les traces d'accès des resolutions périodiques du sondage des services longue durée sont dédupliquées par fenêtre
      // (une fois par 10 min pour une même clé, le compteur de la fenêtre est joint à l'événement suivant) ; les vrais accès appel/découverte d'outils ne portent pas de clé, tracés à chaque fois
      const entries = options.dedupKey ? broker.resolve(service.id, { dedupKey: options.dedupKey }) : broker.resolve(service.id)
      if (entries) {
        for (const entry of entries) headers[entry.headerName] = entry.secret
      }
    }
    return headers
  }

  /**
   * Couche de transport réelle : tools/call JSON-RPC du MCP streamable HTTP.
   * Un service avec état prend d'abord l'en-tête de session via ensureSession ; session invalide (erreur serveur de type non initialisé) = une re-poignée de main automatique.
   * Latence/erreurs réelles intégralement mesurées ; consommation de jetons lue dans le champ usage de la réponse (défaut 0, sans invention).
   */
  private async realTransport(service: McpServiceRecord, toolName: string, args: Record<string, unknown>, traceId?: string): Promise<{ ok: true; result: unknown; tokens: number; upstreamStatus?: number } | { ok: false; error: string }> {
    // Point d'injection W1-T2 §6 : les en-têtes sortants passent uniformément par l'assemblage SecretBroker (headers préexistants non sensibles inchangés, identifiants surchargeant les clés homonymes)
    const headers = await this.resolveCallHeaders(service)
    // W3-T5 §14 : le transfert HTTP aval porte l'en-tête traceparent (traceId absent = pas d'en-tête — les faces latérales sondage/découverte d'outils n'en ont pas besoin)
    if (traceId) headers['traceparent'] = formatTraceparent(traceId)
    const call = (sessionId?: string) => this.mcpRequest(service.endpoint, headers, {
      jsonrpc: '2.0',
      id: `dsh-${Date.now()}`,
      method: 'tools/call',
      params: { name: toolName, arguments: args },
    }, REAL_TRANSPORT_TIMEOUT_MS, sessionId)
    try {
      let sessionId: string | undefined
      try {
        sessionId = await this.ensureSession(service.endpoint, headers)
      } catch { /* échec de poignée de main non bloquant : certains services autorisent l'appel direct sans session */ }
      let { payload, status } = await call(sessionId)
      if (payload?.error && sessionId && /session|initialized/i.test(String(payload.error.message ?? ''))) {
        this.mcpSessions.delete(service.endpoint)
        sessionId = await this.ensureSession(service.endpoint, headers).catch(() => undefined)
        ;({ payload, status } = await call(sessionId))
      }
      if (payload?.error) {
        return { ok: false, error: t('MCP 服务返回错误：{reason}', { reason: payload.error.message ?? JSON.stringify(payload.error).slice(0, 200) }) }
      }
      const result = payload?.result
      if (result?.isError) {
        return { ok: false, error: t('MCP 工具执行返回错误（isError=true）') }
      }
      return { ok: true, result: result?.content ?? result ?? null, tokens: result?.usage?.totalTokens ?? 0, upstreamStatus: status }
    } catch (error) {
      const message = error instanceof Error ? (error.name === 'AbortError' ? t('MCP 服务调用超时（{timeout}ms）', { timeout: REAL_TRANSPORT_TIMEOUT_MS }) : error.message) : String(error)
      return { ok: false, error: message }
    }
  }

  private recordCall(service: McpServiceRecord, tool: string, caller: InvokeCaller, outcome: {
    ok: boolean
    status: McpCallRecord['status']
    latencyMs: number
    version: string
    error?: string
    tokens?: number
    /** Code de refus de domaine d'un refus d'autorisation au niveau travail (additive, l'audit distingue le niveau de refus). */
    code?: WorkDenyCode
    // -- trace de bout en bout et expression de décision (W3-T5, contrats §11/§14, additive) --
    traceId?: string
    argsHash?: string
    upstreamStatus?: number
    decisionId?: string
    decisionReasons?: string[]
    /** Valeur du risque de barrière (read/write/admin/unknown ; source du riskLevel du payload v2 mcp.invoked). */
    riskLevel?: 'read' | 'write' | 'admin' | 'unknown'
  }, work?: McpCallWorkRef): void {
    const record: McpCallRecord = {
      id: newId('call'),
      at: now(),
      serviceId: service.id,
      serviceName: service.name,
      tool,
      callerType: caller.type,
      callerId: caller.id,
      callerName: caller.name,
      ...(caller.onBehalfOf !== undefined ? { onBehalfOf: caller.onBehalfOf } : {}),
      ...(caller.actChain !== undefined ? { actChain: caller.actChain } : {}),
      version: outcome.version,
      ok: outcome.ok,
      status: outcome.status,
      ...(service.finalReview ? { watermark: { finalReview: true as const, at: service.finalReview.at } } : {}),
      latencyMs: outcome.latencyMs,
      tokens: outcome.tokens ?? 0,
      exec: service.exec,
      ...(outcome.error !== undefined ? { error: outcome.error } : {}),
      ...(outcome.code !== undefined ? { code: outcome.code } : {}),
      ...(work ? { work } : {}),
      ...(outcome.traceId !== undefined ? { traceId: outcome.traceId } : {}),
      ...(outcome.argsHash !== undefined ? { argsHash: outcome.argsHash } : {}),
      ...(outcome.upstreamStatus !== undefined ? { upstreamStatus: outcome.upstreamStatus } : {}),
      ...(outcome.decisionId !== undefined ? { decisionId: outcome.decisionId } : {}),
      ...(outcome.decisionReasons !== undefined ? { decisionReasons: outcome.decisionReasons } : {}),
    }
    this.calls().insert(record)
    // Anneau d'appels plafonné à 5000 entrées, contre l'enflure
    const all = this.calls().all()
    if (all.length > 5000) {
      for (const item of all.slice(0, all.length - 5000)) this.calls().remove(item.id)
    }
    // payload v2 de mcp.invoked (contrat §14, additive) : traceId/argsHash/decisionId/decisionReasons/
    // delegationChain (projection de l'actChain unified)/riskLevel/dataClass/upstreamStatus — la souscription d'audit
    // et les consommateurs existants (agrégation de métriques Agent, etc.) sont insensibles aux champs inconnus
    this.ctx.platformBus.emit(PlatformEvents.McpInvoked, {
      serviceId: service.id, name: service.name, tool,
      callerType: caller.type, callerId: caller.id, callerName: caller.name,
      ok: outcome.ok, latencyMs: outcome.latencyMs, tokens: record.tokens,
      // Gradation de statut (audit de sécurité W4 P0-4, additive) : l'audit distingue ainsi « refus de politique » et « panne amont »
      status: record.status,
      actChain: caller.actChain,
      ...(record.traceId !== undefined ? { traceId: record.traceId } : {}),
      ...(record.argsHash !== undefined ? { argsHash: record.argsHash } : {}),
      ...(record.decisionId !== undefined ? { decisionId: record.decisionId } : {}),
      ...(record.decisionReasons !== undefined ? { decisionReasons: record.decisionReasons } : {}),
      ...(caller.actChain?.length ? { delegationChain: caller.actChain } : {}),
      ...(outcome.riskLevel !== undefined ? { riskLevel: outcome.riskLevel } : {}),
      dataClass: service.dataClass,
      ...(record.upstreamStatus !== undefined ? { upstreamStatus: record.upstreamStatus } : {}),
    })
    // Pipeline de metering (v1.2 étape 2) : les appels du transport real entrent dans les événements usage (le trafic demo n'est ni facturé ni compté SLO)
    if (service.exec === 'real') {
      try {
        this.ctx.usage.record({
          org: service.orgId,
          subject: `${caller.type}:${caller.id}`,
          principal: `org:${service.orgId}`,
          resource: `mcp:${service.slug}`,
          meters: [
            { key: 'calls', value: 1, unit: 'call' },
            ...(record.tokens > 0 ? [{ key: 'tokens', value: record.tokens, unit: 'token' }] : []),
          ],
          idempotency_key: `mcp:${record.id}`,
          // trace de bout en bout (W3-T5 §14) : le renseignement de trace_id passe de « seulement les appels gérés via invocationId » à tous les appels
          // real — l'appel géré garde la priorité invocationId (registre workforce traversant), les autres prennent le traceId du jour
          trace_id: work?.invocationId ?? record.traceId ?? '',
        })
      } catch (error) {
        this.ctx.logger('mcp').warn('usage 计量登记失败', error)
      }
    }
  }

  // -- Métriques de supervision -----------------------------------------------------------

  metricsOverview(): {
    totalCalls: number
    successRate: number
    p95Latency: number
    tokens: number
    onlineServices: number
    unhealthyServices: number
  } {
    const calls = this.calls().all()
    const okCalls = calls.filter((call) => call.ok)
    const latencies = calls.map((call) => call.latencyMs).sort((a, b) => a - b)
    const services = this.services().all()
    return {
      totalCalls: calls.length,
      successRate: calls.length === 0 ? 1 : round3(okCalls.length / calls.length),
      p95Latency: latencies.length === 0 ? 0 : latencies[Math.floor(latencies.length * 0.95)]!,
      tokens: calls.reduce((sum, call) => sum + call.tokens, 0),
      onlineServices: services.filter((item) => ['online', 'gray'].includes(item.status)).length,
      unhealthyServices: services.filter((item) => item.status === 'unhealthy').length,
    }
  }

  serviceMetrics(serviceId: string): {
    calls: number
    okCalls: number
    successRate: number
    p95Latency: number
    tokens: number
    callers: Array<{ callerName: string; callerType: string; calls: number }>
    toolStats: Array<{ tool: string; calls: number; ok: number; avgLatency: number }>
    series: Array<{ minute: string; calls: number; errors: number; avgLatency: number }>
  } {
    const calls = this.calls().find((call) => call.serviceId === serviceId)
    const okCalls = calls.filter((call) => call.ok)
    const latencies = calls.map((call) => call.latencyMs).sort((a, b) => a - b)
    const byCaller = new Map<string, { callerName: string; callerType: string; calls: number }>()
    for (const call of calls) {
      const key = `${call.callerType}:${call.callerId}`
      const bucket = byCaller.get(key) ?? { callerName: call.callerName, callerType: call.callerType, calls: 0 }
      bucket.calls++
      byCaller.set(key, bucket)
    }
    const byTool = new Map<string, { tool: string; calls: number; ok: number; totalLatency: number }>()
    for (const call of calls) {
      const bucket = byTool.get(call.tool) ?? { tool: call.tool, calls: 0, ok: 0, totalLatency: 0 }
      bucket.calls++
      if (call.ok) bucket.ok++
      bucket.totalLatency += call.latencyMs
      byTool.set(call.tool, bucket)
    }
    // Série minute par minute sur les 60 dernières minutes
    const series = new Map<string, { calls: number; errors: number; totalLatency: number }>()
    const nowMs = Date.now()
    for (let i = 59; i >= 0; i--) {
      const minute = new Date(nowMs - i * 60_000).toISOString().slice(0, 16)
      series.set(minute, { calls: 0, errors: 0, totalLatency: 0 })
    }
    for (const call of calls) {
      const minute = call.at.slice(0, 16)
      const bucket = series.get(minute)
      if (!bucket) continue
      bucket.calls++
      if (!call.ok) bucket.errors++
      bucket.totalLatency += call.latencyMs
    }
    return {
      calls: calls.length,
      okCalls: okCalls.length,
      successRate: calls.length === 0 ? 1 : round3(okCalls.length / calls.length),
      p95Latency: latencies.length === 0 ? 0 : latencies[Math.floor(latencies.length * 0.95)]!,
      tokens: calls.reduce((sum, call) => sum + call.tokens, 0),
      callers: [...byCaller.values()].sort((a, b) => b.calls - a.calls),
      toolStats: [...byTool.values()].map((bucket) => ({
        tool: bucket.tool, calls: bucket.calls, ok: bucket.ok,
        avgLatency: bucket.calls === 0 ? 0 : Math.round(bucket.totalLatency / bucket.calls),
      })).sort((a, b) => b.calls - a.calls),
      series: [...series.entries()].map(([minute, bucket]) => ({
        minute, calls: bucket.calls, errors: bucket.errors,
        avgLatency: bucket.calls === 0 ? 0 : Math.round(bucket.totalLatency / bucket.calls),
      })),
    }
  }

  callLog(filter: { serviceId?: string; callerId?: string; status?: string; limit?: number }): { total: number; items: McpCallRecord[] } {
    const all = this.calls().find((call) => {
      if (filter.serviceId && call.serviceId !== filter.serviceId) return false
      if (filter.callerId && call.callerId !== filter.callerId) return false
      if (filter.status && call.status !== filter.status) return false
      return true
    }).sort((a, b) => b.at.localeCompare(a.at))
    return { total: all.length, items: all.slice(0, filter.limit ?? 100) }
  }

  private requireService(id: string): McpServiceRecord {
    const service = this.services().get(id)
    if (!service) throw new Error(t('MCP 服务不存在：{id}', { id }))
    return service
  }
}

// ---------------------------------------------------------------------------
// Aides de couche de transport (real = HTTP réel ; demo = pseudo-aléatoire déterministe, démonstration seulement)
// ---------------------------------------------------------------------------

/** Délai d'expiration des appels real (ms). */
const REAL_TRANSPORT_TIMEOUT_MS = 10_000
/** Délai d'expiration des sondages real (ms). */
const REAL_PROBE_TIMEOUT_MS = 5_000
/** Durée de cache des sessions MCP distantes (ms) : nouvelle poignée de main à expiration ou sur erreur de session du serveur. */
const MCP_SESSION_TTL_MS = 5 * 60_000

function probeLatency(service: McpServiceRecord): number {
  // Sonde demo : santé déterministe ; les chemins d'échec/dégradation sont présentés par la sonde real (HTTP réel), pas de fluctuation fabriquée.
  return 40 + (Number.parseInt(sha256Hex(service.id).slice(0, 4), 16) % 360)
}

function simulateLatency(service: McpServiceRecord, tool: string): number {
  return 30 + (Number.parseInt(sha256Hex(`${service.slug}:${tool}`).slice(0, 4), 16) % 220)
}

function mockToolResult(service: McpServiceRecord, tool: string, args: Record<string, unknown>): unknown {
  const digest = sha256Hex(`${service.slug}:${tool}:${JSON.stringify(args)}`).slice(0, 8)
  if (/search|query|find|list/i.test(tool)) {
    return {
      matched: Number.parseInt(digest.slice(0, 4), 16) % 20 + 1,
      items: Array.from({ length: 3 }, (_, index) => ({
        id: `${digest}-${index}`,
        title: t('{tool} 结果 #{n}', { tool, n: index + 1 }),
        score: round3(0.75 + ((Number.parseInt(digest.slice(index, index + 2), 16) % 25) / 100)),
      })),
    }
  }
  if (/write|create|update|send|exec/i.test(tool)) {
    return { acknowledged: true, affected: Number.parseInt(digest.slice(0, 2), 16) % 5 + 1, receipt: `rcpt-${digest}` }
  }
  return { status: 'success', tool, digest, echo: args }
}

function defaultToolsFor(slug: string): McpToolSpec[] {
  return [
    { name: `${slug}_search`, description: `检索 ${slug} 数据`, inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] }, riskLevel: 'read' },
    { name: `${slug}_fetch`, description: `按 ID 获取 ${slug} 详情`, inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }, riskLevel: 'read' },
    { name: `${slug}_write`, description: `写入 ${slug} 数据`, inputSchema: { type: 'object', properties: { payload: { type: 'object' } } }, riskLevel: 'write' },
  ]
}

function bumpVersion(version: string): string {
  const parts = version.split('.').map(Number)
  parts[2] = (parts[2] ?? 0) + 1
  return parts.join('.')
}

function now(): string {
  return new Date().toISOString()
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms))
}

function round3(value: number): number {
  return Math.round(value * 1000) / 1000
}

// ---------------------------------------------------------------------------
// Aide d'autorisation au niveau travail (blueprint §10.2 / D.5 : la passerelle ne consomme que le port étroit, pas de dépendance inverse vers workforce)
// ---------------------------------------------------------------------------

/**
 * Lecture du port étroit au runtime : platform-core enregistre WorkforcePolicyRegistry à l'assemblage (provide='workforcePolicy').
 * L'augmentation de types de Context est détenue uniformément côté workforce ; lecture défensive ici — si le service n'est pas assemblé (hôte de test unitaire autonome),
 * Renvoie undefined : gateManagedWork suit le chemin legacy tant que le port n'est pas prêt, statu quo maintenu.
 */
function workforcePolicyOf(ctx: Context): WorkforcePolicyRegistry | undefined {
  try {
    return (ctx as unknown as { workforcePolicy?: WorkforcePolicyRegistry }).workforcePolicy ?? undefined
  } catch {
    return undefined
  }
}

/**
 * Appelant vérifié → WorkCallerRef (l'identité vient toujours de l'analyse du jeton d'entrée, jamais des paramètres de requête).
 * user → human (principalId=userId) ; agent/app → machine (refType/refId fournis à workforce pour
 * Recherche inverse de la liaison technique de l'employé numérique, alignée sur la sémantique refType des principals authn).
 */
function workCallerRefFromInvokeCaller(caller: InvokeCaller): WorkCallerRef {
  if (caller.type === 'user') {
    return { kind: 'human', principalId: caller.id, userId: caller.id, name: caller.name }
  }
  return {
    kind: 'machine',
    principalId: caller.id,
    refType: caller.type === 'agent' ? 'agent' : 'app',
    refId: caller.id,
    name: caller.name,
  }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    mcpRegistry: McpService
    /** Lot W1 (W, correction de fond V11) : registre des risques de confiance des outils MCP (enregistrement → approbation à deux niveaux → mise en vigueur → réexamen → retrait). */
    mcpToolRisks: McpToolRiskRegistry
    /** W1-T2 (gouvernance MCP §6) : Secret Broker des identifiants aval (fichier de clés 0600, zéro clé dans les collections métier). */
    secretBroker: SecretBroker
  }
}

// W1-T2 (contrat §6) : SecretBroker et les assistants de normalisation des en-têtes sensibles exportés (partagés CLI/hôte/tests unitaires)
export {
  SecretBroker,
  SENSITIVE_HEADER_RE,
  sensitiveHeaderKeys,
  plainSensitiveHeaderViolation,
} from './secret-broker.ts'
export type {
  McpCredentialEntry,
  McpCredentialFile,
  McpCredentialDescription,
} from './secret-broker.ts'

export const name = 'mcp'
export const inject = ['opsStorage', 'platformBus', 'iam', 'audit', 'usage', 'workforcePolicy']

export function apply(ctx: Context) {
  const registry = new McpService(ctx)
  // Lot W1 (W, correction de fond V11) : le service de registre de risques d'outils est assemblé et relié directement dans le même lot que la passerelle (barrière d'invoke et face REST console
  // Accès via mcpRegistry.riskRegistry() ; la clé ctx.mcpToolRisks reste déclarée par declare module pour l'hôte/le contexte racine)
  registry.attachRiskRegistry(new McpToolRiskRegistry(ctx))
  // W1-T2 (contrat §6) : le Secret Broker est assemblé et relié directement dans le même lot que la passerelle (point d'injection des appels sortants et face identifiants REST partagent la même instance ;
  // la clé ctx.secretBroker est fournie par declare module pour l'hôte/le contexte racine)
  registry.attachSecretBroker(new SecretBroker(ctx))
  ctx.plugin(mcpTools)
  // Exécuteur d'approbation L4 : après approbation de mcp.offline, exécute automatiquement la mise hors ligne
  ctx.effect(() => ctx.audit.registerExecutor('mcp.offline', async (payload) => {
    const serviceId = String(payload.serviceId)
    const reason = String(payload.reason ?? t('审批通过下线'))
    return registry.offlineService(serviceId, 'approval-center', reason)
  }))
  // Contrat §5 : migration idempotente des champs de gouvernance des services préexistants (compléter les manques ; un échec n'interrompt pas le démarrage, nouvelle tentative au prochain)
  try {
    registry.ensureGovernanceMigration()
  } catch (error) {
    console.error('[mcp] 治理字段迁移失败（不阻断启动，下次启动重试）', error)
  }
}
