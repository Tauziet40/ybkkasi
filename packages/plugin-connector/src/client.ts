/**
 * OcClient — client d'adaptation fine d'open-connector v1.4.0 (couche d'isolation à contrat verrouillé).
 *
 * Unique endroit du dépôt conscient du contrat HTTP amont ; avant de monter la version du sidecar, exécuter d'abord le groupe de tests de verrouillage de contrat selftest (T-01).
 * Surface de contrat (correspondance ligne à ligne avec le tableau du plan §2.3) :
 *   GET  /v1/health                        sondage de santé {success,data:{ok,runtime}}
 *   GET  /v1/providers                     catalogue provider
 *   GET  /v1/actions[?service=]            catalogue d'actions (avec requiredScopes/providerPermissions/inputSchema)
 *   GET  /v1/actions/:actionId             détail d'une action
 *   GET  /api/actions/:actionId/agent.md   guide de l'assistant de connexion (interface admin, texte)
 *   PUT/DELETE /api/connections/:service    gestion des connexions (GET /api/connections pour la liste)
 *   POST /api/oauth/authorizations         lancement OAuth → {authorizationUrl, state}
 *   POST/GET/PUT/DELETE /api/runtime-tokens jetons d'exécution oct_ (la valeur n'est renvoyée qu'une fois, à la création)
 *   POST /v1/actions/:actionId             exécution du plan de données (Bearer oct_ + x-oo-connector-alias + Idempotency-Key)
 *   GET  /api/runs                         journaux de run (pagination cursor + filtre runtimeTokenId)
 *
 * Enveloppe unifiée : succès { success:true, data, meta } ; échec { success:false, errorCode }.
 * Points non documentés en amont (déclarés tels quels) : le code de statut de succès de PUT connections et POST authorizations n'est pas documenté —
 * traité comme 200 par défaut avec assertion de l'enveloppe success:true.
 */
import { OcError, OcUnavailableError } from './errors.ts'
import { t } from '../../platform-i18n/src/index.ts'

export const OC_VERSION_PIN = 'v1.4.0'
const DEFAULT_TIMEOUT_MS = 15_000

/** ConnectionSummary en huit champs (base des assertions de schéma T-01). */
export interface OcConnectionSummary {
  id: string
  service: string
  connectionName: string
  authType?: string
  configured?: boolean
  virtual?: boolean
  default?: boolean
  profile?: Record<string, unknown>
}

export interface OcAuthorizationStart {
  authorizationUrl: string
  state: string
}

/** RuntimeTokenSummary : la valeur du token n'apparaît qu'une fois, dans la réponse de createRuntimeToken. */
export interface OcRuntimeTokenSummary {
  id: string
  name?: string
  token?: string
  policy?: OcTokenPolicy
  createdAt?: string
}

export type TokenPattern = '*' | string

/** Politique à quatre tableaux : le PUT doit envoyer les quatre tableaux complets (sans perdre les allowedConnections existants). */
export interface OcTokenPolicy {
  allowedActions: TokenPattern[] | ['*']
  blockedActions: TokenPattern[]
  allowedProxies: TokenPattern[]
  allowedConnections: string[]
}

export interface OcRunLog {
  id: string
  service?: string
  actionId?: string
  ok?: boolean
  runtimeTokenId?: string
  caller?: string
  policy?: unknown
  startedAt?: string
  latencyMs?: number
  input?: unknown
  outputSummary?: unknown
  error?: string
}

export interface OcRunsPage {
  items: OcRunLog[]
  nextCursor?: string
}

export interface OcAction {
  id: string
  name?: string
  service?: string
  description?: string
  requiredScopes?: Array<unknown>
  providerPermissions?: Array<unknown>
  inputSchema?: Record<string, unknown>
  [key: string]: unknown
}

export interface OcProvider {
  service?: string
  name?: string
  description?: string
  auth?: Array<unknown>
  categories?: Array<unknown>
  [key: string]: unknown
}

export interface ExecuteOutcome {
  data: unknown
  meta: Record<string, unknown>
  raw: Record<string, unknown>
}

export class OcClient {
  private readonly baseUrl: string
  /** Bearer du plan de gestion (/api/*) ; l'oct_ du plan de données est passé explicitement par executeAction. */
  private readonly adminToken: string
  private readonly timeoutMs: number

  constructor(baseUrl: string, adminToken: string, timeoutMs = DEFAULT_TIMEOUT_MS) {
    this.baseUrl = baseUrl
    this.adminToken = adminToken
    this.timeoutMs = timeoutMs
  }

  // -- Socle commun de requête ---------------------------------------------------------

  private async request(path: string, init: { method?: string; body?: unknown; bearer?: string; timeoutMs?: number; acceptText?: boolean } = {}): Promise<{ status: number; json: Record<string, unknown> | null; text: string }> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), init.timeoutMs ?? this.timeoutMs)
    let response: Response
    try {
      response = await fetch(`${this.baseUrl.replace(/\/$/, '')}${path}`, {
        method: init.method ?? 'GET',
        headers: {
          ...(init.body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...((init.bearer ?? this.adminToken) ? { authorization: `Bearer ${init.bearer ?? this.adminToken}` } : {}),
          ...(init.acceptText ? { accept: 'text/plain' } : {}),
        },
        ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
        signal: controller.signal,
      })
    } catch (error) {
      const message = error instanceof Error ? (error.name === 'AbortError' ? t('open-connector 响应超时（{timeout}ms）', { timeout: init.timeoutMs ?? this.timeoutMs }) : error.message) : String(error)
      throw new OcUnavailableError(t('连接器网关不可达：{reason}', { reason: message }))
    } finally {
      clearTimeout(timer)
    }
    const text = await response.text().catch(() => '')
    if (init.acceptText && !text.startsWith('{')) {
      return { status: response.status, json: null, text }
    }
    let json: Record<string, unknown> | null = null
    if (text.trim().length > 0) {
      try {
        json = JSON.parse(text) as Record<string, unknown>
      } catch {
        throw new OcUnavailableError(t('open-connector 响应不是合法 JSON（HTTP {status}）：{body}', { status: response.status, body: text.slice(0, 120) }))
      }
    }
    return { status: response.status, json, text }
  }

  /** Déballage d'enveloppe : non-2xx ou success:false lève uniformément une OcError (code d'erreur préservé et transmis). */
  private async envelope(path: string, init: Parameters<OcClient['request']>[1] = {}): Promise<{ data: unknown; meta: Record<string, unknown> }> {
    const { status, json, text } = await this.request(path, init)
    if (json === null) {
      throw new OcUnavailableError(t('open-connector 响应缺少 JSON 信封（HTTP {status}）：{path}', { status, path }))
    }
    if (json.success === false || status >= 400) {
      const code = String(json.errorCode ?? (json.error as Record<string, unknown> | undefined)?.code ?? `http_${status}`)
      throw new OcError(code, typeof json.message === 'string' ? json.message : t('{path} 失败：HTTP {status} {body}', { path, status, body: text.slice(0, 160) }), undefined, undefined)
    }
    return { data: json.data ?? null, meta: (json.meta && typeof json.meta === 'object' ? json.meta : {}) as Record<string, unknown> }
  }

  // -- Santé et catalogue -----------------------------------------------------------

  async health(): Promise<{ ok: boolean; runtime?: string }> {
    const { json, status } = await this.request('/v1/health')
    if (status >= 400 || !json || json.success === false) {
      throw new OcUnavailableError(t('健康检查失败：HTTP {status}', { status }))
    }
    const data = (json.data && typeof json.data === 'object' ? json.data : {}) as Record<string, unknown>
    return { ok: data.ok === true, runtime: typeof data.runtime === 'string' ? data.runtime : undefined }
  }

  async listProviders(): Promise<OcProvider[]> {
    const { data } = await this.envelope('/v1/providers')
    return Array.isArray(data) ? data as OcProvider[] : []
  }

  async listActions(service?: string): Promise<OcAction[]> {
    const path = service ? `/v1/actions?service=${encodeURIComponent(service)}` : '/v1/actions'
    const { data } = await this.envelope(path)
    return Array.isArray(data) ? data as OcAction[] : []
  }

  async getAction(actionId: string): Promise<OcAction> {
    const { data } = await this.envelope(`/v1/actions/${encodeURIComponent(actionId)}`)
    return (data ?? {}) as OcAction
  }

  /** Affichage proxy du guide de l'assistant de connexion (interface admin renvoyant du texte markdown). */
  async getActionGuide(actionId: string): Promise<string> {
    const { text, status } = await this.request(`/api/actions/${encodeURIComponent(actionId)}/agent.md`, { acceptText: true })
    if (status >= 400) throw new OcError(`http_${status}`, t('agent.md 获取失败（HTTP {status}）', { status }))
    return text
  }

  // -- Gestion des connexions -------------------------------------------------------------

  async listConnections(): Promise<OcConnectionSummary[]> {
    const { data } = await this.envelope('/api/connections')
    return Array.isArray(data) ? data as OcConnectionSummary[] : []
  }

  /** Code de statut de succès non documenté en amont — traité comme 200 par défaut avec assertion de l'enveloppe success:true (déjà affirmée par envelope). */
  async upsertConnection(service: string, body: { authType: string; connectionName?: string; values?: Record<string, unknown>; default?: boolean }): Promise<OcConnectionSummary> {
    const { data } = await this.envelope(`/api/connections/${encodeURIComponent(service)}`, { method: 'PUT', body })
    return (data ?? {}) as OcConnectionSummary
  }

  async deleteConnection(service: string, connectionName?: string): Promise<void> {
    await this.envelope(`/api/connections/${encodeURIComponent(service)}`, { method: 'DELETE', body: { ...(connectionName ? { connectionName } : {}) } })
  }

  // -- OAuth -----------------------------------------------------------------

  async createOAuthAuthorization(payload: {
    service: string
    connectionName?: string
    clientId?: string
    clientSecret?: string
    requestedScopes?: string[]
    extra?: Record<string, unknown>
    secretExtra?: Record<string, unknown>
  }): Promise<OcAuthorizationStart> {
    const { data } = await this.envelope('/api/oauth/authorizations', { method: 'POST', body: payload })
    return (data ?? {}) as OcAuthorizationStart
  }

  // -- Jetons d'exécution oct_ -------------------------------------------------------

  /** La valeur du token n'apparaît qu'une fois dans cette réponse, l'appelant doit immédiatement en prendre charge (la plateforme choisit un cache mémoire, sans persistance). */
  async createRuntimeToken(policy: OcTokenPolicy & { name?: string }): Promise<OcRuntimeTokenSummary> {
    const { data } = await this.envelope('/api/runtime-tokens', { method: 'POST', body: policy })
    return (data ?? {}) as OcRuntimeTokenSummary
  }

  async listRuntimeTokens(): Promise<Array<OcRuntimeTokenSummary>> {
    const { data } = await this.envelope('/api/runtime-tokens')
    return Array.isArray(data) ? data as Array<OcRuntimeTokenSummary> : []
  }

  /** Mise à jour de politique : le PUT doit envoyer les quatre tableaux complets (responsabilité de l'appelant, voir mirrorTokenPolicy). */
  async updateRuntimeToken(id: string, policy: OcTokenPolicy): Promise<OcRuntimeTokenSummary> {
    const { data } = await this.envelope(`/api/runtime-tokens/${encodeURIComponent(id)}`, { method: 'PUT', body: policy })
    return (data ?? {}) as OcRuntimeTokenSummary
  }

  async deleteRuntimeToken(id: string): Promise<void> {
    await this.envelope(`/api/runtime-tokens/${encodeURIComponent(id)}`, { method: 'DELETE' })
  }

  // -- Exécution du plan de données et journaux de run ---------------------------------------------------

  /** Exécute une action : jeton oct_ + x-oo-connector-alias pour choisir la connexion nommée ; pour les écritures, il est conseillé de porter un Idempotency-Key. */
  async executeAction(actionId: string, options: { input?: Record<string, unknown>; alias?: string; idempotencyKey?: string }, octToken: string): Promise<ExecuteOutcome> {
    const { status, json } = await this.requestRawWithHeaders(
      `/v1/actions/${encodeURIComponent(actionId)}`, 'POST',
      { input: options.input ?? {} }, octToken,
      {
        ...(options.alias ? { 'x-oo-connector-alias': options.alias } : {}),
        ...(options.idempotencyKey ? { 'idempotency-key': options.idempotencyKey } : {}),
      },
    )
    if (json && (json.success === false || status >= 400)) {
      const code = String(json.errorCode ?? `http_${status}`)
      throw new OcError(code, typeof json.message === 'string' ? json.message : t('action {action} 执行失败（HTTP {status}）', { action: actionId, status }))
    }
    return {
      data: json?.data ?? null,
      meta: (json?.meta && typeof json.meta === 'object' ? json.meta : {}) as Record<string, unknown>,
      raw: (json ?? {}) as Record<string, unknown>,
    }
  }

  private async requestRawWithHeaders(path: string, method: string, body: unknown, bearer: string, extraHeaders: Record<string, string>): Promise<{ status: number; json: Record<string, unknown> | null; text: string }> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)
    try {
      const response = await fetch(`${this.baseUrl.replace(/\/$/, '')}${path}`, {
        method,
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${bearer}`,
          ...extraHeaders,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      })
      const text = await response.text().catch(() => '')
      let json: Record<string, unknown> | null = null
      try {
        json = text.trim() ? JSON.parse(text) as Record<string, unknown> : null
      } catch {
        throw new OcUnavailableError(t('执行响应不是合法 JSON（HTTP {status}）：{body}', { status: response.status, body: text.slice(0, 120) }))
      }
      return { status: response.status, json, text }
    } catch (error) {
      if (error instanceof OcError || error instanceof OcUnavailableError) throw error
      const message = error instanceof Error ? (error.name === 'AbortError' ? t('执行超时（{timeout}ms）', { timeout: this.timeoutMs }) : error.message) : String(error)
      throw new OcUnavailableError(t('连接器网关不可达：{reason}', { reason: message }))
    } finally {
      clearTimeout(timer)
    }
  }

  // -- Réconciliation des runs --------------------------------------------------------------

  /** Pagination cursor : le cursor vaut encodeURIComponent(JSON.stringify({startedAt,id})). */
  async listRuns(params: { limit?: number; cursor?: string; service?: string; actionId?: string; ok?: boolean } = {}): Promise<OcRunsPage> {
    const search = new URLSearchParams()
    if (params.limit !== undefined) search.set('limit', String(params.limit))
    if (params.cursor) search.set('cursor', params.cursor)
    if (params.service) search.set('service', params.service)
    if (params.actionId) search.set('actionId', params.actionId)
    if (params.ok !== undefined) search.set('ok', String(params.ok))
    const suffix = search.size > 0 ? `?${search.toString()}` : ''
    const { data } = await this.envelope(`/api/runs${suffix}`)
    const record = (data && typeof data === 'object' ? data : {}) as { items?: unknown; nextCursor?: unknown }
    return {
      items: Array.isArray(record.items) ? record.items as OcRunLog[] : [],
      ...(typeof record.nextCursor === 'string' && record.nextCursor ? { nextCursor: record.nextCursor } : {}),
    }
  }
}
