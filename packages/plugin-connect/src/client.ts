/**
 * Service client d'accès : moitié cliente du runtime dsh distant (forme installée via le marché de plugins) se connectant au service de la plateforme hôte.
 *
 * Responsabilités :
 *   - persister la configuration de connexion à l'hôte (<dataDir>/connect-client.json, 0600, identifiants machine en clair uniquement sur cette machine)
 *   - trois voies d'identifiants : échange d'un code d'accès contre des identifiants machine (enroll) / configuration directe d'identifiants existants / déconnexion et réinitialisation
 *   - cache du jeton machine (client-credentials contre un machine token de 2 h, renouvellement automatique à expiration, une unique retry sur 401)
 *   - proxy distant d'outils : forward() transfère l'exécution des 37 outils d'exploitation de la plateforme vers l'hôte /api/tools/execute
 */
import { existsSync } from 'node:fs'
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { hostname } from 'node:os'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { t } from '../../platform-i18n/src/index.ts'

/** Configuration de connexion à l'hôte persistée localement (les identifiants machine équivalent à des mots de passe, permissions du fichier resserrées à 0600). */
export interface ConnectClientConfig {
  hubUrl: string
  clientId: string
  clientSecret: string
  clientName: string
  template: string
  principalId: string
  enrolledAt: string
  /** Informations du dernier échec de transfert (à des fins de diagnostic). */
  lastError?: string
}

interface CachedToken {
  token: string
  expiresAt: number
}

const CONNECT_TOOLS_PREFIX = 'connect_'

export class ConnectClientService extends Service {
  static readonly provide = 'connectClient'

  private configFile: string
  private config: ConnectClientConfig | null = null
  private cached: CachedToken | null = null
  /** État de dégradation du proxy distant (OPT-P1-03) : raison consignée en cas d'échec d'installation, exposée explicitement par connect_status. */
  private degradedReason: string | undefined
  private degradedDetail: string | undefined
  /** Throttling de l'alerte d'échec de transfert (OPT-P1-03) : au plus un connect.degraded par 60 s, pour éviter qu'une tempête de retries sature l'audit. */
  private lastForwardFailureEmitAt = 0

  constructor(ctx: Context, options: { dataDir?: string } = {}) {
    super(ctx, 'connectClient')
    this.configFile = join(options.dataDir ?? ctx.opsStorage.dataDirPath, 'connect-client.json')
    this.config = this.load()
  }

  /** Si un hôte est configuré (détermine si le proxy d'outils passe en distant ou en local). */
  hasHub(): boolean {
    return this.config !== null && this.config.hubUrl !== ''
  }

  getConfig(): Readonly<ConnectClientConfig> | null {
    return this.config
  }

  // ---------------------------------------------------------------- trois voies d'identifiants

  /**
   * Échange d'un code d'accès contre des identifiants machine (voie principale de demande d'identifiants en un geste par l'Agent) :
   * POST /api/connect/enroll vers l'hôte, puis persistance de clientId/clientSecret en cas de succès.
   */
  async enroll(input: { hubUrl: string; enrollmentCode: string; clientName?: string }): Promise<ConnectClientConfig> {
    const hubUrl = normalizeBaseUrl(input.hubUrl)
    const clientName = input.clientName?.trim() || defaultClientName()
    const payload = await this.hubCall(hubUrl, 'POST', '/api/connect/enroll', {
      enrollmentCode: input.enrollmentCode.trim(),
      clientName,
      meta: { hostname: hostname(), platform: process.platform, node: process.version },
    })
    const credential = payload as { clientId: string; clientSecret: string; principalId: string; template: string }
    if (!credential?.clientId || !credential?.clientSecret) throw new Error(t('宿主返回的接入凭证不完整'))
    this.config = {
      hubUrl,
      clientId: credential.clientId,
      clientSecret: credential.clientSecret,
      clientName,
      template: credential.template ?? 'readonly',
      principalId: credential.principalId ?? '',
      enrolledAt: new Date().toISOString(),
    }
    this.cached = null
    this.save()
    return this.config
  }

  /** Configuration directe d'identifiants machine existants (signés à la main par l'admin dans la console hôte puis distribués). */
  async loginWithCredential(input: { hubUrl: string; clientId: string; clientSecret: string; clientName?: string }): Promise<ConnectClientConfig> {
    const hubUrl = normalizeBaseUrl(input.hubUrl)
    if (!input.clientId || !input.clientSecret) throw new Error(t('clientId 与 clientSecret 必填'))
    this.config = {
      hubUrl,
      clientId: input.clientId.trim(),
      clientSecret: input.clientSecret.trim(),
      clientName: input.clientName?.trim() || defaultClientName(),
      template: '',
      principalId: '',
      enrolledAt: new Date().toISOString(),
    }
    this.cached = null
    // Vérifie immédiatement la validité des identifiants (en cas d'échec, rien n'est persisté afin d'éviter d'écrire une mauvaise configuration)
    const probe = await this.machineToken()
    void probe
    this.save()
    return this.config
  }

  /** Déconnexion : efface les identifiants locaux et le cache de jetons (sans impact côté hôte ; la révocation se fait dans la console hôte). */
  reset(): void {
    this.config = null
    this.cached = null
    try {
      if (existsSync(this.configFile)) writeFileSync(this.configFile, JSON.stringify({ configured: false }, null, 2), 'utf8')
    } catch { /* un échec de nettoyage n'interrompt pas la déconnexion */ }
  }

  /** Met à jour l'information d'erreur en mémoire (pour le diagnostic par status). */
  noteError(message: string): void {
    if (this.config) this.config = { ...this.config, lastError: message }
  }

  // ---------------------------------------------------------------- jeton et transfert

  /** Obtient le jeton machine (cache + expiration anticipée de 60 s ; renouvellement automatique via client-credentials à expiration). */
  async machineToken(): Promise<string> {
    if (this.cached && this.cached.expiresAt > Date.now() + 60_000) return this.cached.token
    if (!this.config) throw new Error(t('尚未配置宿主服务，请先完成接入（connect_setup 或本地配置页）'))
    const config = this.config
    try {
      const payload = await this.hubCall(config.hubUrl, 'POST', '/api/auth/client-credentials', {
        clientId: config.clientId,
        clientSecret: config.clientSecret,
      }) as { token: string; expiresAt: string }
      if (!payload?.token) throw new Error(t('宿主未返回机器令牌'))
      this.cached = { token: payload.token, expiresAt: new Date(payload.expiresAt).getTime() || Date.now() + 110 * 60_000 }
      return this.cached.token
    } catch (error) {
      if (error instanceof HubUnauthorizedError) {
        // Identifiants machine révoqués/désactivés : un renouvellement serait inutile, fournir directement un diagnostic actionnable
        throw new Error(t('机器凭证无效或已在宿主侧吊销，请重新接入（connect_setup）或联系宿主管理员'))
      }
      throw error
    }
  }

  /**
   * Proxy distant d'outils : transfère un appel d'outil vers le pont d'outils de l'hôte.
   * L'hôte renvoie { isError, value, error } — l'erreur est levée sur place, l'encapsulation uniforme est faite par le ToolRuntime local.
   * Sur 401 (jeton machine expiré/rotation des clés de l'hôte), renouvelle le jeton et réessaie une fois ; les échecs de niveau identifiants ne sont pas réessayés.
   */
  async forward(toolName: string, args: Record<string, unknown>, exec?: { signal?: AbortSignal }): Promise<unknown> {
    if (!this.config) throw new Error(t('尚未配置宿主服务，本工具需要远程执行，请先完成接入'))
    const hubUrl = this.config.hubUrl
    const executeOnce = async (): Promise<{ isError?: boolean; value?: unknown; error?: { message?: string } }> => {
      const token = await this.machineToken()
      return await this.hubCall(hubUrl, 'POST', '/api/tools/execute', {
        name: toolName,
        args,
        // Identité du nœud ≠ identité d'exécution de l'employé (D13/§10.4) : la requête transférée porte de façon additive l'enveloppe de liaison de son propre principal vérifié,
        // uniquement pour l'observation logs/attribution côté pont d'outils de l'hôte (/api/tools/execute). Frontières strictes :
        //   1. l'enveloppe ne transmet que la liaison à ses propres identifiants lors du transfert, sans aucune déclaration permettant d'élever les droits ;
        //   2. l'authentification de l'hôte reste vérifiée indépendamment par le jeton machine Bearer, ce champ ne participe jamais à la décision d'autorisation ;
        //   3. ne porte ni n'accepte aucun marqueur d'exemption « requête interne plateforme » (§10.5 : les actions internes doivent être initiées par un chemin interne de confiance).
        meta: {
          principal: {
            kind: 'machine' as const,
            principalId: this.config.principalId,
            clientId: this.config.clientId,
            clientName: this.config.clientName,
          },
        },
      }, {
        authorization: `Bearer ${token}`,
        signal: exec?.signal ?? AbortSignal.timeout(60_000),
      }) as { isError?: boolean; value?: unknown; error?: { message?: string } }
    }
    try {
      let result
      try {
        result = await executeOnce()
      } catch (error) {
        if (error instanceof HubUnauthorizedError) {
          this.cached = null
          result = await executeOnce()
        } else {
          throw error
        }
      }
      if (this.config?.lastError) {
        const { lastError: _cleared, ...rest } = this.config
        void _cleared
        this.config = rest as ConnectClientConfig
      }
      if (result && result.isError) throw new Error(result.error?.message ?? t('宿主工具执行失败'))
      return result?.value
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.noteError(`${toolName}: ${message}`)
      throw error
    }
  }

  // ------------------------------------------------- observabilité de la dégradation (OPT-P1-03)

  /** Dégradation de niveau installation (points d'extension absents, etc.) : état consigné de façon persistante, exposé explicitement par connect_status. */
  noteDegraded(reason: string, detail?: string): void {
    this.degradedReason = reason
    this.degradedDetail = detail
  }

  /**
   * Alerte d'échec de transfert (OPT-P1-03 fail-closed) : l'appelant lève déjà explicitement l'erreur sans repli local,
   * ici est émis en complément l'événement connect.degraded (throttle 60 s) pour que le bus/audit observe les dérives sémantiques du type « on croit gérer le distant alors qu'on gère le local ».
   */
  noteForwardFailure(toolName: string, error: unknown): void {
    const now = Date.now()
    if (now - this.lastForwardFailureEmitAt < 60_000) return
    this.lastForwardFailureEmitAt = now
    const message = error instanceof Error ? error.message : String(error)
    try {
      this.ctx.platformBus?.emit('connect.degraded', { reason: 'forward_failed', tool: toolName, detail: message, at: new Date().toISOString() })
    } catch { /* bus non prêt : lastError déjà consigné par noteError */ }
  }

  // ---------------------------------------------------------------- sondage d'état

  /**
   * Envoi de battement de cœur (côté accès → poussée active vers l'hôte) : POST /api/connect/heartbeat,
   * transporte les métadonnées d'exécution (nombre d'outils / version du runtime / uptime), le dernier battement est visible côté hôte dans « accès plateforme ».
   * Silencieusement ignoré si aucun hôte configuré ; l'échec est consigné par l'appelant (noteError), pas d'exception pour ne pas bloquer le minuteur.
   */
  async heartbeat(meta: { tools?: number; version?: string; uptimeSec?: number } = {}): Promise<void> {
    if (!this.config) return
    const token = await this.machineToken()
    await this.hubCall(this.config.hubUrl, 'POST', '/api/connect/heartbeat', meta, {
      authorization: `Bearer ${token}`,
    })
  }

  /** Sondage de connectivité (n'exige pas d'identifiants configurés) : santé de l'hôte + informations de la plateforme. */
  async probeHub(hubUrl?: string): Promise<{ reachable: boolean; health?: unknown; platform?: { name: string; version: string; tools: number }; error?: string }> {
    const base = normalizeBaseUrl(hubUrl ?? this.config?.hubUrl ?? '')
    if (!base) return { reachable: false, error: t('未指定宿主地址') }
    try {
      const health = await this.hubCall(base, 'GET', '/api/health') as { status?: string }
      const token = await this.machineToken().catch(() => null)
      let platform: { name: string; version: string; tools: number } | undefined
      if (token) {
        const info = await this.hubCall(base, 'GET', '/api/platform/info', undefined, { authorization: `Bearer ${token}` }) as { name?: string; version?: string; tools?: unknown[] }
        platform = { name: info?.name ?? '', version: info?.version ?? '', tools: Array.isArray(info?.tools) ? info.tools.length : 0 }
      }
      return { reachable: health?.status === 'ok', health, platform }
    } catch (error) {
      return { reachable: false, error: error instanceof Error ? error.message : String(error) }
    }
  }

  /** Instantané d'état destiné à l'Agent/à la page de configuration. */
  async status(): Promise<Record<string, unknown>> {
    const config = this.config
    const base = {
      configured: config !== null,
      toolProxy: config ? t('remote（转发宿主执行）') : t('local（本地数据）'),
      ...(this.degradedReason ? { proxyDegraded: this.degradedReason, ...(this.degradedDetail ? { degradedDetail: this.degradedDetail } : {}) } : {}),
    }
    if (!config) return { ...base, hint: t('尚未接入宿主服务：调用 connect_setup（接入码）或 connect_login（已有凭证）完成配置') }
    const probe = await this.probeHub().catch((error: unknown) => ({ reachable: false, error: error instanceof Error ? error.message : String(error) }))
    let tokenState = t('未知')
    try {
      await this.machineToken()
      tokenState = t('有效')
    } catch (error) {
      tokenState = t('异常：{reason}', { reason: error instanceof Error ? error.message : String(error) })
    }
    return {
      ...base,
      hubUrl: config.hubUrl,
      clientName: config.clientName,
      template: config.template || t('（手工配置凭证，未走接入码）'),
      principalId: config.principalId,
      enrolledAt: config.enrolledAt,
      hubReachable: (probe as { reachable?: boolean }).reachable === true,
      tokenState,
      lastError: config.lastError ?? '',
    }
  }

  // ---------------------------------------------------------------- outils internes

  private load(): ConnectClientConfig | null {
    try {
      if (!existsSync(this.configFile)) return null
      const parsed = JSON.parse(readFileSync(this.configFile, 'utf8')) as Partial<ConnectClientConfig>
      if (!parsed?.hubUrl || !parsed?.clientId || !parsed?.clientSecret) return null
      return {
        hubUrl: parsed.hubUrl,
        clientId: parsed.clientId,
        clientSecret: parsed.clientSecret,
        clientName: parsed.clientName ?? defaultClientName(),
        template: parsed.template ?? '',
        principalId: parsed.principalId ?? '',
        enrolledAt: parsed.enrolledAt ?? new Date().toISOString(),
        ...(parsed.lastError !== undefined ? { lastError: parsed.lastError } : {}),
      }
    } catch {
      return null
    }
  }

  private save(): void {
    try {
      mkdirSync(dirname(this.configFile), { recursive: true })
      writeFileSync(this.configFile, JSON.stringify(this.config, null, 2), { encoding: 'utf8', mode: 0o600 })
      try { chmodSync(this.configFile, 0o600) } catch { /* Windows n'a pas de chmod */ }
    } catch (error) {
      console.error('[connect] 客户端配置落盘失败', error)
    }
  }

  private async hubCall(base: string, method: string, path: string, body?: unknown, extra?: { authorization?: string; signal?: AbortSignal }): Promise<unknown> {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(extra?.authorization !== undefined ? { authorization: extra.authorization } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: extra?.signal ?? AbortSignal.timeout(15_000),
    }).catch((error: unknown) => {
      throw new Error(t('宿主服务不可达（{url}）：{reason}', { url: base, reason: error instanceof Error ? error.message : String(error) }))
    })
    const payload = await response.json().catch(() => null) as { ok?: boolean; data?: unknown; error?: { code?: string; message?: string } } | null
    if (response.status === 401) throw new HubUnauthorizedError(payload?.error?.message ?? t('令牌无效或已过期'))
    if (!response.ok || payload?.ok === false) {
      throw new Error(payload?.error?.message ?? t('宿主请求失败：HTTP {status}', { status: response.status }))
    }
    return payload?.data
  }
}

class HubUnauthorizedError extends Error {}

/** Détermine si un outil doit être pris en charge par le proxy distant (les propres outils connect_* s'exécutent toujours en local). */
export function isProxiedTool(name: string): boolean {
  return !name.startsWith(CONNECT_TOOLS_PREFIX)
}

export function normalizeBaseUrl(input: string): string {
  const trimmed = (input ?? '').trim().replace(/\/+$/, '')
  if (!trimmed) return ''
  if (!/^https?:\/\//.test(trimmed)) return `http://${trimmed}`
  return trimmed
}

export function defaultClientName(): string {
  return `dsh-${hostname()}`.slice(0, 60)
}
