/**
 * IdentityProviderAdapter — couche d'adaptation unifiée des sources d'identité (fusion de la conception du module OS-skill/auth-identity).
 *
 * Le flux principal de connexion programme uniquement contre cette interface, insensible aux différences DingTalk/Feishu/WeCom ;
 * ajouter une source d'identité = ajouter une implémentation d'Adapter + une ligne de configuration de connecteur.
 *
 * Double mode (conception écosystème v1.2 étape 0, résorption M7) :
 *   - real : avec appKey/appSecret configurés, passe par la vraie OpenAPI DingTalk (apiBase peut pointer vers un proxy/déploiement dédié).
 *   - mock : repli explicite sans identifiants configurés — annuaire de démonstration intégré, healthCheck marque mock:true, interdiction de se faire passer pour du réel.
 */
import { t } from '../../platform-i18n/src/index.ts'

/** Scénario de connexion : quatre formes normalisées en trois classes (auth-identity docs/04). */
export type LoginScene = 'web_qr' | 'h5' | 'in_app'

/** Dossier de personne physique normalisé — le flux principal de connexion ne reconnaît que cette structure. */
export interface NormalizedProfile {
  /** Clé unique côté plateforme utilisateur (unionId prioritaire : identifiant d'une même personne à travers applications/entreprises). */
  providerUserId: string
  corpId: string
  name: string
  email?: string
  phone?: string
  avatar?: string
}

/** Enveloppe du jeton obtenue contre le code (les différences de structure entre fournisseurs sont confinées ici). */
export interface ProviderTokenSet {
  accessToken: string
  refreshToken?: string
  expiresIn: number
  raw: unknown
}

export class ProviderAuthError extends Error {
  readonly code: string
  constructor(message: string, code = 'PROVIDER_AUTH_FAILED') {
    super(message)
    this.code = code
  }
}

export interface IdentityProviderAdapter {
  readonly type: 'dingtalk' | 'feishu' | 'wecom'
  readonly label: string
  /** Si le mode courant est le repli mock (l'endpoint IdP exposé interdit l'usage de données mock). */
  readonly mock: boolean
  /** Construit l'URL de redirection d'autorisation ou le contenu du QR (le scénario in_app peut renvoyer null, le SDK front prend le code).
   *  Avec options.promptConsent=true, force la page de confirmation d'autorisation : après l'ajout de points de permission à l'application,
   *  l'instantané d'autorisation historique des anciens utilisateurs ne contient pas le nouveau scope, une ré-autorisation est nécessaire pour le rafraîchir. */
  buildAuthorizeUrl(scene: LoginScene, state: string, redirectUri: string, options?: { promptConsent?: boolean }): Promise<string | null>
  /** code → jeton de plateforme. Le code est à consommation unique ; échec/expiration lève ProviderAuthError. */
  exchangeCode(code: string): Promise<ProviderTokenSet>
  /** Jeton de plateforme → dossier brut. */
  getUserInfo(tokenSet: ProviderTokenSet): Promise<unknown>
  /** Dossier brut → dossier normalisé (point de convergence final des différences entre les trois fournisseurs). */
  normalizeProfile(raw: unknown): NormalizedProfile
  /**
   * Pré-contrôle optionnel de disponibilité de connexion : le serveur tire une fois la page d'autorisation, identifie les refus
   * au niveau application côté IdP (DingTalk 900103 « application inexistante » = ce AppKey n'est pas dans l'application de connexion/scan non activé).
   * Si ok=false, le front ne redirige pas la page entière et affiche directement une consigne de réparation actionnable.
   */
  probeAuthorize?(redirectUri: string): Promise<{ ok: boolean; code?: string; message?: string }>
}

/** Identifiants du connecteur DingTalk (requis en mode real ; sinon repli mock). */
export interface DingTalkCredentials {
  corpId: string
  appKey: string
  appSecret: string
  /** URL de base OpenAPI (défaut https://api.dingtalk.com ; tests/déploiement dédié peuvent pointer vers un stub local). */
  apiBase?: string
  /** URL de base topapi d'annuaire (défaut https://oapi.dingtalk.com ; tests/déploiement dédié peuvent pointer vers un stub local). */
  oapiBase?: string
}

/** Annuaire de démonstration DingTalk (le mode mock partage la même donnée distante que l'OrgConnector). */
export const DINGTALK_DIRECTORY = {
  corpId: 'ding-yuanbingke',
  users: [
    { unionId: 'dd_u001', name: '陈远舟', jobNumber: 'DD0001', email: 'chenyz@yuanbingke.com' },
    { unionId: 'dd_u002', name: '林小满', jobNumber: 'DD0002', email: 'linxm@yuanbingke.com' },
    { unionId: 'dd_u003', name: '周既白', jobNumber: 'DD0003', email: 'zhoujb@yuanbingke.com' },
    { unionId: 'dd_u004', name: '苏砚秋', jobNumber: 'DD0004', email: 'suyq@yuanbingke.com' },
    { unionId: 'dd_u005', name: '何青梧', jobNumber: 'DD0005', email: 'heqw@yuanbingke.com' },
    { unionId: 'dd_u006', name: '顾星阑', jobNumber: 'DD0006', email: 'guxl@yuanbingke.com' },
    { unionId: 'dd_u007', name: '叶栖迟', jobNumber: 'DD0007', email: 'yqz@yuanbingke.com' },
  ],
} as const

/** Fenêtre de consommation unique du code : rejet du rejeu dans la fenêtre, au-delà = nouveau cycle de code d'autorisation (amical pour la démo et sémantiquement correct). */
const CODE_TTL_MS = 5 * 60_000

/** Adapter d'authentification DingTalk : implémentation de repli mock (démonstration). */
export class DingTalkAuthAdapter implements IdentityProviderAdapter {
  readonly type = 'dingtalk' as const
  readonly label = '钉钉'
  readonly mock = true
  private consumedCodes = new Map<string, number>()

  async buildAuthorizeUrl(scene: LoginScene, state: string, redirectUri: string, _options?: { promptConsent?: boolean }): Promise<string | null> {
    if (scene === 'in_app') return null
    // Sans prompt=consent : un utilisateur déjà autorisé (navigateur tenant une session DingTalk) passe silencieusement, chaîne de retour raccourcie
    // (le mock n'a pas de vraie page d'autorisation, promptConsent n'est là que pour compatibilité de signature, sans différence de comportement)
    const params = new URLSearchParams({
      client_id: 'demo-app-key',
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid corpid',
      state,
    })
    return `https://login.dingtalk.com/oauth2/auth?${params}`
  }

  async exchangeCode(code: string): Promise<ProviderTokenSet> {
    const consumedAt = this.consumedCodes.get(code)
    const now = Date.now()
    if (consumedAt !== undefined && now - consumedAt < CODE_TTL_MS) {
      throw new ProviderAuthError(t('授权码已被使用（code 仅可消费一次）'), 'CODE_REPLAY')
    }
    const user = DINGTALK_DIRECTORY.users.find((item) => item.jobNumber === code || item.unionId === code)
    if (!user) throw new ProviderAuthError(t('授权码无效或已过期'), 'INVALID_CODE')
    this.consumedCodes.set(code, now)
    return {
      accessToken: `mock-user-token-${user.unionId}-${now}`,
      expiresIn: 7200,
      raw: { unionId: user.unionId, code },
    }
  }

  async getUserInfo(tokenSet: ProviderTokenSet): Promise<unknown> {
    const raw = tokenSet.raw as { unionId: string }
    const user = DINGTALK_DIRECTORY.users.find((item) => item.unionId === raw.unionId)
    if (!user) throw new ProviderAuthError(t('用户档案不存在'), 'PROFILE_NOT_FOUND')
    return { ...user, corpId: DINGTALK_DIRECTORY.corpId }
  }

  normalizeProfile(raw: unknown): NormalizedProfile {
    const record = raw as { unionId: string; name: string; email?: string; corpId: string }
    return {
      providerUserId: record.unionId,
      corpId: record.corpId,
      name: record.name,
      ...(record.email !== undefined ? { email: record.email } : {}),
    }
  }
}

/**
 * Adapter d'authentification DingTalk : implémentation vraie OpenAPI.
 * Chaîne (alignée sur la documentation officielle DingTalk) :
 *   scan d'autorisation → POST /v1.0/oauth2/userAccessToken (clientId/clientSecret/code → accessToken)
 *   → GET /v1.0/contact/users/me（Bearer accessToken → unionId/name/email）
 */
export class RealDingTalkAuthAdapter implements IdentityProviderAdapter {
  readonly type = 'dingtalk' as const
  readonly label = '钉钉'
  readonly mock = false
  private consumedCodes = new Map<string, number>()
  private readonly credentials: DingTalkCredentials

  constructor(credentials: DingTalkCredentials) {
    this.credentials = credentials
  }

  private get apiBase(): string {
    return this.credentials.apiBase ?? 'https://api.dingtalk.com'
  }

  async buildAuthorizeUrl(scene: LoginScene, state: string, redirectUri: string, options?: { promptConsent?: boolean }): Promise<string | null> {
    if (scene === 'in_app') return null
    // Par défaut sans prompt=consent : un utilisateur déjà autorisé (navigateur tenant une session DingTalk) passe silencieusement, chaîne de retour raccourcie ;
    // le rattachement d'organisation est choisi une bonne fois par l'utilisateur sur la page DingTalk « choisir votre organisation », la plateforme n'exige plus de présélection d'entité.
    // Avec promptConsent=true, force la page de confirmation d'autorisation : après ajout de points de permission, l'instantané historique des anciens utilisateurs ne contient pas le nouveau scope,
    // le userAccessToken obtenu silencieusement prendra un 403 sur users/me (AccessTokenPermissionDenied), une ré-autorisation est nécessaire pour rafraîchir.
    const params = new URLSearchParams({
      client_id: this.credentials.appKey,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid corpid',
      state,
    })
    if (options?.promptConsent) params.set('prompt', 'consent')
    return `https://login.dingtalk.com/oauth2/auth?${params}`
  }

  /**
   * Pré-contrôle de disponibilité de connexion : tire une fois la page d'autorisation, identifie un refus au niveau application côté IdP.
   * DingTalk exprime « l'AppKey n'appartient pas à cette application de connexion / scan non activé » sous forme HTTP 200 avec
   * `__ERROR_PAGE_VARS` (errorCode 900103 « application inexistante ») : l'utilisateur ne voit dans le navigateur qu'une
   * page d'erreur sans recours ; une sonde serveur préalable permet d'afficher sur la page de connexion la consigne « quelle case activer dans la console développeur ».
   * Échec réseau/changement de structure de page = toujours considéré ok (le pré-contrôle n'est pas une barrière de connexion, seulement un enrichissement).
   */
  async probeAuthorize(redirectUri: string): Promise<{ ok: boolean; code?: string; message?: string }> {
    const params = new URLSearchParams({
      client_id: this.credentials.appKey,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid corpid',
      state: 'probe',
    })
    try {
      const response = await fetch(`https://login.dingtalk.com/oauth2/auth?${params}`, {
        headers: { 'user-agent': 'dsh-ops-authorize-probe' },
        signal: AbortSignal.timeout(5000),
      })
      const html = await response.text()
      const match = /errorCode:\s*'([^']+)'[\s\S]*?errorMsg:\s*'((?:[^'\\]|\\.)*)'/.exec(html)
      if (!match) return { ok: true }
      const raw = match[2].replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      // L'errorMsg de la page d'erreur DingTalk varie avec la langue d'interface (« 应用不存在 » en chinois / Application does not exist en anglais),
      // unification sur le code d'erreur avec un motif en chinois, pour éviter de relancer le brut de l'IdP à l'utilisateur.
      const known: Record<string, string> = {
        '900103': t('钉钉应用不存在：当前 AppKey 不是该企业已开通扫码登录的应用（或被删除/停用）'),
        '900108': t('钉钉应用未开通登录能力：需在开发者后台为企业内部应用开启「登录与分享」'),
      }
      return { ok: false, code: match[1], message: known[match[1]] ?? raw }
    } catch {
      return { ok: true }
    }
  }

  async exchangeCode(code: string): Promise<ProviderTokenSet> {
    const consumedAt = this.consumedCodes.get(code)
    const now = Date.now()
    if (consumedAt !== undefined && now - consumedAt < CODE_TTL_MS) {
      throw new ProviderAuthError(t('授权码已被使用（code 仅可消费一次）'), 'CODE_REPLAY')
    }
    const response = await fetch(`${this.apiBase}/v1.0/oauth2/userAccessToken`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientId: this.credentials.appKey,
        clientSecret: this.credentials.appSecret,
        code,
        grantType: 'authorization_code',
      }),
    })
    const payload = (await response.json().catch(() => ({}))) as {
      accessToken?: string
      refreshToken?: string
      expireIn?: number
      corpId?: string
    }
    if (!response.ok || !payload.accessToken) {
      throw new ProviderAuthError(t('钉钉 userAccessToken 换取失败（HTTP {status}）', { status: response.status }), 'INVALID_CODE')
    }
    this.consumedCodes.set(code, now)
    return {
      accessToken: payload.accessToken,
      ...(payload.refreshToken !== undefined ? { refreshToken: payload.refreshToken } : {}),
      expiresIn: payload.expireIn ?? 7200,
      raw: { accessToken: payload.accessToken, corpId: payload.corpId ?? this.credentials.corpId },
    }
  }

  async getUserInfo(tokenSet: ProviderTokenSet): Promise<unknown> {
    const response = await fetch(`${this.apiBase}/v1.0/contact/users/me`, {
      headers: { 'x-acs-dingtalk-access-token': tokenSet.accessToken },
    })
    const bodyText = await response.text().catch(() => '')
    let payload: Record<string, unknown> = {}
    try {
      payload = JSON.parse(bodyText) as Record<string, unknown>
    } catch {
      payload = {}
    }
    if (!response.ok) {
      // Exposition du diagnostic : le corps de réponse DingTalk contient errcode/message/requiredScopes, le champ entreprise sert à identifier le scénario « mauvaise organisation choisie »
      const tokenCorpId = (tokenSet.raw as { corpId?: string }).corpId ?? t('未知')
      // AccessTokenPermissionDenied (requiredScopes non couvert) : le plus souvent un instantané d'autorisation d'ancien utilisateur non rafraîchi après ajout de points de permission,
      // code d'erreur dédié pour que la couche de rappel l'identifie et relance automatiquement une ré-autorisation prompt=consent
      const scopeDenied = bodyText.includes('AccessTokenPermissionDenied')
      throw new ProviderAuthError(
        t('钉钉用户档案获取失败（HTTP {status}，token企业={corpId}）：{body}', { status: response.status, corpId: tokenCorpId, body: bodyText.slice(0, 500) }),
        scopeDenied ? 'PROVIDER_SCOPE_DENIED' : 'PROFILE_NOT_FOUND',
      )
    }
    // Priorité à l'entreprise réellement choisie par l'utilisateur sur la page de sélection DingTalk (corpId renvoyé par la réponse userAccessToken),
    // pour que « l'organisation choisie détermine l'entité sous laquelle le lien d'identité est atteint » ; sans renvoi, repli selon le rattachement du connecteur
    const rawCorpId = (tokenSet.raw as { corpId?: string }).corpId
    return { ...payload, corpId: rawCorpId || this.credentials.corpId }
  }

  normalizeProfile(raw: unknown): NormalizedProfile {
    const record = raw as { unionId?: string; userId?: string; nick?: string; name?: string; email?: string; corpId?: string }
    const providerUserId = record.unionId ?? record.userId
    if (!providerUserId) throw new ProviderAuthError(t('钉钉档案缺少 unionId/userId'), 'PROFILE_NOT_FOUND')
    return {
      providerUserId,
      corpId: record.corpId ?? this.credentials.corpId,
      name: record.name ?? record.nick ?? providerUserId,
      ...(record.email !== undefined && record.email !== '' ? { email: record.email } : {}),
    }
  }
}
