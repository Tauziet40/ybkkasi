/**
 * OIDC Provider (conception écosystème v1.2 étape 6, mode B : la plateforme comme source d'identité des applications externes).
 *
 * Mode code d'autorisation (flux d'autorisation navigateur) :
 *   GET  /oauth/authorize — valide client/redirect_uri/scope/PKCE forcé (S256), enregistre la requête d'autorisation,
 *                            302 vers la page d'autorisation plateforme /#/oauth/authorize?req=<id> (tout échec → 302 vers la page d'erreur plateforme,
 *                            jamais avec le redirect_uri externe, anti-redirection ouverte) ;
 *   POST /api/authn/oidc/authorize — l'utilisateur connecté confirme sur la page (human-only) → émission d'un code à usage unique →
 *                            renvoi de l'adresse de retour (avec code/state/iss, anti-mix-up RFC 9207) ;
 *   POST /oauth/token — le code échange une paire de jetons RS256 ; double authentification client_secret_basic et client_secret_post,
 *                            double encodage form-encoded et JSON ; grant refresh_token en rotation ;
 *   GET  /oauth/userinfo — NormalizedProfile (org/rôles/tenant), gelé/départ → 401 immédiat ;
 *   GET  /oauth/end_session — logout initié par le RP (id_token_hint localise le client, retour si postLogoutUris trouvé) ;
 *   POST /oauth/revoke — révocation de jetons RFC 7009 (liste noire jti des access / chaîne entière des refresh).
 *
 * Clés : JWKS en tableau RS256 (vérification par correspondance kid, signature toujours avec la clé la plus récente ; ancienne clé conservée 24 h en grâce pour vérification).
 * CORS : les clients purement frontend (public + PKCE) appellent en cross-origin navigateur /oauth/token, /oauth/userinfo,
 *      /oauth/revoke et les points discovery — origines autorisées = origin des redirect_uri des clients enregistrés
 *      ∪ OIDC_CORS_ORIGINS (séparés par virgules), préflight OPTIONS répond uniformément 204 (voir allowedCorsOrigins).
 * Note : /oauth/* et /.well-known/* ne sont pas soumis au middleware Bearer console (points protocole publics) ;
 *      /api/authn/oidc/auth-requests/:id est une requête publique (n'affiche que le nom du client/scope, ne divulgue pas redirect_uri).
 */
import { createHash, generateKeyPairSync, randomUUID, sign as rsSign, verify as rsVerify, createPublicKey } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, sha256Hex, newId, generateSecret, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'

/** Erreurs des points de protocole OIDC (remise en place des statuts RFC 6749 §5.2 : invalid_grant etc. → 400, invalid_client → 401). */
export class OidcEndpointError extends Error {
  status: number
  error: string
  headers: Record<string, string>
  constructor(status: number, error: string, description: string, headers: Record<string, string> = {}) {
    super(description)
    this.status = status
    this.error = error
    this.headers = headers
  }
}

export interface OidcClientRecord extends RecordBase {
  name: string
  clientId: string
  clientSecretHash: string
  redirectUris: string[]
  /** Ressource associée ('app' = Application IA / 'agent' = corps d'Agent ; renseigné lors de l'auto-émission par le owner depuis la page de détail). */
  refType?: 'app' | 'agent'
  refId?: string
  /** active par défaut (zéro migration des anciennes données). */
  status?: 'active' | 'disabled'
  /** La page d'autorisation exige-t-elle un consentement explicite de l'utilisateur. */
  consentRequired?: boolean
  /** Liste blanche des adresses de retour légitimes pour un logout initié par le RP. */
  postLogoutUris?: string[]
  description?: string
  /** confidential (détient un secret) / public (SPA pure frontend, sans secret + PKCE forcé + pas de refresh). */
  clientType?: 'confidential' | 'public'
}

/** Requête d'autorisation stockée au premier saut du flux navigateur (5 min, consommation unique). */
export interface OidcAuthRequestRecord extends RecordBase {
  clientId: string
  redirectUri: string
  state: string
  scope: string
  nonce?: string
  codeChallenge: string
  codeChallengeMethod: 'S256'
  expiresAt: string
  consumedAt?: string
  createdAt: string
}

export interface OidcCodeRecord extends RecordBase {
  clientId: string
  userId: string
  redirectUri: string
  state: string
  nonce?: string
  scope: string
  /** PKCE (S256) : l'échange de token doit porter le code_verifier correspondant (actuellement forcé). */
  codeChallenge?: string
  codeChallengeMethod?: 'S256'
  expiresAt: string
  usedAt?: string
}

/** refresh token OIDC (rotation à chaque usage ; rejeu → révocation de la chaîne entière ; stockage en hash seul). */
export interface OidcRefreshRecord extends RecordBase {
  clientId: string
  userId: string
  scope: string
  tokenHash: string
  chainId: string
  rotatedAt?: string
  revokedAt?: string
  revokedReason?: string
  expiresAt: string
}

/** RFC 7009 : liste noire de révocation des jti des access token sans état (JWT). */
export interface OidcDeniedJtiRecord extends RecordBase {
  jti: string
  expiresAt: string
  reason: string
}

interface OidcKeyMaterial {
  privatePem: string
  publicPem: string
  kid: string
  createdAt: string
  /** Horodatage de retrait de la rotation : 24 h de grâce conservant la vérification et la publication JWKS. */
  retiredAt?: string
}

/** Période de grâce de vérification/JWKS des anciennes clés (alignée sur la convention de rotation des clés de signature de session de la plateforme). */
const KEY_GRACE_MS = 24 * 3600_000
/** TTL du code d'autorisation et de la requête d'autorisation (5 min). */
const AUTHREQ_TTL_MS = (Number(process.env.OIDC_AUTHREQ_TTL_SECONDS ?? 300) || 300) * 1000
const CODE_TTL_MS = (Number(process.env.OIDC_CODE_TTL_SECONDS ?? 300) || 300) * 1000
/** TTL de l'access token (défaut 2 h, ajustable par variable d'environnement). */
const ACCESS_TTL_SECONDS = Number(process.env.OIDC_ACCESS_TTL_SECONDS ?? 7200) || 7200
/** TTL du refresh token (défaut 7 j). */
const REFRESH_TTL_SECONDS = Number(process.env.OIDC_REFRESH_TTL_SECONDS ?? 604800) || 604800

export class OidcService extends Service {
  static readonly provide = 'oidc'
  /** authn : réutilise la limitation de connexion ; resourceCore : écho du nom d'application associé aux clients OIDC (resource-core prêt avant ce service, pas de cycle). */
  static readonly inject = ['authn', 'resourceCore']

  private keys: OidcKeyMaterial[]
  private cleanupTimer: ReturnType<typeof setInterval> | undefined

  constructor(ctx: Context) {
    super(ctx, 'oidc')
    if (!process.env.OIDC_ISSUER) {
      ctx.logger('oidc').info(
        '未配置 OIDC_ISSUER：issuer 按请求 Host/X-Forwarded-* 头派生（反代/公网域名部署开箱可用，#15）；' +
        '多域名或需要固定 issuer 锚点的部署请显式声明 OIDC_ISSUER（见 docs/app-sso-integration.md）',
      )
    }
    this.keys = this.loadOrCreateKeys()
    this.registerRoutes()
    this.cleanupExpired()
    this.cleanupTimer = setInterval(() => this.cleanupExpired(), 24 * 3600_000)
    this.cleanupTimer.unref?.() // OPT-P3-02
    ctx.effect(() => () => {
      if (this.cleanupTimer) clearInterval(this.cleanupTimer)
    })
    // -- Cascades du cycle de vie (noms d'événements réels, voir platform-core/src/bus.ts) --------------------------
    // Application retirée/archivée → client associé désactivé (chaînes de refresh révoquées ensemble) ; remise en ligne/restauration → réactivation ; renommage → synchronisation
    ctx.platformBus.on(PlatformEvents.AppOfflined, (payload) => {
      const { id } = payload as { id: string }
      for (const client of this.clientsForApp(id)) this.disableClient(client.id, t('应用下线联动'))
    })
    ctx.platformBus.on(PlatformEvents.AppArchived, (payload) => {
      const { id } = payload as { id: string }
      for (const client of this.clientsForApp(id)) this.disableClient(client.id, t('应用归档联动'))
    })
    ctx.platformBus.on(PlatformEvents.AppOnlined, (payload) => {
      const { id } = payload as { id: string }
      for (const client of this.clientsForApp(id)) this.enableClient(client.id)
    })
    ctx.platformBus.on(PlatformEvents.AppUpdated, (payload) => {
      const { id, name } = payload as { id: string; name: string }
      for (const client of this.clientsForApp(id)) this.updateClient(client.id, { name })
    })
    // Agent mis hors ligne → client associé désactivé (chaînes de refresh révoquées ensemble) ; remise en ligne/restauration → réactivation (association OIDC-agent)
    ctx.platformBus.on(PlatformEvents.AgentOfflined, (payload) => {
      const { id } = payload as { id: string }
      for (const client of this.clientsForAgent(id)) this.disableClient(client.id, t('Agent 下线联动'))
    })
    ctx.platformBus.on(PlatformEvents.AgentOnlined, (payload) => {
      const { id } = payload as { id: string }
      for (const client of this.clientsForAgent(id)) this.enableClient(client.id)
    })
    // Compte gelé/désactivé → toutes les chaînes de refresh OIDC de cet utilisateur s'invalident immédiatement (sans attendre l'expiration)
    ctx.platformBus.on(PlatformEvents.UserFrozen, (payload) => {
      const { userId, reason } = payload as { userId: string; reason: string }
      this.revokeUserRefreshChains(userId, t('账号冻结联动：{reason}', { reason }))
    })
  }

  /**
   * Émetteur issuer (#15, 2026-10-29) : priorité de résolution —
   *   1. déclaration explicite OIDC_ISSUER (ancre fixe des déploiements multi-domaines/stricts, priorité maximale) ;
   *   2. dérivation par requête : x-forwarded-host/host + x-forwarded-proto (scénario reverse proxy, même périmètre que requestOrigin de console
   *      ) + préfixe externalBase — sur un déploiement à domaine public, discovery/émission/vérification s'alignent automatiquement, le SSO distant marche d'emblée ;
   *   3. repli http://127.0.0.1:<port><base> (débogage local).
   * Sans contexte de requête, comportement historique conservé (env ?? boucle locale) — les appels hors facette requête (tests/validations internes) ne perçoivent rien.
   *
   * Revue sécurité P1-06 (2026-10-31) : la dérivation par requête dépend d'en-têtes externes (x-forwarded-host/host) et peut, sur Internet public,
   * être falsifiée pour réécrire les métadonnées de discovery. Règles de convergence :
   *   - OIDC_ISSUER défini → valeur fixe toujours renvoyée, plus de dérivation par requête (émetteur fixe) ;
   *   - non défini : l'hôte dérivé n'est admis que s'il figure dans la liste blanche OIDC_TRUSTED_HOSTS (correspondance exacte, séparée par virgules),
   *     sinon repli sur la boucle locale (fail-closed) — un déploiement public doit configurer explicitement l'un des deux.
   */
  issuer(origin?: { headers: import('node:http').IncomingHttpHeaders }): string {
    if (process.env.OIDC_ISSUER) return process.env.OIDC_ISSUER
    const derived = this.deriveIssuerFromRequest(origin)
    return derived ?? `http://127.0.0.1:${this.ctx.httpServer.port}${this.ctx.httpServer.externalBase}`
  }

  /** Dérive l'issuer externe depuis les en-têtes de requête (undefined si host absent/hors liste blanche → repli). */
  private deriveIssuerFromRequest(origin?: { headers: import('node:http').IncomingHttpHeaders }): string | undefined {
    if (!origin) return undefined
    const header = (name: string): string | undefined => {
      const value = origin.headers[name]
      return value === undefined ? undefined : String(Array.isArray(value) ? value[0] : value)
    }
    const host = header('x-forwarded-host') ?? header('host')
    if (!host) return undefined
    const trusted = new Set(String(process.env.OIDC_TRUSTED_HOSTS ?? '')
      .split(',').map((item) => item.trim().toLowerCase()).filter(Boolean))
    // Hôtes en boucle locale implicitement dignes de confiance (les flux locaux comme les retours same-origin dsh-bridge en dépendent) : un Host: 127.x falsifié ne peut rediriger
    // que vers la propre machine de l'attaquant, aucune cible à blesser ; les hôtes hors boucle locale doivent être explicitement enregistrés dans la liste blanche.
    // L'en-tête host peut porter un port (127.0.0.1:7300) : parsing URL pour extraire le nom d'hôte nu avant comparaison.
    let hostname = ''
    try { hostname = new URL(`http://${host}`).hostname.toLowerCase() } catch { hostname = '' }
    const loopback = hostname === 'localhost' || hostname === '::1' || hostname === '0.0.0.0' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
    if (!loopback && !trusted.has(hostname)) return undefined
    const proto = header('x-forwarded-proto') ?? 'http'
    return `${proto}://${host}${this.webBase()}`
  }

  /** Ensemble des issuers acceptables pour la vérification JWT : OIDC_ISSUER défini → valeur fixe seule ; sinon union avec les valeurs dérivées de la liste blanche de confiance. */
  private acceptedIssuers(origin?: { headers: import('node:http').IncomingHttpHeaders }): string[] {
    const staticIssuer = this.issuer()
    const derived = this.deriveIssuerFromRequest(origin)
    return derived !== undefined && derived !== staticIssuer ? [staticIssuer, derived] : [staticIssuer]
  }

  /** Préfixe externe des pages internes de la SPA plateforme ('' en forme autonome, '/rq' en forme montée dsh). */
  private webBase(): string {
    return this.ctx.httpServer?.externalBase ?? ''
  }

  clients(): Collection<OidcClientRecord> {
    const collection = this.ctx.opsStorage.collection<OidcClientRecord>('authn:oidcClients')
    collection.uniqueOn('oidc_client_id', (item) => item.clientId)
    return collection
  }

  codes(): Collection<OidcCodeRecord> {
    return this.ctx.opsStorage.collection<OidcCodeRecord>('authn:oidcCodes')
  }

  authRequests(): Collection<OidcAuthRequestRecord> {
    return this.ctx.opsStorage.collection<OidcAuthRequestRecord>('authn:oidcAuthRequests')
  }

  refreshTokens(): Collection<OidcRefreshRecord> {
    return this.ctx.opsStorage.collection<OidcRefreshRecord>('authn:oidcRefreshTokens')
  }

  deniedJtis(): Collection<OidcDeniedJtiRecord> {
    return this.ctx.opsStorage.collection<OidcDeniedJtiRecord>('authn:oidcDeniedJtis')
  }

  clientByClientId(clientId: string): OidcClientRecord | undefined {
    return this.clients().findOne((item) => item.clientId === clientId)
  }

  clientsForAgent(agentId: string): OidcClientRecord[] {
    return this.clients().find((item) => item.refType === 'agent' && item.refId === agentId)
  }

  clientsForApp(appId: string): OidcClientRecord[] {
    return this.clients().find((item) => item.refType === 'app' && item.refId === appId)
  }

  static isClientActive(client: OidcClientRecord): boolean {
    return (client.status ?? 'active') === 'active'
  }

  // -- Cycle de vie des clients -------------------------------------------------------

  /** Anonymisation externe (QA SEC-02) : clientSecretHash est un hash d'identifiant, jamais expédié dans les réponses de liste/détail des clients (même périmètre d'anonymisation que principals) ; la validation interne passe toujours par les enregistrements bruts clients()/clientByClientId(). */
  private publicClient<C extends OidcClientRecord>(client: C): Omit<C, 'clientSecretHash'> {
    const { clientSecretHash, ...safe } = client
    void clientSecretHash
    return safe
  }

  createClient(input: {
    name: string
    redirectUris: string[]
    description?: string
    consentRequired?: boolean
    postLogoutUris?: string[]
    clientType?: 'confidential' | 'public'
    refType?: 'app' | 'agent'
    refId?: string
  }): { client: Omit<OidcClientRecord, 'clientSecretHash'>; clientSecret: string } {
    const clientType = input.clientType ?? 'confidential'
    const clientId = 'oc-' + newId('id').slice(3)
    // Les clients public n'ont pas de secret (PKCE forcé, pas de refresh) ; les confidential le génèrent une fois
    const clientSecret = clientType === 'public' ? '' : generateSecret('ocs')
    const client = this.clients().insert({
      id: newId('oc'),
      name: input.name,
      clientId,
      clientSecretHash: clientType === 'public' ? '' : sha256Hex(clientSecret),
      redirectUris: input.redirectUris,
      ...(input.description !== undefined ? { description: input.description } : {}),
      ...(input.consentRequired !== undefined ? { consentRequired: input.consentRequired } : {}),
      ...(input.postLogoutUris !== undefined ? { postLogoutUris: input.postLogoutUris } : {}),
      clientType,
      ...(input.refType !== undefined ? { refType: input.refType } : {}),
      ...(input.refId !== undefined ? { refId: input.refId } : {}),
    })
    return { client: this.publicClient(client), clientSecret }
  }

  listClients(): Array<Omit<OidcClientRecord, 'clientSecretHash'> & { refAppName?: string; refAgentName?: string }> {
    return this.clients().all().map((client) => this.publicClient({
      ...client,
      ...(client.refType === 'app' && client.refId
        ? { refAppName: this.ctx.resourceCore?.get('app', client.refId)?.name ?? client.refId }
        : {}),
      ...(client.refType === 'agent' && client.refId
        ? { refAgentName: this.ctx.resourceCore?.get('agent', client.refId)?.name ?? client.refId }
        : {}),
    }))
  }

  updateClient(id: string, patch: { name?: string; redirectUris?: string[]; description?: string; consentRequired?: boolean; postLogoutUris?: string[] }): Omit<OidcClientRecord, 'clientSecretHash'> {
    return this.publicClient(this.clients().update(id, patch))
  }

  /** Rotation du secret : ancienne valeur invalidée immédiatement, la nouvelle n'est renvoyée que cette fois. */
  rotateSecret(id: string): { client: Omit<OidcClientRecord, 'clientSecretHash'>; clientSecret: string } {
    const client = this.clients().get(id)
    if (!client) throw new Error(t('OIDC 客户端不存在：{id}', { id }))
    if ((client.clientType ?? 'confidential') === 'public') throw new Error(t('public 客户端无 secret，无需轮换'))
    const clientSecret = generateSecret('ocs')
    const updated = this.clients().update(id, { clientSecretHash: sha256Hex(clientSecret) })
    return { client: this.publicClient(updated), clientSecret }
  }

  disableClient(id: string, reason: string): Omit<OidcClientRecord, 'clientSecretHash'> {
    const client = this.clients().get(id)
    if (!client) throw new Error(t('OIDC 客户端不存在：{id}', { id }))
    this.revokeClientRefreshChains(client.clientId, t('客户端禁用联动：{reason}', { reason }))
    return this.publicClient(this.clients().update(id, { status: 'disabled' }))
  }

  enableClient(id: string): Omit<OidcClientRecord, 'clientSecretHash'> {
    return this.publicClient(this.clients().update(id, { status: 'active' }))
  }

  // -- Flux d'autorisation navigateur ---------------------------------------------------------

  /** Liste blanche des scopes émis (aucune demande arbitraire ne doit entrer telle quelle dans le JWT). */
  static readonly ALLOWED_SCOPES = ['openid', 'profile', 'email']

  /** Validation du format du code d'autorisation (S256 : 43-128 caractères base64url attendus). */
  private static assertPkceChallenge(challenge: string | undefined): void {
    if (challenge === undefined || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) {
      throw new OidcEndpointError(302, 'invalid_request', t('缺少或非法的 code_challenge（本 Provider 强制 PKCE S256，43-128 位 base64url）'))
    }
  }

  /**
   * Initie l'autorisation (GET /oauth/authorize) : validation de la facette protocole → enregistrement de la requête → 302 vers la page d'autorisation plateforme.
   * Tout échec de validation lève OidcEndpointError (la couche de routes répond uniformément 302 vers la page d'erreur plateforme, sans redirect_uri externe).
   */
  beginAuthorization(input: {
    responseType?: string
    clientId?: string
    redirectUri?: string
    state?: string
    scope?: string
    nonce?: string
    codeChallenge?: string
    codeChallengeMethod?: string
  }): OidcAuthRequestRecord {
    if (input.responseType !== 'code') {
      throw new OidcEndpointError(302, 'unsupported_response_type', t('response_type 仅支持 code（收到：{received}）', { received: input.responseType ?? t('缺失') }))
    }
    if (!input.state) throw new OidcEndpointError(302, 'invalid_request', t('state 必填（CSRF 防护）'))
    const client = this.clientByClientId(String(input.clientId ?? ''))
    if (!client) throw new OidcEndpointError(302, 'unauthorized_client', t('OIDC 客户端不存在：{id}', { id: input.clientId ?? t('缺失') }))
    if (!OidcService.isClientActive(client)) throw new OidcEndpointError(302, 'unauthorized_client', t('OIDC 客户端已禁用，请联系管理员'))
    const redirectUri = input.redirectUri ?? client.redirectUris[0]
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      throw new OidcEndpointError(302, 'invalid_request', t('redirect_uri 未登记在客户端白名单'))
    }
    const scopes = (input.scope ?? 'openid profile').split(/\s+/).filter(Boolean)
    const offender = scopes.find((scope) => !OidcService.ALLOWED_SCOPES.includes(scope))
    if (offender) throw new OidcEndpointError(302, 'invalid_scope', t('scope 未获授权：{scope}（允许：{allowed}）', { scope: offender, allowed: OidcService.ALLOWED_SCOPES.join(' ') }))
    if (input.codeChallengeMethod !== undefined && input.codeChallengeMethod !== 'S256') {
      throw new OidcEndpointError(302, 'invalid_request', t('code_challenge_method 仅支持 S256'))
    }
    OidcService.assertPkceChallenge(input.codeChallenge)
    return this.authRequests().insert({
      id: randomUUID(),
      clientId: client.clientId,
      redirectUri,
      state: input.state,
      scope: scopes.join(' '),
      ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
      codeChallenge: input.codeChallenge!,
      codeChallengeMethod: 'S256' as const,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + AUTHREQ_TTL_MS).toISOString(),
    })
  }

  /** Requête publique de la page d'autorisation (ne divulgue pas redirect_uri / secret ni les champs internes). */
  authRequestInfo(reqId: string): { clientName: string; appRef?: { id: string; name: string }; scope: string; consentRequired: boolean } {
    const req = this.authRequests().get(reqId)
    if (!req || req.consumedAt || new Date(req.expiresAt).getTime() < Date.now()) {
      throw new Error(t('授权请求无效、已使用或已过期'))
    }
    const client = this.clientByClientId(req.clientId)
    if (!client || !OidcService.isClientActive(client)) throw new Error(t('OIDC 客户端不可用'))
    const appRef = client.refType === 'app' && client.refId
      ? (() => {
          const app = this.ctx.resourceCore?.get('app', client.refId!)
          return app ? { id: app.id, name: app.name } : undefined
        })()
      : undefined
    return {
      clientName: client.name,
      ...(appRef !== undefined ? { appRef } : {}),
      scope: req.scope,
      consentRequired: client.consentRequired === true,
    }
  }

  /**
   * Confirmation de la page d'autorisation (POST /api/authn/oidc/authorize, human-only) :
   * validation de la requête d'autorisation → (consentement explicite obligatoire si exigé) → émission d'un code à usage unique → renvoi de l'adresse de retour.
   * consent explicitement false → retour access_denied + événement denied ; défaut → 400 (consentement non exprimé).
   */
  completeAuthorization(input: { reqId: string; userId: string; consent?: boolean }, origin?: { headers: import('node:http').IncomingHttpHeaders }): { location: string } {
    const req = this.authRequests().get(input.reqId)
    if (!req) throw new Error(t('授权请求无效（reqId 错误或已被清理）'))
    if (req.consumedAt) throw new Error(t('授权请求已被使用（单次消费，防重放）'))
    if (new Date(req.expiresAt).getTime() < Date.now()) throw new Error(t('授权请求已过期，请从应用重新发起'))
    const client = this.clientByClientId(req.clientId)
    if (!client) throw new Error(t('授权请求指向的客户端不存在'))
    if (!OidcService.isClientActive(client)) throw new Error(t('OIDC 客户端已禁用，无法完成授权'))
    const user = this.ctx.iam.users().get(input.userId)
    if (!user) throw new Error(t('用户不存在'))
    if (user.status !== 'active') throw new Error(t('账号状态异常，无法授权'))
    if (client.consentRequired === true && input.consent !== true) {
      if (input.consent === undefined) throw new Error(t('该应用要求显式同意后才能授权'))
      // Refus explicite : redirect_uri déjà dans la liste blanche, retour access_denied selon RFC
      this.authRequests().update(req.id, { consumedAt: new Date().toISOString() })
      this.ctx.platformBus.emit(PlatformEvents.OidcAuthorizeDenied, {
        reqId: req.id, clientId: client.clientId, clientName: client.name, userId: user.id, userName: user.displayName,
      })
      return { location: withQuery(req.redirectUri, { error: 'access_denied', error_description: t('用户拒绝授权'), state: req.state }) }
    }
    const code = this.issueCode({ ...req, userId: user.id })
    this.authRequests().update(req.id, { consumedAt: new Date().toISOString() })
    this.ctx.platformBus.emit(PlatformEvents.OidcAuthorizeGranted, {
      reqId: req.id, clientId: client.clientId, clientName: client.name, userId: user.id, userName: user.displayName, scope: req.scope,
    })
    // Paramètre de retour iss (anti-mix-up RFC 9207) — #15 : dérivé de la facette requête, cohérent avec discovery
    return { location: withQuery(req.redirectUri, { code, state: req.state, iss: this.issuer(origin) }) }
  }

  private issueCode(req: { clientId: string; userId: string; redirectUri: string; state: string; scope: string; nonce?: string; codeChallenge: string }): string {
    const code = randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '')
    this.codes().insert({
      id: code,
      clientId: req.clientId,
      userId: req.userId,
      redirectUri: req.redirectUri,
      state: req.state,
      ...(req.nonce !== undefined ? { nonce: req.nonce } : {}),
      scope: req.scope,
      codeChallenge: req.codeChallenge,
      codeChallengeMethod: 'S256' as const,
      expiresAt: new Date(Date.now() + CODE_TTL_MS).toISOString(),
    })
    return code
  }

  // -- Échange / rafraîchissement -----------------------------------------------------------

  /** Authentification du client : formes Basic et Post ; les clients public sont exemptés de secret. Les échecs alimentent le verrouillage anti-force-brute. */
  private authenticateClient(clientId: string | undefined, clientSecret: string | undefined): OidcClientRecord {
    const invalidClient = (description: string): OidcEndpointError =>
      new OidcEndpointError(401, 'invalid_client', description, { 'www-authenticate': 'Basic realm="dsh-ops-oidc"' })
    if (!clientId) throw invalidClient(t('缺少 client_id'))
    const client = this.clientByClientId(clientId)
    if (!client) throw invalidClient(t('client_id 不存在：{clientId}', { clientId }))
    if (!OidcService.isClientActive(client)) throw invalidClient(t('OIDC 客户端已禁用'))
    if ((client.clientType ?? 'confidential') === 'confidential') {
      if (!clientSecret) throw invalidClient(t('缺少 client_secret'))
      if (client.clientSecretHash !== sha256Hex(clientSecret)) {
        // Le client_secret alimente aussi le verrouillage d'échecs (pas de devinette de secrets par force brute)
        this.ctx.authn.recordLoginFailure(`oidc-token:${clientId}`)
        throw invalidClient(t('client_secret 错误'))
      }
    }
    this.ctx.authn.recordLoginSuccess(`oidc-token:${clientId}`)
    return client
  }

  /**
   * /oauth/token : authorization_code (PKCE validé forcé, code à consommation unique) et refresh_token (rotation + révocation de chaîne au rejeu).
   */
  token(input: {
    grantType: string
    clientId?: string
    clientSecret?: string
    code?: string
    redirectUri?: string
    codeVerifier?: string
    refreshToken?: string
    scope?: string
  }, origin?: { headers: import('node:http').IncomingHttpHeaders }): { access_token: string; id_token: string; token_type: 'Bearer'; expires_in: number; scope: string; refresh_token?: string } {
    const client = this.authenticateClient(input.clientId, input.clientSecret)
    if (input.grantType === 'authorization_code') return this.authorizationCodeGrant(client, input, origin)
    if (input.grantType === 'refresh_token') return this.refreshGrant(client, input, origin)
    throw new OidcEndpointError(400, 'unsupported_grant_type', t('不支持的 grant_type：{grantType}', { grantType: input.grantType }))
  }

  private authorizationCodeGrant(client: OidcClientRecord, input: { code?: string; redirectUri?: string; codeVerifier?: string }, origin?: { headers: import('node:http').IncomingHttpHeaders }): ReturnType<OidcService['issueTokenSet']> {
    const bad = (description: string): OidcEndpointError => new OidcEndpointError(400, 'invalid_grant', description)
    if (!input.code) throw new OidcEndpointError(400, 'invalid_request', t('code 必填'))
    const record = this.codes().get(input.code)
    if (!record) throw bad(t('授权码无效'))
    if (record.usedAt) throw bad(t('授权码已被使用（单次消费，防重放）'))
    if (new Date(record.expiresAt).getTime() < Date.now()) throw bad(t('授权码已过期'))
    if (record.clientId !== client.clientId) throw bad(t('授权码与客户端不匹配'))
    if (input.redirectUri && input.redirectUri !== record.redirectUri) throw bad(t('redirect_uri 与授权时不一致'))
    // PKCE (S256) : BASE64URL(SHA256(code_verifier)) doit correspondre au challenge enregistré à l'autorisation
    if (!record.codeChallenge) throw bad(t('授权未登记 PKCE challenge'))
    if (!input.codeVerifier) throw bad(t('授权使用了 PKCE，token 请求必须携带 code_verifier'))
    const derived = createHash('sha256').update(input.codeVerifier).digest('base64url')
    if (derived !== record.codeChallenge) throw bad(t('PKCE 校验失败：code_verifier 不匹配'))
    this.codes().update(record.id, { usedAt: new Date().toISOString() })
    const user = this.ctx.iam.users().get(record.userId)
    if (!user || user.status !== 'active') throw bad(t('用户状态异常，无法签发令牌'))
    return this.issueTokenSet(client, { userId: record.userId, scope: record.scope, ...(record.nonce !== undefined ? { nonce: record.nonce } : {}) }, origin)
  }

  private refreshGrant(client: OidcClientRecord, input: { refreshToken?: string; scope?: string }, origin?: { headers: import('node:http').IncomingHttpHeaders }): ReturnType<OidcService['issueTokenSet']> {
    const bad = (description: string): OidcEndpointError => new OidcEndpointError(400, 'invalid_grant', description)
    if (!input.refreshToken) throw new OidcEndpointError(400, 'invalid_request', t('refresh_token 必填'))
    if ((client.clientType ?? 'confidential') === 'public') throw bad(t('public 客户端不签发 refresh token'))
    const hash = sha256Hex(input.refreshToken)
    const record = this.refreshTokens().findOne((item) => item.tokenHash === hash)
    if (!record || record.clientId !== client.clientId) throw bad(t('refresh token 无效'))
    if (record.revokedAt) throw bad(t('refresh token 已吊销：{reason}', { reason: record.revokedReason ?? '' }))
    if (new Date(record.expiresAt).getTime() < Date.now()) throw bad(t('refresh token 已过期，请重新授权'))
    if (record.rotatedAt) {
      this.revokeRefreshChain(record.chainId, t('refresh token 重放检测（原轮转于 {at}）', { at: record.rotatedAt }))
      throw bad(t('检测到 refresh token 重放：该授权链已整体吊销，请重新发起授权'))
    }
    // Nécessaire à la sécurité : validation en temps réel de l'état utilisateur à l'échange (gelé/départ → invalidation immédiate, sans attendre l'expiration)
    const user = this.ctx.iam.users().get(record.userId)
    if (!user || user.status !== 'active') throw bad(t('用户状态异常（冻结/离职联动失效）'))
    // Le scope ne peut que se resserrer
    const granted = record.scope.split(/\s+/).filter(Boolean)
    const requested = input.scope !== undefined ? input.scope.split(/\s+/).filter(Boolean) : granted
    const widened = requested.find((scope) => !granted.includes(scope))
    if (widened) throw new OidcEndpointError(400, 'invalid_scope', t('refresh 只允许收窄 scope：{scopes} 未在原授权范围内', { scopes: widened }))
    const scope = requested.join(' ')
    this.refreshTokens().update(record.id, { rotatedAt: new Date().toISOString() })
    const tokenSet = this.issueTokenSet(client, { userId: record.userId, scope, chainId: record.chainId }, origin)
    return tokenSet
  }

  private issueTokenSet(client: OidcClientRecord, granted: { userId: string; scope: string; nonce?: string; chainId?: string }, origin?: { headers: import('node:http').IncomingHttpHeaders }): { access_token: string; id_token: string; token_type: 'Bearer'; expires_in: number; scope: string; refresh_token?: string } {
    const nowSec = Math.floor(Date.now() / 1000)
    const user = this.ctx.iam.users().get(granted.userId)
    const payload = {
      // #15 : iss dérivé de la facette requête (déclaration explicite env prioritaire), aligné sur discovery
      iss: this.issuer(origin),
      sub: granted.userId,
      aud: client.clientId,
      azp: client.clientId,
      iat: nowSec,
      exp: nowSec + ACCESS_TTL_SECONDS,
      jti: randomUUID(),
      scope: granted.scope,
      ...(granted.nonce !== undefined ? { nonce: granted.nonce } : {}),
      ...(user !== undefined ? { preferred_username: user.username, name: user.displayName } : {}),
    }
    // Distinction des types de token (surface de convergence : quand access/id sont isomorphes, userinfo ne peut les distinguer, marquage obligatoire avant envoi)
    const access = this.signJwt({ ...payload, token_use: 'access' })
    const idToken = this.signJwt({ ...payload, token_use: 'id' })
    const result: { access_token: string; id_token: string; token_type: 'Bearer'; expires_in: number; scope: string; refresh_token?: string } = {
      access_token: access,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_SECONDS,
      scope: granted.scope,
    }
    if ((client.clientType ?? 'confidential') === 'confidential') {
      // Le refresh n'est stocké qu'en hash ; le clair otr_ n'apparaît que cette fois ; rotation sur la même chaîne (détection de rejeu → révocation par chaîne)
      const refreshRaw = 'otr_' + randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '')
      this.refreshTokens().insert({
        id: newId('ort'),
        clientId: client.clientId,
        userId: granted.userId,
        scope: granted.scope,
        tokenHash: sha256Hex(refreshRaw),
        chainId: granted.chainId ?? newId('rchain'),
        expiresAt: new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString(),
      })
      result.refresh_token = refreshRaw
    }
    return result
  }

  // -- Facette de révocation ---------------------------------------------------------------

  revokeRefreshChain(chainId: string, reason: string): number {
    let count = 0
    for (const record of this.refreshTokens().find((item) => item.chainId === chainId && !item.revokedAt)) {
      this.refreshTokens().update(record.id, { revokedAt: new Date().toISOString(), revokedReason: reason })
      count++
    }
    return count
  }

  revokeUserRefreshChains(userId: string, reason: string): number {
    let count = 0
    for (const record of this.refreshTokens().find((item) => item.userId === userId && !item.revokedAt)) {
      this.refreshTokens().update(record.id, { revokedAt: new Date().toISOString(), revokedReason: reason })
      count++
    }
    return count
  }

  private revokeClientRefreshChains(clientId: string, reason: string): number {
    let count = 0
    for (const record of this.refreshTokens().find((item) => item.clientId === clientId && !item.revokedAt)) {
      this.refreshTokens().update(record.id, { revokedAt: new Date().toISOString(), revokedReason: reason })
      count++
    }
    return count
  }

  /** RFC 7009 /oauth/revoke : access (liste noire jti) ou refresh (chaîne entière) ; toujours 200. */
  revokeToken(input: { clientId?: string; clientSecret?: string; token?: string; tokenTypeHint?: string }, origin?: { headers: import('node:http').IncomingHttpHeaders }): void {
    const client = this.authenticateClient(input.clientId, input.clientSecret)
    if (!input.token) return
    if (input.token.startsWith('otr_') || input.tokenTypeHint === 'refresh_token') {
      const hash = sha256Hex(input.token)
      const record = this.refreshTokens().findOne((item) => item.tokenHash === hash)
      if (record && record.clientId === client.clientId) this.revokeRefreshChain(record.chainId, t('客户端主动吊销（RFC 7009）'))
      return
    }
    try {
      const claims = this.verifyJwt(input.token, { audience: undefined, ...(origin !== undefined ? { origin } : {}) })
      if (claims.aud !== client.clientId) return
      this.deniedJtis().insert({
        id: newId('odj'),
        jti: String(claims.jti ?? ''),
        expiresAt: new Date((typeof claims.exp === 'number' ? claims.exp : Math.floor(Date.now() / 1000)) * 1000).toISOString(),
        reason: t('客户端主动吊销（RFC 7009）'),
      })
    } catch { /* token inexploitable : silencieux et toujours 200 selon RFC */ }
  }

  private isJtiDenied(jti: unknown): boolean {
    if (typeof jti !== 'string' || !jti) return false
    const record = this.deniedJtis().findOne((item) => item.jti === jti)
    return record !== undefined && new Date(record.expiresAt).getTime() > Date.now()
  }

  // -- Logout initié par le RP -----------------------------------------------------------

  /**
   * GET /oauth/end_session : vérification de id_token_hint pour localiser le client → révocation des
   * chaînes de refresh de cet utilisateur chez ce client → retour si l'adresse est dans postLogoutUris → 302 vers la page de logout plateforme (la page purge la session puis revient avec state).
   * Sans post_logout_redirect_uri (RP léger ne passant que id_token_hint), si ce client n'a enregistré
   * qu'une seule adresse de retour de logout, retour selon l'intention enregistrée — toujours sous liste blanche, un argument explicite invalide reste refusé (anti-redirection ouverte).
   */
  endSession(input: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string }, origin?: { headers: import('node:http').IncomingHttpHeaders }): { location: string } {
    if (!input.idTokenHint) throw new OidcEndpointError(302, 'invalid_request', t('缺少 id_token_hint'))
    let claims: Record<string, unknown>
    try {
      claims = this.verifyJwt(input.idTokenHint, { audience: undefined, ...(origin !== undefined ? { origin } : {}) })
    } catch (error) {
      throw new OidcEndpointError(302, 'invalid_request', t('id_token_hint 验签失败：{message}', { message: error instanceof Error ? error.message : String(error) }))
    }
    const client = this.clientByClientId(String(claims.aud ?? ''))
    if (!client) throw new OidcEndpointError(302, 'invalid_request', t('id_token_hint 受众（aud）未命中已登记客户端'))
    // Le logout coupe le renouvellement silencieux : révocation de toutes les chaînes de refresh de cet utilisateur chez ce client
    const userId = String(claims.sub ?? '')
    for (const record of this.refreshTokens().find((item) => item.clientId === client.clientId && item.userId === userId && !item.revokedAt)) {
      this.refreshTokens().update(record.id, { revokedAt: new Date().toISOString(), revokedReason: t('RP 发起登出联动') })
    }
    // Sauts internes de la SPA plateforme : la query converge dans le hash (même convention que les routes de la console)
    const logoutParams = new URLSearchParams({
      ...(input.postLogoutRedirectUri !== undefined ? { post_logout_redirect_uri: input.postLogoutRedirectUri } : {}),
      ...(input.state !== undefined ? { state: input.state } : {}),
      client: client.name,
    })
    const logoutPage = `${this.webBase()}/#/oauth/logout?${logoutParams.toString()}`
    const whitelist = client.postLogoutUris ?? []
    if (input.postLogoutRedirectUri === undefined) {
      // Le RP n'a pas passé d'argument de retour : retour selon l'intention enregistrée seulement si une unique adresse de logout est enregistrée ; sinon (ou plusieurs candidates) on reste sur la page de logout plateforme
      if (whitelist.length === 1) {
        logoutParams.set('post_logout_redirect_uri', whitelist[0]!)
        return { location: `${this.webBase()}/#/oauth/logout?${logoutParams.toString()}` }
      }
      return { location: logoutPage }
    }
    if (!whitelist.includes(input.postLogoutRedirectUri)) {
      // Retour invalide : seule la page d'erreur plateforme, jamais de redirection ouverte
      throw new OidcEndpointError(302, 'invalid_request', t('post_logout_redirect_uri 未登记在客户端登出白名单'))
    }
    return { location: logoutPage }
  }

  // -- userinfo ---------------------------------------------------------------

  /** userinfo : n'accepte que des access token (validation token_use) + aud devant toucher un client valide + état utilisateur en temps réel ; origin fourni → iss accepte aussi la valeur dérivée de la requête (#15). */
  userinfo(accessToken: string, origin?: { headers: import('node:http').IncomingHttpHeaders }): Record<string, unknown> {
    const claims = this.verifyJwt(accessToken, { audience: undefined, ...(origin !== undefined ? { origin } : {}) })
    if (claims.token_use !== 'access') throw new Error(t('该端点仅接受 access token（id_token 不能直接调 userinfo）'))
    const client = this.clientByClientId(String(claims.aud ?? ''))
    if (!client || !OidcService.isClientActive(client)) throw new Error(t('token 受众（aud）不是有效客户端'))
    if (this.isJtiDenied(claims.jti)) throw new Error(t('token 已被吊销（RFC 7009）'))
    const user = this.ctx.iam.users().get(claims.sub ?? '')
    if (!user) throw new Error(t('用户不存在'))
    if (user.status !== 'active') throw new Error(t('用户状态异常（冻结/离职联动失效）'))
    const org = this.ctx.iam.orgs().get(user.orgId)
    const scopes = String(claims.scope ?? '').split(/\s+/)
    return {
      sub: user.id,
      preferred_username: user.username,
      name: user.displayName,
      // Le claim email est rogné selon le scope (sans demande du scope email, pas d'envoi)
      ...(scopes.includes('email') && user.email ? { email: user.email } : {}),
      org: org !== undefined ? { id: org.id, name: org.name, tenantId: org.tenantId ?? 't_default' } : null,
      roles: user.roleIds.map((roleId) => this.ctx.iam.roles().get(roleId)?.code).filter(Boolean),
      tenant: org?.tenantId ?? 't_default',
      scope: claims.scope,
    }
  }

  // -- JWT (RS256, JWKS en tableau) ----------------------------------------------

  signJwt(payload: Record<string, unknown>): string {
    const key = this.activeKey()
    const header = { alg: 'RS256', typ: 'JWT', kid: key.kid }
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const head = Buffer.from(JSON.stringify(header)).toString('base64url')
    const signature = rsSign('RSA-SHA256', Buffer.from(`${head}.${body}`), key.privatePem).toString('base64url')
    return `${head}.${body}.${signature}`
  }

  /** La signature utilise toujours la clé la plus récente ; la vérification cherche header.kid dans le tableau (clés retirées en grâce incluses). */
  private activeKey(): OidcKeyMaterial {
    const alive = this.keys.filter((key) => key.retiredAt === undefined || Date.now() - new Date(key.retiredAt).getTime() < KEY_GRACE_MS)
    const candidates = alive.filter((key) => key.retiredAt === undefined)
    return candidates[0] ?? alive[0]!
  }

  /**
   * Vérification JWT : signature + header.kid correspondant aux clés publiées en JWKS + iss rattaché à ce Provider + exp valide ;
   * options.audience → validation d'audience (azp/aud doivent correspondre) ;
   * options.origin → iss accepte aussi la valeur dérivée de la requête (#15 : un jeton émis sur un domaine public valide sur le même domaine).
   */
  verifyJwt(token: string, options: { audience?: string; origin?: { headers: import('node:http').IncomingHttpHeaders } } = {}): Record<string, unknown> {
    const parts = token.split('.')
    if (parts.length !== 3) throw new Error(t('JWT 格式不合法'))
    let header: Record<string, unknown>
    try {
      header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8')) as Record<string, unknown>
    } catch {
      throw new Error(t('JWT 头部解析失败'))
    }
    const key = this.keys.find((item) => item.kid === header.kid)
    if (!key) throw new Error(t('JWT kid 与 JWKS 公布密钥不匹配'))
    if (key.retiredAt !== undefined && Date.now() - new Date(key.retiredAt).getTime() >= KEY_GRACE_MS) {
      throw new Error(t('JWT 签名密钥已过宽限期'))
    }
    const valid = rsVerify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key.publicPem, Buffer.from(parts[2]!, 'base64url'))
    if (!valid) throw new Error(t('JWT 签名校验失败（RS256）'))
    let claims: Record<string, unknown>
    try {
      claims = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>
    } catch {
      throw new Error(t('JWT 载荷解析失败'))
    }
    if (!this.acceptedIssuers(options.origin).includes(String(claims.iss ?? ''))) throw new Error(t('JWT 签发方（iss）校验失败'))
    if (typeof claims.exp === 'number' && claims.exp * 1000 < Date.now()) throw new Error(t('JWT 已过期'))
    if (options.audience !== undefined) {
      const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
      if (!aud.includes(options.audience)) throw new Error(t('JWT 受众（aud）校验失败：期望 {expected}', { expected: options.audience }))
    }
    return claims
  }

  jwks(): { keys: Array<Record<string, unknown>> } {
    // Les clés retirées encore en grâce restent publiées (les vérifications en vol ne sont pas déconnectées), retirées du JWKS après grâce
    const published = this.keys.filter((key) => key.retiredAt === undefined || Date.now() - new Date(key.retiredAt).getTime() < KEY_GRACE_MS)
    return { keys: published.map((key) => {
      const jwk = createPublicKey(key.publicPem).export({ format: 'jwk' }) as { kty: string; n?: string; e?: string }
      return {
        kty: jwk.kty,
        use: 'sig',
        alg: 'RS256',
        kid: key.kid,
        n: jwk.n,
        e: jwk.e,
      }
    }) }
  }

  /** Rotation des clés côté administration : la nouvelle clé signe immédiatement, l'ancienne entre en grâce de vérification de 24 h. */
  rotateKeys(): { graceHours: number; kid: string } {
    const now = new Date().toISOString()
    this.keys = this.keys.map((key) => (key.retiredAt === undefined ? { ...key, retiredAt: now } : key))
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const material: OidcKeyMaterial = {
      privatePem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      publicPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      kid: createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest('hex').slice(0, 16),
      createdAt: now,
    }
    this.keys = [material, ...this.keys]
    this.saveKeys()
    return { graceHours: KEY_GRACE_MS / 3600_000, kid: material.kid }
  }

  discovery(origin?: { headers: import('node:http').IncomingHttpHeaders }): Record<string, unknown> {
    const issuer = this.issuer(origin)
    return {
      issuer,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      userinfo_endpoint: `${issuer}/oauth/userinfo`,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      end_session_endpoint: `${issuer}/oauth/end_session`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: [...OidcService.ALLOWED_SCOPES],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      claims_supported: ['sub', 'name', 'preferred_username', 'iss', 'aud', 'exp', 'iat', 'jti', 'nonce', 'email'],
    }
  }

  /** Nettoyage des enregistrements expirés (même convention que M2 : suppression physique après 7 jours d'expiration, pas d'accumulation infinie). */
  private cleanupExpired(): number {
    const cutoff = Date.now() - 7 * 24 * 3600_000
    let removed = 0
    for (const record of this.authRequests().all()) {
      if (new Date(record.expiresAt).getTime() < cutoff && this.authRequests().remove(record.id)) removed++
    }
    for (const record of this.codes().all()) {
      if (new Date(record.expiresAt).getTime() < cutoff && this.codes().remove(record.id)) removed++
    }
    for (const record of this.refreshTokens().all()) {
      if (new Date(record.expiresAt).getTime() < cutoff && this.refreshTokens().remove(record.id)) removed++
    }
    for (const record of this.deniedJtis().all()) {
      if (new Date(record.expiresAt).getTime() < cutoff && this.deniedJtis().remove(record.id)) removed++
    }
    // Les clés retirées au-delà de la grâce sont purgées du tableau (convergence synchronisée du fichier)
    const before = this.keys.length
    this.keys = this.keys.filter((key) => key.retiredAt === undefined || Date.now() - new Date(key.retiredAt).getTime() < KEY_GRACE_MS)
    if (this.keys.length !== before) this.saveKeys()
    return removed
  }

  private loadOrCreateKeys(): OidcKeyMaterial[] {
    const file = join(this.ctx.opsStorage.dataDirPath, 'oidc-keys.json')
    const fresh = (): OidcKeyMaterial => {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
      return {
        privatePem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        publicPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        kid: createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest('hex').slice(0, 16),
        createdAt: new Date().toISOString(),
      }
    }
    try {
      if (existsSync(file)) {
        const stored = JSON.parse(readFileSync(file, 'utf8')) as unknown
        // Ancien fichier à clé unique enveloppé automatiquement en tableau (migration sans arrêt)
        const list = Array.isArray((stored as { keys?: unknown }).keys)
          ? (stored as { keys: OidcKeyMaterial[] }).keys
          : [stored as OidcKeyMaterial]
        const valid = list.filter((item) => item && item.privatePem && item.publicPem && item.kid)
        if (valid.length > 0) return valid
      }
      mkdirSync(this.ctx.opsStorage.dataDirPath, { recursive: true })
      const material = fresh()
      writeFileSync(file, JSON.stringify({ keys: [material] }, null, 2), { encoding: 'utf8', mode: 0o600 })
      return [material]
    } catch {
      // Anomalies comme un répertoire non inscriptible : clé en mémoire (jetons invalidés après redémarrage, scénarios exceptionnels seulement)
      return [fresh()]
    }
  }

  private saveKeys(): void {
    try {
      const file = join(this.ctx.opsStorage.dataDirPath, 'oidc-keys.json')
      writeFileSync(file, JSON.stringify({ keys: this.keys }, null, 2), { encoding: 'utf8', mode: 0o600 })
    } catch (error) {
      console.error('[oidc] 密钥文件落盘失败（仅影响轮换持久化）', error)
    }
  }

  // -- Points de protocole ---------------------------------------------------------------

  /**
   * Origines CORS autorisées : origin des redirect_uri des clients enregistrés ∪ OIDC_CORS_ORIGINS (liste explicite séparée par virgules).
   * Convergence dans les origines enregistrées — les pages de sites non enregistrés n'obtiennent pas d'en-têtes d'autorisation ; le code est lui-même lié au redirect_uri, double filet.
   */
  private allowedCorsOrigins(): Set<string> {
    const origins = new Set<string>(
      String(process.env.OIDC_CORS_ORIGINS ?? '').split(',').map((item) => item.trim()).filter(Boolean),
    )
    for (const client of this.clients().all()) {
      for (const uri of client.redirectUris ?? []) {
        try { origins.add(new URL(uri).origin) } catch { /* un redirect_uri invalide ne participe pas au jugement CORS */ }
      }
    }
    return origins
  }

  /** Génère les en-têtes d'autorisation selon l'en-tête Origin ; sans Origin (appel non navigateur) rien n'est délivré, origine non enregistrée → vary seul. */
  private corsHeaders(exchange: { headers: import('node:http').IncomingHttpHeaders }): Record<string, string> {
    const header = exchange.headers['origin']
    const origin = Array.isArray(header) ? header[0] : header
    if (!origin) return {}
    if (!this.allowedCorsOrigins().has(origin)) return { vary: 'Origin' }
    return { vary: 'Origin', 'access-control-allow-origin': origin }
  }

  /** Points publics (hors /api/* : non soumis au middleware Bearer console, exigés par le protocole OIDC). */
  private registerRoutes(): void {
    const http = this.ctx.httpServer
    // Les points de protocole OIDC renvoient du JSON brut (les clients standard ne reconnaissent pas l'enveloppe {ok,data} de la plateforme) ; succès/erreur fusionnent toujours les en-têtes CORS
    const raw = (exchange: { res: import('node:http').ServerResponse; headers: import('node:http').IncomingHttpHeaders }, status: number, payload: unknown, extra: Record<string, string> = {}): void => {
      exchange.res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...this.corsHeaders(exchange), ...extra })
      exchange.res.end(JSON.stringify(payload))
    }
    const redirect = (exchange: { res: import('node:http').ServerResponse }, location: string): void => {
      exchange.res.writeHead(302, { location })
      exchange.res.end()
    }
    const clientIp = (exchange: { raw: import('node:http').IncomingMessage }): string =>
      String(exchange.raw.socket?.remoteAddress ?? 'unknown')

    // -- Préflight CORS : points appelés en cross-origin par les clients purement frontend (public + PKCE), réponse 204 uniforme ------
    const preflight = (exchange: { res: import('node:http').ServerResponse; headers: import('node:http').IncomingHttpHeaders }): void => {
      exchange.res.writeHead(204, {
        ...this.corsHeaders(exchange),
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'authorization, content-type',
        'access-control-max-age': '600',
      })
      exchange.res.end()
    }
    for (const pattern of ['/oauth/token', '/oauth/userinfo', '/oauth/revoke', '/.well-known/openid-configuration', '/.well-known/jwks.json']) {
      http.register('OPTIONS', pattern, preflight)
    }

    http.register('GET', '/.well-known/openid-configuration', (exchange) => {
      raw(exchange, 200, this.discovery(exchange))
    })

    http.register('GET', '/.well-known/jwks.json', (exchange) => {
      raw(exchange, 200, this.jwks())
    })

    // -- Premier saut du flux d'autorisation navigateur : validation → enregistrement de la requête → 302 page d'autorisation plateforme --------------------
    http.register('GET', '/oauth/authorize', (exchange) => {
      const q = exchange.query
      // Limitation de base par IP source (réutilise le squelette de verrouillage de connexion, convergence de la surface de sondage client)
      const throttleKey = `oidc-authorize-ip:${clientIp(exchange)}`
      try {
        this.ctx.authn.assertNotLocked(throttleKey)
        const req = this.beginAuthorization({
          responseType: q.get('response_type') ?? undefined,
          clientId: q.get('client_id') ?? undefined,
          redirectUri: q.get('redirect_uri') ?? undefined,
          state: q.get('state') ?? undefined,
          scope: q.get('scope') ?? undefined,
          nonce: q.get('nonce') ?? undefined,
          codeChallenge: q.get('code_challenge') ?? undefined,
          codeChallengeMethod: q.get('code_challenge_method') ?? undefined,
        })
        redirect(exchange, `${this.webBase()}/#/oauth/authorize?req=${encodeURIComponent(req.id)}`)
      } catch (error) {
        const err = error instanceof OidcEndpointError
          ? error
          : new OidcEndpointError(302, 'access_denied', error instanceof Error ? error.message : String(error))
        // Les formes de sondage client_id / redirect_uri comptent comme échec (verrouille l'énumération par force brute)
        if (err.error === 'unauthorized_client' || err.message.includes('redirect_uri')) {
          try { this.ctx.authn.recordLoginFailure(throttleKey) } catch { /* un échec d'écriture du verrouillage ne bloque pas l'affichage de l'erreur */ }
        }
        redirect(exchange, `${this.webBase()}/#/oauth/error?error=${encodeURIComponent(err.error)}&error_description=${encodeURIComponent(err.message)}`)
      }
    })

    // -- Requête publique de la page d'autorisation (nom du client/scope seulement, sans divulguer redirect_uri) --------------------
    http.register('GET', '/api/authn/oidc/auth-requests/:id', (exchange) => {
      try {
        raw(exchange, 200, this.authRequestInfo(exchange.params['id']!))
      } catch (error) {
        raw(exchange, 404, { error: 'invalid_request', error_description: error instanceof Error ? error.message : String(error) })
      }
    }, { access: 'public', selfValidated: true })

    // -- Confirmation de la page d'autorisation (Bearer ; human-only, tout principal machine → 403) ------------------
    http.register('POST', '/api/authn/oidc/authorize', async (exchange) => {
      const input = (exchange.body ?? {}) as { reqId?: string; consent?: boolean }
      const info = exchange.principal as { kind?: string; userId?: string } | undefined
      if (!info) {
        raw(exchange, 401, { error: 'invalid_request', error_description: t('缺少 Bearer 会话，请先登录平台') })
        return
      }
      if (info.kind !== 'human' || !info.userId) {
        raw(exchange, 403, { error: 'invalid_request', error_description: t('授权确认仅限登录用户（human），机器身份不可代替用户授权') })
        return
      }
      if (!input.reqId) {
        raw(exchange, 400, { error: 'invalid_request', error_description: t('reqId 必填') })
        return
      }
      try {
        const result = this.completeAuthorization({ reqId: input.reqId, userId: info.userId, ...(input.consent !== undefined ? { consent: input.consent } : {}) }, exchange)
        raw(exchange, 200, result)
      } catch (error) {
        raw(exchange, 400, { error: 'consent_required', error_description: error instanceof Error ? error.message : String(error) })
      }
    }, { access: 'authenticated' })

    // -- Échange : client_secret_basic + client_secret_post ; double encodage form-encoded et JSON --
    http.register('POST', '/oauth/token', async (exchange) => {
      const bodyInput = (exchange.body ?? {}) as Record<string, string>
      // Authentification Basic : Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))
      const authHeader = String(exchange.headers['authorization'] ?? '')
      let basicId: string | undefined
      let basicSecret: string | undefined
      if (authHeader.startsWith('Basic ')) {
        try {
          const decoded = Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8')
          const idx = decoded.indexOf(':')
          basicId = decodeURIComponent(decoded.slice(0, idx))
          basicSecret = decodeURIComponent(decoded.slice(idx + 1))
        } catch { /* en-tête Basic malformé traité comme absent */ }
      }
      try {
        const result = this.token({
          grantType: bodyInput['grant_type'] ?? 'authorization_code',
          clientId: basicId ?? bodyInput['client_id'],
          clientSecret: basicSecret ?? bodyInput['client_secret'],
          ...(bodyInput['code'] !== undefined ? { code: bodyInput['code'] } : {}),
          ...(bodyInput['redirect_uri'] !== undefined ? { redirectUri: bodyInput['redirect_uri'] } : {}),
          ...(bodyInput['code_verifier'] !== undefined ? { codeVerifier: bodyInput['code_verifier'] } : {}),
          ...(bodyInput['refresh_token'] !== undefined ? { refreshToken: bodyInput['refresh_token'] } : {}),
          ...(bodyInput['scope'] !== undefined ? { scope: bodyInput['scope'] } : {}),
        }, exchange)
        raw(exchange, 200, result, { 'cache-control': 'no-store', pragma: 'no-cache' })
      } catch (error) {
        const err = error instanceof OidcEndpointError
          ? error
          : new OidcEndpointError(400, 'invalid_grant', error instanceof Error ? error.message : String(error))
        raw(exchange, err.status, { error: err.error, error_description: err.message }, err.headers)
      }
    })

    // -- userinfo (RFC 6750 : 401 avec WWW-Authenticate: Bearer) ----------------------
    http.register('GET', '/oauth/userinfo', (exchange) => {
      const header = String(exchange.headers['authorization'] ?? '')
      // Les en-têtes n'acceptent que de l'ASCII : les libellés descriptifs passent en encodage pourcent, le texte original reste dans le corps JSON de la réponse
      const headerSafe = (text: string): string => encodeURIComponent(text).replace(/"/g, '%22')
      const deny = (description: string): void => {
        raw(exchange, 401, { error: 'invalid_token', error_description: description }, { 'www-authenticate': `Bearer error="invalid_token", error_description="${headerSafe(description)}"` })
      }
      if (!header.startsWith('Bearer ')) {
        raw(exchange, 401, { error: 'invalid_token', error_description: t('缺少 Bearer access token') }, { 'www-authenticate': 'Bearer' })
        return
      }
      try {
        raw(exchange, 200, this.userinfo(header.slice(7), exchange))
      } catch (error) {
        deny(error instanceof Error ? error.message : String(error))
      }
    })

    // -- Logout initié par le RP (implémentation minimale OIDC Front-Channel / RP-Initiated Logout) ----------
    http.register('GET', '/oauth/end_session', (exchange) => {
      const q = exchange.query
      try {
        const result = this.endSession({
          idTokenHint: q.get('id_token_hint') ?? undefined,
          postLogoutRedirectUri: q.get('post_logout_redirect_uri') ?? undefined,
          state: q.get('state') ?? undefined,
        }, exchange)
        redirect(exchange, result.location)
      } catch (error) {
        const err = error instanceof OidcEndpointError
          ? error
          : new OidcEndpointError(302, 'invalid_request', error instanceof Error ? error.message : String(error))
        redirect(exchange, `${this.webBase()}/#/oauth/error?error=${encodeURIComponent(err.error)}&error_description=${encodeURIComponent(err.message)}`)
      }
    })

    // -- Révocation de jetons (RFC 7009 : toujours 200, token inconnu → succès silencieux) --------------------------
    http.register('POST', '/oauth/revoke', async (exchange) => {
      const bodyInput = (exchange.body ?? {}) as Record<string, string>
      const authHeader = String(exchange.headers['authorization'] ?? '')
      let basicId: string | undefined
      let basicSecret: string | undefined
      if (authHeader.startsWith('Basic ')) {
        try {
          const decoded = Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8')
          const idx = decoded.indexOf(':')
          basicId = decodeURIComponent(decoded.slice(0, idx))
          basicSecret = decodeURIComponent(decoded.slice(idx + 1))
        } catch { /* en-tête Basic malformé traité comme absent */ }
      }
      try {
        this.revokeToken({
          clientId: basicId ?? bodyInput['client_id'],
          clientSecret: basicSecret ?? bodyInput['client_secret'],
          token: bodyInput['token'],
          tokenTypeHint: bodyInput['token_type_hint'],
        }, exchange)
        raw(exchange, 200, {})
      } catch (error) {
        const err = error instanceof OidcEndpointError
          ? error
          : new OidcEndpointError(400, 'unsupported_token_type', error instanceof Error ? error.message : String(error))
        raw(exchange, err.status, { error: err.error, error_description: err.message }, err.headers)
      }
    })
  }
}

/** Assemble l'adresse de retour (conserve la query existante ; l'iss / error de RFC 9207 passent tous deux ici ; réservé aux adresses absolues). */
function withQuery(base: string, params: Record<string, string>): string {
  const url = new URL(base)
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value)
  return url.toString()
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    oidc: OidcService
  }
}
