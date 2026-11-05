/**
 * @dsh-ops/plugin-authn —— centre d'authentification unifié.
 *
 * Identité à double voie : les humains (SSO/mot de passe) et les machines (Client Credentials) partagent le même système de Principal.
 * Jetons : jetons d'accès courts signés HMAC (30 min par défaut, rafraîchissables), avec révocation et rotation de clés.
 * Chaînes de jetons (on-behalf-of) : utilisateur → application → Agent → MCP, la chaîne act se superpose dans le jeton, reconstituable à l'audit.
 */
import { createHmac, randomUUID } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  PlatformEvents, generateSecret, newId, sha256Hex,
  type Collection, type RecordBase,
} from '../../platform-core/src/index.ts'
import { PermissionCatalog, SYSTEM_ACTOR } from '../../plugin-iam/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import * as authnTools from './tools.ts'
import { OidcService } from './oidc.ts'
import { EntryTicketService } from './entry-ticket.ts'

export * from './oidc.ts'
export * from './entry-ticket.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

export interface PrincipalRecord extends RecordBase {
  type: 'human' | 'machine'
  /** human : userId ; machine : référence de ressource (agent:xxx / app:xxx) ou sujet libre. */
  refType?: 'user' | 'agent' | 'app' | 'external'
  refId?: string
  name: string
  status: 'active' | 'disabled'
  clientId?: string
  clientSecretHash?: string
  /** Rôles machine : ID de rôles référençant iam:roles, permissions synchronisées en temps réel avec le rôle (human passe par user.roleIds, même stockage). */
  roleIds?: string[]
  /** Points de permission directs additionnels (union avec roleIds ; doivent figurer dans le catalogue de permissions, anti-faute de frappe). */
  scopes: string[]
}

export interface ActEntry {
  principalId: string
  name: string
  type: 'human' | 'machine'
}

export interface TokenRecord extends RecordBase {
  jti: string
  principalId: string
  kind: 'access' | 'machine' | 'refresh'
  scopes: string[]
  /** Déclaration d'audience : ce jeton n'est valable que pour le service/plugin désigné (resserrement de l'étape 1 de la conception écosystème v1.2). */
  audience?: string
  actChain: ActEntry[]
  issuedAt: string
  expiresAt: string
  lastUsedAt?: string
  revokedAt?: string
  revokedReason?: string
  issuedBy: string
  /** id de session : interdiction/changement de mot de passe/déliaison → révocation immédiate par session (auth-identity docs/06). */
  sid?: string
  /** id de chaîne de rafraîchissement : en cas de rejeu du refresh token, révocation de tous les jetons de la chaîne. */
  chainId?: string
  /** Hash SHA-256 du refresh token (le texte original n'est pas stocké, renvoyé une seule fois à l'émission). */
  refreshHash?: string
  /** Horodatage de rotation : toute réapparition = rejeu (sauf dans la fenêtre de grâce, voir REFRESH_GRACE_MS). */
  rotatedAt?: string
  /** Nombre d'échanges dans la fenêtre de grâce (compteur d'auto-réparation des collisions multi-onglets ; au-delà du plafond, refus et plus aucune émission). */
  graceRedemptions?: number
  /** Complément de jeton délégué (contrat de gouvernance MCP §3) : utilisateur représenté (sub = chaîne de délégation de cet utilisateur, gel = révocation en cascade). */
  delegatedUserId?: string
  /** Complément de jeton délégué (contrat de gouvernance MCP §3) : instantané d'audience (mcp:service:<slug> / plugin:<id>). */
  delegationAudience?: string
  /** Note du jeton d'accès personnel (émission en libre-service de la configuration MCP des employés, additif ; non transmis pour les émissions hors de ce canal). */
  label?: string
}

/** Enregistrement de state OAuth (anti-CSRF, consommation unique). */
export interface OAuthStateRecord extends RecordBase {
  provider: string
  /** Multi-instances : id de l'instance de configuration de connecteur désignée à l'initiation d'autorisation (défaut = la première du provider, comportement historique). */
  configId?: string
  scene: string
  /** Isolation des usages : login = connexion tierce ; bind = liaison d'identité tierce d'un compte déjà connecté (empêche d'utiliser un state de liaison pour se connecter). */
  purpose?: 'login' | 'bind'
  /** Compte plateforme cible verrouillé quand purpose=bind (résolu côté serveur depuis la session à l'authorize, non spécifiable par le frontend). */
  userId?: string
  createdAt: string
  consumedAt?: string
}

/** Billet de liaison en attente quand la connexion tierce ne trouve pas de correspondance. */
export interface SsoTicketRecord extends RecordBase {
  provider: string
  profile: Record<string, string>
  createdAt: string
  expiresAt: string
  usedAt?: string
}

export interface VerifiedPrincipal {
  principal: PrincipalRecord
  token: TokenRecord
  scopes: string[]
  actChain: ActEntry[]
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

/** Base du cycle de vie des jetons (auth-identity docs/06) : access 30 min + rotation du refresh tous les 7 j. */
const ACCESS_TTL_MS = 30 * 60_000
const REFRESH_TTL_MS = 7 * 24 * 3600_000
/**
 * Fenêtre de grâce de rotation du refresh (QA 2026-09-08 T-08 / liste de passation H3) : la réapparition d'un ancien refresh dans les N secondes après rotation
 * n'est pas jugée comme rejeu mais émet une nouvelle paire frère de la même chaîne — dans un scénario multi-onglets, après que l'onglet A a rafraîchi, le même ancien
 * token détenu par les onglets B/C se répare en 401, sans être révoqué en chaîne par la « détection de rejeu ». Une réapparition hors fenêtre reste un rejeu dur : révocation de la chaîne entière (inchangé).
 * Filet du plafond d'échanges de grâce par enregistrement déjà tourné (contre la frappe illimitée dans la fenêtre) ; au-delà, seule la requête est refusée, sans révocation de chaîne.
 */
const REFRESH_GRACE_MS = 30_000
const REFRESH_GRACE_MAX_REDEMPTIONS = 10
/** Période de grâce de vérification des anciennes clés de signature : après rotation, les anciens jetons restent vérifiables dans la fenêtre, puis expirent naturellement (revue S2). */
const SECRET_GRACE_MS = 24 * 3600_000

/** TTL des jetons délégués (contrat de gouvernance MCP §3) : défaut 900 s, plafond 3600 s. */
const DELEGATION_TTL_DEFAULT_SECONDS = 900
const DELEGATION_TTL_MAX_SECONDS = 3600
/** Plafond de sauts de la chaîne act (après l'humain) : refus au-delà (contre l'empilement infini de chaînes de délégation). */
const DELEGATION_CHAIN_MAX_JUMPS = 4

/**
 * Crochet de validation des faits d'autorisation de délégation (fail-closed) : injecté par l'hôte (à l'assemblage console) —
 * consulte les liaisons agent / owner d'app / administrateurs iam. Sans injection, exchangeDelegatedToken refuse systématiquement
 * (DELEGATION_GUARD_UNAVAILABLE), jamais de passage silencieux.
 */
export interface DelegationGuardInput {
  /** Utilisateur sujet de la délégation (obligatoire pour un appelant machine ; par défaut l'appelant lui-même pour un humain) */
  userId?: string
  /** Principal cible (sujet agent/app pour lequel l'appelant humain émet la délégation OBO) */
  targetPrincipalId?: string
  caller: { principalId: string; kind: string; refType?: string; refId?: string }
}

export type DelegationGuardFn = (input: DelegationGuardInput) => Promise<boolean> | boolean

/** Erreur de domaine de l'échange de délégation (avec code de motif stable ; la facette REST en déduit le statut HTTP et extra.reason). */
export class DelegationError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

/** Stratégie de verrouillage après échecs de connexion (revue S3) : seuil d'échecs consécutifs dans la fenêtre = verrouillage, durée croissante à chaque fois. */
const LOGIN_MAX_FAILS = 5
const LOGIN_WINDOW_MS = 15 * 60_000
const LOGIN_BASE_LOCK_MS = 15 * 60_000
const LOGIN_MAX_LOCK_MS = 24 * 3600_000

/** Compteur de tentatives de connexion (persistant : un redémarrage ne remet pas à zéro, un attaquant ne contourne pas le verrouillage par redémarrage). */
export interface LoginAttemptRecord extends RecordBase {
  key: string
  fails: number
  /** Début de fenêtre (ISO) : le compteur décroît naturellement quand la fenêtre glisse. */
  windowStart: string
  lockCount: number
  lockedUntil?: string
}

export class AuthnService extends Service {
  static readonly provide = 'authn'

  private signingSecret: string
  /** Clés de signature retirées mais encore en période de grâce (vérification compatible des anciens jetons). */
  private retiredSecrets: Array<{ secret: string; retiredAt: number }> = []
  private refreshIndex = new Map<string, string>()
  /** Cache du pré-contrôle de la page d'autorisation (key=provider|configId|redirectUri ; 2 min) : chaque clic sur la page de connexion ne sollicite plus l'IdP une fois de plus. */
  private authorizeProbeCache = new Map<string, { at: number; ok: boolean; code?: string; message?: string }>()
  private cleanupTimer: ReturnType<typeof setInterval> | undefined
  /** Crochet des faits d'autorisation de délégation (injecté par l'hôte ; absent = tout échange de délégation refusé, fail-closed). */
  private delegationGuard: DelegationGuardFn | undefined

  constructor(ctx: Context) {
    super(ctx, 'authn')
    // Les données d'authentification utilisent des collections durable : révocation/verrouillage écrits immédiatement (fsync), une mort après le 200 ne perd rien
    this.ctx.opsStorage.collection<TokenRecord>('authn:tokens', { durability: 'durable' })
    this.ctx.opsStorage.collection<LoginAttemptRecord>('authn:loginAttempts', { durability: 'durable' })
    this.ctx.opsStorage.collection<PrincipalRecord>('authn:principals', { durability: 'durable' })
    this.signingSecret = this.loadOrCreateSecret()
    this.loadRetiredSecrets()
    // Index de hash des refresh : remplace le scan de table complet (revue M2)
    for (const token of this.tokens().all()) {
      if (token.kind === 'refresh' && token.refreshHash) this.refreshIndex.set(token.refreshHash, token.id)
    }
    this.tokens().onChange((change) => {
      const hash = change.record.refreshHash
      if (!hash) return
      if (change.kind === 'remove') this.refreshIndex.delete(hash)
      else this.refreshIndex.set(hash, change.record.id)
    })
    // Nettoyage des jetons expirés (revue M2 / test DEF-03 : les enregistrements révoqués/expirés ne croissent pas indéfiniment, inspection horaire maîtrisant la croissance mémoire et stockage) :
    // nettoyage au démarrage + inspection horaire
    this.cleanupExpiredTokens()
    this.cleanupTimer = setInterval(() => this.cleanupExpiredTokens(), 3600_000)
    this.cleanupTimer.unref?.() // OPT-P3-02 : en forme embarquée/test, laisse le processus sortir naturellement
    ctx.effect(() => () => {
      if (this.cleanupTimer) clearInterval(this.cleanupTimer)
    })
    // Cascades d'événements : gel de compte → révocation de tous les jetons ; mise hors ligne d'un Agent → révocation des identifiants machine
    ctx.platformBus.on(PlatformEvents.UserFrozen, (payload) => {
      const { userId, reason } = payload as { userId: string; reason: string }
      // Cascade des jetons délégués (contrat de gouvernance MCP §3) : tous les jetons délégués avec sub = cet utilisateur s'invalident immédiatement
      // (exécuté avant le nettoyage du sujet pour obtenir un motif dédié ; motif consultable par machine, facilitant la distinction des chaînes à l'audit)
      for (const token of this.tokens().find((item) => item.delegatedUserId === userId && !item.revokedAt)) {
        this.revokeToken(token.jti, 'user-frozen-delegation')
      }
      const principal = this.humanPrincipal(userId)
      if (principal) this.revokePrincipalTokens(principal.id, t('账号冻结联动：{reason}', { reason }))
    })
    // Cascade de réinitialisation de mot de passe (revue sécurité P1-08, 2026-10-31) : après réinitialisation, tous les access/refresh existants sont révoqués —
    // les anciens refresh ne peuvent plus obtenir de nouveaux jetons ; les jetons délégués avec sub = cet utilisateur expirent dans le même lot. Auditable (motif de révocation consultable par machine).
    ctx.platformBus.on(PlatformEvents.UserPasswordReset, (payload) => {
      const { userId } = payload as { userId: string }
      for (const token of this.tokens().find((item) => item.delegatedUserId === userId && !item.revokedAt)) {
        this.revokeToken(token.jti, 'password-reset-delegation')
      }
      const principal = this.humanPrincipal(userId)
      if (principal) this.revokePrincipalTokens(principal.id, t('口令重置联动：既有会话全部失效，请重新登录'))
    })
    ctx.platformBus.on(PlatformEvents.AgentOfflined, (payload) => {
      const { id } = payload as { id: string }
      for (const principal of this.principals().find((item) => item.refType === 'agent' && item.refId === id)) {
        this.disablePrincipal(principal.id, t('Agent 下线联动'))
      }
    })
    ctx.platformBus.on(PlatformEvents.AppOfflined, (payload) => {
      const { id } = payload as { id: string }
      for (const principal of this.principals().find((item) => item.refType === 'app' && item.refId === id)) {
        this.disablePrincipal(principal.id, t('应用下线联动'))
      }
    })
  }

  principals(): Collection<PrincipalRecord> {
    return this.ctx.opsStorage.collection<PrincipalRecord>('authn:principals')
  }

  /** state OAuth (anti-CSRF, consommation unique, valable 10 min). */
  oauthStates(): Collection<OAuthStateRecord> {
    return this.ctx.opsStorage.collection<OAuthStateRecord>('authn:oauthStates')
  }

  /** Billet de liaison en attente quand la connexion tierce ne trouve pas de correspondance (valable 5 min, usage unique). */
  ssoTickets(): Collection<SsoTicketRecord> {
    return this.ctx.opsStorage.collection<SsoTicketRecord>('authn:ssoTickets')
  }

  // -- Paire de jetons de session (chaîne de rotation access + refresh) --------------------------------

  /** Émet la paire de jetons de session : access (30 min) + refresh (7 j, stocké en hash seul, rotation unique). */
  issueSessionPair(principalId: string, options: { sid?: string; chainId?: string; issuedBy: string }): { token: string; refreshToken: string; access: TokenRecord; sid: string } {
    const sid = options.sid ?? newId('sid')
    const chainId = options.chainId ?? newId('chn')
    const access = this.issueToken(principalId, {
      kind: 'access',
      ttlHours: ACCESS_TTL_MS / 3600_000,
      issuedBy: options.issuedBy,
      sid,
      chainId,
    })
    const refreshRaw = 'dstr_' + randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '')
    const refreshJti = randomUUID()
    this.tokens().insert({
      id: refreshJti,
      jti: refreshJti,
      principalId,
      kind: 'refresh',
      scopes: [],
      actChain: [],
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + REFRESH_TTL_MS).toISOString(),
      issuedBy: options.issuedBy,
      sid,
      chainId,
      refreshHash: sha256Hex(refreshRaw),
    })
    return { token: access.token, refreshToken: refreshRaw, access: access.record, sid }
  }

  /**
   * Rafraîchit la session : validation du hash du refresh → détection de rejeu (réapparition d'un refresh déjà tourné → révocation de la chaîne entière).
   * Contrat de grâce (H3/T-08) : dans REFRESH_GRACE_MS après rotation, la réapparition de l'ancien token n'est pas un rejeu, émission d'une paire frère de la même chaîne
   * (chaque onglet détient ensuite ses jetons propres, rotations ultérieures indépendantes) ; hors fenêtre, révocation de la chaîne entière. Forme de réponse inchangée
   * ({token, refreshToken, sid}), les consommateurs obtiennent l'auto-réparation multi-onglets sans modification.
   */
  refreshSession(refreshToken: string): { token: string; refreshToken: string; sid: string } {
    const hash = sha256Hex(refreshToken)
    const recordId = this.refreshIndex.get(hash)
    const record = recordId ? this.tokens().get(recordId) : undefined
    if (!record || record.kind !== 'refresh') throw new Error(t('refresh token 无效'))
    if (record.revokedAt) throw new Error(t('refresh token 已吊销：{reason}', { reason: record.revokedReason ?? '' }))
    if (new Date(record.expiresAt).getTime() < Date.now()) throw new Error(t('refresh token 已过期，请重新登录'))
    if (record.rotatedAt) {
      const rotatedAtMs = new Date(record.rotatedAt).getTime()
      const withinGrace = Date.now() - rotatedAtMs <= REFRESH_GRACE_MS
      const redemptions = record.graceRedemptions ?? 0
      if (withinGrace) {
        if (redemptions < REFRESH_GRACE_MAX_REDEMPTIONS) {
          this.tokens().update(record.id, { graceRedemptions: redemptions + 1 })
          return this.issueSessionPair(record.principalId, {
            sid: record.sid,
            chainId: record.chainId,
            issuedBy: 'refresh-grace',
          })
        }
        // Dépassement dans la fenêtre : seule cette requête est refusée (filet de frappe borné), la chaîne n'est pas entraînée — l'onglet
        // N+1 de la tempête multi-onglets retombe sur une reconnexion, les paires sœurs déjà émises restent intactes.
        throw new Error(t('refresh token 宽限兑换已达上限（{n} 次），请重新登录', { n: REFRESH_GRACE_MAX_REDEMPTIONS }))
      }
      this.revokeChain(record.chainId ?? '', t('refresh token 重放检测（原轮转于 {at}）', { at: record.rotatedAt }))
      throw new Error(t('检测到 refresh token 重放：该会话整链已吊销，请重新登录'))
    }
    this.tokens().update(record.id, { rotatedAt: new Date().toISOString() })
    return this.issueSessionPair(record.principalId, {
      sid: record.sid,
      chainId: record.chainId,
      issuedBy: 'refresh-rotation',
    })
  }

  /** Révoque tous les jetons d'une chaîne. */
  revokeChain(chainId: string, reason: string): number {
    let count = 0
    for (const token of this.tokens().find((item) => item.chainId === chainId && !item.revokedAt)) {
      this.revokeToken(token.jti, reason)
      count++
    }
    return count
  }

  /** Révoque par session (logout/interdiction/changement de mot de passe effectifs immédiatement). */
  revokeSession(sid: string, reason: string): number {
    let count = 0
    for (const token of this.tokens().find((item) => item.sid === sid && !item.revokedAt)) {
      this.revokeToken(token.jti, reason)
      count++
    }
    return count
  }

  // -- Connexion tierce (chaîne IdentityProviderAdapter, fusion auth-identity docs/03/04)--

  /**
   * Initie l'autorisation tierce : génère un state à usage unique, renvoie l'adresse d'autorisation.
   * Les IdP réels comme DingTalk exigent un redirect_uri en URL absolue ; l'origin est déduit par l'appelant des en-têtes de requête et transmis ;
   * à défaut, repli sur le chemin relatif (valable seulement pour les chaînes locales/mock).
   * options.purpose='bind' sert à « lier par scan l'identité tierce d'un compte déjà connecté » : le state verrouille le userId cible,
   * le callback est pris en charge par GET /api/auth/sso/callback (isolé de l'usage connexion, voir completeSso).
   * options.configId désigne l'instance de connecteur multi-instances : l'autorisation est initiée via son adaptateur et consignée dans le state, le callback se résout par instance.
   * options.promptConsent=true force l'IdP à afficher la page de confirmation d'autorisation (rafraîchit l'instantané d'autorisation des anciens utilisateurs, voir providers.ts).
   */
  async beginSso(provider: string, scene: 'web_qr' | 'h5' | 'in_app', origin?: string, options: { purpose?: 'login' | 'bind'; userId?: string; configId?: string; promptConsent?: boolean } = {}): Promise<{ authorizeUrl: string | null; state: string; blocked?: { code: string; message: string } }> {
    // Multi-instances : avec configId, adaptateur pris sur l'instance de configuration et cohérence du type de plateforme vérifiée ; sinon la première du provider (comportement historique)
    const adapter = options.configId !== undefined
      ? this.ctx.iam.getAuthProviderByConfig(options.configId)
      : this.ctx.iam.getAuthProvider(provider)
    if (options.configId !== undefined && adapter.type !== provider) {
      throw new Error(t('连接器实例（{configId}）平台类型 {type} 与请求 provider {provider} 不一致', { configId: options.configId, type: adapter.type, provider }))
    }
    const state = randomUUID().replace(/-/g, '')
    this.oauthStates().insert({
      id: state,
      createdAt: new Date().toISOString(),
      provider,
      ...(options.configId !== undefined ? { configId: options.configId } : {}),
      scene,
      purpose: options.purpose ?? 'login',
      ...(options.userId !== undefined ? { userId: options.userId } : {}),
    })
    // redirect_uri prend en priorité le callbackUrl de la configuration de connecteur (doit correspondre mot à mot à la liste blanche « paramètres de sécurité » de la console DingTalk) ;
    // sans configuration, repli sur /api/auth/sso/callback déduit de l'origin.
    const configured = (options.configId !== undefined
      ? this.ctx.iam.connectorConfigById(options.configId)?.callbackUrl
      : this.ctx.iam.connectorConfig(provider)?.callbackUrl)?.trim()
    const redirectUri = configured || (origin ? `${origin.replace(/\/+$/, '')}/api/auth/sso/callback` : '/api/auth/sso/callback')
    const authorizeUrl = await adapter.buildAuthorizeUrl(scene, state, redirectUri, { promptConsent: options.promptConsent ?? false })
    // Pré-contrôle de refus au niveau application (DingTalk 900103 « application inexistante ») : plutôt que d'envoyer l'utilisateur vers une page d'erreur qu'il ne peut que fermer,
    // mieux vaut donner sur la page de connexion le conseil « quelle entrée ouvrir dans la console développeur DingTalk ». Un échec du pré-contrôle ne bloque pas (anomalie réseau = passage).
    let blocked: { code: string; message: string } | undefined
    if (authorizeUrl && adapter.probeAuthorize) {
      const cacheKey = `${provider}|${options.configId ?? ''}|${redirectUri}`
      const cached = this.authorizeProbeCache.get(cacheKey)
      const probe = cached && Date.now() - cached.at < 120_000
        ? cached
        : { at: Date.now(), ...(await adapter.probeAuthorize(redirectUri).catch(() => ({ ok: true }))) }
      this.authorizeProbeCache.set(cacheKey, probe)
      if (!probe.ok) blocked = { code: probe.code ?? 'AUTHORIZE_BLOCKED', message: probe.message ?? '' }
    }
    return { authorizeUrl, state, ...(blocked ? { blocked } : {}) }
  }

  /**
   * Achève la connexion tierce : consommation unique du state → chaîne de l'Adapter (exchangeCode/getUserInfo/normalizeProfile)
   * → correspondance d'un lien d'identité = connexion directe ; sinon émission d'un billet de liaison en attente (deux branches : lier un compte existant / créer un nouveau compte).
   */
  async completeSso(provider: string, code: string, state: string): Promise<{ kind: 'hit'; session: { token: string; refreshToken: string; access: TokenRecord; sid: string }; userId: string } | { kind: 'pending'; pendingTicket: string; profileName: string }> {
    const stateRecord = this.oauthStates().get(state)
    if (!stateRecord) throw new Error(t('state 无效（未发起授权或已消费）'))
    if (stateRecord.consumedAt) throw new Error(t('state 已被使用（防重放）'))
    if (stateRecord.purpose === 'bind') throw new Error(t('state 用途为账号绑定，不能用于登录'))
    if (Date.now() - new Date(stateRecord.createdAt).getTime() > 10 * 60_000) throw new Error(t('state 已过期'))
    this.oauthStates().update(state, { consumedAt: new Date().toISOString() })

    // Multi-instances : l'enregistrement du state fait foi (le paramètre provider ne sert qu'à la compatibilité des anciens appels) ; configId trouvé → adaptateur pris sur l'instance de configuration
    const ssoProvider = stateRecord.provider
    const adapter = stateRecord.configId
      ? this.ctx.iam.getAuthProviderByConfig(stateRecord.configId)
      : this.ctx.iam.getAuthProvider(ssoProvider)
    const tokenSet = await adapter.exchangeCode(code) // code à usage unique, rejeu lève ProviderAuthError
    const raw = await adapter.getUserInfo(tokenSet)
    const profile = adapter.normalizeProfile(raw)

    const link = this.ctx.iam.findLinkByProfile(ssoProvider, profile.providerUserId, profile.corpId)
    if (link) {
      const user = this.ctx.iam.users().get(link.userId)
      if (!user) throw new Error(t('身份链接指向的账号不存在'))
      if (user.status !== 'active') throw new Error(t('账号状态异常，无法登录'))
      const principal = this.ensureHumanPrincipal(user.id, user.displayName)
      const session = this.issueSessionPair(principal.id, { issuedBy: 'sso:' + ssoProvider })
      this.ctx.iam.markLogin(user.id)
      this.ctx.platformBus.emit(PlatformEvents.TokenIssued, { jti: session.access.jti, principalId: principal.id, kind: 'access' })
      return { kind: 'hit', session, userId: user.id }
    }
    const ticket = newId('tkt')
    this.ssoTickets().insert({
      id: ticket,
      provider: ssoProvider,
      profile: {
        providerUserId: profile.providerUserId,
        corpId: profile.corpId,
        name: profile.name,
        ...(profile.email !== undefined ? { email: profile.email } : {}),
      },
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    })
    return { kind: 'pending', pendingTicket: ticket, profileName: profile.name }
  }

  /** Lit l'usage enregistré dans le state (pour le dispatch des routes de callback ; sans consommer). */
  peekOAuthState(state: string): { provider: string; purpose: 'login' | 'bind'; userId?: string; configId?: string } {
    const record = this.oauthStates().get(state)
    if (!record) throw new Error(t('state 无效（未发起授权或已消费）'))
    return {
      provider: record.provider,
      purpose: record.purpose ?? 'login',
      ...(record.userId !== undefined ? { userId: record.userId } : {}),
      ...(record.configId !== undefined ? { configId: record.configId } : {}),
    }
  }

  /**
   * Achève la liaison par scan (purpose=bind) : consommation unique du state → chaîne de l'Adapter pour obtenir l'unionId
   * → liaison au compte plateforme verrouillé par le state. Aucune saisie manuelle d'identifiant tiers nécessaire sur tout le parcours.
   * « Une personne, un compte » est garanti par la contrainte d'unicité au niveau moteur de identityLinks.
   */
  async completeSsoBind(code: string, state: string): Promise<{ userId: string; provider: string; displayName: string; providerUserId: string }> {
    const stateRecord = this.oauthStates().get(state)
    if (!stateRecord) throw new Error(t('state 无效（未发起授权或已消费）'))
    if (stateRecord.consumedAt) throw new Error(t('state 已被使用（防重放）'))
    if ((stateRecord.purpose ?? 'login') !== 'bind') throw new Error(t('state 用途不是账号绑定'))
    if (!stateRecord.userId) throw new Error(t('绑定目标账号缺失，请重新发起绑定'))
    if (Date.now() - new Date(stateRecord.createdAt).getTime() > 10 * 60_000) throw new Error(t('state 已过期'))
    this.oauthStates().update(state, { consumedAt: new Date().toISOString() })

    // Multi-instances : state portant configId → adaptateur de l'instance de configuration ; sinon la première du provider (comportement historique)
    const adapter = stateRecord.configId
      ? this.ctx.iam.getAuthProviderByConfig(stateRecord.configId)
      : this.ctx.iam.getAuthProvider(stateRecord.provider)
    const tokenSet = await adapter.exchangeCode(code) // code à usage unique, rejeu lève ProviderAuthError
    const raw = await adapter.getUserInfo(tokenSet)
    const profile = adapter.normalizeProfile(raw)

    const user = this.ctx.iam.users().get(stateRecord.userId)
    if (!user) throw new Error(t('绑定目标账号不存在'))
    if (user.status === 'deactivated') throw new Error(t('绑定目标账号已注销'))
    const existing = this.ctx.iam.findLinkByProfile(stateRecord.provider, profile.providerUserId, profile.corpId)
    if (existing && existing.userId !== user.id) {
      throw new Error(t('该钉钉身份已绑定其他平台账号（一人一号）'))
    }
    if (user.bindings.some((item) => item.provider === stateRecord.provider) && !existing) {
      throw new Error(t('该账号已绑定钉钉身份，请先解绑再重新绑定'))
    }
    if (!existing) {
      this.ctx.iam.linkIdentity(user.id, {
        provider: stateRecord.provider as 'dingtalk',
        providerUserId: profile.providerUserId,
        corpId: profile.corpId,
        displayName: profile.name,
      }, 'sso-bind-oauth')
    }
    return { userId: user.id, provider: stateRecord.provider, displayName: profile.name, providerUserId: profile.providerUserId }
  }

  /** Billet de liaison → liaison à un compte plateforme existant (validation du mot de passe) → création du lien d'identité et connexion. */
  ssoBindExisting(pendingTicket: string, username: string, password: string): { session: { token: string; refreshToken: string; access: TokenRecord; sid: string }; userId: string } {
    const ticket = this.peekTicket(pendingTicket)
    const throttleKey = `sso-bind:${username}`
    this.assertNotLocked(throttleKey)
    let user
    try {
      user = this.ctx.iam.verifyPassword(username, password)
    } catch (error) {
      this.recordLoginFailure(throttleKey)
      throw error
    }
    this.recordLoginSuccess(throttleKey)
    this.ctx.iam.linkIdentity(user.id, {
      provider: ticket.provider as 'dingtalk',
      providerUserId: ticket.profile['providerUserId'] ?? '',
      corpId: ticket.profile['corpId'] ?? '',
      displayName: ticket.profile['name'] ?? '',
    }, 'sso-bind:' + username)
    this.consumeTicket(pendingTicket)
    const principal = this.ensureHumanPrincipal(user.id, user.displayName)
    const session = this.issueSessionPair(principal.id, { issuedBy: 'sso-bind:' + ticket.provider })
    this.ctx.iam.markLogin(user.id)
    return { session, userId: user.id }
  }

  /** Billet de liaison → création d'un nouveau compte (par défaut dans la première organisation) → création du lien d'identité et connexion. */
  ssoRegister(pendingTicket: string): { session: { token: string; refreshToken: string; access: TokenRecord; sid: string }; userId: string } {
    const ticket = this.consumeTicket(pendingTicket)
    void ticket
    const defaultOrg = this.ctx.iam.orgs().all()[0]
    if (!defaultOrg) throw new Error(t('平台尚未初始化组织，无法注册'))
    const username = ticket.provider + '_' + (ticket.profile['providerUserId'] ?? '')
    const { user } = this.ctx.iam.createUser({
      username,
      displayName: ticket.profile['name'] ?? username,
      orgId: defaultOrg.id,
      email: ticket.profile['email'],
    }, SYSTEM_ACTOR)
    this.ctx.iam.activateUser(user.id, SYSTEM_ACTOR)
    this.ctx.iam.linkIdentity(user.id, {
      provider: ticket.provider as 'dingtalk',
      providerUserId: ticket.profile['providerUserId'] ?? '',
      corpId: ticket.profile['corpId'] ?? '',
      displayName: ticket.profile['name'] ?? '',
    }, 'sso-register')
    const principal = this.ensureHumanPrincipal(user.id, user.displayName)
    const session = this.issueSessionPair(principal.id, { issuedBy: 'sso-register:' + ticket.provider })
    this.ctx.iam.markLogin(user.id)
    return { session, userId: user.id }
  }

  /** Lit le billet (sans consommer). */
  private peekTicket(pendingTicket: string): { provider: string; profile: Record<string, string> } {
    const ticket = this.ssoTickets().get(pendingTicket)
    if (!ticket) throw new Error(t('待绑定票据无效'))
    if (ticket.usedAt) throw new Error(t('票据已被使用'))
    if (new Date(ticket.expiresAt).getTime() < Date.now()) throw new Error(t('票据已过期，请重新发起授权'))
    return { provider: ticket.provider, profile: ticket.profile }
  }

  private consumeTicket(pendingTicket: string): { provider: string; profile: Record<string, string> } {
    const ticket = this.ssoTickets().get(pendingTicket)
    if (!ticket) throw new Error(t('待绑定票据无效'))
    if (ticket.usedAt) throw new Error(t('票据已被使用'))
    if (new Date(ticket.expiresAt).getTime() < Date.now()) throw new Error(t('票据已过期，请重新发起授权'))
    this.ssoTickets().update(pendingTicket, { usedAt: new Date().toISOString() })
    return { provider: ticket.provider, profile: ticket.profile }
  }

  tokens(): Collection<TokenRecord> {
    return this.ctx.opsStorage.collection<TokenRecord>('authn:tokens')
  }

  private loadOrCreateSecret(): string {
    const file = join(this.ctx.opsStorage.dataDirPath, 'authn-signing-secret')
    try {
      if (existsSync(file)) return readFileSync(file, 'utf8').trim()
      mkdirSync(this.ctx.opsStorage.dataDirPath, { recursive: true })
      const secret = generateSecret('sign')
      writeFileSync(file, secret, { encoding: 'utf8', mode: 0o600 })
      return secret
    } catch (error) {
      // La rétrogradation en clé en mémoire doit alerter explicitement (un redémarrage invalide tous les jetons, pas de silence)
      console.error('[authn] 签名密钥读取/落盘失败，降级为进程内密钥（重启后所有令牌失效）', error)
      return generateSecret('sign')
    }
  }

  private loadRetiredSecrets(): void {
    try {
      const file = join(this.ctx.opsStorage.dataDirPath, 'authn-signing-secret-history.json')
      if (!existsSync(file)) return
      const stored = JSON.parse(readFileSync(file, 'utf8')) as Array<{ secret: string; retiredAt: number }>
      const cutoff = Date.now() - SECRET_GRACE_MS
      this.retiredSecrets = stored.filter((item) => item.retiredAt > cutoff)
    } catch { /* fichier historique absent/corrompu : traité comme absence de clé de grâce */ }
  }

  private saveRetiredSecrets(): void {
    try {
      const file = join(this.ctx.opsStorage.dataDirPath, 'authn-signing-secret-history.json')
      writeFileSync(file, JSON.stringify(this.retiredSecrets, null, 2), 'utf8')
    } catch (error) {
      console.error('[authn] 退役密钥历史落盘失败（仅影响轮换宽限）', error)
    }
  }

  /**
   * Rotation de la clé de signature (correctif revue S2) : l'ancienne clé entre en période de grâce (24 h par défaut) au lieu d'être invalidée immédiatement —
   * pendant la grâce, les anciens jetons passent encore la vérification (les requêtes en vol ne sont pas déconnectées), puis expirent naturellement ;
   * les sessions peuvent à tout moment échanger un refresh token contre un jeton d'accès signé par la nouvelle clé, rotation imperceptible globalement.
   */
  rotateSigningSecret(): { graceMs: number } {
    this.retiredSecrets = [
      ...this.retiredSecrets.filter((item) => Date.now() - item.retiredAt < SECRET_GRACE_MS),
      { secret: this.signingSecret, retiredAt: Date.now() },
    ]
    this.signingSecret = generateSecret('sign')
    const file = join(this.ctx.opsStorage.dataDirPath, 'authn-signing-secret')
    writeFileSync(file, this.signingSecret, 'utf8')
    this.saveRetiredSecrets()
    return { graceMs: SECRET_GRACE_MS }
  }

  /** Vérifie la signature : d'abord la clé courante, puis les clés retirées encore en grâce (compatibilité pendant la rotation). */
  private signatureMatches(body: string, signature: string): boolean {
    const candidates = [this.signingSecret, ...this.retiredSecrets.filter((item) => Date.now() - item.retiredAt < SECRET_GRACE_MS).map((item) => item.secret)]
    return candidates.some((secret) => createHmac('sha256', secret).update(body).digest('base64url') === signature)
  }

  /** Nettoyage des jetons expirés/révoqués (revue M2) : suppression physique après 7 jours d'expiration (une période de refresh conservée pour l'expertise de rejeu), l'état révoqué ne s'accumule plus indéfiniment. */
  cleanupExpiredTokens(): number {
    const cutoff = Date.now() - 7 * 24 * 3600_000
    let removed = 0
    for (const token of this.tokens().all()) {
      if (new Date(token.expiresAt).getTime() < cutoff) {
        if (this.tokens().remove(token.id)) removed++
      }
    }
    return removed
  }

  // -- Principal ----------------------------------------------------------

  humanPrincipal(userId: string): PrincipalRecord | undefined {
    return this.principals().findOne((item) => item.type === 'human' && item.refId === userId)
  }

  ensureHumanPrincipal(userId: string, name: string): PrincipalRecord {
    const existing = this.humanPrincipal(userId)
    if (existing) return existing
    return this.principals().insert({
      id: newId('pri'),
      type: 'human',
      refType: 'user',
      refId: userId,
      name,
      status: 'active',
      scopes: [],
    })
  }

  /** Crée un identifiant d'identité machine (Client Credentials). Le secret n'est renvoyé qu'une fois ; autorisation = rôles machine (roleIds, synchronisation temps réel) + points de permission additionnels (scopes, devant figurer au catalogue). */
  createMachineCredential(input: {
    name: string
    refType?: 'agent' | 'app' | 'external'
    refId?: string
    roleIds?: string[]
    scopes: string[]
  }): { principal: PrincipalRecord; clientId: string; clientSecret: string } {
    this.assertMachineScopes(input.scopes)
    this.assertMachineRoles(input.roleIds ?? [])
    if ((input.roleIds ?? []).length === 0 && input.scopes.length === 0) throw new Error(t('授权不能为空：至少选择机器角色或附加权限点'))
    const clientId = `mc-${newId('id').slice(3)}`
    const clientSecret = generateSecret('cs')
    const principal = this.principals().insert({
      id: newId('pri'),
      type: 'machine',
      ...(input.refType !== undefined ? { refType: input.refType } : {}),
      ...(input.refId !== undefined ? { refId: input.refId } : {}),
      name: input.name,
      status: 'active',
      clientId,
      clientSecretHash: sha256Hex(clientSecret),
      ...((input.roleIds ?? []).length > 0 ? { roleIds: input.roleIds } : {}),
      scopes: input.scopes,
    })
    return { principal, clientId, clientSecret }
  }

  disablePrincipal(id: string, reason: string): PrincipalRecord {
    const principal = this.principals().get(id)
    if (!principal) throw new Error(t('身份不存在：{id}', { id }))
    this.revokePrincipalTokens(id, reason)
    return this.principals().update(id, { status: 'disabled' })
  }

  /** Valide les points de permission additionnels d'une identité machine : exactement ['*'] ou tous présents au catalogue de permissions (anti-faute de frappe, p. ex. usage.wrtie) ; nullable (l'autorisation peut venir intégralement des rôles machine).
   *  Incrément W3-T5 (contrat §12) : accepte les formes de scopes MCP à ressource limitée — mcp.service:<slug>.invoke / mcp.tool:<slug>:<tool>.invoke,
   *  validation de la forme du préfixe + (si le port est câblé) existence du service correspondant au slug ; les autres règles (présence au catalogue/'*' unique) inchangées. */
  private assertMachineScopes(scopes: string[]): void {
    if (scopes.length === 0) return
    if (scopes.includes('*')) {
      if (scopes.length !== 1) throw new Error(t("'*' 不可与其他权限点混用"))
      return
    }
    const catalog = new Set(PermissionCatalog.map((item) => item.point))
    const invalid = scopes.filter((scope) => !catalog.has(scope) && !this.validResourceScopedMcpScope(scope))
    if (invalid.length > 0) throw new Error(t('非法权限点：{points}（须为权限目录中的点、资源限定 mcp.service:/mcp.tool: 形态，或仅 \'*\'）', { points: invalid.join('、') }))
  }

  /** Port d'existence des scopes MCP à ressource limitée (W3-T5) : l'hôte (au montage console) peut injecter un callback d'existence de slug ; non câblé = validation de forme seule (port optionnel). */
  private mcpServiceExists: ((slug: string) => boolean) | undefined

  /** Enregistre le callback d'existence de service des scopes à ressource limitée (slug → existe ?) ; undefined = retour à la validation de forme seule. */
  setMcpServiceExistsCheck(fn: ((slug: string) => boolean) | undefined): void {
    this.mcpServiceExists = fn
  }

  /** Validation de forme des scopes MCP à ressource limitée (contrat §12) : mcp.service:<slug>.invoke / mcp.tool:<slug>:<tool>.invoke ; validation forte quand le port d'existence de slug est câblé. */
  private validResourceScopedMcpScope(scope: string): boolean {
    const service = /^mcp\.service:([^:\s]+)\.invoke$/.exec(scope)
    if (service) return this.mcpServiceExists ? this.mcpServiceExists(service[1]!) : true
    const tool = /^mcp\.tool:([^:\s]+):([^:\s]+)\.invoke$/.exec(scope)
    if (tool) return this.mcpServiceExists ? this.mcpServiceExists(tool[1]!) : true
    return false
  }

  /** Valide les références de rôles machine : les rôles doivent réellement exister (stockage iam:roles partagé). */
  private assertMachineRoles(roleIds: string[]): void {
    for (const roleId of roleIds) {
      if (!this.ctx.iam.roles().get(roleId)) throw new Error(t('机器角色不存在：{id}', { id: roleId }))
    }
  }

  /** Permissions effectives d'un sujet machine = permissions des rôles (expansion des jokers, synchronisation temps réel) ∪ points de permission directs additionnels. */
  resolveMachineScopes(principal: PrincipalRecord): string[] {
    const fromRoles = this.ctx.iam.resolveRolePermissions(principal.roleIds ?? [])
    if (fromRoles.includes('*') || principal.scopes.includes('*')) return ['*']
    const merged = new Set([...fromRoles, ...principal.scopes])
    return [...merged]
  }

  /** Ajuste l'autorisation d'une identité machine (rôles / points additionnels) ; révocation en cascade de tous les jetons existants (retrait de droit effectif immédiat, prochaine émission au nouveau périmètre). */
  updateMachineScopes(id: string, patch: { roleIds?: string[]; scopes?: string[] }): PrincipalRecord {
    const principal = this.principals().get(id)
    if (!principal) throw new Error(t('身份不存在：{id}', { id }))
    if (principal.type !== 'machine') throw new Error(t('仅机器身份支持调整权限范围'))
    const roleIds = patch.roleIds ?? principal.roleIds ?? []
    const scopes = patch.scopes ?? principal.scopes
    this.assertMachineScopes(scopes)
    this.assertMachineRoles(roleIds)
    if (roleIds.length === 0 && scopes.length === 0) throw new Error(t('授权不能为空：至少保留机器角色或附加权限点'))
    const updated = this.principals().update(id, {
      ...(patch.roleIds !== undefined ? { roleIds } : {}),
      ...(patch.scopes !== undefined ? { scopes } : {}),
    })
    this.revokePrincipalTokens(id, t('权限范围调整联动'))
    return updated
  }

  /** Renouvelle le secret d'un identifiant machine : clientId inchangé, ancien secret invalidé immédiatement, tous les jetons existants révoqués ; le nouveau secret n'est renvoyé qu'une fois. */
  rotateMachineCredential(id: string): { principal: PrincipalRecord; clientSecret: string } {
    const principal = this.principals().get(id)
    if (!principal) throw new Error(t('身份不存在：{id}', { id }))
    if (principal.type !== 'machine' || !principal.clientId) throw new Error(t('仅机器凭证（clientId/clientSecret）支持轮换'))
    const clientSecret = generateSecret('cs')
    const updated = this.principals().update(id, { clientSecretHash: sha256Hex(clientSecret) })
    this.revokePrincipalTokens(id, t('凭证轮换联动'))
    return { principal: updated, clientSecret }
  }

  enablePrincipal(id: string): PrincipalRecord {
    return this.principals().update(id, { status: 'active' })
  }

  // -- Connexion ---------------------------------------------------------------

  /** Collection des compteurs de tentatives de connexion (durable : un redémarrage ne remet pas à zéro). */
  loginAttempts(): Collection<LoginAttemptRecord> {
    const collection = this.ctx.opsStorage.collection<LoginAttemptRecord>('authn:loginAttempts')
    collection.uniqueOn('login_attempt_key', (item) => item.key)
    return collection
  }

  /** Contrôle de verrouillage : dans la fenêtre de verrouillage → refus direct (revue S3 : réduction de la surface de force brute ; réutilisé par les points d'autorisation/échange OIDC). */
  assertNotLocked(key: string): void {
    const record = this.loginAttempts().findOne((item) => item.key === key)
    if (!record?.lockedUntil) return
    const remainMs = new Date(record.lockedUntil).getTime() - Date.now()
    if (remainMs > 0) {
      const minutes = Math.ceil(remainMs / 60_000)
      throw new Error(t('失败次数过多已锁定：请约 {minutes} 分钟后重试（或联系管理员重置）', { minutes }))
    }
  }

  recordLoginFailure(key: string): void {
    const collection = this.loginAttempts()
    const now = Date.now()
    const existing = collection.findOne((item) => item.key === key)
    if (!existing) {
      collection.insert({ id: newId('lga'), key, fails: 1, windowStart: new Date().toISOString(), lockCount: 0 })
      return
    }
    // Nouveau comptage après glissement de la fenêtre
    const inWindow = now - new Date(existing.windowStart).getTime() < LOGIN_WINDOW_MS
    const fails = inWindow ? existing.fails + 1 : 1
    const patch: Partial<LoginAttemptRecord> = {
      fails,
      ...(inWindow ? {} : { windowStart: new Date().toISOString() }),
    }
    if (fails >= LOGIN_MAX_FAILS) {
      const lockCount = existing.lockCount + 1
      const lockMs = Math.min(LOGIN_BASE_LOCK_MS * 2 ** (lockCount - 1), LOGIN_MAX_LOCK_MS)
      patch.lockCount = lockCount
      patch.lockedUntil = new Date(now + lockMs).toISOString()
      patch.fails = 0
      this.ctx.platformBus.emit(PlatformEvents.AlertFired, {
        id: newId('alt'), severity: 'warning', title: t('登录失败锁定触发'),
        message: t('主体 {key} 在 {window} 分钟内连续失败 {maxFails} 次，锁定 {lockMinutes} 分钟（暴力破解防护）', { key, window: LOGIN_WINDOW_MS / 60_000, maxFails: LOGIN_MAX_FAILS, lockMinutes: Math.round(lockMs / 60_000) }),
        resourceType: 'authn', resourceId: key,
      })
    }
    collection.update(existing.id, patch)
  }

  recordLoginSuccess(key: string): void {
    const collection = this.loginAttempts()
    const existing = collection.findOne((item) => item.key === key)
    if (existing) collection.remove(existing.id)
  }

  login(username: string, password: string): { token: string; refreshToken: string; sid: string; record: TokenRecord; principal: PrincipalRecord; userId: string } {
    const throttleKey = `login:${username}`
    this.assertNotLocked(throttleKey)
    let user
    try {
      user = this.ctx.iam.verifyPassword(username, password)
    } catch (error) {
      this.recordLoginFailure(throttleKey)
      throw error
    }
    this.recordLoginSuccess(throttleKey)
    const principal = this.ensureHumanPrincipal(user.id, user.displayName)
    const session = this.issueSessionPair(principal.id, { issuedBy: `password:${username}` })
    this.ctx.iam.markLogin(user.id)
    this.ctx.platformBus.emit(PlatformEvents.TokenIssued, { jti: session.access.jti, principalId: principal.id, kind: 'access' })
    return { token: session.token, refreshToken: session.refreshToken, sid: session.sid, record: session.access, principal, userId: user.id }
  }

  clientCredentialsLogin(clientId: string, clientSecret: string): { token: string; record: TokenRecord; principal: PrincipalRecord } {
    const throttleKey = `cc:${clientId}`
    this.assertNotLocked(throttleKey)
    const principal = this.principals().findOne((item) => item.clientId === clientId)
    if (!principal || principal.clientSecretHash !== sha256Hex(clientSecret)) {
      this.recordLoginFailure(throttleKey)
      throw new Error(t('client_id 或 client_secret 错误'))
    }
    this.recordLoginSuccess(throttleKey)
    if (principal.status !== 'active') throw new Error(t('机器身份已禁用'))
    const { token, record } = this.issueToken(principal.id, {
      kind: 'machine',
      ttlHours: 2,
      scopes: this.resolveMachineScopes(principal),
      issuedBy: 'client_credentials',
    })
    this.ctx.platformBus.emit(PlatformEvents.TokenIssued, { jti: record.jti, principalId: principal.id, kind: 'machine' })
    return { token, record, principal }
  }

  // -- Jetons ---------------------------------------------------------------

  issueToken(principalId: string, options: {
    kind: TokenRecord['kind']
    ttlHours?: number
    scopes?: string[]
    audience?: string
    actChain?: ActEntry[]
    issuedBy?: string
    sid?: string
    chainId?: string
    /** Complément de jeton délégué (contrat de gouvernance MCP §3) : utilisateur représenté / instantané d'audience (non produit par défaut, comportement existant inchangé). */
    delegatedUserId?: string
    delegationAudience?: string
    /** Note du jeton d'accès personnel (canal de libre-service MCP des employés, stockée dans TokenRecord pour être visible dans les listes). */
    label?: string
  }): { token: string; record: TokenRecord } {
    const principal = this.principals().get(principalId)
    if (!principal) throw new Error(t('身份不存在：{id}', { id: principalId }))
    if (principal.status !== 'active') throw new Error(t('身份已禁用，无法签发令牌'))
    // Surface de convergence d'audience des plugins (v1.2 étape 1) : aud = plugin:<id> → le scope doit intégralement rester dans l'espace de noms du plugin
    if (options.audience?.startsWith('plugin:')) {
      const namespace = `${options.audience}:`
      const offender = (options.scopes ?? []).find((scope) => scope !== '*' && !scope.startsWith(namespace))
      if (offender !== undefined) {
        throw new Error(t('插件令牌 scope 越界：{scope} 不在命名空间 {namespace} 内', { scope: offender, namespace }))
      }
    }
    const jti = randomUUID()
    const issuedAt = new Date()
    const expiresAt = new Date(issuedAt.getTime() + (options.ttlHours ?? 2) * 3600_000)
    const payload = {
      iss: 'dsh-ops-authn',
      sub: principal.id,
      typ: options.kind,
      jti,
      iat: Math.floor(issuedAt.getTime() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
      scope: options.scopes ?? [],
      act: options.actChain ?? [],
      ...(options.audience !== undefined ? { aud: options.audience } : {}),
      ...(options.sid !== undefined ? { sid: options.sid } : {}),
    }
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const sig = createHmac('sha256', this.signingSecret).update(body).digest('base64url')
    const token = `dst1.${body}.${sig}`
    const record = this.tokens().insert({
      id: jti,
      jti,
      principalId,
      kind: options.kind,
      scopes: options.scopes ?? [],
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
      actChain: options.actChain ?? [],
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      issuedBy: options.issuedBy ?? 'api',
      ...(options.sid !== undefined ? { sid: options.sid } : {}),
      ...(options.chainId !== undefined ? { chainId: options.chainId } : {}),
      ...(options.delegatedUserId !== undefined ? { delegatedUserId: options.delegatedUserId } : {}),
      ...(options.delegationAudience !== undefined ? { delegationAudience: options.delegationAudience } : {}),
      ...(options.label !== undefined ? { label: options.label } : {}),
    })
    return { token, record }
  }

  /**
   * Échange de jeton délégué (contrat de gouvernance MCP §3, sous-ensemble sémantique de RFC 8693) :
   *   - appelant humain : peut émettre un jeton de délégation OBO pour un principal agent/app cible (sub = utilisateur, act = appelant + cible) ;
   *   - appelant machine (identifiants agent/app) : peut échanger avec un userId contre un jeton délégué sub = cet utilisateur (act = sujet appelant) ;
   *   - validation des faits d'autorisation fail-closed : sans delegationGuard injecté, refus systématique (DELEGATION_GUARD_UNAVAILABLE) ;
   *   - validation forte d'audience : forme mcp:service:<slug> ou plugin:<id> obligatoire (réutilise la convergence issueToken existante) ;
   *   - scopes = requête ∩ scopes de l'appelant ∩ scopes du principal cible (resserrement secondaire du préfixe delegate: côté verify) ;
   *   - TTL défaut 900 s, plafond 3600 s ; sauts de la chaîne act (après l'humain) ≤ 4.
   * issueOnBehalfOf reste inchangé (compatibilité ancienne chaîne).
   */
  async exchangeDelegatedToken(input: {
    caller: VerifiedPrincipal
    userId?: string
    targetPrincipalId?: string
    audience: string
    scopes?: string[]
    ttlSeconds?: number
  }): Promise<{ token: string; record: TokenRecord }> {
    if (!this.delegationGuard) {
      throw new DelegationError('DELEGATION_GUARD_UNAVAILABLE', t('委托授权钩子未装配（fail-closed），令牌交换被拒绝'))
    }
    // Validation forte de la forme d'audience : seules les formes service MCP et espace de noms plugin sont acceptées
    const audience = String(input.audience ?? '')
    if (!(audience.startsWith('mcp:service:') && audience.length > 'mcp:service:'.length)
      && !(audience.startsWith('plugin:') && audience.length > 'plugin:'.length)) {
      throw new DelegationError('DELEGATION_AUDIENCE_INVALID', t('委托令牌受众必须是 mcp:service:<slug> 或 plugin:<id> 形态'))
    }
    const ttlSeconds = Math.min(Math.max(Math.floor(Number(input.ttlSeconds ?? DELEGATION_TTL_DEFAULT_SECONDS)) || DELEGATION_TTL_DEFAULT_SECONDS, 1), DELEGATION_TTL_MAX_SECONDS)

    const caller = input.caller
    const callerEntry: ActEntry = { principalId: caller.principal.id, name: caller.principal.name, type: caller.principal.type }
    let subjectPrincipalId: string
    let subjectUserId: string
    let actChain: ActEntry[]
    let targetScopes: string[]

    if (caller.principal.type === 'human') {
      // Appelant humain : principal agent/app cible obligatoire, sub = utilisateur (soi-même ou sujet explicitement désigné)
      if (!input.targetPrincipalId) {
        throw new DelegationError('DELEGATION_TARGET_REQUIRED', t('人类调用者必须指定目标主体（targetPrincipalId，agent/app）'))
      }
      const target = this.principals().get(input.targetPrincipalId)
      if (!target || target.type !== 'machine' || !(target.refType === 'agent' || target.refType === 'app')) {
        throw new DelegationError('DELEGATION_TARGET_INVALID', t('目标主体不存在或不是 agent/app 机器主体'))
      }
      subjectUserId = input.userId ?? caller.principal.refId ?? ''
      if (!subjectUserId) throw new DelegationError('DELEGATION_USER_REQUIRED', t('调用者令牌缺少用户身份（refId），无法确定委托 subject'))
      // L'utilisateur sujet doit réellement exister et être enregistré (validation du profil quand un tiers est explicitement désigné, anti-erreur de sujet)
      const subjectUser = this.ctx.iam.users().get(subjectUserId)
      if (!subjectUser) throw new DelegationError('DELEGATION_USER_NOT_FOUND', t('委托 subject 用户不存在：{id}', { id: subjectUserId }))
      if (subjectUser.status !== 'active') throw new DelegationError('DELEGATION_USER_INACTIVE', t('委托 subject 用户状态异常（{status}），拒绝签发', { status: subjectUser.status }))
      const subjectPrincipal = this.ensureHumanPrincipal(subjectUser.id, subjectUser.displayName)
      subjectPrincipalId = subjectPrincipal.id
      actChain = [...caller.actChain, callerEntry, { principalId: target.id, name: target.name, type: target.type }]
      targetScopes = this.resolveMachineScopes(target)
    } else {
      // Appelant machine : deux modes
      //  ① Auto-délégation (sans userId/targetPrincipalId) : sub = appelant lui-même, chaîne act vide — la forme « appels propres de l'Agent »
      //     du plan §6.2 (sub=agent:xxx, aud=mcp:service:<slug>). L'identifiant machine longue durée de la plateforme
      //     ne sort pas du domaine, on n'échange que contre un « jeton court + audience liée à un seul service » (validation forte d'aud appliquée au plan de données).
      //  ② Délégation pour un utilisateur (avec userId) : sub = cet utilisateur, chaîne act contenant le sujet appelant (sémantique existante inchangée).
      if (input.targetPrincipalId) {
        throw new DelegationError('DELEGATION_TARGET_NOT_ALLOWED', t('机器调用者仅可携带 userId 换取委托令牌（不可指定 targetPrincipalId）'))
      }
      if (!input.userId) {
        // Auto-délégation : le sujet est l'appelant lui-même, ni profil utilisateur ni validation de liaison requis
        subjectPrincipalId = caller.principal.id
        actChain = []
        targetScopes = caller.scopes
      } else {
        const user = this.ctx.iam.users().get(input.userId)
        if (!user) throw new DelegationError('DELEGATION_USER_NOT_FOUND', t('委托 subject 用户不存在：{id}', { id: input.userId }))
        if (user.status !== 'active') throw new DelegationError('DELEGATION_USER_INACTIVE', t('委托 subject 用户状态异常（{status}），拒绝签发', { status: user.status }))
        const subjectPrincipal = this.ensureHumanPrincipal(user.id, user.displayName)
        subjectUserId = user.id
        subjectPrincipalId = subjectPrincipal.id
        actChain = [...caller.actChain, callerEntry]
        targetScopes = this.ctx.iam.userPermissions(user.id)
      }
    }

    // Sauts de la chaîne act : si la tête est human, elle ne se compte pas (≤ 4 après l'humain) ; si la tête est machine, tout compte (l'utilisateur sujet est l'humain hors chaîne)
    const jumps = actChain.length > 0 && actChain[0]!.type === 'human' ? actChain.length - 1 : actChain.length
    if (jumps > DELEGATION_CHAIN_MAX_JUMPS) {
      throw new DelegationError('DELEGATION_CHAIN_TOO_LONG', t('委托链过长：human 之后跳数 {jumps} 超过上限 {max}', { jumps, max: DELEGATION_CHAIN_MAX_JUMPS }))
    }

    // Validation des faits d'autorisation (fail-closed) : refus du guard/indisponible = arrêt immédiat
    const allowed = await this.delegationGuard({
      userId: subjectUserId,
      ...(input.targetPrincipalId !== undefined ? { targetPrincipalId: input.targetPrincipalId } : {}),
      caller: {
        principalId: caller.principal.id,
        kind: caller.principal.type,
        ...(caller.principal.refType !== undefined ? { refType: caller.principal.refType } : {}),
        ...(caller.principal.refId !== undefined ? { refId: caller.principal.refId } : {}),
      },
    })
    if (!allowed) {
      throw new DelegationError('DELEGATION_DENIED', t('委托授权校验未通过（绑定关系/归属/管理员白名单均未命中）'))
    }

    // Intersection tripartite des scopes : requête ∩ scopes temps réel de l'appelant ∩ scopes du principal cible ('*' converge selon la sémantique d'intersection existante)
    const requested = input.scopes ?? caller.scopes
    const scopes = intersectScopes(intersectScopes(requested, caller.scopes), targetScopes)

    return this.issueToken(subjectPrincipalId, {
      kind: 'machine',
      ttlHours: ttlSeconds / 3600,
      scopes,
      audience,
      actChain,
      issuedBy: `delegate:${caller.principal.id}`,
      delegatedUserId: subjectUserId,
      delegationAudience: audience,
    })
  }

  /** Enregistre le crochet des faits d'autorisation de délégation (injecté à l'assemblage hôte ; undefined = retour au refus fail-closed). */
  setDelegationGuard(fn: DelegationGuardFn | undefined): void {
    this.delegationGuard = fn
  }

  /** on-behalf-of : émet un jeton de transmission pour un autre sujet sous l'identité du sujet courant (chaîne act superposée). */
  issueOnBehalfOf(parent: VerifiedPrincipal, targetPrincipalId: string): { token: string; record: TokenRecord } {
    const target = this.principals().get(targetPrincipalId)
    if (!target) throw new Error(t('目标身份不存在：{id}', { id: targetPrincipalId }))
    const actChain: ActEntry[] = [
      ...parent.actChain,
      { principalId: parent.principal.id, name: parent.principal.name, type: parent.principal.type },
    ]
    return this.issueToken(targetPrincipalId, {
      kind: 'machine',
      ttlHours: 1,
      scopes: intersectScopes(parent.scopes, target.scopes),
      actChain,
      issuedBy: `obo:${parent.principal.id}`,
    })
  }

  /**
   * Vérifie un jeton. Avec options.audience, contrôle d'audience : aud du jeton non concordant = refus
   * (v1.2 étape 1 : un jeton de plugin divulgué n'atteint pas les autres services de la plateforme).
   */
  verify(tokenString: string, options: { audience?: string } = {}): VerifiedPrincipal {
    const parts = tokenString.split('.')
    if (parts.length !== 3 || parts[0] !== 'dst1') throw new Error(t('令牌格式不合法'))
    if (!this.signatureMatches(parts[1]!, parts[2]!)) throw new Error(t('令牌签名校验失败'))
    let payload: any
    try {
      payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'))
    } catch {
      throw new Error(t('令牌载荷解析失败'))
    }
    if (payload.iss !== 'dsh-ops-authn') throw new Error(t('令牌签发方（iss）不匹配'))
    if (payload.exp * 1000 < Date.now()) throw new Error(t('令牌已过期'))
    if (options.audience !== undefined) {
      if (payload.aud === undefined) throw new Error(t('令牌未绑定受众（aud），目标服务要求受众校验'))
      if (payload.aud !== options.audience) throw new Error(t('令牌受众不匹配：期望 {expected}，实际 {actual}', { expected: options.audience, actual: payload.aud }))
    }
    const record = this.tokens().get(payload.jti)
    if (!record) throw new Error(t('令牌不存在或已被清理'))
    if (record.revokedAt) throw new Error(t('令牌已被吊销：{reason}', { reason: record.revokedReason ?? t('策略吊销') }))
    const principal = this.principals().get(record.principalId)
    if (!principal) throw new Error(t('令牌主体不存在'))
    if (principal.status !== 'active') throw new Error(t('令牌主体已禁用'))
    // Humain et machine résolus en temps réel : human par les rôles utilisateur, machine par rôles machine + points additionnels ; un changement de rôle se synchronise immédiatement aux jetons existants
    let scopes = principal.type === 'human'
      ? this.ctx.iam.userPermissions(principal.refId ?? '')
      : this.resolveMachineScopes(principal)
    // QA A-07 : à l'émission d'un jeton OBO, les scopes prennent l'intersection « chaîne parentale ∩ cible » — si la vérification résolvait seulement les permissions temps réel du sujet,
    // l'intersection serait perdue (le jeton transmis obtiendrait au contraire les permissions complètes de la cible). Pour les jetons OBO émis, resserrement secondaire à l'intersection d'émission :
    // la contraction des permissions temps réel reste effective (intersection), mais plus aucune amplification au-delà de ce qui était accordé à l'instant d'émission.
    // Gouvernance MCP (contrat §3) : même périmètre pour les jetons délégués au préfixe delegate: (intersection tripartite faite à l'émission, en temps réel on ne fait que resserrer).
    if (record.issuedBy?.startsWith('obo:') || record.issuedBy?.startsWith('delegate:')) {
      scopes = intersectScopes(scopes, record.scopes)
    }
    this.tokens().update(record.id, { lastUsedAt: new Date().toISOString() })
    return { principal, token: record, scopes, actChain: record.actChain }
  }

  hasPermission(verified: VerifiedPrincipal, point: string): boolean {
    return verified.scopes.includes('*') || verified.scopes.includes(point)
  }

  revokeToken(jti: string, reason: string): TokenRecord {
    const record = this.tokens().get(jti)
    if (!record) throw new Error(t('令牌不存在：{id}', { id: jti }))
    if (record.revokedAt) return record
    const updated = this.tokens().update(record.id, {
      revokedAt: new Date().toISOString(),
      revokedReason: reason,
    })
    this.ctx.platformBus.emit(PlatformEvents.TokenRevoked, { jti, principalId: record.principalId, reason })
    return updated
  }

  revokePrincipalTokens(principalId: string, reason: string): number {
    let count = 0
    for (const token of this.tokens().find((item) => item.principalId === principalId && !item.revokedAt)) {
      this.revokeToken(token.jti, reason)
      count++
    }
    return count
  }

  /** Le jeton est-il encore actif (DEF-03 : les enregistrements expirés/déjà tournés ne comptent pas comme « jetons actifs », pour éviter une dérive du comptage avec la durée d'exécution). */
  isTokenActive(token: TokenRecord, now = Date.now()): boolean {
    if (token.revokedAt) return false
    if (new Date(token.expiresAt).getTime() <= now) return false
    // Un refresh token déjà tourné (même chaîne, nouveaux jetons émis) n'est plus un identifiant actif
    if (token.kind === 'refresh' && token.rotatedAt) return false
    return true
  }

  activeTokenCount(principalId: string): number {
    return this.tokens().find((item) => item.principalId === principalId && this.isTokenActive(item)).length
  }
}

function intersectScopes(a: string[], b: string[]): string[] {
  if (a.includes('*')) return [...b]
  if (b.includes('*')) return [...a]
  const setB = new Set(b)
  return a.filter((scope) => setB.has(scope))
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    authn: AuthnService
  }
}

export const name = 'authn'
export const inject = ['opsStorage', 'platformBus', 'iam', 'httpServer']

export function apply(ctx: Context) {
  ctx.plugin(AuthnService)
  ctx.plugin(OidcService)
  ctx.plugin(EntryTicketService)
  ctx.plugin(authnTools)
}
