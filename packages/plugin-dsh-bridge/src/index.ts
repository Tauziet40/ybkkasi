/**
 * @dsh-ops/plugin-dsh-bridge — pont hôte dsh : montage du plan de données (M1) + liaison d'identité de la plateforme (M4).
 *
 * 【Moitié montage】 monte le plan de données method (ensemble des routes/middlewares/ressources statiques du httpServer de platform-core)
 * sous forme de préfixe d'URL dans le webServer dsh (ctx.webServer, unique écouteur du processus web dsh) :
 *   http://<host>:<port>/rq/*   →  le préfixe /rq retiré puis confié à httpServer.dispatch
 *   http://<host>:<port>/rq     →  302 /rq/ (normalisation en forme répertoire, garantit la résolution des références relatives de la SPA)
 *
 * 【Moitié identité】 le web dsh n'a pas de couche d'authentification propre (fence n'est pas auth, voir deepseek-harness connection/README),
 * et l'enveloppe RPC de /api n'expose pas de Cookie aux handlers — la liaison d'identité de la plateforme ne peut se faire que sur des routes propres
 * (les handlers de webServer.register disposent du req/res natif, peuvent lire les Cookie et poser des Set-Cookie) :
 *   GET  /auth/entry?ticket=…   échange d'un billet d'entrée à usage unique → Set-Cookie rq_sid → 302 /
 *                               (canal naturel de connexion sans ressaisie pour « ouvrir l'interface interactive » de la console/du portail)
 *   POST /dsh-bridge/redeem     échange {ticket} (appelé par le script d'amorçage tapIndex recevant le fragment #entry_ticket)
 *   GET  /dsh-bridge/status     lit le Cookie et renvoie l'identité liée (le plugin côté navigateur affiche l'état connecté)
 *   POST /dsh-bridge/logout     efface la liaison et le Cookie
 *   POST /dsh-bridge/bind-session {sessionId} associe la session dsh à l'identité liée
 *                               (attribution sortante des outils : exec.agent.session.id → X-On-Behalf-User)
 *
 * Stockage de liaison IdentityBindingService (provide 'identityBinding') :
 *   - byToken (rq_sid → identité, TTL 24 h) : à l'échange, consommation unique via EntryTicketService.redeem et
 *     validation en temps réel de l'état du compte ; à la lecture, nouvelle validation que le compte est active (gel/départ = invalidation immédiate).
 *   - bySession (sessionId → identité) : lié explicitement par le script d'amorçage du navigateur ; sans liaison, repli sur `current`
 *     (identité de la dernière liaison, posture LAN mono-opérateur) — l'attribution multi-utilisateurs concurrents est une limitation connue (dev-plan §7).
 *   - injection sortante plugin-nas : quand ctx.identityBinding existe, résout l'utilisateur réel par session/repli →
 *     X-On-Behalf-User (ligne rouge P0-2 : l'identité ne passe que par en-tête de requête) ; en forme autonome, ce service est absent, comportement inchangé.
 *
 * Fondements de conception : docs/internal/dev-plan-agent-host-unification.md §3/§5/§6.
 * Contrat de montage côté dsh (deepseek-harness packages/host/webserver/src/index.ts:94-101) :
 *   WebRoute = { kind:'exact'|'prefix', path, handler(req,res) }, le handler possède le cycle de réponse complet.
 * Contrainte dure : le préfixe `/api` et le siège de fallback global sont déjà occupés par dsh (un double enregistrement throw),
 * le plan de données method doit passer intégralement par un préfixe dédié (/rq).
 *
 * 【Resserrement du couplage W5】 tous les points de contact avec webServer passent par le port étroit pont hôte de platform-core
 * (HostWebPort, adapter = createHostWebPort) ; le registre de ports ctx.hostBridge
 * sonde ou monte directement (ctx léger = saut silencieux). Les clés inject et le comportement des routes/endpoints exposés ne changent pas —
 * en cas de dérive de l'API dsh à une montée de version, seul l'adapter change + relance des tests de contrat (tests/host-bridge.contract.mjs).
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { createHash, randomBytes } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Service } from '@deepseek-ai/cordis'
import { t } from '../../platform-i18n/src/index.ts'
import type { HttpServerService } from '../../platform-core/src/index.ts'
// Port étroit du pont hôte W5 : les contacts webServer passent tous par le type de port + adapter (createHostWebPort),
// ce fichier ne dépend plus directement de la forme concrète du webServer dsh ; une montée de version dsh ne demande que adapter + relance
// des tests de contrat (packages/plugin-dsh-bridge/tests/host-bridge.contract.mjs).
import {
  HostBridgeRegistry, createHostWebPort,
  type HostWebPort, type HostWebServerLike,
} from '../../platform-core/src/host-bridge.ts'

export interface DshBridgeConfig {
  /** Préfixe externe du plan de données method (par défaut /rq ; doit être un chemin non racine commençant par /). */
  mountPath?: string
  /** Nom du Cookie de liaison d'identité (par défaut rq_sid). */
  cookieName?: string
  /** Durée de validité de la liaison (secondes, 24 h par défaut). */
  bindTtlSeconds?: number
  /**
   * Fichier d'identifiants du client OIDC associé à l'Agent (produit de register-dsh-agent.mjs, contient oidc.clientId/clientSecret).
   * Par défaut <dataDir>/dsh-agent-credential.json ; une fois configuré, active le canal de connexion par code d'autorisation /auth/oidc/start.
   */
  oidcCredentialFile?: string
}

export const name = 'dsh-bridge'

/** webServer/httpServer fournis par le profil web dsh et platform-core ; entryTickets/oidc/authn/audit/iam assemblés par plugin-authn/iam/audit. */
// plan-gate01 Phase 3 (2026-09-10) [dérive contrôlée · inscrite au liste F] : inject réduit à 3 clés de dépendance dure —
// entryTickets/oidc assemblés par plugin-authn, iam/authn/audit sont le pain de l'hôte ; sous l'assemblage 01-gate 4-entry
// (cordis.patch.yml), aucun fournisseur n'existe, la déclaration resterait suspendue indéfiniment (sémantique cordis : déclarée + sans fournisseur = INACTIVE
// silencieuse, entérinée par le spike). L'accès à l'exécution relevait déjà d'une sémantique défensive optionnelle (entryTickets/oidc/iam sont tous « assertion de forme + lecture
// optionnelle », l'absence vaut dégradation honnête « seule la moitié montage est effective » / 503 AUTHN_UNAVAILABLE / audit?.record appel optionnel),
// ce qui correspond exactement à la surface déclarée après réduction ; en forme complète (cordis.yml 22 entry), tous les services sont présents, comportement inchangé.
export const inject = ['webServer', 'httpServer', 'opsStorage']

/**
 * Lecture souple des services optionnels (plan-gate01 Phase 3) : compatibilité double forme —
 *   - vrai ctx cordis : ctx.reflect.get(key, false) (contourne le contrôle inject ; l'accès à une propriété de clé non déclarée
 *     est durement jeté par le get trap « without inject », l'assertion de forme `(ctx as {k?}).k` n'y peut rien) ;
 *   - objet vue de services (baie selftest / objet simple monté à la main en assemblage léger) : sans façade reflect,
 *     lecture directe de propriété (un objet simple n'a pas de trap, l'absence vaut undefined).
 * Dans les deux formes, absence = undefined = dégradation honnête des fonctions d'identité du pont.
 */
const softRead = (ctx: any, key: string): any => {
  try {
    if (typeof ctx?.reflect?.get === 'function') return ctx.reflect.get(key, false)
    return ctx?.[key]
  } catch {
    return undefined
  }
}
// Note : identityBinding est fourni par montage direct de l'IdentityBindingService interne à cette extension (sans déclaration inject,
// pour éviter l'impasse « s'auto-fournit et s'auto-dépend ») ; iam/authn/audit passent par un accès défensif souple (absence = dégradation honnête des fonctions d'identité du pont).

const BIND_TOKEN_PREFIX = 'rbs_'
const DEFAULT_COOKIE = 'rq_sid'
const DEFAULT_TTL_SECONDS = 24 * 3600
const MAX_BINDINGS = 500

/** Surface de services minimale requise par les endpoints directs de session hôte (lecture défensive pour le ctx léger form B). */
interface BridgeUserView {
  id: string
  username: string
  displayName: string
  orgId: string
  roleIds: string[]
  status?: string
}

interface BridgeSessionDeps {
  authn?: {
    ensureHumanPrincipal(userId: string, displayName: string): { id: string }
    issueSessionPair(principalId: string, options: { issuedBy: string }): { token: string; refreshToken: string; access: { expiresAt: string } }
  }
  iam?: {
    users(): { get(id: string): BridgeUserView | undefined }
    roles(): { get(id: string): { name?: string } | undefined }
    markLogin(id: string): void
    userPermissions(id: string): string[]
  }
  audit?: {
    record(entry: Record<string, unknown>): unknown
  }
}

const base64url = (input: Buffer): string => input.toString('base64url')
const originOf = (req: IncomingMessage): string => {
  const proto = String(req.headers['x-forwarded-proto'] ?? 'http')
  return `${proto}://${req.headers.host ?? 'localhost'}`
}

interface BindingRecord {
  token: string
  userId: string
  name: string
  roles: string[]
  orgId?: string
  issuedAt: number
}

/** Stockage de liaison d'identité de la plateforme (Cookie ↔ identité, session dsh ↔ identité). Voir l'en-tête de module. */
export class IdentityBindingService extends Service {
  static readonly provide = 'identityBinding'

  private readonly byToken = new Map<string, BindingRecord>()
  private readonly bySession = new Map<string, string>()
  private current: BindingRecord | undefined
  private readonly ttlMs: number
  private readonly cookieName: string

  constructor(ctx: Context, config: { cookieName?: string; bindTtlSeconds?: number } = {}) {
    super(ctx, 'identityBinding')
    this.cookieName = config.cookieName ?? DEFAULT_COOKIE
    this.ttlMs = (config.bindTtlSeconds ?? DEFAULT_TTL_SECONDS) * 1000
  }

  /** Échange le billet et établit la liaison : consommation unique + validation en temps réel de l'état du compte faites dans redeem. */
  bindByTicket(redeem: (ticket: string) => { identity: { sub: string; name?: string; roles?: string[]; org?: { id?: string } } }, ticket: string): { token: string; identity: Record<string, unknown> } {
    const result = redeem(ticket)
    const token = BIND_TOKEN_PREFIX + randomBytes(24).toString('hex')
    const record: BindingRecord = {
      token,
      userId: result.identity.sub,
      name: result.identity.name ?? result.identity.sub,
      roles: result.identity.roles ?? [],
      orgId: result.identity.org?.id,
      issuedAt: Date.now(),
    }
    this.evictExpired()
    if (this.byToken.size >= MAX_BINDINGS) {
      const oldest = [...this.byToken.values()].sort((a, b) => a.issuedAt - b.issuedAt)[0]
      if (oldest) this.byToken.delete(oldest.token)
    }
    this.byToken.set(token, record)
    this.current = record
    return { token, identity: this.publicIdentity(record) }
  }

  /** Lit le Cookie et résout l'identité liée : expirée/inconnue/compte non active = toujours considéré non lié. */
  identityForCookie(cookieHeader: string | undefined): Record<string, unknown> | undefined {
    const token = this.readCookieToken(cookieHeader)
    if (!token) return undefined
    const record = this.byToken.get(token)
    if (!record || Date.now() - record.issuedAt > this.ttlMs) return undefined
    if (!this.isAccountActive(record.userId)) return undefined
    return this.publicIdentity(record)
  }

  /**
   * Auto-contrôle de liaison (WP-04/A2) : interrogation de l'état de liaison avec code de raison identifiable —
   * no_cookie (jamais lié/déconnecté) / expired (liaison expirée) / account_inactive (invalidée par le gel/départ du compte).
   * Le bandeau de l'espace de travail et le guidage de re-liaison affichent le libellé selon la reason (famille « liaison d'identité expirée » de errors.js).
   */
  bindingStatus(cookieHeader: string | undefined): { bound: boolean; reason?: 'no_cookie' | 'expired' | 'account_inactive'; identity?: Record<string, unknown> } {
    const token = this.readCookieToken(cookieHeader)
    if (!token) return { bound: false, reason: 'no_cookie' }
    const record = this.byToken.get(token)
    if (!record || Date.now() - record.issuedAt > this.ttlMs) return { bound: false, reason: 'expired' }
    if (!this.isAccountActive(record.userId)) return { bound: false, reason: 'account_inactive' }
    return { bound: true, identity: this.publicIdentity(record) }
  }

  /** Établit directement une liaison sous l'identité de la plateforme (canal code d'autorisation OIDC : après obtention du userinfo). */
  bindIdentity(identity: { sub: string; name?: string; roles?: string[]; org?: { id?: string } }): string {
    const token = BIND_TOKEN_PREFIX + randomBytes(24).toString('hex')
    const record: BindingRecord = {
      token,
      userId: identity.sub,
      name: identity.name ?? identity.sub,
      roles: identity.roles ?? [],
      orgId: identity.org?.id,
      issuedAt: Date.now(),
    }
    this.evictExpired()
    this.byToken.set(token, record)
    this.current = record
    return token
  }

  /** Lie une session dsh (appelé par le script d'amorçage du navigateur ; le Cookie détermine l'identité). */
  bindSession(sessionId: string, cookieHeader: string | undefined): boolean {
    const identity = this.identityForCookie(cookieHeader)
    if (!identity) return false
    this.evictExpired()
    if (this.bySession.size >= MAX_BINDINGS) {
      const oldest = this.bySession.keys().next().value
      if (oldest !== undefined) this.bySession.delete(oldest)
    }
    this.bySession.set(sessionId, String(identity.sub))
    return true
  }

  /** Résolution de l'attribution sortante des outils : la liaison de session prime, sans liaison repli sur la dernière liaison (posture mono-opérateur). */
  identityForSession(sessionId?: string): { userId: string; name: string } | undefined {
    this.evictExpired()
    const boundId = sessionId ? this.bySession.get(sessionId) : undefined
    const record = (boundId && [...this.byToken.values()].find((item) => item.userId === boundId)) ?? this.current
    if (!record || Date.now() - record.issuedAt > this.ttlMs) return undefined
    if (!this.isAccountActive(record.userId)) return undefined
    return { userId: record.userId, name: record.name }
  }

  /** Déconnexion : retire la liaison de ce Cookie (les liaisons de session expirent naturellement avec le TTL). */
  revoke(cookieHeader: string | undefined): void {
    const token = this.readCookieToken(cookieHeader)
    if (token) this.byToken.delete(token)
  }

  get cookie(): string {
    return this.cookieName
  }

  private publicIdentity(record: BindingRecord): Record<string, unknown> {
    return { sub: record.userId, name: record.name, roles: record.roles, org: record.orgId ? { id: record.orgId } : undefined }
  }

  private readCookieToken(cookieHeader: string | undefined): string | undefined {
    if (!cookieHeader) return undefined
    for (const part of cookieHeader.split(';')) {
      const [name, ...rest] = part.trim().split('=')
      if (name === this.cookieName) return decodeURIComponent(rest.join('='))
    }
    return undefined
  }

  private isAccountActive(userId: string): boolean {
    try {
      const iam = softRead(this.ctx, 'iam') as { users(): { get(id: string): { status?: string } | undefined } } | undefined
      const user = iam?.users().get(userId)
      if (!user) return false
      return user.status === undefined || user.status === 'active'
    } catch {
      // IAM indisponible (ne devrait pas arriver : arbre de plugins dans le même processus) — fail-closed, considéré non lié
      return false
    }
  }

  private evictExpired(): void {
    const now = Date.now()
    for (const [token, record] of this.byToken) {
      if (now - record.issuedAt > this.ttlMs) this.byToken.delete(token)
    }
  }
}


export function apply(ctx: Context, config: DshBridgeConfig = {}) {
  const mountPath = (config.mountPath ?? '/rq').replace(/\/+$/, '')
  // Montage direct (la classe de base Service enregistre ctx.identityBinding) : réutilise l'instance existante (injection de vue selftest), sinon en crée une.
  // Le ctx léger du loader dsh jette sur la lecture d'un service « non déclaré dans inject » (constaté en form B) :
  // on sonde d'abord puis on construit ; échec de sonde (non pré-injecté/élagué) = construction locale systématique.
  let prebound: IdentityBindingService | undefined
  try {
    prebound = (ctx as unknown as { identityBinding?: IdentityBindingService }).identityBinding
  } catch {
    prebound = undefined
  }
  const bindingService = prebound ?? new IdentityBindingService(ctx, { cookieName: config.cookieName, bindTtlSeconds: config.bindTtlSeconds })
  if (!mountPath.startsWith('/') || mountPath === '/') {
    throw new Error(t('dsh-bridge mountPath 非法：{value}（须为以 / 开头的非根路径）', { value: JSON.stringify(config.mountPath) }))
  }
  const webServer = (ctx as unknown as { webServer?: HostWebServerLike }).webServer
  const httpServer = (ctx as unknown as { httpServer?: HttpServerService }).httpServer
  if (!webServer || typeof webServer.register !== 'function') {
    throw new Error(t('dsh-bridge 需要 ctx.webServer（仅在完整 dsh web 宿主下装配本插件）'))
  }
  if (!httpServer) {
    throw new Error(t('dsh-bridge 需要 ctx.httpServer（platform-core 必须先于本插件装配）'))
  }

  // ---- Port étroit du pont hôte W5 : webServer → HostWebPort (resserrement par adapter)----------------
  // Le code métier (tous les enregistrements de routes ci-dessous et tapIndex) ne dépend que du port, pas de l'implémentation hôte.
  // Gradation de la surface de capacités (voir l'en-tête de platform-core/src/host-bridge.ts) :
  //   register obligatoire (vérifié ci-dessus) ; tapIndex optionnel (absence = dégradation du canal de script de connexion sans ressaisie,
  //   un faux webServer selftest sans cette capacité doit continuer de fonctionner — l'adapter resserre selon l'existence).
  const hostWeb: HostWebPort = createHostWebPort(webServer)
  // Enregistrement du port (au mieux) : sur le vrai arbre cordis, « sonder ou monter directement » ctx.hostBridge (aligné sur
  // la méthode d'auto-fourniture d'IdentityBindingService ci-dessus ; dans le périmètre W5, le apply de platform-core
  // n'assemble pas le registre). Le ctx léger (vue de services selftest) n'a pas de façade reflect cordis, la construction
  // jetterait — l'enregistrement est sauté, le port sert localement en direct, le comportement externe moitié montage/moitié identité ne change d'un cheveu.
  try {
    const existing = softRead(ctx, 'hostBridge') as HostBridgeRegistry | undefined
    const registry = existing && typeof existing.registerWebPort === 'function' ? existing : new HostBridgeRegistry(ctx)
    registry.registerWebPort(hostWeb)
  } catch {
    // Sans façade reflect (ctx plain-object) ou échec d'enregistrement : seule la prise inter-partie est absente, sans impact sur cette extension
  }

  // ---- Moitié montage : plan de données method → préfixe /rq ----------------------------------------
  hostWeb.register({
    kind: 'prefix',
    path: mountPath,
    handler(req, res) {
      const url = req.url ?? '/'
      if (url === mountPath) {
        res.writeHead(302, { location: `${mountPath}/` }).end()
        return
      }
      const inner = url.startsWith(`${mountPath}/`) ? url.slice(mountPath.length) : url
      req.url = inner.startsWith('/') ? inner : `/${inner}`
      void httpServer.dispatch(req, res)
    },
  })
  ctx.logger('dsh-bridge').info(`元冰可数据面已挂载至 dsh webServer：${mountPath}/*（单进程单入口）`)

  // ---- Moitié identité : échange de billet + liaison + association de session ------------------------------------
  const binding = bindingService
  // EntryTicketService (provide 'entryTickets') est au même rang que authn, assemblé par plugin-authn.
  // Correctif du nœud N (liste de passation F, 2026-09-11) : résolution paresseuse à la requête — quand le loader dsh charge en concurrence les patch entry,
  // authn peut publier entryTickets après cette extension ; une lecture souple au moment du apply est une écriture en course (lecture souple à undefined = départ
  // précoce de tout le bloc, la face d'identité /dsh-bridge/* intégralement en 404, le passage direct du Cookie hôte cassé). Après résolution paresseuse : la face
  // d'enregistrement ne dépend plus de l'ordre d'assemblage ; les demandes d'échange avant disponibilité du service reçoivent une erreur explicite, dès que prêt cela passe.
  const entryTicketsAt = () => (softRead(ctx, 'entryTickets') as unknown as {
    redeem(ticket: string, clientIp: string): { refType: string; refId: string; identity: { sub: string; name?: string; roles?: string[]; org?: { id?: string } } }
  } | undefined)
  if (!binding) {
    ctx.logger('dsh-bridge').warn('身份半未装配：缺少 identityBinding 服务（仅挂载半生效）')
    return
  }
  const redeemTicket = (ticket: string) => {
    const entryTickets = entryTicketsAt()
    if (!entryTickets) throw new Error(t('entryTickets 服务未就绪（装配进行中），请稍后重试'))
    return entryTickets.redeem(ticket, 'dsh-bridge')
  }

  /** Resserrement same-origin : toute requête portant un Origin doit avoir la même authority que le Host (même sémantique que fence dsh, contre la conduite inter-sites de la face de liaison). */
  const sameOrigin = (req: IncomingMessage): boolean => {
    const origin = req.headers.origin
    if (!origin) return true
    try {
      const host = req.headers.host ?? ''
      return new URL(origin).host === host
    } catch {
      return false
    }
  }

  const readBody = async (req: IncomingMessage): Promise<Record<string, unknown>> => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(chunk as Buffer)
    const raw = Buffer.concat(chunks).toString('utf8')
    if (!raw) return {}
    try { return JSON.parse(raw) as Record<string, unknown> } catch { return {} }
  }

  const cookieAttrs = (token: string, maxAge: number): string =>
    `${config.cookieName ?? DEFAULT_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`

  // Canal naturel de connexion sans ressaisie : la console/le portail « ouvrir l'interface interactive » redirige avec ?entry_ticket= (version query du contrat)
  hostWeb.register({
    kind: 'exact',
    path: '/auth/entry',
    handler(req, res) {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
      const ticket = url.searchParams.get('entry_ticket') ?? url.searchParams.get('ticket') ?? ''
      if (!ticket) {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }).end('missing entry_ticket')
        return
      }
      try {
        const bound = binding.bindByTicket((t) => redeemTicket(t), ticket)
        res.writeHead(302, {
          'set-cookie': cookieAttrs(bound.token, (config.bindTtlSeconds ?? DEFAULT_TTL_SECONDS)),
          location: '/',
        }).end()
      } catch (error) {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }).end(t('entry_ticket 无效或已过期：{reason}', { reason: error instanceof Error ? error.message : String(error) }))
      }
    },
  })

  // Face de liaison same-origin du plugin/amorçage côté navigateur (req/res natifs : peut lire les Cookie, peut poser des Set-Cookie)
  hostWeb.register({
    kind: 'prefix',
    path: '/dsh-bridge',
    handler(req, res) {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
      const endpoint = url.pathname.replace(/^\/dsh-bridge\/?/, '')
      if (!sameOrigin(req)) {
        res.writeHead(403).end('forbidden')
        return
      }
      const json = (status: number, payload: Record<string, unknown>, extraHeaders: Record<string, string> = {}) => {
        res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...extraHeaders }).end(JSON.stringify(payload))
      }
      if (req.method === 'POST' && endpoint === 'redeem') {
        void readBody(req).then((body) => {
          const ticket = String(body['ticket'] ?? '')
          if (!ticket) { json(400, { ok: false, error: { code: 'BAD_REQUEST', message: 'missing ticket' } }); return }
          try {
            const bound = binding.bindByTicket((t) => redeemTicket(t), ticket)
            json(200, { ok: true, data: { identity: bound.identity } }, {
              'set-cookie': cookieAttrs(bound.token, (config.bindTtlSeconds ?? DEFAULT_TTL_SECONDS)),
            })
          } catch (error) {
            json(400, { ok: false, error: { code: 'INVALID_TICKET', message: error instanceof Error ? error.message : String(error) } })
          }
        })
        return
      }
      if (req.method === 'GET' && endpoint === 'status') {
        // WP-04/A2 : auto-contrôle de liaison avec code de raison (no_cookie/expired/account_inactive), pour le bandeau de l'espace de travail et le guidage de re-liaison
        const status = binding.bindingStatus(req.headers.cookie)
        json(200, { ok: true, data: status })
        return
      }
      if (req.method === 'POST' && endpoint === 'logout') {
        binding.revoke(req.headers.cookie)
        json(200, { ok: true, data: { bound: false } }, { 'set-cookie': `${config.cookieName ?? DEFAULT_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` })
        return
      }
      if (req.method === 'POST' && endpoint === 'bind-session') {
        void readBody(req).then((body) => {
          const sessionId = String(body['sessionId'] ?? '')
          if (!sessionId) { json(400, { ok: false, error: { code: 'BAD_REQUEST', message: 'missing sessionId' } }); return }
          const okFlag = binding.bindSession(sessionId, req.headers.cookie)
          json(okFlag ? 200 : 401, { ok: okFlag, data: { bound: okFlag } })
        })
        return
      }
      // Passerelle directe Cookie hôte → session de la plateforme (panneau départemental/console SPA sans seconde connexion, interconnexion hôte review-dsh-agent-panel-v2) :
      // identité liée rq_sid → ensureHumanPrincipal + issueSessionPair — même sémantique de sécurité que l'endpoint de connexion sans ressaisie par billet
      // (validation en temps réel de l'état du compte faite dans bindingStatus ; le resserrement same-origin déjà appliqué uniformément ci-dessus)
      if (req.method === 'POST' && endpoint === 'session') {
        void (async () => {
          const status = binding.bindingStatus(req.headers.cookie)
          if (!status.bound || !status.identity) {
            json(401, { ok: false, error: { code: 'NOT_BOUND', message: t('宿主会话未绑定（{reason}）——请从 dsh 宿主入口进入或使用入场票据', { reason: status.reason ?? 'unknown' }) } })
            return
          }
          const deps = {
            get authn() { return softRead(ctx, 'authn') },
            get iam() { return softRead(ctx, 'iam') },
            get audit() { return softRead(ctx, 'audit') },
          } as unknown as BridgeSessionDeps
          if (!deps.authn || !deps.iam) {
            json(503, { ok: false, error: { code: 'AUTHN_UNAVAILABLE', message: t('authn 服务不可用（挂载形态装配不完整）') } })
            return
          }
          const user = deps.iam.users().get(String(status.identity.sub))
          if (!user || (user.status !== undefined && user.status !== 'active')) {
            json(401, { ok: false, error: { code: 'ACCOUNT_INACTIVE', message: t('绑定账号已冻结或不存在（fail-closed）') } })
            return
          }
          const principal = deps.authn.ensureHumanPrincipal(user.id, user.displayName)
          const session = deps.authn.issueSessionPair(principal.id, { issuedBy: 'dsh-bridge:cookie' })
          try { deps.iam.markLogin(user.id) } catch { /* marquage de connexion hors chemin critique */ }
          deps.audit?.record({
            type: 'auth', actorType: 'human', actorId: user.id, actorName: user.displayName,
            action: 'dsh_bridge.cookie.session', resourceType: 'dsh_bridge', resourceId: 'rq_sid',
            resourceName: t('宿主会话'), result: 'ok', detail: t('宿主 Cookie 绑定身份兑换平台会话（免登直达元冰可数据面）'),
          })
          json(200, {
            ok: true,
            data: {
              token: session.token,
              refreshToken: session.refreshToken,
              expiresAt: session.access.expiresAt,
              user: {
                id: user.id, username: user.username, displayName: user.displayName,
                orgId: user.orgId, roleIds: user.roleIds,
                roles: user.roleIds.map((roleId) => deps.iam?.roles().get(roleId)?.name).filter(Boolean),
                permissions: deps.iam.userPermissions(user.id),
              },
            },
          })
        })()
        return
      }
      json(404, { ok: false, error: { code: 'NOT_FOUND', message: t('未知端点：{method} /dsh-bridge/{endpoint}', { method: req.method ?? '', endpoint }) } })
    },
  })
  // ---- Canal de code d'autorisation OIDC (/auth/oidc/start → page d'autorisation de la plateforme → /auth/oidc/callback) --------
  // Utilisateur ouvrant dsh web directement sans billet : le plugin navigateur (ou à la main) pointe vers /auth/oidc/start →
  // le serveur génère un PKCE et 302 vers la page d'autorisation de la plateforme (mot de passe local/QR DingTalk) → retour avec code → userinfo → liaison Cookie.
  const oidc = softRead(ctx, 'oidc') as { issuer(): string } | undefined
  const dataDirPath = (ctx as unknown as { opsStorage?: { dataDirPath?: string } }).opsStorage?.dataDirPath
  const credFile = config.oidcCredentialFile ?? (dataDirPath ? join(dataDirPath, 'dsh-agent-credential.json') : undefined)
  const pendingOidc = new Map<string, { verifier: string; redirectUri: string; issuedAt: number }>()
  const OIDC_PENDING_TTL = 10 * 60_000

  if (oidc && credFile && existsSync(credFile)) {
    let oidcClient: { clientId: string; clientSecret?: string } | undefined
    try {
      const parsed = JSON.parse(readFileSync(credFile, 'utf8'))
      if (parsed?.oidc?.clientId) oidcClient = { clientId: parsed.oidc.clientId, clientSecret: parsed.oidc.clientSecret }
    } catch { /* fichier d'identifiants absent/corrompu : canal OIDC dégradé en indisponible, le canal entry-ticket n'est pas affecté */ }
    if (oidcClient) {
      hostWeb.register({
        kind: 'exact',
        path: '/auth/oidc/start',
        handler(req, res) {
          if (!sameOrigin(req)) { res.writeHead(403).end('forbidden'); return }
          const redirectUri = `${originOf(req)}/auth/oidc/callback`
          const verifier = base64url(randomBytes(32))
          const state = base64url(randomBytes(16))
          const challenge = base64url(createHash('sha256').update(verifier).digest())
          pendingOidc.set(state, { verifier, redirectUri, issuedAt: Date.now() })
          for (const [key, value] of pendingOidc) {
            if (Date.now() - value.issuedAt > OIDC_PENDING_TTL) pendingOidc.delete(key)
          }
          const authorize = new URL(`${oidc.issuer({ headers: req.headers })}/oauth/authorize`)
          authorize.searchParams.set('response_type', 'code')
          authorize.searchParams.set('client_id', oidcClient!.clientId)
          authorize.searchParams.set('redirect_uri', redirectUri)
          authorize.searchParams.set('scope', 'openid profile')
          authorize.searchParams.set('state', state)
          authorize.searchParams.set('code_challenge', challenge)
          authorize.searchParams.set('code_challenge_method', 'S256')
          res.writeHead(302, { location: authorize.toString() }).end()
        },
      })
      hostWeb.register({
        kind: 'exact',
        path: '/auth/oidc/callback',
        handler(req, res) {
          void (async () => {
            const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
            const code = url.searchParams.get('code') ?? ''
            const state = url.searchParams.get('state') ?? ''
            const pending = pendingOidc.get(state)
            pendingOidc.delete(state)
            if (!code || !pending || Date.now() - pending.issuedAt > OIDC_PENDING_TTL) {
              res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }).end(t('OIDC 回跳无效或已过期，请重新发起登录'))
              return
            }
            try {
              const tokenRes = await fetch(`${oidc.issuer({ headers: req.headers })}/oauth/token`, {
                method: 'POST',
                headers: {
                  'content-type': 'application/x-www-form-urlencoded',
                  ...(oidcClient!.clientSecret
                    ? { authorization: `Basic ${Buffer.from(`${oidcClient!.clientId}:${oidcClient!.clientSecret}`).toString('base64')}` }
                    : {}),
                },
                body: new URLSearchParams({
                  grant_type: 'authorization_code', code,
                  redirect_uri: pending.redirectUri, code_verifier: pending.verifier,
                }).toString(),
              })
              const tokenPayload = await tokenRes.json().catch(() => null)
              const accessToken = tokenPayload?.access_token
              if (!tokenRes.ok || !accessToken) throw new Error(tokenPayload?.error_description ?? t('token 端点失败（{status}）', { status: tokenRes.status }))
              const userinfoRes = await fetch(`${oidc.issuer({ headers: req.headers })}/oauth/userinfo`, { headers: { authorization: `Bearer ${accessToken}` } })
              const userinfo = await userinfoRes.json().catch(() => null)
              if (!userinfoRes.ok || !userinfo?.sub) throw new Error(t('userinfo 换取失败'))
              const identity = {
                sub: String(userinfo.sub),
                name: typeof userinfo.name === 'string' ? userinfo.name : undefined,
                roles: Array.isArray(userinfo.roles) ? userinfo.roles.map(String) : undefined,
                org: userinfo.org && typeof userinfo.org === 'object' ? { id: String((userinfo.org as { id?: unknown }).id ?? '') || undefined } : undefined,
              }
              const token = binding.bindIdentity(identity)
              res.writeHead(302, {
                'set-cookie': cookieAttrs(token, (config.bindTtlSeconds ?? DEFAULT_TTL_SECONDS)),
                location: '/',
              }).end()
            } catch (error) {
              res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }).end(t('OIDC 登录失败：{reason}', { reason: error instanceof Error ? error.message : String(error) }))
            }
          })()
        },
      })
      ctx.logger('dsh-bridge').info('OIDC 授权码通道已挂载：/auth/oidc/start → /auth/oidc/callback（PKCE S256）')
    } else {
      ctx.logger('dsh-bridge').info(`OIDC 凭证文件无 oidc 字段，授权码通道未启用：${credFile}`)
    }
  } else {
    ctx.logger('dsh-bridge').info(`OIDC 凭证文件不存在（${credFile ?? '未配置'}），授权码通道未启用——可先运行 register-dsh-agent.mjs`)
  }

  // ---- Script d'amorçage de connexion sans ressaisie (tapIndex) : reprend le contrat existant du fragment #entry_ticket= ----------------
  // Le fragment n'entre pas dans les logs serveur (mieux que query) ; le POST same-origin passe naturelment la barrière de confiance dsh.
  // La console openAgentEntry redirige <entryUrl>#entry_ticket=<ticket> → ce script échange → efface le hash → rafraîchit.
  // Capacité optionnelle tapIndex : absente du port (non fournie par l'hôte) = dégradation warn, le canal converge vers la version query de /auth/entry
  const tapIndex = hostWeb.tapIndex
  if (typeof tapIndex === 'function') {
    tapIndex((html: string) => {
      const script = `<script>(function(){try{var m=(location.hash||'').match(/[#&]entry_ticket=([^&]+)/);if(!m)return;` +
        `fetch('/dsh-bridge/redeem',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ticket:decodeURIComponent(m[1])})})` +
        `.then(function(r){return r.json()}).then(function(j){` +
        `try{history.replaceState(null,'',location.pathname+location.search)}catch(e){}` +
        `if(j&&j.ok)location.reload();}).catch(function(){});}catch(e){}})();</script>`
      const head = html.indexOf('<head>')
      if (head !== -1) return `${html.slice(0, head + 6)}${script}${html.slice(head + 6)}`
      return `${script}${html}`
    })
    ctx.logger('dsh-bridge').info('免登引导脚本已注入 dsh web UI（#entry_ticket fragment 兑换）')
  } else {
    ctx.logger('dsh-bridge').warn('webServer.tapIndex 不可用——#entry_ticket fragment 通道降级，仅 /auth/entry?entry_ticket= query 通道可用')
  }
}
