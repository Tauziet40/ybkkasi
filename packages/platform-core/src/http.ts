/**
 * Serveur HTTP : routes REST + ressources statiques + middleware, point d'entrée du plan de données de l'hôte autonome.
 * Dans un déploiement dsh réel, la console peut tourner dans un processus indépendant (ce service est fourni avec platform-core).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import { extname, join, normalize, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { parseCookieHeader, resolveRequestLocale, runWithLocale, t } from '../../platform-i18n/src/index.ts'

export interface HttpExchange {
  method: string
  path: string
  params: Record<string, string>
  query: URLSearchParams
  headers: IncomingMessage['headers']
  body: any
  raw: IncomingMessage
  res: ServerResponse
  /** Identité de l'appelant écrite par le middleware d'authentification. */
  principal?: unknown
  ok(data?: unknown, init?: { status?: number }): void
  fail(status: number, code: string, message: string, extra?: Record<string, unknown>): void
  file(absolutePath: string, contentType?: string): void
}

export type HttpHandler = (exchange: HttpExchange) => void | Promise<void>
export type HttpMiddleware = (exchange: HttpExchange) => boolean | void | Promise<boolean | void>

/**
 * Profil d'authentification des routes (durcissement plateforme issu de la leçon QA 2026-09-08 T-01, liste de passation H5) :
 * les points /api/* doivent le déclarer explicitement à l'enregistrement, afin que le filet d'assertions RBAC puisse énumérer tous les points —
 * y compris la catégorie explicite « public + auto-validé » (p. ex. points SSE ?token=/?ticket=),
 * les failles similaires (points auto-enregistrés échappant au filet d'assertions) ne dépendent plus d'une découverte manuelle.
 * - guarded : protégé par point de permission (enregistré dans routeMatrix, le filet affirme 403 pour les sondes de membres ordinaires) ;
 * - authenticated : seul le middleware d'authentification console exige un Bearer, pas de point de permission propre (points d'identité autonomes) ;
 * - public : liste blanche sans authentification ; selfValidated=true signifie que le handler embarque sa propre validation d'identifiants (fail-closed),
 *   le filet d'assertions couvre l'obligation qu'une sonde anonyme soit rejetée.
 */
export type RouteAuthDecl =
  | { access: 'guarded'; permission: string }
  | { access: 'authenticated' }
  | { access: 'public'; selfValidated?: boolean }

/** Entrée de registre : les routes hors /api/* (/oauth/*, /mcp, /docs…) n'appartiennent pas au domaine d'authentification console, classées automatiquement outside-api. */
export type RouteLedgerEntry = { method: string; path: string; auth: RouteAuthDecl | { access: 'outside-api' } }

/** Détection des chemins /api/* (périmètre de l'obligation de déclaration : couverture du middleware d'authentification console et du filet d'assertions RBAC). */
const isApiPattern = (pattern: string): boolean => pattern === '/api' || pattern.startsWith('/api/')

interface Route {
  method: string
  segments: string[]
  handler: HttpHandler
}

export interface HttpServerConfig {
  port?: number
  host?: string
  /**
   * Préfixe de montage externe ('' par défaut, soit la racine). Monté dans l'hôte dsh complet (plugin-dsh-bridge), vaut '/rq' :
   * toutes les constructions « chemins absolus racine » côté plateforme (302 de la page d'autorisation OIDC, HTML de retour SSO, etc.) se concatènent en conséquence,
   * garantissant la cohérence des liens sous le préfixe /rq via l'entrée unique (port web dsh).
   */
  externalBase?: string
  /**
   * Origines autorisées cross-origin (docs/frontend-host-switching.md : « changement de connexion hôte » de la console — une page de la machine A accède directement au plan de données de la machine B).
   * Défaut ['*'] : le plan de données est un pur canal Bearer, les requêtes cross-origin ne portent pas de Cookie (/dsh-bridge/* est enregistré
   * à la racine du webServer dsh, sans passer par ce dispatch) — l'ouverture ne change pas la sémantique same-origin ; [] pour désactiver ; une liste d'origines précise est renvoyée en écho exact (avec Vary: Origin).
   */
  corsAllowOrigins?: string[]
  /**
   * En-têtes de sécurité (activés par défaut) : toutes les réponses ajoutent `x-content-type-options: nosniff`, `x-frame-options: SAMEORIGIN`
   * (forme montée /rq same-origin avec le web dsh, SAMEORIGIN n'empêche pas l'incorporation same-origin de la facette hôte ; l'application H5 DingTalk est une webview de premier niveau),
   * `referrer-policy: strict-origin-when-cross-origin` et le `content-security-policy` de base (G1-F2).
   * `SECURITY_HEADERS=off` (ou config false) désactive tout, dans la convention de PORTAL_SYNC / IAM_CONNECTOR_AUTO_SYNC.
   */
  securityHeaders?: boolean
}

/**
 * Décision CORS (fonction pure, testée par selftest) : renvoie la valeur access-control-allow-origin à écrire,
 * undefined si aucune correspondance (pas d'en-tête d'autorisation).
 */
export function corsAllowOriginFor(allowOrigins: readonly string[], originHeader: string | undefined): string | undefined {
  if (!originHeader || allowOrigins.length === 0) return undefined
  if (allowOrigins.includes('*')) return '*'
  let origin = ''
  try { origin = new URL(originHeader).origin } catch { return undefined }
  return allowOrigins.includes(origin) ? origin : undefined
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.map': 'application/json',
}

/**
 * CSP de base (G1-F2, pilotée par le commutateur securityHeaders). Valeurs fondées sur l'usage réel des pages :
 * console/panneau : SPA sans build (scripts module externes + quelques gestionnaires d'événements inline générés en template strings),
 * page d'autorisation OIDC/index de documentation : styles inline côté serveur — script/style exigent 'unsafe-inline' ;
 * connect-src autorise http/https au-delà de 'self' : le « changement de connexion hôte » de la console (docs/frontend-host-switching.md)
 * envoie les requêtes API directement à l'hôte distant, 'self' seul couperait cette fonction. Pistes de resserrement ultérieur : gestionnaires inline → délégation d'événements
 * (suppression du script 'unsafe-inline') ; connect-src restreint à la liste explicite des hôtes de déploiement.
 */
const CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http: https:"

/**
 * Préfixes réservés protocole/intégrations (C-10) : /oauth, /.well-known, /mcp sont la facette protocole enregistrée dans ce service ;
 * /rq, /dsh-bridge, /auth/entry ne sont enregistrés que sur le webServer dsh (ce service n'a pas les handlers correspondants en hôte autonome) ;
 * /api est le plan de données, /docs le montage de la documentation embarquée. Si un préfixe est touché sans aucune correspondance de route/répertoire statique → 404 JSON,
 * au lieu d'être avalé par le repli SPA en 200 HTML — les intégrateurs obtiennent un signal d'échec diagnostiquable.
 * Ne s'applique qu'à la branche de repli « aucun handler trouvé » : les routes enregistrées (/oauth/authorize, /mcp, /docs/*…) ne sont pas affectées,
 * les routes de pages propres à la console/au panneau (routing par hash + /panel, / montage statique) ne sont pas concernées.
 */
const RESERVED_PATH_PREFIXES = ['/api', '/rq', '/dsh-bridge', '/auth/entry', '/oauth', '/.well-known', '/mcp', '/docs']

const isReservedPath = (pathname: string): boolean =>
  RESERVED_PATH_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`))

export class HttpServerService extends Service {
  static readonly provide = 'httpServer'

  private routes: Route[] = []
  private middlewares: HttpMiddleware[] = []
  private staticDirs: Array<{ prefix: string; dir: string; fallback?: string }> = []
  private server: Server | undefined
  readonly port: number
  readonly host: string
  /** Préfixe de montage externe : '' ou de la forme '/rq' (sans slash final). Voir HttpServerConfig.externalBase. */
  readonly externalBase: string
  private readonly corsAllowOrigins: string[]
  /** En-têtes de sécurité activés par défaut (nosniff / SAMEORIGIN / Referrer-Policy) ; SECURITY_HEADERS=off ou config false pour désactiver. */
  private readonly securityHeaders: boolean
  /**
   * Matrice routes×permissions (registre partagé inter-plugins). register() y fusionne automatiquement les déclarations guarded (déduplication idempotente),
   * le « filet d'assertions 100% de dépassement de droits sur la matrice de points RBAC » du selftest s'en sert (review-dsh-agent-panel-v2 Phase 0).
   */
  readonly routeMatrix: Array<{ method: string; path: string; permission: string }> = []
  /**
   * Registre complet des routes (H5) : chaque register y écrit une entrée ; un /api/* sans déclaration lève dès l'enregistrement (fail-loud),
   * le point route-matrix y expose le compteur, le filet d'assertions vérifie la « couverture complète guarded+public+authenticated ».
   */
  readonly declaredRoutes: RouteLedgerEntry[] = []

  constructor(ctx: Context, config: HttpServerConfig = {}) {
    super(ctx, 'httpServer')
    this.port = config.port ?? 7300
    this.host = config.host ?? '0.0.0.0'
    this.externalBase = (config.externalBase ?? '').replace(/\/+$/, '')
    this.corsAllowOrigins = config.corsAllowOrigins ?? ['*']
    this.securityHeaders = config.securityHeaders ?? process.env.SECURITY_HEADERS !== 'off'
    ctx.effect(() => () => {
      void this.stop()
    })
  }

  async start(): Promise<void> {
    if (this.server) return
    const server = createServer((req, res) => {
      void this.dispatch(req, res)
    })
    await new Promise<void>((resolvePromise, reject) => {
      server.once('error', reject)
      server.listen(this.port, this.host, () => {
        server.removeListener('error', reject)
        resolvePromise()
      })
    })
    this.server = server
  }

  async stop(): Promise<void> {
    if (!this.server) return
    const server = this.server
    this.server = undefined
    await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()))
  }

  use(middleware: HttpMiddleware): () => void {
    this.middlewares.push(middleware)
    return () => {
      const index = this.middlewares.indexOf(middleware)
      if (index >= 0) this.middlewares.splice(index, 1)
    }
  }

  register(method: string, pattern: string, handler: HttpHandler, auth?: RouteAuthDecl): () => void {
    // H5 (leçon T-01) : les points /api/* doivent déclarer leur profil d'authentification, sans déclaration → levée dès l'enregistrement —
    // une levée pendant apply du plugin fait échouer l'assemblage bruyamment ; jamais de point non déclaré mis en ligne en silence, échappant au filet d'assertions.
    if (isApiPattern(pattern) && auth === undefined) {
      throw new Error(
        `httpServer: 注册 ${method.toUpperCase()} ${pattern} 缺少鉴权声明（auth: guarded{permission} | authenticated | public{selfValidated?}）`
        + '——自注册端点必须可被 RBAC 断言网枚举（交接清单 H5）',
      )
    }
    const normalized = auth ?? { access: 'outside-api' as const }
    this.declaredRoutes.push({ method: method.toUpperCase(), path: pattern, auth: normalized })
    if (auth?.access === 'guarded') {
      const key = `${method.toUpperCase()} ${pattern}`
      if (!this.routeMatrix.some((route) => `${route.method} ${route.path}` === key)) {
        this.routeMatrix.push({ method: method.toUpperCase(), path: pattern, permission: auth.permission })
      }
    }
    const segments = pattern.split('/').filter(Boolean)
    const route: Route = { method: method.toUpperCase(), segments, handler }
    this.routes.push(route)
    return () => {
      const index = this.routes.indexOf(route)
      if (index >= 0) this.routes.splice(index, 1)
    }
  }

  /** Enregistrement pratique de tous les verbes courants. */
  route(pattern: string, handler: HttpHandler, methods = ['GET']): void {
    for (const method of methods) this.register(method, pattern, handler)
  }

  serveStatic(prefix: string, dir: string, fallback?: string): () => void {
    const entry = { prefix, dir: resolve(dir), fallback }
    this.staticDirs.push(entry)
    return () => {
      const index = this.staticDirs.indexOf(entry)
      if (index >= 0) this.staticDirs.splice(index, 1)
    }
  }

  private match(method: string, pathSegments: string[]): { route: Route; params: Record<string, string> } | undefined {
    for (const route of this.routes) {
      if (route.method !== method && !(route.method === 'GET' && method === 'HEAD')) continue
      if (route.segments.length !== pathSegments.length) continue
      const params: Record<string, string> = {}
      let matched = true
      for (let i = 0; i < route.segments.length; i++) {
        const pattern = route.segments[i]!
        const actual = pathSegments[i]!
        if (pattern.startsWith(':')) {
          params[pattern.slice(1)] = decodeURIComponent(actual)
        } else if (pattern !== actual) {
          matched = false
          break
        }
      }
      if (matched) return { route, params }
    }
    return undefined
  }

  /**
   * Entrée des requêtes (public). En forme autonome, appelé par le listener de start() ; en forme montée (plugin-dsh-bridge,
   * processus unique à entrée unique sous hôte dsh complet), appelé directement par les routes préfixées du webServer dsh après retrait du préfixe externe.
   * L'appelant garantit que req.url est déjà un chemin interne de la plateforme (/api/*, /, /docs/*…).
   */
  async dispatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const pathSegments = url.pathname.split('/').filter(Boolean).map((s) => s)
    const method = (req.method ?? 'GET').toUpperCase()

    // Globalisation UI (2026-10-16) : résolution de langue par requête (?lang= > Cookie rq_lang > Accept-Language >
    // PLATFORM_LOCALE > zh-CN), en enveloppant middleware+handlers+repli statique dans AsyncLocalStorage sur toute la chaîne —
    // tout code de route/service appelle t() et obtient la langue de la requête ; la sortie zh-CN par défaut reste identique octet par octet (selftest sans impact).
    const requestLocale = resolveRequestLocale({
      query: url.searchParams.get('lang'),
      cookie: parseCookieHeader(req.headers.cookie)['rq_lang'],
      acceptLanguage: req.headers['accept-language'],
      env: process.env.PLATFORM_LOCALE,
    })

    // Repli de saut pour port en clair en bordure (QA externe 20261014 QA-01 / interne G1-F1) : la plateforme n'écoute qu'en HTTP (TLS pris en
    // charge par Cloudflare Tunnel/le reverse proxy) ; x-forwarded-proto: http signifie que l'utilisateur est passé par l'entrée en clair → 308 en préservant la méthode
    // vers HTTPS ; les connexions directes locales/intranet sans cet en-tête et la forme montée dsh ne sont pas affectées. La vraie correction reste la couche de bord
    // (« Always Use HTTPS ») ; ceci est le repli côté origine. HSTS n'est émis qu'après confirmation d'un transport sécurisé (inutile sur lien en clair).
    const forwardedProto = (req.headers['x-forwarded-proto'] ?? '').split(',')[0]?.trim() ?? ''
    if (forwardedProto === 'http') {
      res.statusCode = 308
      res.setHeader('location', `https://${req.headers.host ?? url.host}${url.pathname}${url.search}`)
      res.end()
      return
    }

    // En-têtes de sécurité (activés par défaut, SECURITY_HEADERS=off pour désactiver) : pré-posés via setHeader, fusionnés naturellement
    // avec les writeHead ultérieurs de ok/fail/file (même mécanisme de fusion que les en-têtes CORS ci-dessous).
    if (this.securityHeaders) {
      res.setHeader('x-content-type-options', 'nosniff')
      res.setHeader('x-frame-options', 'SAMEORIGIN')
      res.setHeader('referrer-policy', 'strict-origin-when-cross-origin')
      res.setHeader('content-security-policy', CONTENT_SECURITY_POLICY)
      if (forwardedProto === 'https' || (req.socket as { encrypted?: boolean }).encrypted) {
        res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains')
      }
    }

    // Le plan de données /api/* est toujours no-store (G1-F2) : les réponses d'authentification/métier ne doivent entrer dans aucun cache ;
    // les en-têtes de cache explicitement émis par les handlers via writeHead (contrat portal no-cache, SSE no-cache, statique no-cache) priment
    if (isApiPattern(url.pathname)) {
      res.setHeader('cache-control', 'no-store')
    }

    // Autorisation cross-origin (changement de connexion hôte, docs/frontend-host-switching.md) : couvre uniquement le plan REST /api/*,
    // et exempte les sous-facettes gérant leur propre CORS — le canal portail /api/portal/* et le protocole OIDC /api/authn/oidc/* autorisent
    // par origine exacte, sans être relâchés (/oauth/*, /.well-known/* sont hors /api, naturellement non affectés) ;
    // la facette de frappe/échange de jetons /api/auth/* (login/refresh/échange de tickets… points publics) ne reçoit jamais de '*' générique
    // (clarification RQ point 1 : empêcher toute page web de lire en cross-site la réponse de login pour sonder des identifiants drive-by) — avec une liste
    // d'origines configurée, l'autorisation reste par origine exacte (corsAllowOriginFor renvoyant une origine précise n'est pas concerné) ; la connexion
    // en ligne vers un hôte distant est configurée explicitement côté B, conforme au principe zéro confiance par défaut.
    // Avant le middleware d'authentification — le préflight OPTIONS du navigateur ne porte pas de Bearer et ne doit pas être bloqué en 401 ; les en-têtes d'autorisation sont pré-posés
    // via setHeader et fusionnés naturellement avec les writeHead ultérieurs de ok/fail/file (les corps d'erreur restent lisibles en cross-origin).
    const blanketCorsExempt = url.pathname.startsWith('/api/portal/')
      || url.pathname.startsWith('/api/authn/oidc/')
      || (this.corsAllowOrigins.includes('*') && url.pathname.startsWith('/api/auth/'))
    const blanketCorsPath = url.pathname.startsWith('/api/') && !blanketCorsExempt
    const allowOrigin = blanketCorsPath ? corsAllowOriginFor(this.corsAllowOrigins, req.headers.origin) : undefined
    if (allowOrigin) {
      res.setHeader('access-control-allow-origin', allowOrigin)
      res.setHeader('vary', 'Origin')
      if (method === 'OPTIONS') {
        res.writeHead(204, {
          'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
          'access-control-allow-headers': String(req.headers['access-control-request-headers'] ?? 'authorization, content-type'),
          'access-control-max-age': '600',
        })
        res.end()
        return
      }
    }

    let body: any
    if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(chunk as Buffer)
      const rawBody = Buffer.concat(chunks).toString('utf8')
      if (rawBody) {
        const contentType = String(req.headers['content-type'] ?? '')
        if (contentType.includes('application/json')) {
          try {
            body = JSON.parse(rawBody)
          } catch {
            body = undefined
          }
        } else if (contentType.includes('form')) {
          body = Object.fromEntries(new URLSearchParams(rawBody))
        } else {
          body = rawBody
        }
      }
    }

    const exchange: HttpExchange = {
      method,
      path: url.pathname,
      params: {},
      query: url.searchParams,
      headers: req.headers,
      body,
      raw: req,
      res,
      ok(data, init) {
        // Garde d'idempotence : ignore si le gestionnaire d'erreurs a déjà écrit la réponse (la transmission d'erreur des routes connecteur et le repli
        // du guarded externe partagent un chemin de double écriture sur la même requête ; un second writeHead lèverait ERR_HTTP_HEADERS_SENT)
        if (res.headersSent) return
        const payload = data === undefined ? { ok: true } : { ok: true, data }
        const text = JSON.stringify(payload)
        res.writeHead(init?.status ?? 200, { 'content-type': 'application/json; charset=utf-8' })
        res.end(text)
      },
      fail(status, code, message, extra) {
        if (res.headersSent) return
        const payload = JSON.stringify({ ok: false, error: { code, message, ...extra } })
        res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
        res.end(payload)
      },
      file(absolutePath, contentType) {
        void (async () => {
          try {
            // Garde d'idempotence (même modèle que ok/fail) : ignore si le gestionnaire d'erreurs a déjà écrit la réponse — ce corps de méthode tourne
            // dans une IIFE asynchrone ; un second writeHead lève ERR_HTTP_HEADERS_SENT sans personne pour l'attraper, et tue tout le processus hôte
            // en uncaughtException (prouvé sur machine réelle par gate01-smoke, 2026-09-10)
            if (res.headersSent) return
            const info = await stat(absolutePath)
            if (!info.isFile()) {
              res.writeHead(404).end('not found')
              return
            }
            const type = contentType ?? MIME[extname(absolutePath)] ?? 'application/octet-stream'
            res.writeHead(200, { 'content-type': type, 'content-length': info.size, 'cache-control': 'no-cache' })
            createReadStream(absolutePath).pipe(res)
          } catch {
            if (!res.headersSent) res.writeHead(404).end('not found')
          }
        })()
      },
    }

    try {
      // Enveloppe du contexte de locale par requête sur toute la chaîne (middleware → handlers de routes → repli statique/SPA)
      await runWithLocale(requestLocale, () => this.dispatchInner(exchange, method, pathSegments, url))
    } catch (error) {
      if (!res.writableEnded) {
        // Sécurité en production : le repli 500 ne renvoie pas le texte interne de l'exception, les détails ne vont qu'au log du service
        exchange.fail(500, 'INTERNAL', t('服务器内部错误，请稍后重试或联系管理员'))
      }
      console.error(`[http] ${method} ${url.pathname} 处理异常`, error)
    }
  }

  /** Couche interne de dispatch (exécutée dans le contexte de locale par requête) : chaîne de middleware → correspondance de route → repli répertoire statique/SPA. */
  private async dispatchInner(
    exchange: HttpExchange,
    method: string,
    pathSegments: string[],
    url: URL,
  ): Promise<void> {
    const res = exchange.res
    for (const middleware of this.middlewares) {
      const blocked = await middleware(exchange)
      if (blocked === true) return
      if (res.writableEnded) return
    }

    const matched = this.match(method, pathSegments)
    if (matched) {
      exchange.params = matched.params
      await matched.route.handler(exchange)
      return
    }

    // Répertoires statiques : préfixe le plus long d'abord (/docs et autres sous-chemins montés avant le repli / ; à longueur égale, ordre d'enregistrement conservé)
    const staticCandidates = this.staticDirs
      .map((entry) => ({ entry, prefix: entry.prefix.replace(/\/$/, '') }))
      .filter(({ prefix }) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`))
      .sort((a, b) => b.prefix.length - a.prefix.length)
    if (staticCandidates.length > 0) {
      // DEF-01 + C-10 : /api et les préfixes réservés protocole/intégrations (/rq, /dsh-bridge, /auth/entry, /oauth…) ne retombent jamais sur les
      // ressources statiques/pages SPA — sans route correspondante ni montage statique homonyme → toujours 404 JSON, signal d'échec diagnostiquable pour les intégrateurs ;
      // un vrai montage (/docs, /panel touchés comme répertoires statiques) est servi normalement, les routes de pages de la console ne sont pas affectées
      const handledByStatic = staticCandidates.some(({ prefix }) => prefix !== '' && (url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)))
      if (isReservedPath(url.pathname) && !handledByStatic) {
        exchange.fail(404, 'NOT_FOUND', t('路由不存在：{method} {path}', { method, path: url.pathname }))
        return
      }
      const best = staticCandidates[0]!
      await this.serveFromDir(exchange, best.entry, url.pathname.slice(best.prefix.length))
      return
    }
    if (this.staticDirs.length > 0) {
      // Repli SPA : les chemins non protocole/intégrations retombent sur la page fallback du premier répertoire statique (même règle C-10 que ci-dessus)
      if (!isReservedPath(url.pathname)) {
        const entry = this.staticDirs[0]!
        await this.serveFromDir(exchange, entry, entry.fallback ?? '/index.html')
        return
      }
    }
    exchange.fail(404, 'NOT_FOUND', t('路由不存在：{method} {path}', { method, path: url.pathname }))
  }

  private async serveFromDir(exchange: HttpExchange, entry: { dir: string; fallback?: string }, relative: string): Promise<void> {
    // Décodage percent-encoding par segment (noms de fichiers non ASCII comme le chinois : /docs/<chinois>.md émis par le navigateur est
    // percent-encoded ; sans décodage, stat échoue toujours → 404 sur les documents chinois, QA-20261014 G3-08-D1).
    // Après décodage, aucun séparateur de chemin ni '..' ne doit apparaître dans le segment — empêche %2F de franchir le répertoire via le décodage (niveau anti-traversée identique au chemin brut).
    let rel = relative
    try {
      rel = relative
        .split('/')
        .map((segment) => {
          const decoded = decodeURIComponent(segment)
          if (decoded.includes('/') || decoded.includes('\\') || decoded === '..') throw new Error('unsafe segment')
          return decoded
        })
        .join('/')
    } catch {
      // Encodage malformé (séquence % illégale ou segment hors bornes) : tentative sur le chemin brut, le stat ci-dessous tranche
    }
    let target = join(entry.dir, normalize(rel).replace(/^([/\\])+/, ''))
    if (relative === '' || relative === '/') target = join(entry.dir, 'index.html')
    try {
      const info = await stat(target)
      if (info.isDirectory()) target = join(target, 'index.html')
    } catch {
      // Les chemins de ressources avec extension non trouvés (/openapi.json, /js/missing.js, /docs/x.md…) ne retombent pas sur index.html (issue #6) :
      // un chemin « qui ressemble à du JSON/script » répondant 200 HTML crée des faux positifs dans les sondes d'API et health checks des Agents ; le repli SPA ne sert
      // que les routes frontend sans extension (console/panneau en routing par hash, les deep links n'ont de toute façon pas d'extension).
      if (hasFileExtension(rel)) {
        exchange.fail(404, 'NOT_FOUND', t('路由不存在：{method} {path}', { method: exchange.method, path: exchange.path }))
        return
      }
      const fallback = entry.fallback ?? '/index.html'
      target = join(entry.dir, fallback.replace(/^\/+/, ''))
    }
    exchange.file(target)
  }
}

/** Le dernier segment contient `.ext` (ext de 1 à 8 caractères alphanumériques) → chemin de fichier de ressource ; `/v1/x`, `/locales/zh-CN` (sans extension) ne comptent pas. */
export function hasFileExtension(pathname: string): boolean {
  const last = pathname.split('/').filter(Boolean).at(-1) ?? ''
  return /\.[a-zA-Z0-9]{1,8}$/.test(last)
}

/** Résout le répertoire de ressources relativement au module courant (remplace __dirname en ESM). */
export function assetDir(importMeta: ImportMeta, ...relative: string[]): string {
  return join(fileURLToPath(importMeta.url), '..', '..', ...relative)
}
