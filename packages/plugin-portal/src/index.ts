/**
 * @dsh-ops/plugin-portal — canal de données du portail (interconnexion de systèmes externes, fonction cœur de la plateforme exclue).
 *
 * Le portail d'entreprise (http://192.168.0.4:8092, site statique pur front) vient activement chercher sur la plateforme hôte selon une stratégie « tirer (Pull) »
 * les applications IA publiées / employés numériques, etc. (contrat d'interface : docs/portal-integration.md, document d'interconnexion
 * api.md v1.1). Cette extension n'implémente que 6 endpoints GET publics en lecture seule + CORS + trace d'audit de visibilité,
 * sans jamais pousser/rappeler vers le portail. Changements v1.1 : le téléchargement de paquets de skills doit porter un jeton de connexion portail (Bearer),
 * sans connexion 401, téléchargement autorisé tracé dans l'audit (qui/quand/quoi/IP) ; le pré-vol autorise l'en-tête authorization.
 *
 * Frontières (délibérément maintenues, le mode d'interconnexion du portail peut évoluer avec le fournisseur du portail) :
 *   - désactivable en bloc : PORTAL_SYNC=off ; retrait = supprimer ce répertoire + une ligne dans boot-all/cordis.yml,
 *     sans impact sur aucune chaîne métier de la plateforme ;
 *   - lecture directe seule : les endpoints lisent en temps réel resourceCore/skillHub/mcpRegistry, sans copie locale, sans cache,
 *     « mise en ligne/retrait → le portail rafraîchit la page et voit » (exigence d'immédiateté de mise à jour du contrat) ;
 *   - contrat variable : la cartographie des champs est concentrée dans src/mapping.ts ; préfixe d'endpoints et origines autorisées surchargeables par variables d'environnement.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, type HttpExchange } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import {
  emptySolutions, emptyTools, mapApps, mapEmployees, mapSkills, mapStats,
  type PortalMappingContext, type PortalSolution, type PortalTool,
} from './mapping.ts'

/** Préfixe d'endpoints : le VITE_API_BASE du portail pointe « <adresse publique de la plateforme><préfixe> » (défaut /api/portal). */
export function portalPrefix(): string {
  const raw = (process.env.PORTAL_API_PREFIX ?? '/api/portal').trim().replace(/\/+$/, '')
  return raw === '' ? '/api/portal' : (raw.startsWith('/') ? raw : `/${raw}`)
}

/** Interrupteur général du canal de données (ouvert par défaut ; PORTAL_SYNC=off désactive endpoints et traces, le portail affiche en repli ses gabarits intégrés). */
export function portalEnabled(): boolean {
  return String(process.env.PORTAL_SYNC ?? 'on').trim().toLowerCase() !== 'off'
}

/** Adresse publique de la plateforme : entre dans downloadUrl et autres champs exigeant une adresse absolue (surchargeable par variable d'environnement en cas de reverse-proxy/changement d'adresse). */
export function portalPublicBase(): string {
  return (process.env.PORTAL_PUBLIC_BASE ?? 'http://192.168.0.7:7300').trim().replace(/\/+$/, '')
}

const ENDPOINTS = ['apps', 'employees', 'solutions', 'tools', 'skills', 'stats'] as const

export class PortalFeedService extends Service {
  static readonly provide = 'portalFeed'

  /** Instantané de contrat d'un endpoint isolé (unique sortie de la réponse de l'endpoint ; réutilisable par CLI/auto-test). */
  feed(endpoint: string): unknown[] | undefined {
    const mctx = this.mappingCtx()
    switch (endpoint) {
      case 'apps': return mapApps(this.ctx.resourceCore.list('app'), mctx)
      case 'employees': return mapEmployees(this.ctx.resourceCore.list('agent'), mctx)
      case 'solutions': return emptySolutions() satisfies PortalSolution[]
      case 'tools': return emptyTools() satisfies PortalTool[]
      case 'skills': return mapSkills(this.ctx.skillHub.skills().all(), mctx)
      case 'stats': return mapStats({
        apps: mapApps(this.ctx.resourceCore.list('app'), mctx).length,
        employees: mapEmployees(this.ctx.resourceCore.list('agent'), mctx).length,
        skills: mapSkills(this.ctx.skillHub.skills().all(), mctx).length,
        mcp: this.ctx.mcpRegistry.services().all()
          .filter((service) => service.status === 'online' || service.status === 'gray').length,
      })
      default: return undefined
    }
  }

  /**
   * Octets d'un paquet de skill publié (bout répondeur de downloadUrl ; api.md v1.1 §4.7 : doit porter un jeton de connexion portail).
   * Seule la version courante publiée status=published est prenable ; via skillHub.download, le metering de téléchargement est enregistré
   * (tolérance aux pannes interne), puis prise des octets zip de même source que l'artefact publié sur NAS.
   * Référentiel d'audit (qui télécharge) : actor = utilisateur plateforme résolu, detail porte le canal du jeton et l'IP d'origine.
   */
  skillPackage(skillId: string, downloader: { id: string; name: string; via: string; ip?: string }): { buffer: Buffer; filename: string } | undefined {
    try {
      const skill = this.ctx.skillHub.skills().get(skillId)
      if (!skill || skill.status !== 'published') return undefined
      const version = skill.currentVersion
      const published = skill.versions.find((item) => item.version === version && item.status === 'published')
      if (!published) return undefined
      const pkg = this.ctx.skillHub.packageOf(skillId, version)
      try {
        this.ctx.skillHub.download(skillId, version, { id: downloader.id, name: downloader.name })
      } catch {
        // un échec de metering de téléchargement n'interrompt pas la prise du paquet
      }
      try {
        this.ctx.audit.record({
          type: 'invoke', actorType: 'human', actorId: downloader.id, actorName: downloader.name,
          action: 'portal.skill.download', resourceType: 'skill', resourceId: skillId, resourceName: skill.name,
          result: 'ok',
          detail: `门户登录下载：via=${downloader.via} version=${version} bytes=${pkg.buffer.length}${downloader.ip ? ` ip=${downloader.ip}` : ''}`,
        })
      } catch {
        // un échec de trace n'interrompt pas le téléchargement
      }
      return { buffer: pkg.buffer, filename: pkg.filename }
    } catch {
      return undefined
    }
  }

  /**
   * Résolution de l'identité du téléchargeur (api.md v1.1 §4.7 : connexion exigée pour télécharger). Jeton Bearer → utilisateur plateforme ;
   * les deux classes de jetons détenues par le portail sont prises en charge : jeton de session plateforme (dst1.*, authn.verify) et access token OIDC
   * (obtenu par connexion OIDC du portail ; validation userinfo inclut token_use/client valide/révocation jti/état utilisateur en temps réel).
   * Absent ou irrésoluble = undefined (la couche de routage répond 401, sans divulguer l'existence du skill).
   */
  resolveDownloader(authorization: unknown, origin?: { headers: import('node:http').IncomingHttpHeaders }): { id: string; name: string; via: string } | undefined {
    const raw = typeof authorization === 'string' ? authorization.trim() : ''
    if (!/^bearer\s+/i.test(raw)) return undefined
    const token = raw.replace(/^bearer\s+/i, '').trim()
    if (!token) return undefined
    try {
      const verified = this.ctx.authn.verify(token)
      const principal = verified.principal
      const userId = principal.refType === 'user' ? principal.refId ?? '' : ''
      if (userId) {
        const user = this.ctx.iam.users().get(userId)
        if (user && user.status === 'active') return { id: user.id, name: user.displayName, via: 'session' }
      }
      // Principal machine (ex. tirage serveur-à-serveur des identifiants du backend du portail) : metering sous l'identité du principal, sans usurper une personne
      return { id: principal.id, name: principal.name, via: 'machine' }
    } catch {
      // jeton de forme non dst1, poursuivre la résolution OIDC
    }
    try {
      // quand origin est fourni, iss accepte aussi la valeur dérivée de la face de requête (#15 : un jeton OIDC émis pour le domaine public passe la résolution sous le même domaine)
      const claims = this.ctx.oidc.userinfo(token, origin)
      return { id: String(claims.sub ?? ''), name: String(claims.name ?? claims.preferred_username ?? ''), via: 'oidc' }
    } catch {
      return undefined
    }
  }

  private mappingCtx(): PortalMappingContext {
    const prefix = portalPrefix()
    return {
      deptName: (orgId) => {
        try { return this.ctx.iam.orgs().get(orgId)?.name ?? '' } catch { return '' }
      },
      skillName: (skillId) => {
        try { return this.ctx.skillHub.skills().get(skillId)?.name ?? skillId } catch { return skillId }
      },
      skillDownloadUrl: (skillId) => `${portalPublicBase()}${prefix}/skills/${skillId}/download`,
      // P1-03 (revue de sécurité 2026-10-31) : le portail anonyme masque par défaut les actifs de niveau secret (opt-out : PORTAL_HIDE_CONFIDENTIAL=0
      // pour fermer explicitement) — l'ancienne version publiait tout par défaut et exigeait d'activer le masquage ; la liste anonyme publique divulguait la topologie des actifs internes
      hideConfidential: String(process.env.PORTAL_HIDE_CONFIDENTIAL ?? '1').trim() !== '0',
    }
  }
}

// ---- CORS (contrat §6 : le portail se connecte directement depuis le navigateur en cross-origin, il faut autoriser, sinon le portail ne peut pas accéder) --------------

/** Origine du portail de production. */
const PRODUCTION_PORTAL_ORIGINS = ['http://192.168.0.4:8092']

/** Origines explicitement ajoutées côté portail (séparées par virgules, ex. http://192.168.0.4:8092,http://portal.example:8092). */
function extraOrigins(): Set<string> {
  return new Set(String(process.env.PORTAL_CORS_ORIGINS ?? '')
    .split(',').map((item) => item.trim()).filter(Boolean))
}

/** Le serveur de dev du portail écoute 0.0.0.0:8443 (localhost en dev local, IP de chacun pour les collègues de l'intranet). */
function isPortalDevOrigin(origin: string): boolean {
  try {
    const url = new URL(origin)
    const host = url.hostname.toLowerCase()
    const intranet = host === 'localhost' || host === '127.0.0.1' || host === '::1'
      || /^10\.\d+\.\d+\.\d+$/.test(host)
      || /^192\.168\.\d+\.\d+$/.test(host)
      || /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host)
    return intranet && (url.port === '8443' || url.port === '8092')
  } catch {
    return false
  }
}

/** Si autorisé, renvoie l'origine en écho (sans identifiant, le contrat n'exige pas de credentials), sinon seulement Vary. */
function corsHeaders(origin: unknown): Record<string, string> {
  const value = typeof origin === 'string' ? origin : ''
  const allowed = value !== ''
    && (PRODUCTION_PORTAL_ORIGINS.includes(value) || isPortalDevOrigin(value) || extraOrigins().has(value))
  return allowed
    ? { vary: 'Origin', 'access-control-allow-origin': value }
    : { vary: 'Origin' }
}

/** Enveloppe de réponse du contrat ({code, message, data}, code 0/200 considéré succès par le portail ; no-cache garantit visible au rafraîchissement). */
function respond(exchange: HttpExchange, status: number, payload: unknown, headers: Record<string, string>): void {
  if (exchange.res.headersSent) return
  exchange.res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-cache',
    ...headers,
  })
  exchange.res.end(JSON.stringify(payload))
}

export const name = 'portal'
export const inject = ['httpServer', 'platformBus', 'resourceCore', 'iam', 'skillHub', 'mcpRegistry', 'audit', 'authn', 'oidc']

export function apply(ctx: Context) {
  const service = new PortalFeedService(ctx)

  if (portalEnabled()) {
    const prefix = portalPrefix()
    // Les endpoints du portail sont publics en lecture seule (contrat §3 : sans authentification) — intercepter ce préfixe avant le middleware d'authentification console,
    // avec son propre CORS et son enveloppe de contrat, le reste des chemins passe tel quel. L'ordre d'enregistrement exige que cette extension soit assemblée avant console
    // (boot-all / cordis.yml le déclarent ainsi).
    ctx.effect(() => ctx.httpServer.use((exchange) => {
      if (exchange.path !== prefix && !exchange.path.startsWith(`${prefix}/`)) return
      const headers = corsHeaders(exchange.headers.origin)
      if (exchange.method === 'OPTIONS') {
        if (!exchange.res.headersSent) {
          exchange.res.writeHead(204, {
            ...headers,
            'access-control-allow-methods': 'GET, OPTIONS',
            // authorization : depuis le portail v1.1, le téléchargement doit porter un jeton Bearer de connexion (le pré-vol doit autoriser cet en-tête personnalisé)
            'access-control-allow-headers': 'authorization, content-type',
            'access-control-max-age': '600',
          })
          exchange.res.end()
        }
        return true
      }
      if (exchange.method !== 'GET' && exchange.method !== 'HEAD') {
        respond(exchange, 405, { code: 40500, message: t('门户契约为只读 GET，不支持该方式'), data: null }, headers)
        return true
      }
      // Téléchargement de paquet de skill (bout répondeur de downloadUrl) : api.md v1.1 §4.7 — connexion exigée (jeton Bearer portail),
      // jeton absent/invalide = toujours 401 d'erreur de contrat (avant le jugement d'existence, sans divulguer l'ID du skill), en-têtes CORS présents (lisible par le navigateur)
      const downloadMatch = exchange.path.slice(prefix.length).match(/^\/skills\/([^/]+)\/download$/)
      if (downloadMatch) {
        const downloader = service.resolveDownloader(exchange.headers.authorization, exchange)
        if (!downloader) {
          respond(exchange, 401, { code: 40100, message: t('下载需要登录：请携带门户登录令牌（Authorization: Bearer <token>）'), data: null }, headers)
          return true
        }
        const ip = String(exchange.raw.socket?.remoteAddress ?? 'unknown')
        const pkg = service.skillPackage(decodeURIComponent(downloadMatch[1]!), { ...downloader, ip })
        if (!pkg) {
          respond(exchange, 404, { code: 40400, message: t('技能不存在或未上架，无可下载包'), data: null }, headers)
          return true
        }
        try {
          if (!exchange.res.headersSent) {
            // Un en-tête HTTP n'accepte que l'ISO-8859-1 : nom de repli ASCII (caractères non ASCII remplacés par _) + extension UTF-8 RFC 5987
            const asciiName = pkg.filename.replace(/[^\x20-\x7E]/g, '_').replace(/"/g, "'")
            exchange.res.writeHead(200, {
              'content-type': 'application/zip',
              'content-length': pkg.buffer.length,
              'content-disposition': `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(pkg.filename)}`,
              'cache-control': 'no-cache',
              ...headers,
            })
            exchange.res.end(pkg.buffer)
          }
        } catch (error) {
          console.error('[portal] 技能包下载应答失败', error)
          respond(exchange, 500, { code: 50000, message: t('技能包读取失败，请稍后重试'), data: null }, headers)
        }
        return true
      }
      const tail = exchange.path.slice(prefix.length).replace(/^\/+|\/+$/g, '')
      if (tail === '') {
        // Découverte d'endpoints : entrée d'auto-vérification d'intégration (curl <BASE>/ doit montrer la liste des endpoints)
        respond(exchange, 200, {
          code: 0,
          message: 'ok',
          data: {
            service: 'portal-feed',
            contract: 'api.md v1.1',
            endpoints: ENDPOINTS,
            subResources: [t('skills/:id/download（技能包下载，须 Bearer 登录令牌：未登录 401，审计谁在下载）')],
            generatedAt: new Date().toISOString(),
          },
        }, headers)
        return true
      }
      if (!(ENDPOINTS as readonly string[]).includes(tail)) {
        respond(exchange, 404, { code: 40400, message: t('门户端点不存在：{endpoint}', { endpoint: tail }), data: null }, headers)
        return true
      }
      respond(exchange, 200, { code: 0, message: 'ok', data: service.feed(tail) }, headers)
      return true
    }))
  } else {
    ctx.logger('portal').info('门户数据通道已停用（PORTAL_SYNC=off），门户将降级展示内置样板数据')
  }

  // Trace de visibilité : mise en ligne/hors ligne d'applications/employés numériques → enregistrement d'audit. Le portail est en mode tirage, la trace n'est que d'observabilité
  // opérationnelle (« quand visible/invisible pour le portail »), sans aucune action sortante.
  const visibilityTrail: Array<[string, string, string]> = [
    [PlatformEvents.AppOnlined, 'app', 'portal.feed.app.visible'],
    [PlatformEvents.AppOfflined, 'app', 'portal.feed.app.hidden'],
    [PlatformEvents.AgentOnlined, 'agent', 'portal.feed.employee.visible'],
    [PlatformEvents.AgentOfflined, 'agent', 'portal.feed.employee.hidden'],
  ]
  for (const [event, resourceType, action] of visibilityTrail) {
    ctx.platformBus.on(event, (payload) => {
      const record = payload as { id?: string; name?: string } | undefined
      try {
        ctx.audit.record({
          type: 'change', actorType: 'system', actorId: 'portal-feed', actorName: '门户数据通道',
          action, resourceType, resourceId: record?.id ?? '', resourceName: record?.name ?? '',
          result: 'ok', detail: '门户拉取模式：资源对门户可见性已变化，门户刷新页面即可见',
        })
      } catch {
        // un échec de trace n'interrompt pas la chaîne d'événements métier
      }
    })
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    portalFeed: PortalFeedService
  }
}
