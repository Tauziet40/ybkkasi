/**
 * Module partagé de la porte d'authentification REST (convergence des gabarits d'authentification R5, REFACTOR-2026-10-13, 2026-10-13).
 *
 * Auparavant, CallerInfo + requirePermission + guarded + body + changeLog existaient en
 * plugin-console / plugin-panel-core / plugin-flow-core / plugin-dingtalk-bridge
 * quatre quasi-duplications (guarded/body isomorphes au mot près, CallerInfo aux réductions de champs divergentes) —
 * la correction en point unique et l'audit en point unique convergent ici. La construction de principal reste dans le middleware
 * d'authentification console (seul point d'écriture faisant autorité, voir plugin-console/src/index.ts) ; ce module ne fait que consommer.
 *
 * Direction des dépendances : platform-core ne dépend pas en retour des plugins métier — audit est injecté par type structurel minimal
 * (il suffit que le ctx de l'appelant satisfasse la structure) ; les plugins sans audit injecté comme flow-core ne doivent pas appeler
 * changeLog (en cas d'absence d'audit à la construction, changeLog échoue immédiatement, pour éviter une perte d'audit silencieuse).
 */
import type { HttpExchange, HttpHandler, RouteAuthDecl } from './http.ts'
import type { WorkCallerRef } from './workforce-port.ts'
import { toWorkCallerRef, unifiedFromCaller } from './principal.ts'
import { t } from '../../platform-i18n/src/index.ts'

/** Identité de l'appelant (structure complète écrite par le middleware d'authentification console dans exchange.principal) */
export interface CallerInfo {
  kind: 'human' | 'machine'
  principalId: string
  userId?: string
  /** Spécifique machine : ressource liée à l'identifiant (refType=agent : les appels modelgw etc. comptabilisent sous agent:<refId>). */
  refType?: string
  refId?: string
  name: string
  permissions: string[]
  actChain: Array<{ name: string; type: string }>
}

/** Hôte structurel minimal : le ctx des plugins métier satisfait tous la structure (pas de dépendance typée vers des services concrets) */
export interface RestGateHost {
  httpServer: { register(method: string, pattern: string, handler: HttpHandler, auth?: RouteAuthDecl): unknown }
  platformBus: { emit(event: string, payload: unknown): unknown }
  audit?: { record(entry: Record<string, unknown>): unknown }
}

export interface RestGate {
  /** Récupère l'identité de l'appelant (principal écrit au préalable par le middleware d'authentification console) */
  caller(exchange: HttpExchange): CallerInfo
  /** Décision de permission : 403 sans permission + trace audit.authz.denied (surface de décision de la sonde RBAC) */
  requirePermission(exchange: HttpExchange, point: string): boolean
  /** Enregistre une route protégée par permission (H5 : la déclaration est fusionnée automatiquement par register dans la matrice routes×permissions) */
  guarded(method: string, path: string, permission: string, handler: (exchange: HttpExchange) => unknown | Promise<unknown>): void
  /** Analyse du corps de requête (conversion tolérante) */
  body<T extends Record<string, any>>(exchange: HttpExchange): T
  /** Trace d'audit des modifications (exige l'injection d'audit par l'hôte ; échec immédiat sans audit) */
  changeLog(exchange: HttpExchange, action: string, resourceType: string, resourceId: string, resourceName: string, detail?: string): void
  /** id de sujet d'audit (userId pour les humains, principalId pour les machines) */
  actorOf(exchange: HttpExchange): string
}

/**
 * Table d'implication des points de permission (lot mode démo 2026-10-17) : la clé est le point métier, la valeur le point de base qui l'implique —
 * détenir le point de base vaut détenir le point métier.
 *
 *   console.read (base de lecture seule de la console : agrégats de l'espace de travail/notifications/informations plateforme/catalogue d'outils/appels récents)
 *     ← console.login (base de session connectée, détenue par tout rôle pouvant se connecter)
 *
 * Motivation : ce lot de routes en pure lecture déclarait auparavant console.login ; la sémantique « session connectée »
 * ne correspond pas exactement à « espace de travail lisible », et la liste blanche en lecture du mode démo sans login (DEMO_MODE=1, voir plugin-console demo-mode.ts)
 * ne contient pas de points de niveau login : les visiteurs ne pouvaient pas ouvrir le premier écran de l'espace de travail. Après bascule des routes vers console.read,
 * la surface de décision complète cette règle d'implication ; les jetons des vrais utilisateurs existants (ne portant que console.login, y compris les anciens jetons émis avant la montée de version)
 * passent sans re-signature, sans s'en apercevoir — le comportement des requêtes avec Bearer reste strictement identique.
 * session.can() côté frontend (plugin-console/public/js/api.js) porte une règle miroir identique ; les deux endroits doivent être modifiés en synchronisation.
 */
const IMPLIED_POINTS: Record<string, string> = { 'console.read': 'console.login' }
// Export de la table d'implication (W3-T5) : les facettes non REST comme le filtrage tools/list du bridge /mcp et le requirePermission REST
// partagent une source unique (pendant la période de gel de platform-core, on ne pouvait obtenir le booléen qu'indirectement via une sonde host factice ; désormais consommation directe)
export { IMPLIED_POINTS }

/**
 * Fonction pure partagée de décision des points de permission (contrat de gouvernance MCP §8/§11, exportée en W3-T5) : même surface de décision que requirePermission
 * ('*' passe / point détenu directement / correspondance dans la table d'implication), pour réutilisation en point unique par les facettes non REST (comme la sonde
 * de filtrage tools/list du bridge /mcp) — la table d'implication est une constante de ce module, une fois exportée il n'est plus nécessaire de
 * passer par un host factice de createRestGate pour obtenir le booléen (l'implémentation transitoire de la période de gel de platform-core peut être remplacée).
 */
export function permissionPointAllows(permissions: string[], point: string): boolean {
  const impliedBy = IMPLIED_POINTS[point]
  return permissions.includes('*') || permissions.includes(point)
    || (impliedBy !== undefined && permissions.includes(impliedBy))
}

export function createRestGate(ctx: RestGateHost): RestGate {
  const caller = (exchange: HttpExchange): CallerInfo => exchange.principal as CallerInfo

  const requirePermission = (exchange: HttpExchange, point: string): boolean => {
    const info = caller(exchange)
    // Convergence de la surface de décision en point unique (W3-T5) : table d'implication et décision booléenne dans permissionPointAllows ci-dessus, ici seulement les effets de bord
    if (permissionPointAllows(info.permissions, point)) return true
    ctx.platformBus.emit('audit.authz.denied', {
      actorId: info.userId ?? info.principalId,
      actorName: info.name,
      point,
      path: exchange.path,
    })
    exchange.fail(403, 'FORBIDDEN', t('缺少权限点 {point}，请联系管理员调整角色', { point }), { permission: point })
    return false
  }

  const guarded = (method: string, path: string, permission: string, handler: (exchange: HttpExchange) => unknown | Promise<unknown>): void => {
    ctx.httpServer.register(method, path, async (exchange) => {
      if (!requirePermission(exchange, permission)) return
      try {
        const result = await handler(exchange)
        if (!exchange.res.writableEnded) exchange.ok(result)
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        exchange.fail(400, 'BAD_REQUEST', message)
      }
    }, { access: 'guarded', permission })
  }

  const body = <T extends Record<string, any>>(exchange: HttpExchange): T => (exchange.body ?? {}) as T

  const changeLog = (exchange: HttpExchange, action: string, resourceType: string, resourceId: string, resourceName: string, detail = ''): void => {
    if (!ctx.audit) throw new Error(t('changeLog 需要宿主注入 audit 服务（本插件未注入，禁止静默丢弃审计）'))
    const info = caller(exchange)
    ctx.audit.record({
      type: 'change',
      actorType: info.kind === 'human' ? 'human' : 'machine',
      actorId: info.userId ?? info.principalId,
      actorName: info.name,
      action,
      resourceType,
      resourceId,
      resourceName,
      result: 'ok',
      detail,
      ...(info.actChain.length > 0 ? { actChain: info.actChain } : {}),
    })
  }

  const actorOf = (exchange: HttpExchange): string => {
    const info = caller(exchange)
    return info.userId ?? info.principalId
  }

  return { caller, requirePermission, guarded, body, changeLog, actorOf }
}

/**
 * Sujet vérifié → référence d'appelant de la stratégie de travail (WorkCallerRef, D01 additif).
 *
 * Permet à chaque route de remettre exchange.principal (CallerInfo) écrit par le middleware d'authentification console au
 * port étroit workforce (ctx.workforcePolicy / gateManagedWork / workforce.claimWork) :
 * l'identité vient toujours du résultat de résolution du jeton, interdiction de l'assembler depuis le corps/les paramètres de requête. Mapping champ à champ,
 * les champs absents ne sont pas produits (préserve la sémantique des champs optionnels de WorkCallerRef). Ne modifie pas le comportement RestGate existant.
 *
 * Convergence de gouvernance MCP (contrat §2) : l'implémentation du mapping est déplacée en point unique vers principal.ts (toWorkCallerRef),
 * cette fonction ne fait qu'aligner la forme CallerInfo → sujet unifié avant délégation, comportement externe inchangé.
 */
export function workCallerOf(info: CallerInfo): WorkCallerRef {
  return toWorkCallerRef(unifiedFromCaller(info))
}
