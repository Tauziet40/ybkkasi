/**
 * Jugement à l'exécution ODD (Operation Design Domain) (OPT-P2-01, 2026-09-12).
 *
 * Un groupe de permissions connecteur peut déclarer un bloc odd (domaine de conception opérationnelle) : liste blanche provider / exclusion explicite d'actions /
 * seuil de fraîcheur des données du catalogue / fenêtre temporelle autorisée. `inOdd` est une fonction pure — la chaîne d'autorisation insère le jugement de domaine avant la barrière d'approbation admin,
 * hors domaine = refus et émission de `connector.odd_exit` (vers l'audit via le bus OPT-P1-04).
 * La frontière devient calculable : action hors catalogue, catalogue périmé, appel hors fenêtre temporelle ne dépendent plus d'une défense passive « rattrapée par admin ».
 */
import { t } from '../../platform-i18n/src/index.ts'

export interface OddDeclaration {
  /** Liste blanche provider (service) : '*' ou liste explicite ; non déclaré = sans limitation. */
  allowedServices?: string[] | '*'
  /** Exclusion explicite d'ids d'action (exclusion nominative d'actions hors catalogue/dangereuses). */
  excludedActions?: string[]
  /** Seuil de fraîcheur des données du catalogue (minutes) : si le syncedAt du catalogue dépasse le seuil par rapport à maintenant → hors domaine (non déclaré = sans limitation). */
  dataFreshnessMinutes?: number
  /** Fenêtre temporelle autorisée (heure locale, format 24 h) : ex. { start: 9, end: 18 } ; passage au-delà de minuit accepté avec start > end ; non déclaré = toute la journée. */
  activeHours?: { start: number; end: number }
}

export interface OddActionRef {
  id: string
  service: string
}

export interface OddVerdict {
  in: boolean
  reasons: string[]
}

function inActiveHours(now: Date, window: { start: number; end: number }): boolean {
  const hour = now.getHours()
  const { start, end } = window
  if (start === end) return hour === start
  if (start < end) return hour >= start && hour < end
  return hour >= start || hour < end // passage de minuit : 22→6
}

/**
 * Jugement de domaine (fonction pure) : toutes les contraintes satisfaites → in=true ; tout point hors domaine produit des reasons (lisibles, vers l'audit).
 */
export function inOdd(
  odd: OddDeclaration,
  action: OddActionRef,
  options: { now?: Date; catalogSyncedAt?: string } = {},
): OddVerdict {
  const reasons: string[] = []
  const now = options.now ?? new Date()

  if (Array.isArray(odd.allowedServices) && !odd.allowedServices.includes(action.service)) {
    reasons.push(t('provider {service} 不在 ODD 白名单（允许：{allowed}）', { service: action.service, allowed: odd.allowedServices.join('、') || t('空') }))
  }

  if (Array.isArray(odd.excludedActions) && odd.excludedActions.includes(action.id)) {
    reasons.push(t('action {action} 在 ODD 显式排除清单内', { action: action.id }))
  }

  if (typeof odd.dataFreshnessMinutes === 'number' && odd.dataFreshnessMinutes > 0) {
    const syncedAt = options.catalogSyncedAt ? Date.parse(options.catalogSyncedAt) : NaN
    if (Number.isNaN(syncedAt)) {
      reasons.push(t('目录缺少同步时间戳，无法证明数据新鲜度（fail-closed）'))
    } else {
      const ageMinutes = (now.getTime() - syncedAt) / 60_000
      if (ageMinutes > odd.dataFreshnessMinutes) {
        reasons.push(t('目录数据已陈旧：距上次同步 {age} 分钟，超过 ODD 阈值 {threshold} 分钟', { age: Math.floor(ageMinutes), threshold: odd.dataFreshnessMinutes }))
      }
    }
  }

  if (odd.activeHours && !inActiveHours(now, odd.activeHours)) {
    reasons.push(t('当前时间 {time} 在 ODD 许可时间窗（{start}:00–{end}:00）之外', {
      time: `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`,
      start: odd.activeHours.start,
      end: odd.activeHours.end,
    }))
  }

  return { in: reasons.length === 0, reasons }
}

/**
 * Normalisation de la déclaration en entrée : retire les champs non déclarés, pour empêcher qu'une affectation partielle écrive une sémantique undefined dans le registre.
 * QA C-04 : **toute déclaration illégale lève une erreur (fail-closed)** — auparavant start=25 / fraîcheur négative / liste blanche sous forme de chaîne
 * et autres déclarations défectueuses étaient silencieusement retirées, l'exploitation croyait le domaine actif alors qu'il tournait à découvert (fail-open). Non déclaré (absent) renvoie toujours undefined.
 * L'erreur remonte via le panneau upsert du groupe de permissions sous forme de 400, l'exploitation corrige sur place.
 */
export function normalizeOdd(input: unknown): OddDeclaration | undefined {
  if (!input || typeof input !== 'object') return undefined
  const odd = input as OddDeclaration
  const normalized: OddDeclaration = {}
  if (odd.allowedServices !== undefined) {
    if (odd.allowedServices === '*') normalized.allowedServices = '*'
    else if (Array.isArray(odd.allowedServices) && odd.allowedServices.length > 0
      && odd.allowedServices.every((item) => typeof item === 'string' && item.trim() !== '')) {
      normalized.allowedServices = odd.allowedServices
    } else {
      throw new Error(t('ODD 声明非法：allowedServices 须为 \'*\' 或非空字符串数组（收到 {value}）', { value: JSON.stringify(odd.allowedServices) }))
    }
  }
  if (odd.excludedActions !== undefined) {
    if (Array.isArray(odd.excludedActions) && odd.excludedActions.every((item) => typeof item === 'string' && item.trim() !== '')) {
      if (odd.excludedActions.length > 0) normalized.excludedActions = [...odd.excludedActions]
    } else {
      throw new Error(t('ODD 声明非法：excludedActions 须为非空字符串数组（收到 {value}）', { value: JSON.stringify(odd.excludedActions) }))
    }
  }
  if (odd.dataFreshnessMinutes !== undefined) {
    if (typeof odd.dataFreshnessMinutes === 'number' && Number.isFinite(odd.dataFreshnessMinutes) && odd.dataFreshnessMinutes > 0) {
      normalized.dataFreshnessMinutes = odd.dataFreshnessMinutes
    } else {
      throw new Error(t('ODD 声明非法：dataFreshnessMinutes 须为正数（分钟），收到 {value}', { value: JSON.stringify(odd.dataFreshnessMinutes) }))
    }
  }
  if (odd.activeHours !== undefined) {
    const { start, end } = odd.activeHours ?? ({} as { start?: unknown; end?: unknown })
    const valid = (value: unknown): value is number => typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 23
    if (valid(start) && valid(end)) {
      normalized.activeHours = { start, end }
    } else {
      throw new Error(t('ODD 声明非法：activeHours.start/end 须为 0-23 的整数（本地时，24h 制），收到 {value}', { value: JSON.stringify(odd.activeHours) }))
    }
  }
  return Object.keys(normalized).length > 0 ? normalized : undefined
}
