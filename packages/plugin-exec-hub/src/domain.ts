/**
 * Couche de décision pure du centre d'exécution (domain) — pas d'IO, pas d'horloge, pas de base.
 *
 * Portage du cœur de conception Paperclip wake-queue : la politique est totalement décollée de l'IO,
 * ce qui permet une énumération exhaustive des frontières par tables (alignée sur l'intensité de test de son policy.test.ts).
 * Ici ne vivent que fonctions de décision et outils purs ; toute logique « lire la base/lire l'horloge » reste dans la couche service
 * (application), qui calcule les faits (facts) avant de les nourrir ici.
 * Exception : les libellés de refus tournés vers l'utilisateur passent par t() de platform-i18n (sortie selon la locale de requête/d'installation, repli chinois si la clé manque au dictionnaire).
 */
import { t } from '../../platform-i18n/src/index.ts'

// ---------------------------------------------------------------------------
// Admission de réveil (trois états decideWakeAdmission de Paperclip)
// ---------------------------------------------------------------------------

export type WakeAdmissionFacts = {
  /** Si le détenteur du verrou d'exécution de l'issue cible est le même Agent (comparaison par clé de nom normalisée). */
  isSameExecutionAgent: boolean
  /** Si ce réveil doit être différé (demande explicite de l'amont, ex. approbation en attente). */
  shouldDeferFollowupWake: boolean
  /** Si l'on doit fusionner dans le réveil en cours (sémantique de réveil suivi). */
  shouldQueueFollowupForRunningWake: boolean
  /** S'il existe un run d'exécution actif sur l'issue cible (executionRunId non vide = existence). */
  availableActiveExecutionRunPresent: boolean
  /** Si la fusion de run est permise (permise par défaut). */
  allowRunCoalescing?: boolean
  /** Si même exécutant persistant (considéré comme oui par défaut ; fusionner entre exécutants est un risque de gouvernance). */
  sameDurableActor?: boolean
}

export type WakeAdmissionDecision =
  | { kind: 'proceed' }   // pas de run actif → démarrage normal d'un nouveau run
  | { kind: 'coalesce' }  // même Agent + fusionnable → fusion dans le run existant
  | { kind: 'defer' }     // run actif mais conditions de fusion non remplies → file différée

/**
 * Arbitrage trois états de l'admission de réveil. Décision et CAS sont deux mécanismes :
 * cette fonction rend sa décision hors transaction ; la garde `executionRunId IS NULL` de la couche stockage n'est
 * qu'un garde-fou anti-double-prise-de-verrou, pas un signal de décision (conception Paperclip d'origine).
 */
export function decideWakeAdmission(f: WakeAdmissionFacts): WakeAdmissionDecision {
  if (
    f.allowRunCoalescing !== false &&
    f.sameDurableActor !== false &&
    f.isSameExecutionAgent &&
    !f.shouldDeferFollowupWake &&
    !f.shouldQueueFollowupForRunningWake &&
    f.availableActiveExecutionRunPresent
  ) {
    return { kind: 'coalesce' }
  }
  if (f.availableActiveExecutionRunPresent) {
    return { kind: 'defer' }
  }
  return { kind: 'proceed' }
}

// ---------------------------------------------------------------------------
// Récupération de libération (version élaguée de decideReleaseRecovery de Paperclip)
// ---------------------------------------------------------------------------

export type ReleaseRecoveryFacts = {
  /** Si l'enregistrement du run détenteur du verrou n'existe plus (données perdues/nettoyées). */
  runMissing: boolean
  /** Si le run est déjà en état terminal (completed/failed/timeout) mais verrou non libéré. */
  runSettled: boolean
  /** Si le run est toujours running mais que le verrou a expiré (au-delà du seuil de récupération). */
  lockTimedOut: boolean
}

export type ReleaseRecoveryDecision =
  | { kind: 'keep' }             // tout va bien, on n'y touche pas
  | { kind: 'force-release' }    // libération forcée du verrou (run disparu/terminal/expiré)
  | { kind: 'timeout-run' }      // run expiré : d'abord marquer l'état terminal timeout puis libération forcée

export function decideReleaseRecovery(f: ReleaseRecoveryFacts): ReleaseRecoveryDecision {
  if (f.runMissing || f.runSettled) return { kind: 'force-release' }
  if (f.lockTimedOut) return { kind: 'timeout-run' }
  return { kind: 'keep' }
}

// ---------------------------------------------------------------------------
// Normalisation des noms (synonyme normalizeAgentKey de Paperclip)
// ---------------------------------------------------------------------------

/** Clé canonique de nom d'Agent : pour comparer « réveils consécutifs du même Agent », évite le tremblement casse/blancs. */
export function normalizeAgentKey(name: string): string {
  return String(name ?? '').trim().toLowerCase().replace(/\s+/g, ' ')
}

// ---------------------------------------------------------------------------
// Matérialisation de la lignée d'objectifs
// ---------------------------------------------------------------------------

/**
 * Matérialisation : goalChain (racine→parent→objectif courant) + projectId assemblés en issue.goalAncestry,
 * la lecture de lignée n'a plus besoin de requêtes récursives (l'arbre d'objectifs est peu profond : matérialisation à l'écriture, lecture directe).
 */
export function materializeGoalAncestry(goalChain: string[], projectId?: string): string[] {
  return [...goalChain, ...(projectId ? [projectId] : [])]
}

/** Résumé de lignée (à injecter dans le contexte Agent) : [chaîne d'objectifs…] → « racine › parent › objectif › projet ». */
export function lineageSummary(ancestry: string[], titles: Record<string, string>): string {
  return ancestry.map((id) => titles[id] ?? id).join(' › ') || '（未挂目标/项目）'
}

// ---------------------------------------------------------------------------
// Assemblage du contexte Agent (forme d'atterrissage de l'exécution goal-aware)
// ---------------------------------------------------------------------------

export interface ContextPackInput {
  goalTitle?: string
  goalMetric?: string
  projectNames: string[]
  issueTitle: string
  blockerTitles: string[]
  dataClass?: string
  budgetNote?: string
  permissionNote?: string
}

/** Assemble le paquet de contexte du « pourquoi on le fait » : objectif/projet/tâche/prérequis + annotation de périmètre de gouvernance. */
export function buildIssueContextPack(input: ContextPackInput): string {
  const lines: string[] = ['【本任务服务于】']
  lines.push(input.goalTitle
    ? `目标：${input.goalTitle}${input.goalMetric ? `（指标：${input.goalMetric}）` : ''}`
    : '目标：（未挂目标）')
  const projectNames = input.projectNames ?? []
  if (projectNames.length > 0) lines.push(`项目：${projectNames.join('、')}`)
  lines.push(`你的任务：${input.issueTitle}`)
  const blockerTitles = input.blockerTitles ?? []
  lines.push(blockerTitles.length > 0 ? `前置：等待「${blockerTitles.join('」「')}」完成` : '前置：无阻塞依赖')
  lines.push('', '【可用范围】')
  if (input.permissionNote) lines.push(input.permissionNote)
  if (input.dataClass) lines.push(`可访问数据密级上限：${input.dataClass}（更高密级需申请）`)
  if (input.budgetNote) lines.push(input.budgetNote)
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Santé de l'Agent (R9 : les données de battement entrent dans la santé de l'Agent)
// ---------------------------------------------------------------------------

export type AgentHealthLevel = 'healthy' | 'stale' | 'silent' | 'frozen' | 'offline'

export interface AgentHealthFacts {
  agentStatus: string
  frozen: boolean
  /** Datation du dernier battement (ms epoch ; null si absent). */
  lastHeartbeatAt: number | null
  /** Datation du dernier rapport de métriques géré (ms epoch ; null si absent). */
  lastMetricsReportAt: number | null
  nowMs: number
  /** Période de battement (minutes ; 0/absent = battement non configuré, référentiel tolérant 24 h). */
  heartbeatIntervalMinutes?: number
}

/**
 * Gradation de santé : offline (hors état de marche) → frozen (gelé) → healthy (battement frais)
 * → stale (battement à la traîne) → silent (long silence de battement). Fenêtre de fraîcheur = 3× la période de battement
 * (tolère deux tours manqués), fenêtre de traîne 9× ; les Agents sans battement configuré suivent deux paliers tolérants 24 h/72 h (référentiel d'obligation de rapport).
 */
export function computeAgentHealth(f: AgentHealthFacts): AgentHealthLevel {
  if (f.agentStatus !== 'online' && f.agentStatus !== 'trial') return 'offline'
  if (f.frozen) return 'frozen'
  const configured = (f.heartbeatIntervalMinutes ?? 0) > 0
  const baseMs = configured ? (f.heartbeatIntervalMinutes as number) * 60_000 : 24 * 3_600_000
  const last = f.lastHeartbeatAt ?? f.lastMetricsReportAt
  if (last === null) return 'silent'
  if (f.nowMs - last <= baseMs * 3) return 'healthy'
  if (f.nowMs - last <= baseMs * 9) return 'stale'
  return 'silent'
}

// ---------------------------------------------------------------------------
// Machine à états des tâches (exec:issues)
// ---------------------------------------------------------------------------

export type IssueStatus = 'todo' | 'in_progress' | 'review' | 'done' | 'cancelled'

/** Table de transitions explicite : done/cancelled terminaux ; review peut être renvoyé en in_progress. */
export const ISSUE_TRANSITIONS: Record<IssueStatus, IssueStatus[]> = {
  todo: ['in_progress', 'cancelled'],
  in_progress: ['review', 'cancelled'],
  review: ['done', 'in_progress', 'cancelled'],
  done: [],
  cancelled: [],
}

export function issueCanTransition(from: IssueStatus, to: IssueStatus): boolean {
  return ISSUE_TRANSITIONS[from]?.includes(to) ?? false
}

/** Si la dépendance bloquante est levée : tous les blockers en état terminal (done compte comme levé, cancelled lève aussi l'attente — plus de suspension indéfinie). */
export function blockersResolved(blockerStatuses: IssueStatus[]): boolean {
  return blockerStatuses.every((status) => status === 'done' || status === 'cancelled')
}

// ---------------------------------------------------------------------------
// Planification de routine : cron minimal à 5 champs (granularité minute)
// ---------------------------------------------------------------------------

/** Correspondance d'un champ : `*`, `a`, `a-b`, `a/b` (pas), liste à virgules. */
export function cronFieldMatches(field: string, value: number, min: number, max: number): boolean {
  for (const part of field.split(',')) {
    const [range, stepRaw] = part.split('/')
    const step = stepRaw === undefined ? 1 : Number(stepRaw)
    if (!Number.isInteger(step) || step < 1) continue
    let from = min
    let to = max
    if (range !== undefined && range !== '*' && range !== '') {
      const dash = range.indexOf('-')
      if (dash >= 0) {
        from = Number(range.slice(0, dash))
        to = Number(range.slice(dash + 1))
      } else {
        from = Number(range)
        to = stepRaw === undefined ? from : max
      }
    }
    if (!Number.isInteger(from) || !Number.isInteger(to)) continue
    if (from < min || to > max || from > to) continue
    if (value >= from && value <= to && (value - from) % step === 0) return true
  }
  return false
}

/** Si un cron à 5 champs (min heure jour mois semaine) correspond à l'instant donné. 0/7 pour dimanche tous deux. */
export function cronMatches(expr: string, at: Date): boolean {
  const fields = expr.trim().split(/\s+/)
  if (fields.length !== 5) return false
  const minute = at.getUTCMinutes()
  const hour = at.getUTCHours()
  const dom = at.getUTCDate()
  const month = at.getUTCMonth() + 1
  const dowRaw = at.getUTCDay()
  const dow = dowRaw === 0 ? 7 : dowRaw
  const [fMinute, fHour, fDom, fMonth, fDow] = fields
  if (!cronFieldMatches(fMinute ?? '', minute, 0, 59)) return false
  if (!cronFieldMatches(fHour ?? '', hour, 0, 23)) return false
  if (!cronFieldMatches(fMonth ?? '', month, 1, 12)) return false
  // Sémantique POSIX jour et semaine : quand les deux restreignent (non *), une correspondance suffit
  const domRestricted = fDom !== undefined && fDom !== '*' && fDom !== ''
  const dowRestricted = fDow !== undefined && fDow !== '*' && fDow !== ''
  const domHit = cronFieldMatches(fDom ?? '', dom, 1, 31)
  // Dimanche accepte les deux écritures 0 et 7 (le côté valeur est déjà normalisé à 7 ; si le champ écrit 0, on retente avec 0)
  const dowHit = cronFieldMatches(fDow ?? '', dow, 0, 7) || (dowRaw === 0 && cronFieldMatches(fDow ?? '', 0, 0, 0))
  if (domRestricted && dowRestricted) return domHit || dowHit
  return domHit && dowHit
}

/** Validation de légalité du cron (à l'enregistrement, retour immédiat à l'utilisateur). */
export function cronIsValid(expr: string): boolean {
  const fields = expr.trim().split(/\s+/)
  if (fields.length !== 5) return false
  const ranges: Array<[number, number]> = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 7]]
  return fields.every((field, index) => {
    const [min, max] = ranges[index]!
    // Tester chaque part sur une valeur nécessairement dans l'intervalle ne suffit pas — valider la structure lexicale
    return field.split(',').every((part) => {
      const [range, stepRaw] = part.split('/')
      if (stepRaw !== undefined && (!/^\d+$/.test(stepRaw) || Number(stepRaw) < 1)) return false
      if (range === '*' || range === '') return true
      if (!/^\d+(-\d+)?$/.test(range)) return false
      const [a, b] = range.split('-')
      const from = Number(a)
      const to = b === undefined ? from : Number(b)
      return from >= min && to <= max && from <= to
    })
  })
}

// ---------------------------------------------------------------------------
// Clé d'idempotence de réveil
// ---------------------------------------------------------------------------

export function wakeIdempotencyKey(trigger: string, parts: Array<string | number | undefined>): string {
  return [trigger, ...parts.map((p) => String(p ?? ''))].join(':')
}

// ---------------------------------------------------------------------------
// Décision pure des baux d'exécution (décision 3 de l'annexe A : exec_run_leases fait autorité, les trois champs d'issue sont une projection)
//
// Blueprint §6.2/§7-D05/D06 : réclamer = « confirmation idempotente d'un bail déjà attribué » — réclamer deux fois le même employé sur la même tâche
// renvoie le run/bail existant (pas d'erreur « tenu par autrui ») ; autre principal, bail périmé, tâche fermée : refus.
// Décision et stockage séparés : ce groupe de fonctions ne consomme que des faits (facts), IO et transactions dans lease-store.ts / couche service.
// ---------------------------------------------------------------------------

/** État du bail (structure alignée sur le LeaseStatus de plugin-workforce contract.ts, pas d'import pour éviter la boucle). */
export type LeaseStatusLite = 'active' | 'released' | 'superseded'

export interface LeaseClaimFacts {
  /** Si l'issue a un bail actif dans la table d'autorité. */
  activeLeasePresent: boolean
  /** Si le bail actif existant a dépassé expiresAt (expiré = personne ne détient effectivement, remplaçable par un nouveau bail). */
  activeLeaseExpired: boolean
  /** Employé détenteur du bail existant (chaîne vide en réclamation directe legacy par machine). */
  existingEmployeeId: string
  /** agentKey détenteur du bail existant. */
  existingAgentKey: string
  /** Employé de la présente réclamation. */
  requestedEmployeeId: string
  /** agentKey de la présente réclamation. */
  requestedAgentKey: string
}

export type LeaseClaimDecision =
  | { kind: 'idempotent' }                    // réclamation répétée du même détenteur → renouvellement idempotent du bail existant (created=false)
  | { kind: 'held-by-other'; holder: string } // détenu par un autre/autre Agent → refus
  | { kind: 'acquire' }                       // aucun bail valide (expiré compris) → nouvelle prise (version+1)

/**
 * Arbitrage d'idempotence de réclamation (D05/D06) : l'employé géré est identifié par employeeId (changer l'Agent lié ne casse pas l'idempotence) ;
 * la réclamation directe legacy par machine (employeeId chaîne vide) est identifiée par agentKey. Un bail expiré ne compte pas comme détenu.
 */
export function decideLeaseClaim(f: LeaseClaimFacts): LeaseClaimDecision {
  if (f.activeLeasePresent && !f.activeLeaseExpired) {
    const sameHolder = f.requestedEmployeeId !== ''
      ? f.existingEmployeeId === f.requestedEmployeeId
      : f.existingEmployeeId === '' && f.existingAgentKey === f.requestedAgentKey
    if (sameHolder) return { kind: 'idempotent' }
    return { kind: 'held-by-other', holder: f.existingAgentKey || f.existingEmployeeId }
  }
  return { kind: 'acquire' }
}

export interface LeaseRenewalFacts {
  status: LeaseStatusLite
  /** now > expiresAt。 */
  expired: boolean
  /** Le principal appelant coïncide avec le principalId du bail (principal absent = divergence, fail-closed). */
  principalMatches: boolean
}

export type LeaseRenewalDecision = { kind: 'renew' } | { kind: 'stale' }

/** Arbitrage de renouvellement (§11.6) : même principal + actif + non expiré ; bail périmé/autre principal/libéré = toujours stale. */
export function decideLeaseRenewal(f: LeaseRenewalFacts): LeaseRenewalDecision {
  return f.status === 'active' && !f.expired && f.principalMatches ? { kind: 'renew' } : { kind: 'stale' }
}

export interface CompleteOwnershipFacts {
  /** Si le run a un enregistrement de bail (quel que soit l'état). Sans enregistrement = run de l'ancien chemin, passage compatible (référentiel D07). */
  hasLeaseRecord: boolean
  status: LeaseStatusLite
  expired: boolean
  /** principalId appelant (chaîne vide si exec.principal absent). */
  callerPrincipalId: string
  leasePrincipalId: string
}

export type CompleteOwnershipDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; code: 'LEASE_STALE' | 'RUN_NOT_OWNED'; reason: string }

/**
 * Validation de principal du complete (D07/§6.5/V06) : un run avec enregistrement de bail exige la coïncidence des principaux ;
 * bail périmé (released/superseded/expiré) : d'abord LEASE_STALE, puis divergence de principal RUN_NOT_OWNED ;
 * un run sans enregistrement de bail suit l'ancien chemin compatible (resserrage à la discrétion de l'appelant).
 */
export function decideCompleteOwnership(f: CompleteOwnershipFacts): CompleteOwnershipDecision {
  if (!f.hasLeaseRecord) return { kind: 'allow' }
  if (f.status !== 'active' || f.expired) {
    return { kind: 'deny', code: 'LEASE_STALE', reason: t('执行租约已过期或被更高版本取代（旧租约），请先重新认领') }
  }
  if (!f.callerPrincipalId || f.callerPrincipalId !== f.leasePrincipalId) {
    return { kind: 'deny', code: 'RUN_NOT_OWNED', reason: t('该 run 不归属当前调用主体，禁止代他人交回执行回执') }
  }
  return { kind: 'allow' }
}

export interface RunAdoptionFacts {
  /** Si le champ de projection executionRunId de l'issue est non vide. */
  projectedRunIdPresent: boolean
  /** Si le run pointé par la projection est toujours running (terminal/disparu = projection sale). */
  projectedRunRunning: boolean
}

export type RunAdoptionDecision = { kind: 'adopt' } | { kind: 'create' }

/**
 * Arbitrage get-or-create (V05) : le run laissé par la préemption de verrou par l'ordonnanceur est directement adopté par le runtime (plus de run recréé),
 * seul un projet absent ou une projection sale (run terminal/disparu) fait créer — la sémantique côté run de « réclamer un bail déjà attribué ».
 */
export function decideRunAdoption(f: RunAdoptionFacts): RunAdoptionDecision {
  return f.projectedRunIdPresent && f.projectedRunRunning ? { kind: 'adopt' } : { kind: 'create' }
}
