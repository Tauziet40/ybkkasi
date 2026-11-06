/**
 * Service de maintenance du registre (maintenance-service, face opérationnelle W5, décision D-③ ensemble minimal trois-en-un).
 *
 * Responsabilités (« le minuteur et l'admin manuel exécutent la même fonction », mêmes précédents que l'inspection de rétention de plugin-usage et le tick d'exec-hub) :
 *   1. Comptabilisation des permits expirés : dans workforce_permits, les lignes status='active' et expiresAt<=now
 *      passent individuellement en 'expired'. La vérification d'appel (permit-service.verify / activeForRun) refuse déjà immédiatement selon expiresAt,
 *      la comptabilisation ne fait que réécrire dans le registre « le fait déjà survenu » (l'ancien référentiel « expiration non comptabilisée » converge ainsi,
 *      rendu honnête) ; ce service est le seul endroit du dépôt écrivant 'expired' ; pas d'événement émis, exec-hub non touché
 *      (expirer n'est pas révoquer, aucune face de chaînage).
 *   2. Inventaire du registre des runs à état terminal (compter seulement, ne jamais supprimer de ligne) : les tables workforce_* sont des registres d'audit (annexe A décision 7),
 *      même référentiel que les baux « archivage à l'état terminal sans suppression » — les lignes permit/invocation/deliverable liées aux runs terminaux (sondage structuré exec-hub,
 *      status∈{completed,failed,timeout}) ne donnent lieu qu'à un rapport de comptage,
 *      pour que l'exploitation évalue la politique d'archivage, jamais de suppression sur place des faits historiques.
 *
 * Discipline des minuteurs (verrou dur lint-timers, sur la forme de retention de plugin-usage) :
 * premier passage setTimeout à la construction (20 s, hors du chemin chaud d'assemblage) + inspection setInterval + `.unref?.()`
 * + enregistrement de cycle de vie `ctx.effect(clearInterval)`.
 * Commutateur env WORKFORCE_MAINTENANCE_INTERVAL_MS : défaut 6 h=21600000 ; 0=désactive le minuteur, manuel uniquement.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { t } from '../../platform-i18n/src/index.ts'
import type { WorkforceStore } from './contract.ts'

/** Intervalle d'inspection par défaut : 6 heures (même cadence que l'inspection de rétention de usage). */
const DEFAULT_INTERVAL_MS = 6 * 3_600_000
/** Délai du premier passage à la construction (millisecondes) : sur le modèle des 20 s de retention de plugin-usage. */
const FIRST_SWEEP_DELAY_MS = 20_000

/** Forme du sondage structuré de la collection de runs d'exec-hub (absence = capacité d'inventaire manquante, la comptabilisation des expirations n'est pas affectée ; pas d'import inverse). */
interface ExecHubRunsProbe {
  runs?: () => { all(): Array<{ id: string; status: string }> }
}

/** Ensemble complet des états terminaux de run (les trois états de RunStatus d'exec-hub hors running) ; synchronisation littérale, le sondage structuré ne crée pas de dépendance. */
const TERMINAL_RUN_STATUSES = new Set(['completed', 'failed', 'timeout'])

export interface MaintenanceRunResult {
  ranAt: string
  /** Permits passés en 'expired' ce tour (la vérification d'appel les avait déjà refusés immédiatement, la comptabilisation est une réécriture a posteriori). */
  expiredPermits: string[]
  /** Nombre de runs à état terminal (référence de l'inventaire). */
  terminalRunCount: number
  /** Comptage des lignes de registre portées par des runs terminaux (rapport seul, pas de suppression). */
  permitsOnTerminalRuns: number
  invocationsOnTerminalRuns: number
  deliverablesOnTerminalRuns: number
}

export class MaintenanceService extends Service {
  static readonly provide = 'workforceMaintenance'

  /** Intervalle d'inspection (millisecondes) ; 0 = minuteur désactivé, déclenchement manuel admin uniquement. */
  readonly intervalMs: number

  private timer: ReturnType<typeof setInterval> | undefined

  constructor(ctx: Context) {
    super(ctx, 'workforceMaintenance')
    const parsed = Number(process.env.WORKFORCE_MAINTENANCE_INTERVAL_MS ?? DEFAULT_INTERVAL_MS)
    this.intervalMs = Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : DEFAULT_INTERVAL_MS
    const logger = ctx.logger('workforce')
    if (this.intervalMs > 0) {
      logger.info(`workforce 台账巡检：每 ${this.intervalMs}ms（WORKFORCE_MAINTENANCE_INTERVAL_MS，0=停用定时仅手动）`)
      const first = setTimeout(() => void this.sweep(), FIRST_SWEEP_DELAY_MS)
      ctx.effect(() => () => clearTimeout(first))
      this.timer = setInterval(() => void this.sweep(), this.intervalMs)
      this.timer.unref?.() // OPT-P3-02 : la forme intégrée ne suspend pas la boucle d'événements (verrou dur lint-timers)
      ctx.effect(() => () => {
        if (this.timer) clearInterval(this.timer)
      })
    } else {
      logger.info('workforce 台账巡检定时器停用（WORKFORCE_MAINTENANCE_INTERVAL_MS=0），仅 admin 手动触发')
    }
  }

  // -- Dépendances (sondage structuré, pas de dépendance inverse vers exec-hub ; store absent = erreur observable) ------------------

  private get store(): WorkforceStore {
    const store = (this.ctx as unknown as { workforceStore?: WorkforceStore }).workforceStore
    if (!store || typeof store.txn !== 'function') {
      throw new Error(t('workforceStore 未就绪（迁移未完成），台账巡检无法执行'))
    }
    return store
  }

  private execHub(): ExecHubRunsProbe | undefined {
    return (this.ctx as unknown as { execHub?: ExecHubRunsProbe }).execHub
  }

  // -- Corps de l'inspection (le minuteur et l'entrée manuelle admin partagent la même fonction) -----------------------------------------

  run(): MaintenanceRunResult {
    const now = new Date().toISOString()
    // 1. Comptabilisation des permits expirés : unique endroit du dépôt écrivant 'expired' (courte transaction ligne à ligne ; pas d'événement, exec-hub non touché)
    const expiredPermits: string[] = []
    for (const permit of this.store.permits.findWhere({ status: 'active' })) {
      if (!permit.expiresAt || permit.expiresAt > now) continue
      this.store.txn(() => {
        this.store.permits.update(permit.id, { status: 'expired' })
      })
      expiredPermits.push(permit.id)
    }
    // 2. Inventaire du registre des runs terminaux (compter sans supprimer — « archivage à l'état terminal » du registre d'audit, même référentiel que les baux)
    const hub = this.execHub()
    const terminalRunIds = new Set<string>(
      (hub && typeof hub.runs === 'function' ? hub.runs().all() : [])
        .filter((run) => TERMINAL_RUN_STATUSES.has(run.status))
        .map((run) => run.id),
    )
    const onTerminal = (rows: Array<{ runId: string }>): number =>
      rows.filter((row) => row.runId !== '' && terminalRunIds.has(row.runId)).length
    return {
      ranAt: now,
      expiredPermits,
      terminalRunCount: terminalRunIds.size,
      permitsOnTerminalRuns: onTerminal(this.store.permits.all()),
      invocationsOnTerminalRuns: onTerminal(this.store.invocations.all()),
      deliverablesOnTerminalRuns: onTerminal(this.store.deliverables.all()),
    }
  }

  private async sweep(): Promise<void> {
    try {
      const result = this.run()
      this.ctx.logger('workforce').info(
        `workforce 台账巡检：过期 permit 落账 ${result.expiredPermits.length} 条；` +
          `终态 run ${result.terminalRunCount} 个（挂 permit ${result.permitsOnTerminalRuns}/` +
          `invocation ${result.invocationsOnTerminalRuns}/deliverable ${result.deliverablesOnTerminalRuns} 行，封存不删行）`,
      )
    } catch (error) {
      this.ctx.logger('workforce').warn('workforce 台账巡检失败', error)
    }
  }
}
