/**
 * @dsh-ops/plugin-exec-hub — centre d'exécution (objectif 4 « centre de travail » du ybkk-MATRIX, atterrissage R8/R9/R10).
 *
 * Mécanismes portés de l'orchestration Paperclip (wake-queue), taillés pour la forme de la plateforme :
 *   - verrou d'exécution des tâches (E2) : sémantique CAS sur trois champs de la ligne issue (executionRunId / executionAgentKey / executionLockedAt)
 *     — « vérifier-positionner » dans le même segment synchrone, l'atomicité est garantie par le run-to-completion monothread de Node,
 *     décision (fonctions pures de domain) et garde CAS en couches (conception Paperclip d'origine). La libération est une opération par lot au niveau run.
 *   - réveil par battement d'Agent (E3/R9) : file exec:wakes (déduplication par clé idempotente) + boucle de battement 30 s :
 *     budget d'abord → vérification de permissions → barrière d'approbation (P0) → arbitrage trois états prise de verrou/fusion/différé → assemblage du contexte → dispatch du run.
 *     Énumérations d'états alignées sur Paperclip (état différé nommé deferred_issue_execution).
 *   - lignée d'objectifs (E4/R8) : exec:goals (arbre d'objectifs parents supporté) → exec:projects → exec:issues,
 *     goalAncestry matérialisée à l'écriture, l'assemblage de contexte au réveil injecte le « pourquoi on le fait ».
 *   - planification de routines (E7) : trois sources intervalle / cron 5 champs / webhook ; l'endpoint webhook est public mais le chemin sert d'identifiant
 *     (tout chemin non enregistré renvoie 404, sans fuiter son existence).
 *   - cinq couplages de gouvernance (E6) : arrêt dur sur budget (au-delà de la limite : pas de réveil + gel couplé + approbation L4 de dégel), vérification de permissions
 *     (le principal machine de l'Agent doit porter exec.write), traçabilité d'audit (réveil/prise/libération/récupération, chaîne complète type=invoke/change),
 *     annotation de classe de données (le paquet de contexte embarque le plafond dataClass), barrière d'approbation (P0 : approbation exec.issue.run requise avant exécution de tâche).
 *
 * Ligne rouge de gouvernance : le dispatch de réveil n'invente jamais l'exécution — le run n'enregistre que « dispatché + paquet de contexte », l'exécution revient à l'Agent via
 * les outils exec_claim / exec_complete ou un accusé de runtime externe ; un run sans accusé est bouclé par la récupération des verrous zombies.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import type { HttpExchange } from '../../platform-core/src/index.ts'
import { createRestGate, defineTool, PlatformEvents, newId, WORK_DENY_CODE_LABELS, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import type { AuditLogRecord } from '../../plugin-audit/src/index.ts'
import {
  buildIssueContextPack, blockersResolved, computeAgentHealth, cronIsValid, cronMatches,
  decideCompleteOwnership, decideLeaseClaim, decideReleaseRecovery, decideRunAdoption,
  decideWakeAdmission, issueCanTransition, materializeGoalAncestry,
  normalizeAgentKey, wakeIdempotencyKey,
  type AgentHealthLevel, type IssueStatus,
} from './domain.ts'
import { LeaseStoreService, type RunLeaseRecord } from './lease-store.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { seedExecHub } from './seed.ts'

// ---------------------------------------------------------------------------
// Modèle d'enregistrements (collections exec:*)
// ---------------------------------------------------------------------------

export type GoalStatus = 'active' | 'achieved' | 'dropped' | 'archived'

/** Objectif (R8) : arbre d'objectifs parents supporté ; le trio metric fait de « quantifiable » une contrainte de modélisation et non une promesse verbale. */
export interface GoalRecord extends RecordBase {
  orgId: string
  title: string
  description?: string
  metric?: string
  metricBaseline?: number
  metricTarget?: number
  metricUnit?: string
  ownerUserId?: string
  parentGoalId?: string
  periodStart?: string
  periodEnd?: string
  status: GoalStatus
}

export type ProjectStatus = 'active' | 'done' | 'archived'

/** Projet (E4) : couche intermédiaire entre objectif et tâche, porte dépôt de code et documentation. */
export interface ProjectRecord extends RecordBase {
  orgId: string
  goalId?: string
  name: string
  description?: string
  repos: string[]
  ownerUserId?: string
  status: ProjectStatus
}

export type IssuePriority = 'P0' | 'P1' | 'P2' | 'P3'

/**
 * Tâche (E2/E4) : les trois champs du verrou d'exécution alignés sur Paperclip (executionAgentKey = clé de nom normalisée,
 * executionLockedAt = base de la récupération des verrous zombies) ; goalAncestry matérialisée à l'écriture ; checkoutRunId réservé pour un double verrouillage.
 */
export interface IssueRecord extends RecordBase {
  orgId: string
  projectId?: string
  parentId?: string
  blockerIds: string[]
  title: string
  detail?: string
  assigneeAgentId?: string
  assigneeUserId?: string
  status: IssueStatus
  priority: IssuePriority
  dueAt?: string
  executionRunId?: string
  executionAgentKey?: string
  executionLockedAt?: string
  /** Réservé : verrou de checkout (sémantique de double verrou, checkout_run_id de Paperclip), non activé en première version. */
  checkoutRunId?: string
  goalAncestry: string[]
  createdBy: string
}

export type WakeTrigger = 'assign' | 'comment' | 'dependency' | 'routine' | 'api' | 'webhook'
export type WakeStatus = 'pending' | 'deferred_issue_execution' | 'run' | 'failed' | 'cancelled' | 'done'

/** Requête de réveil (E3) : clé idempotente contre la livraison en double (sans elle, des réveils dupliqués brûlent le budget pour rien). */
export interface WakeRecord extends RecordBase {
  orgId: string
  issueId?: string
  agentId?: string
  trigger: WakeTrigger
  triggerDetail?: string
  payload?: Record<string, unknown>
  status: WakeStatus
  idempotencyKey?: string
  budgetCheckPassed?: boolean
  lineageSnapshot?: string[]
  runId?: string
  lastError?: string
  createdAt: string
}

export type RunStatus = 'running' | 'completed' | 'failed' | 'timeout'

/** Run d'exécution : enregistrement d'un dispatch (paquet de contexte inclus) ; complétion/expiration/échec bouclés par accusé de l'Agent ou récupération zombie. */
export interface RunRecord extends RecordBase {
  orgId: string
  agentId?: string
  issueIds: string[]
  trigger: WakeTrigger
  status: RunStatus
  contextPack?: string
  summary?: string
  startedAt: string
  finishedAt?: string
}

export type RoutineKind = 'interval' | 'cron' | 'webhook'

/** Règle de routine (E7) : trois sources — minutes d'intervalle / cron 5 champs / chemin webhook. */
export interface RoutineRecord extends RecordBase {
  orgId: string
  agentId: string
  name: string
  kind: RoutineKind
  intervalMinutes?: number
  cron?: string
  webhookPath?: string
  payload?: Record<string, unknown>
  enabled: boolean
  lastFiredAt?: string
  createdBy: string
}

export type HeartbeatOutcome = 'woken' | 'skipped_no_todo' | 'skipped_budget' | 'skipped_permission' | 'skipped_frozen' | 'skipped_inactive' | 'deferred'

/** Traçabilité des battements (R9) : source des données de santé de l'Agent, conservation glissante de 7 jours. */
export interface HeartbeatRecord extends RecordBase {
  agentId: string
  orgId: string
  at: string
  outcome: HeartbeatOutcome
  detail?: string
  issueCount?: number
}

export interface TickResult {
  processed: number
  woken: number
  deferred: number
  skipped: number
  failed: number
  reclaimed: number
  routineFired: number
  heartbeatDue: number
}

// ---------------------------------------------------------------------------
// Configuration (surchargeable par env ; selftest compresse les TTL pour la déterminisme)
// ---------------------------------------------------------------------------

const TICK_MS = Number(process.env.EXEC_HUB_TICK_MS ?? 30_000)
const FIRST_TICK_MS = Number(process.env.EXEC_HUB_FIRST_TICK_MS ?? Math.min(TICK_MS, 15_000))

/** Les minuteurs ne sont nettoyés qu'au déchargement de l'extension ; c'est la valeur de retour du effect Cordis qui est le disposer. */
export function registerExecTimers(ctx: Pick<Context, 'effect'>, tick: () => void, metrics: () => void, tickMs = TICK_MS, firstMs = FIRST_TICK_MS): void {
  const tickTimer = setInterval(tick, tickMs)
  tickTimer.unref?.()
  const firstTick = setTimeout(tick, firstMs)
  firstTick.unref?.()
  const metricsTimer = setInterval(metrics, 3_600_000)
  metricsTimer.unref?.()
  ctx.effect(() => () => {
    clearInterval(tickTimer)
    clearTimeout(firstTick)
    clearInterval(metricsTimer)
  })
}
const BATCH_SIZE = Number(process.env.EXEC_HUB_BATCH ?? 50)
/** Seuil de verrou zombie : Paperclip conseille environ 2× la période de battement, 5 minutes par défaut. */
const LOCK_TIMEOUT_MS = Number(process.env.EXEC_LOCK_TIMEOUT_MS ?? 300_000)
/** TTL par défaut des baux d'exécution (décision 3 de l'annexe A : exec_run_leases fait autorité ; le runtime doit renewLease avant expiration). */
const DEFAULT_LEASE_TTL_MS = Number(process.env.EXEC_LEASE_TTL_MS ?? 15 * 60_000)
const HEARTBEAT_RETENTION_MS = 7 * 86_400_000
const METRICS_OVERDUE_MS = 24 * 3_600_000

// ---------------------------------------------------------------------------
// Types de retour du port d'intégration exec-hub (le miroir structurel du contract.ts de plugin-workforce
// EmployeeClaimResult / EmployeeLeaseResult, contrat gelé V1.0 — pas d'import pour éviter la boucle,
// structures alignées champ à champ, consommation structurée du groupe 2)
// ---------------------------------------------------------------------------

/** Codes de refus unifiés (référentiel du plan de travail exec-hub ; sous-ensemble homonyme du WorkDenyCode de platform-core). */
export type ExecHubWorkDenyCode =
  | 'ISSUE_NOT_FOUND' | 'ISSUE_CLOSED' | 'LEASE_HELD_BY_OTHER'
  | 'ADMISSION_DENIED' | 'BUDGET_EXCEEDED' | 'APPROVAL_REQUIRED'
  | 'RUN_NOT_OWNED' | 'LEASE_STALE' | 'EXEC_HUB_UNAVAILABLE' | 'POLICY_INTERNAL_ERROR'

/** Résultat de réclamation d'employé (miroir de contract.EmployeeClaimResult). */
export type EmployeeClaimResult =
  | { ok: true; issueId: string; runId: string; lease: RunLeaseRecord; created: boolean }
  | { ok: false; code: ExecHubWorkDenyCode; message: string; holder?: string }

/** Résultat de bail d'employé (miroir de contract.EmployeeLeaseResult). */
export type EmployeeLeaseResult =
  | { ok: true; lease: RunLeaseRecord }
  | { ok: false; code: Extract<ExecHubWorkDenyCode, 'LEASE_STALE' | 'RUN_NOT_OWNED' | 'EXEC_HUB_UNAVAILABLE'>; message: string }

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class ExecutionHubService extends Service {
  static readonly provide = 'execHub'

  /**
   * Stockage d'autorité des baux d'exécution (décision 3 de l'annexe A : exec_run_leases est l'unique autorité, les trois champs d'issue sont une projection).
   * txnStore est assemblé en premier par platform-core (avant exec-hub), la migration/création de table est possible dès la construction.
   */
  readonly leaseStore: LeaseStoreService

  /** Déduplication quotidienne du rappel des rapports gérés (en processus ; un renvoi après redémarrage est acceptable, l'alerte ne vise pas exactement-une-fois). */
  private metricsReminderDayKeys = new Set<string>()
  private tickBusy = false

  constructor(ctx: Context) {
    super(ctx, 'execHub')

    // Stockage de baux d'autorité : création de table idempotente (exec_run_leases ; index issueId+status, runId)
    this.leaseStore = new LeaseStoreService(ctx.txnStore, { ttlMs: DEFAULT_LEASE_TTL_MS })
    this.leaseStore.migrate()

    // Approbation accordée (exec.issue.run) → remise en file des réveils suspendus par la barrière
    ctx.platformBus.on(PlatformEvents.ApprovalDecided, (payload) => {
      try {
        const p = payload as { approvalId?: string }
        if (!p.approvalId) return
        const approval = this.ctx.opsStorage.collection<{ kind?: string; status?: string; payload?: Record<string, unknown>; orgId?: string }>('audit:approvals').get(p.approvalId)
        if (!approval || approval.kind !== 'exec.issue.run' || approval.status !== 'executed') return
        const issueId = String(approval.payload?.['issueId'] ?? '')
        if (!issueId) return
        this.enqueueWake({
          orgId: approval.orgId ?? '', issueId, trigger: 'api',
          triggerDetail: t('P0 审批通过放行'), idempotencyKey: wakeIdempotencyKey('p0-release', [issueId, approval.id]),
        })
      } catch { /* échec du chaînage d'approbation ne bloque pas la chaîne d'événements */ }
    })

    if (process.env.EXEC_HUB_OFF === 'off') return
    // Boucle de battement (lint-timers : double assurance unref + nettoyage par effect)
    const tickTimer = setInterval(() => { void this.safeTick() }, TICK_MS)
    tickTimer.unref?.()
    const firstTick = setTimeout(() => { void this.safeTick() }, FIRST_TICK_MS)
    firstTick.unref?.()
    // Inspection de rappel des rapports gérés : un tour par heure (R9 : rappel automatique si metrics-report > 24 h)
    const metricsTimer = setInterval(() => { void this.remindOverdueMetrics() }, 3_600_000)
    metricsTimer.unref?.()
    // cordis ctx.effect(fn) : fn s'exécute immédiatement à l'enregistrement, c'est la valeur de retour qui est la fonction de nettoyage — une flèche simple tuerait le minuteur sur place (issue #10)
    ctx.effect(() => () => {
      clearInterval(tickTimer)
      clearTimeout(firstTick)
      clearInterval(metricsTimer)
    })
  }

  private async safeTick(): Promise<void> {
    if (this.tickBusy) return
    this.tickBusy = true
    try {
      await this.tick()
    } catch (error) {
      this.ctx.logger('exec-hub').warn(`tick 异常：${error instanceof Error ? error.message : String(error)}`)
    } finally {
      this.tickBusy = false
    }
  }

  // -- Collections -----------------------------------------------------------------

  goals(): Collection<GoalRecord> {
    return this.ctx.opsStorage.collection<GoalRecord>('exec:goals')
  }

  projects(): Collection<ProjectRecord> {
    return this.ctx.opsStorage.collection<ProjectRecord>('exec:projects')
  }

  issues(): Collection<IssueRecord> {
    return this.ctx.opsStorage.collection<IssueRecord>('exec:issues')
  }

  wakes(): Collection<WakeRecord> {
    return this.ctx.opsStorage.collection<WakeRecord>('exec:wakes')
  }

  runs(): Collection<RunRecord> {
    return this.ctx.opsStorage.collection<RunRecord>('exec:runs')
  }

  routines(): Collection<RoutineRecord> {
    return this.ctx.opsStorage.collection<RoutineRecord>('exec:routines')
  }

  heartbeats(): Collection<HeartbeatRecord> {
    return this.ctx.opsStorage.collection<HeartbeatRecord>('exec:heartbeats')
  }

  // -- Lignée organisationnelle (#16, 2026-10-29) ---------------------------------------------

  /**
      * Première organisation racine de la plateforme (sans organisation parente) ; undefined si l'arbre d'organisations n'est pas ensemencé — dernier recours de la chaîne
   * d'héritage par défaut et base de rattachement de la migration des orgId vides préexistants (migrateEmptyExecOrgId).
   */
  rootOrgId(): string | undefined {
    return this.ctx.iam.orgs().all().find((org) => !org.parentId)?.id
  }

  /**
   * Validation du paramètre orgId explicite (#16) : chaîne vide/blancs toujours refusés (contre « chaîne vide en base → lignée organisationnelle rompue »),
   * non vide doit atteindre une organisation réelle ; undefined signifie non fourni, laissé à la chaîne d'héritage (principal → lignée → organisation racine).
   */
  private assertOrgInput(orgId: string | undefined): void {
    if (orgId === undefined) return
    if (!orgId.trim()) throw new Error(t('orgId 不接受空值：缺省请不传（自动继承组织血缘），显式指定请传非空组织 ID'))
    if (!this.ctx.iam.orgs().get(orgId)) throw new Error(t('组织不存在：{id}', { id: orgId }))
  }

  // -- Objectifs (R8) -------------------------------------------------------------

  /** Chaîne d'objectifs (racine→…→objectif courant) ; sans parent = [self] ; troncature défensive en cas de cycle/chaînon manquant. */
  goalChain(goalId?: string): string[] {
    if (!goalId) return []
    const chain: string[] = []
    const seen = new Set<string>()
    let current = this.goals().get(goalId)
    while (current && !seen.has(current.id) && chain.length < 50) {
      seen.add(current.id)
      chain.unshift(current.id)
      current = current.parentGoalId ? this.goals().get(current.parentGoalId) : undefined
    }
    return chain
  }

  createGoal(input: Omit<GoalRecord, 'id' | 'createdAt' | 'updatedAt' | 'status'> & { status?: GoalStatus }): GoalRecord {
    if (!input.title?.trim()) throw new Error(t('目标标题必填'))
    this.assertOrgInput(input.orgId)
    if (input.parentGoalId) {
      const parent = this.goals().get(input.parentGoalId)
      if (!parent) throw new Error(t('父目标不存在：{id}', { id: input.parentGoalId }))
      if (input.parentGoalId === input.id) throw new Error(t('父目标不得指向自己'))
      if (this.goalChain(input.parentGoalId).includes(input.id ?? '')) throw new Error(t('目标父链成环'))
    }
    const record = this.goals().insert({
      id: newId('goal'),
      // #16 : orgId explicite déjà validé ; par défaut repli sur l'organisation racine de la plateforme (la couche REST résout d'abord par principal/lignée)
      orgId: input.orgId ?? this.rootOrgId() ?? '',
      title: input.title.trim(),
      ...(input.description ? { description: input.description } : {}),
      ...(input.metric ? { metric: input.metric } : {}),
      ...(input.metricBaseline !== undefined ? { metricBaseline: input.metricBaseline } : {}),
      ...(input.metricTarget !== undefined ? { metricTarget: input.metricTarget } : {}),
      ...(input.metricUnit ? { metricUnit: input.metricUnit } : {}),
      ...(input.ownerUserId ? { ownerUserId: input.ownerUserId } : {}),
      ...(input.parentGoalId ? { parentGoalId: input.parentGoalId } : {}),
      ...(input.periodStart ? { periodStart: input.periodStart } : {}),
      ...(input.periodEnd ? { periodEnd: input.periodEnd } : {}),
      status: input.status ?? 'active',
    })
    this.ctx.platformBus.emit(PlatformEvents.ExecGoalChanged, { goalId: record.id, action: 'created' })
    return record
  }

  updateGoal(id: string, patch: Partial<GoalRecord>): GoalRecord {
    const goal = this.goals().get(id)
    if (!goal) throw new Error(t('目标不存在：{id}', { id }))
    if (patch.parentGoalId) {
      if (patch.parentGoalId === id) throw new Error(t('父目标不得指向自己'))
      if (!this.goals().get(patch.parentGoalId)) throw new Error(t('父目标不存在：{id}', { id: patch.parentGoalId }))
      if (this.goalChain(patch.parentGoalId).includes(id)) throw new Error(t('目标父链成环'))
    }
    const updated = this.goals().update(id, {
      ...(patch.title !== undefined ? { title: patch.title.trim() || goal.title } : {}),
      ...(patch.parentGoalId !== undefined ? { parentGoalId: patch.parentGoalId || undefined } : {}),
      ...patch,
    })
    this.ctx.platformBus.emit(PlatformEvents.ExecGoalChanged, { goalId: id, action: 'updated' })
    return updated
  }

  deleteGoal(id: string): { deleted: true } {
    const goal = this.goals().get(id)
    if (!goal) throw new Error(t('目标不存在：{id}', { id }))
    if (this.goals().all().some((item) => item.parentGoalId === id)) throw new Error(t('目标下仍有子目标，先迁移或删除子目标'))
    if (this.projects().all().some((item) => item.goalId === id)) throw new Error(t('目标下仍有项目，先迁移或删除项目'))
    this.goals().remove(id)
    this.ctx.platformBus.emit(PlatformEvents.ExecGoalChanged, { goalId: id, action: 'deleted' })
    return { deleted: true }
  }

  // -- Projets (E4) ---------------------------------------------------------------

  createProject(input: Omit<ProjectRecord, 'id' | 'createdAt' | 'updatedAt' | 'status' | 'repos'> & { repos?: string[]; status?: ProjectStatus }): ProjectRecord {
    if (!input.name?.trim()) throw new Error(t('项目名称必填'))
    this.assertOrgInput(input.orgId)
    if (input.goalId && !this.goals().get(input.goalId)) throw new Error(t('关联目标不存在：{id}', { id: input.goalId }))
    const record = this.projects().insert({
      id: newId('proj'),
      // #16 : par défaut, hérite le long de la lignée d'objectifs, puis repli sur l'organisation racine de la plateforme
      orgId: input.orgId ?? this.goals().get(input.goalId ?? '')?.orgId ?? this.rootOrgId() ?? '',
      ...(input.goalId ? { goalId: input.goalId } : {}),
      name: input.name.trim(),
      ...(input.description ? { description: input.description } : {}),
      repos: input.repos ?? [],
      ...(input.ownerUserId ? { ownerUserId: input.ownerUserId } : {}),
      status: input.status ?? 'active',
    })
    this.ctx.platformBus.emit(PlatformEvents.ExecGoalChanged, { projectId: record.id, action: 'project-created' })
    return record
  }

  updateProject(id: string, patch: Partial<ProjectRecord>): ProjectRecord {
    const project = this.projects().get(id)
    if (!project) throw new Error(t('项目不存在：{id}', { id }))
    if (patch.goalId && !this.goals().get(patch.goalId)) throw new Error(t('关联目标不存在：{id}', { id: patch.goalId }))
    const updated = this.projects().update(id, patch)
    // Projet re-rattaché à un autre objectif → re-matérialisation de la lignée des tâches en dessous
    if (patch.goalId !== undefined) {
      for (const issue of this.issues().all().filter((item) => item.projectId === id)) {
        this.rematerialize(issue.id)
      }
    }
    this.ctx.platformBus.emit(PlatformEvents.ExecGoalChanged, { projectId: id, action: 'project-updated' })
    return updated
  }

  deleteProject(id: string): { deleted: true } {
    const project = this.projects().get(id)
    if (!project) throw new Error(t('项目不存在：{id}', { id }))
    if (this.issues().all().some((item) => item.projectId === id)) throw new Error(t('项目下仍有任务，先迁移或删除任务'))
    this.projects().remove(id)
    this.ctx.platformBus.emit(PlatformEvents.ExecGoalChanged, { projectId: id, action: 'project-deleted' })
    return { deleted: true }
  }

  // -- Tâches (E2/E4) -------------------------------------------------------------

  /** Re-matérialisation de lignée : goalAncestry = goalChain(project.goalId) + [projectId]. */
  private rematerialize(issueId: string): void {
    const issue = this.issues().get(issueId)
    if (!issue) return
    const project = issue.projectId ? this.projects().get(issue.projectId) : undefined
    const chain = this.goalChain(project?.goalId)
    const ancestry = materializeGoalAncestry(chain, issue.projectId)
    if (JSON.stringify(ancestry) !== JSON.stringify(issue.goalAncestry)) {
      this.issues().update(issueId, { goalAncestry: ancestry })
    }
  }

  createIssue(input: {
    orgId?: string; projectId?: string; parentId?: string; blockerIds?: string[]
    title: string; detail?: string; assigneeAgentId?: string; assigneeUserId?: string
    priority?: IssuePriority; dueAt?: string; createdBy: string
  }): IssueRecord {
    if (!input.title?.trim()) throw new Error(t('任务标题必填'))
    this.assertOrgInput(input.orgId)
    if (input.projectId && !this.projects().get(input.projectId)) throw new Error(t('项目不存在：{id}', { id: input.projectId }))
    if (input.parentId && !this.issues().get(input.parentId)) throw new Error(t('父任务不存在：{id}', { id: input.parentId }))
    for (const blockerId of input.blockerIds ?? []) {
      if (!this.issues().get(blockerId)) throw new Error(t('前置任务不存在：{id}', { id: blockerId }))
    }
    if (input.assigneeAgentId && !this.agentOf(input.assigneeAgentId)) throw new Error(t('负责人 Agent 不存在：{id}', { id: input.assigneeAgentId }))
    const project = input.projectId ? this.projects().get(input.projectId) : undefined
    // #16 : chaîne d'héritage principal (la couche REST a déjà résolu dans input.orgId) → projet → Agent → organisation racine de la plateforme
    const orgId = input.orgId ?? project?.orgId ?? this.agentOf(input.assigneeAgentId ?? '')?.orgId ?? this.rootOrgId() ?? ''
    const record = this.issues().insert({
      id: newId('iss'),
      orgId,
      ...(input.projectId ? { projectId: input.projectId } : {}),
      ...(input.parentId ? { parentId: input.parentId } : {}),
      blockerIds: input.blockerIds ?? [],
      title: input.title.trim(),
      ...(input.detail ? { detail: input.detail } : {}),
      ...(input.assigneeAgentId ? { assigneeAgentId: input.assigneeAgentId } : {}),
      ...(input.assigneeUserId ? { assigneeUserId: input.assigneeUserId } : {}),
      status: 'todo',
      priority: input.priority ?? 'P2',
      ...(input.dueAt ? { dueAt: input.dueAt } : {}),
      goalAncestry: materializeGoalAncestry(this.goalChain(project?.goalId), input.projectId),
      createdBy: input.createdBy,
    })
    this.ctx.platformBus.emit(PlatformEvents.ExecIssueChanged, { issueId: record.id, action: 'created', status: record.status })
    // Déclencheur de dispatch : assigneeAgentId passe de vide à non vide (table de câblage des sources de déclenchement E7)
    if (record.assigneeAgentId) {
      this.enqueueWake({
        orgId, issueId: record.id, agentId: record.assigneeAgentId, trigger: 'assign',
        idempotencyKey: wakeIdempotencyKey('assign', [record.id, record.assigneeAgentId, record.createdAt.slice(0, 13)]),
      })
    }
    return record
  }

  updateIssue(id: string, patch: Partial<IssueRecord>, actor: string): IssueRecord {
    const issue = this.issues().get(id)
    if (!issue) throw new Error(t('任务不存在：{id}', { id }))
    if (patch.projectId && !this.projects().get(patch.projectId)) throw new Error(t('项目不存在：{id}', { id: patch.projectId }))
    if (patch.assigneeAgentId && !this.agentOf(patch.assigneeAgentId)) throw new Error(t('负责人 Agent 不存在：{id}', { id: patch.assigneeAgentId }))
    for (const blockerId of patch.blockerIds ?? []) {
      if (!this.issues().get(blockerId)) throw new Error(t('前置任务不存在：{id}', { id: blockerId }))
      if (blockerId === id) throw new Error(t('前置任务不得指向自己'))
    }
    const updated = this.issues().update(id, { ...patch })
    this.rematerialize(id)
    // Changement d'Agent / nouvel Agent rattaché → dispatch d'un réveil (clé idempotente avec seau temporel, un PATCH répété ne réveille pas deux fois)
    const newAssignee = updated.assigneeAgentId
    if (newAssignee && newAssignee !== issue.assigneeAgentId) {
      this.enqueueWake({
        orgId: updated.orgId, issueId: id, agentId: newAssignee, trigger: 'assign',
        triggerDetail: t('改派（{actor}）', { actor }),
        idempotencyKey: wakeIdempotencyKey('assign', [id, newAssignee, new Date().toISOString().slice(0, 13)]),
      })
    }
    this.ctx.platformBus.emit(PlatformEvents.ExecIssueChanged, { issueId: id, action: 'updated', status: updated.status })
    return this.issues().get(id) ?? updated
  }

  transitionIssue(id: string, to: IssueStatus, actor: string): IssueRecord {
    const issue = this.issues().get(id)
    if (!issue) throw new Error(t('任务不存在：{id}', { id }))
    if (!issueCanTransition(issue.status, to)) {
      throw new Error(t('任务状态 {from} 不允许流转到 {to}', { from: issue.status, to }))
    }
    if (to === 'done' && issue.executionRunId) {
      // Sémantique de clôture : avant l'état terminal, on clôt d'abord le run (libération du verrou + run terminé), pas de verrou suspendu
      this.completeRun(issue.executionRunId, { status: 'completed', summary: t('任务完成收尾（{actor}）', { actor }) })
    }
    if (to === 'cancelled' && issue.executionRunId) {
      this.completeRun(issue.executionRunId, { status: 'failed', summary: t('任务取消收尾（{actor}）', { actor }) })
    }
    const updated = this.issues().update(id, { status: to })
    this.ctx.platformBus.emit(PlatformEvents.ExecIssueChanged, { issueId: id, action: 'transition', status: to })
    // Déclencheur de levée de dépendance : blocker en état terminal, les tâches aval entièrement libérées entrent en file de réveil dependency (table de câblage E7)
    if (to === 'done' || to === 'cancelled') this.wakeUnblockedDependents(id)
    return updated
  }

  /** Scanne les tâches ayant issueId comme prérequis : tous leurs blockers en état terminal → mise en file d'un réveil dependency. */
  private wakeUnblockedDependents(issueId: string): void {
    for (const dependent of this.issues().all().filter((item) => item.blockerIds.includes(issueId))) {
      const statuses = dependent.blockerIds.map((bid) => this.issues().get(bid)?.status ?? 'todo')
      if (!blockersResolved(statuses as IssueStatus[])) continue
      if (!dependent.assigneeAgentId) continue
      this.enqueueWake({
        orgId: dependent.orgId, issueId: dependent.id, agentId: dependent.assigneeAgentId,
        trigger: 'dependency', triggerDetail: t('前置 {issueId} 已解除', { issueId }),
        idempotencyKey: wakeIdempotencyKey('dep', [dependent.id, issueId]),
      })
    }
  }

  deleteIssue(id: string): { deleted: true } {
    const issue = this.issues().get(id)
    if (!issue) throw new Error(t('任务不存在：{id}', { id }))
    if (issue.executionRunId) throw new Error(t('任务执行中（持有执行锁），先完成或取消'))
    if (this.issues().all().some((item) => item.parentId === id)) throw new Error(t('任务下仍有子任务'))
    this.issues().remove(id)
    this.ctx.platformBus.emit(PlatformEvents.ExecIssueChanged, { issueId: id, action: 'deleted' })
    return { deleted: true }
  }

  // -- Verrou d'exécution (E2 : sémantique CAS, vérifier-positionner dans le même segment synchrone = atomique en Node) -------------------

  /**
   * Prise de verrou par projection (CAS sur les trois champs d'issue). Depuis la décision 3 de l'annexe A, cette méthode ne maintient que la projection, l'arbitrage de détention fait
   * autorité sur exec_run_leases ; sémantique des deux gardes (D05/D06 réclamation idempotente) :
   *   - reprise répétée du même runId = ok (rafraîchit agentKey/horodatage de battement, pas de conflit signalé) ;
   *   - projection pointant un run terminal/disparu (au référentiel du bail d'autorité, personne ne détient) → considéré reprenable, écrasement direct.
   */
  acquireLock(issueId: string, runId: string, agentKey: string): { ok: true } | { ok: false; reason: 'no_issue' | 'locked_by_other'; holder?: string } {
    const issue = this.issues().get(issueId)
    if (!issue) return { ok: false, reason: 'no_issue' }
    if (issue.executionRunId === runId) {
      this.issues().update(issueId, { executionAgentKey: agentKey, executionLockedAt: new Date().toISOString() })
      return { ok: true }
    }
    if (issue.executionRunId) {
      const holder = this.runs().get(issue.executionRunId)
      if (holder && holder.status === 'running') return { ok: false, reason: 'locked_by_other', holder: issue.executionRunId }
    }
    this.issues().update(issueId, {
      executionRunId: runId,
      executionAgentKey: agentKey,
      executionLockedAt: new Date().toISOString(),
    })
    return { ok: true }
  }

  /** Libération par lots au niveau run (sémantique Paperclip : libère toutes les issues tenues selon executionRunId, contre les fuites par libération partielle). */
  releaseLocks(runId: string): number {
    let released = 0
    for (const issue of this.issues().all().filter((item) => item.executionRunId === runId)) {
      this.issues().update(issue.id, { executionRunId: undefined, executionAgentKey: undefined, executionLockedAt: undefined })
      released += 1
      this.ctx.platformBus.emit(PlatformEvents.ExecIssueChanged, { issueId: issue.id, action: 'lock-released' })
    }
    return released
  }

  /**
   * Récupération des verrous zombies (approche active-run-watchdog de Paperclip) : quand l'âge du verrou dépasse le seuil, arbitrage par
   * decideReleaseRecovery — run disparu/terminal = libération forte directe ; run toujours running = d'abord noter timeout puis libération forte.
   */
  reclaimZombieLocks(nowMs = Date.now()): number {
    let reclaimed = 0
    for (const issue of this.issues().all().filter((item) => item.executionRunId && item.executionLockedAt)) {
      const lockAge = nowMs - new Date(issue.executionLockedAt!).getTime()
      if (lockAge < LOCK_TIMEOUT_MS) continue
      const run = this.runs().get(issue.executionRunId!)
      const decision = decideReleaseRecovery({
        runMissing: !run,
        runSettled: Boolean(run && run.status !== 'running'),
        lockTimedOut: true,
      })
      if (decision.kind === 'keep') continue
      if (decision.kind === 'timeout-run' && run) {
        this.runs().update(run.id, { status: 'timeout', finishedAt: new Date().toISOString(), summary: t('执行锁超时（{seconds}s）自动回收', { seconds: Math.round(lockAge / 1000) }) })
      }
      const holderRun = issue.executionRunId!
      this.issues().update(issue.id, { executionRunId: undefined, executionAgentKey: undefined, executionLockedAt: undefined })
      // Clôture synchronisée bail et projection : le bail d'autorité correspondant à la projection zombie est aussi libéré (contre la détention fantôme dans le TTL)
      this.releaseLeasesSafe(holderRun, `zombie-reclaim:${decision.kind}`)
      reclaimed += 1
      this.auditSafe({
        type: 'change', actorType: 'machine', actorId: 'exec-hub', actorName: '执行中枢',
        action: 'exec.lock.reclaimed', resourceType: 'issue', resourceId: issue.id, resourceName: issue.title,
        result: 'ok', detail: `run=${holderRun} 锁龄 ${Math.round(lockAge / 1000)}s（${decision.kind}）`,
      })
      this.ctx.platformBus.emit(PlatformEvents.ExecLockReclaimed, { issueId: issue.id, runId: holderRun, reason: decision.kind })
    }
    return reclaimed
  }

  // -- run ------------------------------------------------------------------

  private createRun(input: { orgId: string; agentId?: string; issueIds: string[]; trigger: WakeTrigger; contextPack?: string }): RunRecord {
    return this.runs().insert({
      id: newId('run'),
      orgId: input.orgId,
      ...(input.agentId ? { agentId: input.agentId } : {}),
      issueIds: input.issueIds,
      trigger: input.trigger,
      status: 'running',
      ...(input.contextPack ? { contextPack: input.contextPack } : {}),
      startedAt: new Date().toISOString(),
    })
  }

  /**
   * Clôture du run : état terminal + libération verrous et baux au niveau run + les tâches in_progress retournées en revue (review).
   *
   * Note de compatibilité : à ce jour, la destination des tâches est review (« livrable soumis, acceptation par une personne », §6.5) ; les appelants existants
   * (clôture de transitionIssue, etc.) gardent leur comportement ; seul exec_complete passant explicitement
   * failedIssueDisposition='todo' fait passer les tâches en cours du run échoué en retour à faire (todo) en attente de réaffectation
   * (mise à jour directe, même traitement que review — todo permet au planificateur de réveiller, sans occuper la file d'acceptation review).
   */
  completeRun(runId: string, options: { status?: RunStatus; summary?: string; failedIssueDisposition?: 'review' | 'todo' } = {}): RunRecord {
    const run = this.runs().get(runId)
    if (!run) throw new Error(t('run 不存在：{id}', { id: runId }))
    if (run.status !== 'running') return run
    const updated = this.runs().update(runId, {
      status: options.status ?? 'completed',
      finishedAt: new Date().toISOString(),
      ...(options.summary ? { summary: options.summary } : {}),
    })
    this.releaseLocks(runId)
    // Le bail est libéré à l'état terminal du run (clôture du stockage d'autorité ; la projection a déjà été nettoyée par releaseLocks)
    this.releaseLeasesSafe(runId, `run-${updated.status}`)
    const failedToTodo = updated.status !== 'completed' && options.failedIssueDisposition === 'todo'
    for (const issueId of run.issueIds) {
      const issue = this.issues().get(issueId)
      if (issue && issue.status === 'in_progress') this.issues().update(issueId, { status: failedToTodo ? 'todo' : 'review' })
    }
    this.auditSafe({
      type: 'invoke', actorType: 'machine', actorId: 'exec-hub', actorName: '执行中枢',
      action: 'exec.run.completed', resourceType: 'run', resourceId: runId,
      resourceName: run.agentId ?? '', result: 'ok',
      detail: `issues=${run.issueIds.length} status=${updated.status}${options.summary ? `（${options.summary}）` : ''}`,
    })
    this.ctx.platformBus.emit(PlatformEvents.ExecRunCompleted, {
      runId, agentId: run.agentId, issueIds: run.issueIds, status: updated.status,
    })
    return updated
  }

  // -- Port d'intégration du travail des employés (ExecHubWorkIntegration, décision 3 de l'annexe A/§6.2) ----------------
  //
  // Consommation structurée par plugin-workforce (groupe 2) : réclamer = « confirmation idempotente d'un bail déjà attribué » —
  // admission unifiée (gel/budget/permissions/P0, mêmes fonctions sources que processWake, pas de contournement) → get-or-create run
  // (V05 : le run au verrou préempté par l'ordonnanceur est directement adopté à la réclamation, pas de création superflue) → prise atomique du bail dans exec_run_leases
  // (autorité) → projection issue écrite intégralement (compatibilité du statu quo). Cette extension n'importe pas plugin-workforce (§10.2).

  /** Réclamation idempotente d'employé : réclamer deux fois le même employé+même tâche renvoie le run/bail existant (created=false). */
  async claimForEmployee(input: { issueId: string; employeeId: string; agentKey: string; principalId: string; ttlMs?: number }): Promise<EmployeeClaimResult> {
    try {
      if (!input.issueId) return { ok: false, code: 'ISSUE_NOT_FOUND', message: t('任务 ID 必填') }
      if (!input.employeeId || !input.principalId) {
        return { ok: false, code: 'ADMISSION_DENIED', message: t('认领参数不足：employeeId 与 principalId 必填（fail-closed）') }
      }
      const issue = this.issues().get(input.issueId)
      if (!issue) return { ok: false, code: 'ISSUE_NOT_FOUND', message: t('任务不存在：{id}', { id: input.issueId }) }
      if (issue.status === 'done' || issue.status === 'cancelled') {
        return { ok: false, code: 'ISSUE_CLOSED', message: t('任务已{state}关闭，不可认领', { state: issue.status === 'done' ? t('完成') : t('取消') }) }
      }
      // Normalisation de l'agentKey : paramètre d'entrée en priorité, sinon employee:<id>
      const agentKey = input.agentKey?.trim() ? normalizeAgentKey(input.agentKey) : `employee:${input.employeeId}`
      // L'admission unifiée s'exécute (gel/budget/permissions/P0 — réutilise les mêmes fonctions sources que processWake, D06 sans contournement)
      const admission = this.admitAgentForClaim(issue, agentKey)
      if (!admission.ok) return { ok: false, code: admission.code, message: admission.message }
      const ttlMs = input.ttlMs && input.ttlMs > 0 ? input.ttlMs : DEFAULT_LEASE_TTL_MS
      // Arbitrage d'idempotence (fonctions pures de domain) d'abord : même détenteur avec bail valide → renouvellement et réutilisation du run existant, pas de création
      const existing = this.leaseStore.activeForIssue(issue.id)
      if (existing) {
        const decision = decideLeaseClaim({
          activeLeasePresent: true,
          activeLeaseExpired: false,
          existingEmployeeId: existing.employeeId,
          existingAgentKey: existing.agentKey,
          requestedEmployeeId: input.employeeId,
          requestedAgentKey: agentKey,
        })
        if (decision.kind === 'idempotent') {
          const renewed = this.leaseStore.renew({ leaseId: existing.id, ttlMs })
          const lease = renewed.ok ? renewed.lease : existing
          this.writeExecutionProjection(issue.id, lease.runId, agentKey)
          this.ensureIssueInProgress(issue)
          return { ok: true, issueId: issue.id, runId: lease.runId, lease, created: false }
        }
        if (decision.kind === 'held-by-other') {
          return { ok: false, code: 'LEASE_HELD_BY_OTHER', message: t('任务执行租约由 {holder} 持有，不可重复认领', { holder: decision.holder }), holder: decision.holder }
        }
      }
      // get-or-create run (V05/D05 : un run en cours au verrou préempté par le réveil est directement adopté ; seule une projection sale fait créer)
      const agentId = this.resolveAgentIdForIssue(issue, agentKey)
      const projectedRun = issue.executionRunId ? this.runs().get(issue.executionRunId) : undefined
      const adoption = decideRunAdoption({
        projectedRunIdPresent: Boolean(issue.executionRunId),
        projectedRunRunning: Boolean(projectedRun && projectedRun.status === 'running'),
      })
      let runId: string
      if (adoption.kind === 'adopt' && issue.executionRunId) {
        runId = issue.executionRunId
        if (projectedRun && !projectedRun.issueIds.includes(issue.id)) {
          this.runs().update(runId, { issueIds: [...projectedRun.issueIds, issue.id] })
        }
      } else {
        const agent = agentId ? this.agentOf(agentId) : undefined
        runId = this.createRun({
          orgId: issue.orgId, ...(agentId ? { agentId } : {}), issueIds: [issue.id], trigger: 'api',
          contextPack: this.buildIssueContext(issue, agent ?? {}),
        }).id
      }
      // Prise atomique du bail (CAS d'autorité ; échec de concurrence mappé en détenu par autrui)
      const acquired = this.leaseStore.acquire({ issueId: issue.id, runId, employeeId: input.employeeId, agentKey, principalId: input.principalId, ttlMs })
      if (!acquired.ok) {
        return { ok: false, code: 'LEASE_HELD_BY_OTHER', message: t('任务执行租约由 {holder} 持有，不可重复认领', { holder: acquired.holder }), holder: acquired.holder }
      }
      // Projection écrite intégralement (décision 3 de l'annexe A : l'autorité est dans exec_run_leases, la projection maintient la compatibilité du statu quo)
      const cas = this.acquireLock(issue.id, runId, agentKey)
      if (!cas.ok && cas.reason === 'locked_by_other') {
        // Projection résiduelle pointant le run en cours d'un autre (projection sale de période de migration) : le bail d'autorité fait foi et écrase la projection
        this.writeExecutionProjection(issue.id, runId, agentKey)
      }
      this.ensureIssueInProgress(issue)
      this.ctx.platformBus.emit(PlatformEvents.ExecIssueChanged, { issueId: issue.id, action: 'claimed', status: 'in_progress', runId, employeeId: input.employeeId })
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: `employee:${input.employeeId}`, actorName: agentKey,
        action: 'exec.work.claimed', resourceType: 'issue', resourceId: issue.id, resourceName: issue.title,
        result: 'ok', detail: `run=${runId} lease=${acquired.lease.id} v${acquired.lease.leaseVersion}${acquired.created ? '' : '（幂等续期）'}`,
      })
      return { ok: true, issueId: issue.id, runId, lease: acquired.lease, created: acquired.created }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return { ok: false, code: 'EXEC_HUB_UNAVAILABLE', message: t('执行中枢认领失败：{message}', { message }) }
    }
  }

  /** Renouvellement/battement de progression : même principal, actif, non expiré pour renouveler (sinon LEASE_STALE). */
  async renewLease(input: { runId: string; principalId: string; ttlMs?: number }): Promise<EmployeeLeaseResult> {
    try {
      if (!input.runId || !input.principalId) {
        return { ok: false, code: 'LEASE_STALE', message: t('续租参数不足：runId 与 principalId 必填（fail-closed）') }
      }
      const renewed = this.leaseStore.renew({ runId: input.runId, principalId: input.principalId, ttlMs: input.ttlMs })
      if (!renewed.ok) return { ok: false, code: 'LEASE_STALE', message: renewed.message }
      return { ok: true, lease: renewed.lease }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return { ok: false, code: 'EXEC_HUB_UNAVAILABLE', message: t('执行中枢续租失败：{message}', { message }) }
    }
  }

  /** Validation de propriété principal/run pour exec_complete (D07) : refus entre employés ou bail périmé (référentiel port resserré : sans enregistrement de bail, refus aussi). */
  async assertRunOwnership(input: { runId: string; principalId: string }): Promise<{ ok: true; lease: RunLeaseRecord } | { ok: false; code: ExecHubWorkDenyCode; message: string }> {
    try {
      if (!input.runId || !input.principalId) {
        return { ok: false, code: 'RUN_NOT_OWNED', message: t('所有权校验参数不足：runId 与 principalId 必填（fail-closed）') }
      }
      const lease = this.leaseStore.latestForRun(input.runId)
      const decision = decideCompleteOwnership({
        hasLeaseRecord: Boolean(lease),
        status: lease?.status ?? 'released',
        expired: lease ? new Date(lease.expiresAt).getTime() <= Date.now() : true,
        callerPrincipalId: input.principalId,
        leasePrincipalId: lease?.principalId ?? '',
      })
      if (decision.kind === 'deny') return { ok: false, code: decision.code, message: decision.reason }
      if (!lease) return { ok: false, code: 'RUN_NOT_OWNED', message: t('该 run 无有效执行租约，不归属当前调用主体') }
      return { ok: true, lease }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return { ok: false, code: 'EXEC_HUB_UNAVAILABLE', message: t('执行中枢所有权校验失败：{message}', { message }) }
    }
  }

  /** Couplage suspension/retrait : libère les baux d'autorité par run et nettoie la projection issue (sans changer l'état métier du run). */
  releaseForRun(runId: string, reason: string): void {
    if (!runId) return
    const released = this.leaseStore.release(runId, reason || 'released')
    this.releaseLocks(runId)
    if (released > 0) {
      this.auditSafe({
        type: 'change', actorType: 'machine', actorId: 'exec-hub', actorName: '执行中枢',
        action: 'exec.work.lease_released', resourceType: 'run', resourceId: runId,
        result: 'ok', detail: `leases=${released} reason=${reason || 'released'}`,
      })
    }
  }

  /** Admission unifiée (D06) : gel/budget/permissions (quand l'Agent est résoluble) + barrière d'approbation P0 (toujours vérifiée au niveau tâche). Réutilise les mêmes fonctions sources que processWake. */
  private admitAgentForClaim(issue: IssueRecord, agentKey: string): { ok: true } | { ok: false; code: 'ADMISSION_DENIED' | 'BUDGET_EXCEEDED' | 'APPROVAL_REQUIRED'; message: string } {
    const agentId = this.resolveAgentIdForIssue(issue, agentKey)
    const agent = agentId ? this.agentOf(agentId) : undefined
    if (agent) {
      if (this.isAgentFrozen(agent.id)) {
        return { ok: false, code: 'ADMISSION_DENIED', message: t('Agent 已冻结（预算超限联动），待解冻审批：{name}', { name: agent.name }) }
      }
      const budgetGate = this.checkAgentBudget(agent.id, agent.orgId)
      if (budgetGate.blocked) return { ok: false, code: 'BUDGET_EXCEEDED', message: t('预算熔断：{reason}', { reason: budgetGate.reason ?? t('预算已超限') }) }
      const scopes = this.agentScopes(agent.id)
      if (scopes === null || !(scopes.includes('exec.write') || scopes.includes('*'))) {
        return { ok: false, code: 'ADMISSION_DENIED', message: t('Agent 机器主体无 exec.write 权限（身份未纳管或权限收敛）') }
      }
    }
    if (issue.priority === 'P0' && !this.p0ApprovalPassed(issue.id)) {
      return { ok: false, code: 'APPROVAL_REQUIRED', message: t('P0 任务需先通过 exec.issue.run 审批（已自动挂单，等待放行）') }
    }
    return { ok: true }
  }

  /** Contrôle de gel (point de réutilisation : même source que l'admission de processWake et de la réclamation d'employé). */
  private isAgentFrozen(agentId: string): boolean {
    try {
      return Boolean(this.ctx.agentRegistry && typeof this.ctx.agentRegistry.isFrozen === 'function' && this.ctx.agentRegistry.isFrozen(agentId))
    } catch {
      return false
    }
  }

  /** Résolution d'Agent pour l'admission à la réclamation : d'abord le responsable de la tâche, sinon correspondance par agentKey (égalité d'id / nom normalisé). */
  private resolveAgentIdForIssue(issue: IssueRecord, agentKey: string): string | undefined {
    if (issue.assigneeAgentId && this.agentOf(issue.assigneeAgentId)) return issue.assigneeAgentId
    const normalized = normalizeAgentKey(agentKey)
    if (normalized) {
      const byId = this.agentOf(normalized)
      if (byId) return byId.id
      const byName = this.ctx.resourceCore.list('agent').find((candidate) => normalizeAgentKey(candidate.name) === normalized)
      if (byName) return byName.id
    }
    return issue.assigneeAgentId || undefined
  }

  /** Écriture intégrale de la projection (décision 3 de l'annexe A : l'autorité est dans exec_run_leases, les trois champs rétrogradés en projection). */
  private writeExecutionProjection(issueId: string, runId: string, agentKey: string): void {
    this.issues().update(issueId, {
      executionRunId: runId,
      executionAgentKey: agentKey,
      executionLockedAt: new Date().toISOString(),
    })
  }

  /** Entrée d'écriture de projection côté outils (réutilisée par la branche idempotente d'exec_claim ; fine enveloppe publique). */
  writeClaimProjectionForTool(issueId: string, runId: string, agentKey: string): void {
    this.writeExecutionProjection(issueId, runId, agentKey)
  }

  /** Progression de tâche en cours (partagé réclamation/réveil : todo → in_progress). */
  private ensureIssueInProgress(issue: IssueRecord): void {
    if (issue.status === 'todo') this.issues().update(issue.id, { status: 'in_progress' })
  }

  /** Enveloppe de sécurité pour la libération de bail (une exception côté bail ne bloque pas la chaîne principale de clôture du run). */
  private releaseLeasesSafe(runId: string, reason: string): void {
    try {
      this.leaseStore.release(runId, reason)
    } catch (error) {
      this.ctx.logger('exec-hub').warn(`租约释放异常（run=${runId} reason=${reason}）：${error instanceof Error ? error.message : String(error)}`)
    }
  }

  // -- File de réveils (E3) -------------------------------------------------------------

  enqueueWake(input: {
    orgId: string; issueId?: string; agentId?: string; trigger: WakeTrigger
    triggerDetail?: string; payload?: Record<string, unknown>; idempotencyKey?: string
  }): WakeRecord {
    // Déduplication par clé idempotente : une livraison répétée pendant pending / deferred_issue_execution renvoie directement la fiche existante
    if (input.idempotencyKey) {
      const existing = this.wakes().findOne((item) =>
        item.idempotencyKey === input.idempotencyKey
        && (item.status === 'pending' || item.status === 'deferred_issue_execution'))
      if (existing) return existing
    }
    const issue = input.issueId ? this.issues().get(input.issueId) : undefined
    const record = this.wakes().insert({
      id: newId('wake'),
      orgId: input.orgId || issue?.orgId || '',
      ...(input.issueId ? { issueId: input.issueId } : {}),
      ...(input.agentId ? { agentId: input.agentId } : {}),
      trigger: input.trigger,
      ...(input.triggerDetail ? { triggerDetail: input.triggerDetail } : {}),
      ...(input.payload ? { payload: input.payload } : {}),
      status: 'pending',
      ...(input.idempotencyKey ? { idempotencyKey: input.idempotencyKey } : {}),
      ...(issue?.goalAncestry ? { lineageSnapshot: issue.goalAncestry } : {}),
      createdAt: new Date().toISOString(),
    })
    this.ctx.platformBus.emit(PlatformEvents.ExecWakeEnqueued, {
      wakeId: record.id, trigger: record.trigger, issueId: record.issueId, agentId: record.agentId,
    })
    return record
  }

  // -- Boucle de battement (E3/R9) ----------------------------------------------------------

  async tick(): Promise<TickResult> {
    const result: TickResult = { processed: 0, woken: 0, deferred: 0, skipped: 0, failed: 0, reclaimed: 0, routineFired: 0, heartbeatDue: 0 }
    // 1. Récupération des verrous zombies
    result.reclaimed = this.reclaimZombieLocks()
    // 2. Règles de routine échues → mise en file de réveils routine
    result.routineFired = this.fireDueRoutines()
    // 3. Battements échus (Agents en marche ayant configuré heartbeatIntervalMinutes) → mise en file de réveils routine
    result.heartbeatDue = this.enqueueDueHeartbeats()
    // 4. Traitement des réveils pending + deferred (FIFO, plafond par lot)
    const batch = this.wakes().all()
      .filter((item) => item.status === 'pending' || item.status === 'deferred_issue_execution')
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .slice(0, BATCH_SIZE)
    for (const wake of batch) {
      result.processed += 1
      const outcome = this.processWake(wake.id)
      if (outcome === 'woken') result.woken += 1
      else if (outcome === 'deferred') result.deferred += 1
      else if (outcome === 'failed') result.failed += 1
      else result.skipped += 1
    }
    // 5. Conservation glissante de 7 jours de la traçabilité des battements
    const cutoff = new Date(Date.now() - HEARTBEAT_RETENTION_MS).toISOString()
    for (const stale of this.heartbeats().all().filter((item) => item.at < cutoff)) this.heartbeats().remove(stale.id)
    return result
  }

  /** Jugement d'échéance des règles de routine (intervalle atteint / minute cron correspondante et ≥60 s depuis la dernière / webhook mis en file à la volée par l'endpoint). */
  private fireDueRoutines(nowMs = Date.now()): number {
    let fired = 0
    const now = new Date()
    for (const routine of this.routines().all().filter((item) => item.enabled)) {
      if (!routine.agentId || !this.agentOf(routine.agentId)) continue
      let due = false
      if (routine.kind === 'interval' && (routine.intervalMinutes ?? 0) > 0) {
        const last = routine.lastFiredAt ? new Date(routine.lastFiredAt).getTime() : 0
        due = nowMs - last >= routine.intervalMinutes! * 60_000
      } else if (routine.kind === 'cron' && routine.cron && cronIsValid(routine.cron)) {
        const last = routine.lastFiredAt ? new Date(routine.lastFiredAt).getTime() : 0
        due = cronMatches(routine.cron, now) && nowMs - last >= 60_000
      }
      if (!due) continue
      this.routines().update(routine.id, { lastFiredAt: new Date().toISOString() })
      this.enqueueWake({
        orgId: routine.orgId, agentId: routine.agentId, trigger: 'routine',
        triggerDetail: t('{name}（{kind}）', { name: routine.name, kind: routine.kind }),
        ...(routine.payload ? { payload: routine.payload } : {}),
        idempotencyKey: wakeIdempotencyKey('routine', [routine.id, Math.floor(nowMs / 60_000)]),
      })
      fired += 1
    }
    return fired
  }

  /** Battement échu (R9) : en marche + intervalle configuré + ≥ intervalle depuis le dernier réveil → mise en file d'un réveil de battement. */
  private enqueueDueHeartbeats(nowMs = Date.now()): number {
    let due = 0
    for (const agent of this.listRunnableAgents()) {
      const interval = Number(agent.attrs['heartbeatIntervalMinutes'] ?? 0)
      if (!(interval > 0)) continue
      const lastHeartbeat = this.heartbeats().all()
        .filter((item) => item.agentId === agent.id)
        .sort((a, b) => b.at.localeCompare(a.at))[0]
      const lastMs = lastHeartbeat ? new Date(lastHeartbeat.at).getTime() : 0
      if (nowMs - lastMs < interval * 60_000) continue
      this.enqueueWake({
        orgId: agent.orgId ?? '', agentId: agent.id, trigger: 'routine',
        triggerDetail: `heartbeat:${interval}m`,
        idempotencyKey: wakeIdempotencyKey('hb', [agent.id, Math.floor(nowMs / (interval * 60_000))]),
      })
      due += 1
    }
    return due
  }

  private listRunnableAgents() {
    return this.ctx.resourceCore.list('agent').filter((agent) => agent.status === 'online' || agent.status === 'trial')
  }

  private agentOf(agentId: string) {
    return agentId ? this.ctx.resourceCore.collection('agent').get(agentId) : undefined
  }

  /**
   * Traitement d'un réveil isolé (ordre des cinq couplages de gouvernance : budget d'abord → contrôle de gel → vérification de permissions → barrière d'approbation → prise de verrou/fusion/différé).
   * Renvoie la classification du résultat (pour les compteurs du tick) ; le CAS est bouclé dans un segment synchrone complet, sans await intercalé.
   */
  private processWake(wakeId: string): 'woken' | 'deferred' | 'failed' | 'skipped' {
    const wake = this.wakes().get(wakeId)
    if (!wake) return 'skipped'
    const issue = wake.issueId ? this.issues().get(wake.issueId) : undefined
    if (wake.issueId && !issue) {
      this.wakes().update(wakeId, { status: 'cancelled', lastError: t('任务已删除') })
      return 'skipped'
    }
    if (issue && (issue.status === 'done' || issue.status === 'cancelled')) {
      this.wakes().update(wakeId, { status: 'cancelled', lastError: t('任务已{state}', { state: issue.status === 'done' ? t('完成') : t('取消') }) })
      return 'skipped'
    }
    const agentId = wake.agentId ?? issue?.assigneeAgentId ?? ''
    const agent = this.agentOf(agentId)
    if (!agent) {
      this.wakes().update(wakeId, { status: 'failed', lastError: t('负责人 Agent 不存在或未指定') })
      return 'failed'
    }
    if (agent.status !== 'online' && agent.status !== 'trial') {
      this.recordHeartbeat(agent, 'skipped_inactive', `状态 ${agent.status}`)
      this.wakes().update(wakeId, { status: 'failed', lastError: t('Agent 非运行态（{status}）', { status: agent.status }) })
      return 'failed'
    }

    // Couplage ① : contrôle de gel (R10 : après gel pour dépassement de budget, plus de réveil jusqu'à exécution de l'approbation de dégel ; même source que l'admission de réclamation d'employé isAgentFrozen)
    if (this.isAgentFrozen(agentId)) {
      this.recordHeartbeat(agent, 'skipped_frozen', wake.trigger)
      this.wakes().update(wakeId, { status: 'failed', lastError: t('Agent 已冻结（预算超限联动），待解冻审批') })
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: 'exec-hub', actorName: '执行中枢',
        action: 'exec.wakeup.frozen_skipped', resourceType: 'agent', resourceId: agentId,
        resourceName: agent.name, result: 'denied', detail: `wake=${wakeId} trigger=${wake.trigger}`,
      })
      return 'failed'
    }

    // Couplage ② : budget d'abord (E6 — valeur ajoutée propre à la plateforme : au-delà de la limite, pas de réveil du tout, plutôt qu'une comptabilisation et une alerte a posteriori)
    const budgetGate = this.checkAgentBudget(agentId, agent.orgId)
    if (budgetGate.blocked) {
      this.wakes().update(wakeId, { status: 'failed', budgetCheckPassed: false, lastError: t('预算熔断：{reason}', { reason: budgetGate.reason ?? '' }) })
      this.recordHeartbeat(agent, 'skipped_budget', budgetGate.reason)
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: 'exec-hub', actorName: '执行中枢',
        action: 'exec.wakeup.budget_denied', resourceType: 'agent', resourceId: agentId,
        resourceName: agent.name, result: 'denied', detail: `wake=${wakeId} ${budgetGate.reason}`,
      })
      // Gel couplé au dépassement (R10) : quand le budget marque freezeAgent, gèle l'Agent et génère une approbation L4 de dégel (réutilise l'infrastructure d'approbation, double confirmation native)
      if (budgetGate.freezeAgent && this.ctx.agentRegistry && typeof this.ctx.agentRegistry.freezeAgent === 'function' && !this.ctx.agentRegistry.isFrozen(agentId)) {
        try {
          this.ctx.agentRegistry.freezeAgent(agentId, t('执行中枢预算前置熔断：{reason}', { reason: budgetGate.reason ?? '' }), 'exec-hub')
        } catch (error) {
          this.ctx.logger('exec-hub').warn(`联动冻结失败：${error instanceof Error ? error.message : String(error)}`)
        }
      }
      return 'failed'
    }
    this.wakes().update(wakeId, { budgetCheckPassed: true })

    // Couplage ③ : vérification de permissions (découplage #7 : le battement de survie n'exige que exec.read — les rôles en lecture seule comme évaluateur/acceptant participent aussi au battement ;
    // exec.write est vérifié séparément sur le vrai chemin d'écriture (création de run / dispatch d'exécution), voir couplage ③b ci-dessous)
    const scopes = this.agentScopes(agentId)
    if (scopes === null || !(scopes.includes('exec.read') || scopes.includes('*'))) {
      this.wakes().update(wakeId, { status: 'failed', lastError: t('Agent 机器主体无 exec.read 权限（身份未纳管或权限收敛），存活监测无法成立') })
      this.recordHeartbeat(agent, 'skipped_permission', 'exec.read 缺失')
      this.auditSafe({
        type: 'authz', actorType: 'machine', actorId: `agent:${agentId}`, actorName: agent.name,
        action: 'exec.wakeup', resourceType: 'issue', resourceId: issue?.id ?? agentId,
        resourceName: issue?.title ?? agent.name, result: 'denied',
        detail: `机器主体缺少 exec.read（wake=${wakeId}）`,
      })
      this.ctx.platformBus.emit('audit.authz.denied', {
        actorId: agentId, actorName: agent.name, point: 'exec.read', path: `exec:wake:${wakeId}`,
      })
      return 'failed'
    }

    // Réveil de battement au niveau Agent (sans issue) : tirage des tâches à faire → s'il y en a, dispatch (contexte = liste des tâches), sinon saut
    if (!issue) {
      const todos = this.collectTodos(agent)
      if (todos.total === 0) {
        this.recordHeartbeat(agent, 'skipped_no_todo')
        this.wakes().update(wakeId, { status: 'done' })
        return 'skipped'
      }
      // Rôle en lecture seule avec tâches à faire : le battement est établi (survie), mais pas de dispatch — clôture non-erreur, sans noter status=failed (#7)
      if (!(scopes.includes('exec.write') || scopes.includes('*'))) {
        this.recordHeartbeat(agent, 'skipped_permission', t('{n} 项待办未派发（只读主体，缺 exec.write）', { n: todos.total }))
        this.wakes().update(wakeId, { status: 'done' })
        return 'skipped'
      }
      const pack = this.buildAgentTodoPack(agent, todos)
      const run = this.createRun({ orgId: agent.orgId ?? '', agentId, issueIds: [], trigger: wake.trigger, contextPack: pack })
      this.wakes().update(wakeId, { status: 'run', runId: run.id })
      this.recordHeartbeat(agent, 'woken', `${todos.total} 项待办`, todos.total)
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: 'exec-hub', actorName: '执行中枢',
        action: 'exec.wakeup.dispatched', resourceType: 'agent', resourceId: agentId,
        resourceName: agent.name, result: 'ok', detail: `run=${run.id} trigger=${wake.trigger} 待办=${todos.total}`,
      })
      return 'woken'
    }

    // Couplage ③b : le chemin d'exécution de tâche exige exec.write (#7 : après découplage permission d'écriture et battement de survie, resserrage sur le vrai chemin d'écriture)
    if (!(scopes.includes('exec.write') || scopes.includes('*'))) {
      this.wakes().update(wakeId, { status: 'failed', lastError: t('Agent 机器主体无 exec.write 权限（身份未纳管或权限收敛）') })
      this.recordHeartbeat(agent, 'skipped_permission', 'exec.write 缺失')
      this.auditSafe({
        type: 'authz', actorType: 'machine', actorId: `agent:${agentId}`, actorName: agent.name,
        action: 'exec.wakeup', resourceType: 'issue', resourceId: issue.id,
        resourceName: issue.title, result: 'denied',
        detail: `机器主体缺少 exec.write（wake=${wakeId}）`,
      })
      this.ctx.platformBus.emit('audit.authz.denied', {
        actorId: agentId, actorName: agent.name, point: 'exec.write', path: `exec:wake:${wakeId}`,
      })
      return 'failed'
    }

    // Couplage ④ : barrière d'approbation (P0 = tâche haut risque : approbation exec.issue.run à l'état executed requise avant exécution)
    if (issue.priority === 'P0' && !this.p0ApprovalPassed(issue.id)) {
      const deferred = this.wakes().update(wakeId, { status: 'deferred_issue_execution', lastError: t('P0 任务待审批放行') })
      this.recordHeartbeat(agent, 'deferred', `P0 审批 ${issue.id}`)
      return deferred ? 'deferred' : 'failed'
    }

    // Arbitrage trois états (décision = fonction pure de domain ; CAS = garde ci-dessous)
    const decision = decideWakeAdmission({
      isSameExecutionAgent: issue.executionAgentKey === normalizeAgentKey(agent.name),
      shouldDeferFollowupWake: false,
      shouldQueueFollowupForRunningWake: false,
      availableActiveExecutionRunPresent: Boolean(issue.executionRunId),
    })
    if (decision.kind === 'defer') {
      this.wakes().update(wakeId, { status: 'deferred_issue_execution', lastError: t('执行锁由 {runId} 持有', { runId: issue.executionRunId ?? '' }) })
      return 'deferred'
    }
    const agentKey = normalizeAgentKey(agent.name)
    let runId: string
    if (decision.kind === 'coalesce') {
      runId = issue.executionRunId!
    } else {
      const run = this.createRun({
        orgId: issue.orgId, agentId, issueIds: [issue.id], trigger: wake.trigger,
        contextPack: this.buildIssueContext(issue, agent),
      })
      runId = run.id
    }
    // Garde CAS : sous concurrence, un seul gagne (la couche de décision n'en dépend pas, elle ne fait que prévenir la double prise de verrou)
    const acquired = this.acquireLock(issue.id, runId, agentKey)
    if (!acquired.ok) {
      this.wakes().update(wakeId, { status: 'deferred_issue_execution', lastError: t('取锁竞争失败（{holder} 持有）', { holder: acquired.holder ?? '' }) })
      return 'deferred'
    }
    if (decision.kind === 'coalesce') {
      const run = this.runs().get(runId)
      if (run && !run.issueIds.includes(issue.id)) this.runs().update(runId, { issueIds: [...run.issueIds, issue.id] })
    }
    if (issue.status === 'todo') this.issues().update(issue.id, { status: 'in_progress' })
    this.wakes().update(wakeId, { status: 'run', runId })
    this.ctx.platformBus.emit(PlatformEvents.ExecIssueChanged, { issueId: issue.id, action: 'dispatched', status: 'in_progress', runId })
    this.auditSafe({
      type: 'invoke', actorType: 'machine', actorId: 'exec-hub', actorName: '执行中枢',
      action: 'exec.wakeup.dispatched', resourceType: 'issue', resourceId: issue.id,
      resourceName: issue.title, result: 'ok',
      detail: `run=${runId} trigger=${wake.trigger} 决策=${decision.kind} agent=${agent.name}`,
    })
    return 'woken'
  }

  /** Scopes effectifs du principal machine de l'Agent (principal absent/désactivé = null, fail-closed). */
  private agentScopes(agentId: string): string[] | null {
    try {
      const principal = this.ctx.authn.principals().findOne((item) =>
        item.type === 'machine' && item.refType === 'agent' && item.refId === agentId && item.status !== 'disabled')
      if (!principal) return null
      return this.ctx.authn.resolveMachineScopes(principal)
    } catch {
      return null
    }
  }

  /**
   * Contrôle préalable de budget (couplage ② de E6) : lit le budget du sujet Agent côté modelgw (méthode de contrat du groupe B
   * budgetStatusForSubject). Méthode absente (ancien modelgw) = passage — l'enforceBudget à l'instant de l'invoke
   * reste une barrière dure ; méthode présente mais jetant une erreur = fail-closed, refus du dispatch.
   */
  private checkAgentBudget(agentId: string, orgId?: string): { blocked: boolean; reason?: string; freezeAgent?: boolean } {
    const modelGateway = this.ctx.modelGateway as unknown as {
      budgetStatusForSubject?: (subject: string, orgId?: string) => Array<{
        budget: { action?: string; freezeAgent?: boolean; subject?: string }
        daily: { breached?: boolean } | null
        monthly: { breached?: boolean } | null
      }>
    }
    if (typeof modelGateway?.budgetStatusForSubject !== 'function') return { blocked: false }
    let statuses: ReturnType<NonNullable<typeof modelGateway.budgetStatusForSubject>>
    try {
      statuses = modelGateway.budgetStatusForSubject(`agent:${agentId}`, orgId)
    } catch (error) {
      return { blocked: true, reason: t('预算检查失败（fail-closed）：{message}', { message: error instanceof Error ? error.message : String(error) }) }
    }
    for (const item of statuses ?? []) {
      const breached = item.daily?.breached || item.monthly?.breached
      if (breached && item.budget.action === 'block') {
        return {
          blocked: true, freezeAgent: item.budget.freezeAgent === true,
          reason: t('Agent 主体预算（{subject}）已超限，action=block', { subject: item.budget.subject ?? '' }),
        }
      }
    }
    return { blocked: false }
  }

  /** Barrière d'approbation P0 : sans approbation exec.issue.run à l'état executed, ouverture automatique d'une fiche (idempotent : pending/executed existant = pas de nouvelle fiche). */
  private p0ApprovalPassed(issueId: string): boolean {
    const approvals = this.ctx.opsStorage.collection<{ kind?: string; status?: string; payload?: Record<string, unknown>; orgId?: string }>('audit:approvals')
    const related = approvals.all().filter((item) =>
      item.kind === 'exec.issue.run' && String(item.payload?.['issueId'] ?? '') === issueId)
    if (related.some((item) => item.status === 'executed')) return true
    if (related.some((item) => item.status === 'pending')) return false
    const issue = this.issues().get(issueId)
    try {
      this.ctx.audit.createApproval({
        kind: 'exec.issue.run',
        title: t('P0 任务执行审批：「{title}」', { title: issue?.title ?? issueId }),
        riskLevel: 'high',
        payload: { issueId, title: issue?.title ?? '' },
        ...(issue?.orgId ? { orgId: issue.orgId } : {}),
      })
    } catch { /* face d'approbation absente : la barrière maintient l'interception (fail-closed), le ticket en attente est retenté au prochain tick */ }
    return false
  }

  private recordHeartbeat(agent: { id: string; name: string; orgId?: string }, outcome: HeartbeatOutcome, detail?: string, issueCount?: number): void {
    try {
      this.heartbeats().insert({
        id: newId('hb'), agentId: agent.id, orgId: agent.orgId ?? '',
        at: new Date().toISOString(), outcome, ...(detail ? { detail } : {}),
        ...(issueCount !== undefined ? { issueCount } : {}),
      })
      this.ctx.platformBus.emit(PlatformEvents.ExecHeartbeatRecorded, { agentId: agent.id, outcome })
    } catch { /* échec de traçabilité n'interrompt pas l'ordonnancement */ }
  }

  // -- Tirage des tâches à faire et assemblage de contexte (R9 + E4) --------------------------------------------

  /** Trois sources des tâches à faire de l'Agent : tâches exec (todo) + tâches du panneau départemental (todo/doing) + étapes Agent du flux de dossiers (pending/running). */
  collectTodos(agent: { id: string; name: string }): { total: number; issues: number; panelTasks: number; flowSteps: number } {
    const issues = this.issues().all().filter((item) => item.assigneeAgentId === agent.id && item.status === 'todo').length
    let panelTasks = 0
    try {
      panelTasks = this.ctx.opsStorage.collection<{ assigneeType?: string; assigneeName?: string; lane?: string }>('panel:tasks')
        .all().filter((item) => item.assigneeType === 'agent' && item.assigneeName === agent.name
          && (item.lane === 'todo' || item.lane === 'doing')).length
    } catch { /* collection du panneau absente (forme autonome) : comptée 0 */ }
    let flowSteps = 0
    try {
      for (const flow of this.ctx.flow.flows().all().filter((item) => item.status === 'running')) {
        flowSteps += flow.steps.filter((step) => step.actorType === 'agent' && step.assignee === agent.name
          && (step.status === 'pending' || step.status === 'running')).length
      }
    } catch { /* service de flux transactionnel absent : compté 0 */ }
    return { total: issues + panelTasks + flowSteps, issues, panelTasks, flowSteps }
  }

  private buildIssueContext(issue: IssueRecord, agent: { attrs?: Record<string, unknown> }): string {
    const ancestry = issue.goalAncestry ?? []
    const titles: Record<string, string> = {}
    for (const id of ancestry) {
      const goal = this.goals().get(id)
      if (goal) {
        titles[id] = goal.metric
          ? `${goal.title}（指标：${goal.metricBaseline ?? '—'} → ${goal.metricTarget ?? '—'} ${goal.metricUnit ?? ''}）`.trim()
          : goal.title
        continue
      }
      const project = this.projects().get(id)
      if (project) titles[id] = project.name
    }
    const project = issue.projectId ? this.projects().get(issue.projectId) : undefined
    const blockers = (issue.blockerIds ?? [])
      .map((bid) => this.issues().get(bid)?.title ?? bid)
    return buildIssueContextPack({
      goalTitle: ancestry.length > 0 ? titles[ancestry[ancestry.length - (project ? 2 : 1)] ?? ''] ?? undefined : undefined,
      goalMetric: undefined,
      projectNames: project ? [project.name] : [],
      issueTitle: issue.title,
      blockerTitles: blockers,
      dataClass: typeof agent.attrs?.['dataClass'] === 'string' ? String(agent.attrs['dataClass']) : undefined,
      permissionNote: '你被授予执行权（exec.write）；执行前请通过 exec_claim 取锁，完成后 exec_complete 交回',
    })
  }

  private buildAgentTodoPack(agent: { id: string; name: string; attrs?: Record<string, unknown> }, todos: { total: number; issues: number; panelTasks: number; flowSteps: number }): string {
    const lines = [
      '【例行唤醒】',
      `你有 ${todos.total} 项待办：执行任务 ${todos.issues}、面板任务 ${todos.panelTasks}、事务流步骤 ${todos.flowSteps}。`,
      '请依次认领（exec_claim）并完成后交回（exec_complete）。',
      '',
      '【可用范围】',
      typeof agent.attrs?.['dataClass'] === 'string' ? `可访问数据密级上限：${String(agent.attrs['dataClass'])}` : '',
    ]
    return lines.filter((line) => line !== '').join('\n')
  }

  /** Vue de lignée de tâche (E5 : partagée par l'outil exec_lineage et le tiroir de détail). */
  issueLineage(issueId: string): {
    issue?: IssueRecord
    goal?: GoalRecord
    project?: ProjectRecord
    ancestry: Array<{ id: string; kind: 'goal' | 'project'; title: string }>
    blockers: Array<{ id: string; title: string; status?: IssueStatus }>
  } {
    const issue = this.issues().get(issueId)
    if (!issue) throw new Error(t('任务不存在：{id}', { id: issueId }))
    const project = issue.projectId ? this.projects().get(issue.projectId) : undefined
    const goal = project?.goalId ? this.goals().get(project.goalId) : undefined
    const ancestry = (issue.goalAncestry ?? []).map((id) => {
      const g = this.goals().get(id)
      if (g) return { id, kind: 'goal' as const, title: g.title }
      const p = this.projects().get(id)
      return { id, kind: 'project' as const, title: p?.name ?? id }
    })
    const blockers = (issue.blockerIds ?? []).map((bid) => {
      const blocker = this.issues().get(bid)
      return { id: bid, title: blocker?.title ?? bid, status: blocker?.status }
    })
    return { issue, goal, project, ancestry, blockers }
  }

  // -- Santé et vue d'ensemble (R9) -----------------------------------------------------------

  agentsHealth(): Array<{
    agentId: string; name: string; status: string; orgRole?: string; rank?: string
    frozen: boolean; lastHeartbeatAt?: string; lastMetricsReportAt?: string
    health: AgentHealthLevel
  }> {
    const nowMs = Date.now()
    return this.ctx.resourceCore.list('agent').map((agent) => {
      const lastHeartbeat = this.heartbeats().all()
        // Les refus de permission, budget, gel, etc. ne prouvent pas un battement valide et ne peuvent rafraîchir un échec en santé.
        .filter((item) => item.agentId === agent.id && (item.outcome === 'woken' || item.outcome === 'skipped_no_todo'))
        .sort((a, b) => b.at.localeCompare(a.at))[0]
      let lastMetrics: { updatedAt: string } | undefined
      try {
        lastMetrics = this.ctx.agentRegistry.usage().all()
          .filter((item) => item.agentId === agent.id)
          .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0]
      } catch { /* collection usage absente : traité comme sans rapport */ }
      const frozen = (() => {
        try {
          return Boolean(this.ctx.agentRegistry.isFrozen?.(agent.id))
        } catch {
          return false
        }
      })()
      return {
        agentId: agent.id,
        name: agent.name,
        status: agent.status,
        orgRole: typeof agent.attrs?.['orgRole'] === 'string' ? String(agent.attrs['orgRole']) : undefined,
        rank: typeof agent.attrs?.['rank'] === 'string' ? String(agent.attrs['rank']) : undefined,
        frozen,
        lastHeartbeatAt: lastHeartbeat?.at,
        lastMetricsReportAt: lastMetrics?.updatedAt,
        health: computeAgentHealth({
          agentStatus: agent.status,
          frozen,
          lastHeartbeatAt: lastHeartbeat ? new Date(lastHeartbeat.at).getTime() : null,
          lastMetricsReportAt: lastMetrics ? new Date(lastMetrics.updatedAt).getTime() : null,
          nowMs,
          heartbeatIntervalMinutes: Number(agent.attrs?.['heartbeatIntervalMinutes'] ?? 0) || undefined,
        }),
      }
    })
  }

  overview(): Record<string, unknown> {
    const issues = this.issues().all()
    const issuesByStatus: Record<string, number> = {}
    for (const issue of issues) issuesByStatus[issue.status] = (issuesByStatus[issue.status] ?? 0) + 1
    const nowIso = new Date(Date.now() - LOCK_TIMEOUT_MS).toISOString()
    return {
      goals: this.goals().all().length,
      projects: this.projects().all().length,
      issuesByStatus,
      pendingWakes: this.wakes().all().filter((item) => item.status === 'pending').length,
      deferredWakes: this.wakes().all().filter((item) => item.status === 'deferred_issue_execution').length,
      activeRuns: this.runs().all().filter((item) => item.status === 'running').length,
      lockedIssues: issues.filter((item) => item.executionRunId).length,
      zombieLocks: issues.filter((item) => item.executionRunId && item.executionLockedAt && item.executionLockedAt < nowIso).length,
      agentsHealth: this.agentsHealth(),
    }
  }

  /**
   * Agrégat cockpit de l'espace de travail (spécification d'adaptation de conception 5.1, 2026-10-14, lecture seule additive) :
   * GET /api/exec/overview incorpore de façon incrémentale le résultat de cette méthode au-dessus des champs de l'overview() existant (anciens champs intouchés).
   *
   * Référentiel des champs (tous dérivés de données réelles, aucun discours codé en dur) :
   *   - insight.text : conclusion réelle assemblée depuis « atteinte des objectifs (part achieved + taux d'achèvement des tâches liées) + gradation des alertes non lues
   *     + appels/consommation du jour » ; objectifs et alertes tous deux absents = libellé de référentiel zéro donnée.
   *   - insight.exceptions : alertes non lues (critical/warning) + état disjoncteur MCP + dépassement de budget de modèle —
   *     {name, level, chain, owner}, owner résolu au mieux vers le responsable de l'actif, chaîne vide si irrésoluble.
   *   - kpis.assets : comptage par seau de cycle de vie unifié des six classes d'actifs (mcp/agent/app/skill/model/nas)
   *     (online inclut gray/trial/published/deprecated encore au registre).
   *   - kpis.callsToday/tokensToday/costToday : agrégats réels de la fenêtre du jour de usage (jour UTC).
   *   - kpis.risk : comptage des alertes non lues critical/warning (info non compté).
   */
  cockpit(): { insight: { text: string; exceptions: Array<{ name: string; level: 'critical' | 'warning'; chain: string; owner: string }> }; kpis: { assets: { total: number; online: number; draft: number; deprecated: number }; callsToday: number; tokensToday: number; costToday: number; risk: { critical: number; warning: number } } } {
    // -- Usage du jour (jour UTC, aligné sur le référentiel de fenêtre budgetStatus de modelgw) ----------------
    const todayStart = `${new Date().toISOString().slice(0, 10)}T00:00:00.000Z`
    let callsToday = 0
    let tokensToday = 0
    let costToday = 0
    try {
      const summary = this.ctx.usage.summary({ from: todayStart, to: new Date().toISOString() })
      callsToday = summary.byResource.reduce((sum, row) => sum + row.events, 0)
      tokensToday = summary.input_tokens + summary.output_tokens
      costToday = summary.cost_cents
    } catch { /* face usage absente (forme hôte autonome) : rendue à zéro, ne bloque pas la vue d'ensemble */ }

    // -- Comptage unifié des six classes d'actifs (même cartographie de cycle de vie que le /api/fleet/ledger de plugin-console) --
    const buckets = { total: 0, online: 0, draft: 0, deprecated: 0 }
    const countAsset = (status: string, deprecated = false): void => {
      buckets.total++
      if (deprecated || ['online', 'gray', 'trial', 'published', 'unhealthy'].includes(status)) buckets.online++
      else if (['draft', 'verifying', 'pending_approval', 'scanning'].includes(status)) buckets.draft++
      if (deprecated) buckets.deprecated++
    }
    const ownerNameOf = (userId: string): string => {
      try {
        return this.ctx.iam.users().get(userId)?.displayName ?? userId
      } catch {
        return userId
      }
    }
    const mcpServices = (() => {
      try { return this.ctx.mcpRegistry.services().all() } catch { return [] }
    })()
    const skills = (() => {
      try { return this.ctx.skillHub.skills().all() } catch { return [] }
    })()
    const apps = (() => {
      try { return this.ctx.resourceCore.list('app') } catch { return [] }
    })()
    const nasList = (() => {
      try { return this.ctx.nasRegistry.list() } catch { return [] }
    })()
    const models = (() => {
      try { return this.ctx.modelGateway.models().all() } catch { return [] }
    })()
    for (const service of mcpServices) countAsset(service.status)
    for (const agent of this.ctx.resourceCore.list('agent')) countAsset(agent.status)
    for (const app of apps) countAsset(app.status)
    for (const skill of skills) countAsset(skill.status, skill.status === 'deprecated')
    for (const model of models) countAsset(model.status)
    for (const nas of nasList) countAsset(nas.status)

    // -- Face anomalies : alertes non lues + disjoncteur MCP + budget de modèle dépassé (états réels, sans invention) ------------
    const exceptions: Array<{ name: string; level: 'critical' | 'warning'; chain: string; owner: string }> = []
    let critical = 0
    let warning = 0
    try {
      for (const alert of this.ctx.audit.alerts().find((item) => !item.read)) {
        if (alert.severity === 'critical') critical++
        else if (alert.severity === 'warning') warning++
        else continue
        if (exceptions.length >= 8) continue
        const owner = alert.resourceType === 'mcp_service' || alert.resourceType === 'mcp'
          ? mcpServices.find((item) => item.id === alert.resourceId)?.owner ?? ''
          : alert.resourceType === 'agent'
            ? ownerNameOf(this.ctx.resourceCore.collection('agent').get(alert.resourceId ?? '')?.ownerId ?? '')
            : ''
        exceptions.push({ name: alert.title, level: alert.severity as 'critical' | 'warning', chain: `${alert.ruleId ?? 'ad-hoc'}${alert.resourceType ? ` → ${alert.resourceType}:${alert.resourceId ?? ''}` : ''}`, owner })
      }
    } catch { /* face d'audit absente : traité comme sans alerte */ }
    for (const service of mcpServices) {
      if (!service.health.breakerOpen) continue
      critical++
      if (exceptions.length < 8) exceptions.push({ name: t('MCP 熔断：{name}', { name: service.name }), level: 'critical', chain: `mcp:${service.slug}`, owner: service.owner })
    }
    for (const model of models) {
      if (model.status === 'online' && model.endpoint.trim() === '') {
        warning++
        if (exceptions.length < 8) exceptions.push({ name: t('模型路由已上线但未配置 endpoint：{name}', { name: model.displayName }), level: 'warning', chain: `model:${model.slug}`, owner: model.provider })
      }
    }

    // -- Atteinte des objectifs (part achieved + taux d'achèvement des tâches liées — dérivation réelle) ------------------
    const goals = this.goals().all()
    const issues = this.issues().all()
    const activeGoals = goals.filter((goal) => goal.status === 'active')
    const achieved = goals.filter((goal) => goal.status === 'achieved').length
    const doneIssues = issues.filter((issue) => issue.status === 'done').length
    const goalCompletion = goals.length > 0 ? Math.round((achieved / goals.length) * 100) : null
    const issueCompletion = issues.length > 0 ? Math.round((doneIssues / issues.length) * 100) : null

    // -- Libellé d'aperçu : assemblé exclusivement des chiffres réels ci-dessus (scénarios codés en dur interdits) -------------------
    const bits: string[] = []
    if (goals.length > 0) {
      bits.push(t('目标 {total} 项（进行中 {active}、已达成 {achieved}，达成率 {rate}%）', { total: goals.length, active: activeGoals.length, achieved, rate: goalCompletion }))
      if (issues.length > 0) bits.push(t('关联任务完成率 {rate}%（{done}/{total}）', { rate: issueCompletion, done: doneIssues, total: issues.length }))
    } else {
      bits.push(t('尚无登记目标——可在执行中枢创建季度目标并拆解行动项目'))
    }
    if (critical > 0) bits.push(t('存在 {count} 项严重告警需立即处理', { count: critical }))
    else if (warning > 0) bits.push(t('存在 {count} 项一般告警建议关注', { count: warning }))
    else bits.push(t('当前无未读告警'))
    bits.push(t('今日已计量调用 {calls} 次、tokens {tokens}、内部成本参考 {cost} 分', { calls: callsToday, tokens: tokensToday.toLocaleString('en-US'), cost: costToday }))

    return {
      insight: { text: bits.join('；') + '。', exceptions },
      kpis: { assets: buckets, callsToday, tokensToday, costToday, risk: { critical, warning } },
    }
  }

  /** Rappel des rapports gérés (R9) : un Agent en marche sans rapport depuis > 24 h → alerte de rappel (déduplication quotidienne). */
  private async remindOverdueMetrics(): Promise<void> {
    const dayKey = new Date().toISOString().slice(0, 10)
    for (const agent of this.listRunnableAgents()) {
      const key = `${agent.id}:${dayKey}`
      if (this.metricsReminderDayKeys.has(key)) continue
      let last: { updatedAt: string } | undefined
      try {
        last = this.ctx.agentRegistry.usage().all()
          .filter((item) => item.agentId === agent.id)
          .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0]
      } catch { continue }
      const lastMs = last ? new Date(last.updatedAt).getTime() : 0
      if (lastMs !== 0 && Date.now() - lastMs < METRICS_OVERDUE_MS) continue
      this.metricsReminderDayKeys.add(key)
      this.ctx.audit?.fire?.({
        severity: 'warning',
        title: t('Agent「{name}」纳管指标超 24h 未提报', { name: agent.name }),
        message: t('执行中枢催办：请调用 POST /api/agents/:id/metrics-report 提报 dau/sessions，超期未报将影响健康度评估与预算窗口。'),
        resourceType: 'agent',
        resourceId: agent.id,
      })
    }
  }

  /** Traçabilité d'audit (absence d'audit = repli silencieux — même défense que softRead de dsh-bridge). */
  private auditSafe(entry: Omit<AuditLogRecord, 'id' | 'createdAt' | 'updatedAt'>): void {
    try {
      this.ctx.audit?.record(entry)
    } catch { /* dégradation indépendante du plan d'audit */ }
  }
}

// ---------------------------------------------------------------------------
// REST + outils + assemblage (/api/exec/* : guarded auto-enregistré, l'authentification dépend du middleware console en amont)
// ---------------------------------------------------------------------------

export function apply(ctx: Context) {
  const hub = new ExecutionHubService(ctx)
  const http = ctx.httpServer
  const { caller, guarded, body, actorOf } = createRestGate(ctx)

  const changeLog = (exchange: HttpExchange, action: string, resourceName: string, detail = ''): void => {
    const info = caller(exchange)
    try {
      ctx.audit?.record({
        type: 'change', actorType: info.kind === 'human' ? 'human' : 'machine',
        actorId: info.userId ?? info.principalId, actorName: info.name,
        action, resourceType: 'exec', resourceId: exchange.params['id'] ?? '', resourceName, result: 'ok', detail,
      })
    } catch { /* dégradation indépendante du plan d'audit */ }
  }

  // #16 (2026-10-29) : resserrage de la lignée organisationnelle du domaine exec — chaîne vide explicite = 400 ; par défaut hérite de l'organisation du principal appelant
  // (unified.orgId retrouvé par le middleware d'authentification console selon le rattachement utilisateur/Agent), puis repli le long de la lignée (objectif/projet/Agent),
  // enfin organisation racine de la plateforme ; arbre d'organisations non ensemencé = '' (cohérent avec le repli seedExecHub, la fonction de migration complète idempotemment).
  const principalOrgId = (exchange: HttpExchange): string => {
    const unified = (exchange.principal as { unified?: { orgId?: string } } | undefined)?.unified
    return typeof unified?.orgId === 'string' ? unified.orgId : ''
  }
  const resolveOrgId = (exchange: HttpExchange, explicit: string | undefined, lineage: Array<string | undefined> = []): string => {
    if (explicit !== undefined) {
      const trimmed = explicit.trim()
      if (!trimmed) throw new Error(t('orgId 不接受空值：缺省请不传（自动继承组织血缘），显式指定请传非空组织 ID'))
      if (!ctx.iam.orgs().get(trimmed)) throw new Error(t('组织不存在：{id}', { id: trimmed }))
      return trimmed
    }
    return [principalOrgId(exchange), ...lineage].find((item) => item) ?? hub.rootOrgId() ?? ''
  }

  // -- Vue d'ensemble / santé (R9) ------------------------------------------------------
  // Adaptation de conception (2026-10-14) : incorporation incrémentale de l'agrégat cockpit de l'espace de travail (insight/kpis) — champs existants conservés tels quels,
  // les anciens consommateurs du front (page exec/outils) non affectés ; cockpit() est une méthode de lecture seule.
  guarded('GET', '/api/exec/overview', 'exec.read', () => ({ ...hub.overview(), ...hub.cockpit() }))

  // -- Objectifs (R8) ---------------------------------------------------------------
  guarded('GET', '/api/exec/goals', 'exec.read', (exchange) => {
    // #16 : filtre ?orgId= (plan de données des tableaux de bord par périmètre organisationnel/imputation des coûts)
    const orgId = exchange.query.get('orgId') ?? ''
    return { goals: hub.goals().all().filter((item) => !orgId || item.orgId === orgId) }
  })

  guarded('POST', '/api/exec/goals', 'exec.write', (exchange) => {
    const input = body<{ orgId?: string; title: string; description?: string; metric?: string; metricBaseline?: number; metricTarget?: number; metricUnit?: string; ownerUserId?: string; parentGoalId?: string; periodStart?: string; periodEnd?: string }>(exchange)
    const created = hub.createGoal({ ...input, orgId: resolveOrgId(exchange, input.orgId) })
    changeLog(exchange, 'exec.goal.create', created.title)
    return created
  })

  guarded('PATCH', '/api/exec/goals/:id', 'exec.write', (exchange) => {
    const input = body<{ title?: string; description?: string; metric?: string; metricBaseline?: number; metricTarget?: number; metricUnit?: string; ownerUserId?: string; parentGoalId?: string; periodStart?: string; periodEnd?: string; status?: GoalStatus }>(exchange)
    const updated = hub.updateGoal(exchange.params['id']!, input)
    changeLog(exchange, 'exec.goal.update', updated.title)
    return updated
  })

  guarded('DELETE', '/api/exec/goals/:id', 'exec.write', (exchange) => {
    const result = hub.deleteGoal(exchange.params['id']!)
    changeLog(exchange, 'exec.goal.delete', exchange.params['id'] ?? '')
    return result
  })

  // -- Projets (E4) -----------------------------------------------------------------
  guarded('GET', '/api/exec/projects', 'exec.read', (exchange) => {
    const issues = hub.issues().all()
    // #16 : filtre ?orgId=
    const orgId = exchange.query.get('orgId') ?? ''
    return {
      projects: hub.projects().all()
        .filter((project) => !orgId || project.orgId === orgId)
        .map((project) => {
          const projectIssues = issues.filter((item) => item.projectId === project.id)
          return {
            ...project,
            issueProgress: { done: projectIssues.filter((item) => item.status === 'done').length, total: projectIssues.length },
          }
        }),
    }
  })

  guarded('POST', '/api/exec/projects', 'exec.write', (exchange) => {
    const input = body<{ orgId?: string; goalId?: string; name: string; description?: string; repos?: string[]; ownerUserId?: string }>(exchange)
    const goal = input.goalId ? hub.goals().get(input.goalId) : undefined
    const created = hub.createProject({ ...input, orgId: resolveOrgId(exchange, input.orgId, [goal?.orgId]) })
    changeLog(exchange, 'exec.project.create', created.name)
    return created
  })

  guarded('PATCH', '/api/exec/projects/:id', 'exec.write', (exchange) => {
    const input = body<{ goalId?: string; name?: string; description?: string; repos?: string[]; ownerUserId?: string; status?: ProjectStatus }>(exchange)
    const updated = hub.updateProject(exchange.params['id']!, input)
    changeLog(exchange, 'exec.project.update', updated.name)
    return updated
  })

  guarded('DELETE', '/api/exec/projects/:id', 'exec.write', (exchange) => {
    const result = hub.deleteProject(exchange.params['id']!)
    changeLog(exchange, 'exec.project.delete', exchange.params['id'] ?? '')
    return result
  })

  // -- Tâches (E2/E4) ----------------------------------------------------------------
  guarded('GET', '/api/exec/issues', 'exec.read', (exchange) => {
    const status = exchange.query.get('status') ?? ''
    const agentId = exchange.query.get('agentId') ?? ''
    const projectId = exchange.query.get('projectId') ?? ''
    const orgId = exchange.query.get('orgId') ?? '' // #16 : filtre par périmètre organisationnel
    const agents = ctx.resourceCore.list('agent')
    const projects = hub.projects().all()
    return {
      issues: hub.issues().all()
        .filter((item) => (!status || item.status === status)
          && (!agentId || item.assigneeAgentId === agentId)
          && (!projectId || item.projectId === projectId)
          && (!orgId || item.orgId === orgId))
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .map((item) => ({
          ...item,
          assigneeAgentName: agents.find((agent) => agent.id === item.assigneeAgentId)?.name,
          projectName: projects.find((project) => project.id === item.projectId)?.name,
        })),
    }
  })

  guarded('POST', '/api/exec/issues', 'exec.write', (exchange) => {
    const input = body<{ orgId?: string; projectId?: string; parentId?: string; blockerIds?: string[]; title: string; detail?: string; assigneeAgentId?: string; assigneeUserId?: string; priority?: IssuePriority; dueAt?: string }>(exchange)
    const project = input.projectId ? hub.projects().get(input.projectId) : undefined
    const assignee = input.assigneeAgentId ? ctx.resourceCore.collection('agent').get(input.assigneeAgentId) : undefined
    const created = hub.createIssue({
      ...input,
      orgId: resolveOrgId(exchange, input.orgId, [project?.orgId, assignee?.orgId]),
      createdBy: actorOf(exchange),
    })
    changeLog(exchange, 'exec.issue.create', created.title, `priority=${created.priority}${created.assigneeAgentId ? ' 已派发唤醒' : ''}`)
    return created
  })

  guarded('PATCH', '/api/exec/issues/:id', 'exec.write', (exchange) => {
    const input = body<{ title?: string; detail?: string; assigneeAgentId?: string; assigneeUserId?: string; projectId?: string; blockerIds?: string[]; priority?: IssuePriority; dueAt?: string }>(exchange)
    const updated = hub.updateIssue(exchange.params['id']!, input, actorOf(exchange))
    changeLog(exchange, 'exec.issue.update', updated.title)
    return updated
  })

  guarded('POST', '/api/exec/issues/:id/transition', 'exec.write', (exchange) => {
    const input = body<{ to: IssueStatus }>(exchange)
    const updated = hub.transitionIssue(exchange.params['id']!, input.to, actorOf(exchange))
    changeLog(exchange, 'exec.issue.transition', updated.title, `→ ${updated.status}`)
    return updated
  })

  guarded('DELETE', '/api/exec/issues/:id', 'exec.write', (exchange) => {
    const result = hub.deleteIssue(exchange.params['id']!)
    changeLog(exchange, 'exec.issue.delete', exchange.params['id'] ?? '')
    return result
  })

  guarded('POST', '/api/exec/issues/:id/wake', 'exec.write', (exchange) => {
    const input = body<{ reason?: string }>(exchange)
    const issue = hub.issues().get(exchange.params['id']!)
    if (!issue) { exchange.fail(404, 'NOT_FOUND', t('任务不存在：{id}', { id: exchange.params['id'] ?? '' })); return }
    if (!issue.assigneeAgentId) { exchange.fail(400, 'BAD_REQUEST', t('任务未指定负责人 Agent')); return }
    const wake = hub.enqueueWake({
      orgId: issue.orgId, issueId: issue.id, agentId: issue.assigneeAgentId, trigger: 'api',
      triggerDetail: input.reason ?? t('手动唤醒（{actor}）', { actor: actorOf(exchange) }),
      idempotencyKey: wakeIdempotencyKey('api', [issue.id, Date.now()]),
    })
    changeLog(exchange, 'exec.issue.wake', issue.title, wake.triggerDetail ?? '')
    return wake
  })

  guarded('GET', '/api/exec/lineage/:issueId', 'exec.read', (exchange) => hub.issueLineage(exchange.params['issueId']!))

  // -- Réveils / run ------------------------------------------------------------------
  guarded('GET', '/api/exec/wakes', 'exec.read', (exchange) => {
    const status = exchange.query.get('status') ?? ''
    const agents = ctx.resourceCore.list('agent')
    return {
      wakes: hub.wakes().all()
        .filter((item) => !status || item.status === status)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .slice(0, 200)
        .map((item) => ({
          ...item,
          agentName: agents.find((agent) => agent.id === item.agentId)?.name,
        })),
    }
  })

  guarded('GET', '/api/exec/runs', 'exec.read', (exchange) => {
    const status = exchange.query.get('status') ?? ''
    return { runs: hub.runs().all().filter((item) => !status || item.status === status).sort((a, b) => b.startedAt.localeCompare(a.startedAt)).slice(0, 200) }
  })

  guarded('POST', '/api/exec/wakeup', 'exec.write', (exchange) => {
    const input = body<{ agentId?: string; issueId?: string; reason?: string }>(exchange)
    const wake = hub.enqueueWake({
      orgId: '', ...(input.agentId ? { agentId: input.agentId } : {}),
      ...(input.issueId ? { issueId: input.issueId } : {}),
      trigger: 'api', triggerDetail: input.reason ?? t('API 触发（{actor}）', { actor: actorOf(exchange) }),
      idempotencyKey: wakeIdempotencyKey('api', [input.issueId ?? input.agentId ?? '', Date.now()]),
    })
    changeLog(exchange, 'exec.wakeup', input.issueId ?? input.agentId ?? '', wake.triggerDetail ?? '')
    return wake
  })

  // -- Règles de routine (E7) -----------------------------------------------------------------
  guarded('GET', '/api/exec/routines', 'exec.read', () => {
    const agents = ctx.resourceCore.list('agent')
    return {
      routines: hub.routines().all().map((item) => ({
        ...item,
        agentName: agents.find((agent) => agent.id === item.agentId)?.name,
      })),
    }
  })

  guarded('POST', '/api/exec/routines', 'exec.write', (exchange) => {
    const input = body<{ orgId?: string; agentId: string; name: string; kind: RoutineKind; intervalMinutes?: number; cron?: string; webhookPath?: string; payload?: Record<string, unknown>; enabled?: boolean }>(exchange)
    if (!input.name?.trim()) { exchange.fail(400, 'BAD_REQUEST', t('例行规则名称必填')); return }
    if (!input.agentId || !ctx.resourceCore.collection('agent').get(input.agentId)) { exchange.fail(400, 'BAD_REQUEST', t('负责人 Agent 不存在')); return }
    if (input.kind === 'interval' && !(Number(input.intervalMinutes) > 0)) { exchange.fail(400, 'BAD_REQUEST', t('interval 类型须提供正整数间隔分钟')); return }
    if (input.kind === 'cron') {
      if (!input.cron || !cronIsValid(input.cron)) { exchange.fail(400, 'BAD_REQUEST', t('cron 表达式非法（5 段：分 时 日 月 周，分钟粒度）')); return }
    }
    if (input.kind === 'webhook') {
      const path = (input.webhookPath ?? '').trim()
      if (!/^[a-z0-9-]{6,64}$/.test(path)) { exchange.fail(400, 'BAD_REQUEST', t('webhook 路径非法（小写字母/数字/-，6-64 位，路径即凭证请保持不可猜测）')); return }
      if (hub.routines().all().some((item) => item.webhookPath === path)) { exchange.fail(409, 'CONFLICT', t('webhook 路径已被占用')); return }
    }
    const created = hub.routines().insert({
      id: newId('rtn'),
      orgId: input.orgId ?? ctx.resourceCore.collection('agent').get(input.agentId)?.orgId ?? '',
      agentId: input.agentId,
      name: input.name.trim(),
      kind: input.kind,
      ...(input.kind === 'interval' ? { intervalMinutes: Number(input.intervalMinutes) } : {}),
      ...(input.kind === 'cron' ? { cron: input.cron!.trim() } : {}),
      ...(input.kind === 'webhook' ? { webhookPath: (input.webhookPath ?? '').trim() } : {}),
      ...(input.payload ? { payload: input.payload } : {}),
      enabled: input.enabled ?? true,
      createdBy: actorOf(exchange),
    })
    changeLog(exchange, 'exec.routine.create', created.name, `${created.kind}`)
    ctx.platformBus.emit(PlatformEvents.ExecRoutineChanged, { routineId: created.id, action: 'created' })
    return created
  })

  guarded('PATCH', '/api/exec/routines/:id', 'exec.write', (exchange) => {
    const input = body<{ name?: string; intervalMinutes?: number; cron?: string; payload?: Record<string, unknown>; enabled?: boolean }>(exchange)
    if (input.cron !== undefined && input.cron !== '' && !cronIsValid(input.cron)) { exchange.fail(400, 'BAD_REQUEST', t('cron 表达式非法')); return }
    const updated = hub.routines().update(exchange.params['id']!, {
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.intervalMinutes !== undefined ? { intervalMinutes: Number(input.intervalMinutes) } : {}),
      ...(input.cron !== undefined && input.cron !== '' ? { cron: input.cron } : {}),
      ...(input.payload !== undefined ? { payload: input.payload } : {}),
      ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
    })
    changeLog(exchange, 'exec.routine.update', updated.name)
    ctx.platformBus.emit(PlatformEvents.ExecRoutineChanged, { routineId: updated.id, action: 'updated' })
    return updated
  })

  guarded('DELETE', '/api/exec/routines/:id', 'exec.write', (exchange) => {
    hub.routines().remove(exchange.params['id']!)
    changeLog(exchange, 'exec.routine.delete', exchange.params['id'] ?? '')
    ctx.platformBus.emit(PlatformEvents.ExecRoutineChanged, { routineId: exchange.params['id'] ?? '', action: 'deleted' })
    return { deleted: true }
  })

  // -- Opérations (tick manuel : canal de test et d'exploitation) ----------------------------------------------
  guarded('POST', '/api/exec/tick', 'exec.admin', async (exchange) => {
    const result = await hub.tick()
    changeLog(exchange, 'exec.tick', 'manual', `processed=${result.processed} woken=${result.woken} reclaimed=${result.reclaimed}`)
    return result
  })

  // -- Déclencheur Webhook (E7 : le chemin sert d'identifiant — non enregistré/désactivé = toujours 404, sans fuiter l'existence) ---------------
  http.register('POST', '/api/exec/webhook/:path', (exchange) => {
    const path = exchange.params['path'] ?? ''
    const routine = hub.routines().findOne((item) => item.kind === 'webhook' && item.webhookPath === path && item.enabled)
    if (!routine) {
      exchange.fail(404, 'NOT_FOUND', 'Not Found')
      return
    }
    const wake = hub.enqueueWake({
      orgId: routine.orgId, agentId: routine.agentId, trigger: 'webhook',
      triggerDetail: `webhook:${path}`,
      idempotencyKey: wakeIdempotencyKey('webhook', [routine.id, Date.now()]),
    })
    exchange.ok({ wakeId: wake.id, routine: routine.name })
  }, { access: 'public', selfValidated: true })

  // -- Outils Agent (E5 : appel direct dans la session Agent, sans avoir à connaître l'existence du centre d'exécution) --------------------
  const tools = ctx.tools
  if (tools) {
    tools.register(defineTool({
      name: 'exec_wakeup_status',
      description: '查看执行中枢唤醒队列状态（待唤醒/延迟中/活跃 run 数）。',
      permission: 'exec.read',
      parameters: {},
      output: { type: 'object', additionalProperties: true },
      async execute() {
        const overview = hub.overview() as { pendingWakes: number; deferredWakes: number; activeRuns: number; lockedIssues: number }
        return { pending: overview.pendingWakes, deferred: overview.deferredWakes, activeRuns: overview.activeRuns, lockedIssues: overview.lockedIssues }
      },
    }))

    tools.register(defineTool({
      name: 'exec_claim',
      description: '认领任务并取执行租约（幂等：同主体重复认领返回既有 run 不报错；他人持有则告知 locked_by_other；受管数字员工自动走统一准入与员工租约）。',
      permission: 'exec.write',
      parameters: { issueId: { type: 'string', required: true, description: '任务 ID' } },
      output: { type: 'object', additionalProperties: true },
      async execute(args, exec) {
        const issueId = String(args.issueId ?? '')
        // D05/D06 fail-closed : pas de principal appelant = pas de réclamation (l'identité n'entre pas dans les paramètres d'outil, toujours prise depuis exec.principal)
        if (!exec.principal) throw new Error(t('缺少调用主体（exec.principal），拒绝认领（fail-closed）——请检查令牌与会话注入'))
        const issue = hub.issues().get(issueId)
        if (!issue) throw new Error(t('任务不存在：{id}', { id: issueId }))
        const principal = exec.principal
        // Chemin de l'employé numérique géré (sondage structurel au runtime du service workforce, hors inject — assemblé après exec-hub).
        // Lecture souple (même référentiel que softRead de dsh-bridge) : le service workforce ayant été déclaré dans ctx par le fournisseur, sous l'injection stricte de cordis,
        // l'accès direct `(ctx as any).workforceAdmission` est durement jeté par le get trap « without inject », il faut passer par reflect.
        const softRead = (key: string): unknown => {
          try {
            if (typeof (ctx as unknown as { reflect?: { get?: (k: string, optional?: boolean) => unknown } }).reflect?.get === 'function') {
              return (ctx as unknown as { reflect: { get: (k: string, optional?: boolean) => unknown } }).reflect.get(key, false)
            }
            return (ctx as unknown as Record<string, unknown>)[key]
          } catch {
            return undefined
          }
        }
        const admission = softRead('workforceAdmission') as { claimWork?: (caller: unknown, input: { issueId: string }) => Promise<unknown> } | undefined
        const identity = softRead('workforceIdentity') as { resolveByCaller?: (caller: unknown) => Promise<unknown> } | undefined
        const isManagedAgent = principal.kind === 'machine' && principal.refType === 'agent'
          && typeof admission?.claimWork === 'function' && typeof identity?.resolveByCaller === 'function'
        if (isManagedAgent) {
          // Forme WorkCallerRef (platform-core/workforce-port) : principal de confiance analysé depuis le jeton, passage par args interdit
          const caller = {
            kind: 'machine' as const,
            principalId: principal.principalId,
            refType: principal.refType,
            refId: principal.refId,
            ...(principal.name ? { name: principal.name } : {}),
          }
          let resolution: unknown
          try {
            resolution = await identity.resolveByCaller!(caller)
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            return { ok: false, code: 'POLICY_INTERNAL_ERROR', message: t('受管身份反查失败（fail-closed）：{message}', { message }) }
          }
          if (resolution) {
            // Employé géré atteint → entrée de réclamation unifiée (admission/permit/liste de capacités/bail en une fois, sans dupliquer l'implémentation)
            const outcome = await admission.claimWork!(caller, { issueId }) as {
              ok: boolean
              employeeId?: string; agentId?: string; issueId?: string; runId?: string; idempotent?: boolean
              lease?: { id: string; leaseVersion: number; expiresAt: string }
              permit?: { id: string }; manifest?: { id: string }; tools?: Array<{ handle: string }>
              code?: string; message?: string; holder?: string
            }
            if (outcome.ok) {
              return {
                ok: true,
                issueId: outcome.issueId ?? issueId,
                runId: outcome.runId ?? '',
                employeeId: outcome.employeeId ?? '',
                ...(outcome.agentId ? { agentId: outcome.agentId } : {}),
                leaseId: outcome.lease?.id ?? '',
                leaseVersion: outcome.lease?.leaseVersion ?? 0,
                expiresAt: outcome.lease?.expiresAt ?? '',
                ...(outcome.permit ? { permitId: outcome.permit.id } : {}),
                ...(outcome.manifest ? { manifestId: outcome.manifest.id } : {}),
                ...(outcome.tools ? { tools: outcome.tools.map((tool) => tool.handle) } : {}),
                idempotent: outcome.idempotent === true,
              }
            }
            const code = outcome.code ?? 'POLICY_INTERNAL_ERROR'
            const label = WORK_DENY_CODE_LABELS[code as keyof typeof WORK_DENY_CODE_LABELS]
            return {
              ok: false,
              code,
              message: outcome.message || (label ? t('{label}（code={code}）', { label: t(String(label)), code }) : t('认领被拒绝（code={code}）', { code })),
              ...(outcome.holder ? { holder: outcome.holder } : {}),
            }
          }
          // Non géré (resolveByCaller=null) → retombe dans l'ancienne sémantique d'exec_claim (compatibilité maintenue)
        }
        // -- Ancienne sémantique (version corrigée idempotente D05/D06) -----------------------------------------
        // Le principal machine ne peut réclamer que les tâches qui lui sont assignées (les détenteurs humains d'exec.write ne sont pas soumis à cette limite)
        if (principal.kind === 'machine' && principal.refType === 'agent' && issue.assigneeAgentId !== principal.refId) {
          throw new Error(t('该任务未指派给你（no_permission）'))
        }
        const agent = issue.assigneeAgentId ? ctx.resourceCore.collection('agent').get(issue.assigneeAgentId) : undefined
        const agentKey = normalizeAgentKey(agent?.name ?? 'unknown')
        // Idempotence ① : bail d'autorité existant — même agentKey (clé d'identité legacy) → renvoie le run existant ; autrui → locked_by_other
        const active = hub.leaseStore.activeForIssue(issue.id)
        if (active) {
          const decision = decideLeaseClaim({
            activeLeasePresent: true,
            activeLeaseExpired: false,
            existingEmployeeId: active.employeeId,
            existingAgentKey: active.agentKey,
            requestedEmployeeId: '',
            requestedAgentKey: agentKey,
          })
          if (decision.kind === 'idempotent') {
            hub.leaseStore.renew({ leaseId: active.id })
            hub.writeClaimProjectionForTool(issue.id, active.runId, agentKey)
            return { ok: true, runId: active.runId, idempotent: true, leaseId: active.id, leaseVersion: active.leaseVersion }
          }
          return { ok: false, reason: 'locked_by_other', holder: active.runId }
        }
        // Idempotence ② : pas de bail mais projection pointant un run en cours du même sujet (verrou préempté par réveil/ancienne réclamation) → adoption du run existant (V05)
        if (issue.executionRunId) {
          const existingRun = hub.runs().get(issue.executionRunId)
          if (existingRun && existingRun.status === 'running') {
            const sameSubject = principal.kind === 'machine' && principal.refType === 'agent'
              ? existingRun.agentId === principal.refId
              : existingRun.agentId === issue.assigneeAgentId
            if (sameSubject) {
              const adopted = hub.leaseStore.acquire({ issueId: issue.id, runId: existingRun.id, employeeId: '', agentKey, principalId: principal.principalId })
              if (adopted.ok) {
                hub.writeClaimProjectionForTool(issue.id, existingRun.id, agentKey)
                if (issue.status === 'todo') hub.issues().update(issue.id, { status: 'in_progress' })
                return { ok: true, runId: existingRun.id, idempotent: true, leaseId: adopted.lease.id, leaseVersion: adopted.lease.leaseVersion }
              }
              return { ok: false, reason: 'locked_by_other', holder: existingRun.id }
            }
            return { ok: false, reason: 'locked_by_other', holder: issue.executionRunId }
          }
          // Run manquant/déjà terminal = projection sale : poursuite en création (acquireLock écrasera la projection résiduelle)
        }
        const runId = newId('run')
        const acquired = hub.leaseStore.acquire({ issueId: issue.id, runId, employeeId: '', agentKey, principalId: principal.principalId })
        if (!acquired.ok) return { ok: false, reason: 'locked_by_other', holder: acquired.holder }
        const cas = hub.acquireLock(issue.id, runId, agentKey)
        if (!cas.ok) return { ok: false, reason: cas.reason, holder: cas.holder }
        hub.runs().insert({
          id: runId, orgId: issue.orgId,
          ...(issue.assigneeAgentId ? { agentId: issue.assigneeAgentId } : {}),
          issueIds: [issue.id], trigger: 'api', status: 'running',
          contextPack: agent ? hub.issueLineage(issue.id).ancestry.map((item) => item.title).join(' › ') : undefined,
          startedAt: new Date().toISOString(),
        })
        if (issue.status === 'todo') hub.issues().update(issue.id, { status: 'in_progress' })
        ctx.platformBus.emit(PlatformEvents.ExecIssueChanged, { issueId: issue.id, action: 'claimed', status: 'in_progress', runId })
        return { ok: true, runId, leaseId: acquired.lease.id, leaseVersion: acquired.lease.leaseVersion }
      },
    }))

    tools.register(defineTool({
      name: 'exec_complete',
      description: '交回产出并完结 run（run 级释放执行租约与锁；完成任务转待审 review，失败任务转回待办；需与认领主体一致）。',
      permission: 'exec.write',
      parameters: {
        runId: { type: 'string', description: 'run ID（exec_claim 返回）' },
        issueId: { type: 'string', description: '任务 ID（无 runId 时按其持有 run 收尾）' },
        summary: { type: 'string', description: '产出摘要' },
        status: { type: 'string', enum: ['completed', 'failed'], description: '缺省 completed；failed 时进行中任务转回待办' },
      },
      output: { type: 'object', additionalProperties: true },
      async execute(args, exec) {
        const principal = exec.principal
        const status = args.status === 'failed' ? 'failed' : 'completed'
        let runId = String(args.runId ?? '')
        if (!runId) {
          const issueId = String(args.issueId ?? '')
          const issue = issueId ? hub.issues().get(issueId) : undefined
          runId = issue?.executionRunId ?? ''
          if (!runId && !principal) {
            // Invitation à compléter les paramètres (D07 fail-closed, pas de passage silencieux)
            throw new Error(t('参数不足：既未提供 runId，也无法识别调用主体（exec.principal 缺失）——请携带 exec_claim 返回的 runId 重试；如身份异常请联系管理员升级人工处理'))
          }
          if (!runId) throw new Error(t('缺少 runId，或该任务未持有执行锁'))
        }
        // D07 validation de propriété principal/run : un run avec enregistrement de bail exige la coïncidence des principaux (bail périmé refusé LEASE_STALE)
        const lease = hub.leaseStore.latestForRun(runId)
        const ownership = decideCompleteOwnership({
          hasLeaseRecord: Boolean(lease),
          status: lease?.status ?? 'released',
          expired: lease ? new Date(lease.expiresAt).getTime() <= Date.now() : true,
          callerPrincipalId: principal?.principalId ?? '',
          leasePrincipalId: lease?.principalId ?? '',
        })
        if (ownership.kind === 'deny') {
          throw new Error(t('{reason}（code={code}）', { reason: ownership.reason, code: ownership.code }))
        }
        const run = hub.completeRun(runId, {
          status,
          ...(args.summary ? { summary: String(args.summary) } : {}),
          ...(status === 'failed' ? { failedIssueDisposition: 'todo' as const } : {}),
        })
        return { ok: true, runId, status: run.status, releasedLock: true, ...(lease ? { leaseReleased: true } : {}) }
      },
    }))

    tools.register(defineTool({
      name: 'exec_lineage',
      description: '查看任务的目标血缘（目标 → 项目 → 任务 → 前置依赖），回答「为什么而干」。',
      permission: 'exec.read',
      parameters: { issueId: { type: 'string', required: true, description: '任务 ID' } },
      output: { type: 'object', additionalProperties: true },
      async execute(args) {
        const lineage = hub.issueLineage(String(args.issueId ?? ''))
        return {
          goal: lineage.goal ? { id: lineage.goal.id, title: lineage.goal.title, metric: lineage.goal.metric } : undefined,
          project: lineage.project ? { id: lineage.project.id, name: lineage.project.name } : undefined,
          ancestry: lineage.ancestry,
          blockers: lineage.blockers,
        }
      },
    }))
  }

  // -- Migration des préexistants (#16 : orgId vide rattaché à l'organisation racine, audit tracé, idempotent) --------------------------------
  migrateEmptyExecOrgId(ctx, hub)

  // -- Graines de démonstration (G3 : exemples manufacturiers trois départements sous DEMO_SEED ; idempotent sur base vide) --------------------------
  seedExecHub(ctx, hub)
}

/**
 * #16 (2026-10-29) Migration des préexistants : les enregistrements Goal/Project/Issue à orgId vide sont rattachés à l'organisation racine de la plateforme avec audit.
 * Idempotent (ne traite que les rattachements à chaîne vide) ; saute si l'arbre d'organisations n'est pas ensemencé (complété au prochain démarrage) — « chaîne vide = lignée rompue » n'est plus re-entrant.
 */
function migrateEmptyExecOrgId(ctx: Context, hub: ExecutionHubService): void {
  const rootOrgId = hub.rootOrgId()
  if (!rootOrgId) return
  let migrated = 0
  const samples: string[] = []
  for (const [collection, kind] of [[hub.goals(), 'goal'], [hub.projects(), 'project'], [hub.issues(), 'issue']] as const) {
    for (const record of collection.all().filter((item) => !item.orgId)) {
      collection.update(record.id, { orgId: rootOrgId })
      migrated++
      if (samples.length < 5) samples.push(`${kind}:${record.id}`)
    }
  }
  if (migrated === 0) return
  try {
    ctx.audit?.record({
      type: 'change', actorType: 'system', actorId: 'exec-hub', actorName: t('执行中枢'),
      action: 'exec.orgid.migrate', resourceType: 'exec', resourceId: rootOrgId,
      resourceName: t('平台根组织'), result: 'ok',
      detail: t('存量空 orgId 归根组织（#16）：{count} 条，样例 {samples}', { count: migrated, samples: samples.join(', ') }),
    })
  } catch { /* dégradation indépendante du plan d'audit */ }
  ctx.logger('exec-hub').info(`存量 exec 记录空 orgId 已归根组织（#16）：${migrated} 条（${samples.join(', ')}${samples.length < migrated ? ' 等' : ''}）`)
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    execHub: ExecutionHubService
  }
}

export const name = 'exec-hub'
export const inject = [
  'httpServer', 'opsStorage', 'platformBus', 'iam', 'authn', 'audit', 'tools',
  'modelGateway', 'resourceCore', 'agentRegistry', 'flow',
  // Adaptation de conception (2026-10-14) surface de lecture seule requise par l'agrégat cockpit() (les fournisseurs sont assemblés avant exec-hub,
  // voir la séquence d'assemblage boot-all.ts / cordis.yml) : usage = agrégat de metering du jour, le reste = comptage du stock des six classes d'actifs et face anomalies
  'usage', 'mcpRegistry', 'skillHub', 'nasRegistry',
  // Décision 3 de l'annexe A (2026-10-15) : stockage de baux d'autorité exec_run_leases — txnStore assemblé en premier par platform-core
  // (premier plugin de boot-all.ts), avant exec-hub ; les services côté workforce sont toujours sondés à l'exécution, hors de la présente liste
  'txnStore',
]
