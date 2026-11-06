/**
 * Service du domaine des employés (employee-service) — dossier de l'employé, liaison d'exécution un-à-un avec l'Agent technique, chaînage suspension/reprise/départ.
 *
 * Responsabilités (canevas §5/§8.1/§D.4, annexe A décision 1) :
 *   - liaison valide un-à-un employé↔Agent : un seul active par Agent sur toute la plateforme (vérification en transaction + précontrôle d'unicité de domaine) ;
 *   - employees.primaryAgentId est un pointeur redondant, maintenu synchrone par ce service dans la transaction de liaison ;
 *   - chaînage suspension/départ : révocabation de toutes les autorisations de travail (permit) → libération des baux d'exécution (via le port d'intégration exec-hub,
 *     sondage structuré, sans import inverse) → transition de la machine à états → diffusion d'événement ;
 *   - abonnement à agent.frozen : quand l'Agent technique est gelé (notamment par le chaînage budget), révoquer tous les permits valides des employés liés à cet Agent.
 *
 * Sémantique d'échec honnête : sur la chaîne de chaînage, un échec de « révocation des permits » interrompt la suspension (fail-closed) ;
 * la « libération des baux » passe par un sondage structuré, en cas d'absence d'exec-hub un événement observable est consigné (rattrapage par récupération des verrous zombies), sans simuler une libération.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId } from '../../platform-core/src/ids.ts'
import { WorkforceError } from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type {
  BindingRecord,
  EmployeeRecord,
  EmployeeStatus,
  WorkCallerRef,
  WorkforceEmployees,
  WorkforcePermits,
} from './contract.ts'
import { employeeStatusTransition } from './domain.ts'
import type { WorkforceStoreService } from './repositories.ts'

function nowIso(): string {
  return new Date().toISOString()
}

/** Forme du sondage structuré du chemin de travail employé d'exec-hub (sous-ensemble d'ExecHubWorkIntegration ; absence = capacité de chaînage manquante). */
interface ExecHubReleaseProbe {
  releaseForRun?(runId: string, reason: string): void
}

export class EmployeeService extends Service implements WorkforceEmployees {
  static readonly provide = 'workforceEmployees'

  constructor(ctx: Context) {
    super(ctx, 'workforceEmployees')

    // Chaînage au gel de l'Agent (R10) : révoquer tous les permits valides de l'employé lié à cet agentId et diffuser l'événement.
    // platformBus non injecté dans la fiber courante (forme test unitaire autonome) : saut défensif — le chaînage manquant doit être observable, sans bloquer l'assemblage.
    try {
      ctx.platformBus.on('agent.frozen', (payload) => {
        this.handleAgentFrozen(payload)
      })
    } catch {
      /* bus d'événements absent : abonnement sauté (la liste de dépendances du service assemblé dans index.ts inclut déjà platformBus) */
    }
  }

  // -- Accès internes -----------------------------------------------------------

  private get store(): WorkforceStoreService {
    return this.ctx.workforceStore
  }

  private permits(): WorkforcePermits | undefined {
    return (this.ctx as unknown as { workforcePermits?: WorkforcePermits }).workforcePermits
  }

  private execHub(): ExecHubReleaseProbe | undefined {
    return (this.ctx as unknown as { execHub?: ExecHubReleaseProbe }).execHub
  }

  private emitEvent(name: string, payload: Record<string, unknown>): void {
    try {
      const bus = (this.ctx as unknown as { platformBus?: { emit(event: string, payload: unknown): unknown } }).platformBus
      bus?.emit(name, { ...payload, at: nowIso() })
    } catch {
      /* bus d'événements absent : notification sautée — le fait d'état est déjà en base, le chaînage peut être compensé par liste/audit */
    }
  }

  private actorOf(caller: WorkCallerRef | undefined): string {
    return caller?.userId ?? caller?.principalId ?? ''
  }

  // -- Chaînage au gel de l'Agent ------------------------------------------------------

  /** Traitement d'agent.frozen : employé à liaison active sur cet agentId → révocation de tous les permits + émission de workforce.permit.revoked. */
  private handleAgentFrozen(payload: unknown): void {
    try {
      const p = (payload ?? {}) as { agentId?: string; reason?: string }
      if (!p.agentId) return
      const permits = this.permits()
      if (!permits) {
        this.emitEvent('workforce.permit.revoked', { agentId: p.agentId, revoked: 0, note: '工作授权服务未就绪，联动未执行' })
        return
      }
      const reason = t('技术 Agent 已冻结：{reason}', { reason: p.reason ?? t('原因未登记') })
      for (const binding of this.store.bindings.findWhere({ agentId: p.agentId, status: 'active' })) {
        const revoked = permits.revokeForEmployee(binding.employeeId, reason)
        this.emitEvent('workforce.permit.revoked', { agentId: p.agentId, employeeId: binding.employeeId, revoked, reason })
      }
    } catch (error) {
      // Une exception de l'écouteur est rattrapée par le mécanisme de lettres mortes du bus ; on ne relève pas ici pour ne pas amplifier la panne
      this.emitEvent('workforce.permit.revoked', { note: `Agent 冻结联动失败：${error instanceof Error ? error.message : String(error)}` })
    }
  }

  // -- Dossier de l'employé ------------------------------------------------------------

  create(input: {
    name: string
    displayName?: string
    orgId: string
    supervisorUserId: string
    agentId: string
    principalId?: string
    runtime?: string
  }): EmployeeRecord {
    const name = String(input.name ?? '').trim()
    const orgId = String(input.orgId ?? '').trim()
    const supervisorUserId = String(input.supervisorUserId ?? '').trim()
    const agentId = String(input.agentId ?? '').trim()
    if (name === '') throw new Error(t('创建数字员工必须登记员工名称'))
    if (orgId === '') throw new Error(t('创建数字员工必须登记主组织（orgId）'))
    if (supervisorUserId === '') throw new Error(t('创建数字员工必须登记真人主管（supervisorUserId）——主管是责任人，不自动成为代理用户'))
    if (agentId === '') throw new Error(t('创建数字员工必须绑定技术 Agent（agentId）'))

    const createdAt = nowIso()
    const employee: EmployeeRecord = {
      id: newId('emp'),
      name,
      displayName: String(input.displayName ?? '').trim() || name,
      orgId,
      supervisorUserId,
      status: 'active',
      primaryAgentId: agentId,
      createdAt,
      updatedAt: createdAt,
    }
    const binding: BindingRecord = {
      id: newId('bnd'),
      employeeId: employee.id,
      agentId,
      principalId: String(input.principalId ?? '').trim(),
      runtime: String(input.runtime ?? '').trim() || 'dsh',
      capabilityVersion: 1,
      status: 'active',
      createdAt,
      updatedAt: createdAt,
    }

    // Même transaction pour « validation d'unicité de domaine + création du dossier de l'employé + établissement de la liaison » : la liaison un-à-un est une décision figée (annexe A décision 1)
    this.store.txn(() => {
      const conflict = this.store.bindings.findWhere({ agentId, status: 'active' })
      if (conflict.length > 0) {
        throw new WorkforceError('PRINCIPAL_BINDING_MISMATCH', t('该技术 Agent 已绑定其他数字员工'))
      }
      this.store.employees.insert(employee)
      this.store.bindings.insert(binding)
    })

    this.emitEvent('workforce.employee.changed', { employeeId: employee.id, name: employee.name, action: 'created', agentId, orgId })
    return employee
  }

  get(id: string): EmployeeRecord {
    const employee = this.store.employees.get(id)
    if (!employee) throw new Error(t('数字员工不存在：{id}', { id }))
    return employee
  }

  list(filter?: { orgId?: string; status?: EmployeeStatus }): EmployeeRecord[] {
    let rows = this.store.employees.all()
    if (filter?.orgId) rows = rows.filter((row) => row.orgId === filter.orgId)
    if (filter?.status) rows = rows.filter((row) => row.status === filter.status)
    return rows.sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0))
  }

  /**
   * Suspension/reprise/départ : transition de la machine à états + chaînage.
   * Discipline d'ordre (fail-closed) : replier d'abord la face perturbatrice (révocation des permits → libération des baux), écrire l'état ensuite —
   * un échec de révocation des permits interrompt la suspension (mieux vaut un employé maintenu en poste qu'une fenêtre « suspendu mais permits agissants ») ;
   * la libération des baux passe par le sondage structuré exec-hub, absence/échec consigné en événement (rattrapage par récupération des verrous zombies), sans interrompre le flux.
   */
  setStatus(caller: WorkCallerRef, id: string, status: EmployeeStatus, reason: string): EmployeeRecord {
    const employee = this.get(id)
    employeeStatusTransition(employee.status, status) // une transition illégale lève ici une erreur en chinois
    const trimmedReason = String(reason ?? '').trim()
    if ((status === 'suspended' || status === 'offboarded') && trimmedReason === '') {
      throw new Error(t('停职/离岗必须登记原因（审计与解冻依据）'))
    }
    const actionLabel = status === 'suspended' ? t('停职') : status === 'offboarded' ? t('离岗') : t('复岗')

    // 1. Collecter les runs détenant un permit active pour cet employé (dédupliqués), et revérifier le rattachement via activeForRun avant révocation
    //    (la revérification doit précéder la révocation — après révocation, activeForRun est vide)
    const activePermits = this.store.permits.findWhere({ employeeId: id, status: 'active' })
    const permits = this.permits()
    const runIds: string[] = []
    if (status === 'suspended' || status === 'offboarded') {
      for (const runId of new Set(activePermits.map((permit) => permit.runId).filter((item) => item !== ''))) {
        const active = permits?.activeForRun(runId)
        if (permits && (!active || active.employeeId !== id)) continue // revérification activeForRun non convaincante : ce run n'est pas libéré
        runIds.push(runId)
      }
    }

    // 2. Révoquer toutes les autorisations de travail (la couche de politique de travail cesse la première : toute nouvelle action est immédiatement refusée, V07)
    if (permits && activePermits.length > 0) {
      permits.revokeForEmployee(id, t('员工{action}：{reason}', { action: actionLabel, reason: trimmedReason }))
    }

    // 3. Libérer les baux d'exécution (port d'intégration exec-hub, sondage structuré — pas d'import inverse)
    if (status === 'suspended' || status === 'offboarded') {
      const execHub = this.execHub()
      const releaseReason = t('员工{action}：{reason}', { action: actionLabel, reason: trimmedReason })
      for (const runId of runIds) {
        if (typeof execHub?.releaseForRun !== 'function') {
          this.emitEvent('workforce.employee.changed', {
            employeeId: id, action: 'lease_release_skipped', runId, note: '执行中枢租约释放端口未就绪，交由僵尸锁回收兜底',
          })
          continue
        }
        try {
          execHub.releaseForRun(runId, releaseReason)
        } catch (error) {
          this.emitEvent('workforce.employee.changed', {
            employeeId: id, action: 'lease_release_failed', runId,
            note: `租约释放失败（待僵尸锁回收）：${error instanceof Error ? error.message : String(error)}`,
          })
        }
      }
    }

    // 4. Écriture en base de la machine à états (la reprise reactivate est uniquement suspended→active, contrainte par la table de transition)
    const updatedAt = nowIso()
    this.store.txn(() => {
      this.store.employees.update(id, { status, updatedAt })
    })

    this.emitEvent('workforce.employee.changed', {
      employeeId: id, action: 'status', from: employee.status, to: status, reason: trimmedReason,
      actor: this.actorOf(caller), revokedPermits: activePermits.length, releasedRuns: runIds,
    })
    return { ...employee, status, updatedAt }
  }

  // -- Liaison d'exécution ------------------------------------------------------------

  bindingsFor(employeeId: string): BindingRecord[] {
    return this.store.bindings
      .findWhere({ employeeId })
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0))
  }

  /**
   * Changement de liaison (la transaction garantit un seul active par Agent sur toute la plateforme) :
   * l'ancienne liaison active → inactive ; si l'Agent cible est occupé par un autre employé → refus ;
   * un re-liage répété du même Agent vaut mise à jour idempotente (reconstitution de principalId/runtime).
   * Un employé parti (état terminal) ne peut pas être re-lié ; un employé suspendu le peut (en préparation de la reprise).
   */
  bindAgent(caller: WorkCallerRef, employeeId: string, agentId: string, principalId?: string, runtime?: string): BindingRecord {
    const employee = this.get(employeeId)
    if (employee.status === 'offboarded') throw new Error(t('已离岗员工不接受换绑技术 Agent（如需重新任用请新建数字员工）'))
    const nextAgentId = String(agentId ?? '').trim()
    if (nextAgentId === '') throw new Error(t('换绑必须指定目标技术 Agent（agentId）'))

    const createdAt = nowIso()
    const updated = this.store.txn(() => {
      const occupied = this.store.bindings.findWhere({ agentId: nextAgentId, status: 'active' })
      const foreign = occupied.find((binding) => binding.employeeId !== employeeId)
      if (foreign) throw new WorkforceError('PRINCIPAL_BINDING_MISMATCH', t('该技术 Agent 已绑定其他数字员工'))

      const sameAgent = occupied.find((binding) => binding.employeeId === employeeId)
      if (sameAgent) {
        // Idempotent : re-liage répété du même Agent, simple reconstitution des informations sujet/runtime
        const patch: Partial<BindingRecord> = { updatedAt: createdAt }
        const trimmedPrincipal = String(principalId ?? '').trim()
        if (trimmedPrincipal !== '') patch.principalId = trimmedPrincipal
        const trimmedRuntime = String(runtime ?? '').trim()
        if (trimmedRuntime !== '') patch.runtime = trimmedRuntime
        this.store.bindings.update(sameAgent.id, patch)
        this.store.employees.update(employeeId, { primaryAgentId: nextAgentId, updatedAt: createdAt })
        return { ...sameAgent, ...patch } as BindingRecord
      }

      for (const binding of this.store.bindings.findWhere({ employeeId, status: 'active' })) {
        this.store.bindings.update(binding.id, { status: 'inactive', updatedAt: createdAt })
      }
      const created: BindingRecord = {
        id: newId('bnd'),
        employeeId,
        agentId: nextAgentId,
        principalId: String(principalId ?? '').trim(),
        runtime: String(runtime ?? '').trim() || 'dsh',
        capabilityVersion: 1,
        status: 'active',
        createdAt,
        updatedAt: createdAt,
      }
      this.store.bindings.insert(created)
      this.store.employees.update(employeeId, { primaryAgentId: nextAgentId, updatedAt: createdAt })
      return created
    })

    this.emitEvent('workforce.employee.changed', {
      employeeId: employeeId, action: 'rebind', agentId: nextAgentId, previousAgentId: employee.primaryAgentId, actor: this.actorOf(caller),
    })
    return updated
  }
}
