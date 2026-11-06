/**
 * Stockage d'autorité des baux d'exécution (LeaseStoreService) — exec_run_leases (txnStore SQLite).
 *
 * Décisions 3/7 de l'annexe A (gel) : SQLite est l'unique autorité des baux ; les trois champs issue.executionRunId /
 * executionAgentKey / executionLockedAt sont rétrogradés en projection (écrite intégralement par ExecutionHubService
 * pour compatibilité du statu quo, tout arbitrage de lecture fait foi sur la présente table).
 *
 * Sémantique transactionnelle (txnStore.txn BEGIN IMMEDIATE synchrone) :
 *   - acquire : vérification-insertion/renouvellement dans la même transaction (Node monothread + transaction synchrone = aucune fenêtre de concurrence) ;
 *     au plus un bail actif non expiré par issue ; leaseVersion croît de façon monotone au sein de l'issue.
 *   - renew : même principal + actif + non expiré → renouvelle renewedAt/expiresAt ; sinon LEASE_STALE.
 *   - release / releaseForIssue : passage en released par lots au niveau run/issue (scellé en état terminal, sans suppression de ligne — la chaîne d'audit est conservée).
 *
 * Ce fichier n'importe pas plugin-workforce (anti-boucle, §10.2) ; RunLeaseRecord est un miroir structurel
 * de la forme gelée de plugin-workforce contract.ts, champs alignés un à un.
 */
import { newId } from '../../platform-core/src/ids.ts'
import type { SqlValue } from '../../platform-core/src/sqlite.ts'
import { decideLeaseClaim, decideLeaseRenewal, type LeaseStatusLite } from './domain.ts'
import { t } from '../../platform-i18n/src/index.ts'

/** Bail d'exécution (miroir structurel du RunLeaseRecord de plugin-workforce contract.ts, forme gelée V1.0). */
export interface RunLeaseRecord {
  id: string
  issueId: string
  runId: string
  employeeId: string
  agentKey: string
  principalId: string
  leaseVersion: number
  status: LeaseStatusLite
  acquiredAt: string
  renewedAt: string
  expiresAt: string
  releasedAt: string
  releaseReason: string
}

/** Surface minimale de txnStore (satisfaite structurellement par SqliteTxnService ; facilite l'injection de doublures de test). */
export interface LeaseTxnStore {
  ensureTable(name: string, columns: Record<string, string>, options?: { primaryKey?: string[]; uniques?: string[][]; indexes?: string[][] }): void
  insert(table: string, row: Record<string, SqlValue>): void
  updateByKey(table: string, primaryKey: string[], keyValues: SqlValue[], patch: Record<string, SqlValue>): void
  all<T = Record<string, SqlValue>>(table: string, where?: Record<string, SqlValue>): T[]
  one<T = Record<string, SqlValue>>(table: string, where: Record<string, SqlValue>): T | undefined
  txn<T>(fn: () => T): T
}

export const EXEC_RUN_LEASES_TABLE = 'exec_run_leases'

export interface AcquireLeaseInput {
  issueId: string
  runId: string
  /** ID de l'employé géré ; la réclamation directe legacy par machine passe une chaîne vide (l'identité idempotente se réduit à agentKey). */
  employeeId: string
  agentKey: string
  principalId: string
  ttlMs?: number
}

export type AcquireLeaseResult =
  | { ok: true; lease: RunLeaseRecord; created: boolean }
  | { ok: false; code: 'LEASE_HELD_BY_OTHER'; holder: string }

export type RenewLeaseResult =
  | { ok: true; lease: RunLeaseRecord }
  | { ok: false; code: 'LEASE_STALE'; message: string }

export interface RenewLeaseInput {
  /** L'un des deux : renouvellement exact par leaseId, ou dernier bail du run par runId. */
  leaseId?: string
  runId?: string
  /** Fourni, doit coïncider avec le principal du bail (passé par le port renewLease) ; absent = renouvellement idempotent interne au hub (l'arbitrage a déjà eu lieu au niveau claim). */
  principalId?: string
  ttlMs?: number
}

export class LeaseStoreService {
  readonly table = EXEC_RUN_LEASES_TABLE
  private readonly txn: LeaseTxnStore
  private readonly defaultTtlMs: number
  private readonly nowMs: () => number

  constructor(txn: LeaseTxnStore, options: { ttlMs?: number; now?: () => number } = {}) {
    this.txn = txn
    this.defaultTtlMs = options.ttlMs ?? 15 * 60_000
    this.nowMs = options.now ?? (() => Date.now())
  }

  /** Création de table (idempotente) : colonnes selon la forme gelée contract.RunLeaseRecord ; index issueId+status, runId. */
  migrate(): void {
    this.txn.ensureTable(this.table, {
      id: 'TEXT NOT NULL',
      issueId: 'TEXT NOT NULL',
      runId: 'TEXT NOT NULL',
      employeeId: "TEXT NOT NULL DEFAULT ''",
      agentKey: "TEXT NOT NULL DEFAULT ''",
      principalId: 'TEXT NOT NULL',
      leaseVersion: 'INTEGER NOT NULL DEFAULT 1',
      status: "TEXT NOT NULL DEFAULT 'active'",
      acquiredAt: 'TEXT NOT NULL',
      renewedAt: 'TEXT NOT NULL',
      expiresAt: 'TEXT NOT NULL',
      releasedAt: "TEXT NOT NULL DEFAULT ''",
      releaseReason: "TEXT NOT NULL DEFAULT ''",
    }, { indexes: [['issueId', 'status'], ['runId']] })
  }

  /**
   * Obtention atomique du bail (vérification-positionnement en transaction) :
   *   - bail valide existant : même détenteur (géré par employeeId, legacy par agentKey) → renouvellement idempotent, renvoie created=false ;
   *     détenteur différent → LEASE_HELD_BY_OTHER + holder.
   *   - aucun bail valide (actif mais expiré compris — d'abord marqué superseded puis nouvelle prise) : leaseVersion = max de l'issue +1.
   */
  acquire(input: AcquireLeaseInput): AcquireLeaseResult {
    return this.txn.txn(() => {
      const now = this.nowMs()
      const ttlMs = input.ttlMs && input.ttlMs > 0 ? input.ttlMs : this.defaultTtlMs
      const existing = this.activeLeaseRow(input.issueId, now)
      if (existing) {
        const lease = this.rowToLease(existing)
        const decision = decideLeaseClaim({
          activeLeasePresent: true,
          activeLeaseExpired: false,
          existingEmployeeId: lease.employeeId,
          existingAgentKey: lease.agentKey,
          requestedEmployeeId: input.employeeId,
          requestedAgentKey: input.agentKey,
        })
        if (decision.kind === 'idempotent') {
          const renewed: RunLeaseRecord = {
            ...lease,
            renewedAt: new Date(now).toISOString(),
            expiresAt: new Date(now + ttlMs).toISOString(),
          }
          this.txn.updateByKey(this.table, ['id'], [lease.id], { renewedAt: renewed.renewedAt, expiresAt: renewed.expiresAt })
          return { ok: true, lease: renewed, created: false }
        }
        return { ok: false, code: 'LEASE_HELD_BY_OTHER' as const, holder: decision.holder }
      }
      // Bail actif expiré non marqué sale : rétrogradé en remplacé (référentiel d'autorité : expiré = personne ne détient effectivement)
      for (const row of this.txn.all<LeaseRow>(this.table, { issueId: input.issueId, status: 'active' })) {
        if (new Date(String(row.expiresAt)).getTime() <= now) {
          this.markSettled(String(row.id), 'superseded', 'expired')
        }
      }
      const version = this.maxVersionForIssue(input.issueId) + 1
      const nowIso = new Date(now).toISOString()
      const lease: RunLeaseRecord = {
        id: newId('lease'),
        issueId: input.issueId,
        runId: input.runId,
        employeeId: input.employeeId,
        agentKey: input.agentKey,
        principalId: input.principalId,
        leaseVersion: version,
        status: 'active',
        acquiredAt: nowIso,
        renewedAt: nowIso,
        expiresAt: new Date(now + ttlMs).toISOString(),
        releasedAt: '',
        releaseReason: '',
      }
      this.txn.insert(this.table, this.leaseToRow(lease))
      return { ok: true, lease, created: true }
    })
  }

  /** Renouvellement : même principal + actif + non expiré (principalId absent = renouvellement après arbitrage interne du hub, pas de revalidation). */
  renew(input: RenewLeaseInput): RenewLeaseResult {
    return this.txn.txn(() => {
      const now = this.nowMs()
      const row = input.leaseId
        ? this.txn.one<LeaseRow>(this.table, { id: input.leaseId })
        : this.latestLeaseRowForRun(input.runId ?? '')
      if (!row) return { ok: false as const, code: 'LEASE_STALE' as const, message: t('执行租约不存在（未认领或已被清理），请先重新认领') }
      const lease = this.rowToLease(row)
      const decision = decideLeaseRenewal({
        status: lease.status,
        expired: new Date(lease.expiresAt).getTime() <= now,
        principalMatches: input.principalId === undefined ? true : lease.principalId === input.principalId,
      })
      if (decision.kind === 'stale') {
        return { ok: false as const, code: 'LEASE_STALE' as const, message: t('执行租约已过期或被更高版本取代（旧租约），请先重新认领') }
      }
      const ttlMs = input.ttlMs && input.ttlMs > 0 ? input.ttlMs : this.defaultTtlMs
      const renewed: RunLeaseRecord = {
        ...lease,
        renewedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + ttlMs).toISOString(),
      }
      this.txn.updateByKey(this.table, ['id'], [lease.id], { renewedAt: renewed.renewedAt, expiresAt: renewed.expiresAt })
      return { ok: true as const, lease: renewed }
    })
  }

  /** Libération par lots au niveau run (clôture d'état terminal/couplage suspension), renvoie le nombre libéré. */
  release(runId: string, reason: string): number {
    return this.releaseWhere({ runId }, reason)
  }

  /** Libération par lots au niveau issue (couplage annulation/réaffectation de tâche), renvoie le nombre libéré. */
  releaseForIssue(issueId: string, reason: string): number {
    return this.releaseWhere({ issueId }, reason)
  }

  private releaseWhere(where: { runId?: string; issueId?: string }, reason: string): number {
    return this.txn.txn(() => {
      let released = 0
      for (const row of this.txn.all<LeaseRow>(this.table, where)) {
        if (row.status !== 'active') continue
        this.markSettled(String(row.id), 'released', reason)
        released += 1
      }
      return released
    })
  }

  /** Bail valide courant de l'issue (actif et non expiré) ; sinon undefined. */
  activeForIssue(issueId: string, nowMs = this.nowMs()): RunLeaseRecord | undefined {
    const row = this.activeLeaseRow(issueId, nowMs)
    return row ? this.rowToLease(row) : undefined
  }

  /** Bail valide courant du run (actif et non expiré) ; sinon undefined. */
  activeForRun(runId: string, nowMs = this.nowMs()): RunLeaseRecord | undefined {
    const row = this.activeLeaseRowForRun(runId, nowMs)
    return row ? this.rowToLease(row) : undefined
  }

  /** Dernier enregistrement de bail du run (tout état, released/superseded compris — base du jugement de bail périmé D07). */
  latestForRun(runId: string): RunLeaseRecord | undefined {
    const row = this.latestLeaseRowForRun(runId)
    return row ? this.rowToLease(row) : undefined
  }

  // -- Interne -------------------------------------------------------------------

  private activeLeaseRow(issueId: string, nowMs: number): LeaseRow | undefined {
    for (const row of this.txn.all<LeaseRow>(this.table, { issueId, status: 'active' })) {
      if (new Date(String(row.expiresAt)).getTime() > nowMs) return row
    }
    return undefined
  }

  private activeLeaseRowForRun(runId: string, nowMs: number): LeaseRow | undefined {
    for (const row of this.txn.all<LeaseRow>(this.table, { runId, status: 'active' })) {
      if (new Date(String(row.expiresAt)).getTime() > nowMs) return row
    }
    return undefined
  }

  private latestLeaseRowForRun(runId: string): LeaseRow | undefined {
    return this.txn.all<LeaseRow>(this.table, { runId })
      .sort((a, b) => Number(b.leaseVersion) - Number(a.leaseVersion) || String(b.acquiredAt).localeCompare(String(a.acquiredAt)))[0]
  }

  private maxVersionForIssue(issueId: string): number {
    return this.txn.all<LeaseRow>(this.table, { issueId })
      .reduce((max, row) => Math.max(max, Number(row.leaseVersion) || 0), 0)
  }

  private markSettled(id: string, status: LeaseStatusLite, reason: string): void {
    this.txn.updateByKey(this.table, ['id'], [id], {
      status,
      releasedAt: new Date(this.nowMs()).toISOString(),
      releaseReason: reason,
    })
  }

  private rowToLease(row: LeaseRow): RunLeaseRecord {
    return {
      id: String(row.id),
      issueId: String(row.issueId),
      runId: String(row.runId),
      employeeId: String(row.employeeId ?? ''),
      agentKey: String(row.agentKey ?? ''),
      principalId: String(row.principalId ?? ''),
      leaseVersion: Number(row.leaseVersion),
      status: (row.status === 'released' || row.status === 'superseded' ? row.status : 'active') as LeaseStatusLite,
      acquiredAt: String(row.acquiredAt),
      renewedAt: String(row.renewedAt),
      expiresAt: String(row.expiresAt),
      releasedAt: String(row.releasedAt ?? ''),
      releaseReason: String(row.releaseReason ?? ''),
    }
  }

  private leaseToRow(lease: RunLeaseRecord): Record<string, SqlValue> {
    return {
      id: lease.id,
      issueId: lease.issueId,
      runId: lease.runId,
      employeeId: lease.employeeId,
      agentKey: lease.agentKey,
      principalId: lease.principalId,
      leaseVersion: lease.leaseVersion,
      status: lease.status,
      acquiredAt: lease.acquiredAt,
      renewedAt: lease.renewedAt,
      expiresAt: lease.expiresAt,
      releasedAt: lease.releasedAt,
      releaseReason: lease.releaseReason,
    }
  }
}

/** Ligne brute d'exec_run_leases (référentiel SqlValue). */
interface LeaseRow extends Record<string, SqlValue> {
  id: string
  issueId: string
  runId: string
  employeeId: string
  agentKey: string
  principalId: string
  leaseVersion: number
  status: string
  acquiredAt: string
  renewedAt: string
  expiresAt: string
  releasedAt: string
  releaseReason: string
}
