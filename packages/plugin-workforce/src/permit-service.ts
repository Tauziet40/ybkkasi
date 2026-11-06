/**
 * Service d'autorisation de travail (permit) (chemin d'implémentation §8.1/§13, annexe A décision 4).
 *
 * Le permit est un identifiant aléatoire opaque émis côté serveur (generateSecret, ni JWT ni structure auto-décodables),
 * lié au sujet/employé/version de nomination/inventaire de capacités/run/bail, à validité courte et révocable ;
 * l'appel doit aussi présenter un vrai jeton machine — la chaîne permit n'est pas elle-même un justificatif.
 * Stockage de référence : workforce_permits (SQLite, contrat WORKFORCE_TABLES).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { generateSecret } from '../../platform-core/src/ids.ts'
import type { WorkCallerRef } from '../../platform-core/src/workforce-port.ts'
import {
  WorkforceError,
  type IdentityResolution,
  type PermitRecord,
  type RunLeaseRecord,
  type WorkforcePermits,
  type WorkforceStore,
} from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'

/** Validité par défaut du permit : 30 minutes (§8.3 autorisation à court terme ; bail de 15 minutes par défaut détenu côté exec-hub). */
const DEFAULT_PERMIT_TTL_MS = 30 * 60_000

export class PermitService extends Service implements WorkforcePermits {
  static readonly provide = 'workforcePermits'

  private readonly ttlMs: number

  constructor(ctx: Context, config: { permitTtlMs?: number } = {}) {
    super(ctx, 'workforcePermits')
    this.ttlMs = config.permitTtlMs && config.permitTtlMs > 0 ? config.permitTtlMs : DEFAULT_PERMIT_TTL_MS
  }

  // -- Dépendances (consommation structurée de l'implémentation de dépôt du groupe 1, pas de dépendance inverse vers les classes concrètes) ---------------------------------

  private get store(): WorkforceStore {
    const store = (this.ctx as unknown as { workforceStore?: WorkforceStore }).workforceStore
    if (!store || typeof store.txn !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceStore 未就绪（迁移未完成）'), 503)
    }
    return store
  }

  private emit(event: string, payload: unknown): void {
    try {
      ;(this.ctx as unknown as { platformBus?: { emit(name: string, payload: unknown): unknown } })
        .platformBus?.emit(event, payload)
    } catch {
      // platformBus non injecté dans la fiber courante : ignoré (accès service strict de cordis)
    }
  }

  // -- Émission -------------------------------------------------------------

  issue(input: {
    resolution: IdentityResolution
    issueId: string
    runId: string
    lease: RunLeaseRecord
    manifestId: string
    ttlMs: number
  }): PermitRecord {
    const now = new Date().toISOString()
    const ttl = input.ttlMs > 0 ? input.ttlMs : this.ttlMs
    // Identifiant aléatoire opaque : non devinable, non auto-décodable (annexe A décision 4) ; le sujet prend le principalId de la liaison (fait de la recherche inverse par jeton machine)
    const record: PermitRecord = {
      id: generateSecret('wfpermit'),
      employeeId: input.resolution.employee.id,
      agentId: input.resolution.binding.agentId,
      principalId: input.resolution.binding.principalId,
      appointmentId: input.resolution.appointment.id,
      appointmentVersion: input.resolution.appointment.version,
      manifestId: input.manifestId,
      issueId: input.issueId,
      runId: input.runId,
      leaseId: input.lease.id,
      leaseVersion: input.lease.leaseVersion,
      status: 'active',
      expiresAt: new Date(Date.now() + ttl).toISOString(),
      createdAt: now,
      revokedAt: '',
      revokedReason: '',
    }
    // TableStore.insert renvoie void (effet de bord d'écriture) — l'enregistrement est renvoyé via la variable locale, jamais le résultat d'insert()
    this.store.permits.insert(record)
    return record
  }

  // -- Vérification -------------------------------------------------------------

  verify(permitId: string, caller: WorkCallerRef, opts?: { requireRun?: boolean }): PermitRecord {
    const permit = this.store.permits.get(permitId)
    if (!permit || permit.status !== 'active') {
      throw new WorkforceError('TOOL_NOT_GRANTED', t('工作授权 permit 不存在或已失效（{permitId}…）', { permitId: permitId.slice(0, 12) }))
    }
    if (permit.expiresAt && permit.expiresAt <= new Date().toISOString()) {
      throw new WorkforceError('TOOL_NOT_GRANTED', t('工作授权 permit 已过期，请重新认领（workforce_claim）'))
    }
    if (permit.principalId && caller.principalId !== permit.principalId) {
      throw new WorkforceError('PRINCIPAL_BINDING_MISMATCH', t('permit 与当前调用主体不匹配（permit 主体绑定为签发时机器主体）'))
    }
    if (opts?.requireRun) {
      if (!permit.runId || !permit.leaseId) {
        throw new WorkforceError('RUN_NOT_OWNED', t('permit 未绑定执行 run/租约，不能用于资源调用'))
      }
    }
    // La cohérence version de nomination/IdentityResolution est vérifiée en combinaison par l'appelant (admission/port détiennent le résultat de résolution)
    return permit
  }

  // -- Révocation -------------------------------------------------------------

  revoke(permitId: string, reason: string): void {
    const permit = this.store.permits.get(permitId)
    if (!permit || permit.status !== 'active') return
    this.store.permits.update(permitId, {
      status: 'revoked',
      revokedAt: new Date().toISOString(),
      revokedReason: reason,
    })
    this.emit('workforce.permit.revoked', { permitId, employeeId: permit.employeeId, runId: permit.runId, reason })
  }

  revokeForEmployee(employeeId: string, reason: string): number {
    let revoked = 0
    for (const permit of this.store.permits.findWhere({ employeeId, status: 'active' })) {
      if (permit.expiresAt && permit.expiresAt <= new Date().toISOString()) continue
      this.revoke(permit.id, reason)
      revoked += 1
    }
    return revoked
  }

  activeForRun(runId: string): PermitRecord | undefined {
    return this.store.permits.findWhere({ runId })
      .filter((permit) => permit.status === 'active' && (!permit.expiresAt || permit.expiresAt > new Date().toISOString()))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0]
  }
}
