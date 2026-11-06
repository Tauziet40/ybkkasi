/**
 * Service d'admission et de réclamation (chemin d'implémentation §6.2/annexe A décision 3 : réclamation = confirmation idempotente d'un bail déjà attribué).
 *
 * claimWork est l'entrée unifiée partagée par REST /claims et l'enveloppe de compatibilité exec_claim :
 * recherche inverse de l'employé par caller de confiance → nomination en vigueur → inventaire de capacités → réclamation idempotente exec-hub (référence des baux dans
 * exec_run_leases) → émission du permit (idempotent pour un même run, pas de double émission).
 * exec-hub est consommé par sondage structuré (ExecHubWorkIntegration, sans import inverse).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import type {
  AppointmentRecord,
  ClaimInput,
  ClaimOutcome,
  EmployeeClaimResult,
  EmployeeLeaseResult,
  ExecHubWorkIntegration,
  ManifestRecord,
  PermitRecord,
  RunLeaseRecord,
  WorkforceAdmission,
  WorkforceCapabilities,
  WorkforceGrayConfig,
  WorkforceIdentityResolver,
  WorkforcePermits,
  WorkforceStore,
} from './contract.ts'
import { appointmentInEffect } from './domain.ts'
// WorkforceError est un import de valeur (classe d'erreur de domaine) : commun à tous les chemins de refus de ce fichier (déploiement progressif désactivé/service non prêt/nomination invalide/propriété).
// Son omission antérieure était un défaut latent — invisible tant qu'aucun chemin de refus n'était déclenché, rencontré et corrigé pour la première fois lors du verrouillage progressif (W7).
import { WorkforceError } from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type { WorkCallerRef, WorkDenyCode, WorkExecutionContext } from '../../platform-core/src/workforce-port.ts'

/** Sonde structurée de l'intégration du travail employé d'exec-hub (additive groupe 3 : ctx.execHub.claimForEmployee). */
interface ExecHubProbe {
  claimForEmployee?: ExecHubWorkIntegration['claimForEmployee']
  renewLease?: ExecHubWorkIntegration['renewLease']
  assertRunOwnership?: ExecHubWorkIntegration['assertRunOwnership']
  releaseForRun?: ExecHubWorkIntegration['releaseForRun']
}

function probeExecHub(ctx: Context): ExecHubProbe {
  const hub = (ctx as unknown as { execHub?: ExecHubProbe }).execHub
  return hub && typeof hub === 'object' ? hub : {}
}

export class AdmissionService extends Service implements WorkforceAdmission {
  static readonly provide = 'workforceAdmission'

  /** Commutateur de déploiement progressif (contrat W7 D-② niveau organisation) : l'assemblage de index.ts passe la config complète, défaut {} = off tout ouvert (rétrocompatible). */
  private readonly grayConfig: WorkforceGrayConfig

  constructor(ctx: Context, config: WorkforceGrayConfig = {}) {
    super(ctx, 'workforceAdmission')
    this.grayConfig = config
  }

  // -- Dépendances -------------------------------------------------------------

  private get store(): WorkforceStore {
    const store = (this.ctx as unknown as { workforceStore?: WorkforceStore }).workforceStore
    if (!store || typeof store.txn !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceStore 未就绪（迁移未完成）'), 503)
    }
    return store
  }

  private get identity(): WorkforceIdentityResolver {
    const resolver = (this.ctx as unknown as { workforceIdentity?: WorkforceIdentityResolver }).workforceIdentity
    if (!resolver || typeof resolver.resolveByCaller !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceIdentity 未就绪'), 503)
    }
    return resolver
  }

  private get permits(): WorkforcePermits {
    const permits = (this.ctx as unknown as { workforcePermits?: WorkforcePermits }).workforcePermits
    if (!permits || typeof permits.issue !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforcePermits 未就绪'), 503)
    }
    return permits
  }

  private get capabilities(): WorkforceCapabilities {
    const capabilities = (this.ctx as unknown as { workforceCapabilities?: WorkforceCapabilities }).workforceCapabilities
    if (!capabilities || typeof capabilities.buildForAppointment !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceCapabilities 未就绪'), 503)
    }
    return capabilities
  }

  private emit(event: string, payload: unknown): void {
    try {
      ;(this.ctx as unknown as { platformBus?: { emit(name: string, payload: unknown): unknown } })
        .platformBus?.emit(event, payload)
    } catch {
      // platformBus non injecté dans la fiber courante : ignoré
    }
  }

  /** Distingue les motifs de nullité de la nomination : non en vigueur (préparation/révocation en cours) et expirée relèvent de deux sémantiques « attente/arrêt » (§13.3). */
  private assertAppointmentEffective(appointment: AppointmentRecord): void {
    if (appointmentInEffect(appointment)) return
    const expired = appointment.effectiveUntil !== '' && appointment.effectiveUntil <= new Date().toISOString()
    throw new WorkforceError(
      expired ? 'APPOINTMENT_EXPIRED' : 'APPOINTMENT_NOT_EFFECTIVE',
      expired ? t('任用已过期，请先续任或申请新版本') : t('任用未生效（资源授权准备未完成），不能认领工作'),
    )
  }

  // -- Commutateur de déploiement progressif (contrat W7 D-②, même référentiel que port.authorizeWorkAction) -----------------------

  /**
   * Jugement de refus progressif : mode allowlist et orgId hors liste → true. Mode off (défaut) tout ouvert,
   * équivalent au comportement de phase 1. La face de requête (récupération des work-items, requêtes d'état) n'est pas interceptée — la face d'observation reste ouverte.
   */
  private grayDenied(orgId: string): boolean {
    return (this.grayConfig.grayMode ?? 'off') === 'allowlist'
      && !(this.grayConfig.enabledOrgs ?? []).includes(orgId)
  }

  /**
   * Refus explicite des organisations désactivées dans le déploiement progressif (sémantique = refus explicite et non repli silencieux vers legacy, même référentiel V29 : refus observable) :
   * émet workforce.gray.denied (surface:'admission', payload aligné sur le côté port) puis lève
   * WORKFORCE_DISABLED (403). Réclamation/prolongation sont les entrées du nouveau chemin de travail, le verrouillage se fait ici avant confirmation/prolongation.
   */
  private assertGrayOpen(orgId: string, employeeId: string): void {
    if (!this.grayDenied(orgId)) return
    try {
      this.emit('workforce.gray.denied', {
        orgId,
        employeeId,
        surface: 'admission',
        at: new Date().toISOString(),
      })
    } catch {
      // L'échec de notification n'affecte pas le refus lui-même (le refus prime sur l'observabilité, fail-closed)
    }
    throw new WorkforceError('WORKFORCE_DISABLED', t('数字员工域对组织 {orgId} 处于灰度关闭（仅白名单组织开放）', { orgId }), 403)
  }

  // -- Réclamation -------------------------------------------------------------

  async claimWork(caller: WorkCallerRef, input: ClaimInput): Promise<ClaimOutcome> {
    // 1. Recherche inverse de l'employé par caller de confiance (anti-contournement : indépendant du fait que la requête porte un contexte work, D.5)
    const resolution = await this.identity.resolveByCaller(caller)
    if (!resolution) {
      return { ok: false, code: 'EMPLOYEE_NOT_ACTIVE', message: t('非受管数字员工或绑定缺失') }
    }
    // 2. Commutateur de déploiement progressif (contrat W7 D-②) : organisation désactivée = refus explicite avant confirmation — réclamation = confirmation idempotente d'un bail déjà attribué,
    //    le refus progressif survient avant la confirmation (verrouillage à l'entrée du nouveau chemin de travail, payload/sémantique alignés sur le côté port)
    this.assertGrayOpen(resolution.appointment.orgId, resolution.employee.id)
    // 3. Nomination en vigueur
    try {
      this.assertAppointmentEffective(resolution.appointment)
    } catch (error) {
      if (error instanceof WorkforceError) return { ok: false, code: error.code, message: error.message }
      throw error
    }
    // 4. Inventaire de capacités (réutilise l'active, sinon construit depuis les autorisations en vigueur — la construction inclut la sonde de verrouillage de version des skills, échec = échec de la réclamation)
    let manifest: ManifestRecord
    try {
      manifest = this.capabilities.activeForAppointment(resolution.appointment.id)
        ?? this.capabilities.buildForAppointment(resolution.appointment.id)
    } catch (error) {
      return { ok: false, code: 'APPOINTMENT_NOT_EFFECTIVE', message: t('能力清单构建失败：{message}', { message: error instanceof Error ? error.message : String(error) }) }
    }
    // 5. Intégration exec-hub (sondage structuré ; absence = chemin de travail indisponible, pas de dégradation silencieuse)
    const hub = probeExecHub(this.ctx)
    if (typeof hub.claimForEmployee !== 'function') {
      return { ok: false, code: 'WORKFORCE_NOT_READY', message: t('执行中枢未提供员工工作集成（execHub.claimForEmployee 缺席），工作路径暂不可用') }
    }
    const agentKey = input.agentKey?.trim() || resolution.binding.agentId || resolution.employee.primaryAgentId
    let claim: EmployeeClaimResult
    try {
      claim = await hub.claimForEmployee({
        issueId: input.issueId,
        employeeId: resolution.employee.id,
        agentKey,
        principalId: caller.principalId,
        ...(input.ttlMs !== undefined ? { ttlMs: input.ttlMs } : {}),
      })
    } catch (error) {
      return { ok: false, code: 'WORKFORCE_NOT_READY', message: t('执行中枢认领异常（fail-closed）：{message}', { message: error instanceof Error ? error.message : String(error) }) }
    }
    if (!claim.ok) {
      return this.mapClaimFailure(claim)
    }
    // 6. Idempotence du permit : ce run a déjà un permit active non expiré pour cet employé → réutilisation directe, pas de double émission
    const existing = this.store.permits.findWhere({ runId: claim.runId }).find((permit) =>
      permit.status === 'active'
      && permit.employeeId === resolution.employee.id
      && permit.principalId === caller.principalId
      && (!permit.expiresAt || permit.expiresAt > new Date().toISOString()))
    if (existing) {
      return {
        ok: true,
        employeeId: resolution.employee.id,
        agentId: resolution.binding.agentId,
        issueId: claim.issueId,
        runId: claim.runId,
        lease: claim.lease,
        permit: existing,
        manifest: this.capabilities.get(existing.manifestId),
        tools: this.capabilities.toolsFor(existing.manifestId),
        idempotent: true,
      }
    }
    const permit = this.permits.issue({
      resolution,
      issueId: claim.issueId,
      runId: claim.runId,
      lease: claim.lease,
      manifestId: manifest.id,
      ttlMs: input.ttlMs ?? 0,
    })
    this.emit('workforce.claim.succeeded', {
      employeeId: resolution.employee.id,
      issueId: claim.issueId,
      runId: claim.runId,
      leaseId: claim.lease.id,
      leaseVersion: claim.lease.leaseVersion,
      permitId: permit.id,
      manifestId: manifest.id,
      idempotent: false,
    })
    return {
      ok: true,
      employeeId: resolution.employee.id,
      agentId: resolution.binding.agentId,
      issueId: claim.issueId,
      runId: claim.runId,
      lease: claim.lease,
      permit,
      manifest,
      tools: this.capabilities.toolsFor(manifest.id),
      idempotent: false,
    }
  }

  /** Échec de réclamation exec-hub → mapping vers codes de refus unifiés (l'erreur doit pouvoir guider « arrêter/demander/attendre/vérifier/retenter », §13.3). */
  private mapClaimFailure(claim: Extract<EmployeeClaimResult, { ok: false }>): ClaimOutcome {
    switch (claim.code) {
      case 'LEASE_HELD_BY_OTHER':
        return { ok: false, code: 'RUN_NOT_OWNED', message: t('该任务已由其他执行持有（{holder}），停止认领，不要换入口重试', { holder: claim.holder ?? t('未知持有者') }), holder: claim.holder }
      case 'BUDGET_EXCEEDED':
        return { ok: false, code: 'BUDGET_EXCEEDED', message: claim.message }
      case 'APPROVAL_REQUIRED':
        return { ok: false, code: 'APPROVAL_REQUIRED', message: claim.message }
      case 'ISSUE_NOT_FOUND':
      case 'ISSUE_CLOSED':
        return { ok: false, code: 'RUN_NOT_OWNED', message: t('{message}（该任务当前不可认领，请停止重试）', { message: claim.message }) }
      case 'ADMISSION_DENIED':
        return { ok: false, code: 'APPOINTMENT_NOT_EFFECTIVE', message: claim.message }
      case 'EXEC_HUB_UNAVAILABLE':
        return { ok: false, code: 'WORKFORCE_NOT_READY', message: claim.message }
      default:
        return { ok: false, code: 'POLICY_INTERNAL_ERROR', message: claim.message }
    }
  }

  // -- Prolongation du bail -------------------------------------------------------------

  async renewWorkLease(caller: WorkCallerRef, permitId: string, ttlMs?: number): Promise<EmployeeLeaseResult> {
    // Correctif D3 : verifyPermit renvoie une Promise, il faut l'awaiter pour obtenir la valeur — auparavant permit.runId valait undefined,
    // tout le chemin de prolongation était refusé par la garde « paramètres insuffisants » d'exec-hub (systématiquement LEASE_STALE)
    const permit = await this.verifyPermit(caller, permitId, { requireRun: true })
    // Verrouillage progressif (contrat W7 D-②, même référentiel que réclamation/port) : une organisation désactivée ne peut prolonger le travail —
    // orgId est revérifié depuis la nomination liée au permit (indépendant de la fenêtre de résolution identity, jugable même si la nomination n'est plus en vigueur)
    const appointment = this.store.appointments.get(permit.appointmentId)
    if (appointment) this.assertGrayOpen(appointment.orgId, permit.employeeId)
    const hub = probeExecHub(this.ctx)
    if (typeof hub.renewLease !== 'function') {
      return { ok: false, code: 'EXEC_HUB_UNAVAILABLE', message: t('执行中枢未提供租约续期能力（execHub.renewLease 缺席）') }
    }
    return hub.renewLease({ runId: permit.runId, principalId: caller.principalId, ...(ttlMs !== undefined ? { ttlMs } : {}) })
  }

  // -- Vérification du permit et propriété du run ---------------------------------------------

  /**
   * Normalisation de l'identité repliée des passerelles (volet D1, annexe A décision 10) : l'InvokeCaller des passerelles de ressources n'a qu'une seule place d'id,
   * workCallerRefFromInvokeCaller replie le sujet machine en principalId=refId=identité technique agentId,
   * alors que le sujet lié au permit est le principalId de la liaison (sujet du justificatif machine vérifié). Un tel caller replié a été produit
   * par la passerelle par recherche inverse sur justificatif vérifié (refId de confiance), la cohérence du sujet est vérifiée après normalisation vers le principalId de la liaison ;
   * normalisation indisponible (aucune liaison valide/liaison sans sujet reconstitué) : on reste tel quel en fail-closed. Les callers humains et les callers de runtime
   * à double place d'identité (principalId≠refId, ex. exec.principal) ne sont pas concernés — un sujet non concordant continue de lever l'erreur.
   */
  private normalizeCollapsedCaller(caller: WorkCallerRef): WorkCallerRef {
    if (caller.kind !== 'machine' || caller.refType !== 'agent' || !caller.refId) return caller
    if (caller.principalId !== caller.refId) return caller
    const binding = this.store.bindings.findWhere({ agentId: caller.refId, status: 'active' })[0]
    if (!binding?.principalId) return caller
    return { ...caller, principalId: binding.principalId }
  }

  verifyPermit(caller: WorkCallerRef, permitId: string, opts?: { requireRun?: boolean }): Promise<PermitRecord> {
    return Promise.resolve(this.permits.verify(permitId, this.normalizeCollapsedCaller(caller), opts))
  }

  /**
   * Assertion de propriété du run pour les chemins exec_complete/livraison (D07) :
   * ce run doit avoir un permit valide émis pour ce sujet (cohérence du sujet),
   * puis assertRunOwnership d'exec-hub vérifie le rattachement du bail et les versions anciennes/récentes.
   */
  async assertRunOwnership(caller: WorkCallerRef, runId: string): Promise<WorkExecutionContext> {
    const permit = this.store.permits.findWhere({ runId }).find((candidate) =>
      candidate.status === 'active'
      && candidate.principalId === caller.principalId
      && (!candidate.expiresAt || candidate.expiresAt > new Date().toISOString()))
    if (!permit) {
      throw new WorkforceError('RUN_NOT_OWNED', t('该 run 不归属当前调用主体（无有效 permit 绑定）'))
    }
    const hub = probeExecHub(this.ctx)
    if (typeof hub.assertRunOwnership !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('执行中枢未提供 run 所有权校验能力（execHub.assertRunOwnership 缺席）'), 503)
    }
    const verdict = await hub.assertRunOwnership({ runId, principalId: caller.principalId })
    if (!verdict.ok) {
      throw new WorkforceError(
        verdict.code === 'LEASE_STALE' ? 'LEASE_STALE' : 'RUN_NOT_OWNED',
        verdict.message,
      )
    }
    return this.workContextOf(permit, verdict.lease)
  }

  /** permit + bail → contexte d'exécution de confiance vérifié (§8.3 : tous les champs revérifiés côté serveur, un JSON client de même forme n'est pas cru). */
  private workContextOf(permit: PermitRecord, lease?: RunLeaseRecord): WorkExecutionContext {
    const appointment = this.store.appointments.get(permit.appointmentId)
    const employee = this.store.employees.get(permit.employeeId)
    return {
      employeeId: permit.employeeId,
      agentId: permit.agentId,
      principalId: permit.principalId,
      appointmentId: permit.appointmentId,
      appointmentVersion: permit.appointmentVersion,
      workOrgId: appointment?.orgId ?? employee?.orgId ?? '',
      dataClass: appointment?.dataClass ?? 'internal',
      issueId: permit.issueId,
      runId: permit.runId,
      leaseVersion: lease?.leaseVersion ?? permit.leaseVersion,
      permitId: permit.id,
      capabilityManifestId: permit.manifestId,
      policyVersion: permit.appointmentVersion,
    }
  }
}
