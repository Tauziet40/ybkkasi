/**
 * Service du domaine des nominations (appointment-service) — versions de nomination, autorisations de ressources souhaitées, sondes d'activation et chaînage de révocation.
 *
 * Le cœur est la matérialisation de la machine à états §D.4 « préparation → en vigueur → révocation en cours → révoquée/échec de configuration » :
 *   - une nomination n'est qu'une « politique souhaitée versionnée », pas une permission réelle : l'activation doit, grant par grant, vérifier via les sondes d'adaptateur
 *     que l'autorisation a réellement pris effet dans la passerelle de ressources d'origine (groupe de permissions MCP/politique Connector/mapping de répertoires NAS…) ;
 *   - toutes les sondes passent → nomination effective et assemblage simultané de l'inventaire de capacités (workforceCapabilities) ;
 *     un seul échec → ce grant passe failed, la nomination reste preparing, l'ensemble ne prend pas effet — aucun permit n'est jamais émis ;
 *   - les sondes sont des vérifications en lecture seule (pouvant toucher les passerelles), toujours exécutées hors transaction ; la transaction n'écrit que les états ;
 *   - révocation : révoquer d'abord tous les permits de la nomination (la couche de politique de travail cesse la première), grant et nomination convergent simultanément en revoked en phase 1
 *     (la récupération réelle des autorisations côté passerelle de ressources d'origine est un poste d'exploitation, voir la note en fin de fichier).
 *
 * Sémantique d'échec honnête : adaptateur absent/anomalie de sonde/refus de sonde retombent tous en failed + lastError en chinois, sans faire passer une implémentation vide pour un succès.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId } from '../../platform-core/src/ids.ts'
import { WORK_DATA_CLASS_ORDER, type WorkDataClass } from '../../platform-core/src/workforce-port.ts'
import { WorkforceError } from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type {
  AdapterRegistry,
  AppointmentRecord,
  IdentityResolution,
  ResourceGrantRecord,
  ResourceGrantSpec,
  WorkCallerRef,
  WorkforceAppointments,
  WorkforceCapabilities,
  WorkforcePermits,
} from './contract.ts'
import { appointmentInEffect, appointmentStatusTransition, validateGrantSpec, validateWorkDataClass } from './domain.ts'
import type { WorkforceStoreService } from './repositories.ts'

function nowIso(): string {
  return new Date().toISOString()
}

function parseJsonArray(text: string): string[] {
  try {
    const parsed = JSON.parse(text)
    return Array.isArray(parsed) ? parsed.map(String) : []
  } catch {
    return []
  }
}

function parseJsonObject(text: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}
  } catch {
    return {}
  }
}

/** Enregistrement d'autorisation → spécification souhaitée (paramètre de la sonde ; l'enregistrement est la forme stockée, la spécification la forme de contrat). */
function grantSpecOf(row: ResourceGrantRecord): ResourceGrantSpec {
  return {
    kind: row.kind,
    registryId: row.registryId,
    actions: parseJsonArray(row.actionsJson),
    risk: row.risk,
    constraints: parseJsonObject(row.constraintsJson),
  }
}

/** Verdict de la sonde pour un grant (produit hors transaction, écrit en base dans la transaction). */
interface GrantProbeOutcome {
  grantId: string
  status: 'effective' | 'failed'
  ref: string
  lastError: string
}

export class AppointmentService extends Service implements WorkforceAppointments {
  static readonly provide = 'workforceAppointments'

  constructor(ctx: Context) {
    super(ctx, 'workforceAppointments')
  }

  // -- Accès internes (services de la même extension résolus via ctx à l'exécution ; le sondage structéré garde l'exécution en test unitaire autonome possible) ----------

  private get store(): WorkforceStoreService {
    return this.ctx.workforceStore
  }

  private adapters(): AdapterRegistry | undefined {
    return (this.ctx as unknown as { workforceAdapters?: AdapterRegistry }).workforceAdapters
  }

  private capabilities(): WorkforceCapabilities | undefined {
    return (this.ctx as unknown as { workforceCapabilities?: WorkforceCapabilities }).workforceCapabilities
  }

  private permits(): WorkforcePermits | undefined {
    return (this.ctx as unknown as { workforcePermits?: WorkforcePermits }).workforcePermits
  }

  private emitEvent(name: string, payload: Record<string, unknown>): void {
    try {
      const bus = (this.ctx as unknown as { platformBus?: { emit(event: string, payload: unknown): unknown } }).platformBus
      bus?.emit(name, { ...payload, at: nowIso() })
    } catch {
      /* bus d'événements absent : notification sautée — le fait d'état est déjà en base */
    }
  }

  private actorOf(caller: WorkCallerRef | undefined): string {
    return caller?.userId ?? caller?.principalId ?? ''
  }

  // -- Versions de nomination ------------------------------------------------------------

  create(input: {
    employeeId: string
    position: string
    orgId: string
    dataClass: WorkDataClass
    effectiveFrom: string
    effectiveUntil?: string
    grants: ResourceGrantSpec[]
    approvedBy: string
    approvalRef?: string
  }): AppointmentRecord {
    const employeeId = String(input.employeeId ?? '').trim()
    const orgId = String(input.orgId ?? '').trim()
    if (employeeId === '') throw new Error(t('创建任用必须指定数字员工（employeeId）'))
    if (orgId === '') throw new Error(t('创建任用必须登记工作组织（orgId）——任务归属组织不可空'))

    const employee = this.store.employees.get(employeeId)
    if (!employee) throw new Error(t('数字员工不存在：{id}', { id: employeeId }))
    if (employee.status === 'offboarded') throw new Error(t('已离岗员工不接受新任用（如需重新任用请新建数字员工）'))

    // La classification est validée dès l'enregistrement : une nomination top secret serait refusée avant chaque appel de modèle/ressource ; plutôt que de délivrer une nomination « vouée à l'échec »,
    // refuser explicitement ici (D14 : une classification interdite à l'Agent doit être refusée avant l'appel)
    const dataClass = validateWorkDataClass(input.dataClass)
    if (dataClass === 'topsecret') {
      throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('任用密级不得为绝密（绝密数据禁止数字员工处理）'))
    }

    // Les autorisations souhaitées sont validées et normalisées une à une (kind/registryId/actions/risk ; les actions d'écriture doivent être listées explicitement)
    const grants = (Array.isArray(input.grants) ? input.grants : []).map((spec) => validateGrantSpec(spec))
    if (grants.length === 0) throw new Error(t('任用必须至少登记一项资源授权期望（grants）——空授权的任用不具备工作边界'))

    const effectiveFrom = String(input.effectiveFrom ?? '').trim() || nowIso()
    if (Number.isNaN(Date.parse(effectiveFrom))) throw new Error(t('任用生效时间不合法：{value}（须为 ISO 时间）', { value: String(input.effectiveFrom ?? '') }))
    const effectiveUntil = String(input.effectiveUntil ?? '').trim()
    if (effectiveUntil !== '') {
      if (Number.isNaN(Date.parse(effectiveUntil))) throw new Error(t('任用失效时间不合法：{value}（须为 ISO 时间，空串＝长期）', { value: effectiveUntil }))
      if (Date.parse(effectiveUntil) <= Date.parse(effectiveFrom)) throw new Error(t('任用失效时间必须晚于生效时间'))
    }

    const createdAt = nowIso()
    const appointmentId = newId('apt')
    const appointment: AppointmentRecord = {
      id: appointmentId,
      employeeId,
      version: 0, // attribuée dans la transaction (max+1 de l'employé)
      position: String(input.position ?? '').trim(),
      orgId,
      dataClass,
      effectiveFrom,
      effectiveUntil,
      grantsJson: JSON.stringify(grants),
      approvedBy: String(input.approvedBy ?? '').trim(),
      approvalRef: String(input.approvalRef ?? '').trim(),
      status: 'preparing',
      statusReason: '',
      createdAt,
      updatedAt: createdAt,
    }

    // Même transaction pour « validation d'unicité d'attribution de version + écriture de la nomination + écriture de tous les grants en preparing »
    // Conflit d'unicité employé+version → erreur en chinois (400 par la couche routes), sans dépendre de l'erreur brute SQLite
    this.store.txn(() => {
      const existing = this.store.appointments.findWhere({ employeeId })
      const maxVersion = existing.reduce((max, row) => Math.max(max, row.version), 0)
      appointment.version = maxVersion + 1
      const duplicated = existing.some((row) => row.version === appointment.version)
      if (duplicated) throw new Error(t('该员工任用版本 {version} 已存在，请重试（版本号由服务端分配）', { version: appointment.version }))
      this.store.appointments.insert(appointment)
      for (const spec of grants) {
        this.store.grants.insert({
          id: newId('grt'),
          appointmentId,
          kind: spec.kind,
          registryId: spec.registryId,
          actionsJson: JSON.stringify(spec.actions),
          risk: spec.risk,
          constraintsJson: JSON.stringify(spec.constraints ?? {}),
          ref: '',
          status: 'preparing',
          lastError: '',
          checkedAt: '',
          createdAt,
          updatedAt: createdAt,
        } satisfies ResourceGrantRecord)
      }
    })

    this.emitEvent('workforce.appointment.changed', {
      appointmentId, employeeId, version: appointment.version, status: 'preparing', action: 'created', orgId, dataClass,
    })
    return appointment
  }

  get(id: string): AppointmentRecord {
    const appointment = this.store.appointments.get(id)
    if (!appointment) throw new Error(t('任用不存在：{id}', { id }))
    return appointment
  }

  list(filter?: { employeeId?: string; status?: AppointmentStatus }): AppointmentRecord[] {
    let rows = this.store.appointments.all()
    if (filter?.employeeId) rows = rows.filter((row) => row.employeeId === filter.employeeId)
    if (filter?.status) rows = rows.filter((row) => row.status === filter.status)
    return rows.sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0))
  }

  /** Nomination actuellement en vigueur pour l'employé : status=effective et dernière version dans la fenêtre de validité (les versions expirées ne sont pas renvoyées). */
  effectiveForEmployee(employeeId: string): AppointmentRecord | undefined {
    const rows = this.store.appointments
      .findWhere({ employeeId, status: 'effective' })
      .sort((a, b) => b.version - a.version)
    return rows.find((row) => appointmentInEffect(row))
  }

  // -- Activation (cœur de la machine à états §D.4) ----------------------------------------------

  /**
   * Activation : vérification grant par grant de l'autorisation réelle par sondes.
   * Discipline de transaction : les sondes peuvent toucher les passerelles (sémantique réseau), toutes exécutées hors transaction ; la transaction n'écrit que les états.
   * Tout effective → assemblage de l'inventaire de capacités → nomination effective ; un seul failed → la nomination reste preparing (aucun permit émis) ;
   * un échec d'assemblage de l'inventaire de capacités laisse aussi en preparing (absence honnête, activation retentable).
   */
  async activate(caller: WorkCallerRef, id: string): Promise<AppointmentRecord> {
    const appt = this.get(id)
    if (appt.status === 'effective') throw new Error(t('任用已生效，不得重复激活'))
    if (appt.status === 'revoking' || appt.status === 'revoked') throw new Error(t('任用已进入撤销流程，不得激活（请开新版本）'))
    if (appt.status === 'failed') throw new Error(t('任用已判配置失败（终态），请修正授权范围后开新版本'))
    if (appt.status !== 'preparing') throw new Error(t('任用状态不允许激活：{status}', { status: appt.status }))

    const employee = this.store.employees.get(appt.employeeId)
    if (!employee || employee.status !== 'active') {
      throw new WorkforceError('EMPLOYEE_NOT_ACTIVE', t('员工不在岗（停职或已离岗），任用不得激活'))
    }
    if (!appointmentInEffect({ ...appt, status: 'effective' })) {
      throw new Error(t('任用有效期窗口未覆盖当前时间，请核对 effectiveFrom/effectiveUntil'))
    }

    const grants = this.store.grants.findWhere({ appointmentId: id })
    if (grants.length === 0) throw new Error(t('任用未登记任何资源授权，禁止激活（create 已强制，此处为防御校验）'))

    // Assemble le contexte d'identité vérifié (les sondes s'en servent pour localiser employé/liaison/version de nomination) : l'activation de nomination est initiée par un superviseur humain,
    // resolution doit prendre l'enregistrement du domaine employé et non l'identité de l'appelant — l'appelant est l'approbateur, pas l'employé exécuté
    const binding = this.store.bindings.findWhere({ employeeId: appt.employeeId, status: 'active' })[0]
    const resolution: IdentityResolution = { employee, binding, appointment: appt }

    // 1. Sondes grant par grant hors transaction (adaptateur absent → failed('adaptateur non enregistré') ; anomalie → failed(message d'anomalie))
    const registry = this.adapters()
    const outcomes: GrantProbeOutcome[] = []
    for (const grant of grants) {
      outcomes.push(await this.probeGrantRow(grant, registry, resolution))
    }

    // 2. Écriture en base des états des grants dans la transaction (avec reconstitution du ref — référence du vrai groupe de permissions/politique/mapping de catalogue, pas une case cochée d'UI)
    const checkedAt = nowIso()
    this.store.txn(() => {
      for (const outcome of outcomes) {
        this.store.grants.update(outcome.grantId, {
          status: outcome.status,
          ref: outcome.ref,
          lastError: outcome.lastError,
          checkedAt,
          updatedAt: checkedAt,
        })
      }
    })

    const allEffective = outcomes.every((outcome) => outcome.status === 'effective')
    if (!allEffective) {
      const failedSummary = outcomes
        .filter((outcome) => outcome.status === 'failed')
        .map((outcome) => outcome.lastError)
        .join('；')
      const statusReason = t('资源授权核验未全部通过（{failed}）；任用整体不生效，不得签发工作授权', { failed: failedSummary })
      this.store.txn(() => {
        this.store.appointments.update(id, { status: 'preparing', statusReason, updatedAt: nowIso() })
      })
      const updated = this.get(id)
      this.emitEvent('workforce.appointment.changed', {
        appointmentId: id, employeeId: appt.employeeId, version: appt.version, status: 'preparing',
        action: 'activate_rejected', failedGrants: outcomes.filter((o) => o.status === 'failed').length,
      })
      return updated
    }

    // 3. Assemblage de l'inventaire de capacités (service de la même extension ; l'assemblage gère lui-même sa transaction, donc appelé hors de la présente transaction)
    let manifestError = ''
    try {
      const capabilities = this.capabilities()
      if (!capabilities) manifestError = t('能力清单服务未就绪')
      else capabilities.buildForAppointment(id)
    } catch (error) {
      manifestError = error instanceof Error ? error.message : String(error)
    }

    // 4. Nomination en vigueur (échec d'assemblage de l'inventaire = on reste en preparing — une « fausse disponibilité » du type nomination effective mais inventaire manquant est interdite)
    const statusReason = manifestError === ''
      ? t('资源授权探针全部通过，任用生效（能力清单已装配）')
      : t('能力清单装配失败：{message}；任用保持准备中，请重试激活', { message: manifestError })
    const finalStatus: AppointmentStatus = manifestError === '' ? 'effective' : 'preparing'
    this.store.txn(() => {
      this.store.appointments.update(id, { status: finalStatus, statusReason, updatedAt: nowIso() })
    })

    const updated = this.get(id)
    this.emitEvent('workforce.appointment.changed', {
      appointmentId: id, employeeId: appt.employeeId, version: appt.version, status: finalStatus,
      action: finalStatus === 'effective' ? 'activated' : 'activate_deferred', actor: this.actorOf(caller),
    })
    return updated
  }

  /** Sonde d'un grant : vérification en lecture seule de la configuration réelle, pas d'élargissement automatique (§D.4 3e). */
  private async probeGrantRow(
    grant: ResourceGrantRecord,
    registry: AdapterRegistry | undefined,
    resolution: IdentityResolution,
  ): Promise<GrantProbeOutcome> {
    const base: GrantProbeOutcome = { grantId: grant.id, status: 'failed', ref: '', lastError: '' }
    if (!registry) return { ...base, lastError: t('未登记适配器') }
    const adapter = registry.get(grant.kind)
    if (!adapter) return { ...base, lastError: t('未登记适配器') }
    if (!resolution.binding) return { ...base, lastError: t('员工未绑定技术 Agent，无法核验资源授权') }
    try {
      const probe: AdapterProbeResult = await adapter.probeGrant(grantSpecOf(grant), resolution)
      if (probe.ok) return { ...base, status: 'effective', ref: String(probe.ref ?? '') }
      return { ...base, lastError: String(probe.message ?? t('授权探针未通过')) }
    } catch (error) {
      return { ...base, lastError: t('授权探针执行异常：{message}', { message: error instanceof Error ? error.message : String(error) }) }
    }
  }

  // -- Révocation (§D.4 5e) --------------------------------------------------

  /**
   * Révocation : révoquer d'abord tous les permits de la nomination (la couche de politique de travail cesse la première, émission de workforce.permit.revoked),
   * puis faire converger les états des grants et de la nomination.
   *
   * Référentiel de phase 1 (enregistrement honnête) : la sémantique de retrait de droits devrait être « la couche de travail refuse les nouvelles actions → convergence asynchrone des passerelles de ressources d'origine et des justificatifs distants »,
   * en phase 1 les grants passent revoking→revoked et la nomination revoked de manière synchrone ; **la récupération réelle des autorisations côté passerelle de ressources d'origine**
   * (retrait du groupe de permissions MCP, déliaison de la politique Connector, nettoyage du mapping de répertoires NAS) dépend de canaux de retrait à ajouter par chaque adaptateur,
   * ce qui n'est pas implémenté en phase 1 est enregistré comme poste d'exploitation (voir le rapport de chantier), sans simuler « passerelle déjà récupérée ».
   *
   * revoking est un état intermédiaire reprenable : en cas d'échec partiel de révocation des permits, on demeure en revoking, la présente méthode peut être retentée pour converger.
   */
  async revoke(caller: WorkCallerRef, id: string, reason: string): Promise<AppointmentRecord> {
    const trimmedReason = String(reason ?? '').trim()
    if (trimmedReason === '') throw new Error(t('撤销任用必须登记原因'))
    const appt = this.get(id)

    if (appt.status === 'revoked') throw new Error(t('任用已撤销，请勿重复操作'))
    if (appt.status === 'failed') throw new Error(t('任用配置失败为终态，无须撤销（请开新版本）'))
    if (appt.status !== 'effective' && appt.status !== 'preparing' && appt.status !== 'revoking') {
      throw new Error(t('任用状态不允许撤销：{status}', { status: appt.status }))
    }

    // Nomination non en vigueur : aucun permit à révoquer, passage direct preparing→revoked (la branche preparing de la machine à états est déjà enregistrée)
    if (appt.status === 'preparing') {
      appointmentStatusTransition(appt.status, 'revoked')
      const at = nowIso()
      this.store.txn(() => {
        for (const grant of this.store.grants.findWhere({ appointmentId: id })) {
          if (grant.status === 'revoked') continue
          this.store.grants.update(grant.id, {
            status: 'revoked', lastError: '', checkedAt: at, updatedAt: at,
          })
        }
        this.store.appointments.update(id, { status: 'revoked', statusReason: t('已撤销（未生效任用）：{reason}', { reason: trimmedReason }), updatedAt: at })
      })
      const updated = this.get(id)
      this.emitEvent('workforce.appointment.changed', {
        appointmentId: id, employeeId: appt.employeeId, version: appt.version, status: 'revoked',
        action: 'revoked', actor: this.actorOf(caller), reason: trimmedReason,
      })
      return updated
    }

    // Nomination en vigueur : effective → revoking (reprisable) ; lors de la reprise, on saute la transition dupliquée
    if (appt.status === 'effective') {
      appointmentStatusTransition(appt.status, 'revoking')
      this.store.txn(() => {
        this.store.appointments.update(id, { status: 'revoking', statusReason: t('撤销中：{reason}', { reason: trimmedReason }), updatedAt: nowIso() })
      })
    }

    // 1. Révoquer tous les permits active de cette nomination (localisés par employeeId+appointmentVersion, sans toucher les autres versions par erreur)
    const permits = this.permits()
    const activePermits = permits
      ? this.store.permits.findWhere({ employeeId: appt.employeeId, appointmentVersion: appt.version, status: 'active' })
      : []
    const revokeFailures: Array<{ permitId: string; error: string }> = []
    if (!permits) {
      revokeFailures.push({ permitId: '*', error: t('工作授权服务未就绪，无法撤销 permit') })
    }
    for (const permit of activePermits) {
      try {
        permits!.revoke(permit.id, t('任用 v{version} 撤销：{reason}', { version: appt.version, reason: trimmedReason }))
      } catch (error) {
        revokeFailures.push({ permitId: permit.id, error: error instanceof Error ? error.message : String(error) })
      }
    }
    this.emitEvent('workforce.permit.revoked', {
      appointmentId: id, employeeId: appt.employeeId, appointmentVersion: appt.version,
      revoked: activePermits.length - revokeFailures.length,
      failed: revokeFailures, reason: trimmedReason,
    })

    // 2. Permits non tous révoqués → on demeure en revoking en attente de nouvelle tentative (pas de restauration de qualifications de travail déjà révoquées, ni de convergence simulée)
    if (revokeFailures.length > 0) {
      const statusReason = t('撤销中：部分工作授权撤销失败待重试（{failures}）', {
        failures: revokeFailures.map((f) => `${f.permitId}: ${f.error}`).join('；'),
      })
      this.store.txn(() => {
        this.store.appointments.update(id, { status: 'revoking', statusReason, updatedAt: nowIso() })
      })
      return this.get(id)
    }

    // 3. Convergence synchrone des grants revoking→revoked en phase 1 (la récupération réelle des autorisations côté passerelle est un poste d'exploitation, voir le commentaire de la méthode)
    const at = nowIso()
    this.store.txn(() => {
      for (const grant of this.store.grants.findWhere({ appointmentId: id })) {
        if (grant.status === 'revoked') continue
        this.store.grants.update(grant.id, { status: 'revoked', lastError: '', checkedAt: at, updatedAt: at })
      }
      this.store.appointments.update(id, { status: 'revoked', statusReason: t('已撤销：{reason}', { reason: trimmedReason }), updatedAt: at })
    })

    const updated = this.get(id)
    this.emitEvent('workforce.appointment.changed', {
      appointmentId: id, employeeId: appt.employeeId, version: appt.version, status: 'revoked',
      action: 'revoked', actor: this.actorOf(caller), reason: trimmedReason,
    })
    return updated
  }
}

/*
 * Registre des postes d'exploitation (entrées synchronisées du rapport de chantier) :
 * 1. Canal de récupération des autorisations côté passerelle de ressources d'origine : chaque adaptateur de ressources (mcp/connector/model/skill/nas/app) doit fournir
 *    un appel de retrait de droits (ex. retrait du sujet du groupe de permissions MCP) ; l'actuel probeGrant ne fait que vérifier en lecture seule, sans action de retrait —
 *    après révocation d'une nomination, la configuration côté passerelle est nettoyée à la main par l'exploitation via la référence grant.ref, la phase 1 ne simule pas une récupération effectuée.
 * 2. Nominations demeurées en revoking après échec de révocation : reprise manuelle de revoke requise, ou investigation via l'audit d'une anomalie du service de permits ;
 *    pendant revoking, effectiveForEmployee ne renvoie déjà plus cette nomination, les nouvelles actions sont refusées par construction (fail-closed).
 */
