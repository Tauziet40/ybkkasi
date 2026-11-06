/**
 * Service de registre des appels contrôlés (implémentation de référence du chemin d'implémentation §9.3/§9.4/§11.5/§11.6).
 *
 * Machine à états d'appel (§9.3) : reserved → completed / denied / approval_required /
 * rate_limited / failed / outcome_unknown / cancelled. L'état HTTP et l'état du domaine sont conservés séparément,
 * un HTTP 200 ne fait pas passer un succès métier.
 *
 * Idempotence d'étape (§11.5) : contrainte unique runId+stepKey ; même étape, mêmes paramètres, déjà achevée → rejeu du résultat d'origine ;
 * en cours d'exécution → renvoi de l'état courant ; même étape, paramètres différents → STEP_ARGUMENT_CONFLICT (409).
 * Les appels réseau sont toujours hors transaction txnStore (§9.4) : la transaction ne fait que courts contrôles/réservation/commit.
 * Association usage (§11.1) : simple mapping invocation↔usageEvent, pas de duplication des écritures de consommation, pas de double comptage.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import type {
  AdapterInvokeResult,
  AdapterRegistry,
  InvocationOutcome,
  InvocationRecord,
  InvocationRequest,
  InvocationStatus,
  ManifestRecord,
  ManifestToolHandle,
  PermitRecord,
  WorkforceIdentityResolver,
  WorkforceInvocations,
  WorkforceStore,
} from './contract.ts'
import { WorkforceError, STEP_KEY_PATTERN } from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { argsHashOf, validateAgainstSchema } from './domain.ts'
import type { WorkCallerRef, WorkDenyCode, WorkExecutionContext } from '../../platform-core/src/workforce-port.ts'

/** Toute correspondance vaut « requête d'écriture externe déjà émise mais résultat incertain » (§11.5-4 : vérifier d'abord, réécriture automatique interdite). */
const UNCERTAIN_TIMEOUT_PATTERN = /超时|timeout|abort|aborted|ECONNRESET|ETIMEDOUT/i

export class InvocationService extends Service implements WorkforceInvocations {
  static readonly provide = 'workforceInvocations'

  constructor(ctx: Context) {
    super(ctx, 'workforceInvocations')
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

  private get adapters(): AdapterRegistry {
    const registry = (this.ctx as unknown as { workforceAdapters?: AdapterRegistry }).workforceAdapters
    if (!registry || typeof registry.get !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceAdapters 未就绪'), 503)
    }
    return registry
  }

  private admission(): { verifyPermit: (caller: WorkCallerRef, permitId: string, opts?: { requireRun?: boolean }) => Promise<PermitRecord> } {
    const admission = (this.ctx as unknown as {
      workforceAdmission?: { verifyPermit?: WorkforceAdmission['verifyPermit'] }
    }).workforceAdmission
    if (!admission || typeof admission.verifyPermit !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceAdmission 未就绪'), 503)
    }
    return { verifyPermit: admission.verifyPermit.bind(admission) }
  }

  private capabilities(): { get: (manifestId: string) => ManifestRecord; resolveTool: (manifestId: string, handle: string) => ManifestToolHandle | undefined } {
    const capabilities = (this.ctx as unknown as {
      workforceCapabilities?: { get?: WorkforceCapabilities['get']; resolveTool?: WorkforceCapabilities['resolveTool'] }
    }).workforceCapabilities
    if (!capabilities || typeof capabilities.get !== 'function' || typeof capabilities.resolveTool !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceCapabilities 未就绪'), 503)
    }
    return { get: capabilities.get.bind(capabilities), resolveTool: capabilities.resolveTool.bind(capabilities) }
  }

  private emit(event: string, payload: unknown): void {
    try {
      ;(this.ctx as unknown as { platformBus?: { emit(name: string, payload: unknown): unknown } })
        .platformBus?.emit(event, payload)
    } catch {
      // platformBus non injecté dans la fiber courante : ignoré
    }
  }

  // -- Appel contrôlé (implémentation de référence §9.3/§9.4) ---------------------------------------

  async invoke(caller: WorkCallerRef, request: InvocationRequest): Promise<InvocationOutcome> {
    const started = Date.now()
    // 1. Vérification du permit (existence/active/non expiré/sujet concordant/liaison run+bail)
    const permit = await this.admission().verifyPermit(caller, request.permitId, { requireRun: true })
    const capabilities = this.capabilities()
    const manifest = capabilities.get(permit.manifestId)
    const tool = capabilities.resolveTool(permit.manifestId, request.toolHandle)
    if (!tool) {
      // inventaire présent mais poignée absente = non accordée ; inventaire lui-même manquant = poignée non résoluble
      throw new WorkforceError('TOOL_NOT_GRANTED', t('工具句柄 {handle} 未列入本任用能力清单（manifest v{version}）', { handle: request.toolHandle, version: manifest.version }))
    }
    // 2. Validation lexicale du stepKey (§9.3 : référence métier proposée par l'appelant, pas une identité de confiance) ＋ schéma de paramètres ＋ périmètre métier
    if (!STEP_KEY_PATTERN.test(request.stepKey)) {
      throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('stepKey 非法：须为 1-96 位字母/数字/点/下划线/连字符，且以字母或数字开头'))
    }
    let args: Record<string, unknown>
    // validateAgainstSchema(valeur, schéma) renvoie « première erreur en chinois | null » (pas un convertisseur) :
    // d'abord le contrôle de racine object, puis la validation ; l'implémentation d'origine détourait à la fois l'ordre des paramètres et la convention de retour, invoke refusait systématiquement (avéré par le selftest)
    const rawArgs = request.arguments ?? {}
    if (!rawArgs || typeof rawArgs !== 'object' || Array.isArray(rawArgs)) {
      throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('参数必须为 JSON 对象（object 根）'))
    }
    const violation = validateAgainstSchema(rawArgs, tool.parameters ?? { type: 'object', properties: {} })
    if (violation) {
      throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('参数校验未通过：{violation}', { violation }))
    }
    args = rawArgs as Record<string, unknown>
    this.assertBusinessScope(tool, args)
    const argsHash = argsHashOf(args)

    // 3. Réservation dans la transaction (tout appel réseau y est strictement interdit, §9.4) : la contrainte unique runId+stepKey porte l'idempotence d'étape
    const reserved = this.store.txn(() => {
      const prior = this.store.invocations.findWhere({ runId: permit.runId, stepKey: request.stepKey })[0]
      if (prior) {
        if (prior.argsHash !== argsHash) {
          throw new WorkforceError('STEP_ARGUMENT_CONFLICT', t('步骤 {stepKey} 已绑定不同参数（冲突拒绝，不能覆盖原动作）', { stepKey: request.stepKey }), 409)
        }
        return { replay: true as const, record: prior }
      }
      // TableStore.insert renvoie void (effet de bord d'écriture) — l'enregistrement est renvoyé via la variable locale, jamais le résultat d'insert()
      const record: InvocationRecord = {
        id: `wfinv_${permit.runId}_${request.stepKey.replace(/[^A-Za-z0-9]/g, '')}_${Date.now().toString(36)}`,
        employeeId: permit.employeeId,
        appointmentId: permit.appointmentId,
        appointmentVersion: permit.appointmentVersion,
        runId: permit.runId,
        permitId: permit.id,
        stepKey: request.stepKey,
        kind: tool.kind,
        registryId: tool.registryId,
        action: tool.action,
        risk: tool.risk,
        argsHash,
        argsSummaryJson: JSON.stringify(this.summarizeArgs(args)),
        status: 'reserved',
        errorCode: '',
        message: '',
        gatewayRefJson: '{}',
        usageEventIdsJson: '[]',
        approvalRef: '',
        latencyMs: 0,
        createdAt: new Date().toISOString(),
        settledAt: '',
      }
      this.store.invocations.insert(record)
      return { replay: false as const, record }
    })

    if (reserved.replay) {
      return this.replayOutcome(reserved.record)
    }

    // 4. Hors transaction : revérification nomination/bail (revalidate §9.4) → adaptateur absent = denied → appel réseau
    const appointment = this.store.appointments.get(permit.appointmentId)
    if (!appointment || appointment.status !== 'effective') {
      return this.settle(reserved.record, 'denied', {
        code: 'APPOINTMENT_NOT_EFFECTIVE',
        message: t('任用已不在生效状态，停止本步骤调用'),
      }, started)
    }
    const adapter = this.adapters.get(tool.kind)
    if (!adapter) {
      return this.settle(reserved.record, 'denied', {
        code: 'TOOL_NOT_GRANTED',
        message: t('该资源类型（{kind}）未登记适配器，拒绝调用', { kind: tool.kind }),
      }, started)
    }

    const work = this.workContextOf(permit, appointment, request.traceId)
    let result: AdapterInvokeResult
    try {
      result = await adapter.invoke({ work, tool, args, invocationId: reserved.record.id })
    } catch (error) {
      result = { ok: false, message: t('适配器执行异常：{message}', { message: error instanceof Error ? error.message : String(error) }) }
    }

    // 5. settle : AdapterInvokeResult → InvocationOutcome (sémantique d'états §9.3)
    return this.settleFromAdapter(reserved.record, result, started)
  }

  /** Rejeu d'étape (§11.5-1/2) : fait existant du même run, même étape, mêmes paramètres. */
  private replayOutcome(record: InvocationRecord): InvocationOutcome {
    switch (record.status) {
      case 'completed':
        return {
          status: 'completed',
          invocationId: record.id,
          ...(record.gatewayRefJson !== '{}' ? { gatewayRef: this.parseJson(record.gatewayRefJson, {}) } : {}),
          // Correctif D2 : le rejeu et le chemin d'achèvement d'origine (settle) sont de même source — workContextFromRecord reconstruit le contexte d'exécution de confiance depuis le
          // permit/la nomination liés à l'enregistrement ; auparavant une référence erronée à l'identifiant tool hors de portée faisait échouer le rejeu des étapes completed
          work: this.workContextFromRecord(record),
        }
      case 'outcome_unknown':
        return { status: 'outcome_unknown', invocationId: record.id, message: t('该步骤存在未决历史执行，请先核验，禁止自动重试写入') }
      case 'approval_required':
        return { status: 'approval_required', invocationId: record.id, message: record.message || t('该步骤等待业务审批'), ...(record.approvalRef ? { approvalRef: record.approvalRef } : {}) }
      case 'rate_limited':
        return { status: 'rate_limited', invocationId: record.id, message: record.message || t('命中流控，请按服务端重试策略退避') }
      case 'denied':
        return { status: 'denied', invocationId: record.id, code: (record.errorCode || 'TOOL_NOT_GRANTED') as WorkDenyCode, message: record.message || t('该步骤已被拒绝，停止重试') }
      case 'cancelled':
        return { status: 'denied', invocationId: record.id, code: 'APPOINTMENT_NOT_EFFECTIVE' as WorkDenyCode, message: t('该步骤所属任务或任用已撤销，停止后续调用') }
      case 'failed':
        return { status: 'failed', invocationId: record.id, message: record.message || t('该步骤此前确认失败') }
      case 'reserved':
      default:
        // Dernière tentative interrompue (plantage de processus) : un risque de type écriture est traité en résultat inconnu (§11.7 : une action d'écriture envoyée sans confirmation n'est pas réexécutée)
        if (record.risk !== 'read') {
          return { status: 'outcome_unknown', invocationId: record.id, message: t('该步骤存在中断残留的执行记录，请先核验外部结果') }
        }
        throw new WorkforceError('RATE_LIMITED', t('同一步骤的只读调用正在执行，请稍后重试'), 429)
    }
  }

  /** Contraintes de périmètre métier (§9.2/§D.10 : éléments de base factoryIds/pathPrefixes/maxRows/allowedModels, exécution côté serveur). */
  private assertBusinessScope(tool: ManifestToolHandle, args: Record<string, unknown>): void {
    const constraints = tool.constraints ?? {}
    const deny = (detail: string): never => {
      throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('参数超出任用边界：{detail}', { detail }))
    }
    // Périmètre d'usine : si factoryIds est déclaré, args.factoryId doit correspondre
    const factoryIds = constraints['factoryIds']
    if (Array.isArray(factoryIds) && factoryIds.length > 0 && typeof args['factoryId'] === 'string') {
      if (!factoryIds.includes(args['factoryId'])) deny(t('factoryId {factoryId} 不在授权工厂范围内', { factoryId: String(args['factoryId']) }))
    }
    // Périmètre de répertoires : si pathPrefixes est déclaré, args.path doit correspondre à un préfixe (l'adaptateur NAS revérifie une fois de plus)
    const pathPrefixes = constraints['pathPrefixes']
    if (Array.isArray(pathPrefixes) && pathPrefixes.length > 0 && typeof args['path'] === 'string') {
      const path = String(args['path'])
      if (!pathPrefixes.some((prefix) => typeof prefix === 'string' && path.startsWith(prefix))) {
        deny(t('路径 {path} 超出授权目录范围', { path }))
      }
    }
    // Plafond de lignes : bridage côté serveur (la vigilance du client n'est pas crue)
    const maxRows = constraints['maxRows']
    if (typeof maxRows === 'number' && maxRows > 0) {
      for (const key of ['limit', 'maxRows', 'size']) {
        const value = args[key]
        if (typeof value === 'number' && value > maxRows) args[key] = maxRows
      }
    }
    // Liste blanche de modèles : si allowedModels est déclaré, args.model doit correspondre (défaut = registryId de la poignée)
    const allowedModels = constraints['allowedModels']
    if (tool.kind === 'model' && Array.isArray(allowedModels) && allowedModels.length > 0 && typeof args['model'] === 'string') {
      if (!allowedModels.includes(args['model'])) deny(t('模型 {model} 不在授权模型范围内', { model: String(args['model']) }))
    }
  }

  /** Résumé de paramètres (§11.4 : résumé canonique des paramètres vers l'audit, valeurs sensibles masquées, pas de copie du contenu sensible brut). */
  private summarizeArgs(args: Record<string, unknown>, depth = 0): Record<string, unknown> {
    if (depth > 3) return { '…': '（摘要截断）' }
    const out: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(args)) {
      if (value === undefined) continue
      if (/token|secret|password|apikey|authorization/i.test(key)) {
        out[key] = '***'
      } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        out[key] = this.summarizeArgs(value as Record<string, unknown>, depth + 1)
      } else if (Array.isArray(value)) {
        out[key] = value.length > 8 ? `(${value.length} items)` : value
      } else if (typeof value === 'string' && value.length > 200) {
        out[key] = `${value.slice(0, 200)}…(${value.length} chars)`
      } else {
        out[key] = value
      }
    }
    return out
  }

  /** AdapterInvokeResult → InvocationOutcome + écriture au registre + événement (sémantique d'états complète §9.3). */
  private settleFromAdapter(record: InvocationRecord, result: AdapterInvokeResult, started: number): InvocationOutcome {
    const message = result.message ?? ''
    if (result.ok && !result.outcomeUnknown) {
      return this.settle(record, 'completed', {
        message: 'ok',
        gatewayRef: result.gatewayRef,
        usageEventIds: result.usageEventIds,
        value: result.value,
        content: result.content,
      }, started)
    }
    if (result.outcomeUnknown || (UNCERTAIN_TIMEOUT_PATTERN.test(message) && record.risk !== 'read')) {
      return this.settle(record, 'outcome_unknown', {
        message: message || t('外部结果不确定：请求可能已生效，请先查证核验，禁止自动重试写入'),
        gatewayRef: result.gatewayRef,
      }, started)
    }
    if (result.rateLimited) {
      return this.settle(record, 'rate_limited', { message: message || t('命中可重试流控，请按服务端重试策略退避'), gatewayRef: result.gatewayRef }, started)
    }
    if (result.approvalRef) {
      return this.settle(record, 'approval_required', { message: message || t('该动作需要业务审批，请展示审批单并等待'), approvalRef: result.approvalRef, gatewayRef: result.gatewayRef }, started)
    }
    // Refus au niveau ressource (chaîne d'autorisation d'origine de la passerelle/disjoncteur) → denied (arrêt, pas de nouvelle tentative par une autre entrée) ; le reste est failed
    const denied = result.gatewayRef?.['outcome'] === 'denied'
    return this.settle(record, denied ? 'denied' : 'failed', {
      code: denied ? 'TOOL_NOT_GRANTED' : undefined,
      message: message || (denied ? t('资源网关拒绝该调用') : t('执行失败')),
      gatewayRef: result.gatewayRef,
    }, started)
  }

  /** Écriture au registre (update d'une ligne hors transaction) + association usage + événement. */
  private settle(
    record: InvocationRecord,
    status: Exclude<InvocationStatus, 'reserved'>,
    detail: {
      code?: string
      message: string
      gatewayRef?: Record<string, unknown>
      usageEventIds?: string[]
      approvalRef?: string
      value?: unknown
      content?: string
    },
    started: number,
  ): InvocationOutcome {
    const latencyMs = Date.now() - started
    this.store.invocations.update(record.id, {
      status,
      errorCode: detail.code ?? '',
      message: detail.message,
      gatewayRefJson: JSON.stringify(detail.gatewayRef ?? {}),
      usageEventIdsJson: JSON.stringify(detail.usageEventIds ?? []),
      approvalRef: detail.approvalRef ?? '',
      latencyMs,
      settledAt: new Date().toISOString(),
    })
    for (const usageEventId of detail.usageEventIds ?? []) {
      // Association incrémentale de l'usage (§11.1/§11.3) : simple mapping sans copie des écritures ; la contrainte unique sur la paire garantit l'idempotence
      this.linkUsage(record.id, usageEventId, String(detail.gatewayRef?.['resource'] ?? ''))
    }
    this.emit('workforce.invocation.settled', {
      invocationId: record.id, runId: record.runId, employeeId: record.employeeId,
      stepKey: record.stepKey, kind: record.kind, registryId: record.registryId, action: record.action,
      status, latencyMs,
      ...(detail.code ? { errorCode: detail.code } : {}),
    })
    switch (status) {
      case 'completed':
        return {
          status: 'completed',
          invocationId: record.id,
          ...(detail.value !== undefined ? { value: detail.value } : {}),
          ...(detail.content !== undefined ? { content: detail.content } : {}),
          ...(detail.gatewayRef ? { gatewayRef: detail.gatewayRef } : {}),
          work: this.workContextFromRecord(record),
        }
      case 'denied':
        return { status: 'denied', invocationId: record.id, code: (detail.code ?? 'TOOL_NOT_GRANTED') as WorkDenyCode, message: detail.message }
      case 'approval_required':
        return { status: 'approval_required', invocationId: record.id, message: detail.message, ...(detail.approvalRef ? { approvalRef: detail.approvalRef } : {}) }
      case 'rate_limited':
        return { status: 'rate_limited', invocationId: record.id, message: detail.message }
      case 'outcome_unknown':
        return { status: 'outcome_unknown', invocationId: record.id, message: detail.message }
      case 'failed':
      case 'cancelled':
      default:
        return { status: 'failed', invocationId: record.id, message: detail.message, ...(detail.code ? { code: detail.code as WorkDenyCode } : {}) }
    }
  }

  // -- Appartenance et requêtes ---------------------------------------------------------

  /** Jugement d'appartenance : l'employé lui-même, ou un human (l'entrée a déjà gardé workforce.read) de la même organisation que l'organisation de travail. */
  private async assertReadable(caller: WorkCallerRef, workOrgId: string, subject: string): Promise<void> {
    const resolution = await this.identity.resolveByCaller(caller)
    if (resolution && resolution.employee.id === subject) return
    if (caller.kind === 'human') {
      const userOrg = this.humanOrgId(caller)
      if (userOrg !== null && userOrg === workOrgId) return
    }
    throw new WorkforceError('RUN_NOT_OWNED', t('无权查看该调用记录（仅本人或同组织 workforce.read 主体）'))
  }

  /** Recherche inverse de l'organisation du human (sondage structuré iam ; échec de résolution toujours refusé en fail-closed). */
  private humanOrgId(caller: WorkCallerRef): string | null {
    if (!caller.userId) return null
    try {
      const iam = (this.ctx as unknown as { iam?: { users?: () => { get(id: string): { orgId?: string } | undefined } } }).iam
      const user = typeof iam?.users === 'function' ? iam.users().get(caller.userId) : undefined
      return typeof user?.orgId === 'string' ? user.orgId : null
    } catch {
      return null
    }
  }

  private workOrgOf(record: { appointmentId: string }): string {
    return this.store.appointments.get(record.appointmentId)?.orgId ?? ''
  }

  async get(caller: WorkCallerRef, invocationId: string): Promise<InvocationRecord> {
    const record = this.store.invocations.get(invocationId)
    if (!record) throw new WorkforceError('RUN_NOT_OWNED', t('调用记录不存在或无权访问'), 404)
    await this.assertReadable(caller, this.workOrgOf(record), record.employeeId)
    return record
  }

  async listByRun(caller: WorkCallerRef, runId: string): Promise<InvocationRecord[]> {
    const records = this.store.invocations.findWhere({ runId })
    if (records.length === 0) return []
    await this.assertReadable(caller, this.workOrgOf(records[0]!), records[0]!.employeeId)
    return records.sort((a, b) => a.createdAt.localeCompare(b.createdAt))
  }

  linkUsage(invocationId: string, usageEventId: string, resource: string): void {
    const existing = this.store.usageLinks.findWhere({ invocationId, usageEventId })
    if (existing.length > 0) return
    this.store.usageLinks.insert({
      id: `wfusage_${invocationId}_${usageEventId}`.slice(0, 120),
      invocationId,
      usageEventId,
      resource,
      createdAt: new Date().toISOString(),
    })
  }

  /** Écriture retour après vérification d'un outcome_unknown (appel après vérification humaine/réconciliation ; migration autorisée uniquement depuis outcome_unknown). */
  reconcile(id: string, status: 'completed' | 'failed', message: string, gatewayRef?: Record<string, unknown>): void {
    const record = this.store.invocations.get(id)
    if (!record) throw new WorkforceError('RUN_NOT_OWNED', t('调用记录不存在：{id}', { id }), 404)
    if (record.status !== 'outcome_unknown') {
      throw new WorkforceError('STEP_ARGUMENT_CONFLICT', t('仅 outcome_unknown 记录可核验回写（当前 {status}）', { status: record.status }))
    }
    this.store.invocations.update(id, {
      status,
      message,
      ...(gatewayRef ? { gatewayRefJson: JSON.stringify({ ...this.parseJson(record.gatewayRefJson, {}), ...gatewayRef }) } : {}),
      settledAt: new Date().toISOString(),
    })
    this.emit('workforce.invocation.settled', {
      invocationId: id, runId: record.runId, employeeId: record.employeeId,
      stepKey: record.stepKey, kind: record.kind, registryId: record.registryId, action: record.action,
      status, latencyMs: record.latencyMs, reconciled: true,
    })
  }

  // -- Interne ---------------------------------------------------------------

  private workContextOf(permit: PermitRecord, appointment: { orgId: string; dataClass: WorkExecutionContext['dataClass'] }, traceId?: string): WorkExecutionContext {
    return {
      employeeId: permit.employeeId,
      agentId: permit.agentId,
      principalId: permit.principalId,
      appointmentId: permit.appointmentId,
      appointmentVersion: permit.appointmentVersion,
      workOrgId: appointment.orgId,
      dataClass: appointment.dataClass,
      issueId: permit.issueId,
      runId: permit.runId,
      leaseVersion: permit.leaseVersion,
      permitId: permit.id,
      capabilityManifestId: permit.manifestId,
      policyVersion: permit.appointmentVersion,
      ...(traceId ? { traceId } : {}),
    }
  }

  private workContextFromRecord(record: InvocationRecord): WorkExecutionContext {
    const appointment = this.store.appointments.get(record.appointmentId)
    const permit = this.store.permits.get(record.permitId)
    return {
      employeeId: record.employeeId,
      agentId: permit?.agentId ?? '',
      principalId: permit?.principalId ?? '',
      appointmentId: record.appointmentId,
      appointmentVersion: record.appointmentVersion,
      workOrgId: appointment?.orgId ?? '',
      dataClass: appointment?.dataClass ?? 'internal',
      issueId: permit?.issueId ?? '',
      runId: record.runId,
      leaseVersion: permit?.leaseVersion ?? 0,
      permitId: record.permitId,
      capabilityManifestId: permit?.manifestId ?? '',
      policyVersion: record.appointmentVersion,
    }
  }

  private parseJson<T>(text: string, fallback: T): T {
    try {
      return JSON.parse(text) as T
    } catch {
      return fallback
    }
  }
}
