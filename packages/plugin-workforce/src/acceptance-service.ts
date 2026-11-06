/**
 * Service de livraison et d'acceptation (chemin d'implémentation §6.5 : achèvement et acceptation séparés).
 *
 * La fin de l'exécution technique ne forme qu'un « livrable soumis » (deliverable submitted → completeRun d'exec-hub
 * passe la tâche en review) ; l'acceptation est décidée par un humain titulaire de workforce.accept — accord→tâche done,
 * retour→tâche ramenée en in_progress avec motif. Tous les faits d'appel sont conservés sans suppression (V30 : un simple résumé sans preuve
 * ne peut pas valoir acceptation métier automatique).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId } from '../../platform-core/src/ids.ts'
import type {
  ArtifactRecord,
  DeliverableRecord,
  PermitRecord,
  WorkforceDelivery,
  WorkforceIdentityResolver,
  WorkforceStore,
} from './contract.ts'
import { WorkforceError } from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type { WorkCallerRef } from '../../platform-core/src/workforce-port.ts'

export class DeliveryService extends Service implements WorkforceDelivery {
  static readonly provide = 'workforceDelivery'

  constructor(ctx: Context) {
    super(ctx, 'workforceDelivery')
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

  private admission(): { verifyPermit: (caller: WorkCallerRef, permitId: string, opts?: { requireRun?: boolean }) => Promise<PermitRecord> } {
    const admission = (this.ctx as unknown as {
      workforceAdmission?: { verifyPermit?: import('./contract.ts').WorkforceAdmission['verifyPermit'] }
    }).workforceAdmission
    if (!admission || typeof admission.verifyPermit !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceAdmission 未就绪'), 503)
    }
    return { verifyPermit: admission.verifyPermit.bind(admission) }
  }

  private emit(event: string, payload: unknown): void {
    try {
      ;(this.ctx as unknown as { platformBus?: { emit(name: string, payload: unknown): unknown } })
        .platformBus?.emit(event, payload)
    } catch {
      // platformBus non injecté dans la fiber courante : ignoré
    }
  }

  private warn(message: string): void {
    try {
      ;(this.ctx as unknown as { logger?: (name: string) => { warn(message: string): unknown } })
        .logger?.('workforce').warn(message)
    } catch {
      // logger non injecté : ignoré
    }
  }

  // -- Soumission ---------------------------------------------------------------

  async submit(caller: WorkCallerRef, input: { permitId: string; summary: string; artifactIds: string[] }): Promise<DeliverableRecord> {
    const permit = await this.admission().verifyPermit(caller, input.permitId, { requireRun: true })
    if (!input.summary?.trim()) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('交付摘要不能为空'))
    if (!Array.isArray(input.artifactIds) || input.artifactIds.length === 0) {
      // V30 : un simple résumé sans preuve de livraison ne forme pas une livraison valide
      throw new WorkforceError('ARTIFACT_SCOPE_DENIED', t('交付必须引用至少一个 artifact 证据'))
    }
    // Tous les artefacts existent et appartiennent à cet employé/ce run
    for (const artifactId of input.artifactIds) {
      const artifact = this.store.artifacts.get(artifactId)
      if (!artifact
        || artifact.employeeId !== permit.employeeId
        || (artifact.runId !== '' && artifact.runId !== permit.runId)) {
        throw new WorkforceError('ARTIFACT_SCOPE_DENIED', t('artifact {artifactId} 不存在或不属于该员工/该 run', { artifactId }))
      }
    }
    // Version = max du run + 1 (une nouvelle soumission après retour ne recouvre pas les livraisons historiques). TableStore.insert renvoie void — l'enregistrement est
    // renvoyé via la variable locale, jamais le résultat d'insert() (renvoyer void donnerait undefined à la chaîne de soumission)
    const deliverable = this.store.txn(() => {
      const prior = this.store.deliverables.findWhere({ runId: permit.runId })
      const version = prior.reduce((max, item) => Math.max(max, item.version), 0) + 1
      const record: DeliverableRecord = {
        id: newId('wfdev'),
        runId: permit.runId,
        issueId: permit.issueId,
        employeeId: permit.employeeId,
        summary: input.summary.trim(),
        artifactIdsJson: JSON.stringify(input.artifactIds),
        version,
        status: 'submitted',
        submittedAt: new Date().toISOString(),
        decidedAt: '',
        decidedBy: '',
        decisionReason: '',
      }
      this.store.deliverables.insert(record)
      return record
    })
    // Le passage de la tâche en review est verrouillé par exec-hub : sondage structuré completeRun (signature réelle (runId, {status, summary})).
    // Absence/échec = simple avertissement sans blocage — le fait de livraison est déjà comptabilisé, l'état de la tâche converge par réconciliation d'exploitation.
    try {
      const hub = (this.ctx as unknown as {
        execHub?: { completeRun?: (runId: string, options?: { status?: string; summary?: string }) => unknown }
      }).execHub
      if (typeof hub?.completeRun === 'function') {
        hub.completeRun(permit.runId, { status: 'completed', summary: t('数字员工交付提交：{id}', { id: deliverable.id }) })
      } else {
        this.warn(`execHub.completeRun 缺席：run ${permit.runId} 未自动转 review（交付 ${deliverable.id} 已落账，需人工对账）`)
      }
    } catch (error) {
      this.warn(`execHub.completeRun 失败（run ${permit.runId}）：${error instanceof Error ? error.message : String(error)}——交付 ${deliverable.id} 已落账，任务状态需人工对账`)
    }
    this.emit('workforce.deliverable.submitted', {
      deliverableId: deliverable.id, runId: deliverable.runId, issueId: deliverable.issueId,
      employeeId: deliverable.employeeId, version: deliverable.version,
    })
    return deliverable
  }

  // -- Acceptation ---------------------------------------------------------------

  async decide(caller: WorkCallerRef, input: { deliverableId: string; decision: 'accepted' | 'rejected'; reason: string }): Promise<DeliverableRecord> {
    // L'acceptation ne peut émaner que d'un humain (le point de permission workforce.accept est gardé par la couche routes, ici on revérifie le type de sujet)
    if (caller.kind !== 'human') {
      throw new WorkforceError('PRINCIPAL_BINDING_MISMATCH', t('验收决定必须由真人作出（模型输出「成功」与 HTTP 200 都不能关闭业务任务）'))
    }
    if (!input.reason?.trim()) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('验收/退回必须附原因'))
    const deliverable = this.store.deliverables.get(input.deliverableId)
    if (!deliverable) throw new WorkforceError('RUN_NOT_OWNED', t('交付不存在：{id}', { id: input.deliverableId }), 404)
    if (deliverable.status !== 'submitted') {
      throw new WorkforceError('STEP_ARGUMENT_CONFLICT', t('该交付已{state}，不可重复决定', { state: deliverable.status === 'accepted' ? t('验收通过') : t('被退回') }))
    }
    const actor = caller.userId ?? caller.principalId
    if (input.decision === 'accepted') {
      // Accord→tâche liée done (transition avant écriture : si la réécriture échoue, l'ensemble échoue et est retentable, pas de décision à moitié faite)
      this.transitionIssue(deliverable, 'done', actor, true)
    } else {
      // Retour→tâche ramenée en in_progress avec motif (échec de transition = simple avertissement, le fait de retour est comptabilisé normalement)
      this.transitionIssue(deliverable, 'in_progress', actor, false)
    }
    // TableStore.update renvoie void (effet de bord d'écriture) — la relecture fait foi du fait décidé (ne pas consommer le résultat d'update())
    this.store.deliverables.update(deliverable.id, {
      status: input.decision,
      decidedAt: new Date().toISOString(),
      decidedBy: actor,
      decisionReason: input.reason.trim(),
    })
    const updated = this.store.deliverables.get(deliverable.id)!
    this.emit('workforce.acceptance.decided', {
      deliverableId: updated.id, runId: updated.runId, issueId: updated.issueId,
      decision: input.decision, decidedBy: actor, reason: updated.decisionReason,
    })
    return updated
  }

  /**
   * Réécriture de l'état de la tâche exec-hub (sondage structuré de transitionIssue(id, to, actor) côté couche service — signature réelle).
   * Méthode absente : blocage si accepted (une tâche ne peut rester sans clôture) ; avertissement et passage si rejected (le fait de retour est déjà acquis).
   */
  private transitionIssue(deliverable: DeliverableRecord, to: 'done' | 'in_progress', actor: string, blocking: boolean): void {
    if (!deliverable.issueId) {
      if (blocking) throw new WorkforceError('POLICY_INTERNAL_ERROR', t('交付未关联任务，无法回写验收结果（请检查 permit 签发链）'))
      this.warn(`交付 ${deliverable.id} 未关联任务，退回无需回写`)
      return
    }
    try {
      const hub = (this.ctx as unknown as {
        execHub?: { transitionIssue?: (id: string, to: string, actor: string) => unknown; issues?: () => { get(id: string): { status?: string } | undefined } }
      }).execHub
      if (typeof hub?.transitionIssue !== 'function' || typeof hub?.issues !== 'function') {
        if (blocking) throw new WorkforceError('POLICY_INTERNAL_ERROR', t('execHub.transitionIssue 缺席：验收通过但任务无法收口，请先接入执行中枢'))
        this.warn(`execHub.transitionIssue 缺席：任务 ${deliverable.issueId} 未回写 ${to}（交付 ${deliverable.id}）`)
        return
      }
      const issue = hub.issues().get(deliverable.issueId)
      if (!issue) {
        if (blocking) throw new WorkforceError('POLICY_INTERNAL_ERROR', t('关联任务不存在：{id}', { id: deliverable.issueId }))
        this.warn(`关联任务不存在：${deliverable.issueId}（交付 ${deliverable.id}）`)
        return
      }
      hub.transitionIssue(deliverable.issueId, to, actor)
    } catch (error) {
      if (blocking) {
        throw new WorkforceError('POLICY_INTERNAL_ERROR', t('验收通过但任务状态回写失败：{message}', { message: error instanceof Error ? error.message : String(error) }))
      }
      this.warn(`任务 ${deliverable.issueId} 回写 ${to} 失败（交付 ${deliverable.id}）：${error instanceof Error ? error.message : String(error)}`)
    }
  }

  // -- Requêtes ---------------------------------------------------------------

  async get(caller: WorkCallerRef, deliverableId: string): Promise<DeliverableRecord> {
    const record = this.store.deliverables.get(deliverableId)
    if (!record) throw new WorkforceError('RUN_NOT_OWNED', t('交付不存在：{id}', { id: deliverableId }), 404)
    await this.assertReadable(caller, record.employeeId, this.workOrgOf(record))
    return record
  }

  async listByRun(caller: WorkCallerRef, runId: string): Promise<DeliverableRecord[]> {
    const records = this.store.deliverables.findWhere({ runId })
    if (records.length === 0) return []
    await this.assertReadable(caller, records[0]!.employeeId, this.workOrgOf(records[0]!))
    return records.sort((a, b) => a.version - b.version)
  }

  /** Métadonnées des artefacts référencés par le livrable (pour que l'acceptant confronte les preuves). */
  artifactsOf(deliverable: DeliverableRecord): ArtifactRecord[] {
    const ids = this.parseIds(deliverable.artifactIdsJson)
    return ids.map((id) => this.store.artifacts.get(id)).filter((item): item is ArtifactRecord => Boolean(item))
  }

  // -- Interne ---------------------------------------------------------------

  private workOrgOf(record: { issueId: string; employeeId: string }): string {
    // L'organisation de travail est approchée par l'organisation principale de l'employé (l'enregistrement de livraison ne redondance pas orgId ; le jugement même organisation satisfait « pas de fuite inter-organisations »)
    return this.store.employees.get(record.employeeId)?.orgId ?? ''
  }

  private async assertReadable(caller: WorkCallerRef, employeeId: string, orgId: string): Promise<void> {
    const resolution = await this.identity.resolveByCaller(caller)
    if (resolution && resolution.employee.id === employeeId) return
    if (caller.kind === 'human' && caller.userId && orgId) {
      try {
        const iam = (this.ctx as unknown as { iam?: { users?: () => { get(id: string): { orgId?: string } | undefined } } }).iam
        const user = typeof iam?.users === 'function' ? iam.users().get(caller.userId) : undefined
        if (user?.orgId === orgId) return
      } catch {
        // fail-closed : retombe dans le refus final
      }
    }
    throw new WorkforceError('RUN_NOT_OWNED', t('无权查看该交付记录（仅本人或同组织主体）'))
  }

  private parseIds(text: string): string[] {
    try {
      const value = JSON.parse(text) as unknown
      return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
    } catch {
      return []
    }
  }
}
