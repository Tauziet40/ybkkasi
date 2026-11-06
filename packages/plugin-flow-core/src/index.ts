/**
 * @dsh-ops/plugin-flow-core — moteur de flux de dossiers (livraison IAW 3-1..3-4, PRD M5/§7.5, nouveau domaine hôte).
 *
 * Flux de dossier (TF) = orchestration multi-étapes du déclencheur à l'archivage, couche d'orchestration au-dessus des tâches (panel:tasks) :
 *   - CRUD de TF + machine à états des étapes (3-1) : étapes à exécutant humain/Agent/passserelle (trois types),
 *     machine pending→running→done/blocked/skipped (done avance automatiquement la prochaine étape à démarrer) ;
 *     chaque transition émet flow.created / flow.step.updated / flow.completed (platformBus,
 *     le SSE du pannel peut consommer directement via l'éventail wireEventBus).
 *   - Bibliothèque de modèles (3-2) : modèles enregistrés par scénario, instanciation en un clic par copie-déclinaison ; le paquet de contexte (contextPack)
 *     est renvoyé avec l'instanciation pour injection automatique par l'appelant.
 *   - SLA / progression (3-3) : slaMinutes + dueAt + progress temps réel (done/(total-skipped)),
 *     dépassement calculé à la lecture (slaBreached), pas de minuteur en arrière-plan (référentiel honnête : jugement à l'instant de la requête).
 *   - Gantt (3-4) : startedAt/finishedAt complets sur les étapes, le front peut rendre directement (cette extension ne fournit que les données).
 *
 * Ligne rouge de véridicité : le TF n'invente pas d'état métier — l'avancement des étapes doit être explicitement appelé, aucune logique automatique de « complété simulé ».
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import type { HttpExchange } from '../../platform-core/src/index.ts'
import { createRestGate } from '../../platform-core/src/index.ts'
import { PlatformEvents, newId, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type { AuditLogRecord } from '../../plugin-audit/src/index.ts'

// ---------------------------------------------------------------------------
// Modèle d'enregistrements
// ---------------------------------------------------------------------------

export type FlowStepActorType = 'human' | 'agent' | 'gateway'
export type FlowStepStatus = 'pending' | 'running' | 'done' | 'blocked' | 'skipped'
export type FlowStatus = 'running' | 'completed' | 'cancelled' | 'archived'

export interface FlowStepRecord {
  key: string
  name: string
  actorType: FlowStepActorType
  /** human = userId / agent = nom du collègue numérique / gateway = nom d'action de passerelle. */
  assignee?: string
  status: FlowStepStatus
  note?: string
  startedAt?: string
  finishedAt?: string
  actor?: string
}

export interface FlowRecord extends RecordBase {
  code: string
  name: string
  sceneCode?: string
  dept?: string
  orgId?: string
  /** Modèle source d'instanciation (absent en orchestration libre). */
  templateCode?: string
  steps: FlowStepRecord[]
  status: FlowStatus
  /** SLA (minutes, 3-3) : décompté depuis le déclenchement ; dueAt = createdAt+slaMinutes. */
  slaMinutes?: number
  dueAt?: string
  /** Marque de stagnation (C-06) : horodatée quand l'état est running mais qu'aucune étape n'est running ; effacée dès reprise de l'avancement. Alerte seule, pas de relance automatique. */
  stalledAt?: string
  createdBy: string
  finishedAt?: string
}

export interface FlowTemplateStep {
  key: string
  name: string
  actorType: FlowStepActorType
  assignee?: string
  note?: string
}

/** Modèle de flux de dossier (3-2) : gabarit à copier-décliner par scénario + déclaration du paquet de contexte. */
export interface FlowTemplateRecord extends RecordBase {
  code: string
  name: string
  sceneCode?: string
  description?: string
  steps: FlowTemplateStep[]
  slaMinutes?: number
  /** Paquet de contexte (renvoyé lors de l'instanciation via le champ contextPack, pour injection automatique par l'appelant dans la première étape). */
  contextPack?: Record<string, unknown>
  createdBy: string
}

export const FLOW_STEP_ACTIONS = ['start', 'complete', 'block', 'restart', 'skip'] as const
export type FlowStepAction = (typeof FLOW_STEP_ACTIONS)[number]

const STEP_TRANSITIONS: Record<FlowStepAction, { from: FlowStepStatus[]; to: FlowStepStatus }> = {
  start: { from: ['pending'], to: 'running' },
  complete: { from: ['running'], to: 'done' },
  block: { from: ['running'], to: 'blocked' },
  restart: { from: ['blocked'], to: 'running' },
  skip: { from: ['pending', 'running', 'blocked'], to: 'skipped' },
}

/** Validation du SLA (C-07) : doit être positif — une valeur illégale mettrait dueAt avant createdAt (né dépassé/overdueMinutes négatif). */
const assertSlaMinutes = (value: number): void => {
  if (!Number.isFinite(value) || value <= 0) throw new Error(t('slaMinutes 必须为正数（分钟），收到：{value}', { value }))
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class FlowService extends Service {
  static readonly provide = 'flow'

  constructor(ctx: Context) {
    super(ctx, 'flow')
  }

  // -- Collections -----------------------------------------------------------------

  flows(): Collection<FlowRecord> {
    const collection = this.ctx.opsStorage.collection<FlowRecord>('flow:flows')
    collection.uniqueOn('flow_code', (item) => item.code)
    return collection
  }

  templates(): Collection<FlowTemplateRecord> {
    const collection = this.ctx.opsStorage.collection<FlowTemplateRecord>('flow:templates')
    collection.uniqueOn('template_code', (item) => item.code)
    return collection
  }

  // -- Bibliothèque de modèles (3-2) ----------------------------------------------------------

  upsertTemplate(input: {
    code: string
    name: string
    sceneCode?: string
    description?: string
    steps: FlowTemplateStep[]
    slaMinutes?: number
    contextPack?: Record<string, unknown>
    createdBy: string
  }): FlowTemplateRecord {
    this.validateStepDraft(input.steps)
    if (!input.code?.trim() || !/^[A-Za-z0-9._-]{2,64}$/.test(input.code)) throw new Error(t('模板 code 非法（字母/数字/._-，2-64 位）：{code}', { code: input.code }))
    if (!input.name?.trim()) throw new Error(t('模板名称必填'))
    if (input.slaMinutes !== undefined) assertSlaMinutes(input.slaMinutes)
    const existing = this.templates().findOne((item) => item.code === input.code)
    const payload = {
      code: input.code.trim(),
      name: input.name.trim(),
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}),
      ...(input.description ? { description: input.description } : {}),
      steps: input.steps.map((step) => ({
        key: step.key, name: step.name, actorType: step.actorType,
        ...(step.assignee ? { assignee: step.assignee } : {}),
        ...(step.note ? { note: step.note } : {}),
      })),
      ...(input.slaMinutes !== undefined ? { slaMinutes: input.slaMinutes } : {}),
      ...(input.contextPack ? { contextPack: input.contextPack } : {}),
      createdBy: input.createdBy,
    }
    if (existing) {
      const updated = this.templates().update(existing.id, payload)
      this.ctx.platformBus.emit(PlatformEvents.FlowTemplateChanged, { code: updated.code, action: 'updated' })
      return updated
    }
    const created = this.templates().insert({ id: newId('ftpl'), ...payload })
    this.ctx.platformBus.emit(PlatformEvents.FlowTemplateChanged, { code: created.code, action: 'created' })
    return created
  }

  deleteTemplate(code: string): { deleted: boolean } {
    const template = this.templates().findOne((item) => item.code === code)
    if (!template) throw new Error(t('模板不存在：{code}', { code }))
    this.templates().remove(template.id)
    this.ctx.platformBus.emit(PlatformEvents.FlowTemplateChanged, { code, action: 'deleted' })
    return { deleted: true }
  }

  listTemplates(filter: { sceneCode?: string } = {}): FlowTemplateRecord[] {
    return this.templates().all()
      .filter((item) => (filter.sceneCode ? item.sceneCode === filter.sceneCode : true))
      .sort((a, b) => a.code.localeCompare(b.code))
  }

  // -- Orchestration TF (3-1) -----------------------------------------------------------

  private validateStepDraft(steps: Array<{ key?: string; name?: string; actorType?: string }>): void {
    if (!Array.isArray(steps) || steps.length === 0) throw new Error(t('事务流至少一个步骤（steps）'))
    if (steps.length > 30) throw new Error(t('事务流步骤过多（≤30）：编排请拆分阶段'))
    const keys = new Set<string>()
    for (const step of steps) {
      if (!step.key?.trim() || !/^[A-Za-z0-9._-]{1,40}$/.test(step.key)) throw new Error(t('步骤 key 非法：{key}（字母/数字/._-）', { key: step.key }))
      if (keys.has(step.key)) throw new Error(t('步骤 key 重复：{key}', { key: step.key }))
      keys.add(step.key)
      if (!step.name?.trim()) throw new Error(t('步骤 {key} 缺少名称', { key: step.key }))
      if (!['human', 'agent', 'gateway'].includes(step.actorType ?? '')) throw new Error(t('步骤 {key} 的 actorType 非法（human/agent/gateway）', { key: step.key }))
    }
  }

  /**
   * Crée un TF : instanciation de templateCode (copie-déclinaison depuis la bibliothèque) ou orchestration libre via steps.
   * Première étape automatiquement running (startedAt horodaté) ; slaMinutes converti en même temps en dueAt (3-3).
   * Renvoie avec contextPack (paquet de contexte du modèle, à injecter par l'appelant).
   */
  createFlow(input: {
    name: string
    templateCode?: string
    steps?: Array<{ key: string; name: string; actorType: FlowStepActorType; assignee?: string; note?: string }>
    sceneCode?: string
    dept?: string
    orgId?: string
    slaMinutes?: number
    createdBy: string
  }): FlowRecord & { contextPack?: Record<string, unknown> } {
    if (!input.name?.trim()) throw new Error(t('事务流名称必填'))
    let steps: Array<{ key: string; name: string; actorType: FlowStepActorType; assignee?: string; note?: string }>
    let template: FlowTemplateRecord | undefined
    let slaMinutes = input.slaMinutes
    if (input.templateCode) {
      template = this.templates().findOne((item) => item.code === input.templateCode)
      if (!template) throw new Error(t('事务流模板不存在：{code}（GET /api/flow/templates?sceneCode= 可查在库模板）', { code: input.templateCode }))
      steps = template.steps
      if (slaMinutes === undefined && template.slaMinutes !== undefined) slaMinutes = template.slaMinutes
    } else {
      steps = input.steps ?? []
    }
    this.validateStepDraft(steps)
    // C-07 : le slaMinutes venant de l'entrée ou hérité du modèle doit être positif (contre le « né dépassé »)
    if (slaMinutes !== undefined) assertSlaMinutes(slaMinutes)
    const now = new Date().toISOString()
    const record = this.flows().insert({
      id: newId('tf'),
      code: `tf_${now.slice(0, 10).replace(/-/g, '')}_${newId('x').slice(-6)}`,
      name: input.name.trim(),
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}),
      ...(input.dept ? { dept: input.dept } : {}),
      ...(input.orgId ? { orgId: input.orgId } : {}),
      ...(template ? { templateCode: template.code } : {}),
      steps: steps.map((step, index) => ({
        key: step.key, name: step.name, actorType: step.actorType,
        ...(step.assignee ? { assignee: step.assignee } : {}),
        ...(step.note ? { note: step.note } : {}),
        status: index === 0 ? 'running' as const : 'pending' as const,
        ...(index === 0 ? { startedAt: now } : {}),
      })),
      status: 'running',
      ...(slaMinutes !== undefined ? { slaMinutes, dueAt: new Date(Date.now() + slaMinutes * 60_000).toISOString() } : {}),
      createdBy: input.createdBy,
    })
    this.ctx.platformBus.emit(PlatformEvents.FlowCreated, {
      flowId: record.id, code: record.code, name: record.name, dept: record.dept, sceneCode: record.sceneCode,
      steps: record.steps.length, currentStep: record.steps[0]?.key, createdBy: input.createdBy,
    })
    return { ...record, ...(template?.contextPack ? { contextPack: template.contextPack } : {}) }
  }

  getFlow(idOrCode: string): FlowRecord | undefined {
    return this.flows().get(idOrCode) ?? this.flows().findOne((item) => item.code === idOrCode)
  }

  listFlows(filter: { sceneCode?: string; dept?: string; status?: string; orgId?: string } = {}): Array<FlowRecord & FlowView> {
    return this.flows().all()
      .filter((item) => {
        if (filter.sceneCode && item.sceneCode !== filter.sceneCode) return false
        if (filter.dept && item.dept !== filter.dept) return false
        if (filter.status && item.status !== filter.status) return false
        if (filter.orgId && item.orgId !== filter.orgId) return false
        return true
      })
      .map((item) => ({ ...item, ...this.viewOf(item) }))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  }

  /** Vue à l'état de lecture (3-3/3-4) : progression / SLA / axe temporel des étapes (source de données Gantt). */
  viewOf(flow: FlowRecord): FlowView {
    const executable = flow.steps.filter((step) => step.status !== 'skipped')
    const done = executable.filter((step) => step.status === 'done').length
    const progress = executable.length === 0 ? 0 : Math.round((done / executable.length) * 1000) / 10
    const elapsedMinutes = Math.floor((Date.now() - new Date(flow.createdAt).getTime()) / 60_000)
    const breached = flow.status === 'running' && flow.dueAt !== undefined && flow.dueAt < new Date().toISOString()
    return {
      progress,
      ...(flow.steps.find((step) => step.status === 'running')?.key ? { currentStep: flow.steps.find((step) => step.status === 'running')!.key } : {}),
      elapsedMinutes,
      slaBreached: breached,
      overdueMinutes: breached ? elapsedMinutes - (flow.slaMinutes ?? 0) : 0,
      ...(flow.stalledAt ? { stalled: true } : {}),
    }
  }

  /**
   * Machine à états des étapes (3-1) : pending→running→done/blocked/skipped ; blocked→running (restart) ;
   * done avance automatiquement la prochaine étape pending en running. Chaîne complète done/skipped → TF completed.
   * Chaque changement émet flow.step.updated ; l'achèvement émet flow.completed (éventail SSE du panneau).
   */
  stepTransition(flowId: string, stepKey: string, action: FlowStepAction, actor: string, note?: string): { flow: FlowRecord & FlowView; completed: boolean } {
    const rule = STEP_TRANSITIONS[action]
    if (!rule) throw new Error(t('未知步骤动作：{action}（{allowed}）', { action, allowed: FLOW_STEP_ACTIONS.join('/') }))
    const collection = this.flows()
    const flow = collection.get(flowId) ?? collection.findOne((item) => item.code === flowId)
    if (!flow) throw new Error(t('事务流不存在：{id}', { id: flowId }))
    if (flow.status !== 'running') throw new Error(t('事务流已结束（{status}），步骤不可流转', { status: flow.status }))
    const index = flow.steps.findIndex((step) => step.key === stepKey)
    if (index === -1) throw new Error(t('步骤不存在：{key}', { key: stepKey }))
    const step = flow.steps[index]!
    if (!rule.from.includes(step.status)) {
      throw new Error(t('步骤 {key} 当前状态 {status} 不允许 {action}（允许自：{allowed}）', { key: stepKey, status: step.status, action, allowed: rule.from.join('/') }))
    }
    const now = new Date().toISOString()
    const updatedStep: FlowStepRecord = {
      ...step,
      status: rule.to,
      actor,
      ...(note !== undefined ? { note } : {}),
      ...(step.startedAt ? {} : { startedAt: now }),
      finishedAt: rule.to === 'done' || rule.to === 'skipped' ? now : undefined,
    }
    const steps = flow.steps.map((item) => (item.key === stepKey ? updatedStep : item))
    let completed = false
    if (rule.to === 'done') {
      const next = steps.find((item) => item.status === 'pending')
      if (next) {
        const nextIndex = steps.findIndex((item) => item.key === next.key)
        steps[nextIndex] = { ...next, status: 'running', startedAt: now }
      }
    }
    const allSettled = steps.every((item) => item.status === 'done' || item.status === 'skipped')
    // C-06 : état running mais aucune étape running (ex. sauter la seule étape running alors qu'il reste des pending) — flux stagnant.
    // Seulement pose du marqueur + événement d'alerte, pas de relance automatique (ligne rouge de véridicité : l'avancement doit être explicite) ; le marqueur est effacé à la reprise.
    const stalled = !allSettled && !steps.some((item) => item.status === 'running')
    const updated = collection.update(flow.id, {
      steps,
      status: allSettled ? 'completed' : flow.status,
      ...(allSettled ? { finishedAt: now } : {}),
      ...(stalled && !flow.stalledAt ? { stalledAt: now } : {}),
      ...(!stalled && flow.stalledAt ? { stalledAt: undefined } : {}),
    })
    this.ctx.platformBus.emit(PlatformEvents.FlowStepUpdated, {
      flowId: flow.id, code: flow.code, dept: flow.dept, sceneCode: flow.sceneCode,
      stepKey, action, to: rule.to, actor, note: note ?? '',
      currentStep: steps.find((item) => item.status === 'running')?.key ?? '',
    })
    if (stalled) {
      this.ctx.platformBus.emit(PlatformEvents.FlowStalled, {
        flowId: flow.id, code: flow.code, name: flow.name, dept: flow.dept, sceneCode: flow.sceneCode,
        stalledAt: now, reason: t('running 态但无 running 步骤（步骤 {key} → {to} 后无自动推进）', { key: stepKey, to: rule.to }),
      })
    }
    if (allSettled) {
      completed = true
      this.ctx.platformBus.emit(PlatformEvents.FlowCompleted, {
        flowId: flow.id, code: flow.code, name: flow.name, dept: flow.dept, sceneCode: flow.sceneCode,
        finishedAt: now, createdBy: flow.createdBy,
      })
    }
    return { flow: { ...updated, ...this.viewOf(updated) }, completed }
  }

  cancelFlow(flowId: string, actor: string, note?: string): FlowRecord & FlowView {
    const collection = this.flows()
    const flow = collection.get(flowId) ?? collection.findOne((item) => item.code === flowId)
    if (!flow) throw new Error(t('事务流不存在：{id}', { id: flowId }))
    if (flow.status !== 'running') throw new Error(t('事务流已结束（{status}），不可取消', { status: flow.status }))
    const now = new Date().toISOString()
    const updated = collection.update(flow.id, { status: 'cancelled', finishedAt: now })
    this.ctx.platformBus.emit(PlatformEvents.FlowStepUpdated, {
      flowId: flow.id, code: flow.code, dept: flow.dept, sceneCode: flow.sceneCode,
      stepKey: '*', action: 'cancel', to: 'cancelled', actor, note: note ?? '', currentStep: '',
    })
    return { ...updated, ...this.viewOf(updated) }
  }
}

/** Vue dérivée à l'état de lecture (champs additifs, non persistés). */
export interface FlowView {
  /** Pourcentage d'avancement (done/(total-skipped), 0-100, une décimale). */
  progress: number
  /** Clé de l'étape running courante (vide si aucune). */
  currentStep?: string
  elapsedMinutes: number
  slaBreached: boolean
  overdueMinutes: number
  /** Stagnation (C-06) : état running sans étape running, horodatage voir stalledAt. */
  stalled?: boolean
}

// ---------------------------------------------------------------------------
// REST (/api/flow/* : guarded auto-enregistré et fondu dans routeMatrix, l'authentification dépend du middleware console en amont)
// ---------------------------------------------------------------------------

export function apply(ctx: Context) {
  ctx.plugin(FlowService)
  const flow = new FlowService(ctx)
  const http = ctx.httpServer

  // Convergence R5 : caller/requirePermission/guarded/body/actorOf importent tous l'implémentation partagée de platform-core (correctif et audit en point unique)
  const { caller, requirePermission, guarded, body, actorOf } = createRestGate(ctx)
  /**
   * Point d'exécution de l'autorisation au niveau scénario (QA A-01) : checkScene n'avait jusqu'ici qu'un seul appelant sur toute la plateforme, l'endpoint d'auto-contrôle —
   * l'auto-contrôle jugeait deny alors que l'action réelle passait quand même en 200. Quand le scénario a une politique configurée (jugement non default), ce garde impose l'arbitrage :
   * deny / fail-closed (politique sans correspondance) = toujours 403 avec audit.authz.denied ;
   * allow laisse passer ; scénario sans politique configurée retombe sur le RBAC par rôles (référentiel historique inchangé). Les principaux machine n'entrent pas encore dans le domaine scénario
   * (le RBAC par points de permission couvre déjà), référentiel voir release-notes-2026-09-12.
   */
  const sceneGuard = (exchange: HttpExchange, sceneCode: string | undefined, action: string): boolean => {
    if (!sceneCode?.trim()) return true
    const info = caller(exchange)
    if (!info.userId) return true
    const decision = ctx.iam.checkScene(info.userId, sceneCode, action)
    if (decision.decision !== 'deny') return true
    ctx.platformBus.emit('audit.authz.denied', {
      actorId: info.userId, actorName: info.name, point: `scene:${sceneCode}#${action}`, path: exchange.path,
    })
    exchange.fail(403, 'FORBIDDEN', t('场景授权拒绝（{scene} · {action}）：{reason}', { scene: sceneCode, action, reason: decision.reason }))
    return false
  }
  /** Traçabilité d'audit (audit absent = saut silencieux — même défense que softRead de dsh-bridge). */
  const auditSafe = (entry: Omit<AuditLogRecord, 'id' | 'createdAt' | 'updatedAt'>): void => {
    try {
      ctx.audit?.record(entry)
    } catch { /* dégradation indépendante du plan d'audit */ }
  }
  const changeLog = (exchange: HttpExchange, action: string, resourceName: string, detail = ''): void => {
    const info = caller(exchange)
    auditSafe({
      type: 'change', actorType: info.kind === 'human' ? 'human' : 'machine',
      actorId: info.userId ?? info.principalId, actorName: info.name,
      action, resourceType: 'flow', resourceId: exchange.params['id'] ?? '', resourceName, result: 'ok', detail,
    })
  }

  // -- Bibliothèque de modèles (3-2) ----------------------------------------------------------
  guarded('GET', '/api/flow/templates', 'flow.read', (exchange) => ({
    templates: flow.listTemplates({ ...(exchange.query.get('sceneCode') ? { sceneCode: exchange.query.get('sceneCode')! } : {}) }),
  }))

  guarded('PUT', '/api/flow/templates', 'flow.admin', (exchange) => {
    const input = body<{ code: string; name: string; sceneCode?: string; description?: string; steps: FlowTemplateStep[]; slaMinutes?: number; contextPack?: Record<string, unknown> }>(exchange)
    const template = flow.upsertTemplate({ ...input, createdBy: actorOf(exchange) })
    changeLog(exchange, 'flow.template.upsert', template.name, `${template.steps.length} 步`)
    return template
  })

  guarded('DELETE', '/api/flow/templates/:code', 'flow.admin', (exchange) => {
    const result = flow.deleteTemplate(exchange.params['code']!)
    changeLog(exchange, 'flow.template.delete', exchange.params['code'] ?? '', '')
    return result
  })

  // -- CRUD TF et machine à états (3-1/3-3/3-4) ------------------------------------------
  guarded('GET', '/api/flow/flows', 'flow.read', (exchange) => ({
    flows: flow.listFlows({
      ...(exchange.query.get('sceneCode') ? { sceneCode: exchange.query.get('sceneCode')! } : {}),
      ...(exchange.query.get('dept') ? { dept: exchange.query.get('dept')! } : {}),
      ...(exchange.query.get('status') ? { status: exchange.query.get('status')! } : {}),
    }),
  }))

  guarded('POST', '/api/flow/flows', 'flow.write', (exchange) => {
    const input = body<{ name: string; templateCode?: string; steps?: Array<{ key: string; name: string; actorType: FlowStepActorType; assignee?: string; note?: string }>; sceneCode?: string; dept?: string; slaMinutes?: number }>(exchange)
    const info = caller(exchange)
    // QA A-01 : point d'exécution du scénario — scénario en entrée ou porté par le modèle, dès qu'une politique existe, arbitrage imposé (deny/fail-closed → 403)
    const template = input.templateCode ? flow.templates().findOne((item) => item.code === input.templateCode) : undefined
    if (!sceneGuard(exchange, input.sceneCode ?? template?.sceneCode, 'flow.create')) return
    const created = flow.createFlow({
      ...input,
      createdBy: actorOf(exchange),
    })
    auditSafe({
      type: 'change', actorType: info.kind === 'human' ? 'human' : 'machine', actorId: created.createdBy, actorName: info.name,
      action: 'flow.create', resourceType: 'flow', resourceId: created.id, resourceName: created.name, result: 'ok',
      detail: `steps=${created.steps.length}${input.templateCode ? ` 模板=${input.templateCode}` : ''}`,
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}),
    })
    return created
  })

  guarded('GET', '/api/flow/flows/:id', 'flow.read', (exchange) => {
    const record = flow.getFlow(exchange.params['id']!)
    if (!record) {
      exchange.fail(404, 'NOT_FOUND', t('事务流不存在：{id}', { id: exchange.params['id'] ?? '' }))
      return
    }
    return { ...record, ...flow.viewOf(record) }
  })

  guarded('POST', '/api/flow/flows/:id/steps/:key/transition', 'flow.write', (exchange) => {
    const input = body<{ action?: FlowStepAction; note?: string }>(exchange)
    const action = input.action ?? 'complete'
        // QA A-01 : un TF rattaché à un scénario voit ses actions de transition arbitrées selon la politique du scénario
    const target = flow.getFlow(exchange.params['id']!)
    if (target && !sceneGuard(exchange, target.sceneCode, 'flow.step.transition')) return
    const result = flow.stepTransition(exchange.params['id']!, exchange.params['key']!, action, actorOf(exchange), input.note)
    changeLog(exchange, `flow.step.${action}`, result.flow.name, `${exchange.params['key']}→${STEP_TRANSITIONS[action].to}${input.note ? `（${input.note}）` : ''}`)
    return result
  })

  guarded('POST', '/api/flow/flows/:id/cancel', 'flow.write', (exchange) => {
    const input = body<{ note?: string }>(exchange)
    // QA A-01 : l'annulation est aussi une action dans le scénario, arbitrtée selon la politique du scénario
    const target = flow.getFlow(exchange.params['id']!)
    if (target && !sceneGuard(exchange, target.sceneCode, 'flow.cancel')) return
    const cancelled = flow.cancelFlow(exchange.params['id']!, actorOf(exchange), input.note)
    changeLog(exchange, 'flow.cancel', cancelled.name, input.note ?? '')
    return cancelled
  })
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    flow: FlowService
  }
}

export const name = 'flow-core'
export const inject = ['httpServer', 'opsStorage', 'platformBus', 'iam']
