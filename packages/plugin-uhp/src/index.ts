/**
 * @dsh-ops/plugin-uhp — couche d'exécution UHP (Unified Harness Protocol) (plan de collaboration intranet des employés numériques d'entreprise §7).
 *
 * Positionnement : le `a2a/invoke` v1 était « la plateforme prend le modèle enregistré de l'employé et renvoie une phrase », sans cycle de vie de tâche ;
 * pour que l'employé numérique soit réellement piloté en exécution, il faut une face d'exécution unifiée. Cette extension implémente la face protocole UHP Server :
 *
 *   plateforme (A2A / orchestration) ── UHP Client ──▶ plugin-uhp (Server) ──▶ corps d'exécution configured harness
 *
 * Frontières honnêtes (référentiel v1, pas de fausse implémentation) :
 *   - harness intégré (runtime=dsh) = exécution réelle du modèle en un pas : appel réel du modèle via le routage par gradation et le disjoncteur de budget de modelgw,
 *     reprise de session (previous_response_id) réellement multi-tours ; pas de « boucle d'exécution d'outils » fictive — la face outils continue de passer par la passerelle MCP
 *     (l'exécution d'outils de l'employé numérique géré relève des appels contrôlés workforce, voir la répartition §3 du plan de collaboration) ;
 *   - `tools` au niveau requête / montage dynamique d'un serveur MCP : acceptés mais sans effet, consignés dans metadata.ignored_fields
 *     (blocage des primitives d'élévation, plan de collaboration §7.2) — la face outils de l'employé ne peut être déclarée que par la liste blanche du configured harness ;
 *   - sans endpoint de modèle configuré, erreur honnête, jamais de faux completion (prolonge la frontière d'honnêteté de modelgw).
 *
 * Discipline de couplage avec plugin-a2a : ne passer que par ctx.platformBus (a2a.task.dispatch / a2a.task.progress /
 * a2a.task.cancel), interdiction de se connecter directement aux données de l'autre plugin (ligne d'airain §11 du plan de collaboration).
 *
 * Alignement idempotent (plan de collaboration §7.2) : l'Idempotency-Key UHP s'aligne sur la tâche A2A, tissé dans le motif existant de clé idempotente de metering
 * `a2a:<agentId>:<principal>:<taskId>` — un rejeu de même clé renvoie les événements d'origine, une retry inter-nœuds ne ré-exécute ni ne compte deux fois.
 */
import { readFileSync as readTextFile, writeFileSync as writeTextFile } from 'node:fs'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  newId,
  createRestGate,
  type HttpExchange,
  type Collection,
  type RecordBase,
} from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { PermissionCatalog } from '../../plugin-iam/src/index.ts'
import type { VerifiedPrincipal } from '../../plugin-authn/src/index.ts'
import { DATA_CLASS_RANK, type DataClass } from '../../plugin-modelgw/src/index.ts'

// ---------------------------------------------------------------------------
// Constantes de protocole
// ---------------------------------------------------------------------------

/** Version verrouillée du protocole UHP (plan de collaboration §7.2 : la plateforme verrouille une version vérifiée, la réponse /v1/uhp fait foi de la négociation). */
export const UHP_VERSION = '2026-08-11'
/** Objectif de niveau de cohérence : Core (tâches/sessions/annulation) ; les entrées-sorties de fichiers d'Extended ne sont ni déclarées ni faussement implémentées en v1. */
export const UHP_CONFORMANCE_CLASS = 'core'

export type UhpResponseStatus = 'queued' | 'in_progress' | 'completed' | 'failed' | 'canceled'

/** P0 (Q-1) : erreur dédiée quand un appel externe tente de lier une tâche A2A (la face protocole la délivre en 400 TASK_BINDING_FORBIDDEN). */
export class UhpBindingError extends Error {}
/** Échec de vérification d'appartenance (403). */
export class ForbiddenError extends Error {}

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

/** configured harness (plan de collaboration §7.2) : entrée du registre pointée par uhpHarnessRef — canal de modèle, prompt, liste blanche d'outils et budget. */
export interface UhpHarnessRecord extends RecordBase {
  /** id du harness (identifiant externe stable, référencé par Agent attrs.uhpHarnessRef). */
  id: string
  /** id de l'actif Agent lié. */
  agentId: string
  /** slug du modèle (le groupe de canaux de modèle passe par le routage par gradation et le disjoncteur de budget de modelgw). */
  model: string
  /** slug optionnel de groupe de canaux (configuré = passe par la chaîne de repli invokeWithFallback). */
  channelGroup?: string
  /** Liste blanche de groupes de permissions MCP (déclaration de projection de l'autorisation de la face outils ; v1, le harness intégré n'exécute pas d'outils, voir la frontière d'honnêteté en tête de fichier). */
  toolPermGroupIds: string[]
  /** Budget de pas (exécution v1 en un pas ; ceci est une déclaration de plafond et un référentiel d'affichage d'inspection). */
  stepBudget: number
  /** Budget temporel par tâche (millisecondes). */
  timeBudgetMs: number
  /** Plus haute classe de données que ce harness peut recevoir (plafond côté harness en plus de la gradation de canaux modelgw). */
  dataClassCeiling: DataClass
  enabled: boolean
  createdBy: string
}

/** Enregistrement d'exécution UHP (objet response du sous-ensemble compatible Responses + extensions metadata ybk). */
export interface UhpResponseRecord extends RecordBase {
  id: string
  harnessId: string
  agentId: string
  /** id de session : task-bound=<taskId a2a> ; employee-bound=`emp:<agentId>:<principalId>` ; appel direct = généré indépendamment. */
  sessionId: string
  sessionPolicy: 'task-bound' | 'employee-bound'
  previousResponseId?: string
  status: UhpResponseStatus
  /** Instantané complet de la conversation (source de données de la reprise de session). */
  messagesJson: string
  outputText: string
  inputTokens: number
  outputTokens: number
  model: string
  dataClass: DataClass
  error?: string
  canceledAt?: string
  /** Liaison de tâche A2A (écrivable seulement par le chemin de dispatch interne de la plateforme, voir dispatchedByPlatform). */
  taskId?: string
  contextId?: string
  idempotencyKey?: string
  /**
   * P0 (Q-1) Attribution d'exécution : principal appelant réel de cette exécution.
   * Appel direct externe = principal détenteur de uhp.invoke ; dispatch de la plateforme = callerPrincipalId de la tâche a2a.
   * La lecture/annulation de response juge l'appartenance là-dessus (Q-3), l'audit enregistre le vrai principal (correctif d'accusation d'audit à tort).
   */
  callerPrincipalId: string
  callerName: string
  callerKind: 'machine' | 'human' | 'system'
  /** Chaîne d'identité OBO (chaîne act en JSON) — l'audit trace le vrai initiateur, aucune autobiographie de l'appelant (Q-6). */
  actChainJson: string
  /** Utilisateur représenté OBO (transmis par le chemin de dispatch interne de la plateforme ; écrit après vérification sur l'appel direct externe, valeur forgée non comptabilisée). */
  onBehalfUser?: string
  /**
   * P0 (Q-1) si produit par le chemin de dispatch A2A de la plateforme : seuls les enregistrements à true peuvent porter un taskId et entraîner
   * la machine à états de retour `a2a.task.progress` — l'appel direct externe est toujours false, infalsifiable depuis la face protocole.
   */
  dispatchedByPlatform: boolean
  /** Métadonnées étendues : liaisons ybk_* + ignored_fields (trace du blocage des primitives d'élévation). */
  metadataJson: string
}

export interface UhpDispatchPayload {
  taskId?: string
  contextId?: string
  agentId: string
  harnessRef?: string
  input: string
  dataClass: DataClass
  idempotencyKey: string
  sessionPolicy?: 'task-bound' | 'employee-bound'
  callerPrincipalId: string
  /** Chaîne d'identité OBO (transmise en interne par la plateforme, vrai initiateur ; aucune autobiographie du corps de requête n'est crue). */
  onBehalfUser?: string
  actChain?: Array<{ principalId: string; name: string; type: string }>
  negotiationNote?: string
}

export interface UhpProgressPayload {
  taskId?: string
  responseId: string
  phase: 'started' | 'delta' | 'completed' | 'failed' | 'canceled'
  text?: string
  error?: string
  inputTokens?: number
  outputTokens?: number
  model?: string
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class UhpGatewayService extends Service {
  static readonly provide = 'uhpGateway'

  /** Enregistrement des annulations de tâches en exécution (taskId → responseId). */
  private inflight = new Map<string, string>()
  /** Marques d'annulation (responseId → true) : au retour de l'appel de modèle, le résultat est jeté accordingly (sémantique d'annulation collaborative). */
  private cancelRequested = new Set<string>()

  constructor(ctx: Context) {
    super(ctx, 'uhpGateway')
    // Couplage au dispatch A2A (discipline du seul bus d'événements) : après réception de l'événement de dispatch, démarrage asynchrone de l'exécution —
    // l'écouteur retourne immédiatement (écouteur de bus timeout 5 s), la tâche longue progresse dans une Promise indépendante.
    ctx.platformBus.on('a2a.task.dispatch', (payload) => {
      const p = payload as UhpDispatchPayload
      void this.executeForTask(p).catch((error) => {
        this.ctx.logger('uhp').error('UHP 执行派发处理异常', error)
      })
    })
    // Couplage d'annulation : A2A tasks/cancel → UHP cancel (face protocole) + marque d'invalidation de la réponse
    ctx.platformBus.on('a2a.task.cancel', (payload) => {
      const p = payload as { taskId: string; reason?: string }
      const responseId = this.inflight.get(p.taskId)
      if (responseId) {
        this.cancelRequested.add(responseId)
        this.responses().update(responseId, { status: 'canceled', canceledAt: new Date().toISOString() })
      } else {
        // Sans exécution en vol : trouve la dernière response de la tâche et marque l'annulation (idempotence honnête : l'état terminal n'est pas écrasé)
        const existing = [...this.responses().find((item) => item.taskId === p.taskId)].pop()
        if (existing && (existing.status === 'queued' || existing.status === 'in_progress')) {
          this.responses().update(existing.id, { status: 'canceled', canceledAt: new Date().toISOString() })
        }
      }
    })
  }

  // -- Collections -----------------------------------------------------------------

  harnesses(): Collection<UhpHarnessRecord> {
    return this.ctx.opsStorage.collection<UhpHarnessRecord>('uhp:harnesses', { durability: 'durable' })
  }

  responses(): Collection<UhpResponseRecord> {
    return this.ctx.opsStorage.collection<UhpResponseRecord>('uhp:responses', { durability: 'durable' })
  }

  // -- Registre de harness --------------------------------------------------------

  upsertHarness(input: {
    id?: string
    agentId: string
    model: string
    channelGroup?: string
    toolPermGroupIds?: string[]
    stepBudget?: number
    timeBudgetMs?: number
    dataClassCeiling?: DataClass
    enabled?: boolean
    createdBy: string
  }): UhpHarnessRecord {
    const agent = this.ctx.resourceCore.get('agent', input.agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}（harness 必须绑定真实 Agent 资产）', { id: input.agentId }))
    if (!input.model.trim()) throw new Error(t('model 必填（harness 执行的模型 slug）'))
    const ceiling = input.dataClassCeiling ?? 'internal'
    if (!(ceiling in DATA_CLASS_RANK)) throw new Error(t('dataClassCeiling 非法：{value}（public/internal/secret）', { value: ceiling }))
    const stepBudget = input.stepBudget ?? 8
    const timeBudgetMs = input.timeBudgetMs ?? 120_000
    if (!(stepBudget > 0) || stepBudget > 64) throw new Error(t('stepBudget 须在 1-64 之间'))
    if (!(timeBudgetMs >= 5_000) || timeBudgetMs > 600_000) throw new Error(t('timeBudgetMs 须在 5000-600000 毫秒之间'))
    const existing = input.id ? this.harnesses().get(input.id) : undefined
    if (existing) {
      return this.harnesses().update(existing.id, {
        agentId: input.agentId,
        model: input.model,
        ...(input.channelGroup !== undefined ? { channelGroup: input.channelGroup } : {}),
        toolPermGroupIds: input.toolPermGroupIds ?? existing.toolPermGroupIds,
        stepBudget,
        timeBudgetMs,
        dataClassCeiling: ceiling,
        ...(input.enabled !== undefined ? { enabled: input.enabled } : { enabled: existing.enabled }),
      })
    }
    const id = input.id?.trim() || newId('uhp')
    if (this.harnesses().get(id)) throw new Error(t('harness id 已存在：{id}', { id }))
    return this.harnesses().insert({
      id,
      agentId: input.agentId,
      model: input.model,
      ...(input.channelGroup ? { channelGroup: input.channelGroup } : {}),
      toolPermGroupIds: input.toolPermGroupIds ?? [],
      stepBudget,
      timeBudgetMs,
      dataClassCeiling: ceiling,
      enabled: input.enabled ?? true,
      createdBy: input.createdBy,
    })
  }

  removeHarness(id: string): boolean {
    return this.harnesses().remove(id)
  }

  /** Découverte de capacités (GET /v1/uhp) : la liste des configured harness présentée selon le point de vue runtime. */
  discovery(): {
    uhp_version: string
    conformance_class: string
    capabilities: { files_input: boolean; files_output: boolean; session_listing: boolean; session_sharing: boolean; harness_management: boolean }
    harnesses: Array<{ id: string; configured: string[] }>
  } {
    const onlineAgents = new Map(this.ctx.resourceCore.list('agent').filter((item) => item.status === 'online').map((item) => [item.id, item.slug]))
    const byHarnessId = new Map<string, string[]>()
    for (const harness of this.harnesses().all()) {
      if (!harness.enabled) continue
      const slug = onlineAgents.get(harness.agentId)
      if (!slug) continue
      byHarnessId.set(harness.id, [slug])
    }
    return {
      uhp_version: UHP_VERSION,
      conformance_class: UHP_CONFORMANCE_CLASS,
      capabilities: {
        files_input: false,
        files_output: false,
        session_listing: true,
        session_sharing: false,
        harness_management: false,
      },
      harnesses: [...byHarnessId.entries()].map(([id, configured]) => ({ id, configured })),
    }
  }

  // -- Face tâches ---------------------------------------------------------------

  /**
   * Crée et démarre une exécution UHP (idempotent) : un enregistrement terminal existant de même Idempotency-Key est rejoué tel quel,
   * un enregistrement en vol est renvoyé directement (pas de double exécution). Renvoie l'enregistrement response.
   *
   * P0 (Q-1) fermeture de la liaison de tâche : `taskId` n'est accepté que du chemin de dispatch A2A de la plateforme (`dispatchedByPlatform: true`),
   * rattrapage fail-closed en couche service — même si quelqu'un transmet un taskId par erreur depuis la face protocole, aucune appartenance de tâche ne se crée.
   */
  async createResponse(input: {
    harnessRef?: string
    agentId: string
    inputText: string
    dataClass?: DataClass
    previousResponseId?: string
    idempotencyKey?: string
    taskId?: string
    contextId?: string
    sessionPolicy?: 'task-bound' | 'employee-bound'
    callerPrincipalId: string
    callerName?: string
    callerKind?: 'machine' | 'human' | 'system'
    actChain?: Array<{ principalId: string; name: string; type: string }>
    dispatchedByPlatform?: boolean
    onBehalfUser?: string
    requestTools?: unknown
    requestFunctions?: unknown
    requestMcpServers?: unknown
    negotiationNote?: string
  }): Promise<UhpResponseRecord> {
    if (!input.inputText?.trim()) throw new Error(t('input 必填（UHP 任务输入不能为空）'))
    const dispatched = input.dispatchedByPlatform === true
    // P0 (Q-1) : la liaison de tâche ne reconnaît que le chemin de dispatch de la plateforme — un appel non dispatché portant taskId est toujours refusé (fail-closed)
    if (input.taskId && !dispatched) {
      throw new UhpBindingError(t('外部调用不得绑定 A2A 任务：ybk_a2a_task_id 仅允许由平台内部派发通道注入'))
    }
    // Idempotence : un rejeu de même clé renvoie l'enregistrement d'origine (plan de collaboration §7.2 — une retry inter-nœuds ne ré-exécute pas et ne compte pas deux fois)
    if (input.idempotencyKey) {
      const existing = this.responses().find((item) => item.idempotencyKey === input.idempotencyKey)
      const latest = existing.sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0]
      if (latest) return latest
    }
    const agent = this.ctx.resourceCore.get('agent', input.agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: input.agentId }))
    if (agent.status !== 'online') throw new Error(t('Agent 未上线（{status}），UHP 仅对 online 执行体开放', { status: agent.status }))
    const harness = this.resolveHarness(agent, input.harnessRef)
    const requested: DataClass = input.dataClass ?? 'internal'
    if (DATA_CLASS_RANK[requested] > DATA_CLASS_RANK[harness.dataClassCeiling]) {
      throw new Error(t('数据密级越级：请求 {requested} 高于 harness 天花板 {ceiling}（渠道锁死拒绝口径）', { requested, ceiling: harness.dataClassCeiling }))
    }
    // Blocage des primitives d'élévation de privilèges : tools/functions/mcp_servers au niveau requête sont toujours acceptés mais sans effet, trace dans ignored_fields (plan de collaboration §7.2)
    const ignoredFields: string[] = []
    if (input.requestTools !== undefined) ignoredFields.push('tools')
    if (input.requestFunctions !== undefined) ignoredFields.push('functions')
    if (input.requestMcpServers !== undefined) ignoredFields.push('mcp_servers')
    // Reprise de session (Q-23) : hérite le sessionId de la réponse précédente (fait de session_id une clé de regroupement fiable),
    // et réinjecte la réponse assistant du tour précédent dans le contexte — sinon l'appelé « ne sait pas ce qu'il a dit au tour précédent »
    let messages: Array<{ role: string; content: string }> = []
    let inheritedSessionId = ''
    if (input.previousResponseId) {
      const prev = this.responses().get(input.previousResponseId)
      if (!prev) throw new Error(t('previous_response_id 不存在：{id}', { id: input.previousResponseId }))
      if (prev.agentId !== agent.id) throw new Error(t('previous_response_id 属于其他执行体，拒绝跨 harness 会话续接'))
      // Contrôle d'appartenance (Q-3, en profondeur) : la reprise de session est réservée au propriétaire de l'enregistrement ou à la vue de gouvernance tenant uhp.read dans son organisation
      this.assertResponseAccess(prev, input.callerPrincipalId, ['uhp.read'])
      inheritedSessionId = prev.sessionId
      messages = JSON.parse(prev.messagesJson) as Array<{ role: string; content: string }>
      if (prev.outputText) messages = [...messages, { role: 'assistant', content: prev.outputText }]
    }
    const sessionPolicy = input.sessionPolicy ?? 'task-bound'
    const sessionId = sessionPolicy === 'task-bound'
      ? (input.taskId ?? (inheritedSessionId || newId('uhpsess')))
      : `emp:${agent.id}:${input.callerPrincipalId}`
    const systemPrompt = this.systemPromptFor(agent)
    if (!messages.some((item) => item.role === 'system')) messages = [{ role: 'system', content: systemPrompt }, ...messages]
    messages = [...messages, { role: 'user', content: input.negotiationNote ? `${input.inputText}\n\n（协商附注：${input.negotiationNote}）` : input.inputText }]
    const record = this.responses().insert({
      id: newId('resp'),
      harnessId: harness.id,
      agentId: agent.id,
      sessionId,
      sessionPolicy,
      ...(input.previousResponseId ? { previousResponseId: input.previousResponseId } : {}),
      status: 'queued',
      messagesJson: JSON.stringify(messages),
      outputText: '',
      inputTokens: 0,
      outputTokens: 0,
      model: harness.model,
      dataClass: requested,
      ...(input.taskId ? { taskId: input.taskId } : {}),
      ...(input.contextId ? { contextId: input.contextId } : {}),
      ...(input.idempotencyKey ? { idempotencyKey: input.idempotencyKey } : {}),
      callerPrincipalId: input.callerPrincipalId,
      callerName: input.callerName ?? input.callerPrincipalId,
      callerKind: input.callerKind ?? (dispatched ? 'system' : 'machine'),
      actChainJson: JSON.stringify(input.actChain ?? []),
      ...(input.onBehalfUser ? { onBehalfUser: input.onBehalfUser } : {}),
      dispatchedByPlatform: dispatched,
      metadataJson: JSON.stringify({
        ybk_agent_id: agent.id,
        ...(input.taskId ? { ybk_a2a_task_id: input.taskId } : {}),
        ybk_data_class: requested,
        ...(input.onBehalfUser ? { ybk_on_behalf_user: input.onBehalfUser } : {}),
        ignored_fields: ignoredFields,
      }),
    })
    this.run(record.id).catch((error) => {
      this.ctx.logger('uhp').error(`UHP 执行异常（response=${record.id}）`, error)
    })
    return record
  }

  /**
   * Contrôle d'appartenance des enregistrements d'exécution (Q-3) : seul le propriétaire, `*`, ou un détenteur des points de permission de lecture de gouvernance listés peut lire/annuler.
   * Les intégrations externes d'une même couche ne peuvent ni lire mutuellement leurs entrées/sorties ni annuler les exécutions en cours (protection DoS + fuite de données).
   */
  private assertResponseAccess(record: UhpResponseRecord, principalId: string, overridePoints: string[]): void {
    if (record.callerPrincipalId === principalId) return
    throw new ForbiddenError(t('无权访问该执行记录（仅属主或持治理读权限者可访问）'))
    void overridePoints // points de permission de lecture de gouvernance vérifiés à la couche HTTP (visibles via CallerInfo.scopes), la couche service ne reconnaît que l'appartenance
  }

  response(id: string): UhpResponseRecord | undefined {
    return this.responses().get(id)
  }

  /**
   * Annulation : refus honnête sur état terminal ; l'exécution en cours est marquée annulée, le résultat n'est pas livré au retour du modèle.
   * Contrôle d'appartenance (Q-3) : un non-propriétaire ne peut pas annuler l'enregistrement d'exécution d'autrui (les identifiants d'une même couche ne s'interfèrent pas).
   */
  cancelResponse(id: string, reason: string, callerPrincipalId: string): UhpResponseRecord {
    const record = this.responses().get(id)
    if (!record) throw new Error(t('response 不存在：{id}', { id }))
    this.assertResponseAccess(record, callerPrincipalId, [])
    if (['completed', 'failed', 'canceled'].includes(record.status)) {
      throw new Error(t('response 已终态（{status}），不可取消', { status: record.status }))
    }
    this.cancelRequested.add(id)
    return this.responses().update(id, { status: 'canceled', canceledAt: new Date().toISOString(), error: reason })
  }

  /** Résolution du harness : référence explicite → registre ; non enregistré → configuration temporaire projetée depuis les attrs de l'Agent (sans changer le comportement de la face collaboration). */
  private resolveHarness(agent: { id: string; attrs: Record<string, unknown> }, harnessRef?: string): UhpHarnessRecord {
    const ref = String(harnessRef ?? agent.attrs['uhpHarnessRef'] ?? '').trim()
    if (ref) {
      const found = this.harnesses().get(ref)
      if (!found) throw new Error(t('uhpHarnessRef 指向的 harness 不存在：{id}（请先在 UHP 注册或清空该引用）', { id: ref }))
      if (!found.enabled) throw new Error(t('harness 已停用：{id}', { id: ref }))
      return found
    }
    const model = String(agent.attrs['model'] ?? '').trim()
    if (!model) throw new Error(t('Agent 未配置模型（model 属性为空），无法执行'))
    const ceilingRaw = String(agent.attrs['a2aDataClassCeiling'] ?? 'internal')
    const ceiling: DataClass = ceilingRaw in DATA_CLASS_RANK ? (ceilingRaw as DataClass) : 'internal'
    return {
      id: `adhoc:${agent.id}`,
      agentId: agent.id,
      model,
      toolPermGroupIds: [],
      stepBudget: 1,
      timeBudgetMs: 120_000,
      dataClassCeiling: ceiling,
      enabled: true,
      createdBy: 'system',
      createdAt: '',
      updatedAt: '',
    }
  }

  private systemPromptFor(agent: { name: string; attrs: Record<string, unknown> }): string {
    const custom = String(agent.attrs['systemPrompt'] ?? '').trim()
    if (custom) return custom
    return t('你是企业数字同事「{name}」。{description}', { name: agent.name, description: String(agent.attrs['description'] ?? '') })
  }

  /** Entrée de délégation A2A : enveloppe createResponse (seul canal autorisant le lien taskId), l'état terminal est renvoyé via le bus (a2a.task.progress). */
  private async executeForTask(payload: UhpDispatchPayload): Promise<void> {
    try {
      const record = await this.createResponse({
        agentId: payload.agentId,
        harnessRef: payload.harnessRef,
        inputText: payload.input,
        dataClass: payload.dataClass,
        idempotencyKey: payload.idempotencyKey,
        taskId: payload.taskId,
        contextId: payload.contextId,
        sessionPolicy: payload.sessionPolicy,
        callerPrincipalId: payload.callerPrincipalId,
        callerKind: 'system',
        callerName: payload.callerPrincipalId,
        ...(payload.actChain ? { actChain: payload.actChain } : {}),
        // P0 (Q-1) : true uniquement sur le chemin de délégation plateforme — c'est le justificatif de liaison infalsifiable par les appels externes
        dispatchedByPlatform: true,
        onBehalfUser: payload.onBehalfUser,
        negotiationNote: payload.negotiationNote,
      })
      if (record.status === 'queued' || record.status === 'in_progress') {
        // Attend l'état terminal (la promise du run n'est pas awaitée ici — la machine à états A2A est pilotée par les événements progress)
        await this.awaitTerminal(record.id, payload.taskId)
      } else {
        // Rejeu idempotent : renvoie l'état terminal existant tel quel (la face A2A converge son état sur cette base)
        this.emitProgress(record, record.status === 'completed' ? 'completed' : record.status === 'canceled' ? 'canceled' : 'failed')
      }
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      this.ctx.platformBus.emit('a2a.task.progress', {
        taskId: payload.taskId,
        responseId: '',
        phase: 'failed',
        error: reason,
      } satisfies UhpProgressPayload)
    }
  }

  /** Attend l'état terminal d'une response (implémentation légère par sondage — l'exécutant est dans le même processus, une granularité de 300 ms suffit). */
  private async awaitTerminal(responseId: string, taskId?: string): Promise<void> {
    for (let i = 0; i < 4000; i++) {
      const record = this.responses().get(responseId)
      if (!record) return
      if (['completed', 'failed', 'canceled'].includes(record.status)) {
        this.emitProgress(record, record.status === 'completed' ? 'completed' : record.status === 'canceled' ? 'canceled' : 'failed')
        return
      }
      await new Promise((resolve) => setTimeout(resolve, 300))
    }
    // Timeout de rattrapage : marque en échec (garde-fou du budget temps, ne laisse pas l'appelant en suspens)
    if (taskId) {
      this.responses().update(responseId, { status: 'failed', error: t('执行超时（时间预算耗尽）') })
      this.emitProgress(this.responses().get(responseId)!, 'failed')
    }
  }

  /**
   * Renvoi de progression : tout enregistrement d'exécution émet `uhp.response.progress` (face d'abonnement SSE, P2-03 ferme le flux d'appel direct externe),
   * mais seuls les enregistrements « délégués A2A par la plateforme » émettent en plus `a2a.task.progress` pour piloter la machine à états A2A (barrière centrale P0 Q-1).
   * L'appel direct externe (dispatchedByPlatform=false) n'émet jamais a2a.task.progress —
   * ce qui supprime à la racine le chemin de détournement « un identifiant externe pousse la tâche d'autrui à l'état terminal via un résultat d'exécution ».
   */
  private emitProgress(record: UhpResponseRecord | undefined, phase: UhpProgressPayload['phase']): void {
    if (!record) return
    if (record.taskId) this.inflight.delete(record.taskId)
    const payload = {
      taskId: record.taskId,
      responseId: record.id,
      phase,
      ...(phase === 'completed' ? { text: record.outputText } : {}),
      ...(record.error ? { error: record.error } : {}),
      inputTokens: record.inputTokens,
      outputTokens: record.outputTokens,
      model: record.model,
    } satisfies UhpProgressPayload
    // Événement d'enregistrement d'exécution (séparé des événements de tâche) : appel direct interne/externe/délégation plateforme uniformément souscriptibles —
    // il ne pilote aucun état A2A et n'élargit donc pas la surface d'attaque P0 (la barrière de a2a.task.progress reste inchangée).
    this.ctx.platformBus.emit('uhp.response.progress', payload)
    if (!record.dispatchedByPlatform) return
    this.ctx.platformBus.emit('a2a.task.progress', payload)
  }

  /** Exécutant réel (harness dsh intégré) : appel réel au modèle en une étape (routage par niveaux modelgw + disjoncteur de budget). */
  private async run(responseId: string): Promise<void> {
    const record = this.responses().get(responseId)
    if (!record) return
    const harness = this.harnesses().get(record.harnessId)
    const agent = this.ctx.resourceCore.get('agent', record.agentId)
    if (!agent) {
      this.finish(record.id, 'failed', { error: t('Agent 资产不存在（可能已被删除）') })
      return
    }
    const model = harness?.model ?? String(agent.attrs['model'] ?? '')
    if (!model) {
      this.finish(record.id, 'failed', { error: t('Agent 未配置模型（model 属性为空），诚实拒绝执行') })
      return
    }
    this.inflight.set(record.taskId ?? record.id, record.id)
    this.responses().update(record.id, { status: 'in_progress' })
    this.emitProgress(this.responses().get(record.id)!, 'started')
    try {
      if (record.taskId) this.inflight.set(record.taskId, record.id)
      const messages = JSON.parse(record.messagesJson) as Array<{ role: string; content: string }>
      const result = await this.ctx.modelGateway.invoke({
        model,
        orgId: agent.orgId ?? '',
        subject: `agent:${agent.id}`,
        dataClass: record.dataClass,
        messages,
      })
      if (this.cancelRequested.has(record.id)) {
        // Sémantique d'annulation coopérative : résultat non livré, sortie non réécrite (l'annulateur a déjà reçu l'état terminal canceled)
        this.cancelRequested.delete(record.id)
        this.auditExecution(this.responses().get(record.id)!, agent, 'uhp.invoke.canceled_after_completion', 'ok',
          t('模型已返回但任务已取消，结果不交付（取消语义）'))
        this.emitProgress(this.responses().get(record.id), 'canceled')
        return
      }
      this.responses().update(record.id, {
        status: 'completed',
        outputText: result.content,
        inputTokens: result.inputTokens,
        outputTokens: result.outputTokens,
        model: result.model,
      })
      // Q-1 face ③ : l'audit enregistre le véritable appelant (appel direct externe = principal titulaire du certificat ; délégation plateforme = initiateur de la tâche),
      // detail embarque responseId/taskId pour que « qui a exécuté quelle occurrence » soit retrouvable par id (Q-25)
      this.auditExecution(this.responses().get(record.id)!, agent, 'uhp.invoke', 'ok',
        `harness=${record.harnessId} model=${result.model} tokens=${result.inputTokens}/${result.outputTokens} response=${record.id}${record.taskId ? ` task=${record.taskId}` : ''}${record.contextId ? ` context=${record.contextId}` : ''}`)
      this.emitProgress(this.responses().get(record.id), 'completed')
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      if (this.cancelRequested.has(record.id)) {
        this.cancelRequested.delete(record.id)
        this.emitProgress(this.responses().get(record.id), 'canceled')
        return
      }
      this.finish(record.id, 'failed', { error: reason })
    } finally {
      if (record.taskId) this.inflight.delete(record.taskId)
    }
  }

  private finish(id: string, status: UhpResponseStatus, patch: { error?: string }): void {
    const current = this.responses().get(id)
    if (!current || ['completed', 'failed', 'canceled'].includes(current.status)) return
    this.responses().update(id, { status, ...patch })
    const agent = this.ctx.resourceCore.get('agent', current.agentId)
    if (agent && status === 'failed') {
      this.auditExecution(current, agent, 'uhp.invoke', 'error', `response=${current.id} harness=${current.harnessId} ${patch.error ?? ''}`.trim())
    }
    this.emitProgress(this.responses().get(id), status === 'completed' ? 'completed' : status === 'canceled' ? 'canceled' : 'failed')
  }

  /**
   * Audit d'exécution : le sujet est le véritable appelant de l'enregistrement d'exécution (Q-1 face ③, correctif de l'audit falsifiable).
   * Le chemin de délégation plateforme ramène le principal initiateur de la tâche A2A + la chaîne d'identité OBO, pour que « initié par un humain au nom d'un employé » soit reconstituable dans l'audit.
   */
  private auditExecution(
    record: UhpResponseRecord,
    agent: { id: string; name: string },
    action: string,
    result: 'ok' | 'error',
    detail: string,
  ): void {
    const actChain = JSON.parse(record.actChainJson || '[]') as Array<{ name: string; type: string }>
    this.ctx.audit.record({
      type: 'invoke',
      actorType: record.callerKind,
      actorId: record.callerPrincipalId,
      actorName: record.callerName,
      action,
      resourceType: 'agent',
      resourceId: agent.id,
      resourceName: agent.name,
      result,
      detail: `${detail}${record.onBehalfUser ? ` onBehalfOf=${record.onBehalfUser}` : ''}`,
      ...(actChain.length > 0 ? { actChain } : {}),
    })
  }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    uhpGateway: UhpGatewayService
  }
}

export const name = 'uhp'
// iam + agentRegistry : vérification d'authenticité de l'utilisateur représenté en OBO (Q-6 : quand on déclare agir pour quelqu'un, vérifier que cet utilisateur existe et est représentable par le jeton)
export const inject = ['opsStorage', 'platformBus', 'httpServer', 'resourceCore', 'authn', 'iam', 'agentRegistry', 'audit', 'usage', 'modelGateway']

export function apply(ctx: Context) {
  const gateway = new UhpGatewayService(ctx)
  const gate = createRestGate(ctx)
  // Convention de nommage : l'alias http permet au scanner de littéraux de routes de contract-lint de reconnaître la face déclarée http.register
  const http = ctx.httpServer

  // Au démarrage, complétion idempotente du PermissionCatalog de l'iam avec les points de permission UHP (précédent : complétion exec.read/exec.write de plugin-agent)
  for (const entry of [
    { point: 'uhp.read', label: '读取 UHP harness 注册表与执行记录', group: 'UHP 执行驱动' },
    { point: 'uhp.admin', label: '管理 UHP harness 配置', group: 'UHP 执行驱动' },
    { point: 'uhp.invoke', label: 'UHP 任务面调用（机器凭证执行面）', group: 'UHP 执行驱动' },
  ]) {
    if (!PermissionCatalog.some((item) => item.point === entry.point)) PermissionCatalog.push(entry)
  }

  // -- Découverte des capacités UHP (la norme exige l'absence d'authentification ; /v1/* hors du domaine d'authentification /api, anonyme par construction) --------------------
  // P2-02 : la face découverte renvoie le corps nu de la norme (même référence que l'Agent Card well-known) — les clients UHP externes
  // consomment directement le corps de réponse, sans devoir d'abord dépouiller l'enveloppe plateforme {ok,data}.
  http.register('GET', '/v1/uhp', (exchange) => {
    if (exchange.res.headersSent) return
    exchange.res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
    exchange.res.end(JSON.stringify(gateway.discovery()))
  })

  // -- Face tâches UHP (sous-ensemble compatible Responses ; auto-vérification Bearer + permission uhp.invoke, fail-closed) -------
  // Tout chemin de refus laisse une trace d'audit (Q-27) : la face protocole /v1 n'est pas couverte par le middleware d'authentification de la console, l'auto-vérification doit embarquer ses propres sondes.
  const denyAudit = (exchange: { path: string; headers: Record<string, unknown> }, verified: VerifiedPrincipal | undefined, point: string, detail: string): void => {
    ctx.platformBus.emit('audit.authz.denied', {
      actorId: verified?.principal.id ?? '(anon)',
      actorName: verified?.principal.name ?? '匿名请求',
      point,
      path: exchange.path,
      detail,
    })
  }
  const verifyCaller = (exchange: HttpExchange): VerifiedPrincipal | undefined => {
    const header = String(exchange.headers['authorization'] ?? '')
    const token = header.startsWith('Bearer ') ? header.slice(7) : header
    if (!token) {
      denyAudit(exchange, undefined, 'uhp.invoke', t('缺少 Bearer 令牌'))
      exchange.fail(401, 'UNAUTHORIZED', t('缺少 Bearer 令牌（UHP 任务面要求机器凭证）'))
      return undefined
    }
    try {
      const verified = ctx.authn.verify(token)
      if (!verified.scopes.includes('uhp.invoke') && !verified.scopes.includes('*')) {
        denyAudit(exchange, verified, 'uhp.invoke', t('缺少权限点 uhp.invoke'))
        exchange.fail(403, 'FORBIDDEN', t('缺少权限点 uhp.invoke（UHP 任务面执行凭证）'))
        return undefined
      }
      return verified
    } catch (error) {
      denyAudit(exchange, undefined, 'uhp.invoke', t('令牌校验失败'))
      exchange.fail(401, 'TOKEN_INVALID', error instanceof Error ? error.message : String(error))
      return undefined
    }
  }

  http.register('POST', '/v1/uhp/responses', async (exchange) => {
    const verified = verifyCaller(exchange)
    if (!verified) return
    const body = (exchange.body ?? {}) as {
      model?: string
      input?: string | Array<{ role: string; content: string }>
      stream?: boolean
      previous_response_id?: string
      idempotency?: string
      tools?: unknown
      functions?: unknown
      mcp_servers?: unknown
      metadata?: Record<string, unknown>
      task_id?: unknown
      taskId?: unknown
    }
    const metadata = body.metadata ?? {}
    // P0 (Q-1) : tout appel externe porteur d'un champ de liaison de tâche est refusé — ce champ ne peut être injecté que par le canal interne de délégation de la plateforme.
    // Refuser plutôt qu'ignorer : faire de la tentative d'injection de l'attaquant un événement d'audit observable, et non une prise d'effet silencieuse.
    // P2-04 : la matrice de variantes (metadata.ybk_a2a_task_id / task_id au sommet / taskId au sommet) relève d'un même régime de refus
    // — auparavant les variantes au sommet étaient silencieusement abandonnées, la tentative d'injection était invisible, en désaccord avec la déclaration « refuser plutôt qu'ignorer ».
    const bindingProbes: Array<{ field: string; value: unknown }> = []
    if (metadata['ybk_a2a_task_id'] !== undefined) bindingProbes.push({ field: 'metadata.ybk_a2a_task_id', value: metadata['ybk_a2a_task_id'] })
    if (body.task_id !== undefined) bindingProbes.push({ field: 'task_id', value: body.task_id })
    if (body.taskId !== undefined) bindingProbes.push({ field: 'taskId', value: body.taskId })
    if (bindingProbes.length > 0) {
      const probe = bindingProbes[0]!
      const fields = bindingProbes.map((item) => item.field).join(', ')
      denyAudit(exchange, verified, 'a2a.task.dispatch', t('外部调用试图注入任务绑定字段（任务劫持探针）：{fields}', { fields }))
      ctx.audit.record({
        type: 'authz', actorType: verified.principal.type, actorId: verified.principal.id, actorName: verified.principal.name,
        action: 'uhp.invoke.task_binding_denied', resourceType: 'agent', resourceId: String(metadata['ybk_agent_id'] ?? ''),
        resourceName: t('UHP 任务面'), result: 'denied',
        detail: t('外部调用注入任务绑定字段被拒（{fields}；taskId={taskId}）——该字段仅允许平台派发通道注入', {
          fields, taskId: String(probe.value),
        }),
      })
      exchange.fail(400, 'TASK_BINDING_FORBIDDEN', t('外部调用不得绑定 A2A 任务：任务绑定字段（{fields}）仅允许由平台内部派发通道注入', { fields }))
      return
    }
    const inputText = typeof body.input === 'string'
      ? body.input
      : Array.isArray(body.input)
        ? body.input.filter((item) => item.role === 'user').map((item) => item.content).join('\n')
        : ''
    const idemHeader = exchange.headers['idempotency-key']
    const idempotencyKey = ((Array.isArray(idemHeader) ? idemHeader[0] : idemHeader) ?? body.idempotency) || undefined
    const ref = String(metadata['ybk_agent_id'] ?? String(body.model ?? '').replace(/^harness\//, '') ?? '').trim()
    if (!ref) {
      exchange.fail(400, 'BAD_REQUEST', t('缺少执行体：model 须为 harness/<id>（发现面公布的 harness id）或 metadata.ybk_agent_id 必填'))
      return
    }
    // Adressage (Q-7) : la face découverte publie des harness id, la face d'appel doit pouvoir adresser par harness id —
    // résolution d'abord par Agent (id/slug), à défaut repli sur le registre des harness configurés pour retrouver l'employé lié.
    let agent = ctx.resourceCore.get('agent', ref) ?? ctx.resourceCore.bySlug('agent', ref)
    let harnessRef: string | undefined
    if (!agent) {
      const harness = gateway.harnesses().get(ref)
      if (harness?.enabled) {
        agent = ctx.resourceCore.get('agent', harness.agentId)
        harnessRef = harness.id
      }
    }
    if (!agent) {
      exchange.fail(404, 'NOT_FOUND', t('执行体不存在：{ref}（可传 agent id/slug 或 GET /v1/uhp 公布的 harness id）', { ref }))
      return
    }
    const dataClassRaw = String(metadata['ybk_data_class'] ?? 'internal')
    const dataClass: DataClass = dataClassRaw === 'public' || dataClassRaw === 'secret' ? dataClassRaw : 'internal'
    // Vérification OBO (Q-6) : quand un appel direct externe déclare représenter quelqu'un, ce userId doit réellement exister et être représentable par le jeton —
    // un humain réel apparaît dans la chaîne OBO (act), ou le sujet appelant est '*' / lié à cet utilisateur ; sinon la déclaration n'est pas retenue, pas de comptabilisation.
    let onBehalfUser: string | undefined
    if (typeof metadata['ybk_on_behalf_user'] === 'string' && metadata['ybk_on_behalf_user'].trim()) {
      const claimed = metadata['ybk_on_behalf_user'].trim()
      const actUser = verified.actChain.find((entry) => entry.type === 'human')
      const isPlatformAdmin = verified.scopes.includes('*')
      const binding = ctx.agentRegistry.boundUsers(agent.id).find((item) => item.userId === claimed)
      if (ctx.iam.users().get(claimed) && (actUser?.principalId === claimed || isPlatformAdmin || binding)) {
        onBehalfUser = claimed
      }
    }
    try {
      const record = await gateway.createResponse({
        agentId: agent.id,
        harnessRef,
        inputText,
        dataClass,
        ...(body.previous_response_id ? { previousResponseId: body.previous_response_id } : {}),
        idempotencyKey,
        ...(typeof metadata['ybk_context_id'] === 'string' ? { contextId: metadata['ybk_context_id'] } : {}),
        ...(metadata['ybk_session_policy'] === 'employee-bound' ? { sessionPolicy: 'employee-bound' as const } : {}),
        callerPrincipalId: verified.principal.id,
        callerName: verified.principal.name,
        callerKind: verified.principal.type === 'human' ? 'human' : 'machine',
        ...(verified.actChain.length > 0 ? { actChain: verified.actChain.map((e) => ({ principalId: '', name: e.name, type: e.type })) } : {}),
        ...(onBehalfUser ? { onBehalfUser } : {}),
        // Blocage des primitives d'élévation de privilèges : tools/functions/mcp_servers au niveau requête (au sommet ou dans metadata) toujours acceptés sans effet
        requestTools: body.tools !== undefined ? body.tools : metadata['tools'],
        ...(body.functions !== undefined || metadata['functions'] !== undefined ? { requestFunctions: body.functions ?? metadata['functions'] } : {}),
        ...(body.mcp_servers !== undefined || metadata['mcp_servers'] !== undefined ? { requestMcpServers: body.mcp_servers ?? metadata['mcp_servers'] } : {}),
      })
      if (body.stream === true) {
        // Flux de progression SSE : l'incrément textuel est envoyé en une seule trame avec la sortie complète (harness intégré mono-étape, granularité honnête)
        const res = exchange.res
        if (res.headersSent) return
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' })
        res.write(`retry: 5000\n\n`)
        let closed = false
        let unsubscribe = () => {}
        let heartbeat: ReturnType<typeof setInterval> | undefined
        const send = (event: string, data: unknown) => {
          if (closed || res.writableEnded) return
          res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
        }
        const closeStream = () => {
          if (closed) return
          closed = true
          clearInterval(heartbeat)
          unsubscribe()
          if (!res.writableEnded) res.end()
        }
        /** Clôture sur état terminal (idempotent : le SSE n'autorise qu'une trame terminale, évite un end répété en course). */
        const finishStream = (record: UhpResponseRecord) => {
          if (record.status === 'completed') {
            send('output_text.delta', { delta: record.outputText })
            send('response.completed', { id: record.id, output_text: record.outputText, usage: { input_tokens: record.inputTokens, output_tokens: record.outputTokens } })
          } else if (record.status === 'failed' || record.status === 'canceled') {
            send(`response.${record.status}`, { id: record.id, error: record.error ?? record.status })
          } else {
            return
          }
          closeStream()
        }
        send('response.created', { id: record.id, status: record.status })
        const initial = gateway.response(record.id)
        if (initial && ['completed', 'failed', 'canceled'].includes(initial.status)) {
          finishStream(initial)
          return
        }
        // P2-03 : abonnement aux événements d'enregistrement d'exécution (uhp.response.progress), et non plus à
        // a2a.task.progress qui ne concerne que les enregistrements délégués par la plateforme — l'appel direct externe (dispatchedByPlatform=false) ne recevait jamais la trame de fin,
        // le SSE restait suspendu après response.created jusqu'au battement de cœur de 15 s.
        unsubscribe = ctx.platformBus.on('uhp.response.progress', (payload) => {
          const p = payload as UhpProgressPayload
          if (p.responseId !== record.id) return
          if (p.phase === 'completed') {
            send('output_text.delta', { delta: p.text ?? '' })
            send('response.completed', { id: record.id, output_text: p.text ?? '', usage: { input_tokens: p.inputTokens, output_tokens: p.outputTokens } })
            closeStream()
          } else if (p.phase === 'failed' || p.phase === 'canceled') {
            send(`response.${p.phase}`, { id: record.id, error: p.error ?? p.phase })
            closeStream()
          } else {
            send('response.in_progress', { id: record.id })
          }
        })
        // Revérification de l'état terminal après abonnement : colmate la course d'achèvement entre « createResponse → abonnement » (sinon clôture jamais atteinte)
        const afterSubscribe = gateway.response(record.id)
        if (afterSubscribe && ['completed', 'failed', 'canceled'].includes(afterSubscribe.status)) {
          finishStream(afterSubscribe)
          return
        }
        heartbeat = setInterval(() => res.write(': ping\n\n'), 15_000)
        heartbeat.unref?.()
        exchange.raw.on('close', closeStream)
        return
      }
      // Mode synchrone (stream≠true) : attend l'état terminal avant de répondre (sémantique synchrone de l'API Responses ; plafond 60 s contre la suspension)
      let settled = gateway.response(record.id) ?? record
      for (let i = 0; i < 300 && !['completed', 'failed', 'canceled'].includes(settled.status); i++) {
        await new Promise((resolve) => setTimeout(resolve, 200))
        settled = gateway.response(record.id) ?? settled
      }
      exchange.ok(uhpView(settled))
    } catch (error) {
      if (error instanceof UhpBindingError) {
        exchange.fail(400, 'TASK_BINDING_FORBIDDEN', error.message)
        return
      }
      if (error instanceof ForbiddenError) {
        exchange.fail(403, 'FORBIDDEN', error.message)
        return
      }
      exchange.fail(400, 'BAD_REQUEST', error instanceof Error ? error.message : String(error))
    }
  })

  // Lecture/annulation : propriétaire lui-même ou administrateur de la plateforme (la permission de lecture de gouvernance uhp.read passe par la face de requête /api/uhp/responses,
  // la face d'exécution /v1 ne reconnaît que le propriétaire et '*' — les intégrations externes d'une même couche ne peuvent ni lire ni annuler mutuellement)
  http.register('GET', '/v1/uhp/responses/:id', (exchange) => {
    const verified = verifyCaller(exchange)
    if (!verified) return
    const record = gateway.response(exchange.params['id'] ?? '')
    if (!record) {
      exchange.fail(404, 'NOT_FOUND', t('response 不存在：{id}', { id: exchange.params['id'] ?? '' }))
      return
    }
    // Pas de fuite d'existence : un non-propriétaire reçoit toujours « n'existe pas » (évite de sonder les id d'enregistrements d'exécution d'autrui)
    if (record.callerPrincipalId !== verified.principal.id && !verified.scopes.includes('*')) {
      denyAudit(exchange, verified, 'uhp.response.read', t('越权读取他人执行记录'))
      exchange.fail(404, 'NOT_FOUND', t('response 不存在：{id}', { id: exchange.params['id'] ?? '' }))
      return
    }
    exchange.ok(uhpView(record))
  })

  http.register('POST', '/v1/uhp/responses/:id/cancel', (exchange) => {
    const verified = verifyCaller(exchange)
    if (!verified) return
    try {
      exchange.ok(uhpView(gateway.cancelResponse(exchange.params['id'] ?? '', t('调用方主动取消'), verified.principal.id)))
    } catch (error) {
      if (error instanceof ForbiddenError) {
        denyAudit(exchange, verified, 'uhp.response.cancel', t('越权取消他人执行记录'))
        exchange.fail(403, 'FORBIDDEN', error.message)
        return
      }
      exchange.fail(400, 'BAD_REQUEST', error instanceof Error ? error.message : String(error))
    }
  })

  // -- Gestion du registre des harness (domaine /api, gardé, intégré à la matrice de sondes d'élévation RBAC) -------------------------
  // Isolation organisationnelle (Q-4) : même référence que R11 de /api/agents — une organisation subordonnée titulaire de uhp.read ne voit que son sous-arbre organisationnel
  const visibleOrgScope = (info: { kind: string; userId?: string; refType?: string; refId?: string; permissions: string[] }): Set<string> | null => {
    if (info.permissions.includes('*')) return null
    let orgId = info.userId ? ctx.iam.users().get(info.userId)?.orgId : undefined
    if (!orgId && info.kind === 'machine' && info.refType === 'agent' && info.refId) {
      orgId = ctx.resourceCore.collection('agent').get(info.refId)?.orgId
    }
    if (!orgId) return new Set<string>()
    return new Set(ctx.iam.orgSubtreeIds(orgId))
  }
  const orgVisible = (scope: Set<string> | null, agentId: string): boolean => {
    if (scope === null) return true
    const targetOrg = ctx.resourceCore.collection('agent').get(agentId)?.orgId
    if (!targetOrg) return true
    return scope.has(targetOrg)
  }

  gate.guarded('GET', '/api/uhp/harnesses', 'uhp.read', (exchange) => {
    const scope = visibleOrgScope(gate.caller(exchange))
    return {
      harnesses: gateway.harnesses().all()
        .filter((harness) => orgVisible(scope, harness.agentId))
        .map((harness) => ({
          ...harness,
          agentName: ctx.resourceCore.get('agent', harness.agentId)?.name ?? harness.agentId,
        })),
    }
  })
  gate.guarded('POST', '/api/uhp/harnesses', 'uhp.admin', (exchange) => {
    const input = gate.body<{
      id?: string; agentId: string; model: string; channelGroup?: string
      toolPermGroupIds?: string[]; stepBudget?: number; timeBudgetMs?: number; dataClassCeiling?: DataClass; enabled?: boolean
    }>(exchange)
    const record = gateway.upsertHarness({ ...input, createdBy: gate.actorOf(exchange) })
    gate.changeLog(exchange, 'uhp.harness.upsert', 'uhp_harness', record.id, record.id, `agent=${input.agentId} model=${input.model}`)
    return { harness: record }
  })
  gate.guarded('PATCH', '/api/uhp/harnesses/:id', 'uhp.admin', (exchange) => {
    const input = gate.body<Record<string, unknown>>(exchange)
    const existing = gateway.harnesses().get(exchange.params['id'] ?? '')
    if (!existing) {
      exchange.fail(404, 'NOT_FOUND', t('harness 不存在：{id}', { id: exchange.params['id'] ?? '' }))
      return
    }
    const record = gateway.upsertHarness({
      id: existing.id,
      agentId: String(input['agentId'] ?? existing.agentId),
      model: String(input['model'] ?? existing.model),
      channelGroup: input['channelGroup'] !== undefined ? String(input['channelGroup']) : existing.channelGroup,
      toolPermGroupIds: Array.isArray(input['toolPermGroupIds']) ? (input['toolPermGroupIds'] as string[]) : existing.toolPermGroupIds,
      stepBudget: input['stepBudget'] !== undefined ? Number(input['stepBudget']) : existing.stepBudget,
      timeBudgetMs: input['timeBudgetMs'] !== undefined ? Number(input['timeBudgetMs']) : existing.timeBudgetMs,
      dataClassCeiling: input['dataClassCeiling'] !== undefined ? (input['dataClassCeiling'] as DataClass) : existing.dataClassCeiling,
      enabled: input['enabled'] !== undefined ? Boolean(input['enabled']) : existing.enabled,
      createdBy: existing.createdBy,
    })
    gate.changeLog(exchange, 'uhp.harness.update', 'uhp_harness', record.id, record.id)
    return { harness: record }
  })
  gate.guarded('DELETE', '/api/uhp/harnesses/:id', 'uhp.admin', (exchange) => {
    const removed = gateway.removeHarness(exchange.params['id'] ?? '')
    if (!removed) {
      exchange.fail(404, 'NOT_FOUND', t('harness 不存在：{id}', { id: exchange.params['id'] ?? '' }))
      return
    }
    gate.changeLog(exchange, 'uhp.harness.delete', 'uhp_harness', exchange.params['id'] ?? '', exchange.params['id'] ?? '')
    return { deleted: true }
  })
  gate.guarded('GET', '/api/uhp/responses', 'uhp.read', (exchange) => {
    const taskId = exchange.query.get('taskId') ?? ''
    const agentId = exchange.query.get('agentId') ?? ''
    const limit = Math.min(Number(exchange.query.get('limit') ?? 50) || 50, 200)
    const scope = visibleOrgScope(gate.caller(exchange))
    const scoped = gateway.responses().all().filter((item) => orgVisible(scope, item.agentId))
    const items = scoped
      .filter((item) => (taskId ? item.taskId === taskId : true))
      .filter((item) => (agentId ? item.agentId === agentId : true))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, limit)
    return { total: scoped.length, items: items.map(uhpView) }
  })
}

/** Vue externe : noms de champs du sous-ensemble compatible Responses (clés de protocole ASCII ; pour les libellés chinois, voir le tableau général de correspondance des clés de protocole). */
function uhpView(record: UhpResponseRecord) {
  return {
    id: record.id,
    status: record.status,
    model: record.model,
    harness_id: record.harnessId,
    output_text: record.outputText,
    usage: { input_tokens: record.inputTokens, output_tokens: record.outputTokens },
    session_id: record.sessionId,
    ...(record.previousResponseId ? { previous_response_id: record.previousResponseId } : {}),
    ...(record.taskId ? { task_id: record.taskId } : {}),
    ...(record.error ? { error: record.error } : {}),
    metadata: JSON.parse(record.metadataJson || '{}') as Record<string, unknown>,
    created_at: record.createdAt,
  }
}
