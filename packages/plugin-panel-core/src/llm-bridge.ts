/**
 * Pont de modèles dsh (repli de la face modèle en forme installée porte 01) : quand modelgw est absent mais l'hôte dsh présent (fournissant ctx.llm LlmRuntime),
 * la face modèle du panneau/les appels d'Agent tombent sur les modèles déjà configurés de dsh (settings.yaml agent-default-model + routage de l'adaptateur llm).
 *
 * Motivation (retour utilisateur 2026-09-11) : en forme installée 4-entry porte 01 sans modelgw, « plus - configuration des modèles » restait à 503 dégradé,
 * @Agent toujours escaladé à l'humain — les modèles configurés dans la configuration par défaut de dsh (utilisables en dialogue natif dsh) restaient inaccessibles au panneau.
 * Ce pont rend « configuration dsh = catalogue de modèles du panneau » homogène : catalogue en lecture seule (ajout/suppression/modification honnêtement refusés, la source de fait de la configuration est dans dsh),
 * tests/appels via ctx.llm.stream en vraie sortie, jamais de réponse fabriquée.
 *
 * Frontière : ctx.llm absent (forme plateforme purement autonome) → createDshModelGateway renvoie null, comportement strictement identique à l'ancienne version ;
 * modelgw présent (forme complète) → modelgw prioritaire, ce pont ne participe pas. Les entrées de catalogue ont un slug de forme provider:model,
 * avec en plus un slug synthétique 'default' qui suit le choix du modèle par défaut de dsh (agentDefaultModel.read(), sinon le premier routage disponible).
 */
import type { Context } from '@deepseek-ai/cordis'

/** Structure minimale du LlmRuntime dsh (sans dépendre du paquet dsh ; assertion de forme à l'exécution). */
interface DshLlmLike {
  listProviders(): Array<{ id: string; name: string }>
  listModels(provider: string): Promise<Array<{ id: string; name: string; description?: string }>>
  stream(options: {
    provider: string
    model: string
    messages: Array<{ id: string; role: 'user' | 'assistant'; content: Array<{ type: 'text'; text: string }>; source: { kind: 'plugin'; plugin: string } }>
    system?: string
    maxTokens?: number
    signal?: AbortSignal
  }): AsyncIterable<{
    type: 'block-start' | 'text-delta' | 'reasoning-delta' | 'tool-call-delta' | 'block-end' | 'usage' | 'finish'
    text?: string
    usage?: { outputTokens?: number }
    reason?: { kind: string; failure?: { message?: string; code?: string } }
  }>
}

interface DshDefaultModelLike {
  read(): { provider: string; model: string }
}

/** Entrée du catalogue du pont (alignée littéralement sur ModelRecord de modelgw, consommation sans cas particulier par panneau/service). */
export interface BridgedModelRecord {
  id: string
  slug: string
  displayName: string
  provider: string
  endpoint: string
  apiKey: string
  listCentsPerKTokens: number
  costCentsPerKTokens: number
  status: 'online'
  managedBy: 'dsh'
}

export interface BridgedInvokeInput {
  model: string
  messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>
  maxTokens?: number
  signal?: AbortSignal
}

export interface BridgedInvokeResult {
  model: string
  content: string
  outputTokens: number
}

const BRIDGE_PLUGIN_ID = '@ybkk/gate-01/panel-core'

/** Lecture douce du service hôte dsh (même règle que soft de service.ts ; absent = undefined). */
const soft = (ctx: Context, key: string): any => {
  try {
    return ctx.reflect.get(key, false)
  } catch {
    return undefined
  }
}

/** Assertion de forme : ctx.llm doit exposer listProviders/stream pour que la face modèle dsh soit considérée présente. */
const asDshLlm = (value: unknown): DshLlmLike | undefined => {
  const candidate = value as DshLlmLike | undefined
  if (!candidate || typeof candidate.listProviders !== 'function' || typeof candidate.stream !== 'function') return undefined
  return candidate
}

export class DshModelGateway {
  /** Face de collection identique à modelgw : all/findOne/get — le catalogue du pont découvre paresseusement à la demande, findOne passe par un instantané en cache. */
  private cache = new Map<string, BridgedModelRecord>()
  private cacheAt = 0
  private readonly ttlMs = 30_000
  private inflight: Promise<void> | undefined

  private readonly ctx: Context
  private readonly llm: DshLlmLike

  constructor(ctx: Context, llm: DshLlmLike) {
    this.ctx = ctx
    this.llm = llm
  }

  private defaultSelection(): { provider: string; model: string } | undefined {
    const adm = soft(this.ctx, 'agentDefaultModel') as DshDefaultModelLike | undefined
    try {
      const read = adm?.read?.()
      if (read?.provider && read?.model) return { provider: read.provider, model: read.model }
    } catch { /* service de modèle par défaut absent/échec de lecture → repli sur la première route disponible */ }
    return undefined
  }

  /** Instantané du catalogue : default (si résoluble) + tous les modèles découverts de tous les providers. Les routages en échec de découverte sont honnêtement sautés. */
  private async refresh(): Promise<void> {
    if (Date.now() - this.cacheAt < this.ttlMs) return
    if (this.inflight) return this.inflight
    this.inflight = (async () => {
      const next = new Map<string, BridgedModelRecord>()
      const put = (provider: string, model: string, name?: string) => {
        const slug = `${provider}:${model}`
        if (next.has(slug)) return
        next.set(slug, {
          id: `dshmdl_${slug.replace(/[^A-Za-z0-9]/g, '_')}`,
          slug,
          displayName: name ?? model,
          provider,
          endpoint: '（dsh 内置通道，无需登记）',
          apiKey: 'env:DSH_MANAGED',
          listCentsPerKTokens: 0,
          costCentsPerKTokens: 0,
          status: 'online',
          managedBy: 'dsh',
        })
      }
      const preferred = this.defaultSelection()
      if (preferred) put(preferred.provider, preferred.model)
      let providers: Array<{ id: string; name: string }> = []
      try {
        providers = this.llm.listProviders() ?? []
      } catch { /* échec de lecture du registre → catalogue vide, rendu honnête */ }
      for (const provider of providers) {
        try {
          const models = await this.llm.listModels(provider.id)
          for (const model of models ?? []) put(provider.id, model.id, model.name)
        } catch { /* l'échec de découverte d'une seule route n'entraîne pas le catalogue */ }
      }
      this.cache = next
      this.cacheAt = Date.now()
    })().finally(() => {
      this.inflight = undefined
    })
    return this.inflight
  }

  private snapshot(): BridgedModelRecord[] {
    return [...this.cache.values()]
  }

  /** Isomorphe à modelgw models() : face de collection synchrone (lit l'instantané le plus récent ; la face catalogue fait d'abord await ensureCatalog). */
  models() {
    const self = this
    return {
      all: (): BridgedModelRecord[] => self.snapshot(),
      findOne: (predicate: (item: BridgedModelRecord) => boolean): BridgedModelRecord | undefined =>
        self.snapshot().find(predicate),
      get: (id: string): BridgedModelRecord | undefined => self.snapshot().find((item) => item.id === id),
    }
  }

  /** Pré-tirage de la face catalogue (pour GET /models ; la face appel peut sauter — résolution directe par slug). */
  async ensureCatalog(): Promise<BridgedModelRecord[]> {
    await this.refresh()
    return this.snapshot()
  }

  private async resolveTarget(slug: string): Promise<{ provider: string; model: string }> {
    if (slug === 'default') {
      const preferred = this.defaultSelection()
      if (preferred) return preferred
      // Modèle par défaut non configuré/irrésoluble → repli sur la première entrée du catalogue (ordre du catalogue : défaut configuré d'abord, puis ordre d'énumération des providers)
      await this.refresh()
      const first = this.snapshot()[0]
      if (first) {
        const [provider, ...rest] = first.slug.split(':')
        return { provider: provider!, model: rest.join(':') }
      }
      throw new Error('dsh 未配置默认模型且模型目录为空（settings.yaml agent-default-model 或 llm 适配器配置缺失）')
    }
    await this.refresh()
    const hit = this.cache.get(slug)
    if (hit) {
      const [provider, ...rest] = slug.split(':')
      return { provider: provider!, model: rest.join(':') }
    }
    throw new Error(`模型不在 dsh 模型目录中：${slug}（可在 dsh 侧配置后重试；面板模型目录由 dsh 配置托管）`)
  }

  /** Vrai appel en tour unique : toute la chaîne via ctx.llm.stream (adaptateur/retries/metering côté dsh), l'échec est levé tel quel. */
  async invoke(input: BridgedInvokeInput): Promise<BridgedInvokeResult> {
    let content = ''
    let outputTokens = 0
    let finalModel = ''
    for await (const chunk of this.streamEvents(input)) {
      if (chunk.delta) content += chunk.delta
      if (chunk.model) finalModel = chunk.model
      if (chunk.outputTokens) outputTokens = chunk.outputTokens
    }
    return { model: finalModel, content, outputTokens }
  }

  /**
   * Primitive de streaming (carte de réponse en flux du panneau 2026-09-11) : transmet bloc par bloc les text-delta du modèle ; le bloc de fin porte
   * l'information finish et les model/outputTokens finaux. Un échec est levé tel quel pendant l'itération (l'incrément déjà émis par l'appelant est
   * traité comme un échec : pas d'inscription, pas de done — sémantique de dégradation honnête identique à invoke).
   */
  async *streamEvents(input: BridgedInvokeInput): AsyncIterable<{ delta?: string; model?: string; outputTokens?: number }> {
    const target = await this.resolveTarget(input.model)
    const system = input.messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n\n') || undefined
    const messages = input.messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({
        id: `pnl_${Math.random().toString(36).slice(2, 12)}`,
        role: (m.role === 'assistant' ? 'assistant' : 'user') as 'user' | 'assistant',
        content: [{ type: 'text' as const, text: m.content }],
        source: { kind: 'plugin' as const, plugin: BRIDGE_PLUGIN_ID },
      }))
    let content = ''
    let outputTokens = 0
    let finishKind = 'stop'
    let failureText = ''
    try {
      for await (const chunk of this.llm.stream({
        provider: target.provider,
        model: target.model,
        messages,
        ...(system ? { system } : {}),
        ...(input.maxTokens !== undefined ? { maxTokens: input.maxTokens } : {}),
        ...(input.signal ? { signal: input.signal } : {}),
      })) {
        if (chunk.type === 'text-delta' && chunk.text) {
          content += chunk.text
          yield { delta: chunk.text }
        } else if (chunk.type === 'usage' && chunk.usage?.outputTokens) {
          outputTokens = chunk.usage.outputTokens
        } else if (chunk.type === 'finish') {
          finishKind = chunk.reason?.kind ?? 'stop'
          if (chunk.reason?.failure) {
            failureText = chunk.reason.failure.message ?? chunk.reason.failure.code ?? '上游失败'
          }
        }
      }
    } catch (error) {
      throw new Error(`dsh 模型通道调用失败：${error instanceof Error ? error.message : String(error)}`)
    }
    if (finishKind === 'aborted' || finishKind === 'error') {
      throw new Error(`dsh 模型通道调用失败（${finishKind}）：${failureText || '上游未返回内容'}`)
    }
    if (!content.trim()) throw new Error('dsh 模型通道返回空内容（未生成回复，不造假回复）')
    yield { model: input.model === 'default' ? `${target.provider}:${target.model}` : input.model, outputTokens }
  }

  /** Catalogue en lecture seule : les écritures sont honnêtement refusées (la source de fait de la configuration est dans dsh). */
  private static readonly READ_ONLY_MESSAGE =
    '模型目录由 dsh 配置托管（settings.yaml agent-default-model 与 llm 适配器配置）——01门面板只读，请在 dsh 侧增删改模型'

  upsertModel(): never {
    throw new Error(DshModelGateway.READ_ONLY_MESSAGE)
  }

  removeModel(): never {
    throw new Error(DshModelGateway.READ_ONLY_MESSAGE)
  }
}

/**
 * Résout la passerelle de modèles du panneau : modelgw présent prioritaire (sémantique de la forme complète inchangée) ; sinon, si llm dsh est présent, passage par le pont ;
 * les deux absents (forme démo purement autonome) renvoient null — l'appelant suit la dégradation honnête 503 existante.
 */
export function resolvePanelModelGateway(ctx: Context): { kind: 'modelgw' | 'dsh'; gateway: any } | undefined {
  const modelgw = soft(ctx, 'modelGateway')
  if (modelgw) return { kind: 'modelgw', gateway: modelgw }
  const llm = asDshLlm(soft(ctx, 'llm'))
  if (llm) return { kind: 'dsh', gateway: new DshModelGateway(ctx, llm) }
  return undefined
}
