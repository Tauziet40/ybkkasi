/**
 * ToolRuntime-lite : implémentation hôte autonome du ToolRuntime de dsh (même clé de service que dsh : `tools`).
 *
 * - Contrat d'enregistrement aligné sur dsh : ToolDefinition = { name, description, parameters(JSON Schema),
 *   output: { schema, render }, execute(args, exec) } ; la déclaration output est validée à l'enregistrement.
 * - execute() fige l'instantané des paramètres, exécute la chaîne de guards, valide la valeur canonique, produit les blocs de contenu via render.
 * - Dans un runtime dsh complet, ce service n'est pas chargé (provideToolRuntime=false),
 *   les définitions des mêmes plugins s'enregistrent directement dans le vrai ToolRuntime, où le modèle peut les appeler.
 */
import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'

export interface ContentBlock {
  type: 'text'
  text: string
}

/** Identité de l'appelant (résolue par le point d'entrée depuis le jeton puis injectée ; interdiction pour un outil de lire l'identité depuis args). */
export interface ToolPrincipal {
  kind: 'human' | 'machine'
  principalId: string
  userId?: string
  /** D01 (additif) : spécifique machine — type de ressource liée à l'identifiant (refType=agent : permet de reconnaître l'employé numérique lié). */
  refType?: string
  /** D01 (additif) : spécifique machine — id de la ressource liée à l'identifiant. */
  refId?: string
  name: string
  permissions: string[]
  actChain?: Array<{ name: string; type: string }>
}

export interface ToolRunContext {
  callId: string
  name: string
  signal: AbortSignal
  agent?: unknown
  token?: symbol
  /** Identité de l'appelant ; les outils liés à l'identité doivent fail-closed en cas d'absence, jamais retomber sur une identité partagée. */
  principal?: ToolPrincipal
}

export interface ToolDefinitionLite {
  name: string
  description: string
  /** JSON Schema (racine object), identique au champ parameters de l'enregistrement natif dsh. */
  parameters: Record<string, unknown>
  output: {
    schema: Record<string, unknown>
    render: (args: unknown, value: unknown) => ContentBlock[]
  }
  execute: (args: any, exec: ToolRunContext) => Promise<unknown>
  timeoutMs?: number
  /** Nom du plugin d'origine (pour l'enregistrement de ce runtime). */
  plugin?: string
  /** Point de permission minimal requis pour l'appel (RBAC). Par défaut : aucune permission supplémentaire (simple login). */
  permission?: string
}

export interface ToolExecutionResultLite {
  isError: boolean
  value?: unknown
  content: ContentBlock[]
  error?: { message: string }
  callId: string
  name: string
  durationMs: number
}

export type ToolGuardLite = (input: { name: string; arguments: unknown }) => string | undefined

/**
 * Guard contextuel (D02/D03 additifs) : s'exécute après l'ancien ToolGuardLite, avec en plus
 * l'identité de l'appelant (principal) et le callId — points d'entrée/passerelles continuent de gérer permissions et stratégie, la chaîne de guards
 * gagne ici la visibilité d'identité (les outils fail-closed sans identité peuvent intercepter ici de façon unifiée). L'ancien ToolGuardLite reste inchangé.
 * Renvoie une chaîne = motif de refus ; renvoie undefined = passage autorisé.
 */
export type ContextualToolGuard = (input: { name: string; arguments: unknown; principal?: ToolPrincipal; callId: string }) => string | undefined

/** Intercepteur d'enregistrement (point d'extension officiel OPT-P1-03) : tout appel register passe d'abord par la chaîne d'interception, qui renvoie la (potentiellement remplacée) définition. */
export type ToolInterceptor = (definition: ToolDefinitionLite) => ToolDefinitionLite

export class ToolRuntimeLite extends Service {
  static readonly provide = 'tools'

  private definitions = new Map<string, ToolDefinitionLite>()
  private guards: ToolGuardLite[] = []
  private contextualGuards: ContextualToolGuard[] = []
  private interceptors: ToolInterceptor[] = []

  constructor(ctx: Context) {
    super(ctx, 'tools')
  }

  register(definition: ToolDefinitionLite): () => void {
    for (const fn of this.interceptors) definition = fn(definition)
    const { name, output } = definition
    if (typeof name !== 'string' || !name) throw new TypeError(`[tools] 工具名必须是非空字符串`)
    if (output === undefined || typeof output !== 'object' || typeof output.render !== 'function') {
      throw new TypeError(`工具 "${name}" 必须声明 output { schema, render }`)
    }
    // OPT-P2-04 : validation forte du schéma — force contractuelle alignée sur le récit du rapport initial (auparavant seul render était contrôlé, pas schema)
    if (output.schema === undefined || output.schema === null || typeof output.schema !== 'object' || Array.isArray(output.schema)) {
      throw new TypeError(`工具 "${name}" 必须声明 output.schema（非空对象根，JSON Schema）`)
    }
    if (this.definitions.has(name)) throw new Error(`[tools] 工具名重复：${name}`)
    this.definitions.set(name, definition)
    try {
      this.ctx.platformBus?.emit('tools/change', { kind: 'register', name })
    } catch {
      // Si platformBus n'est pas injecté dans le fiber courant, on saute la notification (accès strict aux services cordis)
    }
    return () => {
      this.definitions.delete(name)
    }
  }

  guard(guard: ToolGuardLite): () => void {
    this.guards.push(guard)
    return () => {
      const index = this.guards.indexOf(guard)
      if (index >= 0) this.guards.splice(index, 1)
    }
  }

  /**
   * Enregistreur de guards contextuels (D02/D03 additifs) : les guards enregistrés s'exécutent après que toute l'ancienne chaîne a passé,
   * dans l'ordre d'enregistrement, avec injection de principal/callId. Tout motif de refus court-circuite (même forme d'échec que
   * l'ancien guard : isError + libellé de refus en chinois). Renvoie la fonction de désinscription.
   */
  guardContext(guard: ContextualToolGuard): () => void {
    if (typeof guard !== 'function') throw new TypeError('[tools] guardContext 的 guard 必须是函数')
    this.contextualGuards.push(guard)
    return () => {
      const index = this.contextualGuards.indexOf(guard)
      if (index >= 0) this.contextualGuards.splice(index, 1)
    }
  }

  /**
   * Intercepteur d'enregistrement (point d'extension officiel OPT-P1-03) : à partir de là, tout register passe par la chaîne d'interception avant la table.
   * Permet de greffer des capacités transversales comme le transfert distant connect sur le contrat, en remplacement du monkey-patch de prototype. Renvoie la fonction de désinscription.
   */
  intercept(fn: ToolInterceptor): () => void {
    if (typeof fn !== 'function') throw new TypeError('[tools] intercept 的拦截器必须是函数')
    this.interceptors.push(fn)
    return () => {
      const index = this.interceptors.indexOf(fn)
      if (index >= 0) this.interceptors.splice(index, 1)
    }
  }

  /**
   * Habillage des exécuteurs des outils enregistrés (point d'extension officiel OPT-P1-03) : remplace l'execute courant par wrap,
   * wrap reçoit l'exécuteur original et renvoie le nouvel exécuteur. Renvoie la fonction de restauration (inverse de l'état au moment de l'habillage).
   * Outil inexistant : lève TypeError (pas de silence).
   */
  decorate(name: string, wrap: (execute: ToolDefinitionLite['execute']) => ToolDefinitionLite['execute']): () => void {
    const definition = this.definitions.get(name)
    if (!definition) throw new Error(`[tools] decorate 目标工具不存在：${name}`)
    if (typeof wrap !== 'function') throw new TypeError(`[tools] decorate 的 wrap 必须是函数（工具 ${name}）`)
    const previous = definition.execute
    definition.execute = wrap(previous)
    return () => {
      definition.execute = previous
    }
  }

  schemas(): Array<{ name: string; description: string; parameters: Record<string, unknown>; plugin?: string; permission?: string }> {
    return [...this.definitions.values()].map(({ name, description, parameters, plugin, permission }) => ({
      name,
      description,
      parameters,
      plugin,
      permission,
    }))
  }

  has(name: string): boolean {
    return this.definitions.has(name)
  }

  async execute(input: { name: string; arguments?: unknown; signal?: AbortSignal; principal?: ToolPrincipal }): Promise<ToolExecutionResultLite> {
    const started = Date.now()
    const callId = randomUUID()
    const name = input.name
    const args = input.arguments ?? {}
    const base = { callId, name }
    const definition = this.definitions.get(name)
    if (!definition) {
      return { ...base, isError: true, content: [{ type: 'text', text: `未知工具：${name}` }], error: { message: `未知工具：${name}` }, durationMs: 0 }
    }
    for (const guard of this.guards) {
      const reason = guard({ name, arguments: args })
      if (reason) {
        return { ...base, isError: true, content: [{ type: 'text', text: `调用被拒绝：${reason}` }], error: { message: reason }, durationMs: Date.now() - started }
      }
    }
    // Guards contextuels (D02/D03) : s'exécutent après l'ancienne chaîne de guards, injectent la visibilité d'identité (principal/callId)
    for (const guard of this.contextualGuards) {
      const reason = guard({ name, arguments: args, ...(input.principal ? { principal: input.principal } : {}), callId })
      if (reason) {
        return { ...base, isError: true, content: [{ type: 'text', text: `调用被拒绝：${reason}` }], error: { message: reason }, durationMs: Date.now() - started }
      }
    }
    const signal = input.signal ?? new AbortController().signal
    const exec: ToolRunContext = { callId, name, signal, ...(input.principal ? { principal: input.principal } : {}) }
    try {
      const value = await definition.execute(structuredClone(args), exec)
      const content = safeRender(definition, args, value)
      return { ...base, isError: false, value, content, durationMs: Date.now() - started }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return { ...base, isError: true, content: [{ type: 'text', text: `工具执行失败：${message}` }], error: { message }, durationMs: Date.now() - started }
    }
  }
}

function safeRender(definition: ToolDefinitionLite, args: unknown, value: unknown): ContentBlock[] {
  try {
    const rendered = definition.output.render(args, value)
    return Array.isArray(rendered) ? rendered : [{ type: 'text', text: JSON.stringify(value) }]
  } catch {
    return [{ type: 'text', text: JSON.stringify(value) }]
  }
}

// ---------------------------------------------------------------------------
// Aides aux définitions d'outils plateforme : description de paramètres à plat → JSON Schema, sortie rendue en JSON pretty par défaut.
// Cette forme correspond au contrat d'enregistrement du ToolRuntime natif dsh, enregistrable tel quel sur les deux hôtes.
// ---------------------------------------------------------------------------

export interface ToolParamSpec {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object'
  required?: boolean
  description?: string
  enum?: Array<string | number>
  items?: Record<string, unknown>
}

export interface PlatformToolSpec {
  name: string
  description: string
  /** Nom du plugin (pour l'origine d'enregistrement). */
  plugin?: string
  parameters: Record<string, ToolParamSpec>
  /** Nœud racine du JSON Schema de sortie. */
  output: Record<string, unknown>
  /** Rendu visible du modèle personnalisé (JSON pretty print par défaut). */
  render?: (args: unknown, value: unknown) => ContentBlock[]
  timeoutMs?: number
  /** Point de permission minimal requis pour l'appel (RBAC). Par défaut : aucune permission supplémentaire (simple login). */
  permission?: string
  execute: (args: any, exec: ToolRunContext) => Promise<unknown>
}

export function defineTool(spec: PlatformToolSpec): ToolDefinitionLite {
  const properties: Record<string, unknown> = {}
  const required: string[] = []
  for (const [key, param] of Object.entries(spec.parameters)) {
    const node: Record<string, unknown> = { type: param.type }
    if (param.description) node.description = param.description
    if (param.enum) node.enum = param.enum
    if (param.items) node.items = param.items
    properties[key] = node
    if (param.required) required.push(key)
  }
  const parameters: Record<string, unknown> = {
    type: 'object',
    properties,
    ...(required.length > 0 ? { required } : {}),
  }
  return {
    name: spec.name,
    description: spec.description,
    plugin: spec.plugin,
    ...(spec.permission !== undefined ? { permission: spec.permission } : {}),
    parameters,
    output: {
      schema: spec.output,
      render: spec.render ?? ((_args: unknown, value: unknown) => [
        { type: 'text', text: JSON.stringify(value, null, 2) },
      ]),
    },
    ...(spec.timeoutMs !== undefined ? { timeoutMs: spec.timeoutMs } : {}),
    execute: spec.execute,
  }
}
