/**
 * Contexte de plugin léger (proxy ctx) : première ligne de défense de la frontière d'exécution des plugins tiers.
 * Périmètre (conception écosystème v1.2 étape 3, résolution S3) : **uniquement l'authentification de la source d'événements + l'élagage des capacités**,
 * pas de sandbox au niveau module (l'isolation require/fs/net relève de l'étape 10, sandbox L1 autonome).
 *
 * Déclaration des trois lignes de défense : proxy ctx (forçage à l'exécution) → lint/scan statique (contournable) → réconciliation à l'exécution
 * (principal/resource des événements usage vs capabilities déclarées du manifest ; écart → alerte et retrait).
 */
import type { Context } from '@deepseek-ai/cordis'

/** Capacité plateforme → nom de service ctx (fondement de la liste blanche d'élagage). */
export const CAPABILITY_SERVICES: Record<string, string[]> = {
  'model-gateway.invoke': ['modelGateway'],
  'knowledgebase.read': [],
  'audit.emit': [],
  'usage.meter': ['usage'],
  'storage.scoped': [],
}

export interface PluginSandboxOptions {
  pluginId: string
  /** Ensemble de capacités approuvées par l'entreprise à l'installation (approved ⊆ requested). */
  capabilities: string[]
}

/**
 * Construit le contexte proxy du plugin :
 *   - platformBus.emit force source: plugin:<id>, les noms d'événements sont forcés dans le préfixe plugin:<id>: ;
 *   - l'accès aux services plateforme est élagué selon les capabilities approuvées, tout accès hors permission lève ;
 *   - le chemin d'émission interne de la plateforme (sans source) est inaccessible aux plugins.
 */
export function createPluginContext(ctx: Context, options: PluginSandboxOptions): PluginContext {
  const { pluginId, capabilities } = options
  const allowed = new Set(capabilities)

  const platformBus = {
    on: (event: string, cb: (payload: unknown, event: unknown) => void) => ctx.platformBus.on(event, cb as never),
    /** Événements de plugin : uniquement leur propre espace de noms ; la couche bus reforce une fois de plus la cohérence de source. */
    emit: (name: string, payload: unknown) => {
      if (!name.startsWith(`plugin:${pluginId}:`)) {
        throw new Error(`[plugin-ctx] 插件 ${pluginId} 只能发射 plugin:${pluginId}: 前缀的事件，收到：${name}`)
      }
      return ctx.platformBus.emit(name, payload, { source: `plugin:${pluginId}` })
    },
    recent: (limit?: number) => ctx.platformBus.recent(limit),
  }

  const proxy = new Map<string, unknown>()

  return {
    pluginId,
    capabilities: [...allowed],
    platformBus,
    /** Point d'accès aux services avec élagage des capacités : lève pour un service non autorisé (forçage à l'exécution). */
    service(name: string): unknown {
      const entry = Object.entries(CAPABILITY_SERVICES).find(([, services]) => services.includes(name))
      const capability = entry?.[0] ?? name
      if (!allowed.has(capability) && !allowed.has('*')) {
        throw new Error(`[plugin-ctx] 插件 ${pluginId} 未获能力 ${capability}，禁止访问服务 ${name}（安装时审批的能力集为准）`)
      }
      if (!proxy.has(name)) {
        const target = (ctx as unknown as Record<string, unknown>)[name]
        if (target === undefined) throw new Error(`[plugin-ctx] 平台服务不存在：${name}`)
        proxy.set(name, target)
      }
      return proxy.get(name)
    },
  }
}

export interface PluginContext {
  readonly pluginId: string
  readonly capabilities: string[]
  platformBus: {
    on: (event: string, cb: (payload: unknown, event: unknown) => void) => () => void
    emit: (name: string, payload: unknown) => unknown
    recent: (limit?: number) => unknown[]
  }
  service(name: string): unknown
}
