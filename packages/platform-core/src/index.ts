/**
 * @dsh-ops/platform-core —— plugin de base de la plateforme.
 *
 * Fournit quatre services de base (tout est plugin : la couche de base aussi) :
 *   ctx.opsStorage      stockage de collections JSON (écriture atomique, remplaçable par une implémentation DB)
 *   ctx.platformBus     bus d'événements de la plateforme (la seule couche de liaison entre plugins)
 *   ctx.tools           ToolRuntime-lite (fourni en hôte autonome ; en dsh complet, fourni par le vrai ToolRuntime)
 *   ctx.httpServer      serveur HTTP (API REST de la console et ressources statiques)
 */
import type { Context } from '@deepseek-ai/cordis'
import { StorageService } from './storage.ts'
import { PlatformBusService } from './bus.ts'
import { ToolRuntimeLite } from './tools-lite.ts'
import { HttpServerService } from './http.ts'
import { SqliteTxnService } from './sqlite.ts'
import { WorkforcePolicyRegistry } from './workforce-port.ts'
import { BehaviorService } from './behavior.ts'
import { ScenegraphService } from './scenegraph.ts'

export * from './storage.ts'
export * from './storage-sqlite.ts'
export * from './bus.ts'
export * from './tools-lite.ts'
export * from './http.ts'
// Projection de la facette API en OpenAPI (issue #6) : document 3.0.3 généré depuis le registre declaredRoutes, servi par /api/openapi.json
export * from './openapi.ts'
export * from './rest-gate.ts'
export * from './principal.ts'
// Point de décision de stratégie + primitives de trace de bout en bout (contrat de gouvernance MCP §11/§14, W3-T5)
export * from './pdp.ts'
export * from './trace.ts'
export * from './ids.ts'
export * from './sensitive.ts'
export * from './sqlite.ts'
export * from './workforce-port.ts'
export * from './host-bridge.ts'
export * from './yaml.ts'
export * from './zip.ts'
export * from './plugin-ctx.ts'
export * from './version.ts'
export * from './behavior.ts'
export * from './scenegraph.ts'
export * from './signature.ts'
export * from './boot-probe.ts'
// Classification métier unifiée des actifs plateforme (périmètre partagé par les volets Skill/Agent/Applications/MCP/A2A)
export * from './taxonomy.ts'

export interface PlatformCoreConfig {
  dataDir?: string
  /** true par défaut en hôte autonome ; false une fois monté dans dsh complet, pour éviter le conflit avec le vrai ToolRuntime. */
  provideToolRuntime?: boolean
  http?: { port?: number; host?: string; externalBase?: string }
  /** Faut-il démarrer automatiquement l'écoute HTTP. */
  startHttp?: boolean
}

export const name = 'platform-core'

export async function apply(ctx: Context, config: PlatformCoreConfig = {}) {
  const storage = new StorageService(ctx, { dataDir: config.dataDir })
  ctx.plugin(PlatformBusService)
  ctx.plugin(SqliteTxnService, { dataDir: config.dataDir })
  // Enregistreur de stratégie de travail des employés numériques (port étroit) : plugin-workforce enregistre son implémentation une fois ready,
  // les passerelles de ressources/exec-hub consomment via ctx.workforcePolicy (indépendant de l'ordre d'assemblage, anti-cycle de dépendances)
  ctx.plugin(WorkforcePolicyRegistry)
  if (config.provideToolRuntime !== false) {
    ctx.plugin(ToolRuntimeLite)
  }
  const http = new HttpServerService(ctx, config.http ?? {})
  // La restauration des collections doit précéder toute lecture de collection métier (leçon forme B : le restoreAll de boot-all n'existait
  // pas dans la chaîne loader → collections toutes vides → le ré-ensemencement de démo percutait une clé d'idempotence, fatal). apply asynchronisé, le loader attend.
  await storage.start()
  await storage.restoreAll()
  // Pipeline d'événements comportementaux behavior (WP-03/D6) : points montés avec la couche de base, authentification dépendant du middleware console + double validation de ce point
  ctx.plugin(BehaviorService)
  // Service de graphe de scénarios sectoriels (review-dsh-agent-panel-v2 Phase 2) : chargement via le canal d'actifs intégrés + rafraîchissement à chaud scenegraph.updated
  ctx.plugin(ScenegraphService)
  if (config.startHttp !== false) {
    void http.start().then(() => {
      ctx.logger('platform-core').info(`HTTP 服务已启动：http://${http.host}:${http.port}`)
    }, (error: unknown) => {
      ctx.logger('platform-core').error('HTTP 服务启动失败', error)
    })
  }
}
