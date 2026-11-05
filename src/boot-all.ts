/**
 * Assemblage de l'arbre de plugins : monte tous les plugins de la plateforme dans l'ordre des dépendances.
 * Cet arbre équivaut au contenu chargé par cordis.yml dans un dsh complet — un seul code de plugin, deux hôtes.
 */
import type { Context } from '@deepseek-ai/cordis'
import * as platformCore from '@dsh-ops/platform-core'
import * as resourceCore from '@dsh-ops/plugin-resource-core'
import * as iam from '@dsh-ops/plugin-iam'
import * as authn from '@dsh-ops/plugin-authn'
import * as usage from '@dsh-ops/plugin-usage'
// plugin-billing est retiré et archivé (M0-2, 2026-09-09) : le portefeuille/la comptabilité en partie double quittent le runtime,
// les flux existants sont exportés en CSV en lecture seule via scripts/billing-archive-export.mjs, archivage 90 jours (voir docs/billing-archive-register.md).
import * as audit from '@dsh-ops/plugin-audit'
import * as market from '@dsh-ops/plugin-market'
import * as connector from '@dsh-ops/plugin-connector'
import * as modelgw from '@dsh-ops/plugin-modelgw'
import * as mcp from '@dsh-ops/plugin-mcp'
import * as nas from '@dsh-ops/plugin-nas'
import * as skillhub from '@dsh-ops/plugin-skillhub'
import * as agent from '@dsh-ops/plugin-agent'
import * as app from '@dsh-ops/plugin-app'
import * as connect from '@dsh-ops/plugin-connect'
import * as update from '@dsh-ops/plugin-update'
import * as portal from '@dsh-ops/plugin-portal'
import * as consolePlugin from '@dsh-ops/plugin-console'
import * as panelCore from '@dsh-ops/plugin-panel-core'
import * as flowCore from '@dsh-ops/plugin-flow-core'
import * as execHub from '@dsh-ops/plugin-exec-hub'
import * as workforce from '@dsh-ops/plugin-workforce'
import * as dingtalkBridge from '@dsh-ops/plugin-dingtalk-bridge'
// Collaboration intranet des employés numériques d'entreprise (A2A/UHP, plan de collaboration §4/§11) : la couche de pilotage d'exécution UHP (facette protocole Server + registre
// de harness configurés) est assemblée avant le plan de collaboration A2A ; leurs interactions passent uniquement par ctx.platformBus (famille d'événements a2a.task.*)
import * as uhp from '@dsh-ops/plugin-uhp'
import * as a2a from '@dsh-ops/plugin-a2a'
// Robustesse du démarrage W2 : assertion de double instance + diagnostic de l'arbre de plugins après assemblage
import { assertSingleRoot, formatTreeHealth, probeTree } from '@dsh-ops/platform-core'

export interface BootOptions {
  dataDir: string
  port: number
}

export async function bootAll(ctx: Context, options: BootOptions): Promise<void> {
  // Avant assemblage : assertion qu'il n'y a qu'un seul root dans le processus (une double instance laisse les fiber en PENDING silencieux, fail-fast obligatoire)
  assertSingleRoot(ctx)
  await ctx.plugin(platformCore, { dataDir: options.dataDir, http: { port: options.port } })
  const restored = await ctx.opsStorage.restoreAll()
  if (restored.length > 0) {
    ctx.logger('boot').info(`已从磁盘恢复 ${restored.length} 个数据集合`)
  }
  await ctx.plugin(resourceCore)
  await ctx.plugin(iam)
  await ctx.plugin(authn)
  await ctx.plugin(usage)
  await ctx.plugin(audit)
  await ctx.plugin(market)
  // Gouvernance des connecteurs (adaptateur passerelle du plan de données open-connector) : dépend d'iam/usage/audit, avant mcp/modelgw
  await ctx.plugin(connector)
  await ctx.plugin(mcp)
  // Actifs NAS (stockage de fichiers FS) : chargés avant skillhub (lors de la mise en ligne, skillhub téléverse skill.zip via nasRegistry)
  await ctx.plugin(nas)
  await ctx.plugin(skillhub)
  await ctx.plugin(agent)
  await ctx.plugin(app)
  await ctx.plugin(modelgw)
  // Rôle de l'hôte : fournir les points d'accès distants (codes d'accès/enroll/gestion des clients) et les outils de gestion des accès
  await ctx.plugin(connect, { role: 'host' })
  // Auto-mise à jour de la plateforme : vérification de version amont (auto+manuelle) et mise à niveau en un clic (forme source)
  await ctx.plugin(update)
  // Canal de données du portail (points de tirage pour systèmes externes, hors cœur ; PORTAL_SYNC=off pour désactiver) :
  // points publics en lecture seule, à assembler avant console — intercepte les requêtes /api/portal/* avant son middleware d'authentification
  await ctx.plugin(portal)
  await ctx.plugin(consolePlugin)
  // Panneau de département (review-dsh-agent-panel-v2) : REST dépend de l'enregistrement préalable du middleware d'authentification console (facette Bearer /api/*) ;
  // les routes auto-enregistrées convergent via le registre partagé httpServer.routeMatrix vers la matrice d'assertions RBAC
  await ctx.plugin(panelCore)
  // Moteur de flux de transactions (IAW passation 3-1..3-4, nouveau domaine de l'hôte) : routes guarded auto-enregistrées /api/flow/*, dépendent aussi du middleware console en amont
  await ctx.plugin(flowCore)
  // Centre d'exécution (ybkk-MATRIX objectif quatre « hub d'exécution ») : lignée d'objectifs/verrous d'exécution de tâches/réveils par heartbeat/ordonnancement de routines,
  // routes guarded auto-enregistrées /api/exec/* — dépendent du middleware console et de resourceCore/agentRegistry/modelgw/flow en amont
  await ctx.plugin(execHub)
  // Domaine des employés numériques (employés/affectations/permit/appels contrôlés/réception des livrables) : routes guarded /api/workforce/* dépendant du middleware console,
  // le parcours de travail des employés dépend d'exec-hub en amont — à monter après lui et avant le pont DingTalk ; une fois assemblé, enregistre l'implémentation de stratégie via le
  // point d'entrée étroit workforcePolicy de platform-core (artifact staging et SQLite sur la même base, répertoire de données réutilisant options.dataDir)
  await ctx.plugin(workforce, { dataDir: options.dataDir })
  // Pont DingTalk (pont de groupe/distribution sortante/poussée des approbations/canal d'alertes) : s'abonne à panel.message.created et audit.alert.fired
  await ctx.plugin(dingtalkBridge)
  // Pilotage d'exécution UHP (plan de collaboration §7) : facette protocole /v1/uhp + routes guarded /api/uhp/* — dépendent du middleware console et
  // de modelgw en amont ; s'abonne à a2a.task.dispatch/cancel, publie a2a.task.progress
  await ctx.plugin(uhp)
  // Plan de collaboration A2A (plan de collaboration §5/§6) : carte well-known/annuaire/facette méthodes JSON-RPC/cinq contrôles de gouvernance/moteur de négociation/
  // recette/inspections — dépend de skillhub/mcp/agent en amont (projection des ensembles d'autorisation de cartes), distribution et exécution passent uniquement par le bus d'événements
  await ctx.plugin(a2a)
  // Diagnostic post-assemblage : doit s'exécuter après tous les await ctx.plugin (à cet instant tous les fiber doivent être ACTIVE) ;
  // si un service requis est inaccessible ou qu'un fiber bloqué empêche le démarrage, on refuse directement le démarrage — jamais de simple alerte en mode dégradé
  // (les fiber FAILED sont exemptés uniquement si le provide déclaré a déjà été repris par un autre fiber ACTIVE, voir boot-probe.ts)
  const health = probeTree(ctx, ['opsStorage', 'platformBus', 'httpServer', 'iam', 'authn', 'usage', 'audit'])
  if (!health.ok) {
    throw new Error(formatTreeHealth(health))
  }
}
