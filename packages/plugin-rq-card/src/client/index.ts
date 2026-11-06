/**
 * Moitié navigateur : enregistrement de slots + sonde de dégradation (livrables 1/3 de WP-06, atterrissage du pseudo-code spike §4.3).
 *
 * [Face d'injection] deux slots :
 *   ① carte d'exécution à quatre états : enregistre un `tool.call.toolview` pour chaque nom d'outil métier de method (RQ_TOOL_NAMES)
 *      entrée clavier — additif, les outils non listés retombent sur le GenericToolCard de dsh ;
 *   ② barre de feedback 👍/👎 : entrée du list `conversation.chat.assistant-actions`
 *      (id 'rq-feedback', coexiste avec le 'feedback' intégré de dsh, order 20 derrière).
 *
 * [Resserrement de la face de couplage W5] toutes les dépendances de ce fichier envers l'hôte convergent via createClientHostPort
 * dans le port étroit HostClientPort (contrat déclaré dans platform-core/src/host-bridge.ts) ; les types
 * des trois paquets dsh n'entrent qu'en un point, host-port.ts — en cas de dérive d'API dsh à une montée de version, adapter + relancer
 * les tests de contrat (tests/host-bridge.contract.mjs), le corps de l'extension ne bouge pas.
 *
 * [Plan de repli (items 1-4 du spike §5, appliqués un à un dans ce apply)]
 *   1. toutes les dépendances déclarées passent par ctx.slots.inject : slot cible non déclaré = la callback ne s'exécute jamais, l'injection reste
 *      paresseuse — renommage/suppression de slot amont = la carte disparaît silencieusement, sans faire tomber l'hôte (rattrapage naturel du mécanisme) ;
 *   2. sonde explicite : contrôle d'existence specDynamic(name) dans apply + vérification
 *      de spec.kind à l'exécution de la callback ; toute non-satisfaction → marque de dégradation (tableau DEGRADED) ;
 *   3. sonde de la face boot : window.__DSH_BOOT__ / bundle 404 relèvent du « mécanisme globalement absent »,
 *      dans ce scénario le présent bundle ne s'exécutera pas du tout, aucun traitement côté code nécessaire (voir spike §5 item 3) ;
 *   4. apply entièrement sous try/catch : toute erreur levée est avalée et pose le marqueur de dégradation ; la frontière slot a par ailleurs
 *      le mécanisme d'abandon reportEntryError (une carte qui crash ne rend que sa cellule) — double assurance ;
 *   5. (le repli est côté outils hôte) le texte du résultat d'outil porte toujours un résumé markdown + lien /rq,
 *      voir le contrat summarizeForToolResult de src/index.ts ;
 *   6. marqueur de dégradation présent = coin « extension de cartes inactive » monté via shell.overlay (monté seulement si le slot existe).
 * @module @dsh-ops/plugin-rq-card/client
 */

import { createElement } from 'react'
import type { ClientContext, SessionId } from './host-port.ts'
import { createClientHostPort } from './host-port.ts'
import type { HostClientPort } from '../../../platform-core/src/host-bridge.ts'
import { deriveExecutionState } from './state.ts'
import { RqFeedbackController } from './controller.ts'
import { ExecutionCard } from './ExecutionCard.tsx'
import { RqFeedback } from './RqFeedback.tsx'
import type { RqFeedbackInjected, RqToolviewInjected } from './slots.ts'
import { en, ja, zh } from './locales.ts'
import { ensureStyles } from './styles.ts'
import {
  DEGRADED_BADGE_ID, FEEDBACK_ENTRY_ID, SLOT_ASSISTANT_ACTIONS, SLOT_OVERLAY,
  SLOT_TOOLVIEW, TOOLVIEW_ENTRY_PREFIX,
} from '../wire.ts'

export type { ExecutionState, ExecutionStateInput, BlockedReason } from './state.ts'
export type { RqFeedbackView, RqToolviewInjected, RqFeedbackInjected } from './slots.ts'
export { deriveExecutionState } from './state.ts'

/** Espace de noms du dictionnaire (nom de place du LocaleNamespaceMap de locales.ts). */
const NS = 'rq-card'

/** id de l'extension (identique au name de package.json et à l'id de ligne du graphe boot). */
const PLUGIN_ID = '@dsh-ops/plugin-rq-card'

/**
 * Répertoire des noms d'outils de method (liste enregistrée des tools.ts des paquets, à la date de WP-06).
 * La carte d'exécution à quatre états enregistre des touches pour ces outils ; un nouvel outil n'obtient pas automatiquement de carte (repli GenericToolCard),
 * ajouter une ligne ici suffit à le couvrir. Le rôle principal est mcp_invoke (terrain principal des quatre états de l'acheminement d'actifs).
 */
const RQ_TOOL_NAMES: readonly string[] = [
  // acheminement d'actifs (terrain principal des quatre états)
  'mcp_invoke', 'mcp_service_list', 'mcp_health_check', 'mcp_metrics', 'mcp_deploy', 'mcp_offline',
  // NAS (fichiers/répertoire de savoir)
  'nas_list', 'nas_get', 'nas_health_check', 'nas_fs_list', 'nas_fs_search', 'nas_fs_upload', 'nas_fs_mkdir', 'nas_fs_delete',
  // skills
  'skill_search', 'skill_submit', 'skill_approve', 'skill_publish', 'skill_install', 'skill_deprecate',
  // applications
  'app_list', 'app_metrics', 'app_cost_breakdown', 'app_topology', 'app_metrics_report',
  // Agent
  'agent_list', 'agent_get', 'agent_bind_user', 'agent_metrics', 'agent_metrics_report', 'agent_offline',
  // identité et accès
  'iam_user_list', 'iam_user_create', 'iam_user_freeze', 'iam_user_reset_password', 'iam_org_tree',
  'iam_org_create', 'iam_org_update', 'iam_role_list', 'iam_sync_run', 'iam_conflict_list',
  'authn_token_issue', 'authn_token_list', 'authn_token_revoke', 'authn_credential_create',
  'authn_credential_rotate', 'authn_credential_scopes',
  // connecteurs / modèles / facturation / audit / marché / approbations
  'connector_catalog_search', 'connector_connection_list', 'connector_execute', 'connector_run_list', 'connector_perm_group_list',
  'model_list', 'billing_wallet_balance', 'audit_logs', 'audit_alerts_list', 'audit_alerts_read_all',
  'audit_cost_report', 'market_plugin_list', 'approval_decide',
]

/** Registre des motifs de dégradation (le « marqueur de dégradation » des items 2/4 du spike §5). */
const DEGRADED: string[] = []

/** Consigne un motif de dégradation (trace console pour l'exploitation ; jamais levé). */
function markDegraded(what: string, error?: unknown): void {
  DEGRADED.push(what)
  console.warn(`[rq-card] degraded (${what}):`, error ?? 'target slot unavailable')
}

/** Exécute sûrement une action d'injection ; l'erreur levée est avalée et consignée en dégradation (spike §5 item 4). */
function safely(what: string, action: () => void): void {
  try {
    action()
  } catch (error) {
    markDegraded(what, error)
  }
}

/** Sonde specDynamic (absent/jette/non-objet déjà repliés en undefined par l'adaptateur). */
function probeSpec(host: HostClientPort, slot: string): { kind?: string } | undefined {
  return host.slots.specDynamic?.(slot)
}

/** Services requis : registre de slots + dictionnaire. */
export const inject = ['slots', 'locale']

/**
 * Entrée du corps de l'extension cliente (contrat du loader client dsh : inject + apply(ctx)).
 * @param ctx - context racine client.
 */
export function apply(ctx: ClientContext): void {
  applyViaPort(createClientHostPort(ctx))
}

/**
 * Corps de l'extension (ne dépend que du port étroit ; les tests de contrat tournent directement par cette entrée + port simulé).
 * @param host - port étroit du pont hôte (face minimale resserrée de ctx.slots / ctx.locale / ctx.effect).
 */
export function applyViaPort(host: HostClientPort): void {
  // La feuille de style d'abord (idempotent ; sans environnement document, saut automatique).
  safely('styles', () => { ensureStyles() })

  // Enregistrement du dictionnaire.
  safely('locale', () => {
    host.effect(() => host.locale.register(NS, { zh, en, ja }), 'rq-card: dictionaries')
  })

  // ── ① carte d'exécution à quatre états : sonde explicite + enregistrement de touches (spike §5 item 2) ──
  const toolviewSpec = probeSpec(host, SLOT_TOOLVIEW)
  if (toolviewSpec?.kind !== 'keyed') {
    markDegraded(`${SLOT_TOOLVIEW} spec missing or not keyed`, toolviewSpec)
  } else {
    for (const tool of RQ_TOOL_NAMES) {
      safely(`toolview:${tool}`, () => {
        host.slots.inject(SLOT_TOOLVIEW, () => host.slots.register({
          name: SLOT_TOOLVIEW,
          key: tool,
          id: `${TOOLVIEW_ENTRY_PREFIX}${tool}`,
          locale: NS,
          inject: (): RqToolviewInjected => ({
            // unique entrée de la mise en correspondance C2 ; healthSnapshot est le point de câblage ultérieur de la moitié hôte.
            deriveState: deriveExecutionState,
          }),
        }, ExecutionCard))
      })
    }
  }

  // ── ② barre de feedback 👍/👎 : entrée list, coexiste avec le 'feedback' intégré de dsh ──
  const actionsSpec = probeSpec(host, SLOT_ASSISTANT_ACTIONS)
  if (actionsSpec?.kind !== 'list') {
    markDegraded(`${SLOT_ASSISTANT_ACTIONS} spec missing or not list`, actionsSpec)
  } else {
    safely('assistant-actions', () => {
      host.slots.inject(SLOT_ASSISTANT_ACTIONS, () => {
        const controllers = new Map<SessionId, RqFeedbackController>()
        const controllerFor = (sessionId: SessionId): RqFeedbackController => {
          let controller = controllers.get(sessionId)
          if (controller === undefined) {
            controller = new RqFeedbackController()
            controllers.set(sessionId, controller)
          }
          return controller
        }
        const dispose = host.slots.register({
          name: SLOT_ASSISTANT_ACTIONS,
          id: FEEDBACK_ENTRY_ID,
          order: 20,
          locale: NS,
          inject: (sessionId): RqFeedbackInjected => {
            const controller = controllerFor(sessionId as SessionId)
            return {
              hooks: { rqfb: controller },
              rate: (messageId, score, note) => controller.rate(messageId, score, note),
            }
          },
        }, RqFeedback)
        return () => {
          dispose()
          controllers.clear()
        }
      })
    })
  }

  // ── ③ coin de repli : seulement s'il y a vraiment un motif de dégradation et que shell.overlay existe encore (spike §5 item 6) ──
  if (DEGRADED.length > 0) {
    const overlaySpec = probeSpec(host, SLOT_OVERLAY)
    if (overlaySpec?.kind === 'list') {
      safely('overlay-badge', () => {
        host.slots.inject(SLOT_OVERLAY, () => host.slots.register({
          name: SLOT_OVERLAY,
          id: DEGRADED_BADGE_ID,
          order: 90,
          locale: NS,
        }, function RqCardDegradedBadge(props?: unknown) {
          // Dictionnaire injecté via la place locale: NS (props.t) ; contrat de slot sans t injecté = repli texte chinois — préférer sous-traduire plutôt que jeter.
          const maybeT = (props as { t?: unknown } | undefined)?.t
          const translate = typeof maybeT === 'function'
            ? (maybeT as (key: string) => string)
            : ((key: string) => (zh as Record<string, string>)[key] ?? key)
          // aucune autre dépendance de props : tout changement du contrat de slot ne fera au pire qu'un coin vide, jamais d'erreur.
          // ce fichier est .ts (non tsx), donc createElement plutôt qu'un littéral JSX.
          return createElement('span', { className: 'rq-badge' }, translate('badge.degraded'))
        }))
      })
    }
    console.warn(`[rq-card] degraded mode with ${DEGRADED.length} reason(s); markdown fallback remains available`)
  }

  // [Auto-attestation fumable (premier jalon d'intégration du risque R8 du spike)] après boot, on peut vérifier dans la console :
  //   window.__DSH_BOOT__ contient une ligne { id: '@dsh-ops/plugin-rq-card', ... },
  //   et ce log apparaît — les deux réunis prouvent « l'extension vide sur la chaîne » établie.
  console.info('[rq-card] client plugin applied:', PLUGIN_ID)
}
