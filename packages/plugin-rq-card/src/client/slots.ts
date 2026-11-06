/**
 * Types de la face d'injection (combinaison InjectFace / PropsRuntime, slots.ts de la liste de fichiers spike §4.1).
 *
 * Forme des props des deux entrées de slot :
 *   - ExecutionCard ← slot clavier `tool.call.toolview` : l'owner (ToolCallTree d'ui-tool)
 *     fournit callId/toolName/block/cwd/openFile/inspect ; InjectFace déploie le produit
 *     de la callback inject de la présente extension ; PropsLocale lie la place du dictionnaire `rq-card`.
 *   - RqFeedback ← slot list `conversation.chat.assistant-actions` : l'owner fournit
 *     messageId (spike §2.4 preuve D2).
 *
 * Toutes les références de paquets dsh sont type-only (effacées à la compilation, hors bundle, sans toucher la barrière de pureté du build).
 * @module @dsh-ops/plugin-rq-card/client/slots
 */

import type {
  HostObservable, InjectFace, PropsLocale, PropsRuntime,
} from '@deepseek-ai/dsh-client-ui-slots'
// Type-only : introduit la fusion SlotMap d'ui-conversation (forme d'entrée assistant-actions).
import type {} from '@deepseek-ai/dsh-client-ui-conversation/client'
// Type-only : introduit l'union de types ToolCallBlock de l'instantané runtime (spike §2.5 preuve E3).
import type { ToolCallBlock } from '@deepseek-ai/dsh-client-runtime/client'
// Type-only : introduit la fusion LocaleNamespaceMap du présent paquet (place 'rq-card').
import type {} from './locales.ts'
import type { ExecutionState, ExecutionStateInput } from './state.ts'

/**
 * Face d'injection de la carte d'exécution.
 */
export interface RqToolviewInjected {
  /**
   * Entrée de la mise en correspondance des quatre états (enveloppe deriveExecutionState, la carte reste un pur renderer, remplaçable en test).
   */
  deriveState: (input: ExecutionStateInput) => ExecutionState
  /**
   * Instantané face santé de ressource/marqueurs de blocage (point de câblage du scrutin 30 s et des marqueurs disjoncteur/autorisation/liaison).
   * Avant le câblage de la moitié hôte, renvoie un objet vide (= health unknown), la carte se dégrade sur la présentation du cycle de vie de l'appel ;
   * après câblage, le retour de cette fonction se déploie dans l'entrée de deriveState, la carte monte automatiquement en présentation complète des quatre états.
   */
  healthSnapshot?: () => Partial<ExecutionStateInput>
}

/** Props complètes de la carte d'exécution (combinaison standard d'entrée clavier, alignée sur l'usage ToolCallViewProps d'ui-tool). */
export type ExecutionCardProps = PropsRuntime<'tool.call.toolview'>
  & InjectFace<RqToolviewInjected>
  & PropsLocale<'rq-card'>

/** Vue de la barre de feedback : état optimiste local du score déjà soumis par message (la confirmation serveur n'est pas renvoyée — endpoint léger
 * sans interface de lecture, l'échec silencieux conserve le marqueur local, sans déranger la session). */
export interface RqFeedbackView {
  /** Une par message : le score actuellement sélectionné. */
  items: ReadonlyMap<string, { score: 'up' | 'down' }>
}

/**
 * Face d'injection de la barre de feedback.
 */
export interface RqFeedbackInjected {
  /** État optimiste partagé de la session (un contrôleur par Session). */
  hooks: { rqfb: HostObservable<RqFeedbackView> }
  /**
   * Soumet un score (fire-and-forget : échec réseau = dégradation silencieuse, pas d'erreur vers la zone de session).
   * @param messageId id du message assistant définitif.
   * @param score 👍/👎。
   * @param note complément optionnel (l'UI actuelle ne le collecte pas, réserve de contrat).
   */
  rate: (messageId: string, score: 'up' | 'down', note?: string) => Promise<void>
}

/** Props complètes de la barre de feedback (combinaison standard d'une entrée list, alignée sur les usages d'ui-message-feedback). */
export type RqFeedbackProps = PropsRuntime<'conversation.chat.assistant-actions'>
  & InjectFace<RqFeedbackInjected>
  & PropsLocale<'rq-card'>

/** Description de la forme ToolCallBlock réellement consommée par le composant (le vrai type dsh est passé par le cadre à l'exécution). */
export type ToolCallBlockView = ToolCallBlock
