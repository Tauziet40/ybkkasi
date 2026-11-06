/**
 * Contrôleur de feedback par Session (sur la posture de couche objet de ui-message-feedback/MessageFeedbackController,
 * mais délibérément plus léger) :
 *   - le retour de données passe par REST same-origin (fetch FEEDBACK_ENDPOINT, credentials same-origin réutilisant
 *     l'état de connexion rq_sid), sans occuper le canal Remote de dsh (le spike §4.3 conseille de partir sur ②).
 *   - état optimiste local : le clic est enregistré immédiatement ; la confirmation serveur n'est pas renvoyée (endpoint léger sans interface de lecture).
 *   - échec silencieux (contrat WP-06 « la dégradation ne dérange pas la session ») : échec réseau/HTTP = trace console seulement,
 *     aucun rendu d'erreur dans la zone de session — le feedback est un plus, jamais une nouvelle source de dérangement.
 *   - contrat HostObservable (getSnapshot/subscribe) compatible avec le kit de liaison useSyncExternalStore
 *     de dsh, la vue est délivrée via hooks.rqfb de la face d'injection slots.
 * @module @dsh-ops/plugin-rq-card/client/controller
 */

import type { FeedbackResult, FeedbackScore } from '../wire.ts'
import { FEEDBACK_ENDPOINT } from '../wire.ts'
import type { RqFeedbackView } from './slots.ts'

/** Vue initiale (à froid : sans aucun marqueur local). */
const INITIAL_VIEW: RqFeedbackView = Object.freeze({
  items: new Map(),
})

/** POST same-origin ; tout échec replié en ok:false, jamais de rejet vers l'appelant. */
async function postFeedback(body: {
  messageId: string
  score: FeedbackScore
  note?: string
}): Promise<FeedbackResult> {
  try {
    const response = await fetch(FEEDBACK_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
    })
    if (!response.ok) {
      return {
        ok: false,
        error: { code: 'http', message: `feedback endpoint HTTP ${response.status}` },
      }
    }
    // l'endpoint léger admet un corps vide (204/chaîne vide) : on interprète ce qu'on lit, ok absent = succès.
    await response.json().catch(() => undefined)
    return { ok: true }
  } catch (error) {
    return {
      ok: false,
      error: {
        code: 'transport',
        message: error instanceof Error ? error.message : 'feedback request failed',
      },
    }
  }
}

/**
 * Couche objet de feedback par Session : une instance cautionne les contrôles 👍/👎 de tous les messages de la Session.
 */
export class RqFeedbackController {
  private view: RqFeedbackView = INITIAL_VIEW
  private readonly listeners = new Set<() => void>()

  /** Renvoie la vue non mutable en cache (contrat HostObservable). */
  getSnapshot = (): RqFeedbackView => this.view

  /** Souscrit au remplacement de vue (contrat HostObservable). */
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => { this.listeners.delete(listener) }
  }

  /**
   * Soumet un score : écrit d'abord l'état optimiste local (sélection = allumé), puis signale en fire-and-forget.
   * Un clic répété au même score = no-op (idempotent, évite les renvois inutiles).
   * @param messageId id du message assistant définitif.
   * @param score 👍/👎。
   * @param note explication optionnelle (l'UI ne la collecte pas encore, réserve de contrat).
   */
  rate(messageId: string, score: FeedbackScore, note?: string): Promise<void> {
    const current = this.view.items.get(messageId)
    if (current?.score === score) return Promise.resolve()
    this.commit(messageId, score)
    // Le signalement est découplé de l'UI : le résultat n'affecte que la trace console, pas de retour arrière de l'état optimiste (sémantique d'échec silencieux).
    return postFeedback({ messageId, score, ...(note === undefined ? {} : { note }) })
      .then((result) => {
        if (!result.ok) {
          // dégradation silencieuse : endpoint non mis en ligne (404)/échec réseau tombent ici, pas d'erreur vers la zone de session.
          console.debug('[rq-card] feedback not recorded:', result.error.message)
        }
      })
  }

  /** Remplace la vue et notifie les abonnés (les exceptions des abonnés sont avalées sur place, sans casser la boucle de notification). */
  private commit(messageId: string, score: FeedbackScore): void {
    const items = new Map(this.view.items)
    items.set(messageId, { score })
    this.view = Object.freeze({ items })
    for (const listener of this.listeners) {
      try {
        listener()
      } catch (error) {
        console.error('[rq-card] feedback subscriber threw:', error)
      }
    }
  }
}
