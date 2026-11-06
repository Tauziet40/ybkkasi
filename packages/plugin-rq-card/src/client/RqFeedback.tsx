/**
 * Barre de feedback 👍/👎 : entrée du slot list `conversation.chat.assistant-actions` (livrable 6 de WP-06).
 *
 * Coexiste avec l'entrée 'feedback' intégrée de dsh (id : 'rq-feedback', order 20 derrière elle) :
 * l'entrée intégrée dépose l'évaluation dans le Remote messageFeedback de dsh ; la présente entrée envoie la même évaluation par **REST
 * same-origin** au plan de données de method `POST /rq/api/usage/feedback` (endpoint léger WP-07, tombant
 * dans usage.record en instantané à prix zéro et attribué selon l'identité liée) — les deux voies coexistent, sans substitution.
 *
 * [Échec silencieux] endpoint non mis en ligne/échec réseau : le contrôleur ne trace qu'en console, ce composant ne rend aucune
 * erreur (la dégradation ne dérange pas la session). Après soumission réussie, brève confirmation « enregistré ».
 * @module @dsh-ops/plugin-rq-card/client/RqFeedback
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { RqFeedbackProps } from './slots.ts'

/** Durée d'affichage de la confirmation « enregistré » (millisecondes). */
const DONE_HINT_MS = 1800

/** Forme d'usage minimale du crochet de la face d'injection (kit standard du framework : hooks.{name} → use{Name}). */
type RqfbHook = (
  selector: (view: { items: ReadonlyMap<string, { score: string } | undefined> }) => { score: string } | undefined,
) => { score: string } | undefined

/**
 * Contrôle 👍/👎 de chaque message assistant définitif.
 * @param props - messageId de l'owner + face d'injection (crochet rqfb/verbe rate) + dictionnaire.
 */
export function RqFeedback(props: RqFeedbackProps) {
  const { messageId, rate, t } = props
  // La face d'injection hooks.rqfb se déploie en useRqfb (convention de liaison du kit standard, alignée sur le useFeedback de la barre intégrée).
  const maybeHook = (props as { useRqfb?: unknown }).useRqfb
  const useRqfb = typeof maybeHook === 'function' ? (maybeHook as RqfbHook) : null
  const text = t as (key: string) => string

  // Souscription à l'état optimiste : crochet de la face d'injection prioritaire ; forme indisponible = la vue dégénère en rendu sans crochet (le bouton reste cliquable,
  // seul l'état sélectionné n'est plus renvoyé — la dégradation prime sur l'erreur).
  const item = useRqfb?.((view) => view.items.get(messageId))

  const [doneHint, setDoneHint] = useState(false)
  const alive = useRef(true)
  useEffect(() => () => { alive.current = false }, [])

  const onRate = useCallback((score: 'up' | 'down') => {
    if (item?.score === score) return // clic répété au même score = no-op (idempotent aussi côté contrôleur)
    void rate(messageId, score).then(() => {
      if (alive.current) {
        setDoneHint(true)
        setTimeout(() => { if (alive.current) setDoneHint(false) }, DONE_HINT_MS)
      }
    })
  }, [item?.score, messageId, rate])

  const likeLabel = text('fb.like')
  const dislikeLabel = text('fb.dislike')

  return (
    <span className="rq-fb" data-rq-feedback="">
      <button
        type="button"
        className="rq-fb-btn"
        aria-label={likeLabel}
        title={likeLabel}
        aria-pressed={item?.score === 'up' || undefined}
        data-active={item?.score === 'up' || undefined}
        onClick={() => { onRate('up') }}
      >
        👍
      </button>
      <button
        type="button"
        className="rq-fb-btn"
        aria-label={dislikeLabel}
        title={dislikeLabel}
        aria-pressed={item?.score === 'down' || undefined}
        data-active={item?.score === 'down' || undefined}
        onClick={() => { onRate('down') }}
      >
        👎
      </button>
      {doneHint && <span className="rq-fb-done" role="status">{text('fb.done')}</span>}
    </span>
  )
}
