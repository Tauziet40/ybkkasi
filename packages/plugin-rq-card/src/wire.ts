/**
 * @dsh-ops/plugin-rq-card — constantes de canal et types de charge (couche wire).
 *
 * [Sécurité navigateur] ce fichier est consommé à la fois par la moitié hôte et la moitié navigateur : seules constantes et types purs,
 * zéro natif Node, zéro dépendance de paquet — inlinable par n'importe quel côté (bundle navigateur compris) sans fuite
 * d'identité d'exécution (aligné sur le critère INLINE_SAFE de dsh tsdown.client.ts).
 *
 * [Choix du retour de données (spike §4.3, une option sur deux)] REST same-origin : le navigateur fetch directement
 * le plan de données de method monté par plugin-dsh-bridge sur le préfixe /rq, réutilisant l'authentification propre de method (cookie
 * rq_sid) et l'audit ; pas de nouveau canal RPC hôte (le jugement loopback de connection.rpc a des
 * incertitudes en scénario reverse-proxy/accès distant, risque R6 du spike).
 */

/** Préfixe externe du plan de données de method (mountPath de plugin-dsh-bridge, entrée unique en processus unique). */
export const CONSOLE_BASE = '/rq'

/** Endpoint léger de feedback 👍/👎 (chemin relatif REST same-origin). L'endpoint lui-même est implémenté par WP-07
 * (POST → usage.record en instantané à prix zéro, attribution par l'identité liée) ; avant sa mise en ligne, l'appel
 * front reçoit 404, le contrôleur traite en « échec silencieux », sans déranger la session. */
export const FEEDBACK_ENDPOINT = `${CONSOLE_BASE}/api/usage/feedback`

/** Score de feedback (contrat WP-07 : score n'a que deux valeurs). */
export type FeedbackScore = 'up' | 'down'

/** Corps de la requête POST /rq/api/usage/feedback (note optionnelle ; sans note = score pur). */
export interface FeedbackPayload {
  messageId: string
  score: FeedbackScore
  note?: string
}

/** Forme de réponse minimale de l'endpoint de feedback (endpoint léger admet un corps vide : corps vide interprété comme succès). */
export interface FeedbackReply {
  ok?: boolean
}

/** Résultat de soumission du feedback : l'échec de transport ne lève pas, replié en ok:false (dégradation silencieuse côté appelant). */
export type FeedbackResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly error: { readonly code: string; readonly message: string } }

/** Noms de slots enregistrés par cette extension (alignés sur le SlotMap dsh rc.7, répertoire spike §3.2). */
export const SLOT_TOOLVIEW = 'tool.call.toolview' as const
export const SLOT_ASSISTANT_ACTIONS = 'conversation.chat.assistant-actions' as const
export const SLOT_OVERLAY = 'shell.overlay' as const

/** Id d'entrée de la barre de feedback dans le slot list assistant-actions : coexiste avec le 'feedback' intégré de dsh (order 10). */
export const FEEDBACK_ENTRY_ID = 'rq-feedback' as const

/** Préfixe d'id d'entrée de la carte d'exécution dans le slot clavier tool.call.toolview (id réel = préfixe + nom d'outil). */
export const TOOLVIEW_ENTRY_PREFIX = 'rq-tool-' as const

/** Id d'entrée du coin de repli dans le slot list shell.overlay (spike §5 item 6). */
export const DEGRADED_BADGE_ID = 'rq-card-degraded' as const
