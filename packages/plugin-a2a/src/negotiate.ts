/**
 * Moteur de stratégie de négociation par niveaux d'autonomie A0-A3 (plan de collaboration §6.4, comble les absences 3/4 de contract-c3).
 *
 * Fonction pure, sans effet de bord — entrée « niveau de l'appelant × niveau de l'appelé », sortie le mode d'interaction.
 * Matrice alignée case par case sur la table de négociation du plan de collaboration §6.4 :
 *
 *   appelé＼appelant   A0 conseil      A1 exécution          A2 autonome          A3 négociation
 *   A0              Q&R en un tour      refus             refus             refus
 *   A1              Q&R en un tour      exécution, confirmation humaine   exécution+humain dans la boucle       refus
 *   A2              Q&R en un tour      exécution, rapport a posteriori     exécution, rapport a posteriori     traité comme A2
 *   A3              Q&R en un tour      exécution             exécution             négociation de Task bidirectionnelle
 *
 * Frontière d'honnêteté (plan de collaboration §14.6) : le moteur de négociation garantit seulement que le comportement protocolaire est fidèle (offre/contre-offre/refus au-delà des limites/audit),
 * il ne promet pas que deux modèles « se mettent d'accord » — la qualité du consensus métier dépend des prompts et du filet humain dans la boucle ; c'est une frontière de capacité, pas un défaut.
 */

export type Autonomy = 'A0' | 'A1' | 'A2' | 'A3'

export type NegotiationMode =
  | 'single_turn'      // Q&R en un tour (réponse par la plateforme, sémantique v1)
  | 'rejected'         // refus de matrice (un A0 ne peut pas être piloté en exécution, etc.)
  | 'execute_confirm'  // exécution + confirmation humaine dans la boucle (exécution après dossier au centre d'approbations)
  | 'execute_report'   // exécution + rapport a posteriori (distribution UHP directe)
  | 'negotiate'        // négociation de Task bidirectionnelle A3×A3 (offre/contre-offre, refus au-delà des limites)

export function normalizeAutonomy(value: unknown): Autonomy {
  const text = String(value ?? '').trim().toUpperCase()
  return text === 'A1' || text === 'A2' || text === 'A3' ? (text as Autonomy) : 'A0'
}

export function negotiateMode(caller: Autonomy, target: Autonomy): NegotiationMode {
  if (target === 'A0') return caller === 'A0' ? 'single_turn' : 'rejected'
  if (target === 'A1') {
    if (caller === 'A0') return 'single_turn'
    if (caller === 'A3') return 'rejected'
    return 'execute_confirm'
  }
  if (target === 'A2') {
    if (caller === 'A0') return 'single_turn'
    return 'execute_report'
  }
  // target = A3
  if (caller === 'A0') return 'single_turn'
  if (caller === 'A3') return 'negotiate'
  return 'execute_report'
}

/** Plafond de tours de négociation (défaut 3, au-delà → rejected — plan de collaboration §6.4). */
export const NEGOTIATION_MAX_ROUNDS = 3

/** Décision de négociation donnée par le modèle cible (analyse tolérante : premier objet JSON extrait de la sortie du modèle). */
export type NegotiationDecision =
  | { decision: 'accept'; note?: string }
  | { decision: 'counter'; proposal?: unknown; note?: string }

export function parseNegotiationDecision(raw: string): NegotiationDecision {
  const match = raw.match(/\{[\s\S]*\}/)
  if (match) {
    try {
      const parsed = JSON.parse(match[0]) as { decision?: string; proposal?: unknown; note?: string }
      if (parsed.decision === 'accept') return { decision: 'accept', ...(parsed.note ? { note: String(parsed.note) } : {}) }
      if (parsed.decision === 'counter') {
        return { decision: 'counter', ...(parsed.proposal !== undefined ? { proposal: parsed.proposal } : {}), ...(parsed.note ? { note: String(parsed.note) } : {}) }
      }
    } catch { /* retombe sur le repli tolérant */ }
  }
  // Échec d'analyse : traité comme contre-offre (texte original en annexe), convergence naturelle au plafond de tours, la négociation ne reste jamais suspendue
  return { decision: 'counter', note: raw.slice(0, 2000) }
}
