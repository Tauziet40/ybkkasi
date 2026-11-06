/**
 * Mise en correspondance des sources vers les quatre états — fonctions pures (table C2 du couloir C du plan d'action §3, livrable 2 de WP-06).
 *
 * [Ligne d'airain zéro dépendance] ce fichier n'importe rien (react / quelque paquet / natif Node) —
 * le selftest du dépôt principal importe directement ce fichier TS pour test unitaire (Node ≥22.18 charge TS nativement),
 * script d'auto-attestation : node packages/plugin-rq-card/src/client/state.test.mjs
 *
 * Correspondance ligne à ligne avec la table C2 :
 *   ┌────────┬────────────────────────────────────────────┬──────────────────────┐
 *   │ quatre états utilisateur │ source d'état (texte original C2)            │ jugement de la présente fonction │
 *   ├────────┼────────────────────────────────────────────┼──────────────────────┤
 *   │ en appel              │ invoke() mcp en cours de lancement           │ invokePhase='calling' │
 *   │ en exécution          │ online/gray et health∈{healthy,degraded}     │ health=healthy|       │
 *   │                       │ (scrutin 30 s)                               │ degraded, et sans résultat  │
 *   │ terminé               │ retour d'appel + usage.recorded en base      │ hasResult et non-erreur   │
 *   │ bloqué en anomalie    │ down / breakerOpen / nas-authz deny /        │ un marqueur de blocage quelconque │
 *   │                       │ quota épuisé                                 │ (voir priorité ci-dessous) │
 *   └────────┴────────────────────────────────────────────┴──────────────────────┘
 *
 * Priorité de jugement (de haut en bas, premier atteint = retour) :
 *   ① bloqué en anomalie (marqueurs côté plateforme, premier atteint selon la priorité établie)
 *      authzDenied > quotaExceeded > pdpUnreachable > breakerOpen > down > bindingInvalid
 *      — le blocage prime globalement sur le cycle de vie de l'appel : les marqueurs décrivent « pas permis/indisponible en ce moment », fail-safe
 *      en vertu du principe fail-safe, le bandeau rouge ne trompe jamais ; l'information d'achèvement des appels historiques fait foi sur le texte
 *      de repli markdown du résultat d'outil (contrat summarizeForToolResult de la moitié hôte) et sur le registre usage.
 *   ② terminé : hasResult et résultat non-erreur → 'done' (présentation du résultat + 👍/👎) ;
 *      résultat en erreur (spike §2.5 preuve E3 : tool/result.isError → anomalie) → 'blocked' +
 *      code de motif de repli 'invoke-error' (les codes de motif C2 sont les six codes côté plateforme, l'erreur de l'outil lui-même complète par ce code).
 *   ③ en appel : invokePhase='calling' (segment de lancement d'invoke, la poignée de main de la passerelle non encore tombée sur le segment d'exécution de ressource)
 *      → 'calling' (même si la face santé est aussi présente à cet instant, le segment de lancement est d'abord présenté : squelette + annulable).
 *   ④ en exécution : health ∈ {healthy, degraded} et sans résultat → 'executing' ;
 *      en degraded, ajouter degraded:true (présente l'astuce « un peu lent », ligne en exécution de C2).
 *   ⑤ le reste → 'idle' (état de base au repos : sans résultat, sans invoke, face santé unknown).
 */

/** Phase de lancement d'invoke (informations observables du côté lancement par la présente extension). */
export type InvokePhase = 'idle' | 'calling'

/** Face santé de ressource (scrutin 30 s ; unknown = pas encore de données de santé). */
export type HealthStatus = 'unknown' | 'healthy' | 'degraded' | 'down'

/** Instantané d'entrée de la mise en correspondance des quatre états (tous les champs sont de « l'observation courante », sans couplage temporel). */
export interface ExecutionStateInput {
  /** Résultat d'outil reçu (tool/result définitif). */
  hasResult: boolean
  /** Si le résultat est une erreur (ToolResultNode.isError). */
  resultIsError: boolean
  /** Face santé de ressource (défaut unknown). */
  healthStatus?: HealthStatus
  /** Disjoncteur de la passerelle mcp ouvert. */
  breakerOpen?: boolean
  /** Refus du jugement en cinq étapes nas-authz (fail-closed). */
  authzDenied?: boolean
  /** Quota du portefeuille épuisé. */
  quotaExceeded?: boolean
  /** Point de décision de politique (PDP) injoignable — blocage protecteur. */
  pdpUnreachable?: boolean
  /** Liaison d'identité dsh-bridge expirée. */
  bindingInvalid?: boolean
  /** Phase de lancement d'invoke. */
  invokePhase: InvokePhase
}

/** Quatre états perceptibles par l'utilisateur + état de base au repos (colonne « quatre états utilisateur » de C2 ; idle est l'état de base sans appel). */
export type ExecutionUiState = 'idle' | 'calling' | 'executing' | 'done' | 'blocked'

/**
 * Codes de motif des blocages — clés du module partagé de libellés d'erreurs C3 (js/errors.js côté console).
 * Les six premiers correspondent un à un à la table C3/C2 ; 'invoke-error' est le code de repli de l'erreur de l'outil lui-même
 * (la preuve E3 du spike juge isError comme anomalie, mais les six codes côté plateforme de C2 ne le contiennent pas, d'où ce code ajouté,
 * présentant le libellé d'erreur générique + le détail du résultat).
 */
export type BlockedReason =
  | 'nas-authz-deny'
  | 'quota-exhausted'
  | 'pdp-unreachable'
  | 'breaker-open'
  | 'down'
  | 'binding-invalid'
  | 'invoke-error'

/** Sortie de la mise en correspondance : état UI + code de motif de blocage + information additionnelle degraded. */
export interface ExecutionState {
  /** État UI. */
  state: ExecutionUiState
  /** Présent seulement si state === 'blocked' : code de motif de blocage (clé du libellé d'erreur/bouton d'action). */
  reason?: BlockedReason
  /** true seulement si state === 'executing' et healthStatus === 'degraded' (astuce « un peu lent »). */
  degraded?: boolean
}

/** Assemble l'état bloqué (forme de sortie resserrée : blocked porte toujours reason). */
function blocked(reason: BlockedReason): ExecutionState {
  return { state: 'blocked', reason }
}

/**
 * Fonction pure de mise en correspondance des quatre états (codification de la table C2).
 * Entrées et sorties sont des données pures : pas de lecture d'horloge, pas de requête, pas de modification d'état externe, mêmes entrées = mêmes sorties.
 */
export function deriveExecutionState(input: ExecutionStateInput): ExecutionState {
  // ① blocage anomalie : marqueurs côté plateforme, premier atteint selon la priorité établie (ordre du cahier des charges :
  //    authzDenied > quotaExceeded > pdpUnreachable > breakerOpen > down > bindingInvalid）。
  if (input.authzDenied === true) return blocked('nas-authz-deny')
  if (input.quotaExceeded === true) return blocked('quota-exhausted')
  if (input.pdpUnreachable === true) return blocked('pdp-unreachable')
  if (input.breakerOpen === true) return blocked('breaker-open')
  if (input.healthStatus === 'down') return blocked('down')
  if (input.bindingInvalid === true) return blocked('binding-invalid')

  // ② terminé / anomalie au niveau résultat : l'appel est revenu, l'inscription usage est garantie par le serveur (le front ne croit que le résultat).
  if (input.hasResult) {
    return input.resultIsError ? blocked('invoke-error') : { state: 'done' }
  }

  // ③ en appel : segment de lancement d'invoke (source d'état de la première ligne de la table C2).
  if (input.invokePhase === 'calling') return { state: 'calling' }

  // ④ en exécution : ressource online/gray et face santé saine/dégradée (scrutin 30 s) ;
  //    degraded ajoute degraded:true → la carte présente « un peu lent ».
  if (input.healthStatus === 'healthy') return { state: 'executing' }
  if (input.healthStatus === 'degraded') return { state: 'executing', degraded: true }

  // ⑤ état de base au repos.
  return { state: 'idle' }
}
