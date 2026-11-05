/**
 * Policy Decision Point (contrat de gouvernance MCP §11, W3-T5).
 *
 * Point d'arbitrage de stratégie au niveau plateforme : les facettes métier (passerelle MCP / NAS / Connector) concentrent leur logique de décision dans
 * des PolicyModule enregistrés ici, qui produisent uniformément PolicyDecision (allow / reasons / decisionId /
 * obligations) — « même expression et même enregistrement de décision » : tout passage/refus peut fournir une décision structurée et un
 * decisionId, comptabilisés dans les enregistrements d'appel et les événements d'audit (l'audit peut reconstituer les motifs d'arbitrage via la chaîne de décisions).
 *
 * Sémantique d'agrégation (verrouillée par le contrat) :
 *   - deny prioritaire : un seul module deny et l'ensemble passe à allow=false ;
 *   - agrégation des reasons : motifs de tous les modules concaténés dans l'ordre d'enregistrement (les motifs du premier module deny sont la cause principale,
 *     les consommateurs s'y tiennent pour ne pas faire dériver leurs libellés de refus de domaine existants) ;
 *   - agrégation des obligations : obligations structurées émises par chaque module en cas de passage (p. ex. {type:'read-only'}) résumées telles quelles,
 *     pour l'affichage audit ; cette vague n'ajoute pas de sémantique d'exécution.
 *   - decisionId = `pd_<newId>` (newId de platform-core, croissant et triable dans le processus).
 */
import { newId } from './ids.ts'
import type { UnifiedPrincipal } from './principal.ts'

/** Décision de stratégie (types du contrat §11, mot pour mot). */
export interface PolicyDecision {
  allow: boolean
  reasons: string[]
  decisionId: string
  obligations: Array<{ type: string; [k: string]: unknown }>
}

/** Requête d'arbitrage de stratégie (types du contrat §11, mot pour mot). */
export interface PolicyRequest {
  subject: UnifiedPrincipal
  action: string
  resource: { type: string; id: string; orgId?: string; dataClass?: string; [k: string]: unknown }
  tool?: { name: string; risk?: string }
  context: { environment?: string; traceId?: string; [k: string]: unknown }
}

/** Module de stratégie (types du contrat §11, mot pour mot) : id + decide synchrone/asynchrone. */
export interface PolicyModule {
  id: string
  decide(req: PolicyRequest): Promise<PolicyDecision> | PolicyDecision
}

/** Construction pratique d'une décision au niveau module (sortie unifiée interne à chaque module, garantit une forme de decisionId cohérente). */
export function moduleDecision(
  allow: boolean,
  reasons: string[],
  obligations: Array<{ type: string; [k: string]: unknown }> = [],
): PolicyDecision {
  return { allow, reasons: [...reasons], decisionId: newId('pd'), obligations }
}

/**
 * Point de décision de stratégie : register absorbe les modules, decide arbitre module par module dans l'ordre d'enregistrement et agrège.
 * L'exception d'un module n'est pas amplifiée en échec d'arbitrage (fail-safe : le module est compté deny avec le motif de l'exception —
 * cohérent avec le fail-closed existant de la plateforme, jamais de passage silencieux à cause du crash d'un module).
 */
export class PolicyDecisionPoint {
  private modules: PolicyModule[] = []

  register(m: PolicyModule): void {
    this.modules.push(m)
  }

  /** id des modules enregistrés (vue en lecture seule, pour le diagnostic de la surface d'assemblage). */
  moduleIds(): string[] {
    return this.modules.map((m) => m.id)
  }

  async decide(req: PolicyRequest): Promise<PolicyDecision> {
    const allowReasons: string[] = []
    const denyReasons: string[] = []
    const obligations: Array<{ type: string; [k: string]: unknown }> = []
    let allow = true
    for (const module of this.modules) {
      let decision: PolicyDecision
      try {
        decision = await module.decide(req)
      } catch (error) {
        // Un module qui lève est traité comme deny de ce module (fail-closed) : motif précisant module et exception, sans bloquer les autres modules
        const message = error instanceof Error ? error.message : String(error)
        decision = { allow: false, reasons: [`模块 ${module.id} 裁决异常（fail-closed）：${message}`], decisionId: newId('pd'), obligations: [] }
      }
      ;(decision.allow ? allowReasons : denyReasons).push(...decision.reasons)
      if (Array.isArray(decision.obligations)) obligations.push(...decision.obligations)
      if (!decision.allow) allow = false
      // deny prioritaire : après un refus, on continue d'exécuter les autres modules (agrégation complète des reasons, chaîne d'arbitrage entièrement visible dans l'audit),
      // mais aucun module ne change son arbitrage à cause de la conclusion des suivants — l'agrégation ne fait qu'un ET logique.
    }
    // Agrégation des reasons (deny en tête) : en cas de refus global, les motifs deny viennent en premier (les motifs du premier module deny sont la cause principale,
    // le consommateur prend directement reasons[0] comme libellé de refus de domaine, zéro dérive de la sémantique de refus existante) ; les motifs des modules passants suivent, pour mémoire.
    const reasons = allow ? allowReasons : [...denyReasons, ...allowReasons]
    return { allow, reasons, decisionId: newId('pd'), obligations }
  }
}

/**
 * Sortie d'arbitrage existante → expression de décision unifiée (contrat §11 : NAS / Connector ne réécrivent pas leur moteur,
 * les sorties de décision sont enveloppées par cette fonction qui leur donne decisionId + reasons, comptabilisées dans le detail d'audit existant).
 */
export function wrapPolicyDecision(allow: boolean, reasons: string[]): PolicyDecision {
  return { allow, reasons: [...reasons], decisionId: newId('pd'), obligations: [] }
}
