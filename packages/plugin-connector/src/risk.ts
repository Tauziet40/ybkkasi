/**
 * Mise en correspondance heuristique des riskLevel (plan §2.4 correctif P2 ⑭) + couverture par catalogue déclaratif de risques (R6,
 * absorbe le modèle de catalogue déclaratif de paperclip app-definitions) :
 * l'action open-connector n'a pas de champ risk en soi — on privilégie le catalogue déclaratif
 * catalog/risk-overrides.json (gen-connector-catalog.mjs génère la constante RISK_OVERRIDES),
 * à défaut, mise en correspondance heuristique selon requiredScopes/providerPermissions + nom de l'action ;
 * les cas indécidables retombent par défaut sur admin en fail-closed.
 */

import { RISK_OVERRIDES } from './risk-overrides.generated.ts'

export type RiskLevel = 'read' | 'write' | 'admin'

/** Étage provider (aligné sur l'étagement S2 de paperclip) : déclaration et affichage seulement dans cette itération, couplage approbation S2 à venir. */
export type RiskTier = 'S1' | 'S2'

/** Entrée de catalogue déclaratif pour un provider (type d'élément du généré risk-overrides.json). */
export interface RiskOverrideEntry {
  /** Niveau de risque de repli pour les actions non explicitement déclarées dans actions (obligatoire). */
  defaultRisk: RiskLevel
  /** S1 = connexion conventionnelle à bas risque (surtout lecture) ; S2 = connexion haute sensibilité (écriture/plan de gestion, ordres de type fonds/droits/organisation). */
  riskTier: RiskTier
  actions: Record<string, RiskLevel>
}

/** Catalogue déclaratif de risques : service → déclaration de couverture. */
export type RiskOverrides = Record<string, RiskOverrideEntry>

export const RISK_RANK: Record<RiskLevel, number> = { read: 0, write: 1, admin: 2 }

export function rankOf(level: RiskLevel): number {
  return RISK_RANK[level]
}

const READ_SCOPE = /(^|[:.])(read|readonly|profile|userinfo|email|public|view)([:.]|$)/i
const ADMIN_SCOPE = /(admin|delete|destroy|revoke|invite|permission|role|org|webhook.*(write|admin)|token)/i

const READ_NAME = /(^|[._])(list|get|search|fetch|query|top|read|find|browse)[._]?|get[A-Z_]/
const ADMIN_NAME = /(delete|remove|destroy|revoke|suspend|ban|invite|permission|role|owner|transfer|admin)/i
const WRITE_NAME = /(create|update|write|send|post|edit|add|merge|deploy|assign|close|reopen|run|trigger|upload|star|watch|pin)/i

interface RiskInputLike {
  id?: string
  name?: string
  description?: string
  requiredScopes?: Array<unknown>
  providerPermissions?: Array<unknown>
  service?: unknown
}

function scopeStrings(input: RiskInputLike): string[] {
  return [
    ...(Array.isArray(input.requiredScopes) ? input.requiredScopes : []),
    ...(Array.isArray(input.providerPermissions) ? input.providerPermissions : []),
  ].map((item) => String(item))
}

/** Entrée partagée par la synchronisation du catalogue et la chaîne d'autorisation pour la gradation des risques. Un riskLevel explicite est retenu tel quel (compatibilité avant si l'amont ajoute le champ). */
export function heuristicRiskLevel(action: RiskInputLike): RiskLevel {
  if ((action as { riskLevel?: unknown }).riskLevel === 'read' || (action as { riskLevel?: unknown }).riskLevel === 'write' || (action as { riskLevel?: unknown }).riskLevel === 'admin') {
    return (action as { riskLevel: RiskLevel }).riskLevel
  }
  const scopes = scopeStrings(action)
  if (scopes.length > 0) {
    if (scopes.every((scope) => READ_SCOPE.test(scope))) return 'read'
    if (scopes.some((scope) => ADMIN_SCOPE.test(scope))) return 'admin'
    if (scopes.some((scope) => !READ_SCOPE.test(scope))) return 'write'
  }
  const text = `${action.id ?? ''} ${action.name ?? ''}`
  if (ADMIN_NAME.test(text)) return 'admin'
  if (READ_NAME.test(text)) return 'read'
  if (WRITE_NAME.test(text)) return 'write'
  if ((action.description ?? '').length > 0 && WRITE_NAME.test(action.description!)) return 'write'
  return 'admin'
}

function isRiskLevel(value: unknown): value is RiskLevel {
  return value === 'read' || value === 'write' || value === 'admin'
}

/**
 * Entrée unifiée de gradation des risques (catalogue déclaratif R6). Priorité :
 *   riskLevel explicite de l'action > niveau actions du catalogue déclaré > defaultRisk du provider déclaré
 *   > heuristique heuristicRiskLevel (avec dernier recours admin).
 * Prise du paramètre service (l'entrée explicite prime sur action.service) ; après une déclaration atteinte, plus d'heuristique — la déclaration fait foi.
 */
export function resolveRiskLevel(action: RiskInputLike, service?: string): RiskLevel {
  if (isRiskLevel((action as { riskLevel?: unknown }).riskLevel)) {
    return (action as { riskLevel: RiskLevel }).riskLevel
  }
  const svc = String(service ?? action.service ?? '').trim()
  const override = svc ? RISK_OVERRIDES[svc] : undefined
  if (override) {
    const declared = action.id !== undefined ? override.actions[String(action.id)] : undefined
    if (isRiskLevel(declared)) return declared
    return override.defaultRisk
  }
  return heuristicRiskLevel(action)
}

/** Lecture de l'étage de risque du provider (renvoie S1/S2 si le catalogue déclaré est atteint, sinon undefined). */
export function riskTierOf(service: unknown): RiskTier | undefined {
  const svc = String(service ?? '').trim()
  return svc ? RISK_OVERRIDES[svc]?.riskTier : undefined
}
