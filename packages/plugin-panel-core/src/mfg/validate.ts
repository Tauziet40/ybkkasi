/**
 * Boîte à outils manufacture — validation entrée/sortie à l'exécution (réécriture équivalente des schémas zod du « jeu d'outils IA manufacture »).
 *
 * Pourquoi écrire à la main plutôt qu'importer zod : le paquet de la porte 01, en forme installée, charge zéro TS, zéro dépendance de build ; dist est
 * un miroir pur JS pré-construit (scripts/build-dist.mjs transpile fichier par fichier, sans résolution de modules) — introduire une nouvelle dépendance
 * d'exécution casserait à la fois la fermeture d'installation et la sémantique du build-id. Ce fichier couvre en sémantique équivalente les trois seules faces utilisées par le projet source :
 *   - numérique : fini, bornes inf/sup ;
 *   - chaîne : non vide après trim, plafond de longueur ;
 *   - objet : strict (tout champ inconnu refusé — l'assertion « refuser les paramètres superflus » du projet source dépend de cette sémantique).
 *
 * Toute erreur passe par MfgError (même forme que le ToolError du projet source : code/message/status).
 */

export class MfgError extends Error {
  code: string
  status: number
  constructor(code: string, message: string, status = 400) {
    super(message)
    this.name = 'MfgError'
    this.code = code
    this.status = status
  }
}

export const fail = (code: string, message: string, status = 400): never => {
  throw new MfgError(code, message, status)
}

export const requireCondition = (ok: boolean, message: string, code = 'INVALID_INPUT'): void => {
  if (!ok) fail(code, message)
}

/** Plafond de valeur de champ : identique au projet source (16k caractères, contre l'inondation du modèle par les textes surchargés). */
export const TEXT_MAX = 16000

/** Validation d'un champ numérique : fini + bornes (la borne inférieure par défaut 0 est donnée par la définition du champ). */
export function checkNumber(value: unknown, label: string, min?: number, max?: number): number {
  const num = typeof value === 'number' ? value : Number(value)
  if (typeof value === 'boolean' || value === null || value === undefined || value === '' || !Number.isFinite(num)) {
    fail('INVALID_INPUT', `${label}必须是有限数字`)
  }
  if (min !== undefined && num < min) fail('INVALID_INPUT', `${label}不能小于 ${min}`)
  if (max !== undefined && num > max) fail('INVALID_INPUT', `${label}不能大于 ${max}`)
  return num
}

/** Validation d'un champ texte : non vide après trim + plafond de longueur. */
export function checkText(value: unknown, label: string, max = TEXT_MAX): string {
  if (typeof value !== 'string') fail('INVALID_INPUT', `${label}不能为空`)
  const text = value.trim()
  if (text === '') fail('INVALID_INPUT', `${label}不能为空`)
  if (text.length > max) fail('INVALID_INPUT', `${label}长度超过 ${max} 字符`)
  return text
}

/** Validation d'entier (domaine des entiers sûrs : pas de débordement dans les calculs inter-champs). */
export function checkInteger(value: unknown, label: string): number {
  const num = checkNumber(value, label)
  if (!Number.isSafeInteger(num)) fail('INVALID_INPUT', `${label}须为安全范围内的整数`)
  return num
}

/**
 * Validation d'objet strict : tout champ inconnu est refusé (base sémantique de l'assertion « champ injecté rejeté » du projet source).
 * Renvoie un objet propre reconstruit selon les champs déclarés — l'appelant n'a pas l'objet original, aucune transmission de champ de contournement.
 */
export function checkStrictObject<T extends Record<string, unknown>>(
  raw: unknown,
  keys: readonly string[],
  validate: (key: string, value: unknown) => unknown,
): T {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('INVALID_INPUT', '输入必须是对象')
  const source = raw as Record<string, unknown>
  const allowed = new Set(keys)
  for (const key of Object.keys(source)) {
    if (!allowed.has(key) && key !== '_protocol') fail('INVALID_INPUT', `输入包含未知字段：${key}`)
  }
  const out: Record<string, unknown> = {}
  for (const key of keys) out[key] = validate(key, source[key])
  return out as T
}

// ---------------------------------------------------------------------------
// Validation du protocole de sortie du modèle (réécriture équivalente du modelOutputSchema du projet source)
// ---------------------------------------------------------------------------

export type ModelSection = { title: string; content: string; evidence: string[] }
export type ModelOutput = { sections: ModelSection[]; missingInformation: string[] }

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value)

/**
 * Valide la structure JSON renvoyée par le modèle. Toute violation lève MfgError('QUALITY_SCHEMA') —
 * comme le projet source : une sortie non conforme est livrée en erreur, jamais rétrogradée en résultat de succès.
 */
export function checkModelOutputSchema(raw: unknown): ModelOutput {
  if (!isPlainObject(raw)) fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
  const sectionsRaw = raw.sections
  const missingRaw = raw.missingInformation
  if (!Array.isArray(sectionsRaw) || sectionsRaw.length < 1 || sectionsRaw.length > 12) {
    fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
  }
  if (!Array.isArray(missingRaw) || missingRaw.length > 30) {
    fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
  }
  const sections: ModelSection[] = sectionsRaw.map((item) => {
    if (!isPlainObject(item)) fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
    const title = item.title
    const content = item.content
    const evidence = item.evidence
    if (typeof title !== 'string' || title.length < 1 || title.length > 100) fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
    if (typeof content !== 'string' || content.length < 1 || content.length > 12000) fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
    if (!Array.isArray(evidence) || evidence.length > 20) fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
    const quotes: string[] = evidence.map((quote) => {
      if (typeof quote !== 'string' || quote.length < 1 || quote.length > 1000) fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
      return quote
    })
    return { title, content, evidence: quotes }
  })
  const missingInformation: string[] = missingRaw.map((item) => {
    if (typeof item !== 'string' || item.length < 1 || item.length > 1000) fail('QUALITY_SCHEMA', '模型输出未通过结构校验，本次结果未交付。', 502)
    return item
  })
  return { sections, missingInformation }
}