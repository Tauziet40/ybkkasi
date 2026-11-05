/**
 * Hygiène des entrées sensibles (OPT-P2-02, 2026-09-12) : le stockage des approbations ne doit pas transporter de valeurs sensibles.
 * L'approbation admin des connecteurs et le centre d'audit partagent la même liste de noms de clés — la cohérence des deux endroits est garantie par la définition unique.
 */

/** Liste des noms de clés sensibles (élément d'élévation de la vérification d'audit #11) : toute correspondance n'entre pas dans le stockage d'approbation (masquage ou refus d'ouvrir le dossier). */
export const SENSITIVE_KEY_RE = /(password|passwd|secret|token|apikey|api[_-]?key|access[_-]?key|private[_-]?key|credential|client[_-]?secret)/i

/** Scan récursif des chemins de clés sensibles (ne modifie pas les valeurs originales). */
export function scanSensitiveKeys(value: unknown, prefix = ''): string[] {
  const paths: string[] = []
  const walk = (node: unknown, path: string): void => {
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, `${path}[${index}]`))
      return
    }
    if (node && typeof node === 'object') {
      for (const [key, item] of Object.entries(node as Record<string, unknown>)) {
        const childPath = path ? `${path}.${key}` : key
        if (SENSITIVE_KEY_RE.test(key) && item !== null && typeof item !== 'object') paths.push(childPath)
        else walk(item, childPath)
      }
    }
  }
  walk(value, prefix)
  return paths
}

/** Masquage profond : la valeur des clés sensibles est remplacée par *** (noms de clés et structure conservés, pour la contre-vérification avec inputHash). */
export function maskSensitivePayload<T>(value: T): { masked: T; maskedKeys: string[] } {
  const maskedKeys: string[] = []
  const walk = (node: unknown, path: string): unknown => {
    if (Array.isArray(node)) return node.map((item, index) => walk(item, `${path}[${index}]`))
    if (node && typeof node === 'object') {
      const out: Record<string, unknown> = {}
      for (const [key, item] of Object.entries(node as Record<string, unknown>)) {
        out[key] = SENSITIVE_KEY_RE.test(key) && item !== null && typeof item !== 'object'
          ? (maskedKeys.push(path ? `${path}.${key}` : key), '***')
          : walk(item, path ? `${path}.${key}` : key)
      }
      return out
    }
    return node
  }
  return { masked: walk(value, '') as T, maskedKeys }
}
