/**
 * Analyseur du sous-ensemble YAML minimal (sans dépendance externe).
 * Couvre la syntaxe requise par les cinq facettes de contrat des plugins tiers (plugin.yaml / manifest/*.yaml) :
 *   mappings/séquences indentés (- items, y compris items de mapping en ligne et blocs « - seul sur sa ligne ») / scalaires (chaînes, nombres,
 *   booléens, null, collections fluides vides [] {}) / # commentaires pleine ligne.
 * Pas d'ancres, pas de multi-documents, pas de collections fluides non vides — la facette de contrat reste volontairement minimale.
 */

export function parseYaml(text: string): unknown {
  const lines = text.split(/\r?\n/)
    .map((line) => line.replace(/\t/g, '  '))
    .filter((line) => line.trim() !== '' && !line.trim().startsWith('#'))
  let pos = 0

  const indentOf = (line: string): number => line.length - line.trimStart().length

  function parseBlock(indent: number): unknown {
    const first = lines[pos]
    if (first === undefined) return null
    if (first.trimStart().startsWith('- ')) return parseSeq(indent)
    return parseMap(indent)
  }

  function parseMap(indent: number): Record<string, unknown> {
    const result: Record<string, unknown> = {}
    while (pos < lines.length) {
      const line = lines[pos]!
      const ind = indentOf(line)
      if (ind < indent) break
      if (ind > indent) throw new Error(`YAML 缩进异常：「${line.trim()}」`)
      const content = line.trim()
      if (content.startsWith('- ')) break
      const match = content.match(/^("[^"]+"|'[^']+'|[^:]+):\s*(.*)$/)
      if (!match) throw new Error(`YAML 映射行解析失败：「${content}」`)
      const key = String(parseScalar(match[1]!.trim()))
      const rest = (match[2] ?? '').trim()
      pos++
      if (rest === '|' || rest === '>' || rest === '|-' || rest === '>-' || rest === '|+' || rest === '>+') {
        // Scalaire en bloc : les lignes suivantes plus indentées en sont le contenu (| littéral / > plié ; - retire la fin de ligne)
        const blockIndent = pos < lines.length ? indentOf(lines[pos]!) : -1
        const collected: string[] = []
        if (blockIndent > ind) {
          while (pos < lines.length && indentOf(lines[pos]!) >= blockIndent) {
            collected.push(lines[pos]!.trimStart())
            pos++
          }
        }
        const joiner = rest.startsWith('>') ? ' ' : '\n'
        let text = collected.join(joiner)
        if (!rest.endsWith('-') && text !== '') text += '\n'
        result[key] = text
      } else if (rest !== '' && !rest.startsWith('#')) {
        result[key] = parseScalar(rest)
      } else if (pos < lines.length && indentOf(lines[pos]!) > ind) {
        // Les lignes imbriquées sous la clé sont une collection fluide vide (p. ex. permissions:\n  []) — consommée comme collection vide
        if (lines[pos]!.trim() === '[]' || lines[pos]!.trim() === '{}') {
          result[key] = lines[pos]!.trim() === '[]' ? [] : {}
          pos++
        } else {
          result[key] = parseBlock(indentOf(lines[pos]!))
        }
      } else if (pos < lines.length && indentOf(lines[pos]!) === ind && (lines[pos]!.trimStart().startsWith('- ') || lines[pos]!.trim() === '-')) {
        result[key] = parseSeq(ind)
      } else {
        result[key] = null
      }
    }
    return result
  }

  function parseSeq(indent: number): unknown[] {
    const result: unknown[] = []
    while (pos < lines.length) {
      const line = lines[pos]!
      const ind = indentOf(line)
      if (ind < indent) break
      if (ind > indent) throw new Error(`YAML 缩进异常：「${line.trim()}」`)
      const content = line.trim()
      if (content !== '-' && !content.startsWith('- ')) break
      const rest = content === '-' ? '' : content.slice(2).trim()
      pos++
      if (rest === '') {
        result.push(pos < lines.length && indentOf(lines[pos]!) > ind ? parseBlock(indentOf(lines[pos]!)) : null)
      } else if (/^[^:]+:(\s|$)/.test(rest) && !rest.startsWith('"') && !rest.startsWith("'")) {
        // Détection des items de mapping en ligne (E-05) : après les deux-points, un espace ou une fin de ligne est requis pour valider une clé de mapping (convention YAML) —
        // les chaînes à deux-points sans espace comme « 12:34:56 » (heures/proportions) restent scalaires, au lieu d'être prises à tort pour un mapping puis de lever « [object Object] ».
        // Injecte une ligne virtuelle à indentation plus profonde puis analyse comme mapping
        const virtualIndent = ind + 2
        lines.splice(pos, 0, ' '.repeat(virtualIndent) + rest)
        result.push(parseMap(virtualIndent))
      } else {
        result.push(parseScalar(rest))
      }
    }
    return result
  }

  function parseScalar(raw: string): unknown {
    const value = raw.split(' #')[0]!.trim()
    if (value === '[]') return []
    if (value === '{}') return {}
    if (value.startsWith('"') && value.endsWith('"')) return value.slice(1, -1)
    if (value.startsWith("'") && value.endsWith("'")) return value.slice(1, -1)
    if (value === 'true' || value === 'false') return value === 'true'
    if (value === 'null' || value === '~') return null
    if (/^-?\d+$/.test(value)) return Number.parseInt(value, 10)
    if (/^-?\d+\.\d+$/.test(value)) return Number.parseFloat(value)
    return value
  }

  if (lines.length === 0) return null
  return parseBlock(indentOf(lines[0]!))
}
