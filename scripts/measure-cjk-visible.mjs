/**
 * Mesure des libellés CJK visibles (outil de recette de clôture i18n-fr, 2026-11).
 *
 * Périmètre :
 *   - scan caractère par caractère des sources JS (machine à états légère maison : commentaires ligne/bloc, chaînes simples/doubles, gabarits avec ${} imbriqués, littéraux de regex),
 *     ne compte que les segments continus de CJK (U+4E00–U+9FFF) **hors commentaires** — garder les commentaires en chinois est une convention du dépôt, pas une cible d'affichage ;
 *   - sortie table fichier → nombre de segments CJK / nombre de caractères (racine + pages/** + components/**), triée par segments décroissants ;
 *   - `--json` produit le détail lisible par machine (ligne et texte de chaque segment, pour le nettoyage point par point) ; `--only <sous-chaîne glob>` filtre les fichiers.
 *
 * Usage :
 *   node scripts/measure-cjk-visible.mjs                 # table résumée (exit 0)
 *   node scripts/measure-cjk-visible.mjs --json          # détail JSON (stdout)
 *   node scripts/measure-cjk-visible.mjs --file cmdk.js  # détail d'un seul fichier
 */
import { readdir, readFile } from 'node:fs/promises'
import { join, relative, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const JS_ROOT = join(ROOT, 'packages', 'plugin-console', 'public', 'js')
const CJK_RE = /[\u4e00-\u9fff]+/g

const argFile = (() => {
  const i = process.argv.indexOf('--file')
  return i >= 0 ? process.argv[i + 1] : null
})()
const asJson = process.argv.includes('--json')

/** Liste récursivement les .js / .mjs (hors .test.mjs). */
async function listFiles(dir) {
  const out = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...await listFiles(full))
    else if (/\.(js|mjs)$/.test(entry.name) && !entry.name.includes('.test.')) out.push(full)
  }
  return out
}

/**
 * Scanne le source caractère par caractère, renvoie tous les segments CJK continus des « zones de code hors commentaires » [{ line, text, kind, wrapped }].
 * La machine à états couvre : commentaires //, commentaires de bloc, '…', "…", `…` (code imbriqué ${ } et gabarits imbriqués), /regex/.
 * wrapped=true signifie que le segment est déjà la clé d'un rqI18n.t('…') (clé = texte source chinois, convention du dépôt, pas à nettoyer).
 */
export function scanVisibleCjk(source) {
  // Précollecte les spans des littéraux de clés rqI18n.t('…') et tr('…') (clé = texte source chinois, pas à nettoyer).
  // tr( = assistant local des modules à double usage Node/nav (connections.js/errors.js/realtime.js :
  // traduction différée via window.rqI18n, périmètre identique à rqI18n.t).
  const wrappedSpans = []
  {
    const re = /(?:window\.)?rqI18n\.t\(\s*(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")|\btr\(\s*(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")/g
    let m
    while ((m = re.exec(source)) !== null) wrappedSpans.push([m.index, m.index + m[0].length])
  }
  const inWrapped = (start, end) => wrappedSpans.some(([a, b]) => start >= a && end <= b)
  const hits = []
  let i = 0
  let line = 1
  // Éléments de pile : 'tpl' gabarit | 'interp' zone de code d'interpolation
  const stack = []
  let mode = 'code' // code | line | block | single | double
  let lastSig = '' // dernier caractère significatif (hors blanc/hors commentaire), pour le jugement de regex
  let lastWord = '' // dernier mot significatif (jugement des mots-clés return/typeof etc.)

  const pushHit = (runText, kind, startOffset) => {
    if (!runText) return
    hits.push({ line, text: runText, kind, wrapped: inWrapped(startOffset, startOffset + runText.length) })
  }

  while (i < source.length) {
    const c = source[i]
    const next = source[i + 1]
    // Correctif 2026-11 : le retour à la ligne termine un commentaire « // » (avant ce correctif,
    // le mode 'line' ne se fermait jamais et rendait invisible tout le reste du fichier —
    // seuls les fichiers sans commentaire « // » étaient mesurés correctement).
    if (c === '\n') { line++; if (mode === 'line') mode = 'code'; i++; continue }
    if (mode === 'line') { i++; continue }
    if (mode === 'block') {
      if (c === '*' && next === '/') { mode = stack.length ? stack[stack.length - 1].kind === 'tpl' ? 'tpl' : 'code' : 'code'; i += 2 } else i++
      continue
    }
    if (mode === 'single' || mode === 'double') {
      if (c === '\\') { i += 2; continue }
      if ((mode === 'single' && c === "'") || (mode === 'double' && c === '"')) { mode = 'code'; lastSig = c; lastWord = ''; i++; continue }
      if (/[\u4e00-\u9fff]/.test(c)) {
        let j = i
        while (j < source.length && /[\u4e00-\u9fff]/.test(source[j]) && source[j] !== '\\') j++
        pushHit(source.slice(i, j), 'str', i)
        i = j
        continue
      }
      i++
      continue
    }
    if (mode === 'tpl') {
      if (c === '\\') { i += 2; continue }
      if (c === '`') { stack.pop(); mode = stack.length ? (stack[stack.length - 1].kind === 'interp' ? 'code' : 'tpl') : 'code'; lastSig = c; lastWord = ''; i++; continue }
      if (c === '$' && next === '{') { stack.push({ kind: 'interp', braces: 0 }); mode = 'code'; i += 2; continue }
      // Zone de texte de gabarit : CJK directement visible
      if (/[\u4e00-\u9fff]/.test(c)) {
        let j = i
        while (j < source.length && /[\u4e00-\u9fff]/.test(source[j])) j++
        // Note : le retour à la ligne est hors périmètre CJK, rupture de segment naturelle
        pushHit(source.slice(i, j), 'tpl', i)
        const consumed = source.slice(i, j)
        line += (consumed.match(/\n/g) || []).length
        i = j
        continue
      }
      i++
      continue
    }
    // ---- état code
    if (c === '/' && next === '/') { mode = 'line'; i += 2; continue }
    if (c === '/' && next === '*') { mode = 'block'; i += 2; continue }
    if (c === "'") { mode = 'single'; i++; continue }
    if (c === '"') { mode = 'double'; i++; continue }
    if (c === '`') { stack.push({ kind: 'tpl' }); mode = 'tpl'; i++; continue }
    // À l'intérieur d'une interpolation ${…}, « ) » et « ] » précèdent le plus souvent une division
    // (ex. ${Math.round(x * 1000) / 10}) : ne pas y amorcer d'heuristique regex, sinon le balayage
    // jusqu'au « / » suivant (souvent celui d'une balise HTML fermante) avale le « }» de fermeture
    // de l'interpolation et désynchronise toute la machine à états (correctif 2026-11).
    const inInterp = stack.length > 0 && stack[stack.length - 1].kind === 'interp'
    const regexTrigger = inInterp ? /[({,;=!&|?+\-*%~^<>:\[]/.test(lastSig) || lastSig === '' : /[({,;=!&|?+\-*%~^<>:\[)]/.test(lastSig) || lastSig === ''
    if (c === '/' && (regexTrigger || /^(return|typeof|case|in|of|instanceof|new|delete|void|do|else|yield|await)$/.test(lastWord))) {
      // Littéral de regex (heuristique) : sauter jusqu'au / de fin non échappé
      let j = i + 1
      let ok = false
      while (j < source.length) {
        if (source[j] === '\\') { j += 2; continue }
        if (source[j] === '\n') break
        if (source[j] === '/' || source[j] === '`') { ok = source[j] === '/'; break }
        j++
      }
      if (ok) { i = j + 1; continue }
    }
    if (/[A-Za-z0-9_$]/.test(c)) { lastWord += c; lastSig = c; i++; continue }
    if (/\s/.test(c)) {
      if (!/[A-Za-z0-9_$]/.test(source[i - 1] ?? '')) lastWord = ''
      i++; continue
    }
    lastSig = c
    if (!/[A-Za-z0-9_$]/.test(c)) lastWord = ''
    if (stack.length && stack[stack.length - 1].kind === 'interp') {
      const top = stack[stack.length - 1]
      if (c === '{') top.braces++
      else if (c === '}') {
        if (top.braces > 0) top.braces--
        else { stack.pop(); mode = 'tpl' }
      }
    }
    i++
  }
  // Correction des numéros de ligne au niveau fichier : le numéro est déjà calculé au push quand un segment est trouvé
  return hits
}

/**
 * Exclusions (chinois conservé volontairement, listé point par point, voir CHANGELOG/rapport) :
 *   - onboarding.js 8-180 : buildAgentOnboardingText / buildAppOnboardingText — texte intégral du guide d'intégration
 *     remis directement à l'Agent exécutant (gabarit de prompt, destinataire = Agent, pas un utilisateur UI) ;
 *   - access.js 20-95：AGENT_NL_INSTRUCTION / AGENT_CLI_COMMAND / APP_NL_INSTRUCTION /
 *     APP_CLI_COMMAND — gabarits de consignes et chaînes de commandes dshctl copiés à l'Agent (consommés par l'Agent) ;
 *   - access.js 172-203 / 221-249 : texte intégral du <pre> replié des normes d'intégration plateforme (document de protocole
 *     agent-app-onboarding.md affiché tel quel, mélange de syntaxe API ; une traduction casserait la copiabilité) ;
 *   - i18n.js : NATIVE_NAMES noms natifs des langues (`简体中文` / `日本語` — convention des sélecteurs de langue, inchangés dans toutes les langues).
 */
const EXCLUSIONS = [
  { file: 'onboarding.js', ranges: [[8, 180]], label: 'agent-onboarding-prompt' },
  { file: 'access.js', ranges: [[20, 97], [172, 203], [221, 249]], label: 'agent-dshctl-and-spec-doc' },
  { file: 'i18n.js', ranges: [[20, 20], [166, 168]], label: 'native-language-names' },
  { file: 'asset-filters.js', ranges: [[9, 13]], label: 'selftest-pure-module' },
  { file: 'taxonomy.js', ranges: [[7, 14]], label: 'backend-aligned-taxonomy-values' },
  { file: 'errors.js', ranges: [[22, 424], [445, 449], [453, 458]], label: 'deferred-tr-copy-registry' },
]

async function main() {
  const files = (await listFiles(JS_ROOT)).filter((f) => (argFile ? f.includes(argFile) : true))
  const report = []
  for (const file of files.sort()) {
    const rel = relative(ROOT, file)
    const source = await readFile(file, 'utf8')
    const hits = scanVisibleCjk(source)
    for (const h of hits) {
      h.excluded = ''
      for (const ex of EXCLUSIONS) {
        if (!rel.endsWith(ex.file) || rel.replace(/\\/g, '/').split('/').pop() !== ex.file) continue
        for (const [a, b] of ex.ranges) if (h.line >= a && h.line <= b) { h.excluded = ex.label; break }
        if (h.excluded) break
      }
      if (h.wrapped && !h.excluded) h.excluded = '' // wrapped et excluded sont comptabilisés séparément
    }
    const chars = hits.reduce((sum, h) => sum + h.text.length, 0)
    report.push({ file: rel, segments: hits.length, chars, hits })
  }
  if (asJson) { console.log(JSON.stringify(report.filter((r) => r.segments > 0), null, 2)); return }
  console.log('文件'.padEnd(58) + ['CJK段', 't()键', '自愿排除', '未处理'].map((s) => s.padStart(9)).join(''))
  let total = { seg: 0, wrapped: 0, excluded: 0, todo: 0 }
  for (const r of report.slice().sort((a, b) => b.segments - a.segments)) {
    if (r.segments === 0) continue
    const wrapped = r.hits.filter((h) => h.wrapped && !h.excluded).length
    const excluded = r.hits.filter((h) => !h.wrapped && h.excluded).length
    const todo = r.hits.filter((h) => !h.wrapped && !h.excluded).length
    total.seg += r.segments; total.wrapped += wrapped; total.excluded += excluded; total.todo += todo
    console.log(`${r.file.padEnd(58)}${String(r.segments).padStart(9)}${String(wrapped).padStart(9)}${String(excluded).padStart(9)}${String(todo).padStart(9)}`)
  }
  console.log(`\n合计：CJK 段 ${total.seg} = t()键 ${total.wrapped} + 自愿排除 ${total.excluded} + 待清理 ${total.todo}`)
  if (total.todo > 0) process.exitCode = 1
}

if (process.argv[1] && process.argv[1].endsWith('measure-cjk-visible.mjs')) await main()
