/**
 * Recensement de la couverture de sinisation de la couche présentation (R11, REFACTOR-2026-10-13, 2026-10-13).
 *
 * Objectif : quantifier les résidus anglais de la « face visible utilisateur », établir le registre de travail de sinisation (élimination point par point en phase 2,
 * sortie à zéro correspondance — les exemptions de liste blanche doivent être enregistrées avec leur condition de radiation).
 *
 * Surface scannée (périmètre phase 0) :
 *   - .js et .html des répertoires public des plugins sous packages (frontends console / panel-core / rq-card) ;
 *   - cli/dshctl.mjs (face de sortie CLI) ;
 *   - les gabarits de notification/approbation/e-mail sont dispersés dans les sources TS des plugins ; un scan intégral aurait un taux de faux positifs élevé, reporté en phase 2
 *     à un recensement dirigé selon la liste R1 (choix consignés dans docs/internal/重构基线-阶段0-20261013.md).
 *
 * Modèle de jugement (trois filtres, ne garder que « l'anglais vraisemblablement visible par l'utilisateur ») :
 *   1. littéraux de chaîne ('…"…`…`) dont la ligne n'est pas un commentaire ; jugé après retrait des interpolations ${…} de gabarits ;
 *   2. contenant du chinois → conforme ; forme pure d'identifiant (kebab/snake/camel sans espaces, chemins,
 *      URL, noms de fichiers, MIME etc.) → jugé par la liste blanche de mots ;
 *   3. forme de phrase (phrase anglaise avec espaces) ou mot anglais ≥4 lettres hors liste blanche → correspondance.
 *   Les fichiers HTML ne scannent que les nœuds de texte entre balises et les attributs title/alt/placeholder/aria-label.
 *
 * La liste blanche a deux niveaux :
 *   - lexique intégré (TOKEN_WHITELIST de ce fichier) : mots de protocole/marques/unités/abbréviations techniques/
     énumérations d'état (l'ASCII est conservé à la couche protocole, phase 2 ajoute un champ compagnon labelZh) ;
 *   - registre d'exemptions scripts/lint-cjk-coverage.exemptions.json (mécanisme kind::key,
     key = « fichier::littéral » ; chaque entrée doit indiquer sa condition de radiation, retirée une fois éliminée en phase 2).
 *
 * Usage :
 *   node scripts/lint-cjk-coverage.mjs            # mode rapport (exit 0, produit le registre)
 *   node scripts/lint-cjk-coverage.mjs --strict   # mode porte (toute correspondance non exemptée = exit 1)
 */
import { readdir, readFile } from 'node:fs/promises'
import { join, relative } from 'node:path'

/**
 * Lexique blanc intégré : ces mots anglais sont admis sur la face visible utilisateur (protocole/marques/unités/abbréviations techniques/énumérations).
 * Au resserrement de phase 2, les retirer de cette table et les transformer en champs compagnons chinois.
 */
const TOKEN_WHITELIST = new Set([
  // HTTP / protocole
  'HTTP', 'HTTPS', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
  'content', 'type', 'application', 'json', 'text', 'plain', 'Bearer', 'Authorization',
  'token', 'Token', 'refresh', 'session', 'cookie', 'multipart', 'form', 'data',
  'charset', 'utf', 'localhost', 'origin', 'referer', 'scheme', 'query', 'fragment',
  // Formats / abréviations
  'API', 'URL', 'URI', 'JSON', 'CSV', 'HTML', 'CSS', 'DOM', 'SDK', 'CLI', 'UI', 'UX',
  'MIME', 'BASE64', 'HMAC', 'SHA', 'MD5', 'UUID', 'QPS', 'SLA', 'CSV', 'YAML',
  'OpenAPI', 'OAuth', 'OIDC', 'SAML', 'SSO', 'JWT', 'JWKS', 'SSE', 'WebSocket',
  // Marques et noms propres de l'écosystème
  'MCP', 'NAS', 'dsh', 'DSH', 'RQ', 'ACL', 'OK', 'OKTA', 'Keycloak', 'DingTalk',
  'WeChat', 'GitHub', 'GitLab', 'Google', 'Microsoft', 'Apple', 'Linux', 'Windows',
  'macOS', 'Node', 'npm', 'pnpm', 'Ed25519', 'SQLite', 'Cordis', 'cordis',
  'YUANBINGKE', 'Ybk',
  // Noms de domaine (appellations brandées conservées en anglais dans le périmètre produit ; revue en phase 2)
  'Agent', 'Agents', 'Skill', 'Skills', 'Tool', 'Tools', 'Model', 'Models',
  'Connector', 'Connectors', 'Webhook', 'Webhooks', 'Dashboard', 'Marketplace',
  'Client', 'Clients', 'Secret', 'Scope', 'Scopes', 'Issuer', 'Endpoint', 'Endpoints',
  'Owner', 'Admin', 'Reader', 'Writer', ' Upstream', 'Downstream', 'Fallback',
  // Énumérations d'état (ASCII conservé à la couche protocole, l'affichage UI doit être accompagné de chinois — à digérer en phase 2)
  'Active', 'Inactive', 'Pending', 'Running', 'Failed', 'Success', 'Cancelled',
  'Canceled', 'Enabled', 'Disabled', 'Draft', 'Published', 'Offline', 'Online',
  'Degraded', 'Unknown', 'Ready', 'Bound', 'Expired', 'Frozen', 'Approved',
  'Rejected', 'Reviewing', 'Processing', 'Completed', 'Skipped', 'Error',
  // Booléens / vide / unités
  'true', 'false', 'null', 'undefined', 'none', 'None', 'NaN', 'ms', 'qps',
  'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB', 'bytes', 'min', 'hour',
  // Formats d'encodage/clés (couche protocole)
  'base64', 'base64url', 'pkcs8', 'spki', 'pem', 'hex', 'utf8',
  // Mots courants des identifiants techniques frontend (matière des noms de classes/clés)
  'grid', 'flex', 'auto', 'none', 'hidden', 'block', 'inline', 'wrap', 'items',
  'center', 'start', 'dark', 'light', 'primary', 'danger', 'warning', 'info',
  'badge', 'card', 'panel', 'modal', 'toast', 'table', 'page', 'size', 'small',
  // tone / tokens de classes à sémantique UI (couleurs sémantiques CSS et familles de styles, ASCII conservé à la couche protocole)
  'success', 'warning', 'danger', 'info', 'primary', 'default', 'secondary', 'ghost',
  'btn', 'icon', 'tab', 'tabs', 'nav', 'row', 'col', 'wrap', 'gap', 'pill', 'dot',
  'kbd', 'chart', 'terminal', 'ticket', 'globe', 'file', 'files', 'download', 'link',
  'focus', 'hover', 'active', 'disabled', 'checked', 'selected', 'expanded',
  'medium', 'large', 'full', 'half', 'left', 'right', 'middle', 'top', 'bottom',
  'collapse', 'expand', 'search', 'filter', 'sort', 'reset', 'submit', 'cancel',
  'close', 'open', 'copy', 'copied', 'edit', 'delete', 'create', 'update', 'view',
  'detail', 'list', 'item', 'items', 'label', 'value', 'name', 'title', 'desc',
  'status', 'level', 'index', 'total', 'count', 'limit', 'offset', 'cursor',
].map((word) => word.trim()))

const IDENTIFIER_RE = /^[A-Za-z0-9_$./:#&?=,-]+$/

/** Retire les interpolations ${…} des gabarits, renvoie la partie statique */
export function stripInterpolation(literal) {
  return literal.replace(/\$\{[^}]*\}/g, ' ')
}

/** Extrait tous les mots anglais d'une chaîne (≥minLen lettres), camelCase non décomposé (préserve la forme des champs de protocole) */
export function extractWords(text, minLen) {
  return text.match(new RegExp(`[A-Za-z]{${minLen},}`, 'g')) ?? []
}

/** Juge si un littéral de chaîne est un résidu anglais vraisemblable ; renvoie true = correspondance */
export function isSuspectLiteral(raw) {
  const s = stripInterpolation(raw).trim()
  if (!s || /[\u4e00-\u9fff]/.test(s)) return false
  if (!/\s/.test(s)) {
    // Sans espace (mot/identifiant) :
    // chemin / URL / nom de fichier / MIME (contient l'un de / . :) → facette protocole, conforme
    if (/[/./:]/.test(s)) return false
    // clés de protocole snake_case / kebab-case (mots liés) → facette protocole, conforme
    if (/^[a-z0-9]+(?:[-_][a-z0-9]+)+$/i.test(s)) return false
    // autres mots (comme deactivated) : ≥4 lettres hors liste blanche → correspondance (résidu d'affichage)
    const words = extractWords(s, 4)
    return words.length > 0 && words.some((w) => !TOKEN_WHITELIST.has(w))
  }
  // Forme de phrase (phrase anglaise avec espaces) → libellé visible utilisateur à haute confiance : mots ≥3 lettres hors liste blanche = correspondance
  const words = extractWords(s, 3)
  return words.length > 0 && words.some((w) => !TOKEN_WHITELIST.has(w))
}

/** HTML → tableau de textes à inspecter : nœuds de texte entre balises + valeurs des attributs title/alt/placeholder/aria-label */
export function extractHtmlVisibleTexts(html) {
  const texts = []
  const noScripts = html.replace(/<(script|style)[\s\S]*?<\/(script|style)>/g, ' ')
  for (const m of noScripts.matchAll(/(?:^|>)([^<>]*\S[^<>]*)(?:<|$)/g)) {
    const text = m[1].replace(/&[a-z]+;/g, ' ').trim()
    if (text) texts.push(text)
  }
  for (const m of noScripts.matchAll(/\b(?:title|alt|placeholder|aria-label)\s*=\s*["']([^"']*)["']/g)) {
    if (m[1].trim()) texts.push(m[1])
  }
  return texts
}

/** Clés de métadonnées à valeur de matière de code (pas des libellés utilisateur) : les valeurs de chaîne qui suivent ces clés ne sont pas jugées */
const METADATA_KEY_RE = /(?:icon|badge|perm|path|ext|landing|type|key|field|ref|view|tab|mode|size|tone|color|src|slot|align|shape|variant|scope|role|format|category|group|tags?|code|prop|attr|event|signal|channel|source|target|driver|adapter|strategy|slot)\s*:\s*$/

/** Contextes d'appel DOM/matière de code : une chaîne apparaissant juste après ces formes d'appel → non jugée */
const DOM_CALL_RE = /(?:\$|\bicon|\besc|\bcls|\bh|querySelectorAll|querySelector|getElementById|closest|createElement|addEventListener|removeEventListener|classList(?:\.[a-z]+)?|setAttribute|getAttribute|insertAdjacentHTML|dataset\.[a-zA-Z]+)\(\s*$/

/** Fragment HTML → tableau des nœuds de texte entre balises (classes/attributs naturellement retirés) */
export function extractTemplateTextNodes(fragment) {
  const texts = []
  for (const m of fragment.matchAll(/>([^<>]*\S[^<>]*)</g)) {
    const text = m[1].replace(/&[a-z]+;/g, ' ').trim()
    if (text) texts.push(text)
  }
  return texts
}

/** Juge le contenu d'un littéral de gabarit (les sorties d'échafaudage CLI sont souvent du YAML, contenu de protocole, non jugé) */
export function isYamlStructureLine(line) {
  return /^\s*-?\s*[\w."'-]+\s*:(\s|$)/.test(line) || /^\s*- /.test(line)
}

/**
 * Extraction littérale à niveau caractère de tout le texte : consommation séquentielle des caractères — les gabarits sont avalés en entier (les guillemets internes ne s'échappent pas,
 * multi-lignes corrects), l'intérieur des interpolations ${…} est sauté (matière de code), les commentaires de ligne sautés.
 * Renvoie [{ quote, value, index }] (gabarits : quote='`').
 */
export function parseLiterals(text) {
  const out = []
  let i = 0
  const n = text.length
  while (i < n) {
    const ch = text[i]
    if (ch === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i++
      continue
    }
    if (ch === '/' && text[i + 1] === '*') {
      i += 2
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) i++
      i += 2
      continue
    }
    if (ch === '`') {
      let j = i + 1
      let depth = 0
      const start = i
      while (j < n) {
        const c = text[j]
        if (c === '\\') { j += 2; continue }
        if (depth === 0 && c === '`') break
        if (c === '$' && text[j + 1] === '{') { depth++; j += 2; continue }
        if (depth > 0) {
          if (c === '{') depth++
          else if (c === '}') depth--
          j++
          continue
        }
        j++
      }
      // contenu statique après retrait des interpolations
      let value = ''
      let k = i + 1
      let d = 0
      while (k < j) {
        const c = text[k]
        if (c === '\\') { k += 2; continue }
        if (d === 0 && c === '`') break
        if (c === '$' && text[k + 1] === '{') { d++; k += 2; continue }
        if (d > 0) {
          if (c === '{') d++
          else if (c === '}') d--
          k++
          continue
        }
        value += c
        k++
      }
      out.push({ quote: '`', value, index: start })
      i = j + 1
      continue
    }
    if (ch === "'" || ch === '"') {
      let j = i + 1
      let value = ''
      while (j < n) {
        const c = text[j]
        if (c === '\\') { value += text[j + 1] ?? ''; j += 2; continue }
        if (c === ch || c === '\n') break
        value += c
        j++
      }
      out.push({ quote: ch, value, index: i })
      i = j + 1
      continue
    }
    i++
  }
  return out
}

/** index → numéro de ligne */
function makeLineLookup(text) {
  const starts = [0]
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1)
  return (index) => {
    let lo = 0, hi = starts.length - 1
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1
      if (starts[mid] <= index) lo = mid
      else hi = mid - 1
    }
    return lo + 1
  }
}

/** Scanne un fichier JS seul (.mjs CLI inclus), renvoie le tableau de correspondances [{ file, line, literal }] */
export function scanJsFile(file, text) {
  const hits = []
  const lineOf = makeLineLookup(text)
  const lineStart = (index) => {
    let i = index
    while (i > 0 && text[i - 1] !== '\n') i--
    return i
  }
  for (const lit of parseLiterals(text)) {
    const before = text.slice(lineStart(lit.index), lit.index)
    // position de clé d'objet (deux-points juste après le littéral) → matière de code
    const after = text.slice(lit.index + 1 + lit.value.length + 1, lit.index + 1 + lit.value.length + 3)
    if (/^\s*:/.test(after)) continue
    // sémantique clé-valeur de métadonnées (icon: 'x' / badge: 'y' etc.) → matière de code
    if (METADATA_KEY_RE.test(before)) continue
    // contexte d'appel DOM/matière de code → matière de code
    if (DOM_CALL_RE.test(before)) continue
    // côté droit d'une comparaison (e.key === 'Escape', status === 'warn') et des valeurs par défaut (params.get('tab') ?? 'catalog') → jugement d'énumération, matière de code
    if (/[=!]==?\s*$/.test(before) || /\?\?\s*$/.test(before) || /\|\|\s*$/.test(before)) continue
    // matière de valeurs CSS (dégradés/fonctions de couleur) : le style n'est pas du libellé
    if (lit.quote !== '`' && /(linear|radial)-gradient\(|rgba?\(|#[0-9a-fA-F]{3,8}\b/.test(lit.value) && !lit.value.includes(' ')) continue
    // chaînes graphiques SVG (path/rect/circle etc. éléments de dessin) : pas de texte visible utilisateur, chaîne entière sautée
    if (lit.quote !== '`' && /<(svg|path|rect|circle|line|polyline|polygon|g)[\s/>]/.test(lit.value)) continue
    // fragments HTML/SVG incrustés dans des chaînes ordinaires : passage par l'extraction de nœuds de texte (balises fermantes requises ; SVG sans nœuds de texte = zéro correspondance naturelle)
    if (lit.quote !== '`' && lit.value.includes('<') && lit.value.includes('>') && /<\/[a-zA-Z]/.test(lit.value)) {
      for (const node of extractTemplateTextNodes(lit.value)) {
        if (isSuspectLiteral(node)) hits.push({ file, line: lineOf(lit.index), literal: node })
      }
      continue
    }
    if (lit.quote === '`') {
      // littéraux de gabarit : fragments HTML → nœuds de texte ; lignes de structure YAML d'échafaudage sautées ; le reste jugé par ligne.
      // le jugement HTML exige une balise fermante (les <placeholders> du usage CLI n'en ont pas, jugement par ligne)
      if (lit.value.includes('<') && lit.value.includes('>') && /<\/[a-zA-Z]/.test(lit.value)) {
        for (const node of extractTemplateTextNodes(lit.value)) {
          if (isSuspectLiteral(node)) hits.push({ file, line: lineOf(lit.index), literal: node })
        }
        continue
      }
      for (const line of lit.value.split(/\r?\n/)) {
        const trimmed = line.trim()
        if (!trimmed || isYamlStructureLine(trimmed)) continue
        // lignes de syntaxe usage CLI (≥2 --flag ou contenant un pipe de commande |) : contrat de syntaxe d'interface, pas du libellé ; les vraies lignes de libellé contenant du CJK sont déjà passées
        if (isUsageSyntaxLine(trimmed)) continue
        if (isSuspectLiteral(trimmed)) hits.push({ file, line: lineOf(lit.index), literal: trimmed })
      }
      continue
    }
    // tokens de syntaxe flag/option CLI (--user / --orgId= / -n) : contrat de syntaxe d'interface, pas du libellé
    if (isFlagToken(lit.value)) continue
    // littéraux purs d'identifiants du domaine CLI (clés de champs/valeurs d'énumération comme pluginId, createdAt, online) : ASCII conservé à la couche protocole,
    // les en-têtes/énumérations visibles passent par les mappings compagnons HEADER_ZH / zhEnum ; les phrases (avec espaces) ne sont pas exemptées par cette règle
    if (/(^|[\\/])cli[\\/]/.test(file) && /^[a-z][a-zA-Z0-9_]{1,19}$/.test(lit.value)) continue
    // lignes de structure YAML/JSON (gabarits d'échafaudage, fragments de manifeste) : contenu de protocole, pas du libellé (domaine CLI relâché — l'échafaudage est un tableau de chaînes ligne à ligne)
    if (isYamlStructureLine(lit.value) && (/[\[\]{}:|]/.test(lit.value) || /(^|[\\/])cli[\\/]/.test(file))) continue
    // gabarits de chaîne de requête URL (?path= / ?q=&kind=) : contenu de protocole, pas du libellé
    if (/^\?[\w=&%-]*$/.test(lit.value.trim())) continue
    if (isSuspectLiteral(lit.value)) hits.push({ file, line: lineOf(lit.index), literal: lit.value })
  }
  return hits
}

/** Ligne de syntaxe usage CLI : ≥2 tokens --flag, ou contenant un séparateur de commande par pipe (un vrai libellé ne correspond jamais) */
export function isUsageSyntaxLine(line) {
  if (/[一-鿿]/.test(line)) return false
  const flagCount = (line.match(/--[\w-]+=?/g) ?? []).length
  return flagCount >= 2 || /^\|\s/.test(line) || / \| /.test(line)
}

/** Tokens de syntaxe flag/option CLI : formes --flag / --flag= / -f / --flag=value */
export function isFlagToken(token) {
  const t = token.trim()
  return /^--?[a-zA-Z][\w-]*(=.{0,40})?$/.test(t) && t.length <= 44
}

/** Scanne un fichier HTML seul (nœuds de texte et attributs visibles) */
export function scanHtmlFile(file, text) {
  const hits = []
  const lines = text.split(/\r?\n/)
  const lineStarts = [0]
  for (const ch of text) lineStarts.push(lineStarts[lineStarts.length - 1] + ch.length + 1)
  const lineOf = (pos) => lineStarts.findIndex((start, idx) => start <= pos && (idx === lineStarts.length - 1 || lineStarts[idx + 1] > pos)) + 1
  for (const visible of extractHtmlVisibleTexts(text)) {
    if (isSuspectLiteral(visible)) {
      const pos = text.indexOf(visible)
      hits.push({ file, line: pos >= 0 ? lineOf(pos) : 0, literal: visible })
    }
  }
  return hits
}

async function walkTargets(packagesDir) {
  const targets = []
  async function walk(dir) {
    let entries
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      const p = join(dir, e.name)
      if (e.isDirectory()) await walk(p)
      else if (/\.(js|html)$/.test(e.name) && !/\.test\.mjs$/.test(e.name)) targets.push(p)
    }
  }
  for (const pkg of await readdir(packagesDir, { withFileTypes: true })) {
    if (!pkg.isDirectory()) continue
    await walk(join(packagesDir, pkg.name, 'public'))
  }
  return targets
}

export async function loadExemptions(root) {
  const parsed = JSON.parse(await readFile(join(root, 'scripts', 'lint-cjk-coverage.exemptions.json'), 'utf8'))
  return new Map((parsed.exemptions ?? []).map((item) => [`${item.kind}::${item.key}`, item]))
}

/**
 * Entrée principale : scanne tous les fichiers cibles, renvoie { hits, exempted, stats }.
 * hits = correspondances non exemptées ; exempted = correspondances couvertes par une exemption enregistrée (affichage transparent).
 */
export async function runCjkCoverageScan(root, options = {}) {
  const strict = options.strict ?? false
  const targets = await walkTargets(join(root, 'packages'))
  targets.push(join(root, 'cli', 'dshctl.mjs'))
  const exemptions = await loadExemptions(root)

  const hits = []
  const exempted = []
  for (const file of targets) {
    const text = await readFile(file, 'utf8')
    const found = file.endsWith('.html') ? scanHtmlFile(file, text) : scanJsFile(file, text)
    const rel = relative(root, file).replace(/\\/g, '/')
    for (const hit of found) {
      const key = `literal::${rel}::${hit.literal.slice(0, 80)}`
      const entry = { ...hit, file: rel }
      if (exemptions.has(key)) exempted.push(entry)
      else hits.push(entry)
    }
  }

  const byFile = new Map()
  for (const hit of hits) byFile.set(hit.file, (byFile.get(hit.file) ?? 0) + 1)

  const stats = {
    fileCount: targets.length,
    rawHitCount: hits.length + exempted.length,
    hitCount: hits.length,
    exemptCount: exempted.length,
    byFile: [...byFile.entries()].sort((a, b) => b[1] - a[1]),
  }
  return { ok: !strict || hits.length === 0, hits, exempted, stats, exemptions }
}

// -- Entrée CLI --
if (process.argv[1]?.replace(/\\/g, '/').endsWith('scripts/lint-cjk-coverage.mjs')) {
  const strict = process.argv.includes('--strict')
  const root = process.cwd()
  const { ok, hits, exempted, stats, exemptions } = await runCjkCoverageScan(root, { strict })
  console.log('━━ 表现层汉化覆盖清点（R11，REFACTOR-2026-10-13）━━')
  console.log(`  扫描面：${stats.fileCount} 文件（packages/*/public/**.js|html + cli/dshctl.mjs）`)
  console.log(`  命中：${stats.hitCount} 处疑似英文残留（豁免 ${stats.exemptCount} 处）${strict ? '【门禁模式】' : '【报告模式——阶段 2 逐项消灭】'}`)
  for (const [file, count] of stats.byFile) console.log(`    ${String(count).padStart(4)}  ${file}`)
  console.log('  —— 命中明细（前 60 条）——')
  for (const hit of hits.slice(0, 60)) {
    console.log(`    ${hit.file}:${hit.line}  «${hit.literal.slice(0, 90)}»`)
  }
  if (hits.length > 60) console.log(`    …（其余 ${hits.length - 60} 处略，--strict 门禁模式外不逐条展开）`)
  if (exempted.length > 0) {
    console.log(`  —— 豁免命中 ${exempted.length} 处 ——`)
    for (const hit of exempted.slice(0, 10)) console.log(`    ${hit.file}:${hit.line}  «${hit.literal.slice(0, 70)}»`)
  }
  console.log(`  结果：${stats.hitCount} 命中 ${ok ? '✔' : '✘'}`)
  process.exit(ok ? 0 : 1)
}
