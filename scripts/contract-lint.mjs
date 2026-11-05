/**
 * Moteur de comparaison bidirectionnelle contrat↔implémentation (OPT-P0-01, 2026-09-12).
 *
 * Objectif : faire passer le manifeste à cinq facettes de « document » à « artefact vérifiable » — la surface d'enregistrement du code (routes guarded /
 * routes http.register / noms d'outils / références de points de permission) comparée bidirectionnellement à la surface déclarative du manifeste (api.yaml endpoints+tools,
 * permissions.yaml points, plugin.yaml permissions) ; toute dérive dans un sens = rouge.
 *
 * Syntaxe normalisée (sous-ensemble analysable des lignes de résumé endpoints) :
 *   fragment := METHODS ' ' PATH [ '?query' retirée ] [ (annotation) | '# commentaire' retirés ]
 *   METHODS  := METHOD ( '/' METHOD )*            — GET/PUT déployés en plusieurs entrées
 *   PATH     := chemin absolu commençant par / ; '|' dans un segment déployé en candidates ; '[/seg]' segment optionnel déployé ;
 *               ':param' généralisé en ':*' avant comparaison
 *   fragment relatif (premier segment commençant par ':', comme 'DELETE /:id') hérite du chemin complet du fragment absolu précédent sur la même ligne.
 *   les entrées commençant par '#' sont de pures annotations, sautées sans rapport.
 *
 * Exemptions : scripts/contract-lint.exemptions.json ({exemptions:[{kind,key,reason}]}),
 * réservées aux rares facettes « structurellement non extractibles en littéraux » (p. ex. le dispatch de préfixes interne du handler unique de portal),
 * chaque exemption doit indiquer sa condition de radiation ; les exemptions restent transparentes dans la sortie du lint.
 *
 * Usage :
 *   - CLI : runContractLint(root) appelé par scripts/lint-manifests.mjs ;
 *   - tests : scripts/contract-lint.test.mjs importe directement ce module, assertions constructives rouge/vert sur des fixtures synthétiques.
 */
import { readdir, readFile } from 'node:fs/promises'
import { join, relative, sep } from 'node:path'
import { parseYaml } from '../packages/platform-core/src/yaml.ts'

const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])

/** Déploiement des candidates '|' dans un segment : /a/:id/disable|enable → [/a/:id/disable, /a/:id/enable] */
export function expandAlternatives(path) {
  const segs = path.split('/').filter((seg) => seg !== '')
  let acc = ['']
  for (const seg of segs) {
    const variants = seg.includes('|') ? seg.split('|') : [seg]
    acc = acc.flatMap((base) => variants.map((variant) => `${base}/${variant}`))
  }
  return acc
}

/** Déploiement du segment optionnel '[/seg]' : /a/:id[/guide] → [/a/:id, /a/:id/guide] (récursif sur plusieurs segments optionnels) */
export function expandOptionalSegments(path) {
  const match = path.match(/^(.*?)\[(\/[^\]]*)\](.*)$/)
  if (!match) return [path]
  const [, head, optional, tail] = match
  return [...expandOptionalSegments(head + tail), ...expandOptionalSegments(head + optional + tail)]
}

/** ':param' généralisé en ':*', élimine les différences de nommage des paramètres des deux côtés */
export function generalizePath(path) {
  return path.replace(/:[^/]+/g, ':*')
}

/**
 * Ligne de résumé endpoints individuelle → liste normalisée de (METHOD, chemin généralisé).
 * Renvoie { routes: [{ method, path }], unparseable: [string], notes: [string] }.
 */
export function parseEndpointLine(line, previousAbsolutePath = undefined) {
  const routes = []
  const unparseable = []
  const notes = []
  let prevAbsolute = previousAbsolutePath
  const trimmedLine = line.trim()
  if (trimmedLine.startsWith('#')) return { routes: [], unparseable: [], notes: [trimmedLine] }
  for (const rawFragment of line.split('·')) {
    let fragment = rawFragment.trim()
    if (fragment === '') continue
    if (fragment.startsWith('#')) {
      notes.push(fragment)
      continue
    }
    // Retire la queue '# commentaire' en ligne, les annotations pleine largeur ((…)) et la chaîne de requête demi-largeur
    fragment = fragment.replace(/\s+#.*$/, '')
    fragment = fragment.replace(/（[^）]*）/g, '').replace(/\([^)]*\)/g, '').replace(/\?.*$/, '').trim()
    // Retire la virgule/point-virgule éventuellement résiduelle en fin de ligne
    fragment = fragment.replace(/[,;。]+$/, '').trim()
    const methodMatch = fragment.match(/^([A-Za-z/]+)\s+(\/.*)$/)
    if (!methodMatch) {
      unparseable.push(rawFragment.trim())
      continue
    }
    const methods = methodMatch[1].split('/').map((item) => item.trim().toUpperCase())
    if (!methods.every((method) => METHODS.has(method)) || methods.length === 0) {
      unparseable.push(rawFragment.trim())
      continue
    }
    let path = methodMatch[2].trim()
    // Fragment relatif (premier segment ':param') : hérite du chemin absolu précédent sur la même ligne
    if (path.startsWith('/:')) {
      if (!prevAbsolute) {
        unparseable.push(rawFragment.trim())
        continue
      }
      path = prevAbsolute + path
    }
    for (const expanded of expandAlternatives(path)) {
      for (const finalPath of expandOptionalSegments(expanded)) {
        const generalized = generalizePath(finalPath)
        for (const method of methods) routes.push({ method, path: generalized })
      }
    }
    if (!path.startsWith('/:')) prevAbsolute = path
  }
  return { routes, unparseable, notes }
}

async function walkTsFiles(dir) {
  const out = []
  let entries
  try {
    entries = await readdir(dir, { withFileTypes: true, recursive: true })
  } catch {
    return out
  }
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith('.ts')) out.push(join(entry.parentPath ?? dir, entry.name))
  }
  return out
}

/**
 * Extrait de l'api.yaml brut les entrées de la liste endpoints (lignes de littéraux de chaîne).
 * Sans passer par parseYaml : l'analyseur du sous-ensemble coupe à tort le ':param' des lignes de résumé en paires clé-valeur (constaté OPT-P0-01),
 * or les lignes de résumé sont la source de faits destinée aux humains, à extraire une à une selon le texte original.
 */
export function extractEndpointLines(apiYamlText) {
  const items = []
  let inEndpoints = false
  for (const line of apiYamlText.split(/\r?\n/)) {
    if (/^endpoints:/.test(line)) {
      inEndpoints = true
      continue
    }
    if (!inEndpoints) continue
    if (/^\s/.test(line)) {
      const match = line.match(/^\s{2}-\s(.*)$/)
      if (match) items.push(match[1].trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1'))
    } else if (line.trim() !== '' && !line.trim().startsWith('#')) {
      break
    }
  }
  return items
}

/** Extrait d'un fichier source ts : routes guarded / routes http.register / noms d'outils / références de points de permission (littéraux de chaîne obligatoires) */
export function extractCodeSurface(text) {
  const lines = text.split(/\r?\n/)
  const routes = []
  const tools = []
  const perms = []
  const routeRe = /guarded\(\s*'([A-Za-z]+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'/g
  const httpRe = /http\.register\(\s*'([A-Za-z]+)'\s*,\s*'([^']+)'/g
  const toolRe = /(?:defineTool\(\{|tools\.register\(\{)([\s\S]{0,400}?)\bname:\s*'([^']+)'/g
  const permRe = /permission:\s*'([^']+)'/g
  for (let i = 0; i < lines.length; i++) {
    for (const match of lines[i].matchAll(routeRe)) {
      routes.push({ method: match[1].toUpperCase(), path: generalizePath(match[2]), permission: match[3], line: i + 1 })
      // Le troisième argument de guarded est la référence du point de permission : compté dans l'ensemble des utilisés, même périmètre que les littéraux permission:
      for (const part of match[3].split(',')) {
        const perm = part.trim()
        if (perm !== '') perms.push(perm)
      }
    }
    // OPTIONS (préflight CORS) et HEAD de http.register sont hors facette de contrat, sautés
    for (const match of lines[i].matchAll(httpRe)) {
      const method = match[1].toUpperCase()
      if (method === 'OPTIONS' || method === 'HEAD') continue
      routes.push({ method, path: generalizePath(match[2]), permission: '', line: i + 1 })
    }
    for (const match of lines[i].matchAll(permRe)) {
      // Les littéraux de permission acceptent plusieurs valeurs séparées par virgules ('a.b,c.d' = l'une suffit) — décomposés un à un pour la comparaison déclarative
      for (const part of match[1].split(',')) {
        const perm = part.trim()
        if (perm !== '') perms.push(perm)
      }
    }
  }
  // Le nom d'outil peut être sur plusieurs lignes (defineTool({ retour ligne name: 'x') — correspondance sur le fichier entier, numéro de ligne pris à la ligne du name
  const nameLineOf = (name) => {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(`name: '${name}'`)) return i + 1
    }
    return 0
  }
  for (const match of text.matchAll(toolRe)) {
    tools.push({ name: match[2], line: nameLineOf(match[2]) })
  }
  return { routes, tools, perms }
}

/** Extrait les chemins publics du littéral d'ensemble PUBLIC_PATHS (method=ANY, chemins généralisés participant à la correspondance ANY) */
export function extractPublicPaths(text) {
  const start = text.indexOf('PUBLIC_PATHS = new Set([')
  if (start < 0) return []
  const end = text.indexOf('])', start)
  if (end < 0) return []
  const block = text.slice(start, end)
  return [...block.matchAll(/'([^']+)'/g)].map((match) => match[1]).filter((path) => path.startsWith('/'))
}

async function readYamlOrNull(file) {
  try {
    return parseYaml(await readFile(file, 'utf8'))
  } catch {
    return null
  }
}

async function loadExemptions(root) {
  try {
    const parsed = JSON.parse(await readFile(join(root, 'scripts', 'contract-lint.exemptions.json'), 'utf8'))
    return new Map((parsed.exemptions ?? []).map((item) => [`${item.kind}::${item.key}`, item]))
  } catch {
    return new Map()
  }
}

/**
 * Entrée de la comparaison intégrale. root est la racine du dépôt (contient packages/).
 * Renvoie { ok, diffs: [{severity: 'red'|'warn'|'exempt', kind, message}], stats }.
 */
export async function runContractLint(root) {
  const packagesDir = join(root, 'packages')
  const exemptions = await loadExemptions(root)
  const diffs = []
  const stats = {
    packages: 0, withManifest: 0, codeRoutes: 0, manifestRoutes: 0,
    codeTools: 0, manifestTools: 0, unparseable: 0, exempted: 0,
  }

  // Port d'émission unifié des rouges : entrée figurant dans la liste d'exemptions → dégradée en exempt (transparence conservée, sans compter rouge)
  const pushRed = (kind, key, message) => {
    const hit = exemptions.get(`${kind}::${key}`)
    if (hit) {
      stats.exempted++
      diffs.push({ severity: 'exempt', kind, message: `[豁免] ${message} —— 理由：${hit.reason ?? '未填写'}` })
      return
    }
    diffs.push({ severity: 'red', kind, message })
  }

  const codeRouteMap = new Map() // 'GET /a/:*' -> [{pkg, ref}]
  const publicPathSet = new Set()
  const manifestRouteMap = new Map() // 'GET /a/:*' -> [apiRel]
  const manifestPathSet = new Set() // chemins généralisés (pour la correspondance ANY)
  const toolDeclsByPkg = new Map() // pkg -> Map(name -> {file})
  const toolManifestByPkg = new Map() // pkg -> Set(name)
  const usedPerms = new Map() // perm -> [{pkg, ref}]
  const declaredPerms = new Map() // perm -> [pkg]
  const pkgsWithoutManifest = []

  const pkgEntries = await readdir(packagesDir, { withFileTypes: true })
  for (const pkgEntry of pkgEntries) {
    if (!pkgEntry.isDirectory()) continue
    const pkg = pkgEntry.name
    stats.packages++
    const pkgDir = join(packagesDir, pkg)
    const srcDir = join(pkgDir, 'src')

    // -- Extraction de la surface code --
    const tsFiles = await walkTsFiles(srcDir)
    const toolDecls = new Map()
    for (const file of tsFiles) {
      const text = await readFile(file, 'utf8')
      const surface = extractCodeSurface(text)
      const relFile = relative(packagesDir, file).split(sep).join('/')
      for (const route of surface.routes) {
        stats.codeRoutes++
        const key = `${route.method} ${route.path}`
        if (!codeRouteMap.has(key)) codeRouteMap.set(key, [])
        codeRouteMap.get(key).push({ pkg, ref: `${relFile}:${route.line}` })
      }
      for (const tool of surface.tools) {
        stats.codeTools++
        if (!toolDecls.has(tool.name)) toolDecls.set(tool.name, { file: `${relFile}:${tool.line}` })
      }
      for (const perm of surface.perms) {
        if (!usedPerms.has(perm)) usedPerms.set(perm, [])
        usedPerms.get(perm).push({ pkg, ref: relFile })
      }
    }
    const publicPaths = tsFiles.length > 0
      ? extractPublicPaths(await readFile(join(srcDir, 'index.ts'), 'utf8').catch(() => ''))
      : []
    for (const path of publicPaths) publicPathSet.add(generalizePath(path))

    // -- Extraction de la surface manifeste --
    const pluginYaml = await readYamlOrNull(join(pkgDir, 'plugin.yaml'))
    const apiYaml = await readYamlOrNull(join(pkgDir, 'manifest', 'api.yaml'))
    const hasManifest = pluginYaml !== null && apiYaml !== null
    if (hasManifest) stats.withManifest++

    // La déclaration de permissions est indépendante de api.yaml : les paquets portant seulement plugin.yaml + permissions.yaml peuvent aussi déclarer des points
    const permissionsYaml = await readYamlOrNull(join(pkgDir, 'manifest', 'permissions.yaml'))
    for (const source of [pluginYaml?.permissions, permissionsYaml?.points]) {
      for (const perm of source ?? []) {
        const key = String(perm)
        if (!declaredPerms.has(key)) declaredPerms.set(key, [])
        if (!declaredPerms.get(key).includes(pkg)) declaredPerms.get(key).push(pkg)
      }
    }

    if (hasManifest) {
      const apiRel = `${pkg}/manifest/api.yaml`

      const endpointLines = extractEndpointLines(await readFile(join(pkgDir, 'manifest', 'api.yaml'), 'utf8'))
      let previousAbsolute
      for (const line of endpointLines) {
        const { routes, unparseable } = parseEndpointLine(String(line), previousAbsolute)
        for (const bad of unparseable) {
          stats.unparseable++
          diffs.push({ severity: 'red', kind: 'endpoint_unparseable', message: `${apiRel}：摘要片段不符合规范语法（OPT-P0-01）：「${bad}」` })
        }
        if (routes.length > 0) previousAbsolute = routes[routes.length - 1].path
        for (const route of routes) {
          stats.manifestRoutes++
          const key = `${route.method} ${route.path}`
          if (!manifestRouteMap.has(key)) manifestRouteMap.set(key, [])
          manifestRouteMap.get(key).push(apiRel)
          manifestPathSet.add(route.path)
        }
      }
      const manifestTools = new Set((apiYaml.tools ?? []).map(String))
      toolManifestByPkg.set(pkg, manifestTools)
      stats.manifestTools += manifestTools.size
    } else if (tsFiles.length > 0) {
      pkgsWithoutManifest.push(pkg)
    }

    toolDeclsByPkg.set(pkg, toolDecls)
  }

  // -- Source complémentaire des déclarations de permissions : PermissionCatalog d'iam (autorité d'enregistrement RBAC à l'exécution, source de faits au niveau code) --
  // Le permissions.yaml du manifeste est la face documentaire ; ce qui est réellement enregistré dans le RBAC est ce catalogue. Un point utilisé touchant l'une des _sources est réputé déclaré.
  const catalogText = await readFile(join(packagesDir, 'plugin-iam', 'src', 'index.ts'), 'utf8').catch(() => '')
  for (const match of catalogText.matchAll(/point:\s*'([^']+)'/g)) {
    const perm = match[1]
    if (!declaredPerms.has(perm)) declaredPerms.set(perm, [])
    if (!declaredPerms.get(perm).includes('plugin-iam#PermissionCatalog')) declaredPerms.get(perm).push('plugin-iam#PermissionCatalog')
  }

  // -- Comparaison bidirectionnelle : routes --
  for (const [key, refs] of codeRouteMap) {
    if (!manifestRouteMap.has(key)) {
      pushRed('route_undeclared', key, `代码注册路由未见于任何清单：${key}（${refs.map((item) => item.ref).join('，')}）`)
    }
  }
  for (const [key, refs] of manifestRouteMap) {
    if (codeRouteMap.has(key)) continue
    const path = key.slice(key.indexOf(' ') + 1)
    if (publicPathSet.has(path)) continue // les chemins publics se comparent en méthode ANY
    pushRed('endpoint_ghost', key, `清单声明路由无代码实现（幽灵 endpoint）：${key}（${refs.join('，')}）`)
  }
  for (const path of publicPathSet) {
    if (manifestPathSet.has(path)) continue
    const covered = [...codeRouteMap.keys()].some((key) => key.slice(key.indexOf(' ') + 1) === path)
    if (!covered) diffs.push({ severity: 'warn', kind: 'public_path_undeclared', message: `公开路径未见于任何清单（先行登记/路由未合入时允许）：${path}` })
  }

  // -- Comparaison bidirectionnelle : outils (paquet par paquet) --
  for (const [pkg, decls] of toolDeclsByPkg) {
    const manifestTools = toolManifestByPkg.get(pkg)
    if (!manifestTools) continue // l'angle de couverture des paquets sans manifeste passe en warn résumé (rouge après le complément P2-04)
    for (const [name, loc] of decls) {
      if (!manifestTools.has(name)) pushRed('tool_undeclared', `${pkg}::${name}`, `代码注册工具未见于清单 api.yaml tools：${pkg}::${name}（${loc.file}）`)
    }
    for (const name of manifestTools) {
      if (!decls.has(name)) pushRed('tool_ghost', `${pkg}::${name}`, `清单声明工具无代码实现（幽灵 tool）：${pkg}::${name}（${pkg}/manifest/api.yaml）`)
    }
  }

  // -- Comparaison bidirectionnelle : points de permission --
  for (const [perm, refs] of usedPerms) {
    if (!declaredPerms.has(perm)) {
      pushRed('perm_undeclared', perm, `代码引用权限点未在清单声明：${perm}（${[...new Set(refs.map((item) => `${item.pkg}/${item.ref}`))].slice(0, 4).join('，')}${refs.length > 4 ? ' 等' : ''}）`)
    }
  }
  for (const [perm, pkgs] of declaredPerms) {
    if (!usedPerms.has(perm)) diffs.push({ severity: 'warn', kind: 'perm_unused', message: `清单声明权限点无代码引用（预留/死点，请确认）：${perm}（${pkgs.join('，')}）` })
  }

  for (const pkg of pkgsWithoutManifest) {
    diffs.push({ severity: 'warn', kind: 'manifest_missing', message: `包有 src 注册面但无完整 manifest（P2-04 补齐前豁免比对）：${pkg}` })
  }

  diffs.sort((a, b) => (a.kind + a.message).localeCompare(b.kind + b.message, 'zh-Hans-CN'))
  const reds = diffs.filter((item) => item.severity === 'red')
  return { ok: reds.length === 0, diffs, stats }
}
