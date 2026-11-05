/**
 * Validation de l'ordre d'assemblage et des frontières de modules (R3, REFACTOR-2026-10-13, 2026-10-13).
 *
 * Contexte : le contrat d'ordre de chargement des plugins n'existait auparavant que dans les commentaires de boot-all.ts et l'ordre du yml cordis ;
 * un inject déclarant un fournisseur absent laissait le plugin INACTIVE en silence, sans aucune porte. Cet outil transforme le contrat implicite
 * en validation machine (s'inspire du modèle scripts/check-module-boundaries.mjs de paperclip).
 *
 * Points de validation :
 *   [A] dépendance avant usage : sur les deux séquences d'assemblage boot-all et cordis.yml, pour chaque plugin, valider que les
 *       fournisseurs de ses clés inject (déclarations static provide dans le code) sont assemblés avant lui ;
 *       une clé inject sans aucun fournisseur = risque d'INACTIVE silencieux, rouge direct.
 *   [B] réconciliation des depends de plugin.yaml : les références dsh-plugin-* doivent mapper à de vrais paquets et précéder
 *       l'usage ; les entrées en langage naturel non-id doivent être enregistrées en exemption ; les dépendances réelles
 *       déduites de inject×provide non enregistrées dans depends donnent un rappel de complément (warn).
 *   [C] cordis.yml ↔ cordis.patch.yml : les séquences de plugins des deux fichiers d'assemblage hôte doivent être identiques
 *       (membres et ordre ; les différences de forme de name file:///paquet+sous-chemin sont hors périmètre).
 *   [D] boot-all ↔ yml : la séquence commune doit être cohérente : après retrait des entrées de différences de forme hôte enregistrées, l'ordre relatif
 *       des plugins communs doit être identique (exemption connue : différence de séquencement des rôles host/client de connect).
 *   [E] réconciliation provides.services : les clés de services déclarées dans plugin.yaml doivent avoir une implémentation provide dans le code
       (déclaration fantôme = rouge) ; les clés provide du code non enregistrées dans le manifeste donnent un rappel de complément (warn).
 *
 * Enregistrement structurel (différences de forme hôte, pas des dettes ; toute modification doit synchroniser les constantes du script et les motifs) :
 *   - propres au yml : plugin-dsh-bridge (pont du webServer dsh, inutile en hôte autonome),
 *               plugin-rq-card (plugin moitié navigateur, uniquement côté session dsh) ;
 *   - propres au boot : aucun.
 *
 * Exemptions : scripts/check-boot-order.exemptions.json ({exemptions:[{kind,key,reason}]},
 * même mécanisme que contract-lint), chaque entrée doit indiquer sa condition de radiation.
 *
 * Usage : node scripts/check-boot-order.mjs (rouge = exit 1) ; npm run lint:boot-order.
 */
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { parseYaml } from '../packages/platform-core/src/yaml.ts'

/** Clés de services fournies par l'hôte dsh (en hôte autonome, fournies en équivalent par platform-core ou le plugin n'est pas assemblé) ;
 *  slots/locale sont le runtime client dsh (slots de session et environnement de langue du plugin moitié navigateur), n'existent qu'en forme yml */
const HOST_PROVIDED_KEYS = new Set(['webServer', 'slots', 'locale'])

/** Plugins propres à la forme yml (enregistrement structurel, voir l'en-tête du fichier) */
const YML_ONLY_PKGS = new Set(['plugin-dsh-bridge', 'plugin-rq-card'])
/** Plugins propres à la forme boot (enregistrement structurel) */
const BOOT_ONLY_PKGS = new Set([])

const PROVIDE_RE = /static\s+(?:readonly\s+)?provide\s*=\s*'([^']+)'/
const INJECT_RE = /export\s+const\s+inject\s*(?::\s*string\s*\[\]\s*)?=\s*\[([^\]]*)\]/

/** Analyse boot-all.ts : mapping alias d'import → noms de paquets @dsh-ops + séquence d'assemblage ctx.plugin(x) (noms de répertoires de paquets) */
export function parseBootAll(text) {
  const aliasToPkg = new Map()
  for (const m of text.matchAll(/import\s+\*\s+as\s+(\w+)\s+from\s+'@dsh-ops\/([\w-]+)'/g)) {
    aliasToPkg.set(m[1], m[2])
  }
  const sequence = []
  for (const m of text.matchAll(/ctx\.plugin\((\w+)/g)) {
    const pkg = aliasToPkg.get(m[1])
    if (pkg) sequence.push(pkg)
  }
  return { sequence, aliasCount: aliasToPkg.size }
}

/**
 * Analyse le yml cordis : extrait la séquence (id, name) des listes insert, name normalisé en nom de répertoire de paquet.
 * Trois formes de name prises en charge : chemin absolu file:// / nom de paquet + sous-chemin (forme installée) / nom de paquet nu (moitié navigateur).
 */
export function parseCordisYml(text) {
  const sequence = []
  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const idMatch = lines[i].match(/^\s*-\s*id:\s*(\S+)/)
    if (!idMatch) continue
    let name = ''
    for (let j = i + 1; j < Math.min(i + 4, lines.length); j++) {
      const nameMatch = lines[j].match(/^\s*name:\s*(.+)$/)
      if (nameMatch) {
        name = nameMatch[1].trim().replace(/^['"]|['"]$/g, '')
        break
      }
    }
    let dir = undefined
    const pkgPath = name.match(/\/packages\/([\w-]+)\//)
    if (pkgPath) dir = pkgPath[1]
    else if (name.startsWith('@dsh-ops/')) dir = name.slice('@dsh-ops/'.length)
    sequence.push({ id: idMatch[1], name, dir })
  }
  return sequence
}

/** Scanne tous les .ts sous src d'un paquet (récursif), renvoie { provides:Set, injects:Set } (clés de services) */
export async function scanPackageFaces(srcDir) {
  const provides = new Set()
  const injects = new Set()
  let files = []
  try {
    files = await readdir(srcDir, { recursive: true })
  } catch {
    return { provides, injects }
  }
  for (const rel of files) {
    if (!rel.endsWith('.ts')) continue
    let text = ''
    try {
      text = await readFile(join(srcDir, rel), 'utf8')
    } catch {
      continue
    }
    for (const m of text.matchAll(new RegExp(PROVIDE_RE.source, 'g'))) provides.add(m[1])
    const inj = text.match(INJECT_RE)
    if (inj) for (const m of inj[1].matchAll(/'([^']+)'/g)) injects.add(m[1])
  }
  return { provides, injects }
}

/** id dsh-plugin-X → nom de répertoire de paquet */
export function yamlIdToDir(id) {
  if (id === 'dsh-plugin-platform-core') return 'platform-core'
  return id.replace(/^dsh-plugin-/, 'plugin-')
}

/** Normalisation de depends : parseYaml ne gère pas les tableaux flow en ligne (renvoie la chaîne brute), extraction unifiée ici en tableau de chaînes */
export function normalizeDepends(value) {
  if (Array.isArray(value)) return value
  if (typeof value !== 'string') return []
  const inner = value.replace(/^\[/, '').replace(/\]$/, '')
  if (!inner.trim()) return []
  return [...inner.matchAll(/'([^']+)'/g)].map((m) => m[1])
}

export async function loadExemptions(root) {
  const parsed = JSON.parse(await readFile(join(root, 'scripts', 'check-boot-order.exemptions.json'), 'utf8'))
  return new Map((parsed.exemptions ?? []).map((item) => [`${item.kind}::${item.key}`, item]))
}

/**
 * Validation principale : renvoie { ok, diffs, stats }. Entrées de diffs : { severity:'red'|'warn', kind, message }.
 */
export async function runBootOrderCheck(root) {
  const diffs = []
  const pushRed = (kind, message) => diffs.push({ severity: 'red', kind, message })
  const pushWarn = (kind, message) => diffs.push({ severity: 'warn', kind, message })

  // -- Collecte : les trois fichiers d'assemblage --
  const bootText = await readFile(join(root, 'src', 'boot-all.ts'), 'utf8')
  const boot = parseBootAll(bootText)
  const ymlEntries = parseCordisYml(await readFile(join(root, 'cordis.yml'), 'utf8'))
  const patchEntries = parseCordisYml(await readFile(join(root, 'cordis.patch.yml'), 'utf8'))
  const ymlSeq = ymlEntries.map((e) => e.dir).filter(Boolean)
  const patchSeq = patchEntries.map((e) => e.dir).filter(Boolean)

  // -- Collecte : répertoires de paquets, plugin.yaml, surfaces provide/inject du code --
  // « Répertoires porteurs de manifestes » : ont un plugin.yaml mais pas de src (comme plugin-platform-core portant le manifeste à cinq facettes
  // de platform-core, forme séparée avant le complément P2-04) — leur manifeste est rattaché au répertoire de code correspondant pour la réconciliation.
  const allDirs = (await readdir(join(root, 'packages'), { withFileTypes: true }))
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
  const faces = new Map()
  const manifests = new Map()
  for (const pkg of allDirs) {
    faces.set(pkg, await scanPackageFaces(join(root, 'packages', pkg, 'src')))
  }
  for (const pkg of allDirs) {
    let text
    try {
      text = await readFile(join(root, 'packages', pkg, 'plugin.yaml'), 'utf8')
    } catch {
      continue
    }
    let owner = pkg
    if ((faces.get(pkg)?.provides.size ?? 0) === 0 && (faces.get(pkg)?.injects.size ?? 0) === 0) {
      const bare = pkg.replace(/^plugin-/, '')
      if (allDirs.includes(bare)) owner = bare
      else pushWarn('manifest_orphan', `目录 ${pkg} 有 plugin.yaml 但无 src 且找不到挂靠代码目录（孤儿清单）`)
    }
    manifests.set(owner, parseYaml(text))
  }

  // clé → ensemble de paquets fournisseurs
  const provideMap = new Map()
  for (const [pkg, face] of faces) {
    for (const key of face.provides) {
      if (!provideMap.has(key)) provideMap.set(key, [])
      provideMap.get(key).push(pkg)
    }
  }

  const exemptions = await loadExemptions(root)
  const isExempt = (kind, key) => exemptions.has(`${kind}::${key}`)

  // -- [A] dépendance avant usage (séquences boot et yml validées séparément) --
  const checkOrder = (sequence, label) => {
    const pos = new Map(sequence.map((pkg, i) => [pkg, i]))
    for (const pkg of sequence) {
      for (const key of faces.get(pkg)?.injects ?? []) {
        if (HOST_PROVIDED_KEYS.has(key)) continue
        const providers = provideMap.get(key) ?? []
        const loaded = providers.filter((d) => pos.has(d))
        if (loaded.length === 0) {
          pushRed('inject_no_provider', `[${label}] ${pkg} 注入的服务键「${key}」无已装配提供者（providers=${providers.join(',') || '无'}）——插件将静默 INACTIVE`)
        } else if (loaded.every((d) => pos.get(d) > pos.get(pkg))) {
          pushRed('inject_order', `[${label}] ${pkg} 注入「${key}」但提供者（${loaded.join(',')}）均晚于其装配——依赖必须先于使用`)
        }
      }
    }
  }
  checkOrder(boot.sequence, 'boot-all')
  checkOrder(ymlSeq, 'cordis.yml')

  // -- [B] réconciliation des depends de plugin.yaml (séquence boot-all comme ordre de référence) --
  const bootPos = new Map(boot.sequence.map((pkg, i) => [pkg, i]))
  for (const [pkg, manifest] of manifests) {
    for (const dep of normalizeDepends(manifest.depends)) {
      if (!dep.startsWith('dsh-plugin-')) {
        if (!isExempt('depends_free_text', dep)) {
          pushRed('depends_free_text', `${pkg} depends 含非插件 id 条目「${dep}」且未登记豁免`)
        }
        continue
      }
      const depDir = yamlIdToDir(dep)
      if (!allDirs.includes(depDir)) {
        pushRed('depends_unknown', `${pkg} depends 引用不存在的插件「${dep}」（映射目录 ${depDir}）`)
        continue
      }
      if (bootPos.has(pkg) && bootPos.has(depDir) && bootPos.get(depDir) > bootPos.get(pkg)) {
        pushRed('depends_order', `${pkg} depends「${dep}」晚于其装配（boot-all 序列）`)
      }
    }
    // dépendances réelles déduites de inject×provide non enregistrées → rappel de complément
    const declared = new Set(normalizeDepends(manifest.depends).filter((d) => d.startsWith('dsh-plugin-')).map(yamlIdToDir))
    for (const key of faces.get(pkg)?.injects ?? []) {
      for (const provider of provideMap.get(key) ?? []) {
        if (provider !== pkg && !declared.has(provider) && manifests.has(provider) && !isExempt('depends_undeclared', `${pkg}→${provider}`)) {
          pushWarn('depends_undeclared', `${pkg} 注入「${key}」实际依赖 ${provider}，但 plugin.yaml depends 未登记（建议补录）`)
        }
      }
    }
  }

  // -- [C] cohérence des séquences cordis.yml ↔ cordis.patch.yml --
  const ymlIds = ymlEntries.map((e) => e.id)
  const patchIds = patchEntries.map((e) => e.id)
  if (ymlIds.join('|') !== patchIds.join('|')) {
    pushRed('yml_pair_divergence', `cordis.yml 与 cordis.patch.yml 插件序列不一致：\n    cordis.yml       = ${ymlIds.join(' → ')}\n    cordis.patch.yml = ${patchIds.join(' → ')}`)
  }

  // -- [D] cohérence de la séquence commune boot-all ↔ yml --
  const ymlSet = new Set(ymlSeq)
  const bootSet = new Set(boot.sequence)
  for (const pkg of boot.sequence) {
    if (!ymlSet.has(pkg) && !BOOT_ONLY_PKGS.has(pkg)) {
      pushRed('boot_only_unregistered', `boot-all 装配了 ${pkg} 但 cordis yml 未装配，且未在 BOOT_ONLY_PKGS 登记`)
    }
  }
  for (const pkg of ymlSeq) {
    if (!bootSet.has(pkg) && !YML_ONLY_PKGS.has(pkg)) {
      pushRed('yml_only_unregistered', `cordis yml 装配了 ${pkg} 但 boot-all 未装配，且未在 YML_ONLY_PKGS 登记`)
    }
  }
  const alignFilter = (seq, otherSet) => seq.filter((p) => otherSet.has(p) && !isExempt('boot_yml_order', p))
  const bootAligned = alignFilter(boot.sequence, ymlSet)
  const ymlAligned = alignFilter(ymlSeq, bootSet)
  for (let i = 0; i < Math.max(bootAligned.length, ymlAligned.length); i++) {
    if (bootAligned[i] !== ymlAligned[i]) {
      pushRed('boot_yml_divergence', `boot-all 与 cordis.yml 公共序列在第 ${i + 1} 位分歧：${bootAligned[i] ?? '（结束）'} ↔ ${ymlAligned[i] ?? '（结束）'}（豁免插件已过滤；序列差异或位置漂移）`)
      break
    }
  }

  // -- [E] réconciliation provides.services --
  for (const [pkg, manifest] of manifests) {
    const codeProvides = faces.get(pkg)?.provides ?? new Set()
    for (const key of manifest.provides?.services ?? []) {
      if (!codeProvides.has(key)) {
        pushRed('provides_ghost', `${pkg} plugin.yaml 声明服务「${key}」无代码 provide 实现（幽灵声明）`)
      }
    }
    for (const key of codeProvides) {
      if (!(manifest.provides?.services ?? []).includes(key)) {
        pushWarn('provides_undeclared', `${pkg} 代码提供服务「${key}」未登记进 plugin.yaml provides.services（建议补录）`)
      }
    }
  }

  const stats = {
    bootCount: boot.sequence.length,
    ymlCount: ymlSeq.length,
    patchCount: patchSeq.length,
    pkgCount: allDirs.length,
    serviceKeys: provideMap.size,
  }
  const reds = diffs.filter((item) => item.severity === 'red')
  return { ok: reds.length === 0, diffs, stats, exemptions }
}

// -- Entrée CLI --
if (process.argv[1]?.replace(/\\/g, '/').endsWith('scripts/check-boot-order.mjs')) {
  const root = process.cwd()
  const { ok, diffs, stats, exemptions } = await runBootOrderCheck(root)
  console.log('━━ 装配顺序与模块边界校验（R3，REFACTOR-2026-10-13）━━')
  console.log(`  装配序列：boot-all ${stats.bootCount} 插件 / cordis.yml ${stats.ymlCount} / cordis.patch.yml ${stats.patchCount}；包 ${stats.pkgCount} 个，服务键 ${stats.serviceKeys} 个`)
  for (const item of diffs) {
    const tag = item.severity === 'red' ? '❌' : '⚠ '
    console.log(`  ${tag} [${item.kind}] ${item.message}`)
  }
  if (exemptions.size > 0) {
    console.log(`  🔖 豁免登记 ${exemptions.size} 条：`)
    for (const [key, item] of exemptions) console.log(`     - ${key} —— ${item.reason}`)
  }
  const reds = diffs.filter((item) => item.severity === 'red').length
  const warns = diffs.length - reds
  console.log(`  结果：${reds} 错误 / ${warns} 提示 ${reds === 0 ? '✔' : '✘'}`)
  process.exit(ok ? 0 : 1)
}
