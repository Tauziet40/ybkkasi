/**
 * Porte de couverture trilingue des libellés frontend (QA 2026-10-21 P2-05 : 7 clés manquantes dans a2a.js = 93,5 %, aucune porte à tenir).
 *
 * Périmètre :
 *   - scanne toutes les pages et composants sous packages/plugin-console/public/js (pages/**, components/**),
 *     extrait les clés littérales `rqI18n.t('…')` (même périmètre de correspondance que le runtime : clé = texte source chinois) ;
 *   - pour chaque paquet de langue (en-US / ja-JP / fr-FR ; zh-CN est l'original, non concerné), compte les clés manquantes ;
 *   - **seuil au niveau fichier ≥ 95 %** : tout fichier sous le seuil = rouge (pas de « 99 % global mais page neuve à 60 % ») ;
 *   - vérifie aussi la cohérence des placeholders de gabarits ({n}/{time} etc., les noms d'interpolation ne doivent ni disparaître ni être renommés dans les traductions) —
     un placeholder manquant fait que la branche traduite avale silencieusement la variable, plus difficile à détecter qu'une clé manquante.
 *
 * Usage :
 *   node scripts/lint-i18n-coverage.mjs            # mode porte (sous le seuil = exit 1)
 *   node scripts/lint-i18n-coverage.mjs --report   # rapport seul (exit 0)
 */
import { readdir, readFile } from 'node:fs/promises'
import { join, relative, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const JS_ROOT = join(ROOT, 'packages', 'plugin-console', 'public', 'js')
const LOCALE_ROOT = join(ROOT, 'packages', 'plugin-console', 'public', 'locales')
const LOCALES = ['en-US', 'ja-JP', 'fr-FR']
/** Seuil de couverture au niveau fichier (retour QA : 95 % est la ligne de passage). */
const THRESHOLD = 0.95

const reportOnly = process.argv.includes('--report')

/** Liste récursivement les .js d'un répertoire (sauf *.test.mjs et les modules de pure logique comme realtime). */
async function listJs(dir) {
  const out = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...await listJs(full))
    else if (entry.name.endsWith('.js')) out.push(full)
  }
  return out
}

/** Extrait les clés rqI18n.t('literal') (échappements inclus, gabarits et clés variables exclus). */
function extractKeys(source) {
  const keys = new Set()
  const re = /rqI18n\.t\(\s*'((?:[^'\\]|\\.)*)'/g
  let match
  while ((match = re.exec(source)) !== null) keys.add(match[1].replace(/\\'/g, "'"))
  return keys
}

/** Ensemble des placeholders (forme {name}). */
function placeholders(text) {
  return new Set([...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]))
}

async function loadLocale(locale) {
  const merged = {}
  for (const file of (await readdir(join(LOCALE_ROOT, locale))).filter((f) => f.endsWith('.json')).sort()) {
    Object.assign(merged, JSON.parse(await readFile(join(LOCALE_ROOT, locale, file), 'utf8')))
  }
  return merged
}

const catalogs = Object.fromEntries(await Promise.all(LOCALES.map(async (locale) => [locale, await loadLocale(locale)])))

const targets = [
  ...await listJs(join(JS_ROOT, 'pages')),
  ...await listJs(join(JS_ROOT, 'components')),
].filter((file) => !file.endsWith('.test.mjs'))

let filesChecked = 0
let missingTotal = 0
const failures = []

for (const file of targets) {
  const keys = extractKeys(await readFile(file, 'utf8'))
  if (keys.size === 0) continue
  filesChecked++
  const rel = relative(ROOT, file)
  for (const locale of LOCALES) {
    const catalog = catalogs[locale]
    const missing = [...keys].filter((key) => catalog[key] === undefined).sort()
    const badPlaceholders = [...keys]
      .filter((key) => catalog[key] !== undefined)
      .filter((key) => {
        const want = placeholders(key)
        const got = placeholders(String(catalog[key]))
        return want.size !== got.size || [...want].some((name) => !got.has(name))
      })
      .sort()
    if (missing.length > 0 || badPlaceholders.length > 0) {
      const covered = keys.size - missing.length
      const ratio = covered / keys.size
      const lines = []
      if (missing.length) lines.push(`缺 ${missing.length} 条：${missing.slice(0, 8).join(' / ')}${missing.length > 8 ? ' …' : ''}`)
      if (badPlaceholders.length) lines.push(`占位符不一致 ${badPlaceholders.length} 条：${badPlaceholders.slice(0, 5).join(' / ')}`)
      const line = `${rel} [${locale}] 覆盖 ${(ratio * 100).toFixed(1)}%（${covered}/${keys.size}）· ${lines.join('；')}`
      missingTotal += missing.length + badPlaceholders.length
      if (ratio < THRESHOLD || badPlaceholders.length > 0) failures.push(line)
      else console.log(`  ⚠ ${line}`)
    }
  }
}

console.log(`\n多语文案覆盖（${LOCALES.join(' / ')}）：${filesChecked} 个前端文件，缺失/不一致 ${missingTotal} 处（门槛 ${(THRESHOLD * 100).toFixed(0)}%）`)
for (const line of failures) console.error(`  ✘ ${line}`)
if (failures.length > 0) {
  if (reportOnly) {
    console.log('（--report 模式：仅报告，不阻断）')
    process.exit(0)
  }
  console.error('存在低于门槛的文件：补词典后再放行')
  process.exit(1)
}
console.log('全部通过 ✔')