/**
 * Lint des manifestes de contrat : valide que les manifest de tous les plugins plateforme (plugin.yaml + manifest/*.yaml) sont analysables.
 * Utilise le même analyseur du sous-ensemble YAML que l'analyseur de contrats du marketplace (platform-core yaml.ts) —
 * les manifestes de la plateforme elle-même et les cinq facettes tierces suivent la même syntaxe (on mange sa propre nourriture pour chiens).
 * Usage : npm run lint:manifests
 */
import { readdir, readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseYaml } from '../packages/platform-core/src/yaml.ts'
import { validateScenegraph } from '../packages/platform-core/src/scenegraph.ts'
import { runContractLint } from './contract-lint.mjs'
import { scanTimerHygiene } from './lint-timers.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const packagesDir = join(root, 'packages')

let total = 0
let failed = 0
for (const pkg of await readdir(packagesDir, { withFileTypes: true })) {
  if (!pkg.isDirectory()) continue
  const manifestDir = join(packagesDir, pkg.name, 'manifest')
  let files = []
  try {
    files = (await readdir(manifestDir)).filter((file) => file.endsWith('.yaml')).map((file) => join('manifest', file))
  } catch {
    continue
  }
  const pluginYaml = join(packagesDir, pkg.name, 'plugin.yaml')
  try {
    await readFile(pluginYaml, 'utf8')
    files = ['plugin.yaml', ...files]
  } catch {
    // paquets sans plugin.yaml sautés
  }
  for (const rel of files) {
    total++
    const file = join(packagesDir, pkg.name, rel)
    try {
      const text = await readFile(file, 'utf8')
      const parsed = parseYaml(text)
      if (parsed === null || typeof parsed !== 'object') throw new Error('解析结果为空')
      console.log(`  ✔ ${pkg.name}/${rel}`)
    } catch (error) {
      failed++
      console.error(`  ✘ ${pkg.name}/${rel}：${error instanceof Error ? error.message : String(error)}`)
    }
  }
}

// -- Graphes de scénarios sectoriels (review-dsh-agent-panel-v2 Phase 2) : chaque packages/*/scenegraphs/*.json passe par validateScenegraph
// avec les mêmes règles que le chargement à l'exécution (scenegraph.ts) ; une erreur volontaire = rouge
let sgTotal = 0
let sgFailed = 0
for (const pkg of await readdir(packagesDir, { withFileTypes: true })) {
  if (!pkg.isDirectory()) continue
  const sgDir = join(packagesDir, pkg.name, 'scenegraphs')
  let files = []
  try {
    files = (await readdir(sgDir)).filter((file) => file.endsWith('.json'))
  } catch {
    continue
  }
  for (const name of files) {
    sgTotal++
    const file = join(sgDir, name)
    try {
      const parsed = JSON.parse(await readFile(file, 'utf8'))
      const errors = validateScenegraph(parsed, name)
      if (errors.length > 0) throw new Error(errors.join('；'))
      console.log(`  ✔ ${pkg.name}/scenegraphs/${name}`)
    } catch (error) {
      sgFailed++
      console.error(`  ✘ ${pkg.name}/scenegraphs/${name}：${error instanceof Error ? error.message : String(error)}`)
    }
  }
}

console.log(`\n清单校验：${total - failed}/${total} 通过；场景图谱：${sgTotal - sgFailed}/${sgTotal} 通过`)

// -- Cohérence bidirectionnelle contrat↔implémentation (OPT-P0-01, 2026-09-12) : surface d'enregistrement du code ↔ surface déclarative du manifeste --
const contract = await runContractLint(root)
const exemptCount = contract.diffs.filter((d) => d.severity === 'exempt').length
console.log(`契约比对：路由 代码${contract.stats.codeRoutes}/清单${contract.stats.manifestRoutes} · 工具 代码${contract.stats.codeTools}/清单${contract.stats.manifestTools} · 差异 ${contract.diffs.filter((d) => d.severity === 'red').length} 红 ${contract.diffs.filter((d) => d.severity === 'warn').length} 警${exemptCount > 0 ? ` · ${exemptCount} 豁免（见 scripts/contract-lint.exemptions.json）` : ''}`)
for (const diff of contract.diffs) {
  const mark = diff.severity === 'red' ? '✘' : '⚠'
  ;(diff.severity === 'red' ? console.error : console.log)(`  ${mark} [${diff.kind}] ${diff.message}`)
}
if (!contract.ok) console.error('契约比对存在红项：实现与清单漂移，拒绝放行')

// -- Hygiène des minuteurs (OPT-P3-02) : chaque setInterval doit être suivi d'un unref proche (une sémantique de keepalive exige une exemption commentée) ou le fichier doit gérer son cycle par clearInterval --
const timerReport = await scanTimerHygiene(packagesDir)
console.log(`定时器卫生：${timerReport.total} 处 setInterval，${timerReport.violations} 处违规`)
for (const message of timerReport.messages) console.error(`  ⚠ [timer_hygiene] ${message}`)

process.exit(failed + sgFailed > 0 || !contract.ok || timerReport.violations > 0 ? 1 : 0)
