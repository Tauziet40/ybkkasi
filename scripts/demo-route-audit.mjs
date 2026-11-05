/**
 * Audit de la facette en lecture seule du mode démo (lot mode démo 2026-10-17).
 *
 * Énumère statiquement toutes les déclarations de routes `guarded(` du dépôt, calcule la différence entre « routes GET/HEAD → point de permission requis » et la liste blanche
 * de lecture seule démo DEMO_READONLY_PERMISSIONS (plugin-console/src/demo-mode.ts) :
 *   - points de la différence à sémantique de lecture (finissant par `.read` / point console.login) → rouge :
     un visiteur du mode démo prendra un 403 sur la page correspondante ; à passer en revue pour compléter la liste blanche ou changer le point déclaré de la route ;
 *   - points de la différence à sémantique d'écriture (.write/.approve/.invoke/.admin etc.) → comportement attendu (403 en mode démo), pas de rouge.
 * Contre-vérifie en même temps l'hygiène de la liste blanche elle-même : findWritePermissionLeaks doit être vide (aucun point d'écriture mélangé).
 *
 * Usage : node scripts/demo-route-audit.mjs (le selftest lance aussi ce script ; code de sortie non nul = rouge)
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DEMO_READONLY_PERMISSIONS, findWritePermissionLeaks } from '../packages/plugin-console/src/demo-mode.ts'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const packagesDir = join(root, 'packages')

function* walkTs(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) yield* walkTs(path)
    else if (entry.name.endsWith('.ts')) yield path
  }
}

// Triplets de littéraux (method, path, permission) ; tolérant aux retours à la ligne/espaces. Les appels sous forme de variables ne se résolvent pas statiquement,
// comptés dans la liste unmatched pour revue humaine (pas de rouge — l'enregistrement dynamique doit passer par la revue de code).
const callRe = /\bguarded\(\s*['"]([A-Z]+)['"]\s*,\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/

const routes = []
const unmatched = []
let totalCalls = 0
for (const file of walkTs(packagesDir)) {
  const text = readFileSync(file, 'utf8')
  const lines = text.split('\n')
  totalCalls += (text.match(/\bguarded\(/g) ?? []).length
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(callRe)
    if (match) routes.push({ file: relative(root, file), line: i + 1, method: match[1], path: match[2], point: match[3] })
  }
}
const matchedCount = routes.length
// guarded( apparaît aussi dans les déclarations de types/commentaires (interfaces de rest-gate.ts, exemples en commentaires) ; une inégalité après filtrage par ligne est normale ;
// seuls les fichiers « contenant des appels guarded( mais zéro correspondance » donnent lieu à un rappel de revue humaine
const filesWithCalls = new Set()
for (const file of walkTs(packagesDir)) {
  const text = readFileSync(file, 'utf8')
  if (/\bguarded\(\s*['"]/.test(text)) filesWithCalls.add(file)
}
const filesMatched = new Set(routes.map((route) => join(root, route.file)))
for (const file of filesWithCalls) {
  if (!filesMatched.has(file)) unmatched.push(relative(root, file))
}

const whitelist = new Set(DEMO_READONLY_PERMISSIONS)
const isReadSemantic = (point) => point === 'console.read' || point.endsWith('.read') || point.endsWith('.read-v1')

const readOnly = routes.filter((route) => ['GET', 'HEAD'].includes(route.method))
const gaps = readOnly.filter((route) => !whitelist.has(route.point) && (isReadSemantic(route.point) || route.point === 'console.login'))
const writeGated = readOnly.filter((route) => !whitelist.has(route.point) && !isReadSemantic(route.point) && route.point !== 'console.login')
const covered = readOnly.filter((route) => whitelist.has(route.point))
const leaks = findWritePermissionLeaks()

console.log(`路由声明扫描：guarded( 字面量路由 ${matchedCount} 条（GET/HEAD ${readOnly.length} · 其中演示白名单直接覆盖 ${covered.length}）`)
if (unmatched.length > 0) console.log(`人工复核（文件含 guarded 调用但零字面量匹配）：${unmatched.join('、')}`)
console.log(`写语义 GET 路由（演示态 403，预期行为）：${writeGated.length} 条`)

let failed = false
if (leaks.length > 0) {
  failed = true
  console.error(`✘ 演示白名单混入写/审批/调用类权限点：${leaks.join('、')}`)
}
if (gaps.length > 0) {
  failed = true
  for (const gap of gaps) console.error(`✘ 演示态只读缺口：${gap.method} ${gap.path} → ${gap.point}（${gap.file}:${gap.line}）`)
}
if (matchedCount === 0) {
  failed = true
  console.error('✘ 未扫描到任何 guarded( 字面量路由——扫描器失效或路由注册方式变更，须人工核对')
}
if (failed) process.exit(1)
console.log('✔ 演示只读面审计通过：白名单无写点泄漏，GET/HEAD 路由无只读缺口')
