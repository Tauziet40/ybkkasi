/**
 * Export des collections SQLite → collections JSON (outil de retour arrière ADR-0001).
 *
 * Scénario : après un fonctionnement en PLATFORM_STORAGE=sqlite, pour repasser au backend JSON,
 * exporte les données les plus récentes de collections.db en fichiers de collections JSON (écrasant l'ancienne source de retour arrière homonyme),
 * puis un redémarrage sur le backend par défaut (json) suffit pour un retour arrière sans couture.
 *
 * Usage :
 *   node scripts/storage-export.mjs --data ./data            # exporte toutes les collections dans le même répertoire de données
 *   node scripts/storage-export.mjs --data ./data --out ./data-json
 *   node scripts/storage-export.mjs --data ./data --only iam:users,authn:tokens
 */
import { DatabaseSync } from 'node:sqlite'
import { mkdirSync, writeFileSync, existsSync, renameSync } from 'node:fs'
import { join, resolve } from 'node:path'

const args = process.argv.slice(2)
function argValue(flag, fallback) {
  const index = args.indexOf(flag)
  return index >= 0 ? args[index + 1] : fallback
}

const dataDir = resolve(argValue('--data', './data'))
const outDir = resolve(argValue('--out', dataDir))
const only = (argValue('--only', '') ?? '').split(',').map((item) => item.trim()).filter(Boolean)

const dbFile = join(dataDir, 'collections.db')
if (!existsSync(dbFile)) {
  console.error(`未找到 ${dbFile}——该数据目录未以 sqlite 后端运行过，无需导出。`)
  process.exit(1)
}

const db = new DatabaseSync(dbFile, { readOnly: true })
const names = db.prepare('SELECT name FROM collection_meta ORDER BY name').all().map((row) => row.name)
const selected = only.length > 0 ? names.filter((name) => only.includes(name)) : names

mkdirSync(outDir, { recursive: true })
let total = 0
for (const name of selected) {
  const rows = db.prepare('SELECT id, doc FROM collection_docs WHERE name = ? ORDER BY rowid').all(name)
  const file = join(outDir, `${name.replace(/[:*?"<>|]/g, '~')}.json`)
  // Un JSON homonyme existant (ancienne source de retour arrière) est d'abord déplacé, jamais d'écrasement sans trace
  if (existsSync(file)) renameSync(file, `${file}.pre-export-${Date.now()}`)
  writeFileSync(file, JSON.stringify(rows.map((row) => JSON.parse(row.doc)), null, 2), 'utf8')
  console.log(`  ${name} → ${file}（${rows.length} 条）`)
  total += rows.length
}
console.log(`导出完成：${selected.length} 个集合，共 ${total} 条记录。以默认后端（json）重启即完成回退。`)
