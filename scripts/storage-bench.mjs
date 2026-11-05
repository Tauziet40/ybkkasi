/**
 * Benchmark des backends de stockage : collections JSON vs collections SQLite (accompagnement de la recette ADR-0001).
 *
 * Usage :
 *   node scripts/storage-bench.mjs                     # 10k écritures par backend
 *   node scripts/storage-bench.mjs --writes 50000      # volume d'écritures augmenté
 *   node scripts/storage-bench.mjs --backend sqlite    # un seul backend
 *
 * Notes de périmètre (benchmark honnête) :
 *   - latence d'écriture unitaire du backend JSON = écriture Map en mémoire + marque anti-rebond (l'écriture disque est asynchrone en arrière-plan, non comptée dans la latence unitaire) ;
 *   - latence d'écriture unitaire du backend SQLite = validation complète de transaction (WAL + synchronous=FULL, fsync inclus) —
 *     c'est le prix de « l'écriture = persistance », et le bénéfice du « 200 renvoyé = écrit sur disque ».
 *   - Ligne de recette (ADR-0001 §8) : P99 des 10k écritures série SQLite < 50 ms ; l'empreinte mémoire ne croît pas linéairement avec le volume d'écritures.
 *     Le périmètre est « série » et non concurrent : node:sqlite est une API synchrone, un seul écrivain par processus ; la boucle d'écriture de ce benchmark
 *     émet en série ; « 10k écritures concurrentes » ne constitue pas un périmètre réellement concurrent dans cette forme de backend (changement formel de périmètre
 *     voir ADR-0001 §5/§8, lot 2026-10-16 ; pas de test de charge multi-processus — un seul processus, un seul écrivain, est le plafond de sa forme de déploiement).
 */
import { Context } from '@deepseek-ai/cordis'
import { StorageService } from '../packages/platform-core/src/storage.ts'
import { rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const args = process.argv.slice(2)
function argValue(flag, fallback) {
  const index = args.indexOf(flag)
  return index >= 0 ? args[index + 1] : fallback
}
const WRITES = Number(argValue('--writes', '10000'))
const ONLY = argValue('--backend', 'both')

function percentile(sorted, p) {
  if (sorted.length === 0) return 0
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)
  return sorted[Math.max(0, index)]
}
const rssMB = () => Math.round(process.memoryUsage().rss / 1024 / 1024)

async function benchBackend(kind) {
  const dataDir = join(tmpdir(), `ybkk-storage-bench-${kind}-${process.pid}-${Date.now()}`)
  const ctx = new Context()
  const svc = new StorageService(ctx, { dataDir, backend: kind })
  const col = svc.collection('bench:calls')

  const writeLatencies = []
  const payload = { service: 'svc-demo', tool: 'search', status: 'ok', caller: 'agent:42', dept: 'dept:7', meta: { tokens: 812, latencyMs: 233, day: '2026-10-16' } }
  const t0 = performance.now()
  for (let i = 0; i < WRITES; i++) {
    const s = performance.now()
    col.insert({ id: `call-${i}`, ...payload })
    writeLatencies.push(performance.now() - s)
  }
  const totalMs = performance.now() - t0

  const readGetStart = performance.now()
  for (let i = 0; i < 1000; i++) col.get(`call-${(i * 7919) % WRITES}`)
  const readGetMs = performance.now() - readGetStart

  const scanStart = performance.now()
  const hits = col.find((r) => r.status === 'ok').length
  const scanMs = performance.now() - scanStart

  const allStart = performance.now()
  const all = col.all()
  const allMs = performance.now() - allStart

  const rssBefore = rssMB()
  writeLatencies.sort((a, b) => a - b)
  console.log(`\n━━ ${kind} 后端（${WRITES} 次写入）━━`)
  console.log(`  写入吞吐      ：${Math.round(WRITES / (totalMs / 1000))} 写/秒（总耗时 ${(totalMs / 1000).toFixed(2)}s）`)
  console.log(`  单写延迟 P50  ：${writeLatencies[Math.floor(writeLatencies.length / 2)].toFixed(3)} ms`)
  console.log(`  单写延迟 P95  ：${writeLatencies[Math.floor(writeLatencies.length * 0.95)].toFixed(3)} ms`)
  console.log(`  单写延迟 P99  ：${writeLatencies[Math.floor(writeLatencies.length * 0.99)].toFixed(3)} ms`)
  console.log(`  单写延迟 max  ：${writeLatencies[writeLatencies.length - 1].toFixed(3)} ms`)
  console.log(`  点读 1000 次  ：${readGetMs.toFixed(1)} ms`)
  console.log(`  全表 find     ：${scanMs.toFixed(1)} ms（命中 ${hits}）`)
  console.log(`  全表 all()    ：${allMs.toFixed(1)} ms（${all.length} 条）`)
  console.log(`  RSS           ：${rssBefore} MB（写入前 ${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB 基线见进程启动）`)

  // Déclenche le crochet dispose de StorageService (ferme la connexion DB/arrête les minuteurs anti-rebond) ; les anciennes versions de cordis sans dispose sautent
  try {
    await ctx.dispose?.()
  } catch { /* les différences d'API de cycle de vie n'affectent pas les résultats du benchmark */ }
  rmSync(dataDir, { recursive: true, force: true })
  return { kind, p99: writeLatencies[Math.floor(writeLatencies.length * 0.99)] }
}

console.log(`存储后端基准 · Node ${process.version} · 写入量 ${WRITES}`)
const results = []
if (ONLY === 'both' || ONLY === 'json') results.push(await benchBackend('json'))
if (ONLY === 'both' || ONLY === 'sqlite') results.push(await benchBackend('sqlite'))

const sqlite = results.find((r) => r.kind === 'sqlite')
if (sqlite) {
  const pass = sqlite.p99 < 50
  console.log(`\nADR-0001 验收线：SQLite 串行写入 P99 < 50ms（串行口径，见文件头说明）→ ${pass ? '✔ 通过' : `✘ 未过（${sqlite.p99.toFixed(2)}ms）`}`)
  if (!pass) process.exitCode = 1
}
