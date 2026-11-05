/**
 * Exercice de robustesse du démarrage (EXEC-CHECKLIST W2) : validation purement en processus des trois lignes de défense de boot-probe.
 * N'occupe aucun port, n'écrit pas dans le répertoire data. Usage : node scripts/boot-drill.mjs (code de sortie 0 = exercice réussi).
 *
 * Scénarios :
 *   ① assemblage normal d'un arbre minimal de plugins → probeTree ok:true
 *   ② un autre root Context enregistre un service homonyme (pathologie de double instance) → le ctx courant signale le service inaccessible et les fiber PENDING
 *   ③ pollution de globalThis[clé root] → assertSingleRoot lève « double instance »
 *   ④ fiber FAILED perdant (provide déclaré déjà repris, idiome de double inscription) → ok:true, simple entrée au registre de diagnostic
 *   ⑤ FAILED panne réelle (provide déclaré repris par personne) → ok:false, bloque le démarrage
 * Nettoyage de la pollution globalThis après chaque scénario.
 */
import { Context } from '@deepseek-ai/cordis'
import * as platformCore from '../packages/platform-core/src/index.ts'

const ROOT_KEY = Symbol.for('ybkk.cordis.root')
const clearRoot = () => Reflect.deleteProperty(globalThis, ROOT_KEY)

const outcomes = []
function record(name, pass, detail = '') {
  outcomes.push({ name, pass: Boolean(pass) })
  console.log(`  ${pass ? '\x1b[32m✔\x1b[0m' : '\x1b[31m✘\x1b[0m'} ${name}${pass ? '' : `  ← ${detail}`}`)
}

/** Paire minimale de plugins fournisseur/consommateur : l'exercice ne s'intéresse qu'aux états des fiber, aucun métier porté. */
const iamProvider = (source) => ({
  name: 'iam-provider',
  apply(ctx) { ctx.provide('iam', { source }) },
})
const iamConsumer = { name: 'iam-consumer', inject: ['iam'], apply() {} }

// Scénario ① : assemblage normal → diagnostic tout vert
async function scenario1() {
  console.log('\n\x1b[36m━━ 场景① 正常装配最小插件树 ━━\x1b[0m')
  const ctx = new Context()
  platformCore.assertSingleRoot(ctx)
  await ctx.plugin(iamProvider('drill-ok'))
  await ctx.plugin(iamConsumer)
  const health = platformCore.probeTree(ctx, ['iam'])
  record('probeTree ok:true', health.ok === true && health.unreachable.length === 0 && health.stuck.length === 0,
    JSON.stringify(health))
  clearRoot()
}

// Scénario ② : pathologie de double instance → le ctx courant ne voit jamais le service homonyme de l'autre root
async function scenario2() {
  console.log('\n\x1b[36m━━ 场景② 另一 root 注册同名服务 ━━\x1b[0m')
  const ctx = new Context()
  const otherRoot = new Context()
  await otherRoot.plugin(iamProvider('other-root'))
  // La résolution d'inject du fiber consommateur ne trouve pas l'implémentation → PENDING silencieux (cause racine reproduite), sans await (l'état de suspension est la conclusion)
  ctx.plugin(iamConsumer)
  const health = platformCore.probeTree(ctx, ['iam'])
  record('probeTree 报 iam 不可达且 consumer 卡 PENDING',
    !health.ok && health.unreachable.includes('iam')
      && health.stuck.some((f) => f.plugin === 'iam-consumer' && f.state === 'PENDING' && f.waiting.includes('iam')),
    JSON.stringify(health))
  const text = platformCore.formatTreeHealth(health)
  record('formatTreeHealth 可读（拒绝启动 + 插件名 + 等待键）',
    text.includes('插件树未健康') && text.includes('iam-consumer') && text.includes('PENDING') && text.includes('iam'),
    text)
  clearRoot()
}

// Scénario ③ : pollution globalThis → l'assertion lève ; nettoyée, tout revient
function scenario3() {
  console.log('\n\x1b[36m━━ 场景③ 污染 globalThis 后断言双实例 ━━\x1b[0m')
  globalThis[ROOT_KEY] = { polluted: true }
  let thrown = null
  try { platformCore.assertSingleRoot(new Context()) } catch (error) { thrown = error }
  record('assertSingleRoot 抛错且消息含「双实例」',
    thrown instanceof Error && thrown.message.includes('双实例'), String(thrown))
  clearRoot()
  let afterClean = null
  const ctx = new Context()
  try { platformCore.assertSingleRoot(ctx) } catch (error) { afterClean = error }
  record('清理污染后恢复正常登记', afterClean === null && globalThis[ROOT_KEY] === ctx.root, String(afterClean))
  clearRoot()
}

// Scénarios ④⑤ : les deux formes de fiber FAILED — perdant bénin (provide déjà repris) et panne réelle (repris par personne)
async function scenario45() {
  console.log('\n\x1b[36m━━ 场景④ 双注册习语的良性败者 fiber ━━\x1b[0m')
  const ctx = new Context()
  platformCore.assertSingleRoot(ctx)
  // Réplique l'idiome de panel-core/flow-core (forme plugin-fonction, champ statique provide identique à la classe PanelService :
  // registry.resolve prend le corps de la fonction comme callback pour un plugin-fonction) — d'abord ctx.plugin enregistre, puis inscription synchrone du même nom
  // d'implémentation : le synchrone gagne ; le chargement asynchrone du second échoue sur le provide et laisse un husk FAILED
  const decoy = (ctx) => ctx.provide('iam', { source: 'decoy' })
  decoy.provide = 'iam'
  await ctx.plugin({
    name: 'decoy-module',
    apply(ctx) {
      ctx.plugin(decoy)
      ctx.provide('iam', { source: 'module' })
    },
  })
  const health = platformCore.probeTree(ctx, ['iam'])
  const husk = health.stuck.find((f) => f.plugin === 'decoy')
  record('良性败者：ok:true 且 FAILED husk 仅入诊断清单',
    health.ok === true && !!husk && husk.state === 'FAILED' && husk.blocking === false,
    JSON.stringify(health))
  clearRoot()

  console.log('\n\x1b[36m━━ 场景⑤ FAILED 且 provide 无人接管 → 拦启动 ━━\x1b[0m')
  const ctx2 = new Context()
  platformCore.assertSingleRoot(ctx2)
  const broken = () => { throw new Error('boom') }
  broken.provide = 'iam'
  try { await ctx2.plugin(broken) } catch { /* l'échec de démarrage est lui-même la précondition du scénario */ }
  const health2 = platformCore.probeTree(ctx2, [])
  const dead = health2.stuck.find((f) => f.plugin === 'broken')
  record('真实故障：ok:false 且 FAILED 标记 blocking',
    health2.ok === false && health2.unreachable.length === 0 && !!dead && dead.blocking === true,
    JSON.stringify(health2))
  clearRoot()
}

await scenario1()
await scenario2()
scenario3()
await scenario45()

console.log('\n—— 演练结论 ——')
for (const { name, pass } of outcomes) {
  console.log(`${pass ? '✔' : '✘'} ${name}`)
}
const failed = outcomes.filter((o) => !o.pass).length
if (failed > 0) {
  console.log(`\n演练未通过：${failed} 项`)
  process.exit(1)
}
console.log('\n演练全部通过')
