#!/usr/bin/env node
/**
 * Assertions de compatibilité dsh (EXEC-CHECKLIST 3.3).
 *
 * Déclaration : ce script est l'unique source de validation automatisée du champ `dsh.compatibility.dshReleases` du package.json racine ;
 * toute modification manuelle de ce champ est une déclaration invalide — le "compatible" d'une version donnée n'est écrit par ce script
 * que si les cinq assertions ci-dessous passent toutes.
 *
 * Usage : node scripts/check-dsh-compat.mjs <dsh-version>
 *   ex. : node scripts/check-dsh-compat.mjs 0.1.0-rc.7
 *
 * Cinq assertions (dans l'ordre ; au premier échec, affiche « où ça bloque + preuves » et sort en non-zéro) :
 *   ① confirmation de version : la sortie de npx --yes @deepseek-ai/dsh@<version> --version contient le numéro de version.
 *   ② tirage de l'entité cordis de dsh dans un répertoire temporaire, confirmation de la présence de vendor/cordis (voir « chaîne de provenance » plus bas).
 *   ③ dans la copie temporaire du projet, la résolution de @deepseek-ai/cordis pointe vers cette entité (ln -s POSIX /
 *      junction Windows), l'assemblage suivant tournant entièrement sur le cordis côté dsh.
 *   ④ sous cette résolution, assemblage d'un arbre minimal de plugins et exécution de probeTree (packages/platform-core/src/
 *      boot-probe.ts, livré en parallèle par l'équipe démarrage ; message d'erreur convivial si absent), assertion ok:true et
      absence de double enregistrement de plugin dans le registry.
 *   ⑤ après tout passant, écriture de "<version>": "compatible" dans dshReleases du package.json racine
      (lecture-modification-écriture fs, indentation 2 espaces ; jamais d'écriture en cas d'échec).
 *
 * Chaîne de provenance du ② (fondement mesuré, 2026-10-16) :
 *   - de préférence : git clone de l'arbre source de deepseek-ai/deepseek-harness au tag correspondant, validation du répertoire d'entité
 *     vendor/cordis (dégradation automatique si le dépôt est privé/inaccessible) ;
 *   - repli par npm : le paquet CLI de @deepseek-ai/dsh ne contient pas vendor/cordis (son tarball
 *     ne contient que lib/config), mais le paquet npm de @deepseek-ai/cordis est précisément le build de publication du répertoire
 *     vendor/cordis du dépôt harness (attesté par son champ package.json repository.directory).
 *     Le script résout la plage de dépendances cordis déclarée par dsh@<version>, pack la version et,
 *     après validation des champs de provenance, sert d'entité vendor/cordis de manière équivalente.
 *
 * Codes de sortie : 0 = compatibilité vérifiée ; 1 = échec d'assertion (incompatible/structure non conforme/sonde manquante) ;
 *         2 = environnement inaccessible, compatibilité non vérifiée (interdiction de prétendre compatible sans vérification).
 */
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { realpathSync } from 'node:fs'

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const VERSION_RE = /^\d+\.\d+\.\d+[-+.\w]*$/
const NET_MARKERS = /ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNREFUSED|ECONNRESET|EPROTO|EPIPE|self-signed|certificate|network|ETARGET|E404|404|Not Found|timed? ?out|socket hang up/i

const IS_WIN = process.platform === 'win32'
const EX_UNVERIFIED = 2

/** Signal de flux de contrôle : lève avec le code de sortie prédéterminé, main fait la clôture unifiée (garantit le nettoyage du répertoire temporaire avant de sortir). */
class ExitSignal extends Error {
  constructor(code) {
    super(`exit-${code}`)
    this.exitCode = code
  }
}

function printEvidence(evidence) {
  console.error(String(evidence).split('\n').map((l) => `    ${l}`).join('\n'))
}
function die(step, message, evidence) {
  console.error(`\n[x] 断言失败 · 卡在第 ${step} 步：${message}`)
  if (evidence) printEvidence(evidence)
  throw new ExitSignal(1)
}
function unreachable(message, evidence) {
  console.error(`\n[!] 环境不可达，兼容性未验证：${message}`)
  if (evidence) printEvidence(evidence)
  throw new ExitSignal(EX_UNVERIFIED)
}
function ok(step, message) {
  console.log(`[✓] 第 ${step} 步：${message}`)
}

/** Exécution de sous-processus avec délai d'attente ; renvoie {code, stdout, stderr, timedOut}. */
function run(cmd, args, { timeoutMs = 120_000, cwd, env } = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(cmd, args, {
      cwd,
      shell: IS_WIN,
      env: { ...process.env, NPM_CONFIG_UPDATE_NOTIFIER: 'false', ...env },
    })
    let stdout = ''
    let stderr = ''
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, timeoutMs)
    child.stdout.on('data', (d) => { stdout += d })
    child.stderr.on('data', (d) => { stderr += d })
    child.on('error', (err) => {
      clearTimeout(timer)
      resolvePromise({ code: -1, stdout, stderr: `${stderr}\n${err.message}`, timedOut })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolvePromise({ code, stdout, stderr, timedOut })
    })
  })
}

/** Crée un lien symbolique de répertoire ; junction sous Windows (sans privilège, peut pointer un répertoire). */
function symlinkDir(target, linkPath) {
  fs.mkdirSync(dirname(linkPath), { recursive: true })
  fs.symlinkSync(target, linkPath, IS_WIN ? 'junction' : 'dir')
}

/** Copie récursive de répertoire, en sautant node_modules / .git / data. */
function copyTree(from, to) {
  fs.cpSync(from, to, {
    recursive: true,
    filter: (src) => !/(^|[/\\])(node_modules|\.git|data)([/\\]|$)/.test(src),
  })
}

// ─── ① Confirmation de version ────────────────────────────────────────────────────────────────
async function assertVersion(version) {
  console.log(`\n[①] 版本确认：npx --yes @deepseek-ai/dsh@${version} --version`)
  const r = await run('npx', ['--yes', `@deepseek-ai/dsh@${version}`, '--version'], { timeoutMs: 480_000 })
  const output = `${r.stdout}\n${r.stderr}`.trim()
  if (r.timedOut || r.code !== 0) {
    const reason = r.timedOut ? `npx 执行超时（480s）` : `npx 退出码 ${r.code}（可能私包/网络/平台不匹配）`
    unreachable(`拉取 @deepseek-ai/dsh@${version} 失败：${reason}`, output)
  }
  if (!r.stdout.includes(version) && !r.stderr.includes(version)) {
    die('①', `dsh CLI 可执行，但 --version 输出不含 ${version}，实际版本不符`, output)
  }
  ok('①', `dsh CLI 版本确认输出含 ${version}`)
}

// ─── ② Tirage de l'entité cordis de dsh (vendor/cordis)────────────────────────────────
async function acquireVendorCordis(version, tmpRoot) {
  console.log('\n[②] 拉取 dsh 源码树 / cordis 实体到临时目录')

  // Chaîne A : arbre source. Si le dépôt est accessible et le tag présent, validation directe du répertoire d'entité vendor/cordis.
  // GIT_TERMINAL_PROMPT=0 : échec rapide si dépôt privé/inaccessible, sans attente d'identifiants interactive.
  const vendorRoot = join(tmpRoot, 'dsh', 'vendor', 'cordis')
  for (const tag of [`v${version}`, `dsh-v${version}`, `dsh@${version}`]) {
    const r = await run('git', ['clone', '--depth', '1', '--branch', tag,
      'https://github.com/deepseek-ai/deepseek-harness.git', join(tmpRoot, 'dsh', 'src')],
      { timeoutMs: 45_000, env: { GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'Never' } })
    if (r.code === 0) {
      const dir = join(tmpRoot, 'dsh', 'src', 'vendor', 'cordis')
      if (!fs.statSync(dir).isDirectory()) {
        die('②', `源码树 ${tag} 已拉取，但其中不存在 vendor/cordis 实体目录`, `期望路径：${dir}`)
      }
      symlinkDir(dir, vendorRoot)
      ok('②', `git tag ${tag} 源码树内 vendor/cordis 实体目录存在`)
      return { vendorRoot, source: `git:${tag}`, cordisVersion: null }
    }
    console.log(`    git 链 ${tag} 未成功（${r.timedOut ? '超时' : `退出码 ${r.code}`}），尝试下一来源`)
  }

  // Chaîne B : build de publication npm. @deepseek-ai/cordis est précisément le produit de publication de vendor/cordis du dépôt harness,
  // la provenance étant prouvée par le champ repository.directory du package.json.
  const rangeView = await run('npm', ['view', `@deepseek-ai/dsh@${version}`, 'dependencies.@deepseek-ai/cordis', '--json'], { timeoutMs: 60_000 })
  if (rangeView.code !== 0) {
    unreachable(`npm registry 不可达（无法解析 dsh@${version} 的 cordis 依赖范围）`, rangeView.stderr)
  }
  const range = JSON.parse(rangeView.stdout.trim() || 'null')
  if (typeof range !== 'string') {
    die('②', `dsh@${version} 未声明 @deepseek-ai/cordis 依赖，无法定位其 cordis 实体`, rangeView.stdout)
  }
  const listView = await run('npm', ['view', `@deepseek-ai/cordis@${range}`, 'version', '--json'], { timeoutMs: 60_000 })
  if (listView.code !== 0) unreachable(`npm registry 不可达（解析 ${range} 失败）`, listView.stderr)
  const versions = JSON.parse(listView.stdout.trim())
  const cordisVersion = (Array.isArray(versions) ? versions.at(-1) : versions)
  console.log(`    dsh@${version} 声明 cordis ${range} → 取发布版 ${cordisVersion}`)

  fs.mkdirSync(join(tmpRoot, 'dsh', 'vendor'), { recursive: true })
  const packed = await run('npm', ['pack', `@deepseek-ai/cordis@${cordisVersion}`], { timeoutMs: 120_000, cwd: tmpRoot })
  if (packed.code !== 0) unreachable(`npm pack cordis@${cordisVersion} 失败`, packed.stderr)
  const tgz = join(tmpRoot, packed.stdout.trim().split('\n').at(-1))
  fs.mkdirSync(vendorRoot, { recursive: true })
  await run('tar', ['-xzf', tgz, '-C', vendorRoot, '--strip-components', '1'], { timeoutMs: 60_000 })

  // Preuve de provenance : cette entité doit attester d'elle-même qu'elle vient du répertoire vendor/cordis du dépôt harness
  const manifest = JSON.parse(fs.readFileSync(join(vendorRoot, 'package.json'), 'utf8'))
  const directory = manifest?.repository?.directory
  if (manifest?.name !== '@deepseek-ai/cordis' || directory !== 'vendor/cordis') {
    die('②', '拉取到的 cordis 实体无法证明其来自 vendor/cordis（来源字段不符）',
        `name=${manifest?.name} repository.directory=${directory}`)
  }
  if (!fs.statSync(vendorRoot).isDirectory()) die('②', 'vendor/cordis 实体目录不存在')
  ok('②', `vendor/cordis 实体就绪（npm 发布构建 ${cordisVersion}，来源字段 repository.directory=vendor/cordis）`)
  return { vendorRoot, source: `npm:@deepseek-ai/cordis@${cordisVersion}`, cordisVersion }
}

// ─── ③ Copie temporaire du projet + couverture node_modules ──────────────────────────────────────
function buildOverlayProject(tmpRoot, vendorRoot) {
  console.log('\n[③] 临时副本内把 @deepseek-ai/cordis 解析指向 vendor/cordis')
  const proj = join(tmpRoot, 'project')
  for (const entry of ['package.json', 'src', 'packages', 'cordis.yml', 'cordis.patch.yml']) {
    const from = join(PROJECT_ROOT, entry)
    if (fs.existsSync(from)) copyTree(from, join(proj, entry))
  }

  const realNm = join(PROJECT_ROOT, 'node_modules')
  const tmpNm = join(proj, 'node_modules')
  fs.mkdirSync(tmpNm, { recursive: true })

  // Dépendances tierces : toute la chaîne installée réellement (hors les deux scopes, traités séparément ci-dessous)
  for (const entry of fs.readdirSync(realNm, { withFileTypes: true })) {
    if (entry.name === '@deepseek-ai' || entry.name === '@dsh-ops' || entry.name.startsWith('.')) continue
    symlinkDir(join(realNm, entry.name), join(tmpNm, entry.name))
  }
  // Paquets workspace : pointent vers le corps des paquets dans la copie temporaire (garantit que leurs imports cordis passent aussi par la couche de couverture)
  const wsScope = join(realNm, '@dsh-ops')
  if (fs.existsSync(wsScope)) {
    for (const entry of fs.readdirSync(wsScope, { withFileTypes: true })) {
      const real = realpathSync(join(wsScope, entry.name))
      const under = resolve(real).startsWith(resolve(PROJECT_ROOT, 'packages') + sep)
      const target = under ? join(proj, 'packages', entry.name) : real
      if (!under) console.log(`    警告：workspace 链接 ${entry.name} 不在 packages/ 下，退化为直连真实路径`)
      symlinkDir(target, join(tmpNm, '@dsh-ops', entry.name))
    }
  }
  // Assertion centrale : cordis bascule en un clic vers l'entité côté dsh ; ses dépendances (cosmokit etc.) retombent dans tmpRoot/node_modules en filet
  symlinkDir(vendorRoot, join(tmpNm, '@deepseek-ai', 'cordis'))
  for (const dep of ['@deepseek-ai/cosmokit', '@standard-schema/spec']) {
    const real = join(realNm, dep)
    if (fs.existsSync(real)) symlinkDir(real, join(tmpRoot, 'node_modules', dep))
  }
  ok('③', `node_modules 覆盖完成（POSIX symlink / Windows junction），cordis → ${vendorRoot}`)
  return proj
}

// ─── ④ Assemblage probeTree + assertion de non-double-enregistrement ─────────────────────────────────────────
// Contrat de sonde (boot-probe.ts déjà livré, W2) : probeTree(ctx, required) → { ok, unreachable, stuck },
// plus assertSingleRoot(ctx) sentinelle de double instance. L'arbre minimal est assemblé par ce runner :
//   le plugin provider enregistre le service dans ctx.provide au apply, le plugin consumer le consomme en inject —
//   si le câblage passe intégralement sous la résolution vendor/cordis, l'arbre isolé partagé par les deux hôtes est prouvé.
const RUNNER_SOURCE = String.raw`
// 由 check-dsh-compat.mjs 生成，在临时副本内执行——③ 的解析覆盖只在此树内生效。
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { isAbsolute, relative, resolve } from 'node:path'

const VENDOR_REAL = resolve(process.env.DSH_VENDOR_CORDIS_REAL)
const fail = (msg, evidence) => {
  console.error('[runner] ' + msg)
  if (evidence) console.error(String(evidence))
  process.exit(1)
}
const ok = (m) => console.log('[runner] ' + m)

// [4a] 单副本断言：本进程内的 @deepseek-ai/cordis 必须真实落在 vendor/cordis 树内
const resolved = realpathSync(fileURLToPath(import.meta.resolve('@deepseek-ai/cordis')))
const rel = relative(VENDOR_REAL, resolved)
if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
  fail('cordis 解析未落在 vendor/cordis 树内', 'resolved=' + resolved + '\nvendor=' + VENDOR_REAL)
}
ok('cordis 解析确认：' + resolved)
const cordis = await import('@deepseek-ai/cordis')

// [4b] 装配最小插件树并跑 probeTree（探针缺失/契约未定时友好报错，不谎报兼容）
let probeMod
try {
  probeMod = await import(new URL('./packages/platform-core/src/boot-probe.ts', import.meta.url).href)
} catch (err) {
  console.error('[runner] probeTree 探针不可用：packages/platform-core/src/boot-probe.ts 导入失败（启动组并行交付中）')
  console.error(String(err?.message || err))
  process.exit(2)
}
const probeTree = probeMod?.probeTree
if (typeof probeTree !== 'function') {
  console.error('[runner] 探针已存在但未导出 probeTree(ctx, required)，契约以启动组交付为准')
  process.exit(2)
}

const SERVICE = 'dshCompatProbeService'
const ctx = new cordis.Context()
try {
  probeMod.assertSingleRoot(ctx)
} catch (err) {
  fail('assertSingleRoot 双实例断言失败（vendor/cordis 单副本被破坏）', err?.stack || String(err))
}
await ctx.plugin({ name: 'dsh-compat-provider', apply(c) { c.provide(SERVICE, { origin: 'dsh-compat' }) } })
await ctx.plugin({ name: 'dsh-compat-consumer', inject: [SERVICE], apply() {} })

const health = probeTree(ctx, [SERVICE])
if (health?.ok !== true) fail('probeTree 未返回 ok:true（必需服务不可达或有拦启动的卡死 fiber）', JSON.stringify(health, null, 2))
ok('probeTree ok:true（required=[' + SERVICE + ']，stuck=' + health.stuck.length + '）')

// [4c] 重复注册断言（对照 cordis 4.0.4 src/registry.ts 真实结构）：
//   RegistryService._internal 是 Map<Function, Plugin.Runtime>——同一 Function 键在
//   单 registry 内不可能出现两个 runtime，因此可观测的重复特征是：
//   a) 两个 runtime 携同一插件名（同一插件经两份模块副本各注册一次）；
//   b) keys() 与 values() 数目失衡（Map 语义被破坏时的健全性哨兵）。
//   Runtime 形状：{ name?, callback: Function, fibers: DisposableList, Config? }。
const registry = ctx.registry
if (!registry || typeof registry.forEach !== 'function') fail('无法取得 cordis RegistryService 实例')
const runtimes = []
registry.forEach((rt, key) => runtimes.push({
  name: rt?.name ?? null,
  callbackFn: typeof rt?.callback === 'function',
  fibers: rt?.fibers?.length ?? 0,
  keyName: key?.name ?? null,
}))
const badShape = runtimes.filter((rt) => !rt.callbackFn)
if (badShape.length > 0) fail('存在 callback 非函数的 runtime，registry 结构与 cordis 4.0.4 不符', JSON.stringify(badShape))

const byName = new Map()
for (const rt of runtimes) {
  if (rt.name == null) continue
  const list = byName.get(rt.name) ?? []
  list.push(rt)
  byName.set(rt.name, list)
}
const dups = [...byName.entries()].filter(([, list]) => list.length > 1)
if (dups.length > 0) fail('发现插件重复注册：同一插件名出现多个 runtime', JSON.stringify(dups.map(([n, l]) => ({ name: n, count: l.length }))))

let keyCount = 0
for (const _ of registry.keys()) keyCount++
if (keyCount !== runtimes.length) fail('registry keys() 与 values() 数目失衡', keyCount + ' vs ' + runtimes.length)

ok('重复注册断言通过：' + runtimes.length + ' 个 runtime，无同名冲突')
console.log('PROBE_OK ' + JSON.stringify({ runtimes: runtimes.length, service: SERVICE }))
`

async function assertProbe(proj, vendorRoot) {
  console.log('\n[④] 覆盖解析下装配最小插件树并跑 probeTree + 重复注册断言')
  const runnerPath = join(proj, 'dsh-compat-runner.mjs')
  fs.writeFileSync(runnerPath, RUNNER_SOURCE)
  const r = await run(process.execPath, [runnerPath], {
    timeoutMs: 120_000,
    cwd: proj,
    env: { ...process.env, DSH_VENDOR_CORDIS_REAL: realpathSync(vendorRoot) },
  })
  const output = `${r.stdout}\n${r.stderr}`.trim()
  if (r.code !== 0) {
    die('④', r.timedOut ? 'probeTree 执行超时（120s）' : `探针进程退出码 ${r.code}`, output)
  }
  const marker = r.stdout.split('\n').find((l) => l.startsWith('PROBE_OK '))
  if (!marker) die('④', '探针进程成功但缺少 PROBE_OK 结论行', output)
  ok('④', marker.replace('PROBE_OK ', '装配结论 '))
}

// ─── ⑤ Écriture dans dshReleases ──────────────────────────────────────────────────────
function recordCompatibility(version) {
  console.log('\n[⑤] 记录 dsh.compatibility.dshReleases')
  const pkgPath = join(PROJECT_ROOT, 'package.json')
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
  const releases = pkg?.dsh?.compatibility?.dshReleases
  if (releases?.[version] === 'compatible') {
    ok('⑤', `${version} 已记录为 compatible，本次运行复核通过（机器确认）`)
    return
  }
  const next = structuredClone(pkg)
  next.dsh ??= {}
  next.dsh.compatibility ??= {}
  next.dsh.compatibility.dshReleases ??= {}
  next.dsh.compatibility.dshReleases[version] = 'compatible'
  try {
    fs.writeFileSync(pkgPath, JSON.stringify(next, null, 2) + '\n')
  } catch (err) {
    die('⑤', '兼容性已验证，但写入 package.json 失败（按约定失败绝不写，请人工核对）', err.stack || String(err))
  }
  ok('⑤', `已写入 "${version}": "compatible"`)
}

// ─── Flux principal ──────────────────────────────────────────────────────────────────
async function main() {
  const version = process.argv[2]
  if (!version || !VERSION_RE.test(version)) {
    console.error('用法：node scripts/check-dsh-compat.mjs <dsh-version>   例：0.1.0-rc.7')
    return 1
  }
  const tmpRoot = fs.mkdtempSync(join(os.tmpdir(), 'dsh-compat-'))
  let exitCode = 0
  try {
    await assertVersion(version)
    const { vendorRoot } = await acquireVendorCordis(version, tmpRoot)
    const proj = buildOverlayProject(tmpRoot, vendorRoot)
    await assertProbe(proj, vendorRoot)
    recordCompatibility(version)
    console.log(`\n[PASS] dsh@${version} 五项断言全部通过，已确认兼容。`)
  } catch (err) {
    if (err instanceof ExitSignal) {
      exitCode = err.exitCode
    } else {
      console.error(`\n[x] 未预期异常`)
      printEvidence(err?.stack || String(err))
      exitCode = 1
    }
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true })
  }
  return exitCode
}

process.exit(await main())
