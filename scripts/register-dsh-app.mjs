#!/usr/bin/env node
/**
 * register-dsh-app.mjs — enregistrement en un clic de l'Application IA du dsh local (aligné sur la moitié enregistrement d'application de docs/app-onboarding.md).
 *
 * Complémentaire de scripts/register-dsh-agent.mjs (registre des Agents) : ce script enregistre le registre « Applications IA » (préfixe app_),
 * au nom de l'hôte web dsh local (dsh --profile web, entrée https://dsh.ybkkasi.com/). Idempotent et réexécutable :
 *   ① dédoublonnage idempotent par slug : une application de même nom/slug existante est réutilisée, pas de double enregistrement sous un autre nom
 *   ② enregistre l'application (état draft ; l'orchestration agentIds n'accepte que des Agents en ligne, à attacher après la mise en ligne de l'Agent de l'hôte DSH)
 *   ③ écrit les identifiants machine de l'application dans <data-dir>/dsh-app-credential.json (0600 ; le secret n'apparaît qu'une fois à la délivrance)
 *   ④ auto-vérification par échange d'identité machine (GET /api/apps/:id, app.read)
 *
 * Usage :
 *   node scripts/register-dsh-app.mjs --url http://127.0.0.1:7300 \
 *     --data-dir /Users/ybkk/ybkkasi/data
 *   (identifiants administrateur : DSHCTL_USER/DSHCTL_PASS ou --user/--pass ; un jeton existant peut être passé directement via DSHCTL_TOKEN)
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { chmodSync } from 'node:fs'

const argv = process.argv.slice(2)
const arg = (flag, fallback) => {
  const i = argv.indexOf(flag)
  return i >= 0 ? argv[i + 1] : fallback
}
const BASE_URL = (arg('--url', process.env.DSHCTL_URL ?? 'http://127.0.0.1:7300')).replace(/\/+$/, '')
const APP_NAME = arg('--name', '本机 dsh')
const APP_SLUG = arg('--slug', 'local-dsh')
const ENTRY_URL = arg('--entry', 'https://dsh.ybkkasi.com/')
const APP_TYPE = arg('--app-type', 'web')
const RISK_LEVEL = arg('--risk-level', 'medium')
const DATA_CLASS = arg('--data-class', 'internal')
const ICON = arg('--icon', '🌀')
const PUBLISH_VERSION = arg('--version', 'v1.0.0')
const DEVELOPER_ID = arg('--developer-id', 'usr_mv6i8r1kgksivdhf')
const AGENT_IDS = (arg('--agent-ids', '') ?? '').split(',').map((s) => s.trim()).filter(Boolean)
const DATA_DIR = resolve(arg('--data-dir', './data'))
const CRED_FILE = join(DATA_DIR, 'dsh-app-credential.json')
const DESCRIPTION = arg('--desc', `本机 dsh（DeepSeek Harness 数字员工宿主）的 AI 应用登记：Web 交互工作台，宿主入口 ${ENTRY_URL}。由 register-dsh-app.mjs 登记与维护。`)

const log = (msg) => console.log(`[register-dsh-app] ${msg}`)
const fail = (msg) => { console.error(`[register-dsh-app] ✘ ${msg}`); process.exit(1) }

async function api(method, path, { token, body } = {}) {
  const headers = { 'content-type': 'application/json' }
  if (token) headers.authorization = `Bearer ${token}`
  const response = await fetch(`${BASE_URL}${path}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  })
  let payload = null
  try { payload = await response.json() } catch { /* non-json */ }
  return { status: response.status, ok: payload?.ok !== false && response.status < 400, data: payload?.data, error: payload?.error }
}

// ---- ① Identité administrateur ----------------------------------------------------------
let adminToken = process.env.DSHCTL_TOKEN ?? ''
if (adminToken) log('使用 DSHCTL_TOKEN 环境变量令牌')
if (!adminToken) {
  const user = arg('--user', process.env.DSHCTL_USER ?? 'admin')
  const pass = arg('--pass', process.env.DSHCTL_PASS)
  if (!pass) fail('缺少管理员凭证：设置 DSHCTL_PASS（或 --pass），或直接提供 DSHCTL_TOKEN')
  const login = await api('POST', '/api/auth/login', { body: { username: user, password: pass } })
  if (!login.ok) fail(`管理员登录失败：${login.error?.message ?? login.status}（注意：连续失败 5 次触发锁定，勿反复试错）`)
  adminToken = login.data.token
  log(`管理员 ${user} 登录成功`)
}

// ---- ② Enregistrement idempotent -------------------------------------------------------------
const list = await api('GET', `/api/apps?q=${encodeURIComponent(APP_SLUG)}`, { token: adminToken })
if (!list.ok) fail(`读取应用台账失败：${list.error?.message ?? list.status}`)
const existing = (list.data?.apps ?? []).find((item) => item.slug === APP_SLUG || item.name === APP_NAME)
let app = existing
let credential = null
if (app) {
  log(`应用已存在，复用：${app.id}（${app.name}），不换名重复注册`)
} else {
  const created = await api('POST', '/api/apps', {
    token: adminToken,
    body: {
      name: APP_NAME,
      slug: APP_SLUG,
      attrs: {
        description: DESCRIPTION,
        appType: APP_TYPE,
        icon: ICON,
        url: ENTRY_URL,
        channels: [],
        publishVersion: PUBLISH_VERSION,
        riskLevel: RISK_LEVEL,
        dataClass: DATA_CLASS,
        developerId: DEVELOPER_ID,
        ...(AGENT_IDS.length > 0 ? { agentIds: AGENT_IDS } : {}),
      },
    },
  })
  if (!created.ok) fail(`注册失败：${created.error?.message ?? created.status}`)
  app = created.data.app
  credential = created.data.credential
  log(`注册成功：${app.id}（${app.name}，draft）${credential ? `；机器凭证已下发（clientId=${credential.clientId}）` : ''}`)
}

// ---- ③ Écriture des identifiants (0600 ; fusion incrémentale, ne jamais écraser un secret existant par une valeur vide) ----------------
mkdirSync(DATA_DIR, { recursive: true })
let stored = {}
if (existsSync(CRED_FILE)) {
  try { stored = JSON.parse(readFileSync(CRED_FILE, 'utf8')) } catch { stored = {} }
}
if (credential) {
  stored.appId = app.id
  stored.appName = app.name
  stored.slug = app.slug
  stored.clientId = credential.clientId
  stored.clientSecret = credential.clientSecret
  stored.registeredAt = new Date().toISOString()
} else if (stored.clientId && stored.appId === app.id) {
  log('凭证文件已有本应用的机器凭证，保留复用（secret 丢失请走 onboarding-prompt rotate，勿重注册）')
} else {
  log('⚠ 本机凭证文件中没有该应用的 clientSecret（注册非本次发起）——自验步骤将跳过，请补齐后重跑')
}
writeFileSync(CRED_FILE, JSON.stringify(stored, null, 2))
try { chmodSync(CRED_FILE, 0o600) } catch { /* au mieux */ }
log(`凭证已写入 ${CRED_FILE}`)

// ---- ④ Auto-vérification de l'identité machine ----------------------------------------------------------
if (stored.clientId && stored.clientSecret && stored.appId === app.id) {
  const cc = await api('POST', '/api/auth/client-credentials', { body: { clientId: stored.clientId, clientSecret: stored.clientSecret } })
  if (!cc.ok) fail(`机器换牌失败：${cc.error?.message ?? cc.status}（secret 可能已丢失/轮换，请管理员轮换后更新凭证文件）`)
  const self = await api('GET', `/api/apps/${app.id}`, { token: cc.data.token })
  if (!self.ok) fail(`应用自读失败：${self.error?.message ?? self.status}`)
  log(`自验通过：机器凭证可读自身（app.read）——metrics-report / PATCH 自助通道可用`)
}

// ---- Rapport d'achèvement ----------------------------------------------------------------
console.log(`
──────────────────────────────────────────────
登记完成 ✅
  应用 ID   : ${app.id}
  台账入口  : ${BASE_URL}/rq/ →「AI 应用」页（ybkkasi.com 同库可见）
  凭证文件  : ${CRED_FILE}
下一步（人工治理闭环，不绕过审批）：
  1. 「DSH 宿主 Agent」（agt_mv79vwdb69d3v56a）上线后，PATCH 本应用 attrs.agentIds 挂编排
  2. web 形态上线门禁：先签发 SSO 客户端（控制台「AI应用→应用详情→SSO配置」；
     环回回调可由应用凭机器凭证自助 POST /api/apps/:id/sso-client）
  3. 「进入试运行」→ 验证免登与指标提报 → 「发布上线」走 L4 审批
──────────────────────────────────────────────`)
