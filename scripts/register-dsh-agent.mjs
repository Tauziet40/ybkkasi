#!/usr/bin/env node
/**
 * register-dsh-agent.mjs — enregistrement d'actif en un clic de l'Agent dsh auto-géré par la plateforme (docs/internal/dev-plan-agent-host-unification.md M3).
 *
 * Exécute le flux complet agent-onboarding sur la plateforme hôte (docs/agent-onboarding.md), idempotent et réexécutable :
 *   ① enregistre l'Agent (idempotent par nom : réutilise s'il existe, pas de double enregistrement sous un autre nom)
 *   ② écrit les identifiants machine dans data/dsh-agent-credential.json (0600 ; le secret n'apparaît qu'une fois à la délivrance, en cas de perte on passe par la rotation, pas par un ré-enregistrement)
 *   ③ PATCH des attributs de gouvernance de l'identité machine (entryUrl / dataClass)
 *   ④ première remontée de données opérationnelles (metrics-report, devoir d'intégration « envoyer une phrase »)
 *   ⑤ émet le client OIDC associé à l'Agent (redirect_uri=<entry>/auth/oidc/callback ; réutilisé si déjà émis)
 *
 * Usage :
 *   node scripts/register-dsh-agent.mjs --url http://192.168.0.7:3080 --entry http://192.168.0.7:3080/
 *   (identifiants administrateur : DSHCTL_USER/DSHCTL_PASS ou --user/--pass ; un jeton existant peut être passé directement via DSHCTL_TOKEN)
 *
 * Après l'enregistrement, la clôture de gouvernance reste humaine : console « corps de l'Agent → transitions d'état » via l'essai/L4 d'approbation de mise en ligne (sans contournement).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { chmodSync } from 'node:fs'

// ---- Paramètres ----------------------------------------------------------------
const argv = process.argv.slice(2)
const arg = (flag, fallback) => {
  const i = argv.indexOf(flag)
  return i >= 0 ? argv[i + 1] : fallback
}
const BASE_URL = (arg('--url', process.env.DSHCTL_URL ?? 'http://127.0.0.1:7300')).replace(/\/+$/, '')
const AGENT_NAME = arg('--name', 'dsh-web-agent')
const ENTRY_URL = (arg('--entry', `${BASE_URL}/`))
const MODEL = arg('--model', 'deepseek-chat')
const RISK_LEVEL = arg('--risk-level', 'low')
const DATA_DIR = resolve(arg('--data-dir', './data'))
const CRED_FILE = join(DATA_DIR, 'dsh-agent-credential.json')
const OIDC_CALLBACK_PATH = arg('--redirect', '/auth/oidc/callback')
const DATA_CLASS = arg('--data-class', 'internal')
const DESCRIPTION = arg('--desc', `元冰可平台自营 dsh Agent（宿主：${BASE_URL}）。由 register-dsh-agent.mjs 登记与维护。`)

const log = (msg) => console.log(`[register-dsh-agent] ${msg}`)
const fail = (msg) => { console.error(`[register-dsh-agent] ✘ ${msg}`); process.exit(1) }

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
  if (!login.ok) fail(`管理员登录失败：${login.error?.message ?? login.status}`)
  adminToken = login.data.token
  log(`管理员 ${user} 登录成功`)
}

// ---- ② Enregistrement (idempotent) --------------------------------------------------------
const list = await api('GET', `/api/agents?q=${encodeURIComponent(AGENT_NAME)}`, { token: adminToken })
if (!list.ok) fail(`读取 Agent 台账失败：${list.error?.message ?? list.status}`)
let agent = (list.data?.agents ?? []).find((item) => item.name === AGENT_NAME)
let credential = null
if (agent) {
  log(`Agent 已存在，复用：${agent.id}（${agent.name}），不重复注册`)
} else {
  const created = await api('POST', '/api/agents', {
    token: adminToken,
    body: { name: AGENT_NAME, attrs: { description: DESCRIPTION, model: MODEL, riskLevel: RISK_LEVEL, avatar: '🛰️', tags: ['dsh', '自营'] } },
  })
  if (!created.ok) fail(`注册失败：${created.error?.message ?? created.status}`)
  agent = created.data.agent
  credential = created.data.credential
  log(`注册成功：${agent.id}；机器凭证已下发（clientId=${credential.clientId}）`)
}

// ---- ③ Écriture des identifiants (0600 ; fusion incrémentale, ne jamais écraser un secret existant par une valeur vide) ----------------
mkdirSync(DATA_DIR, { recursive: true })
let stored = {}
if (existsSync(CRED_FILE)) {
  try { stored = JSON.parse(readFileSync(CRED_FILE, 'utf8')) } catch { stored = {} }
}
if (credential) {
  stored.agentId = agent.id
  stored.agentName = agent.name
  stored.clientId = credential.clientId
  stored.clientSecret = credential.clientSecret
  stored.registeredAt = new Date().toISOString()
} else if (stored.clientId && stored.agentId === agent.id) {
  log('凭证文件已有本 Agent 的机器凭证，保留复用（secret 丢失请走 dshctl credential rotate，勿重注册）')
} else {
  log('⚠ 本机凭证文件中没有该 Agent 的 clientSecret（注册非本次发起）——机器登录与提报步骤将跳过，请补齐后重跑')
}
writeFileSync(CRED_FILE, JSON.stringify(stored, null, 2))
try { chmodSync(CRED_FILE, 0o600) } catch { /* la sémantique des permissions de fichiers Windows diffère, au mieux */ }
log(`凭证已写入 ${CRED_FILE}`)

// ---- ④ PATCH des attributs de gouvernance de l'identité machine + première remontée -----------------------------------
let machineToken = ''
if (stored.clientId && stored.clientSecret) {
  const cc = await api('POST', '/api/auth/client-credentials', { body: { clientId: stored.clientId, clientSecret: stored.clientSecret } })
  if (!cc.ok) fail(`机器换牌失败：${cc.error?.message ?? cc.status}（secret 可能已丢失/轮换，请管理员轮换后更新凭证文件）`)
  machineToken = cc.data.token
  log('机器身份换牌成功（2h 令牌）')

  const patched = await api('PATCH', `/api/agents/${agent.id}`, {
    token: machineToken,
    body: { attrs: { entryUrl: ENTRY_URL, dataClass: DATA_CLASS } },
  })
  if (!patched.ok) fail(`治理属性提报失败：${patched.error?.message ?? patched.status}`)
  log(`治理属性已提报：entryUrl=${ENTRY_URL} dataClass=${DATA_CLASS}`)

  const report = await api('POST', `/api/agents/${agent.id}/metrics-report`, {
    token: machineToken,
    body: { dau: 1, sessions: 1, uniqueUsers: 1 },
  })
  if (!report.ok) fail(`首次运营数据提报失败：${report.error?.message ?? report.status}`)
  log('首次运营数据提报完成（metrics.sessions ≥ 1 即接入验收口径）')
}

// ---- ⑤ Client OIDC associé à l'Agent (réutilisé si déjà émis) -------------------------------
const detail = await api('GET', `/api/agents/${agent.id}`, { token: adminToken })
if (!detail.ok) fail(`读取 Agent 详情失败：${detail.error?.message ?? detail.status}`)
if (detail.data.sso) {
  stored.oidc = { ...(stored.oidc ?? {}), clientId: detail.data.sso.clientId, redirectUris: detail.data.sso.redirectUris }
  writeFileSync(CRED_FILE, JSON.stringify(stored, null, 2))
  log(`OIDC 客户端已存在，复用：${detail.data.sso.clientId}`)
} else {
  const origin = new URL(ENTRY_URL).origin
  const redirectUri = `${origin}${OIDC_CALLBACK_PATH}`
  const issued = await api('POST', `/api/agents/${agent.id}/sso-client`, {
    token: adminToken,
    body: { redirectUris: [redirectUri], clientType: 'confidential', description: `dsh Agent 免登回跳（register-dsh-agent.mjs）` },
  })
  if (!issued.ok) fail(`OIDC 客户端签发失败：${issued.error?.message ?? issued.status}`)
  stored.oidc = { clientId: issued.data.clientId, clientSecret: issued.data.clientSecret, redirectUris: issued.data.redirectUris }
  writeFileSync(CRED_FILE, JSON.stringify(stored, null, 2))
  log(`OIDC 客户端已签发：${issued.data.clientId}（redirect_uri=${redirectUri}；secret 已入凭证文件，仅此一次）`)
}

// ---- Rapport d'achèvement ----------------------------------------------------------------
console.log(`
──────────────────────────────────────────────
登记完成 ✅
  Agent ID     : ${agent.id}
  台账/监控    : ${BASE_URL}/rq/ →「Agent 本体」页
  凭证文件     : ${CRED_FILE}
下一步（人工治理闭环，不绕过审批）：
  1. 控制台确认 SSO 配置/entryUrl/计量（Agent 详情 → SSO 配置/监控）
  2. 「进入试运行」填 trialGroups → 验证免登与审计归因
  3. 「上线」走 L4 审批（门禁已满足：OIDC 客户端 + entryUrl）
──────────────────────────────────────────────`)
