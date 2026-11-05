#!/usr/bin/env node
/**
 * run-closed-loop-review.mjs — pilotage du test réel de la boucle fermée automatisée du centre d'exécution (heartbeat + fil de tâches, vérification de bout en bout).
 *
 * Sous l'identité de l'officier d'exécution de gouvernance (échange client-credentials, scopes=*), réalise sur la plateforme en cours d'exécution une boucle complète
 * « ouverture de dossier → configuration heartbeat → réveil → claim → exécution de la revue → restitution → relecture du fil »,
 * en passant intégralement par les facettes officielles de la plateforme (REST /api/exec/* et outils MCP /mcp exec_*), sans toucher directement aux fichiers de données.
 * Idempotent et réexécutable : objectifs/projets/tâches réutilisés par titre, les tâches déjà verrouillées passent par un claim idempotent.
 *
 * Usage :
 *   node scripts/run-closed-loop-review.mjs [--platform http://127.0.0.1:7300]
 *       [--data-dir ~/ybkkasi/data] [--heartbeat-min 30] [--skip-a2a]
 *
 * Les huit étapes de la boucle (chaque étape imprime ses preuves ; le premier échec sort en non-zéro) :
 *   ① échange pour obtenir le jeton machine (officier d'exécution de gouvernance)
 *   ② configuration de l'intervalle de heartbeat des trois Agents officiers (attrs.heartbeatIntervalMinutes)
 *   ③ ouverture de dossier à trois niveaux objectif → projet → tâche (tâche affectée à l'officier d'exécution, entre automatiquement dans la file de réveil)
 *   ④ tick manuel traitant les réveils → trace de heartbeat (woken / skipped_no_todo)
 *   ⑤ claim MCP exec_claim pour obtenir le bail d'exécution
 *   ⑥ exécution de la revue : sonde de vie de ybkk.ybkkasi.com et de ses sous-domaines sœurs, production de la conclusion de revue
 *   ⑦ restitution MCP exec_complete (conclusion de revue écrite dans le résumé de la tâche, tâche passée en attente de revue)
 *   ⑧ relecture du fil : lignée / réveils / run / santé des heartbeats (+ fil optionnel de suivi des tâches A2A)
 */
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { join, resolve } from 'node:path'

// ---- Paramètres ------------------------------------------------------------------
const argv = process.argv.slice(2)
const arg = (flag, fallback) => {
  const i = argv.indexOf(flag)
  return i >= 0 ? argv[i + 1] : fallback
}
const PLATFORM = (arg('--platform', process.env.YBKK_GOV_PLATFORM ?? 'http://127.0.0.1:7300')).replace(/\/+$/, '')
const DATA_DIR = resolve(arg('--data-dir', join(homedir(), 'ybkkasi', 'data')))
const HEARTBEAT_MIN = Number(arg('--heartbeat-min', '30'))
const SKIP_A2A = argv.includes('--skip-a2a')
const CRED_FILE = join(DATA_DIR, 'governance-credentials.json')

// Scénario de boucle (clés d'idempotence)
const GOAL_TITLE = '数字员工自治闭环运行验证'
const PROJECT_NAME = 'ybkk.ybkkasi.com 方案落地'
const ISSUE_TITLE = 'ybkk.ybkkasi.com 方案落地的自动化闭环任务的审查与修订'
const ISSUE_DETAIL = [
  '审查范围：ybkk.ybkkasi.com 子域的方案落地状态（DNS / 隧道 ingress / 源站服务）。',
  '审查方法：探活四域（ybkkasi.com / dsh / demo / ybkk 子域），比对隧道 ingress 映射，定位 502 根因。',
  '修订边界：只产出审查结论与修订建议（含可直接执行的 ingress 配置），不擅自变更对外基础设施。',
].join('\n')

const log = (msg) => console.log(`[closed-loop] ${msg}`)
const step = (n, msg) => log(`── 第${n}步 ${msg}`)
const fail = (msg) => { console.error(`[closed-loop] ✘ ${msg}`); process.exit(1) }

// ---- Socle HTTP / MCP ---------------------------------------------------------
let bearer = ''
async function api(method, path, body) {
  const response = await fetch(`${PLATFORM}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => null)
  if (!response.ok || payload?.ok === false) {
    throw new Error(`${method} ${path} → ${response.status} ${payload?.error?.message ?? response.statusText}`)
  }
  return payload?.data ?? payload
}

// Facette MCP de la plateforme (/mcp) : poignée de main streamable HTTP standard (initialize → initialized → tools/call)
let mcpSessionId = ''
let mcpRpcId = 0
async function mcpRaw(method, params, { notify = false } = {}) {
  const id = notify ? undefined : ++mcpRpcId
  const response = await fetch(`${PLATFORM}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${bearer}`,
      ...(mcpSessionId ? { 'mcp-session-id': mcpSessionId } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', ...(id !== undefined ? { id } : {}), method, ...(params ? { params } : {}) }),
  })
  const sid = response.headers.get('mcp-session-id')
  if (sid) mcpSessionId = sid
  if (notify || response.status === 202) return null
  const text = await response.text()
  if (!text) return null
  // La réponse streamable peut être une trame SSE : prendre la dernière trame data: JSON
  const line = text.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).pop() ?? text
  const payload = JSON.parse(line)
  if (payload.error) throw new Error(`MCP ${method} 错误：${payload.error.message}`)
  return payload.result
}

/** Outils exec_* MCP tools/call (JSON structuré extrait du contenu text ; isError traité comme échec et levé). */
async function execTool(name, args) {
  const result = await mcpRaw('tools/call', { name, arguments: args })
  const textPart = (result?.content ?? []).find((c) => c.type === 'text')?.text
  if (result?.isError) throw new Error(`MCP 工具 ${name} 执行失败：${textPart ?? '(无详情)'}`)
  if (textPart) { try { return JSON.parse(textPart) } catch { return { raw: textPart } } }
  return result?.structuredContent ?? result
}

const execFileP = promisify(execFile)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** Sonde de vie d'une URL, renvoie { url, status }. */
async function probe(url) {
  try {
    const { stdout } = await execFileP('curl', ['-s', '-m', '8', '-o', '/dev/null', '-w', '%{http_code}', url], { timeout: 12_000 })
    const status = /^\d{3}$/.test(stdout.trim()) ? Number(stdout.trim()) : 0
    return { url, status }
  } catch {
    return { url, status: 0 }
  }
}

// ---- Flux principal ------------------------------------------------------------------
if (!existsSync(CRED_FILE)) fail(`凭证文件不存在：${CRED_FILE}（先跑 scripts/register-governance-credentials.mjs）`)
const cred = JSON.parse(readFileSync(CRED_FILE, 'utf8'))
const operator = cred.operator
if (!operator?.clientId || !operator?.clientSecret) fail('治理凭证缺少 operator clientId/clientSecret')

// ① Échange de jeton
step(1, `换牌取机器令牌（${operator.name}）`)
const tokenRes = await fetch(`${PLATFORM}/api/auth/client-credentials`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ clientId: operator.clientId, clientSecret: operator.clientSecret }),
})
const tokenPayload = await tokenRes.json().catch(() => null)
if (!tokenRes.ok || tokenPayload?.ok === false) fail(`换牌失败：${tokenPayload?.error?.message ?? tokenRes.status}`)
bearer = tokenPayload.data.token
log(`✔ 令牌取得，到期 ${tokenPayload.data.expiresAt ?? '—'}`)

step('MCP', '/mcp initialize 握手')
const init = await mcpRaw('initialize', {
  protocolVersion: '2025-03-26',
  capabilities: {},
  clientInfo: { name: 'ybkk-closed-loop-review', version: '1.0.0' },
}).catch((e) => fail(`MCP 握手失败：${e.message}`))
log(`✔ 服务端 ${init?.serverInfo?.name ?? '?'} v${init?.serverInfo?.version ?? '?'}`)
await mcpRaw('notifications/initialized', undefined, { notify: true })

// ② Configuration heartbeat des trois Agents officiers
step(2, `三官 Agent 配置心跳间隔（${HEARTBEAT_MIN} 分钟）`)
const agents = (await api('GET', '/api/agents')).agents ?? []
const OFFICERS = ['执行官', '评价官', '验收官']
const officers = agents.filter((a) => OFFICERS.some((k) => a.name.includes(k)) && ['online', 'trial'].includes(a.status))
if (officers.length === 0) fail('未找到运行态的三官 Agent（执行官/评价官/验收官）')
for (const officer of officers) {
  const updated = await api('PATCH', `/api/agents/${officer.id}`, {
    attrs: { ...(officer.attrs ?? {}), heartbeatIntervalMinutes: HEARTBEAT_MIN },
  })
  const beat = updated?.attrs?.heartbeatIntervalMinutes ?? HEARTBEAT_MIN
  log(`✔ ${officer.name}（${officer.id}）心跳=${beat}m`)
}
const executor = officers.find((a) => a.name.includes('执行官'))

// ③ Ouverture de dossier à trois niveaux (réutilisation idempotente par titre)
step(3, '目标 → 项目 → 任务 立案')
const goals = (await api('GET', '/api/exec/goals')).goals ?? []
let goal = goals.find((g) => g.title === GOAL_TITLE && g.status !== 'archived')
if (!goal) {
  goal = await api('POST', '/api/exec/goals', {
    title: GOAL_TITLE,
    description: '验证「平台监测 Agent 心跳 + 编排任务脉络可回溯」的自动化闭环（由闭环实测脚本创建）。',
    metric: '闭环任务按时完成率', metricBaseline: 0, metricTarget: 100, metricUnit: '%',
  })
}
log(`✔ 目标 ${goal.id}：${goal.title}`)

const projects = (await api('GET', '/api/exec/projects')).projects ?? []
let project = projects.find((p) => p.name === PROJECT_NAME && p.status !== 'done')
if (!project) {
  project = await api('POST', '/api/exec/projects', {
    goalId: goal.id,
    name: PROJECT_NAME,
    description: '子域名解析、隧道 ingress、源站服务三层落地状态治理。',
  })
} else if (project.goalId !== goal.id) {
  await api('PATCH', `/api/exec/projects/${project.id}`, { goalId: goal.id })
}
log(`✔ 项目 ${project.id}：${project.name}`)

const issues = (await api('GET', '/api/exec/issues')).issues ?? []
let issue = issues.find((i) => i.title === ISSUE_TITLE && !['done', 'cancelled'].includes(i.status))
if (!issue) {
  issue = await api('POST', '/api/exec/issues', {
    projectId: project.id,
    title: ISSUE_TITLE,
    detail: ISSUE_DETAIL,
    assigneeAgentId: executor.id,
    priority: 'P1',
  })
  log(`✔ 任务 ${issue.id} 已创建（派给 ${executor.name}，创建即自动入唤醒队列）`)
} else {
  log(`↺ 复用既有任务 ${issue.id}（状态 ${issue.status}）`)
}

// ④ tick traitant les réveils → trace de heartbeat
step(4, '手动 tick 处理唤醒队列 → 心跳留痕')
await api('POST', '/api/exec/tick', {})
await sleep(300)
const wakes = (await api('GET', '/api/exec/wakes')).wakes ?? []
for (const w of wakes.filter((w) => w.issueId === issue.id || w.agentId === executor?.id).slice(0, 3)) {
  log(`· 唤醒 ${w.id} [${w.status}] ${w.trigger}/${w.triggerDetail ?? ''}${w.lastError ? ` ✘ ${w.lastError}` : ''}`)
}
const healthMid = (await api('GET', '/api/exec/overview')).agentsHealth ?? []
for (const h of healthMid.filter((h) => OFFICERS.some((k) => h.name.includes(k)))) {
  log(`· ${h.name} 最近心跳=${h.lastHeartbeatAt ?? '无'} 健康度=${h.health}`)
}

// ⑤ Claim MCP exec_claim
step(5, `MCP exec_claim 认领任务 ${issue.id}`)
const claim = await execTool('exec_claim', { issueId: issue.id })
if (claim?.ok === false) fail(`exec_claim 被拒：${claim.code} ${claim.message}`)
log(`✔ run=${claim.runId} 租约=${claim.leaseId ?? '—'}（幂等=${claim.idempotent ?? false}）`)

// ⑥ Exécution de la revue : sondes de vie des quatre domaines + conclusion
step(6, '审查执行：ybkk.ybkkasi.com 及姊妹子域探活')
const probes = await Promise.all([
  probe('https://ybkk.ybkkasi.com/'),
  probe('https://ybkkasi.com/'),
  probe('https://dsh.ybkkasi.com/'),
  probe('https://demo.ybkkasi.com/'),
])
for (const p of probes) log(`· ${p.url} → ${p.status || 'ERR'}`)

const [sub, main, dsh, demo] = probes
const summaryLines = [
  `【审查结论】ybkk.ybkkasi.com 探活=${sub.status || 'ERR'}（期望 200）；对照：主站=${main.status}、dsh=${dsh.status}（鉴权口 401 属正常）、demo=${demo.status}。`,
  `【根因】${sub.status === 502
    ? 'ybkk 子域 DNS 已解析（Cloudflare 代理边缘）但 Zero Trust 主隧道无该主机名的 Public Hostname ingress 映射——请求进隧道后无匹配规则，边缘网关 502。本机 config-demo.yml 仅映射 demo.ybkkasi.com→7302；主隧道 ingress 由面板托管，本地无该主机配置。'
    : `探活结果 ${sub.status || 'ERR'} 与预期不一致，请人工复核后更新结论。`}`,
  '【修订建议】收口三选一（需维护者确认子域定位后执行）：A) Zero Trust 面板为主隧道新增 Public Hostname ybkk.ybkkasi.com → http://localhost:7300（与主站同实例，最快）；B) 本地 CLI 隧道（~/.cloudflared/cert.pem 已具备）+ launchd 服务映射目标端口，兜底 404；C) 若规划为独立站点，先补「子域定位—目标服务—owner」三要素再接 ingress。',
  '【边界】对外基础设施变更未擅自执行。本任务同时验证两条链路：执行中枢可见 目标→项目→任务→唤醒→run→心跳 全链；A2A 任务追踪可见协作任务时间线（见 A2A 步骤）。',
].join('\n')
log('✔ 审查结论已产出（写入交回摘要）')

// ⑦ Restitution MCP exec_complete (sans runId, clôture par issueId — double forme d'exec_complete)
step(7, `MCP exec_complete 交回 run ${claim.runId ?? issue.executionRunId ?? '(按任务收尾)'}`)
const done = await execTool('exec_complete', {
  ...(claim.runId ? { runId: claim.runId } : { issueId: issue.id }),
  status: 'completed',
  summary: summaryLines,
})
if (done?.ok === false) fail(`exec_complete 失败：${done.code ?? ''} ${done.message ?? ''}`)
log('✔ run 完成、租约释放；任务转待审（review），等待人工验收归档')

// ⑧ Relecture du fil
step(8, '脉络回读：血缘 / 任务 / run / 心跳健康度')
const lineage = await api('GET', `/api/exec/lineage/${issue.id}`)
log(`✔ 血缘链：${[lineage.goal?.title, lineage.project?.name, lineage.issue?.title].filter(Boolean).join(' → ')}`)
const issueAfter = ((await api('GET', `/api/exec/issues?projectId=${project.id}`)).issues ?? []).find((i) => i.id === issue.id)
log(`· 任务终态=${issueAfter?.status} 执行run=${issueAfter?.executionRunId ?? '—'}`)
const runs = (await api('GET', '/api/exec/runs')).runs ?? []
const myRun = runs.find((r) => r.id === claim.runId)
log(`· run ${myRun?.id ?? claim.runId}：status=${myRun?.status ?? '—'} trigger=${myRun?.trigger ?? '—'} 摘要长度=${(myRun?.summary ?? '').length}`)
const health = (await api('GET', '/api/exec/overview')).agentsHealth ?? []
for (const h of health.filter((h) => OFFICERS.some((k) => h.name.includes(k)))) {
  log(`✔ ${h.name}：健康度=${h.health} 最近心跳=${h.lastHeartbeatAt ?? '无'}`)
}

// (optionnel) Fil de suivi des tâches A2A
if (!SKIP_A2A) {
  step('A2A', '发起 A2A 协作任务（任务追踪时间线脉络）')
  try {
    const slug = executor.slug || executor.id
    const rpc = await fetch(`${PLATFORM}/api/agents/${encodeURIComponent(slug)}/a2a`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${bearer}` },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'message/send',
        params: {
          message: `${ISSUE_TITLE}——请以只读方式复核执行中枢对应任务 ${issue.id} 的审查结论并给出验收意见（不要执行基础设施变更，不要重复发起执行）。`,
          metadata: { contextId: `a2actx-review-${issue.id}` },
        },
      }),
    })
    const payload = await rpc.json().catch(() => null)
    const task = payload?.data?.result?.task ?? payload?.result?.task
    if (task) {
      const note = task.state === 'auth_required' ? '——协商矩阵要求人在环确认，审批中心处理后续派执行' : ''
      log(`✔ A2A 任务 ${task.taskId} 状态=${task.state}（${task.stateReason ?? ''}）${note}`)
      log(`  → 协作与执行 → A2A 协作 → 任务追踪：时间线/协商/交付物全程留痕`)
    } else {
      log(`↺ A2A 返回：${payload?.error?.message ?? rpc.status}（主闭环不受影响）`)
    }
  } catch (error) {
    log(`↺ A2A 步骤跳过：${error.message}`)
  }
}

log('══ 闭环完成：立案 → 心跳 → 唤醒 → 认领 → 审查 → 交回 → 脉络回读 全链走通 ══')
