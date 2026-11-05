#!/usr/bin/env node
/**
 * Montage en un clic de la « remontée quotidienne de métriques opérationnelles » des trois officiers Officer + reconfiguration des identifiants WeKnora (idempotent, réexécutable).
 *
 * Contexte (2026-11-02) : les remontées proactives de métriques des officiers d'exécution/évaluation/réception se sont arrêtées au 28-29/10, ne laissant ensuite
 * que les enregistrements d'observation réinjectés par la passerelle (sans dau/uniqueUsers). Ce script fait des « auto-déclarations dau/sessions/uniqueUsers »
 * l'agenda fixe des trois officiers via les réveils quotidiens de routine du centre d'exécution + les tâches cycliques quotidiennes.
 *
 * Usage (jeton administrateur généré depuis la page « Mes accès » de la console, ou via dshctl credential) :
 *   DSHCTL_URL=http://127.0.0.1:7300 DSHCTL_TOKEN=dst1.xxx node scripts/onboard-officer-reporting.mjs [--dry-run] [--weknora-key=<nouvelle clé>]
 *
 * Actions (idempotent par nom) :
 *   1. pour chaque officier, créer/réutiliser la routine cron « remontée quotidienne de métriques opérationnelles » (0 1 * * * UTC = 09:00 Pékin ; exec-hub compare en UTC)
 *   2. pour chaque officier, créer/réutiliser la tâche cyclique quotidienne (texte d'instruction dans le paquet de contexte : appeler metrics-report en auto-déclaration dau/sessions/uniqueUsers)
 *   3. vérifier puis compléter exec.read / exec.write dans les scopes du sujet machine des trois officiers (précondition de survie/claim des réveils de routine)
 *   4. mettre attrs heartbeatIntervalMinutes=30 pour les trois officiers (maintien en vie + probabilité de claim accrue ; attrs fusionnés réécrits en intégralité)
 *   5. --weknora-key=<nouvelle clé> : reconfigurer la clé de chemin d'endpoint du service weknora-knowledge et déclencher une contre-vérification de sonde de vie
 *      (la clé API du MCP WeKnora est dans le segment de chemin de l'URL ; un 403 amont = clé invalidée, à ré-émettre depuis la console WeKnora)
 */
import process from 'node:process'

const BASE = (process.env.DSHCTL_URL ?? 'http://127.0.0.1:7300').replace(/\/+$/, '')
const TOKEN = process.env.DSHCTL_TOKEN ?? ''
const args = process.argv.slice(2)
const DRY_RUN = args.includes('--dry-run')
const weknoraKey = args.find((item) => item.startsWith('--weknora-key='))?.split('=')[1] ?? ''

if (!TOKEN) {
  console.error('缺少 DSHCTL_TOKEN（管理员令牌）。控制台「我的接入」页可自助生成。')
  process.exit(1)
}

async function call(method, path, body) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let payload = null
  try { payload = await response.json() } catch { /* ignore */ }
  if (response.status === 401) {
    console.error('令牌无效或已过期（401）——请在控制台「我的接入」页重新生成管理员令牌后重试。')
    process.exit(1)
  }
  if (!payload?.ok) {
    throw new Error(`${method} ${path} → ${response.status}: ${payload?.error?.message ?? response.statusText}`)
  }
  return payload.data
}

const ROUTINE_NAME = '每日运营指标提报'
const ISSUE_TITLE = '每日运营指标提报（例行）'
const CRON_UTC_0900_CST = '0 1 * * *'
const REPORT_HINT = [
  '每日例行：提报你今日的运营指标（平台接入义务）。',
  '调用 POST /api/agents/<你的agt_id>/metrics-report，body {"dau":<今日活跃用户数>,"sessions":<今日会话数>,"uniqueUsers":<去重用户数>}；',
  '或经 /mcp 工具面调用 agent_metrics_report 工具（参数同名）。同日重复提报安全（dau 取最大、sessions 累加），可带 date 补录。',
  '无用户交互的执行体如实报 dau=1（你自己）即可，不要编造数字。',
].join('\n')

const summary = []
const note = (message) => { summary.push(message); console.log(`  · ${message}`) }

// —— Localisation des trois officiers (Agents en ligne dont le nom contient Officer) ——
const agentsData = await call('GET', '/api/agents')
const officers = agentsData.agents.filter((agent) => agent.name.includes('Officer') && agent.status === 'online')
if (officers.length === 0) {
  console.error('未找到在线的 Officer Agent（名字含 Officer 且 status=online）——先完成三官注册与上线。')
  process.exit(1)
}
console.log(`定位到 ${officers.length} 个 Officer：${officers.map((agent) => agent.name).join('、')}`)

const routinesData = await call('GET', '/api/exec/routines')
const issuesData = await call('GET', '/api/exec/issues')
const principalsData = await call('GET', '/api/authn/principals')

for (const officer of officers) {
  console.log(`\n■ ${officer.name}（${officer.id}）`)

  // 1) Routine quotidienne (idempotent par agentId+nom)
  const existingRoutine = routinesData.routines?.find((row) => row.agentId === officer.id && row.name === ROUTINE_NAME)
  if (existingRoutine) {
    note(`例行已存在（#${existingRoutine.id}，cron=${existingRoutine.cron}，enabled=${existingRoutine.enabled !== false}）——跳过`)
  } else if (DRY_RUN) {
    note(`[dry-run] 将建例行「${ROUTINE_NAME}」cron=${CRON_UTC_0900_CST}（北京 09:00）`)
  } else {
    await call('POST', '/api/exec/routines', { agentId: officer.id, name: ROUTINE_NAME, kind: 'cron', cron: CRON_UTC_0900_CST, payload: { hint: REPORT_HINT } })
    note(`例行已创建「${ROUTINE_NAME}」（每日北京 09:00 唤醒）`)
  }

  // 2) Tâche cyclique quotidienne (texte d'instruction dans le paquet de contexte ; idempotent par titre+affectation, historique accompli ignoré)
  const existingIssue = issuesData.issues?.find((row) => row.assigneeAgentId === officer.id && row.title === ISSUE_TITLE && row.status !== 'done' && row.status !== 'archived')
  if (existingIssue) {
    note(`循环任务已存在（#${existingIssue.id}，status=${existingIssue.status}）——跳过`)
  } else if (DRY_RUN) {
    note(`[dry-run] 将建循环任务「${ISSUE_TITLE}」（指令文本进上下文包）`)
  } else {
    await call('POST', '/api/exec/issues', { title: ISSUE_TITLE, detail: REPORT_HINT, assigneeAgentId: officer.id, priority: 'high' })
    note('循环任务已创建（含 metrics-report 调用指令，认领后进入上下文包）')
  }

  // 3) Complément exec.read / exec.write des scopes du sujet machine (précondition de survie/claim des réveils de routine)
  const principal = principalsData.principals?.find((row) => row.refType === 'agent' && row.refId === officer.id)
  if (!principal) {
    note('⚠ 未找到机器主体（principal）——跳过 scopes 核对（该 Agent 无法认领唤醒）')
  } else {
    const scopes = new Set(principal.scopes ?? [])
    const missing = ['exec.read', 'exec.write'].filter((scope) => !scopes.has(scope) && !scopes.has('*'))
    if (missing.length === 0) {
      note(`scopes 已含 exec.read/exec.write（共 ${principal.scopes.length} 项）——跳过`)
    } else if (DRY_RUN) {
      note(`[dry-run] 将为机器主体补 scopes：${missing.join('/')}`)
    } else {
      for (const scope of missing) scopes.add(scope)
      await call('PATCH', `/api/authn/principals/${principal.id}`, { scopes: [...scopes] })
      note(`机器主体已补 scopes：${missing.join('/')}`)
    }
  }

  // 4) Maintien en vie par heartbeat (attrs fusionnés réécrits en intégralité — PATCH attrs est une sémantique de remplacement complet)
  const attrs = { ...(officer.attrs ?? {}) }
  if (attrs.heartbeatIntervalMinutes === 30) {
    note('心跳已配 30 分钟——跳过')
  } else if (DRY_RUN) {
    note('[dry-run] 将配 attrs.heartbeatIntervalMinutes=30（全量 attrs 合并写回）')
  } else {
    attrs.heartbeatIntervalMinutes = 30
    await call('PATCH', `/api/agents/${officer.id}`, { attrs })
    note('心跳已配 30 分钟（保活 + 唤醒认领概率↑）')
  }
}

// —— 5) Reconfiguration des identifiants WeKnora (optionnel) ——
if (weknoraKey) {
  console.log('\n■ WeKnora 凭据重配')
  const servicesData = await call('GET', '/api/mcp/services')
  const weknora = servicesData.services?.find((service) => service.slug === 'weknora-knowledge')
  if (!weknora) {
    console.error('未找到 weknora-knowledge 服务——先完成纳管。')
    process.exit(1)
  }
  const oldEndpoint = String(weknora.endpoint ?? '')
  // La clé API du MCP WeKnora est dans le segment de chemin de l'URL (/mcp/<key>) : conserver protocole et hôte, remplacer le dernier segment
  const replaced = oldEndpoint.replace(/\/mcp\/[^/?#]+/, `/mcp/${weknoraKey}`)
  if (replaced === oldEndpoint) {
    note(`⚠ endpoint 形态不符合 /mcp/<key>（${oldEndpoint}）——未改动，请人工核对`)
  } else if (DRY_RUN) {
    note(`[dry-run] 将更新 endpoint（新路径密钥 ${weknoraKey.slice(0, 6)}…）并触发探活`)
  } else {
    await call('PATCH', `/api/mcp/services/${weknora.id}`, { endpoint: replaced })
    const verify = await call('POST', `/api/mcp/services/${weknora.id}/verify`, {})
    note(`endpoint 已更新并探活：status=${verify.status ?? verify.health?.status ?? '见控制台'}`)
  }
} else if (!DRY_RUN) {
  console.log('\n（未提供 --weknora-key，跳过 WeKnora 凭据重配——上游 403 时需从 WeKnora 控制台重新签发后带上该参数重跑）')
}

console.log(`\n完成${DRY_RUN ? '（dry-run，未做任何变更）' : ''}：共 ${summary.length} 条动作。`)
