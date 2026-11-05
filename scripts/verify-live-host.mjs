/**
 * Script de vérification d'authenticité de la plateforme hôte en ligne (review-dsh-agent-panel-v2 branchement hôte · côté exploitation en une étape).
 *
 * Contexte : les tests d'authenticité de la facette d'authentification panneau/pont exigent les identifiants administrateur de la plateforme hôte (les mots de passe de démo ont été tournés selon la liste de déploiement,
 * aucun vrai mot de passe n'est stocké dans le dépôt — voir la discipline d'identifiants de docs/deploy-enterprise.md). Ce script est exécuté par l'exploitation dans un environnement détenant
 * les identifiants, et vérifie un à un :
 *   1. santé et connexion (DSHCTL_USER/DSHCTL_PASS ou DSHCTL_TOKEN)
 *   2. configuration réelle du connecteur DingTalk et « health check du vrai OpenAPI DingTalk » (POST /api/iam/connectors/:id/test,
 *      tire un vrai accessToken et l'arbre des départements avec le vrai appKey/appSecret de la mémoire de l'hôte — les identifiants ne quittent pas l'hôte)
 *   3. inventaire des actifs réels : employés numériques (Agent)/applications/Skill/MCP/NAS + taille du registre de tout le personnel (source de données réelle
 *      des liaisons organisationnelles du panneau et des liaisons agentRef)
 *   4. contrôle de préparation côté panneau : /rq/panel/ joignable (forme montée hôte), cinq départements /api/panel/depts, trois états sectoriels
 *
 * Usage :
 *   DSHCTL_URL=http://192.168.0.7:7300 DSHCTL_USER=admin DSHCTL_PASS='***' node scripts/verify-live-host.mjs
 *   (ou DSHCTL_TOKEN=<jeton existant> pour sauter l'étape de connexion)
 */
const BASE = (process.env.DSHCTL_URL ?? 'http://127.0.0.1:7300').replace(/\/+$/, '')
const USER = process.env.DSHCTL_USER
const PASS = process.env.DSHCTL_PASS
const TOKEN = process.env.DSHCTL_TOKEN

let token = TOKEN
async function api(method, path, body) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => null)
  return { status: response.status, ok: payload?.ok ?? false, data: payload?.data, error: payload?.error }
}

const results = []
const check = (name, pass, detail = '') => {
  results.push(pass)
  console.log(`  ${pass ? '✔' : '✘'} ${name}${pass || !detail ? '' : `  ← ${detail}`}`)
}

console.log(`» 验证目标：${BASE}`)
const health = await api('GET', '/api/health')
check('健康检查', health.ok, JSON.stringify(health.error))

if (!token) {
  if (!USER || !PASS) {
    console.error('缺少凭据：设 DSHCTL_USER/DSHCTL_PASS（或 DSHCTL_TOKEN）后重试')
    process.exit(1)
  }
  const login = await api('POST', '/api/auth/login', { username: USER, password: PASS })
  check(`登录（${USER}）`, login.ok, JSON.stringify(login.error))
  token = login.data?.token
}

// 1. Connecteur DingTalk : configuration réelle + health check du vrai OpenAPI DingTalk (les identifiants ne quittent pas l'hôte)
const connectors = await api('GET', '/api/iam/connectors')
const dingtalkConfigs = (connectors.data?.configs ?? []).filter((config) => config.provider === 'dingtalk')
check(`钉钉连接器配置在案（${dingtalkConfigs.length} 个主体）`,
  dingtalkConfigs.length >= 1,
  JSON.stringify(connectors.error ?? connectors.data?.configs?.map((config) => config.corpId)))
for (const config of dingtalkConfigs) {
  const test = await api('POST', `/api/iam/connectors/${config.id}/test`)
  check(`真钉钉健康检查：${config.name ?? config.corpId}（mode=${config.mode}）`,
    test.ok && test.data?.ok === true,
    JSON.stringify(test.error ?? test.data?.message))
}

// 2. Inventaire des actifs réels (source de données des agentRef/liaisons organisationnelles du panneau)
const agents = await api('GET', '/api/agents')
const agentRows = agents.data?.agents ?? agents.data ?? []
check(`数字员工（Agent 资产）：${agentRows.length} 个`, agentRows.length >= 1, JSON.stringify(agents.error))
console.log('    ' + agentRows.slice(0, 10).map((agent) => `${agent.name}[${agent.status}]`).join(' | '))
const apps = await api('GET', '/api/apps')
check(`AI 应用：${(apps.data?.apps ?? apps.data ?? []).length} 个`, apps.ok, JSON.stringify(apps.error))
const skills = await api('GET', '/api/skills')
check(`Skill 市场：${(skills.data?.skills ?? []).length} 个`, skills.ok, JSON.stringify(skills.error))
const roster = await api('GET', '/api/iam/roster')
check(`全员名册：${roster.data?.users?.length ?? 0} 人 / ${roster.data?.orgs?.length ?? 0} 组织（面板部门绑定与成员名册的真实源）`,
  roster.ok, JSON.stringify(roster.error))

// 3. Préparation côté panneau (après déploiement de cette branche ; forme autonome /panel/, forme montée hôte dsh /rq/panel/)
const panelStatic = await fetch(`${BASE}/panel/`).then((r) => r.status).catch(() => 0)
const panelStaticRq = panelStatic === 200 ? 200 : await fetch(`${BASE}/rq/panel/`).then((r) => r.status).catch(() => 0)
check('/panel/（或 /rq/panel/）面板 SPA 可达', panelStaticRq === 200, `status=${panelStatic}/${panelStaticRq}`)
const depts = await api('GET', '/api/panel/depts')
check(`面板五部门骨架（${(depts.data?.depts ?? []).length} 个）`, depts.ok && depts.data.depts.length === 5, JSON.stringify(depts.error))
const industries = await api('GET', '/api/panel/industries')
check(`行业三态（${(industries.data?.industries ?? []).filter((ind) => ind.state === 'active').length} 已激活）`, industries.ok, JSON.stringify(industries.error))

const failed = results.filter((pass) => !pass).length
console.log(`\n验证结果：${results.length - failed}/${results.length} 通过`)
process.exit(failed > 0 ? 1 : 0)
