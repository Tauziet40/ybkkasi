#!/usr/bin/env node
/**
 * refresh-governance-mcp-tokens.mjs — auto-réparation par rafraîchissement des jetons MCP des deux identités de gouvernance (côté DSH).
 *
 * Contexte : les jetons machine de la plateforme (échange client-credentials) valent 2 heures (TTL fixé par authn.verify),
 * le client stocke un Bearer statique qui échoue dès expiration. DSH ne se renouvelle pas tout seul, d'où un rafraîchissement proactif nécessaire.
 *
 * Ce script fait quatre choses (idempotent, réexécutable) :
 *   ① lit ~/.ybkkasi/../ybkkasi/data/governance-credentials.json pour clientId/clientSecret (secret non tourné)
 *   ② via POST /api/auth/client-credentials, échange un nouveau jeton pour operator / reviewer
 *   ③ via l'API HTTP du connecteur DSH (POST http://127.0.0.1:7777/mcp-connector/api, method=configure)
 *      réécrit le nouveau jeton dans la connexion DSH et reconstruit le client MCP (effectif immédiatement côté DSH après reconstruction, sans redémarrer l'hôte)
 *   ④ contre-vérification d'écriture (anti-faux-vert, 2026-10-28) : relit le stockage DSH, assertion dure que updatedAt des deux connexions date
 *      de ≤ --max-staleness-min (défaut 120) et que le jeton stocké n'est pas expiré — si le connecteur
 *      « répond ok sans persister », le script sort en non-zéro et le job gov-token GT-01 n'est plus masqué par un faux vert
 *
 * Sortie d'alerte d'échec (anti-silence, 2026-10-28 ; toute la chaîne ne dépend que des capacités plateforme et du socle DSH, aucun webhook externe) :
 *   couche script (local au socle DSH, valable même quand la plateforme est injoignable) :
 *     · append d'une ligne JSONL dans <data-dir>/governance-refresh-alerts.jsonl (le job org daily D-GOV-ALERTS comptera un échec dur dans le résumé du jour)
 *     · notification locale macOS (osascript display notification ; le domaine launchd gui peut l'afficher directement)
 *   couche job (visible plateforme, porté par org/automation/jobs/gov-token.mjs) : sur déclenchement au bord d'un échec dur, envoie un artefact d'alerte au panneau du service R&D plateforme,
 *     visible immédiatement dans le panneau console ; l'extrusion vers le groupe DingTalk est prise en charge par le pont DingTalk plateforme (identifiants de l'app d'entreprise côté plateforme), zéro config locale.
 *
 * N'imprime aucun secret/jeton en clair, ne rapporte que l'échéance.
 *
 * Usage :
 *   node scripts/refresh-governance-mcp-tokens.mjs [--data-dir <dir>] [--dsh-url http://127.0.0.1:7777]
 *       [--skip-if-fresh] [--fresh-window-min 90] [--force]
 *
 *   --skip-if-fresh   n'échange et ne reconstruit que si la durée de vie restante du jeton stocké dans DSH est < fresh-window-min (pour les minuteurs, évite les reconstructions inutiles)
 *                     fenêtre passée de 30 à 90 le 2026-10-28 : avec un TTL de 120 min + inspection horaire, une seule occurrence manquée
 *                     de déclenchement horaire suffit à expirer le jeton ; 90 minutes garantit qu'aucun manquement isolé ne coupe (coût : une reconstruction de connexion par heure)
 *   --force           rafraîchissement inconditionnel (ignore le jugement de fraîcheur)
 *   --max-staleness-min  staleness maximale d'updatedAt admise par la contre-vérification d'écriture (défaut 120 min ; chemin skip, jeton frais ⇒ forcément ≤ 30 min)
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { execFileSync } from 'node:child_process'

const argv = process.argv.slice(2)
const arg = (flag, fallback) => {
  const i = argv.indexOf(flag)
  return i >= 0 ? argv[i + 1] : fallback
}
const PLATFORM_URL = (arg('--platform-url', process.env.YBKK_GOV_PLATFORM ?? 'https://ybkkasi.com')).replace(/\/+$/, '')
const DSH_URL = (arg('--dsh-url', process.env.DSH_WEB_URL ?? 'http://127.0.0.1:7777')).replace(/\/+$/, '')
const DATA_DIR = resolve(arg('--data-dir', join(homedir(), 'ybkkasi', 'data')))
const CRED_FILE = join(DATA_DIR, 'governance-credentials.json')
const DSH_STORE = resolve(arg('--dsh-store', join(homedir(), '.dsh', 'storages', 'mcp_connector.json')))
const SKIP_IF_FRESH = argv.includes('--skip-if-fresh')
const FORCE = argv.includes('--force')
const FRESH_WINDOW_MIN = Number(arg('--fresh-window-min', '90'))
const MAX_STALENESS_MIN = Number(arg('--max-staleness-min', '120'))
const ALERTS_FILE = join(DATA_DIR, 'governance-refresh-alerts.jsonl')

const log = (msg) => console.log(`[gov-refresh] ${msg}`)

/**
 * Sortie d'alerte d'échec dur (couche script ; tout échec ne masque pas l'erreur d'origine ni le code de sortie ; valable même plateforme injoignable) :
 *   ① écriture JSONL (consommée par le job org daily D-GOV-ALERTS, entre dans l'échec dur du résumé du jour)
 *   ② notification locale macOS (machine hébergeant le socle DSH ; osascript display notification, domaine launchd gui affiche directement)
 * L'alerte panneau visible côté plateforme est poussée par le job org gov-token au bord d'une sortie non-zéro de ce script (voir en-tête du fichier).
 */
const alert = async (msg) => {
  try {
    mkdirSync(DATA_DIR, { recursive: true })
    appendFileSync(ALERTS_FILE, JSON.stringify({ at: new Date().toISOString(), platform: PLATFORM_URL, error: String(msg).slice(0, 300) }) + '\n')
  } catch { /* ① un échec d'écriture ne masque pas l'erreur d'origine */ }
  if (process.platform === 'darwin') {
    try {
      execFileSync('osascript', ['-e', `display notification ${JSON.stringify(String(msg).slice(0, 200))} with title "gov-refresh 治理令牌刷新失败" sound name "Basso"`], { stdio: 'ignore', timeout: 5000 })
    } catch { /* ② notification locale indisponible (pas de session GUI etc.) → saut */ }
  }
}
const fail = async (msg) => { console.error(`[gov-refresh] ✘ ${msg}`); await alert(msg); process.exit(1) }

if (!existsSync(CRED_FILE)) await fail(`凭证文件不存在：${CRED_FILE}（先跑 scripts/register-governance-credentials.mjs）`)
const cred = JSON.parse(readFileSync(CRED_FILE, 'utf8'))

/** Échange un jeton machine (client-credentials). Les anomalies réseau passent aussi par la sortie d'alerte. */
const exchange = async (entry, label) => {
  let response
  let payload = null
  try {
    response = await fetch(`${PLATFORM_URL}/api/auth/client-credentials`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: entry.clientId, clientSecret: entry.clientSecret }),
    })
    payload = await response.json().catch(() => null)
  } catch (e) {
    await fail(`${label} 换牌请求失败：${e.cause?.code ?? e.message}`)
  }
  if (!response.ok || payload?.ok === false) await fail(`${label} 换牌失败：${payload?.error?.message ?? response.status}`)
  return payload.data
}

/** Met à jour la connexion via l'API connecteur DSH et reconstruit le client. Les anomalies réseau passent aussi par la sortie d'alerte. */
const configure = async (params, label) => {
  let response
  let payload = null
  try {
    response = await fetch(`${DSH_URL}/mcp-connector/api`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method: 'configure', params }),
    })
    payload = await response.json().catch(() => null)
  } catch (e) {
    await fail(`${label} 连接器请求失败：${e.cause?.code ?? e.message}`)
  }
  if (!response.ok || payload?.ok === false) await fail(`${label} 配置失败：${payload?.message ?? response.status}`)
  return payload
}

const targets = [
  { key: 'operator', serverName: 'ybkk-governance', label: 'ybkk-governance（执行官）', dshKey: 'custom-ybkk-governance' },
  { key: 'reviewer', serverName: 'ybkk-governance-review', label: 'ybkk-governance-review（评审官）', dshKey: 'custom-ybkk-governance-review' },
]

/** Lit le jeton configuré dans le stockage de connexions DSH et calcule la durée de vie restante (minutes). Renvoie null si illisible (traité comme « pas frais »). */
const storedTokenTtlMin = (dshKey) => {
  try {
    if (!existsSync(DSH_STORE)) return null
    const store = JSON.parse(readFileSync(DSH_STORE, 'utf8'))
    const token = store?.tables?.connections?.[dshKey]?.auth?.bearerToken
    if (!token) return null
    const payload = JSON.parse(Buffer.from(String(token).split('.')[1] ?? '', 'base64url').toString('utf8'))
    if (!payload?.exp) return null
    return (payload.exp * 1000 - Date.now()) / 60000
  } catch {
    return null
  }
}

let refreshed = 0
let skipped = 0
for (const target of targets) {
  const entry = cred[target.key]
  if (!entry?.clientId) await fail(`凭证文件缺少 ${target.key} 条目`)

  if (SKIP_IF_FRESH && !FORCE) {
    const ttl = storedTokenTtlMin(target.dshKey)
    if (ttl !== null && ttl > FRESH_WINDOW_MIN) {
      log(`${target.label}：令牌仍新鲜（剩余约 ${Math.round(ttl)} 分钟 > ${FRESH_WINDOW_MIN} 分钟），跳过重建`)
      skipped += 1
      continue
    }
  }

  const issued = await exchange(entry, target.label)
  await configure({
    name: target.serverName,
    serverName: target.serverName,
    transport: 'streamable-http',
    url: `${PLATFORM_URL}/mcp`,
    authMode: 'bearer',
    bearerToken: issued.token,
    scope: 'global',
  }, target.label)
  log(`${target.label}：已刷新并重建（到期 ${issued.expiresAt}）`)
  refreshed += 1
}

log(`完成：刷新 ${refreshed} 条、跳过 ${skipped} 条（secret 未轮换，无需重新登记）`)

// ---- ④ Contre-vérification d'écriture (anti-faux-vert) : « le connecteur répond ok » ne vaut pas « écriture réussie ». Relit le stockage et affirme dur :
//      les deux connexions existent, updatedAt ≤ MAX_STALENESS_MIN, jeton stocké non expiré. Un seul manquement = sortie non-zéro.
const readStore = () => {
  try { return JSON.parse(readFileSync(DSH_STORE, 'utf8')) } catch { return null }
}
const store = readStore()
const stale = []
for (const target of targets) {
  const conn = store?.tables?.connections?.[target.dshKey]
  if (!conn) { stale.push(`${target.label}：DSH 存储中连接不存在`); continue }
  const updatedAgoMin = conn.updatedAt ? (Date.now() - Number(conn.updatedAt)) / 60000 : null
  if (updatedAgoMin === null || !Number.isFinite(updatedAgoMin) || updatedAgoMin > MAX_STALENESS_MIN) {
    stale.push(`${target.label}：updatedAt 距今 ${updatedAgoMin === null || !Number.isFinite(updatedAgoMin) ? '未知' : `${Math.round(updatedAgoMin)} 分钟`}（> ${MAX_STALENESS_MIN}）`)
    continue
  }
  const ttl = storedTokenTtlMin(target.dshKey)
  if (ttl === null || ttl <= 0) stale.push(`${target.label}：存储令牌缺失或已过期`)
}
if (stale.length) await fail(`写回核验失败（防假绿）：${stale.join('；')}`)
log(`写回核验：${targets.length} 条连接 updatedAt ≤ ${MAX_STALENESS_MIN} 分钟且令牌未过期`)
