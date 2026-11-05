/**
 * Contrôle de cohérence de la documentation d'intégration : points d'API référencés par docs/*.md ↔ routes enregistrées dans le code (manifestes + sources).
 * Usage : node scripts/check-docs-consistency.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

// QA G-01 : URL.pathname est en encodage pourcent — un répertoire chinois (comme `元冰可产品`) traité directement comme chemin de fichier provoque
// systématiquement ENOENT ; fileURLToPath décode et gère les lettres de lecteur, chemins Windows/non-ASCII corrects dans les deux cas.
const root = fileURLToPath(new URL('..', import.meta.url))
const docFiles = [
  'docs/agent-onboarding.md', 'docs/app-onboarding.md', 'docs/app-sso-integration.md',
  'docs/portal-integration.md', 'docs/connector-integration.md', 'docs/frontend-host-switching.md',
  'docs/host-features-ops-notes.md', 'docs/deploy-enterprise.md', 'docs/nas-authz.md',
  'docs/entry-switching.md', 'docs/panel-implementation.md',
]

// 1. Agrégation des routes côté code : manifests api.yaml + appels register/guarded des sources
const codeRoutes = new Set()
function addRoute(method, path) {
  const norm = String(path).replace(/\/+$/, '')
  if (!norm.startsWith('/')) return
  codeRoutes.add(`${method.toUpperCase()} ${norm}`)
  codeRoutes.add(norm) // pour la correspondance des références sans méthode
}
function walk(dir, cb) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git' || name === 'data-livecheck') continue
    const full = join(dir, name)
    const st = statSync(full)
    if (st.isDirectory()) walk(full, cb)
    else cb(full)
  }
}
walk(join(root, 'packages'), (file) => {
  if (file.endsWith('manifest' + String.fromCharCode(92) + 'api.yaml') || file.endsWith('/manifest/api.yaml') || file.includes('manifest') && file.endsWith('api.yaml')) {
    const text = readFileSync(file, 'utf8')
    for (const m of text.matchAll(/(get|post|put|patch|delete)\s*:\s*\n?\s*([^\s:][^\n]*)?/gi)) { /* structures yaml trop variées, la source fait foi */ }
    for (const m of text.matchAll(/'?(\/api\/[A-Za-z0-9/:_{}.\-]+)'?/g)) addRoute('ANY', m[1])
  }
  if (file.endsWith('.ts')) {
    const text = readFileSync(file, 'utf8')
    for (const m of text.matchAll(/(?:guarded|http\.register)\(\s*'(GET|POST|PUT|PATCH|DELETE|OPTIONS)'\s*,\s*[''`]([^''`]+)[''`]/g)) {
      if (!m[2].startsWith('/')) continue
      if (m[1] === 'OPTIONS') continue
      addRoute(m[1], m[2])
    }
  }
})

// 2. Extraction des références de points d'API de la documentation
// Liste d'exemptions (convention contract-lint.exemptions.json) : références qui ne sont pas des routes plateforme —
// /oauth/callback et /api/connections désignent le propre service du sidecar open-connector (port 3000, hors plateforme),
// /api est une mention de préfixe conceptuel. Après le correctif G-01, ce script tourne intégralement en local pour la première fois et expose ces trois faux positifs historiques.
const DOC_REF_EXEMPTS = new Set(['/oauth/callback', '/api/connections', '/api'])
let missing = [], total = 0
for (const doc of docFiles) {
  const full = join(root, doc)
  let text
  try { text = readFileSync(full, 'utf8') } catch { console.log(`  ⚠ 文档缺失：${doc}`); continue }
  const refs = new Set()
  for (const m of text.matchAll(/(?:GET|POST|PUT|PATCH|DELETE)\s+`?(\/(?:api|oauth|\.well-known|auth|panel|rq)[A-Za-z0-9/:_{}.\-]*)`?/g)) refs.add(m[1])
  for (const m of text.matchAll(/`((?:\/(?:api|oauth|\.well-known|auth|panel)|\{base\}\/api)[A-Za-z0-9/:_{}.\-]*)`/g)) refs.add(m[1])
  for (const ref of refs) {
    if (ref.endsWith('…') || ref.endsWith('…/')) continue
    if (DOC_REF_EXEMPTS.has(ref)) continue
    total++
    const methodMatch = ref.match(/^(GET|POST|PUT|PATCH|DELETE)\s+(.*)/)
    const method = methodMatch ? methodMatch[1] : 'ANY'
    const path = methodMatch ? methodMatch[2] : ref
    const pathNorm = path.replace(/\{[^}]+\}/g, ':x').replace(/:[a-zA-Z]+/g, ':x')
    let hit = false
    for (const route of codeRoutes) {
      const routeNorm = route.replace(/\{[^}]+\}/g, ':x').replace(/:[a-zA-Z]+/g, ':x')
      if (routeNorm === pathNorm || routeNorm === `${method} ${pathNorm}` || routeNorm.endsWith(pathNorm)) { hit = true; break }
      if (routeNorm.includes(':x') && pathNorm.split('/').length === routeNorm.split('/').length) {
        const re = new RegExp('^' + routeNorm.replace(/:x/g, '[^/]+') + '$')
        if (re.test(pathNorm) || re.test(routeNorm)) { hit = true; break }
      }
    }
    // Référence de préfixe (comme /api/portal/, /api/connector/)
    if (!hit && pathNorm.endsWith('/')) {
      for (const route of codeRoutes) { if (route.includes(pathNorm.replace(/\/$/, ''))) { hit = true; break } }
    }
    if (!hit) missing.push(`${doc} → ${ref}`)
  }
}

console.log(`文档端点引用核查：共 ${total} 处引用，未匹配 ${missing.length} 处`)
if (missing.length) {
  for (const m of missing) console.log(`  ✘ ${m}`)
  process.exit(1)
} else {
  console.log('  全部命中 ✔')
}
