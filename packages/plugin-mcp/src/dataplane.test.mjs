/**
 * Tests unitaires du plan de données MCP au niveau service (W2-T3, contrats §7/§8).
 *
 * Mode d'exécution (chargement direct par Node, construction en processus, sur le style de stubs de governance.test.mjs) :
 *
 *     node packages/plugin-mcp/src/dataplane.test.mjs
 *
 * Couverture :
 *   - authorizedToolsFor, logique pure : appariement de sujets du groupe de permissions / liste blanche allowedTools / union de groupes multiples /
 *     contrainte readOnly filtrant write/admin (unknown passe en contexte lecture) / sans groupe de permissions = ensemble vide ;
 *   - équivalence outil par outil d'authorizedToolsFor avec authorize() (assertion de régression de l'extraction, non d'une copie) ;
 *   - endpoint au niveau service de bout en bout (stub http en mémoire + stubs authn/iam/resourceCore, sans occuper de port) :
 *     initialize (mcp-session-id/serverInfo) → filtrage tools/list → mapping des codes de refus tools/call
 *     (-32003 TOOL_NOT_VISIBLE_OR_DENIED) → passage tools/call avec enveloppe content ;
 *     401 non authentifié / 403 AUDIENCE_MISMATCH / -32000 SERVICE_NOT_FOUND / alias :id.
 */
import assert from 'node:assert/strict'
import { test, afterEach } from 'node:test'
import { rmSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { StorageService } from '../../platform-core/src/storage.ts'
import { McpService } from './index.ts'
import { registerMcpDataplaneRoutes } from '../../plugin-console/src/routes/mcp-dataplane.ts'

// -- Hôte construit en processus (bus stub + vrai StorageService + stubs authn/iam/resourceCore + stub http) --------

const cleanup = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()()
})

/** Registre de jetons stub : token → principal/audience (doublure minimale du comportement d'authn.verify). */
function makeAuthnStub() {
  const tokens = new Map()
  let seq = 0
  return {
    tokens,
    issue({ principal, audience, scopes }) {
      const token = `dst1.test.${++seq}`
      tokens.set(token, { principal, audience, scopes: scopes ?? ['console.login'], jti: `jti-${seq}` })
      return token
    },
    verify(tokenString) {
      const record = tokens.get(tokenString)
      if (!record) throw new Error('令牌不存在或已被清理')
      return {
        principal: record.principal,
        token: { jti: record.jti, ...(record.audience !== undefined ? { audience: record.audience } : {}) },
        scopes: record.scopes,
        actChain: [],
      }
    },
    // Port de recherche inverse resolveUnifiedPrincipal : toujours miss (le nom retombe sur principal.name, org/tenant par défaut)
    principals: () => ({ get: () => undefined }),
  }
}

/**
 * Construit l'hôte du plan de données : renvoie registry (vrai McpService) et captured, la table des gestionnaires de routes.
 * Les stubs authn/iam/resourceCore ne satisfont que la chaîne de recherche inverse resolveUnifiedPrincipal (miss = défaut, fail-safe).
 */
function makeHarness() {
  const dataDir = mkdtempSync(join(tmpdir(), 'mcp-dataplane-'))
  cleanup.push(() => rmSync(dataDir, { recursive: true, force: true }))
  const ctx = new Context()
  const events = []
  ctx.platformBus = {
    on: () => () => {},
    emit: (name, payload) => events.push({ name, payload }),
  }
  new StorageService(ctx, { dataDir })
  const registry = new McpService(ctx)
  // Face identité stub : verify passe par le registre de jetons en mémoire ; recherches inverses principal/iam/resource toujours miss (chemin par défaut de resolveUnifiedPrincipal)
  const authn = makeAuthnStub()
  ctx.authn = authn
  ctx.iam = {
    users: () => ({ get: () => undefined }),
    tenantOfOrg: () => undefined,
    resolveGroupMembers: () => [],
  }
  ctx.resourceCore = { get: () => undefined }
  // http stub : capture seulement les enregistrements (method+pattern → handler), les requêtes pilotent directement handler(faux exchange)
  const routes = new Map()
  registerMcpDataplaneRoutes(ctx, {
    http: { register: (method, pattern, handler) => routes.set(`${method} ${pattern}`, handler) },
  })
  return { ctx, registry, authn, routes, events }
}

/** Faux HttpExchange : capture les sorties writeHead/end, pour les assertions JSON-RPC. */
function makeExchange({ pattern, token, audience, body }) {
  const res = {
    status: 0, headers: {}, text: '',
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers ?? {}) },
    end(text) { this.text = text ?? ''; this.ended = true },
  }
  const slugSeg = pattern.split('/')[3] ?? ''
  return {
    method: 'POST',
    path: pattern,
    params: pattern.startsWith('/mcp/s/') ? { serviceId: slugSeg } : { serviceSlug: slugSeg },
    query: new URLSearchParams(),
    headers: token !== undefined ? { authorization: `Bearer ${token}` } : {},
    body,
    raw: {},
    res,
  }
}

const agentPrincipal = (agentId, name = '测试Agent') => ({
  id: `mc-${agentId}`,
  type: 'machine',
  refType: 'agent',
  refId: agentId,
  name,
})

/** Fixture standard : service demo (trois outils read + write + unknown, couche d'exécution demo sans appel sortant) + groupe lecture seule agent. */
async function makeServiceFixture(registry, overrides = {}) {
  const service = registry.createService({
    name: '演示服务', slug: 'demo-svc', orgId: 'org-1', owner: 'tester', exec: 'demo',
    tools: [
      { name: 'demo_search', description: '检索', inputSchema: { type: 'object', properties: { query: { type: 'string' } } }, riskLevel: 'read' },
      { name: 'demo_write', description: '写入', inputSchema: { type: 'object', properties: {} }, riskLevel: 'write' },
      { name: 'demo_sync', description: '同步（风险未登记）', inputSchema: { type: 'object', properties: {} }, riskLevel: 'unknown' },
    ],
    ...overrides,
  })
  await registry.deployService(service.id, { actor: 'tester' })
  return registry.services().get(service.id)
}

// -- §8 authorizedToolsFor, logique pure -------------------------------------------------------------

test('authorizedToolsFor：白名单交集 + 多组并集（首个 allowedTools 命中策略定裁决，与 authorize 同序）', async () => {
  const { registry } = makeHarness()
  const service = await makeServiceFixture(registry)
  // Groupe A : liste blanche uniquement search (sans contrainte) ; groupe B : tout (sans readOnly) — write passe par B, l'union de groupes prend effet
  registry.createPermGroup({
    name: '组A-白名单', description: '',
    policies: { [service.id]: { allowedTools: ['demo_search'], constraints: {} } },
    subjects: [{ type: 'agent', id: 'agt-1' }],
  })
  registry.createPermGroup({
    name: '组B-全量', description: '',
    policies: { [service.id]: { allowedTools: '*', constraints: {} } },
    subjects: [{ type: 'agent', id: 'agt-1' }],
  })
  const caller = { type: 'agent', id: 'agt-1', name: '双组Agent' }
  assert.deepEqual(registry.authorizedToolsFor(caller, service), ['demo_search', 'demo_write', 'demo_sync'])
})

test('authorizedToolsFor：readOnly 约束过滤 write 工具（unknown 按只读语境放行）', async () => {
  const { registry } = makeHarness()
  const service = await makeServiceFixture(registry)
  registry.createPermGroup({
    name: '只读组', description: '',
    policies: { [service.id]: { allowedTools: '*', constraints: { readOnly: true } } },
    subjects: [{ type: 'agent', id: 'agt-2' }],
  })
  const caller = { type: 'agent', id: 'agt-2', name: '只读Agent' }
  // write filtré ; read passe ; unknown passe en contexte lecture (référentiel W1/V11, cohérent avec authorize)
  assert.deepEqual(registry.authorizedToolsFor(caller, service), ['demo_search', 'demo_sync'])
})

test('authorizedToolsFor：无权限组/主体不匹配 → 空集；user_group 主体对 agent/user 调用者均不生效', async () => {
  const { registry } = makeHarness()
  const service = await makeServiceFixture(registry)
  registry.createPermGroup({
    name: '他组', description: '',
    policies: { [service.id]: { allowedTools: '*', constraints: {} } },
    subjects: [
      { type: 'agent', id: 'agt-other' },
      { type: 'user_group', id: 'ug-1' },
    ],
  })
  assert.deepEqual(registry.authorizedToolsFor({ type: 'agent', id: 'agt-9', name: '陌生' }, service), [])
  assert.deepEqual(registry.authorizedToolsFor({ type: 'user', id: 'u-9', name: '路人' }, service), [])
})

test('authorizedToolsFor 与 authorize 逐工具等价（抽取回归：判定面共用，行为零漂移）', async () => {
  const { registry } = makeHarness()
  const service = await makeServiceFixture(registry)
  registry.createPermGroup({
    name: '混合组', description: '',
    policies: { [service.id]: { allowedTools: ['demo_search', 'demo_write'], constraints: { readOnly: true } } },
    subjects: [{ type: 'agent', id: 'agt-3' }],
  })
  const callers = [
    { type: 'agent', id: 'agt-3', name: '组内' },
    { type: 'agent', id: 'agt-x', name: '组外' },
  ]
  const visible = new Set(registry.authorizedToolsFor(callers[0], service))
  for (const caller of callers) {
    for (const tool of service.tools) {
      const verdict = registry.authorize(caller, service.id, tool.name)
      assert.equal(verdict.ok, registry.authorizedToolsFor(caller, service).includes(tool.name),
        `authorizedToolsFor 与 authorize 不一致：${caller.id}/${tool.name}`)
    }
  }
  assert.deepEqual([...visible], ['demo_search'])
})

// -- §7 endpoint au niveau service de bout en bout (pilotage direct des gestionnaires par stubs en mémoire, sans port) -----------------------------------------

async function e2eHarness() {
  const harness = makeHarness()
  const { registry, authn } = harness
  const service = await makeServiceFixture(registry)
  // Groupe de permissions lecture seule : tools/list ne doit montrer que les outils read/unknown, l'appel write doit être refusé
  registry.createPermGroup({
    name: '只读组', description: '',
    policies: { [service.id]: { allowedTools: '*', constraints: { readOnly: true } } },
    subjects: [{ type: 'agent', id: 'agt-77' }],
  })
  const agentToken = authn.issue({ principal: agentPrincipal('agt-77') })
  const outsiderToken = authn.issue({ principal: agentPrincipal('agt-999', '圈外Agent') })
  const wrongAudToken = authn.issue({ principal: agentPrincipal('agt-77'), audience: 'plugin:some-plugin' })
  const rightAudToken = authn.issue({ principal: agentPrincipal('agt-77'), audience: 'mcp:service:demo-svc' })
  return { ...harness, service, agentToken, outsiderToken, wrongAudToken, rightAudToken }
}

test('端到端：initialize 回 mcp-session-id 与 serverInfo.name=mcp:<slug>；缺 Bearer → 401/-32001', async () => {
  const h = await e2eHarness()
  // Sans Bearer : 401 + JSON-RPC -32001
  const anon = makeExchange({ pattern: '/mcp/services/demo-svc', body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(anon)
  assert.equal(anon.res.status, 401)
  assert.equal(anon.res.headers['www-authenticate'], 'Bearer realm="dsh-mcp-dataplane"')
  assert.equal(JSON.parse(anon.res.text).error.code, -32001)
  // Jeton invalide : 401 + -32001
  const bad = makeExchange({ pattern: '/mcp/services/demo-svc', token: 'dst1.bogus.0', body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(bad)
  assert.equal(bad.res.status, 401)
  assert.equal(JSON.parse(bad.res.text).error.code, -32001)
  // initialize : 200 + en-tête de session + serverInfo
  const init = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.agentToken, body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'tester', version: '1.0' } } } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(init)
  assert.equal(init.res.status, 200)
  assert.match(String(init.res.headers['mcp-session-id']), /^dshmcp-demo-svc-/)
  const payload = JSON.parse(init.res.text)
  assert.equal(payload.result.serverInfo.name, 'mcp:demo-svc')
  assert.equal(payload.result.serverInfo.title, '演示服务')
  assert.equal(payload.result.protocolVersion, '2025-03-26')
})

test('端到端：tools/list 按权限过滤（只读组不见 write 工具）；空集主体回空数组', async () => {
  const h = await e2eHarness()
  const list = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.agentToken, body: { jsonrpc: '2.0', id: 2, method: 'tools/list' } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(list)
  const tools = JSON.parse(list.res.text).result.tools
  assert.deepEqual(tools.map((tool) => tool.name), ['demo_search', 'demo_sync'], 'write 工具不得出现在只读主体列表')
  assert.equal(tools[0].inputSchema.type, 'object', '可见工具回完整 inputSchema')
  assert.equal(tools[0].description, '检索')
  // Sujet sans groupe de permissions : tools/list renvoie un tableau vide (et non une erreur)
  const empty = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.outsiderToken, body: { jsonrpc: '2.0', id: 2, method: 'tools/list' } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(empty)
  assert.deepEqual(JSON.parse(empty.res.text).result.tools, [])
})

test('端到端：tools/call 拒绝码映射（不可见 → -32003 TOOL_NOT_VISIBLE_OR_DENIED）、放行回 content 包装', async () => {
  const h = await e2eHarness()
  // Sujet lecture seule appelant l'outil write : la chaîne invoke refuse (avec écriture), mappe -32003 + TOOL_NOT_VISIBLE_OR_DENIED
  const denied = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.agentToken, body: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'demo_write', arguments: {} } } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(denied)
  assert.equal(denied.res.status, 200)
  const denial = JSON.parse(denied.res.text)
  assert.equal(denial.error.code, -32003)
  assert.equal(denial.error.data.code, 'TOOL_NOT_VISIBLE_OR_DENIED')
  // Le refus est aussi entré dans le registre d'appels (écriture par la chaîne invoke : le refus est un fait)
  assert.ok(h.registry.callLog({ serviceId: h.service.id, status: 'denied' }).items.length >= 1)
  // Outil inconnu : l'existence n'est pas divulguée, même code de domaine
  const unknown = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.agentToken, body: { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'no_such_tool', arguments: {} } } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(unknown)
  const unknownPayload = JSON.parse(unknown.res.text)
  assert.equal(unknownPayload.error.code, -32003)
  assert.equal(unknownPayload.error.data.code, 'TOOL_NOT_VISIBLE_OR_DENIED')
  // Sujet lecture seule appelant l'outil visible read : passage, content[0].text est la chaîne JSON du résultat
  const allowed = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.agentToken, body: { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'demo_search', arguments: { query: '你好' } } } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(allowed)
  const okPayload = JSON.parse(allowed.res.text)
  assert.equal(okPayload.result.isError, false)
  assert.equal(okPayload.result.content[0].type, 'text')
  const inner = JSON.parse(okPayload.result.content[0].text)
  assert.ok(Array.isArray(inner.items), 'demo 执行层对 search 类工具返回确定性检索结果')
})

test('端到端：aud 强校验（受众不符 403 AUDIENCE_MISMATCH；匹配 slug 放行）；SERVICE_NOT_FOUND；:id 别名', async () => {
  const h = await e2eHarness()
  // Audience non concordante : 403 + -32003 + AUDIENCE_MISMATCH
  const mismatch = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.wrongAudToken, body: { jsonrpc: '2.0', id: 6, method: 'ping' } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(mismatch)
  assert.equal(mismatch.res.status, 403)
  const mismatchPayload = JSON.parse(mismatch.res.text)
  assert.equal(mismatchPayload.error.code, -32003)
  assert.equal(mismatchPayload.error.data.code, 'AUDIENCE_MISMATCH')
  // Audience correspondant exactement au slug : passage
  const match = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.rightAudToken, body: { jsonrpc: '2.0', id: 7, method: 'ping' } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(match)
  assert.equal(match.res.status, 200)
  assert.deepEqual(JSON.parse(match.res.text).result, {})
  // Service inexistant : -32000 + SERVICE_NOT_FOUND
  const missing = makeExchange({ pattern: '/mcp/services/no-such-svc', token: h.agentToken, body: { jsonrpc: '2.0', id: 8, method: 'ping' } })
  await h.routes.get('POST /mcp/services/:serviceSlug')(missing)
  const missingPayload = JSON.parse(missing.res.text)
  assert.equal(missingPayload.error.code, -32000)
  assert.equal(missingPayload.error.data.code, 'SERVICE_NOT_FOUND')
  // Alias :id (/mcp/s/:serviceId) : même sémantique de gestionnaire, tools/list filtre comme d'habitude
  const alias = makeExchange({ pattern: `/mcp/s/${h.service.id}`, token: h.agentToken, body: { jsonrpc: '2.0', id: 9, method: 'tools/list' } })
  await h.routes.get('POST /mcp/s/:serviceId')(alias)
  assert.deepEqual(JSON.parse(alias.res.text).result.tools.map((tool) => tool.name), ['demo_search', 'demo_sync'])
  // Intégrité de la face d'enregistrement : GET 405 / DELETE 200 (même sémantique Streamable HTTP)
  const get = makeExchange({ pattern: '/mcp/services/demo-svc', token: h.agentToken, body: undefined })
  get.method = 'GET'
  await h.routes.get('GET /mcp/services/:serviceSlug')(get)
  assert.equal(get.res.status, 405)
})
