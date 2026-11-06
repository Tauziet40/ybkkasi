/**
 * Tests unitaires de la politique unifiée et de l'audit W3-T5 (contrat de gouvernance MCP §11/§12/§13/§14).
 *
 * Exécution : node --test packages/plugin-mcp/src/policy.test.mjs
 *
 * Couverture :
 *   - org-constraint trois états : passage dans org / refus inter-organisation inter-tenant ORG_SCOPE_DENIED /
 *     tenant même tenant = passage (inter-organisation dans le même tenant) / cross-org sans approbation = refus + passage avec référence d'approbation valide ;
 *   - première couche aux trois formes de scope de limitation de ressource (mcp.invoke / mcp.service:* / mcp.tool:*),
 *     un scope préfixe mcp. sans couvrir la cible = fail-closed (SCOPE_DENIED), scopes legacy sans protection ;
 *   - rapport d'impact en quatre dimensions de la simulation dry-run (newServices/writeTools/confidential/crossOrg) ;
 *   - génération du gabarit de scope ('*' → niveau service ; liste blanche → niveau outil ; groupe readOnly sans scope d'outil écrit) ;
 *   - chaîne de hachage d'audit : calcul au point unique record(), chaînage prevHash, reprise après redémarrage, falsification détectable, recherche par traceId ;
 *   - agrégation d'audit de sondage : secret.access dédupliqué par fenêtre dedupKey + suppressedCount joint à l'événement à la fermeture.
 */
import assert from 'node:assert/strict'
import { test, afterEach } from 'node:test'
import { rmSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { StorageService } from '../../platform-core/src/storage.ts'
import { McpService } from './index.ts'
import { SecretBroker } from './secret-broker.ts'
import { AuditService, auditHashOf } from '../../plugin-audit/src/index.ts'

const cleanup = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()()
})

/**
 * Hôte de la face politique : vrai McpService + stubs iam (tenant/utilisateur) / resourceCore / audit (registre d'approbations).
 * platformBus stub enregistre les événements pour assertion ; usage stub capte le metering recordCall (services demo non atteints).
 */
function makeHarness(options = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'mcp-policy-'))
  cleanup.push(() => rmSync(dataDir, { recursive: true, force: true }))
  const ctx = new Context()
  const events = []
  ctx.platformBus = {
    on: () => () => {},
    emit: (name, payload) => events.push({ name, payload }),
  }
  const storage = new StorageService(ctx, { dataDir })
  // Stub iam : carte org→tenant injectable (face de jugement inter-tenant d'org-constraint) ; registre d'utilisateurs pour subjectUserOrg
  const tenantMap = options.tenantMap ?? {}
  const users = new Map(Object.entries(options.users ?? {}))
  ctx.iam = {
    users: () => ({ get: (id) => users.get(id) }),
    tenantOfOrg: (orgId) => tenantMap[orgId] ?? 't_default',
    resolveGroupMembers: () => [],
  }
  ctx.resourceCore = { get: () => undefined }
  // Stub du registre d'approbations : id → fiche (face de jugement de la référence d'approbation valide cross-org)
  const approvals = new Map(Object.entries(options.approvals ?? {}))
  ctx.audit = { approvals: () => ({ get: (id) => approvals.get(id) }) }
  const registry = new McpService(ctx)
  return { ctx, registry, events, approvals, users }
}

/** Service demo en ligne (couche d'exécution déterministe sans appel sortant) + groupe de permissions passe-tout ('*'). */
async function onlineService(registry, overrides = {}) {
  const service = registry.createService({
    name: '策略服务', slug: 'policy-svc', orgId: 'org-a', owner: 'tester', exec: 'demo',
    tools: [
      { name: 'policy_search', description: '检索', inputSchema: { type: 'object' }, riskLevel: 'read' },
      { name: 'policy_write', description: '写入', inputSchema: { type: 'object' }, riskLevel: 'write' },
      { name: 'policy_sync', description: '未登记风险', inputSchema: { type: 'object' }, riskLevel: 'unknown' },
    ],
    ...overrides,
  })
  await registry.deployService(service.id, { actor: 'tester' })
  registry.createPermGroup({
    name: '全放行组', description: '',
    policies: { [service.id]: { allowedTools: '*', constraints: {} } },
    subjects: [{ type: 'agent', id: 'agt-1' }],
  })
  return registry.services().get(service.id)
}

const agentCaller = (overrides = {}) => ({ type: 'agent', id: 'agt-1', name: '策略Agent', ...overrides })

// -- B (contrat §13) : org-constraint trois états -------------------------------------------------------

test('org-constraint：org 内放行（caller.org == service.org）', async () => {
  const { registry } = makeHarness()
  const service = await onlineService(registry)
  const result = await registry.invoke(agentCaller({ orgId: 'org-a' }), service.id, 'policy_search', {})
  assert.equal(result.ok, true)
})

test('org-constraint：跨组织且跨租户 → 拒绝 ORG_SCOPE_DENIED（硬拦面）', async () => {
  const { registry } = makeHarness({ tenantMap: { 'org-a': 't-1', 'org-b': 't-2' } })
  const service = await onlineService(registry)
  const result = await registry.invoke(agentCaller({ orgId: 'org-b' }), service.id, 'policy_search', {})
  assert.equal(result.ok, false)
  assert.equal(result.status, 'denied')
  assert.equal(result.code, 'ORG_SCOPE_DENIED')
  assert.ok(result.decisionId?.startsWith('pd_'), '拒绝响应带决策 id')
  assert.ok(Array.isArray(result.decisionReasons) && result.decisionReasons.length > 0)
  // Écriture : l'enregistrement d'appel et l'événement mcp.invoked portent tous deux l'expression de décision
  const call = registry.callLog({ serviceId: service.id, status: 'denied' }).items[0]
  assert.equal(call.code, 'ORG_SCOPE_DENIED')
  assert.equal(call.decisionId, result.decisionId)
})

test('org-constraint：跨组织同租户 + 权限组显式授权 → 放行（默认开放组织内口径）', async () => {
  const { registry } = makeHarness({ tenantMap: { 'org-a': 't-1', 'org-b': 't-1' } })
  const service = await onlineService(registry)
  const result = await registry.invoke(agentCaller({ orgId: 'org-b' }), service.id, 'policy_search', {})
  assert.equal(result.ok, true, '同租户跨组织经显式权限组授权放行（存量演示/自测数据零漂移）')
})

test('org-constraint：visibility=tenant 同租户放行、跨租户拒绝（不要求显式授权事实）', async () => {
  const { registry } = makeHarness({ tenantMap: { 'org-a': 't-1', 'org-b': 't-1', 'org-c': 't-2' } })
  const service = await onlineService(registry, { visibility: 'tenant' })
  // Inter-organisation dans le même tenant : les trois états tenant passent directement (même un sujet sans groupe de permissions passerait — un groupe est quand même donné ici, face équivalente cohérente)
  const okResult = await registry.invoke(agentCaller({ orgId: 'org-b' }), service.id, 'policy_search', {})
  assert.equal(okResult.ok, true)
  // Inter-tenant : refus
  const denied = await registry.invoke(agentCaller({ orgId: 'org-c' }), service.id, 'policy_search', {})
  assert.equal(denied.code, 'ORG_SCOPE_DENIED')
})

test('org-constraint：visibility=cross-org 无审批拒、approved/executed 有效审批放行、过期审批拒', async () => {
  const now = Date.now()
  const { registry } = makeHarness({
    approvals: {
      'apr-ok': { id: 'apr-ok', status: 'executed', decidedAt: new Date(now - 3600_000).toISOString() },
      'apr-stale': { id: 'apr-stale', status: 'approved', decidedAt: new Date(now - 25 * 3600_000).toISOString() },
      'apr-pending': { id: 'apr-pending', status: 'pending', decidedAt: new Date(now - 60_000).toISOString() },
    },
  })
  const service = await onlineService(registry, { visibility: 'cross-org' })
  // Sans référence d'approbation : refus
  const noApproval = await registry.invoke(agentCaller({ orgId: 'org-b' }), service.id, 'policy_search', {})
  assert.equal(noApproval.code, 'ORG_SCOPE_DENIED')
  assert.ok(noApproval.error.includes('审批'))
  // Référence invalide (pending / hors fenêtre 24 h / inexistante) : refus
  for (const approvalId of ['apr-pending', 'apr-stale', 'apr-none']) {
    const denied = await registry.invoke(agentCaller({ orgId: 'org-b', approvalId }), service.id, 'policy_search', {})
    assert.equal(denied.code, 'ORG_SCOPE_DENIED', `无效审批引用 ${approvalId} 必须拒绝`)
  }
  // Référence d'approbation valide (executed et dans la fenêtre 24 h) : passage
  const okResult = await registry.invoke(agentCaller({ orgId: 'org-b', approvalId: 'apr-ok' }), service.id, 'policy_search', {})
  assert.equal(okResult.ok, true)
})

test('org-constraint：委托链 subjectUserId 的 org 与目标服务跨租户 → 同样拒绝', async () => {
  const { registry } = makeHarness({
    tenantMap: { 'org-a': 't-1', 'org-b': 't-2' },
    users: { 'u-delegate': { orgId: 'org-b' } },
  })
  const service = await onlineService(registry)
  // L'appelant lui-même a une face de passage même org, mais l'utilisateur réel de la chaîne de délégation est dans un autre tenant → refus
  const result = await registry.invoke(agentCaller({ orgId: 'org-a', subjectUserId: 'u-delegate' }), service.id, 'policy_search', {})
  assert.equal(result.code, 'ORG_SCOPE_DENIED')
})

// -- C (contrat §12) : première couche scope de limitation de ressource -----------------------------------------------------

test('iam-permission 第一层：unified scopes 三形态任一即放行（第二层权限组照旧强制）', async () => {
  const { registry } = makeHarness()
  const service = await onlineService(registry)
  for (const scopes of [
    ['mcp.invoke'],
    [`mcp.service:${service.slug}.invoke`],
    [`mcp.tool:${service.slug}:policy_search.invoke`],
    ['console.login', 'mcp.invoke'],
  ]) {
    const result = await registry.invoke(agentCaller({ scopes }), service.id, 'policy_search', {})
    assert.equal(result.ok, true, `scopes [${scopes.join(',')}] 应放行`)
  }
})

test('iam-permission 第一层：mcp. 前缀 scope 未覆盖本目标 → SCOPE_DENIED；legacy scopes 不设防', async () => {
  const { registry } = makeHarness()
  const service = await onlineService(registry)
  // Face MCP de scopes déclarée (limitée à un autre service) appelant ce service : fail-closed
  const mismatch = await registry.invoke(agentCaller({ scopes: ['mcp.service:other-svc.invoke'] }), service.id, 'policy_search', {})
  assert.equal(mismatch.status, 'denied')
  assert.equal(mismatch.code, 'SCOPE_DENIED')
  // Scope niveau outil ne laisse passer que l'outil correspondant
  const otherTool = await registry.invoke(agentCaller({ scopes: [`mcp.tool:${service.slug}:policy_write.invoke`] }), service.id, 'policy_search', {})
  assert.equal(otherTool.code, 'SCOPE_DENIED')
  // Scopes legacy (sans aucun préfixe mcp.) : première couche sans protection, arbitrage par la deuxième couche groupes de permissions → passage
  const legacy = await registry.invoke(agentCaller({ scopes: ['console.login'] }), service.id, 'policy_search', {})
  assert.equal(legacy.ok, true)
  // Scopes absents (appelant legacy de la face outils) : de même sans protection
  const absent = await registry.invoke(agentCaller(), service.id, 'policy_search', {})
  assert.equal(absent.ok, true)
})

test('iam-permission + 权限组双层：scope 放行不绕过权限组（无授权主体仍拒）', async () => {
  const harness = makeHarness()
  const { registry } = harness
  const service = await onlineService(registry)
  const outsider = harness && agentCaller({ id: 'agt-999', scopes: ['mcp.invoke'] })
  const result = await registry.invoke(outsider, service.id, 'policy_search', {})
  assert.equal(result.ok, false)
  assert.equal(result.status, 'denied')
  assert.ok(result.error.includes('未被任何 MCP 权限组授权'), '主因仍是权限组文案（模块序保持）')
  assert.equal(result.code, undefined, '权限组层拒绝不带新增领域码（既有口径）')
})

// -- C (contrat §14) : rapport d'impact de la simulation dry-run -------------------------------------------------

test('dry-run 影响报告：newServices/writeTools/confidential/crossOrg 四维 + subjects 原样展开（不落库）', async () => {
  const harness = makeHarness({ tenantMap: { 'org-a': 't-1', 'org-b': 't-2' } })
  const { registry } = harness
  // Org atteignable par les sujets : l'agent agt-1 est rattaché à org-b (différent de l'org-a des services couverts → crossOrg)
  harness.ctx.resourceCore = { get: (kind, id) => (id === 'agt-1' ? { orgId: 'org-b' } : undefined) }
  const plain = await onlineService(registry)
  const confidential = registry.createService({
    name: '高敏服务', slug: 'conf-svc', orgId: 'org-a', owner: 'tester', exec: 'demo',
    dataClass: 'confidential',
    tools: [
      { name: 'conf_read', description: '读', inputSchema: { type: 'object' }, riskLevel: 'read' },
      { name: 'conf_admin', description: '管', inputSchema: { type: 'object' }, riskLevel: 'admin' },
    ],
  })
  const before = registry.permGroups().all().length
  const report = registry.dryRunPermGroup({
    name: '草稿权限组',
    policies: {
      [plain.id]: { allowedTools: ['policy_search', 'policy_write'], constraints: {} },
      [confidential.id]: { allowedTools: '*', constraints: { readOnly: true } },
      ['mcp-none']: { allowedTools: '*', constraints: {} },
    },
    subjects: [{ type: 'agent', id: 'agt-1', name: '策略Agent' }, { type: 'user_group', id: 'ug-1' }],
  })
  // newServices : couvre un service existant (référence inexistante sautée)
  assert.deepEqual(report.newServices.map((item) => item.serviceId).sort(), [plain.id, confidential.id].sort())
  // writeTools : outils write/admin atteints par allowedTools dans les services couverts (la contrainte readOnly n'affecte pas le référentiel d'impact —
  // le rapport présente « quelles capacités d'écriture le brouillon touche », la sémantique de contrainte est exécutée par la face d'arbitrage des appels)
  assert.deepEqual(report.writeTools, [
    { serviceId: plain.id, slug: plain.slug, tool: 'policy_write' },
    { serviceId: confidential.id, slug: 'conf-svc', tool: 'conf_admin' },
  ])
  // dimension confidential
  assert.deepEqual(report.confidential, [{ serviceId: confidential.id, slug: 'conf-svc', dataClass: 'confidential' }])
  // crossOrg : l'org atteignable par les sujets (org-b) diffère de l'org des services couverts (org-a) → true
  assert.equal(report.crossOrg, true)
  // affectedSubjects étendus tels quels
  assert.deepEqual(report.affectedSubjects, [
    { type: 'agent', id: 'agt-1', name: '策略Agent' },
    { type: 'user_group', id: 'ug-1' },
  ])
  // Sémantique dry : pas d'écriture
  assert.equal(registry.permGroups().all().length, before)
})

test('dry-run crossOrg：主体可达 org 与服务 org 一致 → false；org 不可判 → false（不计）', async () => {
  const harness = makeHarness()
  const { registry } = harness
  const service = await onlineService(registry)
  // Sujet de même org (resourceCore renvoie org-a)
  harness.ctx.resourceCore = { get: (kind, id) => (id === 'agt-1' ? { orgId: 'org-a' } : undefined) }
  const sameOrg = registry.dryRunPermGroup({
    policies: { [service.id]: { allowedTools: '*', constraints: {} } },
    subjects: [{ type: 'agent', id: 'agt-1' }],
  })
  assert.equal(sameOrg.crossOrg, false)
  // Principal sans org résoluble : crossOrg non compté
  harness.ctx.resourceCore = { get: () => undefined }
  const unknownOrg = registry.dryRunPermGroup({
    policies: { [service.id]: { allowedTools: '*', constraints: {} } },
    subjects: [{ type: 'agent', id: 'agt-404' }],
  })
  assert.equal(unknownOrg.crossOrg, false)
})

// -- C (contrat §12) : gabarit de scope -----------------------------------------------------------------

test('scope 模板：全量组产出服务级 scope；白名单组产出工具级 scope；readOnly 组不产出写工具 scope', async () => {
  const { registry } = makeHarness()
  const service = await onlineService(registry) // tools: search(read)/write(write)/sync(unknown)
  const wildcard = registry.createPermGroup({
    name: '全量组', description: '',
    policies: { [service.id]: { allowedTools: '*', constraints: {} } },
    subjects: [],
  })
  const full = registry.scopeTemplate(wildcard.id)
  assert.deepEqual(full.scopes, [`mcp.service:${service.slug}.invoke`])
  assert.deepEqual(full.byService, [{ serviceId: service.id, slug: service.slug, scopes: [`mcp.service:${service.slug}.invoke`] }])

  const readonly = registry.createPermGroup({
    name: '只读白名单组', description: '',
    policies: { [service.id]: { allowedTools: ['policy_search', 'policy_write', 'policy_sync'], constraints: { readOnly: true } } },
    subjects: [],
  })
  const scoped = registry.scopeTemplate(readonly.id)
  // Groupe readOnly : pas de scope pour les outils write (gabarit = référentiel de la face d'arbitrage) ; les outils read/unknown produisent chacun
  assert.deepEqual(scoped.scopes, [
    `mcp.tool:${service.slug}:policy_search.invoke`,
    `mcp.tool:${service.slug}:policy_sync.invoke`,
  ])
  assert.equal(scoped.byService.length, 1)

  // Groupe de permissions inexistant : erreur explicite (la sémantique dry ne frappe pas le mauvais objet)
  assert.throws(() => registry.scopeTemplate('mpg-none'), /权限组不存在/)
})

// -- D (contrat §14) : chaîne de hachage d'audit -----------------------------------------------------------------

/** Construit un hôte d'audit minimal (bus stub + pipeline de consommation usage + vrai StorageService). */
function makeAuditHarness() {
  const dataDir = mkdtempSync(join(tmpdir(), 'mcp-policy-audit-'))
  cleanup.push(() => rmSync(dataDir, { recursive: true, force: true }))
  const ctx = new Context()
  ctx.platformBus = { on: () => () => {}, emit: () => {} }
  ctx.usage = { consume: () => () => {}, project: () => {}, record: () => {} }
  new StorageService(ctx, { dataDir })
  return new AuditService(ctx)
}

const auditEntry = (n) => ({
  type: 'invoke', actorType: 'machine', actorId: `agt-${n}`, actorName: `Agent ${n}`,
  action: 'mcp.gateway.invoke', resourceType: 'mcp_service', resourceId: 'mcp-1', resourceName: '策略服务',
  result: 'ok', detail: `latency=${n}ms`,
})

test('审计哈希链：record() 单点计算、prevHash 链式相接、重算校验一致、链首 prevHash 为空串', () => {
  const audit = makeAuditHarness()
  const first = audit.record(auditEntry(1))
  assert.equal(first.prevHash, '')
  assert.match(first.hash, /^[0-9a-f]{64}$/)
  assert.equal(first.hash, auditHashOf(first, ''), '记录可按导出口径重算校验')
  const second = audit.record(auditEntry(2))
  assert.equal(second.prevHash, first.hash, '链式相接')
  assert.equal(second.hash, auditHashOf(second, second.prevHash))
  assert.equal(audit.chainTipHash(), second.hash)
  // Falsification détectable : après modification d'un champ métier quelconque, le recalcul ne correspond plus
  const tampered = { ...second, detail: '被篡改' }
  assert.notEqual(auditHashOf(tampered, tampered.prevHash), tampered.hash)
})

test('审计哈希链：启动续链（链首重取集合最后一条 hash）与 traceId 精确检索', () => {
  const audit = makeAuditHarness()
  const withTrace = { ...auditEntry(1), traceId: 'a'.repeat(32) }
  const first = audit.record(withTrace)
  audit.record(auditEntry(2))
  // Redémarrage simulé : après remise à zéro de l'état de tête de chaîne, le chemin de démarrage de record() reprend le dernier hash de la collection (le redémarrage ne casse pas la chaîne)
  audit.chainReady = false
  audit.chainTip = ''
  const third = audit.record(auditEntry(3))
  const lastHash = audit.logs().all().filter((item) => item.id !== third.id).at(-1).hash
  assert.equal(third.prevHash, lastHash, '启动续链取集合最后一条 hash')
  assert.equal(audit.chainTipHash(), third.hash)
  // Recherche exacte par traceId (filtre incrémental de query)
  const hits = audit.query({ traceId: 'a'.repeat(32) })
  assert.equal(hits.total, 1)
  assert.equal(hits.items[0].id, first.id)
  assert.equal(audit.query({ traceId: 'b'.repeat(32) }).total, 0)
})

// -- D (contrat §14) : agrégation d'audit de sondage (déduplication par fenêtre de secret.access) -------------------------------------

function makeBrokerHarness() {
  const dataDir = mkdtempSync(join(tmpdir(), 'mcp-policy-broker-'))
  cleanup.push(() => rmSync(dataDir, { recursive: true, force: true }))
  const ctx = new Context()
  const events = []
  ctx.platformBus = { on: () => () => {}, emit: (name, payload) => events.push({ name, payload }) }
  new StorageService(ctx, { dataDir })
  const broker = new SecretBroker(ctx)
  broker.probeDedupWindowMs = 30 // fenêtre resserrée pour le test (fermeture de fenêtre observable)
  return { broker, events }
}

test('探活审计聚合：同 dedupKey 窗口内只发一次；窗口关闭后首事件附 suppressedCount；不带键逐次留痕', async () => {
  const { broker, events } = makeBrokerHarness()
  broker.put({ serviceId: 'mcp-probe', headerName: 'Authorization', secret: 'probe-secret' })
  const accessEvents = () => events.filter((item) => item.name === 'mcp.secret.access')
  // trois resolves de sondage dans la fenêtre : un seul événement émis
  broker.resolve('mcp-probe', { dedupKey: 'probe' })
  broker.resolve('mcp-probe', { dedupKey: 'probe' })
  broker.resolve('mcp-probe', { dedupKey: 'probe' })
  assert.equal(accessEvents().length, 1)
  // Fenêtre fermée (fenêtre attendue) : l'événement d'ouverture suivante porte le compteur agrégé de la fenêtre précédente (2 suppressions)
  await new Promise((resolve) => setTimeout(resolve, 45))
  broker.resolve('mcp-probe', { dedupKey: 'probe' })
  const closed = accessEvents()
  assert.equal(closed.length, 2)
  assert.equal(closed[1].payload.suppressedCount, 2)
  // Vrai accès sans dedupKey : trace à chaque fois (zéro modification côté audit)
  broker.resolve('mcp-probe')
  broker.resolve('mcp-probe')
  assert.equal(accessEvents().length, 4)
  // Le payload d'événement n'a jamais le secret en clair
  assert.ok(!JSON.stringify(accessEvents()).includes('probe-secret'))
})
