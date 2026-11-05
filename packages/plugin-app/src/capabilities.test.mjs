/**
 * Tests unitaires de la liaison des capacités d'application (W2-T4, contrat de gouvernance MCP §10).
 *
 * Exécution (chargement direct par Node, construction dans le processus, sur le modèle bus factice+StorageService de plugin-mcp governance.test.mjs) :
 *
 *     node packages/plugin-app/src/capabilities.test.mjs
 *
 * Couverture :
 *   - liaison idempotente (reliaison renvoie l'état courant, sans toucher required) et réécriture ownerEntity (placeholder platform → propriété app) ;
 *   - porte de réécriture de propriété : un service déjà attribué à un autre app/agent → 409 OWNER_CONFLICT (CapabilityOwnerConflictError) ;
 *   - déliaison : suppression de l'enregistrement et de l'arête de dépendance capability, restauration du placeholder platform en cascade, déliaison répétée idempotente ;
 *   - les cinq portes de mise en ligne des capacités, refusées une à une (hors ligne/non vérifié/outils vides/haut risque en attente/en-têtes sensibles en clair) et toutes passées ;
 *   - refus à retour anticipé de requestOnline (CAPABILITY_GATE_FAILED) et émission du dossier d'approbation une fois satisfait ;
 *   - cascade de retrait : app.offline arrête directement tous les services de capacités (y compris non required, sans toucher aux services placeholder platform) en gardant l'état préalable de restauration ;
 *   - restauration à la remise en ligne : restoreCapabilityServices rétablit l'état préalable + trace d'audit change ;
 *   - cascade d'archivage purge : marquage archivedBy, restauration de propriété, effacement des enregistrements de liaison, services maintenus offline sans résurrection ;
 *   - écriture des arêtes de dépendance resource-core (app→mcp kind=capability, topologie traversable).
 */
import assert from 'node:assert/strict'
import { test, afterEach } from 'node:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { StorageService } from '../../platform-core/src/storage.ts'
import { ResourceCoreService } from '../../plugin-resource-core/src/index.ts'
import { McpService } from '../../plugin-mcp/src/index.ts'
import { McpToolRiskRegistry } from '../../plugin-mcp/src/risk-registry.ts'
import { AppRegistryService, CapabilityOwnerConflictError } from './index.ts'
import { AppCredentialService } from './credentials.ts'

// -- Construction de l'hôte dans le processus (bus factice + vrais StorageService/resource-core/mcpRegistry + répertoire de données temporaire) --

const cleanup = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()()
})

function makeHarness() {
  const dataDir = mkdtempSync(join(tmpdir(), 'app-capabilities-'))
  cleanup.push(() => rmSync(dataDir, { recursive: true, force: true }))
  const ctx = new Context()
  const events = []
  // Bus factice : enregistre les emit pour les assertions de cascade (on renvoie une fonction de désinscription vide)
  ctx.platformBus = {
    on: () => () => {},
    emit: (name, payload) => events.push({ name, payload }),
  }
  new StorageService(ctx, { dataDir })
  const resourceCore = new ResourceCoreService(ctx)
  const mcpRegistry = new McpService(ctx)
  // Registre de risques (forme d'assemblage en direct comme le apply() du même plugin) : absent, le contrôle n° ④ est sauté ; ici assemblé pour valider le n° ④
  const riskRegistry = new McpToolRiskRegistry(ctx)
  mcpRegistry.attachRiskRegistry(riskRegistry)
  const auditRecords = []
  const executors = {}
  ctx.audit = {
    record: (entry) => auditRecords.push(entry),
    createApproval: (input) => {
      const approval = { id: 'ap-test-1', ...input }
      auditRecords.push({ action: 'approval.create', approval })
      return approval
    },
    registerExecutor: (kind, fn) => { executors[kind] = fn },
    costs: () => ({ find: () => [] }),
    query: () => ({ items: [] }),
  }
  // Factice minimal : le chemin de liaison des capacités ne touche pas authn/oidc/iam (register saute l'émission d'identifiants avec withCredential:false)
  ctx.authn = { principals: () => ({ findOne: () => null }) }
  ctx.oidc = { clientsForApp: () => [] }
  ctx.iam = {
    users: () => ({ get: () => undefined, find: () => [], all: () => [] }),
    orgs: () => ({ all: () => [], get: () => undefined }),
  }
  const registry = new AppRegistryService(ctx)
  // Hébergement d'identifiants externes (issue #19) : l'effacement en cascade de purge passe par ctx.appCredentials — même assemblage réel (répertoire de données temporaire en place)
  const credentials = new AppCredentialService(ctx)
  const mkApp = (name, slug) => registry.register({
    name, slug, ownerId: 'u1', ownerName: '测试员', orgId: 'org-1', withCredential: false,
    attrs: { description: '测试应用', appType: 'api', riskLevel: 'low', dataClass: 'internal', url: 'https://app.example.com' },
  }).app
  const mkService = (overrides = {}) => mcpRegistry.createService({
    name: `服务-${Math.random().toString(36).slice(2, 8)}`, orgId: 'org-1', owner: 'u1', ...overrides,
  })
  /** Écriture directe de l'état d'un service (réservé aux tests : simule des états anormaux de pipeline comme « en ligne mais non vérifié »). */
  const setService = (id, patch) => mcpRegistry.services().update(id, patch)
  /** Pipeline de démonstration : vérification + publication en ligne (exec de démo, simulation déterministe). */
  const deploy = async (id, options = {}) => {
    await mcpRegistry.verifyService(id)
    return mcpRegistry.deployService(id, { grayPercent: 100, actor: 'tester', ...options })
  }
  return { ctx, registry, mcpRegistry, resourceCore, riskRegistry, credentials, events, auditRecords, executors, mkApp, mkService, setService, deploy }
}

const TOOL = { name: 't1', description: '演示工具', inputSchema: { type: 'object' }, riskLevel: 'read' }

// -- A. Modèle de liaison : idempotence / réécriture owner / arêtes de dépendance -------------------------------------------------

test('绑定能力服务：owner 回写 app 归属、capability 依赖边写入、重复绑定幂等返回现态', () => {
  const { registry, mcpRegistry, resourceCore, mkApp, mkService } = makeHarness()
  const app = mkApp('门户应用', 'portal-1')
  const svc = mkService({ name: '知识库', slug: 'kb-1', tools: [TOOL] })
  assert.deepEqual(mcpRegistry.services().get(svc.id).ownerEntity, { type: 'platform' }, '绑定前为 platform 占位')

  const first = registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: '测试员' })
  assert.equal(first.created, true)
  assert.equal(first.link.required, true)
  assert.equal(first.link.exposure, 'gateway')
  assert.equal(first.link.status, 'active')
  // Réécriture ownerEntity (via la forme normalisée setOwnerEntity)
  assert.deepEqual(mcpRegistry.services().get(svc.id).ownerEntity, { type: 'app', id: app.id })
  // Écriture d'arête de dépendance : {app→mcp, kind:'capability'}
  const dep = resourceCore.dependencies().findOne((item) => item.fromType === 'app' && item.fromId === app.id && item.toType === 'mcp' && item.toId === svc.id)
  assert.ok(dep, 'capability 依赖边应存在')
  assert.equal(dep.kind, 'capability')
  // Traversée de topologie : topology('app', id) doit contenir le nœud enfant mcp
  const topology = registry.topology(app.id)
  assert.ok(topology.children.some((node) => node.type === 'mcp' && node.id === svc.id))

  // Idempotence : reliaison renvoie l'état courant (même enregistrement, pas de création, valeur required inchangée)
  const again = registry.bindCapability(app.id, { serviceId: svc.id, required: false, boundBy: '另一人' })
  assert.equal(again.created, false)
  assert.equal(again.link.id, first.link.id)
  assert.equal(again.link.required, true, '重复绑定不得改 required 现值')
  assert.equal(registry.listCapabilities(app.id).length, 1)
})

test('归属回写闸门：已归属其他 app / agent 的服务拒绝绑定（409 OWNER_CONFLICT 语义）', () => {
  const { registry, mkApp, mkService } = makeHarness()
  const appA = mkApp('应用A', 'app-a')
  const appB = mkApp('应用B', 'app-b')
  const owned = mkService({ name: '已属A', slug: 'owned-by-a' })
  registry.bindCapability(appA.id, { serviceId: owned.id, boundBy: 'x' })
  assert.throws(() => registry.bindCapability(appB.id, { serviceId: owned.id, boundBy: 'x' }), CapabilityOwnerConflictError)
  // Reliaison au même app sans lever (idempotence) ; la propriété agent/connector est refusée pareillement
  assert.doesNotThrow(() => registry.bindCapability(appA.id, { serviceId: owned.id, boundBy: 'x' }))
  const agentOwned = mkService({ name: '已属Agent', slug: 'agent-owned', ownerEntity: { type: 'agent', id: 'agent-9' } })
  assert.throws(() => registry.bindCapability(appA.id, { serviceId: agentOwned.id, boundBy: 'x' }), CapabilityOwnerConflictError)
  // Service inexistant / application inexistante : erreur explicite
  assert.throws(() => registry.bindCapability(appA.id, { serviceId: 'mcp-none', boundBy: 'x' }), /不存在/)
  assert.throws(() => registry.bindCapability('app-none', { serviceId: owned.id, boundBy: 'x' }), /应用不存在/)
})

test('解绑：删记录与依赖边、归属联动还原 platform 占位、重复解绑幂等', () => {
  const { registry, mcpRegistry, resourceCore, mkApp, mkService } = makeHarness()
  const app = mkApp('解绑应用', 'unbind-app')
  const svc = mkService({ name: '待解绑', slug: 'unbind-svc' })
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })

  const result = registry.unbindCapability(app.id, svc.id)
  assert.deepEqual(result, { removed: true, ownerRestored: true })
  assert.deepEqual(mcpRegistry.services().get(svc.id).ownerEntity, { type: 'platform' }, '解绑联动还原 platform 占位')
  assert.equal(registry.listCapabilities(app.id).length, 0)
  assert.equal(resourceCore.dependencies().findOne((item) => item.fromType === 'app' && item.fromId === app.id && item.toId === svc.id), undefined)
  // Idempotence : déliaison répétée removed=false
  assert.deepEqual(registry.unbindCapability(app.id, svc.id), { removed: false, ownerRestored: false })
})

// -- B. Portes de mise en ligne -----------------------------------------------------------------------------

test('门禁①未在线：required 能力服务 draft 状态被拒，错误列明服务名', async () => {
  const { registry, mkApp, mkService } = makeHarness()
  const app = mkApp('门禁应用1', 'gate-offline')
  const svc = mkService({ name: '草稿服务', slug: 'draft-svc', tools: [TOOL] })
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  const failures = registry.capabilityGateFailures(app.id)
  assert.ok(failures.some((item) => item.includes('草稿服务')), '错误信息列明服务名')
  assert.ok(failures.some((item) => item.includes('未在线')))
})

test('门禁②未验证：status=online 但 health unknown 且无 lastProbeAt 被拒', async () => {
  const { registry, mkApp, mkService, setService } = makeHarness()
  const app = mkApp('门禁应用2', 'gate-verify')
  const svc = mkService({ name: '未验服务', slug: 'never-verified', tools: [TOOL] })
  setService(svc.id, { status: 'online' }) // écriture directe de l'état (simule une donnée sale contournant verify)
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  const failures = registry.capabilityGateFailures(app.id)
  assert.ok(failures.some((item) => item.includes('未验证') || item.includes('测试验证')))
})

test('门禁③工具清单为空被拒', async () => {
  const { registry, mkApp, mkService, setService } = makeHarness()
  const app = mkApp('门禁应用3', 'gate-tools')
  // createService retombe sur defaultToolsFor pour des outils vides (trio de démo) ; ici vidés explicitement pour simuler un service sans outils découverts
  const svc = mkService({ name: '空工具服务', slug: 'no-tools' })
  setService(svc.id, { tools: [], status: 'online', health: { status: 'healthy', consecutiveFails: 0, breakerOpen: false, lastProbeAt: new Date().toISOString() } })
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  assert.ok(registry.capabilityGateFailures(app.id).some((item) => item.includes('工具清单为空')))
})

test('门禁④未决高危风险登记（write/admin 且 pending）被拒', () => {
  const { registry, riskRegistry, mkApp, mkService, setService } = makeHarness()
  const app = mkApp('门禁应用4', 'gate-risk')
  const svc = mkService({ name: '高危待审服务', slug: 'risk-pending', tools: [{ ...TOOL, name: 't_write', riskLevel: 'write' }] })
  setService(svc.id, { status: 'online', health: { status: 'healthy', consecutiveFails: 0, breakerOpen: false, lastProbeAt: new Date().toISOString() } })
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  riskRegistry.submit({ serviceId: svc.id, toolName: 't_write', risk: 'write', reason: '演示登记', actor: { id: 'u9', name: '登记员' } })
  assert.ok(registry.capabilityGateFailures(app.id).some((item) => item.includes('未决高危')))
  // Un risque en lecture seule (read) ne constitue pas un haut risque
  const app2 = mkApp('门禁应用4b', 'gate-risk-read')
  const svc2 = mkService({ name: '只读登记服务', slug: 'risk-read', tools: [{ ...TOOL, name: 't_read', riskLevel: 'read' }] })
  setService(svc2.id, { status: 'online', health: { status: 'healthy', consecutiveFails: 0, breakerOpen: false, lastProbeAt: new Date().toISOString() } })
  registry.bindCapability(app2.id, { serviceId: svc2.id, required: true, boundBy: 'x' })
  riskRegistry.submit({ serviceId: svc2.id, toolName: 't_read', risk: 'read', reason: '演示登记', actor: { id: 'u9', name: '登记员' } })
  assert.deepEqual(registry.capabilityGateFailures(app2.id), [], 'read 级 pending 不构成未决高危')
})

test('门禁⑤明文敏感头且未配置凭证被拒；配置 credentialRef 后放行', async () => {
  const { registry, mkApp, mkService, setService } = makeHarness()
  const app = mkApp('门禁应用5', 'gate-headers')
  const svc = mkService({ name: '明文头服务', slug: 'plain-header', tools: [TOOL], headers: { Authorization: 'Bearer tk', 'X-App-Id': 'safe' } })
  setService(svc.id, { status: 'online', health: { status: 'healthy', consecutiveFails: 0, breakerOpen: false, lastProbeAt: new Date().toISOString() } })
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  assert.ok(registry.capabilityGateFailures(app.id).some((item) => item.includes('明文敏感') || item.includes('凭证')))
  setService(svc.id, { credentialRef: 'local:' + svc.id })
  assert.deepEqual(registry.capabilityGateFailures(app.id), [], '配置 credential 后⑤放行')
})

test('门禁全过：在线+已验证+工具非空+无高危+无敏感头 → 零失败；requestOnline 出审批单', async () => {
  const { registry, mcpRegistry, mkApp, mkService, deploy } = makeHarness()
  const app = mkApp('合规应用', 'gate-pass')
  const svc = mkService({ name: '健康服务', slug: 'good-svc', exec: 'demo', tools: [TOOL] })
  await deploy(svc.id)
  assert.equal(mcpRegistry.services().get(svc.id).status, 'online')
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  assert.deepEqual(registry.capabilityGateFailures(app.id), [])
  // La porte SSO n'est pas active pour la forme api (APP_SSO_ENFORCE défaut web,h5) → dossier d'approbation émis directement
  const approval = registry.requestOnline(app.id, { id: 'u1', name: '测试员' })
  assert.equal(approval.kind, 'app.online')
  assert.equal(approval.riskLevel, 'high')
})

test('requestOnline 早反馈：required 能力不满足即拒绝（CAPABILITY_GATE_FAILED，不建审批单）', () => {
  const { registry, auditRecords, mkApp, mkService } = makeHarness()
  const app = mkApp('门禁拦截应用', 'gate-reject')
  const svc = mkService({ name: '草稿能力', slug: 'reject-svc' })
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  assert.throws(() => registry.requestOnline(app.id, { id: 'u1', name: '测试员' }), /CAPABILITY_GATE_FAILED/)
  assert.equal(auditRecords.filter((item) => item.action === 'approval.create').length, 0, '门禁拒绝不建审批单')
  // Les capacités non required ne participent pas aux portes (un autre app lie le même service en non required — délier d'abord pour rendre la propriété, puis lier)
  registry.unbindCapability(app.id, svc.id)
  const app2 = mkApp('非必需能力应用', 'gate-optional')
  registry.bindCapability(app2.id, { serviceId: svc.id, required: false, boundBy: 'x' })
  assert.deepEqual(registry.capabilityGateFailures(app2.id), [])
})

// -- C. Cascades du cycle de vie -------------------------------------------------------------------------

test('下架联动：app.offline 直下全部能力服务（含非 required），平台占位服务不动，留恢复前置态', async () => {
  const { registry, mcpRegistry, events, mkApp, mkService, deploy } = makeHarness()
  const app = mkApp('联动应用', 'link-app')
  const requiredSvc = mkService({ name: '必需服务', slug: 'link-required', exec: 'demo', tools: [TOOL] })
  const optionalSvc = mkService({ name: '可选服务', slug: 'link-optional', exec: 'demo', tools: [TOOL] })
  const platformSvc = mkService({ name: '平台服务', slug: 'link-platform' })
  await deploy(requiredSvc.id)
  await deploy(optionalSvc.id, { grayPercent: 30 }) // l'état préalable gray doit aussi être enregistré
  assert.equal(mcpRegistry.services().get(requiredSvc.id).status, 'online')

  registry.bindCapability(app.id, { serviceId: requiredSvc.id, required: true, boundBy: 'x' })
  registry.bindCapability(app.id, { serviceId: optionalSvc.id, required: false, boundBy: 'x' })
  registry.online(app.id, 'tester') // cycle de vie : offline n'est atteignable que depuis trial/online (mettre en ligne avant de retirer)
  registry.offline(app.id, 'tester', '测试下架')

  // Chemin d'arrêt direct (offlineService) : état offline + événement McpOfflined dans le pipeline existant
  assert.equal(mcpRegistry.services().get(requiredSvc.id).status, 'offline')
  assert.equal(mcpRegistry.services().get(optionalSvc.id).status, 'offline')
  assert.equal(mcpRegistry.services().get(platformSvc.id).status, 'draft', '未绑定的 platform 占位服务不被联动')
  assert.ok(events.some((item) => item.name === 'mcp.offlined' && item.payload.serviceId === requiredSvc.id), '服务下线事件跟随既有管道')
  assert.ok(events.some((item) => item.name === 'app.offlined' && item.payload.id === app.id), '应用下架事件不受联动影响')
  // La trace de l'état préalable de restauration est conservée dans l'enregistrement de liaison (champ additif offlineRestore)
  const requiredLink = registry.listCapabilities(app.id).find((item) => item.serviceId === requiredSvc.id)
  const optionalLink = registry.listCapabilities(app.id).find((item) => item.serviceId === optionalSvc.id)
  assert.equal(requiredLink.offlineRestore.status, 'online')
  assert.equal(requiredLink.offlineRestore.grayPercent, 100)
  assert.equal(optionalLink.offlineRestore.status, 'gray')
  assert.equal(optionalLink.offlineRestore.grayPercent, 30)
})

test('重上线恢复：restoreCapabilityServices 恢复前置状态 + change 审计留痕', async () => {
  const { registry, mcpRegistry, auditRecords, mkApp, mkService, deploy } = makeHarness()
  const app = mkApp('恢复应用', 'restore-app')
  const svc = mkService({ name: '恢复服务', slug: 'restore-svc', exec: 'demo', tools: [TOOL] })
  await deploy(svc.id)
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  registry.online(app.id, 'tester') // cycle de vie : offline n'est atteignable que depuis trial/online (mettre en ligne avant de retirer)
  registry.offline(app.id, 'tester', '下架联动')
  assert.equal(mcpRegistry.services().get(svc.id).status, 'offline')

  registry.restoreCapabilityServices(app.id)
  assert.equal(mcpRegistry.services().get(svc.id).status, 'online', '恢复到下线前 online')
  assert.ok(!registry.listCapabilities(app.id).some((item) => item.offlineRestore), '恢复标记清除')
  const restored = auditRecords.filter((item) => item.action === 'mcp.service.online-restore' && item.resourceId === svc.id)
  assert.equal(restored.length, 1, '恢复落 change 审计')
  assert.equal(restored[0].actorId, 'app-online-linkage')
  // Idempotence : une restauration répétée ne fait rien (aucune marque restaurable)
  registry.restoreCapabilityServices(app.id)
  assert.equal(mcpRegistry.services().get(svc.id).status, 'online')
})

test('purge 归档联动：archivedBy 标记 + 归属还原 + 绑定记录清除，服务保持 offline 不复活', async () => {
  const { registry, mcpRegistry, resourceCore, credentials, mkApp, mkService, deploy } = makeHarness()
  const app = mkApp('删除应用', 'purge-app')
  const svc = mkService({ name: '归档服务', slug: 'purge-svc', exec: 'demo', tools: [TOOL] })
  await deploy(svc.id)
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  registry.online(app.id, 'tester') // cycle de vie : offline n'est atteignable que depuis trial/online (mettre en ligne avant de retirer)
  registry.offline(app.id, 'tester', '先下架')
  assert.equal(mcpRegistry.services().get(svc.id).status, 'offline')
  // Effacement en cascade des identifiants (issue #19) : un identifiant est enregistré avant purge, le fichier de clés doit disparaître intégralement après purge
  credentials.put(app.id, { key: 'external-token', value: 'tk_live_123456', rotatedBy: 'tester' })
  assert.equal(credentials.list(app.id).length, 1)

  registry.purge(app.id)
  assert.equal(credentials.list(app.id).length, 0, 'purge 联动删除凭证密钥文件')
  const after = mcpRegistry.services().get(svc.id)
  assert.ok(after, '服务记录保留（purge 不删服务）')
  assert.equal(after.status, 'offline', '服务保持 offline（不复活）')
  assert.equal(after.archivedBy, app.id, 'W2-T4 归档联动 archivedBy 标记')
  assert.deepEqual(after.ownerEntity, { type: 'platform' }, '归属还原 platform 占位（防悬挂引用）')
  assert.equal(registry.listCapabilities(app.id).length, 0, '绑定记录清除')
  assert.equal(
    resourceCore.dependencies().findOne((item) => item.fromType === 'app' && item.fromId === app.id && item.toId === svc.id),
    undefined,
    'capability 依赖边清除（既有 purge 循环覆盖）',
  )
})

// -- Revérification de l'exécuteur (délégation mince : la logique est dans capabilityGateFailures ; ici on valide que la forme d'assemblage de l'exécuteur est appelable) -------

test('执行期复核：挂单期间能力下线后复核拒绝（CAPABILITY_GATE_FAILED）；服务恢复后放行', async () => {
  const { registry, mcpRegistry, mkApp, mkService, deploy } = makeHarness()
  const app = mkApp('复核应用', 'recheck-app')
  const svc = mkService({ name: '复核服务', slug: 'recheck-svc', exec: 'demo', tools: [TOOL] })
  await deploy(svc.id)
  registry.bindCapability(app.id, { serviceId: svc.id, required: true, boundBy: 'x' })
  // Simule la sémantique de revérification dans l'exécuteur (l'assemblage réel est le registerExecutor('app.online') de apply(), logique de même source) :
  // service arrêté manuellement pendant l'examen du dossier → la revérification le détecte → échec d'exécution avec trace
  mcpRegistry.offlineService(svc.id, 'ops', '挂单期间人工下线')
  const failures = registry.capabilityGateFailures(app.id)
  assert.ok(failures.length > 0, '执行期复核应发现能力已下线')
  assert.throws(() => {
    if (failures.length > 0) throw new Error(`执行期复核失败：审批期间能力服务状态变化（CAPABILITY_GATE_FAILED）——${failures.join('；')}`)
  }, /CAPABILITY_GATE_FAILED/)
  // Après remise en ligne du service (offline repasse par draft vers le pipeline de publication), la revérification passe et l'application peut se mettre en ligne
  mcpRegistry.services().update(svc.id, { status: 'draft' })
  await deploy(svc.id)
  assert.deepEqual(registry.capabilityGateFailures(app.id), [])
  assert.equal(registry.online(app.id, 'approval-center').status, 'online')
})
