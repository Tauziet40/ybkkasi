/**
 * Auto-validation du moteur de lint bidirectionnel contrat↔implémentation (OPT-P0-01, 2026-09-12, tests d'accompagnement).
 *
 * Mode d'exécution (moteur en fonctions pures + dépôt de fixtures synthétiques, chargement direct par Node) :
 *
 *     node --test scripts/contract-lint.test.mjs
 *
 * Couverture :
 *   - tests unitaires du normaliseur : déploiement des groupes de méthodes / candidates '|' / segments optionnels '[/seg]' / généralisation ':param' / retrait de query et d'annotations /
 *     saut des annotations de ligne / héritage des fragments relatifs / erreur sur fragment illégal ;
 *   - extraction de la surface code : guarded / http.register / defineTool+tools.register / littéraux de permission (valeurs multiples par virgule incluses) ;
 *   - rouge/vert constructifs (mini-dépôt synthétique) : route nouvelle non déclarée → rouge (avec numéro de ligne) ; endpoint fantôme d'api.yaml → rouge ;
     outil fantôme/outil non déclaré → rouge ; point de permission non déclaré → rouge ; manifeste complet → vert ; entrée d'exemption trouvée → dégradation transparente.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  runContractLint, parseEndpointLine, expandAlternatives, expandOptionalSegments,
  generalizePath, extractCodeSurface, extractEndpointLines,
} from './contract-lint.mjs'

// -- Tests unitaires du normaliseur --

test('方法组展开：GET/PUT 拆为两条', () => {
  const { routes, unparseable } = parseEndpointLine('GET/PUT /api/a · POST /api/b')
  assert.equal(unparseable.length, 0)
  assert.deepEqual(routes.map((r) => `${r.method} ${r.path}`), ['GET /api/a', 'PUT /api/a', 'POST /api/b'])
})

test("'|' 候选展开：段内多值", () => {
  assert.deepEqual(expandAlternatives('/api/x/:id/disable|enable|rotate'),
    ['/api/x/:id/disable', '/api/x/:id/enable', '/api/x/:id/rotate'])
})

test("'[/seg]' 可选段展开：有/无两型", () => {
  assert.deepEqual(expandOptionalSegments('/api/catalog/actions/:actionId[/guide]'),
    ['/api/catalog/actions/:actionId', '/api/catalog/actions/:actionId/guide'])
})

test("':param' 泛化消除参数命名差异", () => {
  assert.equal(generalizePath('/api/iam/connectors/:provider'), '/api/iam/connectors/:*')
  assert.equal(generalizePath('/api/iam/connectors/:param/test'), '/api/iam/connectors/:*/test')
})

test('查询串与全角注解剥离；# 行内注释剥离', () => {
  const { routes } = parseEndpointLine('GET /api/nas/:id/fs?path=&inline=（流式下载） # 备注')
  assert.deepEqual(routes.map((r) => r.path), ['/api/nas/:*/fs'])
})

test('行级 # 注解条目整体跳过（含 · 分隔的描述性内容）', () => {
  const { routes, notes } = parseEndpointLine('# client 本机面 http://127.0.0.1:7390（GET / · GET /api/status · POST /api/reset）')
  assert.equal(routes.length, 0)
  assert.equal(notes.length, 1)
})

test('相对片段继承上一绝对路径', () => {
  const { routes, unparseable } = parseEndpointLine('PUT /api/iam/scene-policies · DELETE /:id')
  assert.equal(unparseable.length, 0)
  assert.ok(routes.some((r) => r.path === '/api/iam/scene-policies/:*' && r.method === 'DELETE'))
})

test('非规范片段报 unparseable（不接受静默吞）', () => {
  const { unparseable } = parseEndpointLine('POST .../sync')
  assert.equal(unparseable.length, 1)
})

test('api.yaml 原文提取 endpoints 列表项', () => {
  const items = extractEndpointLines('plugin: p\nbase: /api\nendpoints:\n  - GET /a\n  - POST /b（注解）\ntools:\n  - t1\n')
  assert.deepEqual(items, ['GET /a', 'POST /b（注解）'])
})

test('代码面提取：guarded/http.register/工具/权限字面量（含逗号多值）', () => {
  const surface = extractCodeSurface([
    "  guarded('GET', '/api/x/:id', 'x.read', handler)",
    "  http.register('POST', '/api/y', handler, { access: 'guarded', permission: 'x.write' })",
    "  http.register('OPTIONS', '/api/y', preflight)", // le préflight CORS n'entre pas dans le contrat
    "  t.register(defineTool({ name: 'x_tool', permission: 'x.invoke,a.b' }))",
  ].join('\n'))
  assert.deepEqual(surface.routes.map((r) => `${r.method} ${r.path}`), ['GET /api/x/:*', 'POST /api/y'])
  assert.deepEqual(surface.tools.map((t) => t.name), ['x_tool'])
  assert.ok(surface.perms.includes('a.b') && surface.perms.includes('x.invoke'))
})

// -- Rouge/vert constructifs (mini-dépôt synthétique) --

async function makeFixtureRepo({ apiYaml, code, pluginYaml = "id: p\npermissions:\n  - x.read\n  - x.write\n", permissionsYaml = 'plugin: p\npoints:\n  - x.read\n  - x.write\n' }) {
  const root = await mkdtemp(join(tmpdir(), 'contract-lint-'))
  const pkg = join(root, 'packages', 'plugin-fixture')
  await mkdir(join(pkg, 'manifest'), { recursive: true })
  await mkdir(join(pkg, 'src'), { recursive: true })
  await writeFile(join(pkg, 'plugin.yaml'), pluginYaml, 'utf8')
  await writeFile(join(pkg, 'manifest', 'api.yaml'), `plugin: p\nbase: /api\nendpoints:\n${apiYaml.map((line) => `  - ${line}`).join('\n')}\ntools:\n  - fixture_tool\n`, 'utf8')
  await writeFile(join(pkg, 'manifest', 'permissions.yaml'), permissionsYaml, 'utf8')
  await writeFile(join(pkg, 'src', 'index.ts'), code, 'utf8')
  return root
}

const CLEAN_CODE = [
  "export function register(ctx) {",
  "  const guarded = (m, p, perm, h) => {}",
  "  guarded('GET', '/api/fixtures', 'x.read', () => {})",
  "  guarded('POST', '/api/fixtures', 'x.write', () => {})",
  "  ctx.tools.register(defineTool({ name: 'fixture_tool', permission: 'x.read' }))",
  "}",
].join('\n')

test('构造性绿：清单与代码一致 → ok 且 0 红', async () => {
  const root = await makeFixtureRepo({
    apiYaml: ['GET/POST /api/fixtures'],
    code: CLEAN_CODE,
  })
  try {
    const result = await runContractLint(root)
    const reds = result.diffs.filter((d) => d.severity === 'red' && d.message.includes('fixture'))
    assert.equal(reds.length, 0)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('构造性红：代码新增未声明路由 → route_undeclared 且报行号', async () => {
  const root = await makeFixtureRepo({
    apiYaml: ['GET/POST /api/fixtures'],
    code: CLEAN_CODE + "\nguarded('DELETE', '/api/fixtures/:id', 'x.write', () => {})",
  })
  try {
    const result = await runContractLint(root)
    const hit = result.diffs.find((d) => d.severity === 'red' && d.kind === 'route_undeclared' && d.message.includes('DELETE /api/fixtures/:*'))
    assert.ok(hit, '应报 route_undeclared')
    assert.ok(/index\.ts:\d+/.test(hit.message), `应含行号：${hit.message}`)
    assert.equal(result.ok, false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('构造性红：api.yaml 幽灵 endpoint → endpoint_ghost', async () => {
  const root = await makeFixtureRepo({
    apiYaml: ['GET/POST /api/fixtures · DELETE /api/ghost'],
    code: CLEAN_CODE,
  })
  try {
    const result = await runContractLint(root)
    assert.ok(result.diffs.some((d) => d.severity === 'red' && d.kind === 'endpoint_ghost' && d.message.includes('DELETE /api/ghost')))
    assert.equal(result.ok, false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('构造性红：幽灵工具与未声明工具双向', async () => {
  const root = await makeFixtureRepo({
    apiYaml: ['GET/POST /api/fixtures'],
    code: CLEAN_CODE.replace("name: 'fixture_tool'", "name: 'renamed_tool'"),
  })
  try {
    const result = await runContractLint(root)
    assert.ok(result.diffs.some((d) => d.kind === 'tool_ghost' && d.message.includes('fixture_tool')))
    assert.ok(result.diffs.some((d) => d.kind === 'tool_undeclared' && d.message.includes('renamed_tool')))
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('构造性红：代码引用未声明权限点 → perm_undeclared', async () => {
  const root = await makeFixtureRepo({
    apiYaml: ['GET/POST /api/fixtures'],
    code: CLEAN_CODE.replace("'x.write', () => {}", "'x.admin', () => {}"),
  })
  try {
    const result = await runContractLint(root)
    assert.ok(result.diffs.some((d) => d.kind === 'perm_undeclared' && d.message.includes('x.admin')))
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('豁免清单命中 → 透明降级不计红', async () => {
  const root = await makeFixtureRepo({
    apiYaml: ['GET/POST /api/fixtures · GET /api/legacy-only'],
    code: CLEAN_CODE,
  })
  await mkdir(join(root, 'scripts'), { recursive: true })
  await writeFile(join(root, 'scripts', 'contract-lint.exemptions.json'),
    JSON.stringify({ exemptions: [{ kind: 'endpoint_ghost', key: 'GET /api/legacy-only', reason: '夹具演练' }] }), 'utf8')
  try {
    const result = await runContractLint(root)
    const ghost = result.diffs.find((d) => d.kind === 'endpoint_ghost' && d.message.includes('/api/legacy-only'))
    assert.ok(ghost, '豁免项应仍出现在报告中（透明）')
    assert.equal(ghost.severity, 'exempt')
    assert.equal(result.ok, true)
  } finally { await rm(root, { recursive: true, force: true }) }
})
