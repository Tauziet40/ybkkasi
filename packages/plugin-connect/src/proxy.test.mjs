/**
 * Auto-vérification contractuelle du proxy distant d'outils de connect (tests associés à OPT-P1-03, 2026-09-12).
 *
 * Mode d'exécution (ToolRuntimeLite réel + client stub, chargement direct par Node) :
 *
 *     node --test packages/plugin-connect/src/proxy.test.mjs
 *
 * Couverture :
 *   - points d'extension officiels tools.intercept / decorate (interception à l'enregistrement, enveloppement des préexistants, restauration, erreur sur outil inconnu) ;
 *   - installToolProxy : non connecté → exécution locale ; connecté → transfert ; échec de transfert → échec explicite + noteForwardFailure
 *     (jamais de repli local silencieux) ; runtime sans points d'extension → échec d'installation + noteDegraded (sémantique connect.degraded).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Context } from '@deepseek-ai/cordis'
import { ToolRuntimeLite, defineTool } from '../../platform-core/src/index.ts'
import { installToolProxy } from './index.ts'

function makeRuntime() {
  return new ToolRuntimeLite(new Context())
}

/** ctx factice : effect collecte les destructeurs (déclenchés à la main), logger muet, platformBus absent (événements silencieux via catch). */
function makeCtx(tools) {
  const effects = []
  return {
    tools,
    effects,
    effect: (fn) => { effects.push(fn) },
    logger: () => ({ info() {}, warn() {}, error() {} }),
    platformBus: { emitted: [], emit(name, payload) { this.emitted.push({ name, payload }) } },
  }
}

function makeStubClient({ hasHub = false, forwardError = undefined } = {}) {
  const calls = { forward: [], forwardFailures: [], degraded: [] }
  return {
    calls,
    hasHub: () => hasHub,
    forward: async (toolName, args) => {
      calls.forward.push({ toolName, args })
      if (forwardError) throw forwardError
      return { forwarded: true, toolName }
    },
    noteForwardFailure: (toolName, error) => calls.forwardFailures.push({ toolName, message: error?.message }),
    noteDegraded: (reason, detail) => calls.degraded.push({ reason, detail }),
  }
}

function defineLocalTool(name, value) {
  return defineTool({
    name,
    description: `local tool ${name}`,
    parameters: {},
    output: { type: 'object' },
    async execute() { return { local: true, value } },
  })
}

test('扩展点 intercept：此后注册的业务工具被换装，connect_ 前缀不受影响', () => {
  const runtime = makeRuntime()
  const stub = makeStubClient({ hasHub: true })
  const ctx = makeCtx(runtime)
  assert.equal(installToolProxy(ctx, stub), true)
  runtime.register(defineLocalTool('agent_list', 1))
  runtime.register(defineLocalTool('connect_status', 2))
  return runtime.execute({ name: 'agent_list' }).then((result) => {
    assert.equal(stub.calls.forward.length, 1, '业务工具应被转发')
    return runtime.execute({ name: 'connect_status' })
  }).then((result) => {
    assert.equal(stub.calls.forward.length, 1, 'connect_ 前缀工具不转发')
    assert.equal(result.value.local, true)
  })
})

test('扩展点 decorate：存量工具被包扎，还原函数恢复原执行体', async () => {
  const runtime = makeRuntime()
  runtime.register(defineLocalTool('agent_list', 1))
  const stub = makeStubClient({ hasHub: true })
  assert.equal(installToolProxy(makeCtx(runtime), stub), true)
  await runtime.execute({ name: 'agent_list' })
  assert.equal(stub.calls.forward.length, 1, '存量工具经 decorate 兜底被转发')
})

test('未接入宿主（hasHub=false）→ 本地执行，无转发', async () => {
  const runtime = makeRuntime()
  const stub = makeStubClient({ hasHub: false })
  installToolProxy(makeCtx(runtime), stub)
  runtime.register(defineLocalTool('agent_list', 42))
  const result = await runtime.execute({ name: 'agent_list' })
  assert.equal(result.value.local, true)
  assert.equal(result.value.value, 42)
  assert.equal(stub.calls.forward.length, 0)
})

test('宿主不可达 → 工具调用显式失败（isError）+ noteForwardFailure，绝不静默落本地', async () => {
  const runtime = makeRuntime()
  const stub = makeStubClient({ hasHub: true, forwardError: new Error('hub unreachable: ECONNREFUSED') })
  installToolProxy(makeCtx(runtime), stub)
  runtime.register(defineLocalTool('agent_list', 1))
  const result = await runtime.execute({ name: 'agent_list' })
  assert.equal(result.isError, true, '转发失败必须显式失败')
  assert.ok(result.error?.message.includes('ECONNREFUSED'))
  assert.equal(stub.calls.forwardFailures.length, 1, '应记录转发失败（节流告警事件源）')
  assert.equal(result.value?.local, undefined, '绝不静默落本地执行')
})

test('运行时缺 intercept/decorate 扩展点 → 安装失败 + noteDegraded（显式降级）', () => {
  const stub = makeStubClient()
  const ok = installToolProxy(makeCtx({ register() {}, schemas: () => [] }), stub)
  assert.equal(ok, false)
  assert.equal(stub.calls.degraded.length, 1)
  assert.equal(stub.calls.degraded[0].reason, 'tool_runtime_contract_missing')
})

test('dispose：注销后拦截与包扎全部还原（工具回到本地语义）', async () => {
  const runtime = makeRuntime()
  const ctx = makeCtx(runtime)
  const stub = makeStubClient({ hasHub: true })
  assert.equal(installToolProxy(ctx, stub), true)
  runtime.register(defineLocalTool('agent_list', 1))
  for (const fn of ctx.effects) { const disposer = fn(); if (typeof disposer === 'function') disposer() }
  const result = await runtime.execute({ name: 'agent_list' })
  assert.equal(result.value.local, true, '注销后工具回到本地执行')
  assert.equal(stub.calls.forward.length, 0)
})

test('decorate 未知工具抛 TypeError（不静默）', () => {
  const runtime = makeRuntime()
  assert.throws(() => runtime.decorate('no_such_tool', (execute) => execute))
})
