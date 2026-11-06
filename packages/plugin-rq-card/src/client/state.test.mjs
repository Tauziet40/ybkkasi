/**
 * Auto-attestation de la fonction pure de mise en correspondance des quatre états (tests associés au livrable 2 de WP-06).
 *
 * Mode d'exécution (Node ≥22.18 charge TS nativement, state.ts sans dépendance, donc sans aucun build) :
 *
 *     node packages/plugin-rq-card/src/client/state.test.mjs
 *
 * Couverture : un cas par état + les six codes de blocage chacun atteints + chaîne de priorité (retrait des marqueurs un à un) +
 * information additionnelle degraded + sémantique fail-safe (blocage prioritaire sur terminé/en appel) +
 * code de repli invoke-error de l'anomalie au niveau résultat.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { deriveExecutionState } from './state.ts'

/** Entrée toute vide (sans résultat, sans invoke, face santé unknown). */
const IDLE = { hasResult: false, resultIsError: false, invokePhase: 'idle' }

test('四态之 idle：无结果、无 invoke、健康面 unknown', () => {
  assert.deepEqual(deriveExecutionState(IDLE), { state: 'idle' })
})

test('四态之 calling：invoke 发起中（C2 表第一行：mcp invoke() 发起中）', () => {
  assert.deepEqual(
    deriveExecutionState({ ...IDLE, invokePhase: 'calling' }),
    { state: 'calling' },
  )
  // le segment de lancement prime sur la face santé : les deux présents au même instant, présenter le segment de lancement (squelette + annulable).
  assert.deepEqual(
    deriveExecutionState({ ...IDLE, invokePhase: 'calling', healthStatus: 'healthy' }),
    { state: 'calling' },
  )
})

test('四态之 executing：health healthy（C2 表：online/gray 且 health∈{healthy,degraded}）', () => {
  assert.deepEqual(
    deriveExecutionState({ ...IDLE, healthStatus: 'healthy' }),
    { state: 'executing' },
  )
})

test('执行中 + degraded：附「有点慢」信息（degraded:true）', () => {
  assert.deepEqual(
    deriveExecutionState({ ...IDLE, healthStatus: 'degraded' }),
    { state: 'executing', degraded: true },
  )
  // un état non executing ne porte pas le marqueur degraded.
  assert.equal(deriveExecutionState({ ...IDLE, healthStatus: 'degraded', hasResult: true, resultIsError: false }).degraded, undefined)
  assert.equal(deriveExecutionState({ ...IDLE, healthStatus: 'degraded', invokePhase: 'calling' }).degraded, undefined)
})

test('四态之 done：调用返回且非错误（C2 表：调用返回 + usage.recorded 落库）', () => {
  assert.deepEqual(
    deriveExecutionState({ hasResult: true, resultIsError: false, invokePhase: 'idle' }),
    { state: 'done' },
  )
})

test('四态之 blocked：六码各自命中（C2 表：down/breakerOpen/nas-authz deny/额度耗尽 + PDP/绑定）', () => {
  const cases = [
    [{ authzDenied: true }, 'nas-authz-deny'],
    [{ quotaExceeded: true }, 'quota-exhausted'],
    [{ pdpUnreachable: true }, 'pdp-unreachable'],
    [{ breakerOpen: true }, 'breaker-open'],
    [{ healthStatus: 'down' }, 'down'],
    [{ bindingInvalid: true }, 'binding-invalid'],
  ]
  for (const [flags, reason] of cases) {
    assert.deepEqual(
      deriveExecutionState({ ...IDLE, ...flags }),
      { state: 'blocked', reason },
    )
  }
})

test('异常阻断优先级：authzDenied > quotaExceeded > pdpUnreachable > breakerOpen > down > bindingInvalid', () => {
  const all = {
    ...IDLE,
    authzDenied: true,
    quotaExceeded: true,
    pdpUnreachable: true,
    breakerOpen: true,
    healthStatus: 'down',
    bindingInvalid: true,
  }
  // tout présent → prendre la priorité la plus haute ; puis retirer un à un, vérifier toute la chaîne de priorité.
  const chain = [
    [{}, 'nas-authz-deny'],
    [{ authzDenied: false }, 'quota-exhausted'],
    [{ authzDenied: false, quotaExceeded: false }, 'pdp-unreachable'],
    [{ authzDenied: false, quotaExceeded: false, pdpUnreachable: false }, 'breaker-open'],
    [{ authzDenied: false, quotaExceeded: false, pdpUnreachable: false, breakerOpen: false }, 'down'],
    [{ authzDenied: false, quotaExceeded: false, pdpUnreachable: false, breakerOpen: false, healthStatus: 'unknown' }, 'binding-invalid'],
  ]
  for (const [unset, reason] of chain) {
    assert.deepEqual(deriveExecutionState({ ...all, ...unset }), { state: 'blocked', reason })
  }
})

test('fail-safe：阻断标志优先于已完成/调用中（不呈现历史结果）', () => {
  assert.deepEqual(
    deriveExecutionState({ hasResult: true, resultIsError: false, invokePhase: 'idle', authzDenied: true }),
    { state: 'blocked', reason: 'nas-authz-deny' },
  )
  assert.deepEqual(
    deriveExecutionState({ hasResult: true, resultIsError: false, invokePhase: 'calling', breakerOpen: true }),
    { state: 'blocked', reason: 'breaker-open' },
  )
})

test('结果级异常：isError 且无平台侧阻断标志 → blocked + 兜底码 invoke-error', () => {
  assert.deepEqual(
    deriveExecutionState({ hasResult: true, resultIsError: true, invokePhase: 'idle' }),
    { state: 'blocked', reason: 'invoke-error' },
  )
  // marqueurs côté plateforme présents → priorité plateforme maintenue (pas de chute sur le code de repli).
  assert.deepEqual(
    deriveExecutionState({ hasResult: true, resultIsError: true, invokePhase: 'idle', quotaExceeded: true }),
    { state: 'blocked', reason: 'quota-exhausted' },
  )
})

test('输出形状收窄：非 blocked 态不带 reason；blocked 必带 reason', () => {
  for (const state of [
    deriveExecutionState(IDLE),
    deriveExecutionState({ ...IDLE, invokePhase: 'calling' }),
    deriveExecutionState({ ...IDLE, healthStatus: 'healthy' }),
    deriveExecutionState({ hasResult: true, resultIsError: false, invokePhase: 'idle' }),
  ]) {
    assert.equal(state.reason, undefined)
    assert.ok(state.state !== 'blocked')
  }
  assert.ok(deriveExecutionState({ ...IDLE, bindingInvalid: true }).reason)
})
