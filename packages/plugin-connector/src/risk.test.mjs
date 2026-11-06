/**
 * Tests unitaires du catalogue de risques des connecteurs (déclaratifisation R6, 2026-10-13).
 *
 * Mode d'exécution (chargement direct par Node) :
 *
 *     node packages/plugin-connector/src/risk.test.mjs
 *
 * Couverture :
 *   - chaîne de priorité de resolveRiskLevel : riskLevel explicite > actions déclarées > defaultRisk déclaré
 *     > heuristique (avec dernier recours admin fail-closed) ;
 *   - le paramètre service prime sur le champ action.service ;
 *   - lecture étagée riskTierOf (avec/sans déclaration) ;
 *   - le généré risk-overrides.generated.ts correspond clé à clé avec la source de fait catalog/risk-overrides.json
 *     (contre la dérive « JSON modifié mais gen-connector-catalog.mjs oublié »).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { RISK_OVERRIDES } from './risk-overrides.generated.ts'
import { heuristicRiskLevel, resolveRiskLevel, riskTierOf } from './risk.ts'

// -- Chaîne de priorité : riskLevel explicite > actions déclarées > defaultRisk déclaré > heuristique ------------

test('优先级① action 显式 riskLevel 胜过声明目录（前向兼容上游加字段）', () => {
  // github.create_issue vaut write dans le catalogue déclaré, un read explicite est directement retenu
  assert.equal(resolveRiskLevel({ id: 'github.create_issue', service: 'github', riskLevel: 'read' }), 'read')
  assert.equal(resolveRiskLevel({ id: 'github.delete_webhook', service: 'github', riskLevel: 'write' }), 'write')
})

test('优先级② 声明 actions 级胜过 provider defaultRisk', () => {
  // github defaultRisk=write, delete_webhook déclaré explicitement admin
  assert.equal(resolveRiskLevel({ id: 'github.delete_webhook', service: 'github' }), 'admin')
  // hackernews defaultRisk=read, do_the_thing déclaré explicitement admin (la face fail-closed est conservée)
  assert.equal(resolveRiskLevel({ id: 'hackernews.do_the_thing', service: 'hackernews' }), 'admin')
})

test('优先级③ 声明 defaultRisk 胜过名称/作用域启发式（声明即口径）', () => {
  // Action non déclarée : un nom contenant delete/destroy donnerait admin par heuristique, mais github defaultRisk=write s'applique
  const undeclared = { id: 'github.destroy_organization', name: 'destroy organization', service: 'github' }
  assert.equal(heuristicRiskLevel(undeclared), 'admin', '启发式对照面：本应 admin')
  assert.equal(resolveRiskLevel(undeclared), 'write', '声明 defaultRisk 覆盖启发式')
})

test('优先级④ 无声明 provider 回落启发式（scope/名称判定仍生效）', () => {
  assert.equal(resolveRiskLevel({ id: 'zapp.list_widgets', service: 'zapp', requiredScopes: ['data:read'] }), 'read')
  assert.equal(resolveRiskLevel({ id: 'zapp.push_event', service: 'zapp', requiredScopes: ['events:write'] }), 'write')
})

test('优先级⑤ 无声明且无可判定依据 → admin 兜底 fail-closed', () => {
  assert.equal(resolveRiskLevel({ id: 'zapp.do_the_thing', service: 'zapp' }), 'admin')
  assert.equal(resolveRiskLevel({ id: 'zapp.do_the_thing' }), 'admin')
})

// -- Référentiel de résolution service ----------------------------------------------------------

test('service 入参优先于 action.service 字段；缺省时取 action.service', () => {
  assert.equal(resolveRiskLevel({ id: 'github.delete_webhook', service: 'hackernews' }, 'github'), 'admin', '显式入参 github 生效')
  assert.equal(resolveRiskLevel({ id: 'github.delete_webhook', service: 'hackernews' }), 'read', '无入参回落 action.service=hackernews 的 defaultRisk')
  assert.equal(resolveRiskLevel({ id: 'github.delete_webhook' }), 'admin', '两者皆缺 → 无声明回落启发式（名称 delete → admin）')
})

// -- Lecture étagée riskTier ----------------------------------------------------------

test('riskTierOf：有声明返回 S1/S2，无声明返回 undefined', () => {
  assert.equal(riskTierOf('github'), 'S2')
  assert.equal(riskTierOf('hackernews'), 'S1')
  assert.equal(riskTierOf('zapp'), undefined)
  assert.equal(riskTierOf(''), undefined)
  assert.equal(riskTierOf(undefined), undefined)
})

// -- Cohérence généré/source de fait (contre la dérive gen-connector-catalog.mjs oublié) ------------------

test('生成物与 catalog/risk-overrides.json 逐键一致', () => {
  const jsonPath = fileURLToPath(new URL('../catalog/risk-overrides.json', import.meta.url))
  const declared = JSON.parse(readFileSync(jsonPath, 'utf8'))
  assert.deepEqual(RISK_OVERRIDES, declared.providers, 'RISK_OVERRIDES 必须等于 JSON 的 providers 面（键序无关）')
})

test('声明目录自身取值合法（风险级 read|write|admin、tier S1|S2、provider 名规范）', () => {
  const providerName = /^[a-z0-9-]+$/
  for (const [service, entry] of Object.entries(RISK_OVERRIDES)) {
    assert.match(service, providerName, `provider 名须满足 ${providerName.source}`)
    assert.ok(['read', 'write', 'admin'].includes(entry.defaultRisk), `${service}.defaultRisk 取值合法`)
    assert.ok(['S1', 'S2'].includes(entry.riskTier), `${service}.riskTier 取值合法`)
    for (const [actionId, level] of Object.entries(entry.actions ?? {})) {
      assert.ok(actionId.length > 0, `${service} 存在空 action id`)
      assert.ok(['read', 'write', 'admin'].includes(level), `${service}.${actionId} 风险级取值合法`)
    }
  }
})
