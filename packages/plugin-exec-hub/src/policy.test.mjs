/**
 * Tests de la couche de décision pure du centre d'exécution (alignés sur l'énumération par tables de policy.test.ts de Paperclip).
 *
 * Mode d'exécution (chargement direct par Node) :
 *
 *     node --test packages/plugin-exec-hub/src/policy.test.mjs
 *
 * Couverture :
 *   - decideWakeAdmission : énumération exhaustive des trois états (2^6 combinaisons de faits) ;
 *   - decideReleaseRecovery : arbitrage des verrous zombies ;
 *   - normalizeAgentKey / matérialisation de lignée / assemblage de contexte ;
 *   - computeAgentHealth : frontières des cinq paliers ;
 *   - machine à états des tâches et sémantique de levée des dépendances ;
 *   - cron 5 champs : lexicographie et correspondance (dont la sémantique OU POSIX jour/semaine) ;
 *   - décision pure des baux d'exécution (décision 3 de l'annexe A) : idempotence de réclamation (même principal idempotent/autre principal refusé/expiré re-prenable),
 *     migration de renouvellement de bail (bail périmé stale), validation de principal du complete (D07), arbitrage d'adoption de run (V05).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  decideWakeAdmission, decideReleaseRecovery, normalizeAgentKey,
  materializeGoalAncestry, lineageSummary, buildIssueContextPack,
  computeAgentHealth, issueCanTransition, blockersResolved,
  cronMatches, cronIsValid, wakeIdempotencyKey,
  decideLeaseClaim, decideLeaseRenewal, decideCompleteOwnership, decideRunAdoption,
} from './domain.ts'

// ---------------------------------------------------------------------------
// decideWakeAdmission : énumération exhaustive 2^6
// ---------------------------------------------------------------------------

test('decideWakeAdmission：六事实全组合穷举与三态裁决', () => {
  const keys = [
    'isSameExecutionAgent', 'shouldDeferFollowupWake',
    'shouldQueueFollowupForRunningWake', 'availableActiveExecutionRunPresent',
    'allowRunCoalescing', 'sameDurableActor',
  ]
  let combinations = 0
  for (let mask = 0; mask < 64; mask += 1) {
    const facts = {}
    keys.forEach((key, index) => { facts[key] = Boolean((mask >> index) & 1) })
    const decision = decideWakeAdmission(facts)
    combinations += 1
    if (!facts.availableActiveExecutionRunPresent) {
      // pas de run actif : toujours proceed (les autres faits sont indifférents)
      assert.equal(decision.kind, 'proceed', `mask=${mask} 无活跃 run 应 proceed`)
    } else if (
      facts.isSameExecutionAgent && !facts.shouldDeferFollowupWake
      && !facts.shouldQueueFollowupForRunningWake && facts.allowRunCoalescing && facts.sameDurableActor
    ) {
      assert.equal(decision.kind, 'coalesce', `mask=${mask} 同 Agent 可合并应 coalesce`)
    } else {
      assert.equal(decision.kind, 'defer', `mask=${mask} 有活跃 run 不满足合并应 defer`)
    }
  }
  assert.equal(combinations, 64)
})

test('decideWakeAdmission：可选事实缺省语义（允许合并/同执行者）', () => {
  assert.equal(decideWakeAdmission({
    isSameExecutionAgent: true, shouldDeferFollowupWake: false,
    shouldQueueFollowupForRunningWake: false, availableActiveExecutionRunPresent: true,
  }).kind, 'coalesce')
  assert.equal(decideWakeAdmission({
    isSameExecutionAgent: true, shouldDeferFollowupWake: false,
    shouldQueueFollowupForRunningWake: false, availableActiveExecutionRunPresent: true,
    allowRunCoalescing: false,
  }).kind, 'defer')
  assert.equal(decideWakeAdmission({
    isSameExecutionAgent: true, shouldDeferFollowupWake: false,
    shouldQueueFollowupForRunningWake: false, availableActiveExecutionRunPresent: true,
    sameDurableActor: false,
  }).kind, 'defer')
})

// ---------------------------------------------------------------------------
// decideReleaseRecovery
// ---------------------------------------------------------------------------

test('decideReleaseRecovery：run 消失/终态强制释放，超时先终态，否则保持', () => {
  assert.equal(decideReleaseRecovery({ runMissing: true, runSettled: false, lockTimedOut: false }).kind, 'force-release')
  assert.equal(decideReleaseRecovery({ runMissing: false, runSettled: true, lockTimedOut: false }).kind, 'force-release')
  assert.equal(decideReleaseRecovery({ runMissing: false, runSettled: false, lockTimedOut: true }).kind, 'timeout-run')
  assert.equal(decideReleaseRecovery({ runMissing: false, runSettled: false, lockTimedOut: false }).kind, 'keep')
  // run disparu prime sur le jugement d'expiration (vrais tous deux = aussi force-release, pas de timeout-run superflu)
  assert.equal(decideReleaseRecovery({ runMissing: true, runSettled: false, lockTimedOut: true }).kind, 'force-release')
})

// ---------------------------------------------------------------------------
// Normalisation des noms / lignée
// ---------------------------------------------------------------------------

test('normalizeAgentKey：大小写/首尾空白/连续空白归一', () => {
  assert.equal(normalizeAgentKey('  QC  Bot '), 'qc bot')
  assert.equal(normalizeAgentKey('QC Bot'), normalizeAgentKey('qc   bot'))
  assert.equal(normalizeAgentKey(''), '')
})

test('materializeGoalAncestry：目标链+项目物化，空链无项目为空数组', () => {
  assert.deepEqual(materializeGoalAncestry(['g_root', 'g_child'], 'p_1'), ['g_root', 'g_child', 'p_1'])
  assert.deepEqual(materializeGoalAncestry([], undefined), [])
  assert.deepEqual(materializeGoalAncestry(['g_root']), ['g_root'])
})

test('lineageSummary：标题回填与缺省', () => {
  assert.equal(lineageSummary(['g1', 'p1'], { g1: 'Q3 目标', p1: '视觉质检' }), 'Q3 目标 › 视觉质检')
  assert.equal(lineageSummary(['g1'], {}), 'g1')
  assert.equal(lineageSummary([], {}), '（未挂目标/项目）')
})

test('buildIssueContextPack：目标/前置/治理范围注记齐全', () => {
  const pack = buildIssueContextPack({
    goalTitle: '产线质检人效提升', goalMetric: '人均 1200 → 1600 件/日',
    projectNames: ['产线视觉质检改造'], issueTitle: '缺陷分类模型迭代 v2',
    blockerTitles: ['采集通道打通'], dataClass: 'internal',
    budgetNote: '本任务预算余量：¥42.50/日', permissionNote: '你被授予 exec.issue.run（生产部）',
  })
  assert.ok(pack.includes('目标：产线质检人效提升'))
  assert.ok(pack.includes('人均 1200 → 1600 件/日'))
  assert.ok(pack.includes('前置：等待「采集通道打通」完成'))
  assert.ok(pack.includes('internal'))
  assert.ok(pack.includes('¥42.50'))
  // sans dépendance bloquante, la ligne prérequis dit explicitement « aucune »
  const pack2 = buildIssueContextPack({ projectNames: [], issueTitle: 't' })
  assert.ok(pack2.includes('前置：无阻塞依赖'))
  assert.ok(pack2.includes('（未挂目标）'))
})

// ---------------------------------------------------------------------------
// computeAgentHealth
// ---------------------------------------------------------------------------

test('computeAgentHealth：五档裁决与阈值边界', () => {
  const now = 1_700_000_000_000
  assert.equal(computeAgentHealth({ agentStatus: 'offline', frozen: false, lastHeartbeatAt: now, lastMetricsReportAt: now, nowMs: now }), 'offline')
  assert.equal(computeAgentHealth({ agentStatus: 'archived', frozen: false, lastHeartbeatAt: null, lastMetricsReportAt: null, nowMs: now }), 'offline')
  assert.equal(computeAgentHealth({ agentStatus: 'online', frozen: true, lastHeartbeatAt: now, lastMetricsReportAt: now, nowMs: now }), 'frozen')
  // battement configuré à 10 minutes : fenêtre de fraîcheur 3×10=30 minutes (tolère deux tours manqués), fenêtre de traîne 9×10=90 minutes
  const base = { agentStatus: 'online', frozen: false, lastMetricsReportAt: null, heartbeatIntervalMinutes: 10 }
  assert.equal(computeAgentHealth({ ...base, lastHeartbeatAt: now - 30 * 60_000, nowMs: now }), 'healthy')
  assert.equal(computeAgentHealth({ ...base, lastHeartbeatAt: now - 31 * 60_000, nowMs: now }), 'stale')
  assert.equal(computeAgentHealth({ ...base, lastHeartbeatAt: now - 90 * 60_000, nowMs: now }), 'stale')
  assert.equal(computeAgentHealth({ ...base, lastHeartbeatAt: now - 91 * 60_000, nowMs: now }), 'silent')
  // battement non configuré : référentiel tolérant 24 h ; sans battement mais avec rapport, on utilise la datation du rapport
  const loose = { agentStatus: 'online', frozen: false, heartbeatIntervalMinutes: 0 }
  assert.equal(computeAgentHealth({ ...loose, lastHeartbeatAt: null, lastMetricsReportAt: now - 3_600_000, nowMs: now }), 'healthy')
  assert.equal(computeAgentHealth({ ...loose, lastHeartbeatAt: null, lastMetricsReportAt: null, nowMs: now }), 'silent')
  // trial compte aussi comme état de marche
  assert.equal(computeAgentHealth({ agentStatus: 'trial', frozen: false, lastHeartbeatAt: now, lastMetricsReportAt: null, nowMs: now }), 'healthy')
})

// ---------------------------------------------------------------------------
// Machine à états des tâches / levée des dépendances
// ---------------------------------------------------------------------------

test('issueCanTransition：显式流转表与终态', () => {
  assert.ok(issueCanTransition('todo', 'in_progress'))
  assert.ok(issueCanTransition('in_progress', 'review'))
  assert.ok(issueCanTransition('review', 'done'))
  assert.ok(issueCanTransition('review', 'in_progress')) // renvoi
  assert.ok(issueCanTransition('todo', 'cancelled'))
  assert.ok(issueCanTransition('review', 'cancelled'))
  assert.ok(!issueCanTransition('todo', 'done'))        // sauter exécution/revue n'est pas permis
  assert.ok(!issueCanTransition('todo', 'review'))
  assert.ok(!issueCanTransition('done', 'todo'))
  assert.ok(!issueCanTransition('cancelled', 'todo'))
  assert.ok(!issueCanTransition('done', 'cancelled'))
})

test('blockersResolved：全部终态才解除，cancelled 视为解除（不无限挂起）', () => {
  assert.ok(blockersResolved([]))
  assert.ok(blockersResolved(['done']))
  assert.ok(blockersResolved(['done', 'cancelled']))
  assert.ok(!blockersResolved(['done', 'todo']))
  assert.ok(!blockersResolved(['in_progress']))
})

// ---------------------------------------------------------------------------
// cron
// ---------------------------------------------------------------------------

test('cronIsValid：词法校验', () => {
  assert.ok(cronIsValid('* * * * *'))
  assert.ok(cronIsValid('*/5 * * * *'))
  assert.ok(cronIsValid('30 9 * * 1-5'))
  assert.ok(cronIsValid('0 0 1 1 *'))
  assert.ok(!cronIsValid('* * * *'))           // pas assez de champs
  assert.ok(!cronIsValid('* * * * * *'))       // trop de champs
  assert.ok(!cronIsValid('60 * * * *'))        // minute hors bornes
  assert.ok(!cronIsValid('*/0 * * * *'))       // pas 0
  assert.ok(!cronIsValid('a * * * *'))         // non numérique
  assert.ok(!cronIsValid('5-1 * * * *'))       // intervalle inversé
})

test('cronMatches：命中矩阵（UTC）', () => {
  const at = new Date('2026-10-14T09:30:00Z') // mercredi
  assert.ok(cronMatches('* * * * *', at))
  assert.ok(cronMatches('30 * * * *', at))
  assert.ok(cronMatches('*/15 * * * *', at))  // 30 est multiple de 15
  assert.ok(!cronMatches('*/7 * * * *', at))  // 30 n'est pas multiple de 7 (0,7,14,21,28)
  assert.ok(cronMatches('30 9 * * *', at))
  assert.ok(!cronMatches('30 10 * * *', at))
  assert.ok(cronMatches('30 9 14 10 *', at))
  assert.ok(!cronMatches('30 9 15 10 *', at))
  assert.ok(cronMatches('30 9 * * 3', at))    // mercredi
  assert.ok(!cronMatches('30 9 * * 0', at))   // 0=dimanche : ne doit pas correspondre à un mercredi (0 est normalisé à 7, hors du domaine)
  // correspondance dimanche : 2026-10-18 est un dimanche
  const sunday = new Date('2026-10-18T09:30:00Z')
  assert.ok(cronMatches('30 9 * * 0', sunday))
  assert.ok(cronMatches('30 9 * * 7', sunday))
  assert.ok(!cronMatches('30 9 * * 3', sunday))
  // sémantique OU POSIX jour/semaine doublement restreinte : le 13 de chaque mois ou chaque mercredi (instant à 00:00 pour satisfaire champs minute/heure)
  assert.ok(cronMatches('0 0 13 * 3', new Date('2026-10-14T00:00:00Z')))   // mercredi 10-14 : correspondance (semaine satisfaite)
  assert.ok(!cronMatches('0 0 13 * 3', new Date('2026-10-15T00:00:00Z'))) // jeudi non 13
})

test('wakeIdempotencyKey：拼接稳定', () => {
  assert.equal(wakeIdempotencyKey('assign', ['i1', 'a1', 42]), 'assign:i1:a1:42')
  assert.equal(wakeIdempotencyKey('assign', ['i1', undefined]), 'assign:i1:')
})

// ---------------------------------------------------------------------------
// Décision pure des baux d'exécution (décision 3 de l'annexe A : idempotence de réclamation / migration de bail / validation de principal du complete)
// ---------------------------------------------------------------------------

test('decideLeaseClaim：同主体重复认领=幂等，他主体=拒绝，过期=可重取', () => {
  // employé géré : identité par employeeId (changer l'agentKey lié ne casse pas l'idempotence — contrat « même employé+même tâche renvoie le run existant »)
  assert.deepEqual(decideLeaseClaim({
    activeLeasePresent: true, activeLeaseExpired: false,
    existingEmployeeId: 'emp_1', existingAgentKey: 'employee:emp_1',
    requestedEmployeeId: 'emp_1', requestedAgentKey: 'qc bot',
  }), { kind: 'idempotent' })
  // détenu par un autre employé → held-by-other (holder privilégie l'agentKey)
  assert.deepEqual(decideLeaseClaim({
    activeLeasePresent: true, activeLeaseExpired: false,
    existingEmployeeId: 'emp_1', existingAgentKey: 'employee:emp_1',
    requestedEmployeeId: 'emp_2', requestedAgentKey: 'employee:emp_2',
  }), { kind: 'held-by-other', holder: 'employee:emp_1' })
  // réclamation directe legacy par machine (employeeId chaîne vide) : identité par agentKey
  assert.deepEqual(decideLeaseClaim({
    activeLeasePresent: true, activeLeaseExpired: false,
    existingEmployeeId: '', existingAgentKey: 'qc bot',
    requestedEmployeeId: '', requestedAgentKey: 'qc bot',
  }), { kind: 'idempotent' })
  assert.deepEqual(decideLeaseClaim({
    activeLeasePresent: true, activeLeaseExpired: false,
    existingEmployeeId: '', existingAgentKey: 'qc bot',
    requestedEmployeeId: '', requestedAgentKey: 'pack bot',
  }), { kind: 'held-by-other', holder: 'qc bot' })
  // une réclamation legacy ne peut pas reprendre idempotemment un bail géré (référentiel employeeId différent = autre principal)
  assert.equal(decideLeaseClaim({
    activeLeasePresent: true, activeLeaseExpired: false,
    existingEmployeeId: 'emp_1', existingAgentKey: 'employee:emp_1',
    requestedEmployeeId: '', requestedAgentKey: 'employee:emp_1',
  }).kind, 'held-by-other')
  // bail expiré = personne ne détient effectivement → acquire (nouvelle version+1)
  assert.deepEqual(decideLeaseClaim({
    activeLeasePresent: true, activeLeaseExpired: true,
    existingEmployeeId: 'emp_1', existingAgentKey: 'employee:emp_1',
    requestedEmployeeId: 'emp_1', requestedAgentKey: 'employee:emp_1',
  }), { kind: 'acquire' })
  // pas de bail → acquire
  assert.deepEqual(decideLeaseClaim({
    activeLeasePresent: false, activeLeaseExpired: false,
    existingEmployeeId: '', existingAgentKey: '',
    requestedEmployeeId: 'emp_9', requestedAgentKey: 'employee:emp_9',
  }), { kind: 'acquire' })
})

test('decideLeaseRenewal：同主体+active+未过期才续，旧租约一律 stale', () => {
  assert.deepEqual(decideLeaseRenewal({ status: 'active', expired: false, principalMatches: true }), { kind: 'renew' })
  // bail périmé (remplacé par une version supérieure)
  assert.deepEqual(decideLeaseRenewal({ status: 'superseded', expired: false, principalMatches: true }), { kind: 'stale' })
  // déjà libéré
  assert.deepEqual(decideLeaseRenewal({ status: 'released', expired: false, principalMatches: true }), { kind: 'stale' })
  // déjà expiré (même actif et même principal)
  assert.deepEqual(decideLeaseRenewal({ status: 'active', expired: true, principalMatches: true }), { kind: 'stale' })
  // autre principal (fail-closed : principal absent considéré divergent)
  assert.deepEqual(decideLeaseRenewal({ status: 'active', expired: false, principalMatches: false }), { kind: 'stale' })
})

test('decideCompleteOwnership：无租约兼容放行；旧租约=LEASE_STALE；主体不符=RUN_NOT_OWNED', () => {
  // run de l'ancien chemin (sans enregistrement de bail) → passage compatible (référentiel D07 : la coïncidence de principal n'est imposée qu'avec enregistrement de bail)
  assert.deepEqual(decideCompleteOwnership({
    hasLeaseRecord: false, status: 'released', expired: true,
    callerPrincipalId: '', leasePrincipalId: '',
  }), { kind: 'allow' })
  // principal coïncidant + actif + non expiré → allow
  assert.deepEqual(decideCompleteOwnership({
    hasLeaseRecord: true, status: 'active', expired: false,
    callerPrincipalId: 'prin_a', leasePrincipalId: 'prin_a',
  }), { kind: 'allow' })
  // bail périmé (superseded) → LEASE_STALE (avant le jugement de principal)
  assert.deepEqual(decideCompleteOwnership({
    hasLeaseRecord: true, status: 'superseded', expired: false,
    callerPrincipalId: 'prin_a', leasePrincipalId: 'prin_a',
  }), { kind: 'deny', code: 'LEASE_STALE', reason: '执行租约已过期或被更高版本取代（旧租约），请先重新认领' })
  // actif expiré → LEASE_STALE
  assert.equal(decideCompleteOwnership({
    hasLeaseRecord: true, status: 'active', expired: true,
    callerPrincipalId: 'prin_a', leasePrincipalId: 'prin_a',
  }).code, 'LEASE_STALE')
  // principal divergent → RUN_NOT_OWNED (V06 : l'employé soumettant la complétion avec un autre run est refusé)
  assert.equal(decideCompleteOwnership({
    hasLeaseRecord: true, status: 'active', expired: false,
    callerPrincipalId: 'prin_b', leasePrincipalId: 'prin_a',
  }).code, 'RUN_NOT_OWNED')
  // principal appelant absent + bail présent → refus fail-closed (on ne peut pas rendre anonymement le run d'autrui)
  assert.equal(decideCompleteOwnership({
    hasLeaseRecord: true, status: 'active', expired: false,
    callerPrincipalId: '', leasePrincipalId: 'prin_a',
  }).code, 'RUN_NOT_OWNED')
})

test('decideRunAdoption：投影运行中=adopt（V05 不因预持锁卡死），缺席/脏投影=create', () => {
  assert.deepEqual(decideRunAdoption({ projectedRunIdPresent: true, projectedRunRunning: true }), { kind: 'adopt' })
  assert.deepEqual(decideRunAdoption({ projectedRunIdPresent: false, projectedRunRunning: false }), { kind: 'create' })
  // projection pointant un run terminal/disparu = projection sale → création
  assert.deepEqual(decideRunAdoption({ projectedRunIdPresent: true, projectedRunRunning: false }), { kind: 'create' })
})
