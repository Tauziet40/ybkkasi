/**
 * Face de travail REST (/api/workforce/*, chemins et points de permission ayant manifest/api.yaml pour unique source de fait).
 *
 * Convention unifiée : callerRef = gate.caller(exchange) (le middleware d'authentification console a déjà écrit le principal) ;
 * WorkforceError → exchange.fail(e.httpStatus, e.code, e.message) ;
 * les opérations d'écriture de gestion passent par gate.changeLog pour la traçabilité (les appels contrôlés/les livraisons sont eux-mêmes des registres de référence, pas de double audit).
 */
import type { Context } from '@deepseek-ai/cordis'
import { createRestGate, type RestGate } from '../../platform-core/src/rest-gate.ts'
import type { HttpExchange } from '../../platform-core/src/http.ts'
import type { WorkCallerRef, WorkDataClass } from '../../platform-core/src/workforce-port.ts'
import {
  WorkforceError,
  type EmployeeRecord,
  type EmployeeStatus,
  type ResourceGrantSpec,
  type WorkforceAdmission,
  type WorkforceAppointments,
  type WorkforceArtifacts,
  type WorkforceDelivery,
  type WorkforceEmployees,
  type WorkforceIdentityResolver,
  type WorkforceInvocations,
  type WorkforceStore,
} from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type { MaintenanceRunResult } from './maintenance-service.ts'

interface WorkforceServices {
  store: WorkforceStore
  employees: WorkforceEmployees
  appointments: WorkforceAppointments
  identity: WorkforceIdentityResolver
  admission: WorkforceAdmission
  invocations: WorkforceInvocations
  artifacts: WorkforceArtifacts
  delivery: WorkforceDelivery
}

function services(ctx: Context): WorkforceServices {
  const source = ctx as unknown as Partial<WorkforceServices> & Record<string, unknown>
  const missing = (['workforceStore', 'workforceEmployees', 'workforceAppointments', 'workforceIdentity',
    'workforceAdmission', 'workforceInvocations', 'workforceArtifacts', 'workforceDelivery'] as const)
    .filter((key) => !source[key])
  if (missing.length > 0) {
    throw new WorkforceError('WORKFORCE_NOT_READY', t('数字员工服务未就绪：{missing}', { missing: missing.join('、') }), 503)
  }
  // Assemblage explicite par noms de champs d'interface (ctx ne doit pas être renvoyé par simple cast : l'appelant consomme via store/employees/…,
  // alors que les clés de services sur ctx sont workforceStore/workforceEmployees/… — un retour brut ferait de svc.store
  // une lecture de propriété inconnue de ctx, rejetée par cordis en without inject avec un 400)
  return {
    store: source.workforceStore,
    employees: source.workforceEmployees,
    appointments: source.workforceAppointments,
    identity: source.workforceIdentity,
    admission: source.workforceAdmission,
    invocations: source.workforceInvocations,
    artifacts: source.workforceArtifacts,
    delivery: source.workforceDelivery,
  } as WorkforceServices
}

/** gate.caller → caller de confiance (même règle que tools.ts ; lecture d'identité depuis le corps de requête interdite). */
function callerRefOf(gate: RestGate, exchange: HttpExchange): WorkCallerRef {
  const info = gate.caller(exchange)
  return {
    kind: info.kind,
    principalId: info.principalId,
    ...(info.userId ? { userId: info.userId } : {}),
    ...(info.refType !== undefined ? { refType: info.refType } : {}),
    ...(info.refId !== undefined ? { refId: info.refId } : {}),
    ...(info.name ? { name: info.name } : {}),
  }
}

/** Sortie d'erreur unifiée : les erreurs de domaine passent telles quelles avec httpStatus/code, le reste en 400. */
function failOf(exchange: HttpExchange, error: unknown): void {
  if (error instanceof WorkforceError) {
    exchange.fail(error.httpStatus, error.code, error.message)
    return
  }
  exchange.fail(400, 'BAD_REQUEST', error instanceof Error ? error.message : String(error))
}

function readBody(exchange: HttpExchange): Record<string, unknown> {
  const body = exchange.body
  return body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : {}
}

function publicEmployee(record: EmployeeRecord): Record<string, unknown> {
  return {
    id: record.id, name: record.name, displayName: record.displayName, orgId: record.orgId,
    supervisorUserId: record.supervisorUserId, status: record.status, primaryAgentId: record.primaryAgentId,
    createdAt: record.createdAt, updatedAt: record.updatedAt,
  }
}

function parseGrants(value: unknown): ResourceGrantSpec[] {
    if (!Array.isArray(value)) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('grants 必须为数组'))
    return value.map((item) => {
      const grant = item as Record<string, unknown>
      const kind = grant['kind']
      if (kind !== 'mcp' && kind !== 'connector' && kind !== 'model' && kind !== 'skill' && kind !== 'nas' && kind !== 'app') {
        throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('非法授权类型：{kind}', { kind: String(kind) }))
      }
      const risk = grant['risk']
      if (risk !== 'read' && risk !== 'write' && risk !== 'admin') {
        throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('非法风险级：{risk}', { risk: String(risk) }))
      }
      const registryId = String(grant['registryId'] ?? '')
      if (!registryId) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('授权缺少 registryId'))
      const actions = Array.isArray(grant['actions']) ? grant['actions'].map((action) => String(action)) : []
      if (actions.length === 0) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('授权 {registryId} 缺少动作清单（未知风险工具不得默认开放）', { registryId }))
    return {
      kind, registryId, actions, risk,
      constraints: grant['constraints'] && typeof grant['constraints'] === 'object'
        ? grant['constraints'] as Record<string, unknown>
        : undefined,
    }
  })
}

export function registerWorkforceRoutes(ctx: Context): void {
  const gate = createRestGate(ctx as unknown as Parameters<typeof createRestGate>[0])

  // -- Vue d'ensemble ---------------------------------------------------------------

  gate.guarded('GET', '/api/workforce/overview', 'workforce.read', () => {
    const svc = services(ctx)
    return {
      employees: svc.store.employees.count(),
      bindings: svc.store.bindings.count(),
      appointments: svc.store.appointments.count(),
      permits: svc.store.permits.findWhere({ status: 'active' }).length,
      invocations: svc.store.invocations.count(),
      deliverables: svc.store.deliverables.count(),
      artifacts: svc.store.artifacts.count(),
    }
  })

  // -- Employés ---------------------------------------------------------------

  gate.guarded('GET', '/api/workforce/employees', 'workforce.read', (exchange) => {
    const svc = services(ctx)
    // Chaîne de requête via exchange.query (HttpExchange n'a pas de champ request — correctif d'un défaut historique du lot W, l'ancien exchange.request.url explosait systématiquement à l'exécution)
    const orgId = exchange.query.get('orgId') ?? undefined
    const status = exchange.query.get('status') ?? undefined
    const records = svc.employees.list({
      ...(orgId ? { orgId } : {}),
      ...(status ? { status: status as EmployeeStatus } : {}),
    })
    return records.map(publicEmployee)
  })

  gate.guarded('POST', '/api/workforce/employees', 'workforce.write', (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const record = svc.employees.create({
      name: String(body['name'] ?? ''),
      ...(body['displayName'] !== undefined ? { displayName: String(body['displayName']) } : {}),
      orgId: String(body['orgId'] ?? ''),
      supervisorUserId: String(body['supervisorUserId'] ?? ''),
      agentId: String(body['agentId'] ?? ''),
      ...(body['principalId'] !== undefined ? { principalId: String(body['principalId']) } : {}),
      ...(body['runtime'] !== undefined ? { runtime: String(body['runtime']) } : {}),
    })
    gate.changeLog(exchange, 'workforce.employee.create', 'employee', record.id, record.name)
    return publicEmployee(record)
  })

  gate.guarded('GET', '/api/workforce/employees/:id', 'workforce.read', (exchange) => {
    const svc = services(ctx)
    return {
      ...publicEmployee(svc.employees.get(exchange.params['id'] ?? '')),
      bindings: svc.employees.bindingsFor(exchange.params['id'] ?? ''),
    }
  })

  gate.guarded('POST', '/api/workforce/employees/:id/status', 'workforce.write', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const status = String(body['status'] ?? '')
    if (status !== 'active' && status !== 'suspended' && status !== 'offboarded') {
      throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('非法员工状态：{status}', { status }))
    }
    const record = await svc.employees.setStatus(callerRefOf(gate, exchange), exchange.params['id'] ?? '', status, String(body['reason'] ?? ''))
    gate.changeLog(exchange, 'workforce.employee.status', 'employee', record.id, record.name, `→ ${status}（${String(body['reason'] ?? '')}）`)
    return publicEmployee(record)
  })

  gate.guarded('POST', '/api/workforce/employees/:id/bindings', 'workforce.write', (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const binding = svc.employees.bindAgent(
      callerRefOf(gate, exchange),
      exchange.params['id'] ?? '',
      String(body['agentId'] ?? ''),
      ...(body['principalId'] !== undefined ? [String(body['principalId'])] as const : []),
      ...(body['runtime'] !== undefined ? [String(body['runtime'])] as const : []),
    )
    gate.changeLog(exchange, 'workforce.employee.bind', 'binding', binding.id, `${binding.employeeId} → ${binding.agentId}`)
    return binding
  })

  // -- Nominations ---------------------------------------------------------------

  gate.guarded('GET', '/api/workforce/appointments', 'workforce.read', (exchange) => {
    const svc = services(ctx)
    const employeeId = exchange.query.get('employeeId') ?? undefined
    const status = exchange.query.get('status') ?? undefined
    return svc.appointments.list({
      ...(employeeId ? { employeeId } : {}),
      ...(status ? { status: status as 'preparing' | 'effective' | 'revoking' | 'revoked' | 'failed' } : {}),
    })
  })

  gate.guarded('POST', '/api/workforce/appointments', 'workforce.write', (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const actor = gate.actorOf(exchange)
    const record = svc.appointments.create({
      employeeId: String(body['employeeId'] ?? ''),
      position: String(body['position'] ?? ''),
      orgId: String(body['orgId'] ?? ''),
      dataClass: String(body['dataClass'] ?? 'internal') as WorkDataClass,
      effectiveFrom: String(body['effectiveFrom'] ?? new Date().toISOString()),
      ...(body['effectiveUntil'] !== undefined ? { effectiveUntil: String(body['effectiveUntil']) } : {}),
      grants: parseGrants(body['grants']),
      approvedBy: String(body['approvedBy'] ?? actor),
      ...(body['approvalRef'] !== undefined ? { approvalRef: String(body['approvalRef']) } : {}),
    })
    gate.changeLog(exchange, 'workforce.appointment.create', 'appointment', record.id, `${record.employeeId} v${record.version}`)
    return record
  })

  gate.guarded('POST', '/api/workforce/appointments/:id/activate', 'workforce.write', async (exchange) => {
    const svc = services(ctx)
    const record = await svc.appointments.activate(callerRefOf(gate, exchange), exchange.params['id'] ?? '')
    gate.changeLog(exchange, 'workforce.appointment.activate', 'appointment', record.id, `→ ${record.status}`)
    return record
  })

  gate.guarded('POST', '/api/workforce/appointments/:id/revoke', 'workforce.write', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const record = await svc.appointments.revoke(callerRefOf(gate, exchange), exchange.params['id'] ?? '', String(body['reason'] ?? ''))
    gate.changeLog(exchange, 'workforce.appointment.revoke', 'appointment', record.id, `→ ${record.status}（${String(body['reason'] ?? '')}）`)
    return record
  })

  // -- Récupération des tâches à faire (le runtime recherche les tâches de l'employé par sujet machine, aucun filtrage d'employé arbitraire, §13.1) ---------

  gate.guarded('GET', '/api/workforce/work-items', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    const caller = callerRefOf(gate, exchange)
    const resolution = await svc.identity.resolveByCaller(caller)
    if (!resolution) throw new WorkforceError('EMPLOYEE_NOT_ACTIVE', t('非受管数字员工或绑定缺失'))
    const agentId = resolution.binding.agentId
    const hub = (ctx as unknown as {
      execHub?: { issues?: () => { all(): Array<Record<string, unknown>> } }
    }).execHub
    if (!hub || typeof hub.issues !== 'function') {
      exchange.fail(503, 'EXEC_HUB_UNAVAILABLE', t('执行中枢未就绪，无法拉取待办'))
      return
    }
    const issues = hub.issues().all()
      .filter((issue) => issue['assigneeAgentId'] === agentId && (issue['status'] === 'todo' || issue['status'] === 'in_progress'))
      .map((issue) => ({
        id: issue['id'], title: issue['title'], status: issue['status'], priority: issue['priority'],
        dueAt: issue['dueAt'] ?? '', executionRunId: issue['executionRunId'] ?? '',
      }))
    return { employeeId: resolution.employee.id, agentId, items: issues }
  })

  // -- Réclamation et prolongation -----------------------------------------------------------

  gate.guarded('POST', '/api/workforce/claims', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const outcome = await svc.admission.claimWork(callerRefOf(gate, exchange), {
      issueId: String(body['issueId'] ?? ''),
      ...(typeof body['agentKey'] === 'string' && body['agentKey'] ? { agentKey: body['agentKey'] } : {}),
      ...(typeof body['ttlMinutes'] === 'number' && body['ttlMinutes'] > 0 ? { ttlMs: Math.round(body['ttlMinutes'] * 60_000) } : {}),
    })
    if (!outcome.ok) {
      exchange.fail(outcome.code === 'WORKFORCE_NOT_READY' ? 503 : 403, outcome.code, outcome.message,
        outcome.holder ? { holder: outcome.holder } : undefined)
      return
    }
    gate.changeLog(exchange, 'workforce.claim', 'run', outcome.runId, `issue=${outcome.issueId} employee=${outcome.employeeId}`)
    return {
      ok: true,
      employeeId: outcome.employeeId,
      issueId: outcome.issueId,
      runId: outcome.runId,
      lease: outcome.lease,
      permit: outcome.permit,
      manifest: outcome.manifest,
      tools: outcome.tools.map((tool) => tool.handle),
      idempotent: outcome.idempotent,
    }
  })

  gate.guarded('POST', '/api/workforce/leases/:id/renew', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const result = await svc.admission.renewWorkLease(
      callerRefOf(gate, exchange),
      exchange.params['id'] ?? '',
      typeof body['ttlMinutes'] === 'number' && body['ttlMinutes'] > 0 ? Math.round(body['ttlMinutes'] * 60_000) : undefined,
    )
    if (!result.ok) {
      exchange.fail(result.code === 'EXEC_HUB_UNAVAILABLE' ? 503 : 403, result.code, result.message)
      return
    }
    return { ok: true, lease: result.lease }
  })

  // -- Registre des appels contrôlés ---------------------------------------------------------

  gate.guarded('POST', '/api/workforce/invocations', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const outcome = await svc.invocations.invoke(callerRefOf(gate, exchange), {
      permitId: String(body['permitId'] ?? ''),
      toolHandle: String(body['toolHandle'] ?? ''),
      stepKey: String(body['stepKey'] ?? ''),
      arguments: body['arguments'],
      ...(typeof body['traceId'] === 'string' && body['traceId'] ? { traceId: body['traceId'] } : {}),
    })
    // L'état du domaine et l'état HTTP sont conservés séparément (§9.3 : un HTTP 200 ne fait pas passer un succès métier, et un 4xx ne perd pas l'état du domaine)
    return { ok: outcome.status === 'completed', ...outcome }
  })

  gate.guarded('GET', '/api/workforce/invocations/:id', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    return svc.invocations.get(callerRefOf(gate, exchange), exchange.params['id'] ?? '')
  })

  gate.guarded('GET', '/api/workforce/invocations', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    const runId = exchange.query.get('runId') ?? ''
    if (!runId) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('缺少 runId 查询参数'))
    return svc.invocations.listByRun(callerRefOf(gate, exchange), runId)
  })

  // -- Artefacts contrôlés ---------------------------------------------------------

  gate.guarded('POST', '/api/workforce/artifacts', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const record = await svc.artifacts.createUpload(callerRefOf(gate, exchange), {
      name: String(body['name'] ?? ''),
      contentType: String(body['contentType'] ?? 'application/octet-stream'),
      contentBase64: String(body['contentBase64'] ?? ''),
      ...(typeof body['runId'] === 'string' && body['runId'] ? { runId: body['runId'] } : {}),
    })
    return {
      id: record.id, name: record.name, sizeBytes: record.sizeBytes,
      sha256: record.sha256, runId: record.runId, createdAt: record.createdAt,
    }
  })

  gate.guarded('GET', '/api/workforce/artifacts/:id', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    return svc.artifacts.get(callerRefOf(gate, exchange), exchange.params['id'] ?? '')
  })

  // -- Livraisons -----------------------------------------------------------------

  gate.guarded('POST', '/api/workforce/deliverables', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const record = await svc.delivery.submit(callerRefOf(gate, exchange), {
      permitId: String(body['permitId'] ?? ''),
      summary: String(body['summary'] ?? ''),
      artifactIds: Array.isArray(body['artifactIds']) ? body['artifactIds'].map((item) => String(item)) : [],
    })
    gate.changeLog(exchange, 'workforce.deliverable.submit', 'deliverable', record.id, `run=${record.runId} v${record.version}`)
    return record
  })

  gate.guarded('GET', '/api/workforce/deliverables', 'workforce.invoke', async (exchange) => {
    const svc = services(ctx)
    const runId = exchange.query.get('runId') ?? ''
    if (!runId) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('缺少 runId 查询参数'))
    return svc.delivery.listByRun(callerRefOf(gate, exchange), runId)
  })

  // -- Acceptation (humain, workforce.accept) -----------------------------------------

  gate.guarded('POST', '/api/workforce/acceptances', 'workforce.accept', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const decision = String(body['decision'] ?? '')
    if (decision !== 'accepted' && decision !== 'rejected') {
      throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('非法验收决定：{decision}', { decision }))
    }
    const record = await svc.delivery.decide(callerRefOf(gate, exchange), {
      deliverableId: String(body['deliverableId'] ?? ''),
      decision,
      reason: String(body['reason'] ?? ''),
    })
    gate.changeLog(exchange, 'workforce.acceptance.decide', 'deliverable', record.id, `${decision}（${record.decisionReason}）`)
    return record
  })

  // -- Face opérationnelle (workforce.admin, décision W5 D-③ ensemble minimal trois-en-un) ---------------------------
  // Cette section est le point d'atterrissage code du point de permission workforce.admin (auparavant seule déclaration dans l'inventaire/le catalogue, contract-lint rapportait l'avertissement
  // perm_unused ; le littéral du 3e paramètre de guarded ici vaut justificatif d'apurement — routeRe ne reconnaît que les références littérales).
  // Référentiel inter-organisations : la face opérationnelle admin lit directement les tables du store en requête traversante, sans passer par l'assertReadable d'invocation-service
  // (l'isolation org est le référentiel de la face de travail de l'employé) — le point de permission est la frontière.

  /** Référentiel commun de limit pour les requêtes audit/invocations : défaut 50, plafond 500 (requête traversante, empêche le vidage intégral de la base). */
  function readLimit(query: URLSearchParams): number {
    const raw = Number(query.get('limit') ?? 50)
    return Number.isFinite(raw) && raw > 0 ? Math.min(Math.floor(raw), 500) : 50
  }

  gate.guarded('POST', '/api/workforce/admin/employees/status-batch', 'workforce.admin', async (exchange) => {
    const svc = services(ctx)
    const body = readBody(exchange)
    const rawIds = Array.isArray(body['employeeIds']) ? body['employeeIds'].map((item) => String(item).trim()) : []
    const employeeIds = [...new Set(rawIds.filter((item) => item !== ''))]
    if (employeeIds.length === 0) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('employeeIds 必须为非空员工 ID 数组'))
    if (employeeIds.length > 200) throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('employeeIds 单批上限 200（逐员工撤权联动，防止超长批次）'))
    const status = String(body['status'] ?? '')
    if (status !== 'suspended' && status !== 'active') {
      throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('批量状态只允许 suspended（停职）/ active（复岗）：{status}', { status: status || t('（空）') }))
    }
    const reason = String(body['reason'] ?? '').trim()
    if (reason === '') throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('批量停职/复岗必须登记 reason（审计与解冻依据）'))
    const caller = callerRefOf(gate, exchange)
    const now = new Date().toISOString()
    const results: Array<{ employeeId: string; ok: boolean; error?: string; revokedPermits?: number; releasedRuns?: string[] }> = []
    // Transaction indépendante par employé (pas de rollback global du lot) : le setStatus interne « révocation des permits→libération des baux→écriture de l'état » forme pour un seul employé
    // une boucle fail-closed complète (employee-service.ts inchangé d'un caractère) ; les échecs partiels sont rendus honnêtement dans results,
    // la réponse est l'état réel des entités, l'exploitation complète au cas par cas.
    for (const employeeId of employeeIds) {
      const beforeActive = svc.store.permits.findWhere({ employeeId, status: 'active' })
      try {
        await svc.employees.setStatus(caller, employeeId, status, reason)
        const afterStatus = new Map(svc.store.permits.findWhere({ employeeId }).map((permit) => [permit.id, permit.status]))
        // releasedRuns : en suspension, prend « les runs des permits active avant révocation, tels qu'après révocation ce run n'a plus de permit valide » ;
        // la reprise ne libère pas de bail (toujours vide). La référence des baux est dans exec-hub (archivage à l'état terminal), ici une projection observable du registre.
        const releasedRuns = status === 'suspended'
          ? [...new Set(beforeActive.map((permit) => permit.runId).filter((runId) => runId !== ''))]
              .filter((runId) => !svc.store.permits.findWhere({ runId })
                .some((permit) => permit.status === 'active' && (!permit.expiresAt || permit.expiresAt > now)))
          : []
        results.push({
          employeeId,
          ok: true,
          revokedPermits: beforeActive.filter((permit) => afterStatus.get(permit.id) !== 'active').length,
          releasedRuns,
        })
      } catch (error) {
        results.push({ employeeId, ok: false, error: error instanceof Error ? error.message : String(error) })
      }
    }
    const succeeded = results.filter((item) => item.ok).length
    const failed = results.length - succeeded
    gate.changeLog(exchange, 'workforce.employee.status-batch', 'employee', employeeIds.slice(0, 5).join(','),
      '', `批量${status === 'suspended' ? '停职' : '复岗'}：${reason}；ids=${employeeIds.join(',')}；succeeded=${succeeded} failed=${failed}`)
    return { results, succeeded, failed }
  })

  gate.guarded('GET', '/api/workforce/admin/employees/:id/audit', 'workforce.admin', (exchange) => {
    const svc = services(ctx)
    const employeeId = exchange.params['id'] ?? ''
    const employee = svc.store.employees.get(employeeId)
    if (!employee) throw new Error(t('数字员工不存在：{id}', { id: employeeId }))
    // Note sur la traversée inter-organisations : ce endpoint est gardé par workforce.admin, lit directement les tables du store en enchaînant par employeeId/appointmentId
    // (sans passer par l'isolation org d'assertReadable) — rapport d'audit de la face opérationnelle admin, le point de permission est la frontière.
    const limit = readLimit(exchange.query)
    const now = new Date().toISOString()
    const bindings = svc.store.bindings.findWhere({ employeeId })
    const appointments = svc.store.appointments.findWhere({ employeeId })
      .sort((a, b) => a.version - b.version)
      .map((appointment) => ({
        ...appointment,
        grants: svc.store.grants.findWhere({ appointmentId: appointment.id }),
        manifest: svc.store.manifests.findWhere({ appointmentId: appointment.id })
          .sort((a, b) => b.version - a.version)[0] ?? null,
      }))
    const permits = svc.store.permits.findWhere({ employeeId })
    const allInvocations = svc.store.invocations.findWhere({ employeeId })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    const deliverables = svc.store.deliverables.findWhere({ employeeId })
    return {
      employee,
      bindings,
      appointments,
      permits,
      invocations: allInvocations.slice(0, limit),
      deliverables,
      summary: {
        // Valide = active et non passé expiresAt ; expiré calculé sur le fait expiresAt<=now (la base peut ne pas encore contenir
        // de ligne expired comptabilisée — la convergence de la comptabilisation relève de MaintenanceService.run)
        permitActive: permits.filter((permit) => permit.status === 'active' && (!permit.expiresAt || permit.expiresAt > now)).length,
        permitExpired: permits.filter((permit) => permit.expiresAt !== '' && permit.expiresAt <= now).length,
        invocationCount: allInvocations.length,
        invocationDenied: allInvocations.filter((item) => item.status === 'denied').length,
        deliverableAccepted: deliverables.filter((item) => item.status === 'accepted').length,
        deliverableRejected: deliverables.filter((item) => item.status === 'rejected').length,
      },
    }
  })

  gate.guarded('GET', '/api/workforce/admin/invocations', 'workforce.admin', (exchange) => {
    const svc = services(ctx)
    // Requête traversante inter-organisations du registre des appels (face opérationnelle admin, le point de permission est la frontière ; la face de travail GET /invocations ne fait que par runId
    // et passe le contrôle d'appartenance — ce endpoint est l'entrée de réconciliation d'exploitation, tri inverse sur createdAt)
    const query = exchange.query
    const employeeId = query.get('employeeId') ?? ''
    const runId = query.get('runId') ?? ''
    const status = query.get('status') ?? ''
    let rows = svc.store.invocations.all()
    if (employeeId) rows = rows.filter((row) => row.employeeId === employeeId)
    if (runId) rows = rows.filter((row) => row.runId === runId)
    if (status) rows = rows.filter((row) => row.status === status)
    return rows.sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, readLimit(query))
  })

  gate.guarded('POST', '/api/workforce/admin/maintenance/run', 'workforce.admin', (exchange) => {
    // Le minuteur et le déclenchement manuel admin exécutent la même fonction (mêmes précédents que POST /api/exec/tick, POST /api/usage/retention/purge)
    const maintenance = (ctx as unknown as { workforceMaintenance?: { run(): MaintenanceRunResult } }).workforceMaintenance
    if (!maintenance || typeof maintenance.run !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('台账维护服务未就绪'), 503)
    }
    const result = maintenance.run()
    gate.changeLog(exchange, 'workforce.maintenance.run', 'maintenance', 'workforce-ledger', '台账巡检', JSON.stringify(result))
    return result
  })
}
