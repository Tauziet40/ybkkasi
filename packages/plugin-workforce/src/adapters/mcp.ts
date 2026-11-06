/**
 * Adaptateur de ressources MCP (§4.2/D.3 : sortie d'outils contrôlée par laquelle l'employé numérique accède aux systèmes métier).
 *
 * probeGrant : sondage structuré mcpRegistry.authorize(caller, serviceId, toolName) (signature réelle)
 * pour chaque action du grant — l'effectivité réelle fait foi des groupes de permissions de la passerelle, pas des suppositions de cases cochées dans l'UI ;
 * la référence de groupe de permissions est reconstituée par sondage structuré permGroups, à défaut ref='probe:authorize-only'.
 * invoke : appelle mcpRegistry.invoke en passant par la chaîne d'autorisation d'origine de la passerelle (intersection des deux couches d'autorisation, §9.5), et via le 5e paramètre
 * workRef transmet la référence de travail (permit/run) à la barrière de travail de la passerelle et aux enregistrements d'appel (correctif D1 : l'additive du groupe 4
 * est livré ; la passerelle ne renvoie toujours pas l'ID d'appel/l'ID d'événement usage — gatewayRef enregistre la dégradation honnêtement, sans preuve fabriquée).
 */
import { sha256Hex } from '../../../platform-core/src/ids.ts'
import { t } from '../../../platform-i18n/src/index.ts'
import type {
  AdapterInvokeInput,
  AdapterInvokeResult,
  AdapterProbeResult,
  ResourceAdapter,
} from '../contract.ts'
import type { IdentityResolution, ResourceGrantSpec } from '../contract.ts'
import type { WorkExecutionContext, WorkRefIndex } from '../../../platform-core/src/workforce-port.ts'

/** Face de sondage structurée de mcpRegistry (signature réelle dans plugin-mcp/src/index.ts McpService). */
interface McpRegistryProbe {
  authorize?: (caller: { type: 'user' | 'agent' | 'app'; id: string; name: string }, serviceId: string, toolName: string) =>
    { ok: true; readOnly: boolean } | { ok: false; reason: string }
  invoke?: (caller: { type: 'user' | 'agent' | 'app'; id: string; name: string }, serviceId: string, toolName: string, args?: Record<string, unknown>, workRef?: WorkRefIndex) =>
    Promise<{ ok: boolean; status: 'ok' | 'error' | 'denied' | 'rate_limited' | 'breaker_open'; latencyMs: number; version: string; result?: unknown; error?: string }>
  permGroups?: () => { all(): Array<{ id: string; policies: Record<string, unknown>; subjects: Array<{ type: string; id: string }> }> }
}

export function createMcpAdapter(ctx: {
  mcpRegistry?: McpRegistryProbe
}): ResourceAdapter {
  const registry = (): McpRegistryProbe => ctx.mcpRegistry ?? {}

  /** Sujet machine de l'employé → InvokeCaller de la passerelle (recherche inverse de l'Agent lié, identité non acceptée en paramètre). */
  const gatewayCaller = (resolution: IdentityResolution): { type: 'agent'; id: string; name: string } => ({
    type: 'agent',
    id: resolution.binding.agentId || resolution.employee.primaryAgentId || resolution.employee.id,
    name: resolution.employee.displayName || resolution.employee.name,
  })

  return {
    kind: 'mcp',

    async probeGrant(spec: ResourceGrantSpec, resolution: IdentityResolution): Promise<AdapterProbeResult> {
      const hub = registry()
      if (typeof hub.authorize !== 'function') {
        return { ok: false, message: t('mcpRegistry 未提供 authorize 探测能力，无法核验 MCP 授权') }
      }
      const caller = gatewayCaller(resolution)
      for (const action of spec.actions) {
        const verdict = hub.authorize(caller, spec.registryId, action)
        if (!verdict.ok) {
          return { ok: false, message: t('MCP 授权探针未通过（{handle}）：{reason}', { handle: `${spec.registryId}.${action}`, reason: verdict.reason }) }
        }
      }
      // Preuve du groupe de permissions : sondage structuré permGroups ; à défaut, enregistrement honnête authorize-only
      try {
        if (typeof hub.permGroups === 'function') {
          const agentId = caller.id
          const groupIds = hub.permGroups().all()
            .filter((group) => group.policies[spec.registryId]
              && group.subjects.some((subject) => subject.type === 'agent' && subject.id === agentId))
            .map((group) => group.id)
          if (groupIds.length > 0) return { ok: true, ref: `permgroup:${groupIds.join(',')}` }
        }
      } catch {
        // requête de groupes de permissions absente → enregistrement dégradé
      }
      return { ok: true, ref: 'probe:authorize-only' }
    },

    async invoke(input: AdapterInvokeInput): Promise<AdapterInvokeResult> {
      const hub = registry()
      if (typeof hub.invoke !== 'function') {
        return { ok: false, message: t('mcpRegistry 未提供 invoke 能力'), gatewayRef: { outcome: 'denied' } }
      }
      const work: WorkExecutionContext = input.work
      const caller = {
        type: 'agent' as const,
        id: work.agentId || work.principalId,
        name: t('数字员工:{id}', { id: work.employeeId }),
      }
      // Index de référence de travail (§10.4 / correctif D1) : la barrière de travail de la passerelle vérifie l'autorisation au niveau travail par permitId (V28),
      // et relie permit/run/employee aux enregistrements d'appel de la passerelle et à l'usage (D11). Simple transmission d'index,
      // les faits d'autorisation (permit/bail/inventaire/périmètre de paramètres) sont toujours revérifiés côté serveur de la passerelle. stepKey n'est pas dans
      // WorkExecutionContext (l'idempotence d'étape repose sur la contrainte d'unicité de la couche registre), donc non transmis.
      const workRef: WorkRefIndex = {
        permitId: work.permitId,
        ...(work.runId ? { runId: work.runId } : {}),
        ...(work.issueId ? { issueId: work.issueId } : {}),
        ...(work.traceId ? { traceId: work.traceId } : {}),
      }
      const result = await hub.invoke(caller, input.tool.registryId, input.tool.action, input.args, workRef)
      if (result.ok) {
        // la passerelle ne renvoie pas encore l'ID d'appel/l'ID d'événement usage (défaut honnête avant l'additive du groupe 4, pas de fabrication)
        return {
          ok: true,
          value: result.result,
          gatewayRef: {
            note: 'mcp 网关暂未回传调用ID',
            status: result.status,
            version: result.version,
            latencyMs: result.latencyMs,
            workRef: `${work.runId}/${input.invocationId}`,
            argsHash: sha256Hex(JSON.stringify(input.args)).slice(0, 16),
          },
        }
      }
      return {
        ok: false,
        message: result.error ?? t('MCP 网关拒绝或调用失败'),
        // denied/breaker_open = refus au niveau ressource (arrêt, pas de nouvelle tentative par une autre entrée) ; error = échec d'exécution
        gatewayRef: {
          status: result.status,
          version: result.version,
          ...(result.status === 'denied' || result.status === 'breaker_open' ? { outcome: 'denied' } : {}),
        },
        ...(result.status === 'rate_limited' ? { rateLimited: true } : {}),
      }
    },
  }
}
