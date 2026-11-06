/**
 * Adaptateur de ressources Connector (§4.3/D.3 : sortie dédiée aux connecteurs SaaS externes／d'entreprise).
 *
 * invoke : sondage structuré de la signature réelle connectorHub.invokeAction et réutilisation de sa chaîne à six étapes complète
 * (autorisation du sujet→ODD→approbation→limitation→vérification d'instantané→plan de données), l'admission au niveau travail est déjà faite à la couche invocation.
 * Clé idempotente stable : `wf:<runId>:<handle>:<argsHash>` sha256 tronqué — la signature actuelle de la passerelle
 * n'expose pas de paramètre de clé idempotente externe (généré aléatoirement en interne par executeWithRecovery), donc consignée d'abord dans gatewayRef
 * comme preuve de réconciliation, à transmettre après l'additive du groupe 4 (dégradation honnête, sans simuler une effectivité).
 */
import { sha256Hex } from '../../../platform-core/src/ids.ts'
import { canonicalJson } from '../domain.ts'
import { t } from '../../../platform-i18n/src/index.ts'
import type {
  AdapterInvokeInput,
  AdapterInvokeResult,
  AdapterProbeResult,
  ResourceAdapter,
} from '../contract.ts'
import type { IdentityResolution, ResourceGrantSpec } from '../contract.ts'
import type { WorkExecutionContext } from '../../../platform-core/src/workforce-port.ts'

/** Face de sondage structurée de connectorHub (signature réelle dans plugin-connector/src/index.ts ConnectorHubService). */
interface ConnectorHubProbe {
  invokeAction?: (caller: { type: 'user' | 'agent' | 'app'; id: string; name: string; actChain?: Array<{ name: string; type: string }> }, params: {
    actionId: string
    input?: Record<string, unknown>
    alias?: string
    dryRun?: boolean
  }) => Promise<
    | { ok: true; status: 'ok'; runId: string; latencyMs: number; data: unknown; meta: Record<string, unknown>; metered: boolean }
    | { ok: true; status: 'dry_run'; preview: Record<string, unknown> }
    | { ok: false; status: 'denied' | 'rate_limited' | 'quota_exceeded' | 'error'; error: string; latencyMs: number; code?: string }
    | { ok: false; status: 'approval_required'; approvalId: string; actionId: string; message: string }
  >
}

/** Clé idempotente métier stable (§4.3/§11.5-3 : réutilise la même écriture de la même étape métier à travers les requêtes). */
export function workforceIdempotencyKey(work: WorkExecutionContext, toolHandle: string, args: Record<string, unknown>): string {
  return sha256Hex(`wf:${work.runId}:${toolHandle}:${canonicalJson(args)}`).slice(0, 32)
}

export function createConnectorAdapter(ctx: {
  connectorHub?: ConnectorHubProbe
}): ResourceAdapter {
  const hub = (): ConnectorHubProbe => ctx.connectorHub ?? {}

  return {
    kind: 'connector',

    // Sonde d'autorisation : l'autorisation réelle du connector est vérifiée étape par étape dans la chaîne à six étapes d'invokeAction (instantané/ODD/approbation),
    // le côté plateforme fournit la vérification du catalogue d'actions de la face de gestion register — on ne vérifie ici que l'existence dans le registre (pas de simulation réseau).
    async probeGrant(spec: ResourceGrantSpec, _resolution: IdentityResolution): Promise<AdapterProbeResult> {
      if (typeof hub().invokeAction !== 'function') {
        return { ok: false, message: t('connectorHub 未提供 invokeAction 能力，无法核验连接器授权') }
      }
      return { ok: true, ref: `connector:actions:${spec.actions.join('|')}` }
    },

    async invoke(input: AdapterInvokeInput): Promise<AdapterInvokeResult> {
      const probe = hub()
      if (typeof probe.invokeAction !== 'function') {
        return { ok: false, message: t('connectorHub 未提供 invokeAction 能力'), gatewayRef: { outcome: 'denied' } }
      }
      const work: WorkExecutionContext = input.work
      const caller = {
        type: 'agent' as const,
        id: work.agentId || work.principalId,
        name: t('数字员工:{id}', { id: work.employeeId }),
      }
      const alias = typeof input.tool.constraints?.['alias'] === 'string' ? input.tool.constraints['alias'] as string : undefined
      const idempotencyKey = workforceIdempotencyKey(work, input.tool.handle, input.args)
      try {
        const result = await probe.invokeAction(caller, {
          actionId: input.tool.action,
          input: input.args,
          ...(alias ? { alias } : {}),
        })
        if (result.ok) {
          if (result.status === 'dry_run') {
            return { ok: true, value: result.preview, gatewayRef: { dryRun: true, idempotencyKey } }
          }
          // L'executionId du plan de données entre dans gatewayRef (preuve minimale D.3)
          return {
            ok: true,
            value: result.data,
            gatewayRef: {
              executionId: result.runId,
              latencyMs: result.latencyMs,
              metered: result.metered,
              idempotencyKey,
              workRef: `${work.runId}/${input.invocationId}`,
            },
          }
        }
        if (result.status === 'approval_required') {
          return {
            ok: false,
            message: result.message,
            approvalRef: result.approvalId,
            gatewayRef: { outcome: 'approval_required', actionId: result.actionId, idempotencyKey },
          }
        }
        if (result.status === 'rate_limited') {
          return { ok: false, message: result.error, rateLimited: true, gatewayRef: { idempotencyKey } }
        }
        return {
          ok: false,
          message: result.error,
          gatewayRef: {
            status: result.status,
            idempotencyKey,
            ...(result.status === 'denied' ? { outcome: 'denied' } : {}),
            ...(result.code ? { code: result.code } : {}),
          },
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        // Action d'écriture en timeout/incertitude réseau → résultat inconnu (§11.5-4 : vérifier d'abord, réécriture automatique interdite)
        const uncertain = input.tool.risk !== 'read' && /超时|timeout|abort|ECONNRESET|ETIMEDOUT/i.test(message)
        return {
          ok: false,
          message,
          ...(uncertain ? { outcomeUnknown: true } : {}),
          gatewayRef: { idempotencyKey, ...(uncertain ? { outcome: 'unknown' } : {}) },
        }
      }
    },
  }
}
