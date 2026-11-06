/**
 * Adaptateur de ressources d'applications IA (§4.6 : disposer de la connexion unifiée ne signifie pas disposer d'une API appelable par machine).
 *
 * Une application qui ne fait qu'enregistrer une entryUrl ne peut être appelée comme une fonction ; les applications dotées d'une API machine doivent être
 * raccordées explicitement via MCP／Connector／un adaptateur dédié. Non pris en charge honnêtement en phase 1 — probeGrant/invoke
 * renvoient toujours ok:false, sans faire passer une implémentation vide pour un succès, et sans laisser le runtime soumettre une URL arbitraire
 * que la plateforme solliciterait à sa place avec des identifiants internes.
 */
import type {
  AdapterInvokeInput,
  AdapterInvokeResult,
  AdapterProbeResult,
  ResourceAdapter,
} from '../contract.ts'
import type { IdentityResolution, ResourceGrantSpec } from '../contract.ts'
import { t } from '../../../platform-i18n/src/index.ts'

const UNSUPPORTED = 'AI 应用机器 API 适配一期未开放（具备机器 API 的应用请经 MCP/Connector 显式接入）'

export function createAppAdapter(_ctx: unknown): ResourceAdapter {
  return {
    kind: 'app',

    async probeGrant(_spec: ResourceGrantSpec, _resolution: IdentityResolution): Promise<AdapterProbeResult> {
      return { ok: false, message: t(UNSUPPORTED) }
    },

    async invoke(_input: AdapterInvokeInput): Promise<AdapterInvokeResult> {
      return { ok: false, message: t(UNSUPPORTED), gatewayRef: { outcome: 'denied' } }
    },
  }
}
