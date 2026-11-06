/**
 * Adaptateur de ressources de modèles (§4.1/D14 : le modèle fournit la capacité d'inférence, n'assume pas l'identité de poste).
 *
 * Discipline de classification (D14) : la classification métier unifiée ≠ l'ancienne énumération de protocole de ModelGateway —
 *   1. topsecret refusé au préalable (assertAgentAllowedDataClass, jamais mappé vers un canal disponible) ;
 *   2. mapWorkDataClassToChannel mappage explicite (mappage confidential manquant → refus, pas de repli silencieux sur internal) ;
 *   3. le dataClass passé à la passerelle prend la valeur mappée, le franchissement de niveau est verrouillé par le routage par niveaux de la passerelle (double ligne de défense).
 * subject utilise l'attribution technique de l'Agent confirmée côté serveur (agent:<agentId>), le budget est rattaché au même sujet.
 */
import { assertAgentAllowedDataClass, mapWorkDataClassToChannel } from '../domain.ts'
import { t } from '../../../platform-i18n/src/index.ts'
import type {
  AdapterInvokeInput,
  AdapterInvokeResult,
  AdapterProbeResult,
  ResourceAdapter,
} from '../contract.ts'
import type { IdentityResolution, ResourceGrantSpec } from '../contract.ts'
import type { WorkDataClass } from '../../../platform-core/src/workforce-port.ts'

/** Face de sondage structurée de modelGateway (signature réelle dans plugin-modelgw/src/index.ts ModelGatewayService). */
interface ModelGatewayProbe {
  models?: () => { all(): Array<{ slug: string; status: string }> }
  channelGroups?: () => { all(): Array<{ slug: string; enabled: boolean }> }
  invoke?: (input: {
    model: string
    messages: Array<{ role: string; content: string }>
    orgId: string
    subject: string
    maxTokens?: number
    temperature?: number
    dataClass?: 'public' | 'internal' | 'secret'
  }) => Promise<{
    ok: true
    content: string
    model: string
    inputTokens: number
    outputTokens: number
    costCents: number
    /** Réservé à l'additive du groupe 4 : identifiant d'événement renvoyé par usage.record (la passerelle actuelle ne le renvoie pas, défaut de sondage). */
    usageEventId?: string
  }>
}

export function createModelAdapter(ctx: {
  modelGateway?: ModelGatewayProbe
}): ResourceAdapter {
  const gateway = (): ModelGatewayProbe => ctx.modelGateway ?? {}

  return {
    kind: 'model',

    /** Sonde de catalogue : registryId doit être réellement enregistré dans le catalogue de modèles (ou un groupe de canaux), les simples valeurs souhaitées ne sont pas acceptées. */
    async probeGrant(spec: ResourceGrantSpec, _resolution: IdentityResolution): Promise<AdapterProbeResult> {
      const hub = gateway()
      if (typeof hub.models !== 'function') {
        return { ok: false, message: t('modelGateway 未提供模型目录查询能力') }
      }
      const inCatalog = hub.models().all().some((model) => model.slug === spec.registryId)
      if (inCatalog) return { ok: true, ref: 'model-catalog' }
      try {
        if (typeof hub.channelGroups === 'function'
          && hub.channelGroups().all().some((group) => group.slug === spec.registryId)) {
          return { ok: true, ref: 'model-channel-group' }
        }
      } catch {
        // requête de groupes de canaux absente → jugement sur le catalogue
      }
      return { ok: false, message: t('模型 {modelId} 不在模型网关目录中（渠道组亦未登记）', { modelId: spec.registryId }) }
    },

    async invoke(input: AdapterInvokeInput): Promise<AdapterInvokeResult> {
      const hub = gateway()
      if (typeof hub.invoke !== 'function') {
        return { ok: false, message: t('modelGateway 未提供 invoke 能力'), gatewayRef: { outcome: 'denied' } }
      }
      const work = input.work
      // Première ligne de défense de classification (D14) : topsecret interdit en traitement direct par l'Agent — refus avant mappage
      try {
        assertAgentAllowedDataClass(work.dataClass as WorkDataClass)
      } catch (error) {
        return { ok: false, message: error instanceof Error ? error.message : String(error), gatewayRef: { outcome: 'denied' } }
      }
      // Mappage explicite de la classification de l'ancien protocole ; mappage manquant (confidential etc. sans niveau de canal correspondant) → refus, pas de repli silencieux
      const channel = mapWorkDataClassToChannel(work.dataClass as WorkDataClass)
      if (!channel) {
        return { ok: false, message: t('密级映射缺失，拒绝调用'), gatewayRef: { outcome: 'denied', dataClass: work.dataClass } }
      }
      const messages = input.args['messages']
      if (!Array.isArray(messages) || messages.length === 0) {
        return { ok: false, message: t('模型调用参数缺少 messages 数组'), gatewayRef: { outcome: 'denied' } }
      }
      const maxTokens = typeof input.tool.constraints?.['maxTokens'] === 'number'
        ? input.tool.constraints['maxTokens'] as number
        : undefined
      try {
        const result = await hub.invoke({
          model: input.tool.registryId,
          messages: messages as Array<{ role: string; content: string }>,
          orgId: work.workOrgId,
          // Attribution technique : sujet Agent confirmé côté serveur (budget/rapports rattachés au même sujet, pas de dérive selon la chaîne subject)
          subject: `agent:${work.agentId}`,
          ...(maxTokens !== undefined ? { maxTokens } : {}),
          dataClass: channel,
        })
        return {
          ok: true,
          value: {
            content: result.content,
            model: result.model,
            inputTokens: result.inputTokens,
            outputTokens: result.outputTokens,
            costCents: result.costCents,
          },
          content: result.content,
          gatewayRef: {
            model: result.model,
            inputTokens: result.inputTokens,
            outputTokens: result.outputTokens,
            dataClass: channel,
            workRef: `${work.runId}/${input.invocationId}`,
          },
          // Additive groupe 4 : collecté quand la passerelle renvoie l'ID d'événement usage, sinon défaut honnête
          ...(typeof result.usageEventId === 'string' && result.usageEventId
            ? { usageEventIds: [result.usageEventId] }
            : {}),
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        // Disjoncteur de budget/franchissement de niveau = refus de politique (arrêt) ; erreurs réseau/HTTP amont = échec d'exécution
        const policyDenied = /预算熔断|分级越界|数据分级越界|已下线|不存在/.test(message)
        return {
          ok: false,
          message,
          gatewayRef: { ...(policyDenied ? { outcome: 'denied' } : {}), dataClass: channel },
        }
      }
    },
  }
}
