/**
 * Adaptateur de ressources Skill (typage §4.4 : compétence instruction/méthode = charger un texte à version figée, jamais exécuter un programme arbitraire).
 *
 * probeGrant : preuve du verrouillage de version par skillPins (version + résumé de contenu, figé par capability-manifest via
 * skillHub.resolveSkillPin ; on vérifie ici que la capacité de sondage de skillHub est en place).
 * invoke : sondage structuré skillHub.download(skillId, version, user) (signature réelle, renvoie la version publiée
 * { content }) → renvoie le contenu textuel + preuve version/résumé ; les compétences de type programme/script ne sont pas prises en charge en phase 1,
 * une capacité manquante est honnêtement signalée non prise en charge, sans faire passer une implémentation vide pour un succès.
 */
import { createHash } from 'node:crypto'
import { t } from '../../../platform-i18n/src/index.ts'
import type {
  AdapterInvokeInput,
  AdapterInvokeResult,
  AdapterProbeResult,
  ResourceAdapter,
} from '../contract.ts'
import type { IdentityResolution, ResourceGrantSpec } from '../contract.ts'

/** Face de sondage structurée de skillHub (signature réelle dans plugin-skillhub/src/index.ts SkillHubService). */
interface SkillHubProbe {
  download?: (skillId: string, version: string, user: { id: string; name: string }) => { content: string }
  resolveSkillPin?: (skillId: string, version?: string) => { skillId: string; version: string; contentHash: string }
}

export function createSkillAdapter(ctx: {
  skillHub?: SkillHubProbe
}): ResourceAdapter {
  const hub = (): SkillHubProbe => ctx.skillHub ?? {}

  return {
    kind: 'skill',

    async probeGrant(spec: ResourceGrantSpec, _resolution: IdentityResolution): Promise<AdapterProbeResult> {
      const probe = hub()
      if (typeof probe.resolveSkillPin !== 'function') {
        return { ok: false, message: t('skillHub 未提供版本锁定能力（resolveSkillPin 缺席）') }
      }
      try {
        const version = typeof spec.constraints?.['version'] === 'string' ? spec.constraints['version'] as string : undefined
        const pin = probe.resolveSkillPin(spec.registryId, version)
        if (!pin || !pin.version) return { ok: false, message: t('技能 {skillId} 无法锁定发布版本', { skillId: spec.registryId }) }
        // ref = preuve version + résumé (D.3 : version et résumé figés, preuve de chargement)
        return { ok: true, ref: `skill:${spec.registryId}@${pin.version} sha256:${String(pin.contentHash).slice(0, 16)}` }
      } catch (error) {
        return { ok: false, message: t('技能版本锁定失败：{message}', { message: error instanceof Error ? error.message : String(error) }) }
      }
    },

    async invoke(input: AdapterInvokeInput): Promise<AdapterInvokeResult> {
      const probe = hub()
      if (typeof probe.download !== 'function') {
        return { ok: false, message: t('skillHub 未提供固定版本文本读取能力（download 缺席），未支持'), gatewayRef: { outcome: 'denied' } }
      }
      const constraints = input.tool.constraints ?? {}
      const version = typeof constraints['version'] === 'string' ? constraints['version'] : ''
      if (!version) {
        return { ok: false, message: t('能力清单未锁定技能版本，拒绝加载'), gatewayRef: { outcome: 'denied' } }
      }
      try {
        const { content } = probe.download(input.tool.registryId, version, {
          id: input.work.agentId || input.work.principalId,
          name: t('数字员工:{id}', { id: input.work.employeeId }),
        })
        const contentHash = createHash('sha256').update(content).digest('hex')
        // Vérification du résumé (§4.4 : preuve de chargement — le contenu réellement chargé doit correspondre au verrouillage de version)
        const pinnedHash = typeof constraints['contentHash'] === 'string' ? constraints['contentHash'] : ''
        if (pinnedHash && pinnedHash !== contentHash) {
          return {
            ok: false,
            message: t('技能内容摘要与版本锁定不一致（pin={pinned} 实际={actual}），拒绝加载', { pinned: pinnedHash.slice(0, 16), actual: contentHash.slice(0, 16) }),
            gatewayRef: { outcome: 'denied', skillId: input.tool.registryId, version },
          }
        }
        // Type instruction/combinaison d'outils : ne renvoie que le contenu textuel (comme matière première d'instruction), n'exécute jamais un programme arbitraire
        return {
          ok: true,
          content,
          value: { skillId: input.tool.registryId, version, content },
          gatewayRef: { skillId: input.tool.registryId, version, contentHash, workRef: `${input.work.runId}/${input.invocationId}` },
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        return { ok: false, message: t('技能文本加载失败：{message}', { message }), gatewayRef: { skillId: input.tool.registryId, version, outcome: 'denied' } }
      }
    },
  }
}
