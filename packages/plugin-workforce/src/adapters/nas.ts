/**
 * Adaptateur de ressources de fichiers NAS (§4.5/D.3 : capacité de fichiers ≠ capacité de recherche de connaissances ; autorisation action par action).
 *
 * Discipline d'identité (§4.5-1) :
 *   - Sans surveillance : sujet de service de poste — actor.id prend `agent:<agentId>` (avec deux-points, le
 *     onBehalfHeaders de nasRegistry ne produit pas d'en-tête X-On-Behalf-User, pas d'usurpation des permissions d'un humain) ;
 *   - Mandat humain : args.onBehalfUser n'est transmis que s'il concorde avec work.requesterUserId après vérification
 *     (requesterUserId est écrit côté serveur par la couche port depuis la chaîne human ; en son absence, toujours ignoré et consigné).
 * Discipline d'écriture (§4.5-2) : le contenu de write ne peut provenir que d'un artefact contrôlé (args.artifactId →
 * lecture du staging contrôlé par workforceArtifacts), chemin local interdit (toute apparition de args.localPath est refusée).
 */
import { readFile } from 'node:fs/promises'
import type {
  AdapterInvokeInput,
  AdapterInvokeResult,
  AdapterProbeResult,
  ResourceAdapter,
  ArtifactRecord,
  WorkforceArtifacts,
} from '../contract.ts'
import type { IdentityResolution, ResourceGrantSpec } from '../contract.ts'
import { ARTIFACT_MAX_BYTES } from '../contract.ts'
import { t } from '../../../platform-i18n/src/index.ts'
import type { WorkExecutionContext } from '../../../platform-core/src/workforce-port.ts'

/** Face de sondage structurée de nasRegistry (signature réelle dans plugin-nas/src/index.ts NasRegistryService). */
interface NasRegistryProbe {
  get?: (id: string) => { id: string; name: string; status: string } | undefined
  listFiles?: (id: string, path?: string, actor?: { id: string; name: string }) => Promise<unknown>
  search?: (id: string, pattern: string, path?: string, actor?: { id: string; name: string }) => Promise<unknown>
  downloadFile?: (id: string, path: string, actor: { id: string; name: string }) => Promise<{ localFile: string; bytes: number; savedTo?: string }>
  uploadFile?: (id: string, input: { buffer?: Buffer; localFile?: string; destPath: string; actor: { id: string; name: string }; onBehalf?: boolean }) => Promise<{ path: string; sizeBytes: number }>
}

/** Face de sondage structurée de workforceArtifacts (service de cette extension, signature réelle de readBase64). */
interface ArtifactsProbe {
  readBase64?: (caller: { kind: 'machine'; principalId: string; refType?: string; refId?: string }, artifactId: string) => Promise<string>
  get?: (caller: { kind: 'machine'; principalId: string; refType?: string; refId?: string }, artifactId: string) => Promise<ArtifactRecord>
}

const MACHINE_CALLER = (work: WorkExecutionContext) => ({
  kind: 'machine' as const,
  principalId: work.principalId,
  refType: 'agent',
  refId: work.agentId,
})

export function createNasAdapter(ctx: {
  nasRegistry?: NasRegistryProbe
  workforceArtifacts?: ArtifactsProbe
}): ResourceAdapter {
  const registry = (): NasRegistryProbe => ctx.nasRegistry ?? {}
  const artifacts = (): ArtifactsProbe => ctx.workforceArtifacts ?? {}

  const denied = (message: string, gatewayRef?: Record<string, unknown>): AdapterInvokeResult =>
    ({ ok: false, message, gatewayRef: { outcome: 'denied', ...gatewayRef } })

  /** Revérification du périmètre métier pathPrefixes (la couche invocation valide args.path, ici on revérifie tous les paramètres de chemin). */
  const assertPathScope = (tool: AdapterInvokeInput['tool'], path: string): string | null => {
    const prefixes = tool.constraints?.['pathPrefixes']
    if (!Array.isArray(prefixes) || prefixes.length === 0) return null
    if (prefixes.some((prefix) => typeof prefix === 'string' && path.startsWith(prefix))) return null
    return t('路径 {path} 超出授权目录范围', { path })
  }

  /** Sujet du mandat humain : la chaîne humaine n'est transmise que si work.requesterUserId existe et concorde avec args.onBehalfUser. */
  const actorFor = (work: WorkExecutionContext, args: Record<string, unknown>): { id: string; name: string; onBehalf: boolean } => {
    const requested = typeof args['onBehalfUser'] === 'string' ? args['onBehalfUser'] as string : ''
    // onBehalfUser ignoré en l'absence de requesterUserId (anti-falsification de chaîne humaine) ; le sujet de service de poste ne porte pas d'en-tête d'identité
    if (requested && work.requesterUserId && requested === work.requesterUserId) {
      return { id: work.requesterUserId, name: t('人代办:{id}', { id: work.employeeId }), onBehalf: true }
    }
    return { id: `agent:${work.agentId}`, name: t('数字员工:{id}', { id: work.employeeId }), onBehalf: false }
  }

  return {
    kind: 'nas',

    async probeGrant(spec: ResourceGrantSpec, _resolution: IdentityResolution): Promise<AdapterProbeResult> {
      const hub = registry()
      if (typeof hub.get !== 'function') {
        return { ok: false, message: t('nasRegistry 未提供资产查询能力') }
      }
      const nas = hub.get(spec.registryId)
      if (!nas) return { ok: false, message: t('NAS 资产不存在：{id}', { id: spec.registryId }) }
      const prefixes = spec.constraints?.['pathPrefixes']
      return {
        ok: true,
        ref: `nas-scope:${JSON.stringify(Array.isArray(prefixes) ? prefixes : [])}`,
      }
    },

    async invoke(input: AdapterInvokeInput): Promise<AdapterInvokeResult> {
      const hub = registry()
      const work = input.work
      const action = input.tool.action
      const actor = actorFor(work, input.args)
      const path = typeof input.args['path'] === 'string' ? input.args['path'] as string : '/'
      const pathDenial = assertPathScope(input.tool, path)
      if (pathDenial && action !== 'search' && action !== 'list') return denied(pathDenial)

      try {
        switch (action) {
          case 'read': {
            if (typeof hub.downloadFile !== 'function') return denied(t('nasRegistry 未提供文件下载能力，未支持'))
            const result = await hub.downloadFile(input.tool.registryId, path, actor)
            // Contenu relu via le staging contrôlé (texte ≤8 Mo) ; le chemin local de la plateforme n'est pas exposé à l'employé
            let content: string | undefined
            if (result.bytes > 0 && result.bytes <= ARTIFACT_MAX_BYTES) {
              try {
                const buffer = await readFile(result.localFile)
                content = buffer.toString('utf8')
              } catch {
                content = undefined
              }
            }
            return {
              ok: true,
              ...(content !== undefined ? { content } : {}),
              value: {
                path,
                bytes: result.bytes,
                ...(content === undefined ? { note: t('内容超限或读取失败，已落平台受控 staging，请经 artifact 通道获取') } : {}),
              },
              gatewayRef: { nasId: input.tool.registryId, path, bytes: result.bytes, onBehalf: actor.onBehalf },
            }
          }
          case 'search': {
            if (typeof hub.search !== 'function') return denied(t('nasRegistry 未提供文件检索能力，未支持'))
            const pattern = typeof input.args['pattern'] === 'string' ? input.args['pattern'] as string : ''
            if (!pattern) return denied(t('检索缺少 pattern 参数'))
            const result = await hub.search(input.tool.registryId, pattern, path, actor)
            return { ok: true, value: result, gatewayRef: { nasId: input.tool.registryId, pattern, path, onBehalf: actor.onBehalf } }
          }
          case 'list': {
            if (typeof hub.listFiles !== 'function') return denied(t('nasRegistry 未提供目录列举能力，未支持'))
            const result = await hub.listFiles(input.tool.registryId, path, actor)
            return { ok: true, value: result, gatewayRef: { nasId: input.tool.registryId, path, onBehalf: actor.onBehalf } }
          }
          case 'write': {
            // L'écriture n'accepte que la source artefact contrôlé (V15 : la face d'appel de l'employé refuse tout chemin local arbitraire)
            if (typeof input.args['localPath'] === 'string' || typeof input.args['localFile'] === 'string') {
              return denied(t('禁止本地路径写入：write 内容仅允许来自受控 artifact'))
            }
            if (typeof hub.uploadFile !== 'function') return denied(t('nasRegistry 未提供文件上传能力，未支持'))
            const artifactId = typeof input.args['artifactId'] === 'string' ? input.args['artifactId'] as string : ''
            if (!artifactId) return denied(t('NAS 写入必须引用受控 artifact（args.artifactId）'))
            const probe = artifacts()
            if (typeof probe.get !== 'function' || typeof probe.readBase64 !== 'function') {
              return denied(t('workforceArtifacts 未就绪，无法读取受控 artifact'))
            }
            const caller = MACHINE_CALLER(work)
            const artifact = await probe.get(caller, artifactId)
            const base64 = await probe.readBase64(caller, artifactId)
            const destPath = path
            const result = await hub.uploadFile(input.tool.registryId, {
              buffer: Buffer.from(base64, 'base64'),
              destPath,
              actor,
              // Sans surveillance : sujet de service de poste (sans X-On-Behalf-User) ; mandat humain : transmission de la chaîne humaine
              onBehalf: actor.onBehalf ? true : false,
            })
            return {
              ok: true,
              value: { path: result.path, sizeBytes: result.sizeBytes, artifactId },
              gatewayRef: {
                nasId: input.tool.registryId,
                path: result.path,
                bytes: result.sizeBytes,
                sha256: artifact.sha256,
                onBehalf: actor.onBehalf,
                workRef: `${work.runId}/${input.invocationId}`,
              },
            }
          }
          case 'share':
            // Le partage est une action de permission distincte (§4.5) ; non ouvert en phase 1 (le service de liens de partage n'est pas dans la face d'appel contrôlée)
            return denied(t('NAS 分享动作适配一期未开放（外发分享需独立授权与人工通道）'))
          default:
            return denied(t('未知 NAS 动作：{action}', { action }))
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        // Écriture en timeout/incertitude réseau → résultat inconnu (§11.5-4)
        const uncertain = action === 'write' && /超时|timeout|abort|ECONNRESET|ETIMEDOUT/i.test(message)
        return {
          ok: false,
          message,
          ...(uncertain ? { outcomeUnknown: true } : {}),
          gatewayRef: { nasId: input.tool.registryId, path, ...(uncertain ? { outcome: 'unknown' } : {}) },
        }
      }
    },
  }
}
