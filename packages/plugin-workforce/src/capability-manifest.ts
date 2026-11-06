/**
 * Service d'inventaire de capacités (chemin d'implémentation §8.1/§9.2, annexe A décision 5).
 *
 * L'inventaire ne descend que les poignées d'outils permises par la tâche (`<registryId>.<action>`) ; le runtime ne peut référencer que la poignée,
 * pas apporter sa propre clé de ressource. Un outil à risque inconnu n'est pas ouvert par défaut en écriture ; les contraintes de paramètres (parameters schema)
 * sont exécutées côté serveur par la couche d'appel (invocation-service), sans dépendre des prompts.
 *
 * Autorisation skill → skillPins (version figée + résumé de contenu, sondage structuré resolveSkillPin du groupe 5,
 * absent → build lève une erreur et fait échouer activate — fail-closed), et génération simultanée d'une poignée `.load`
 * pour que le runtime charge le texte à version figée via workforce_invoke (§4.4 compétence de type instruction, jamais d'exécution de programme).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  WorkforceError,
  type AppointmentRecord,
  type ManifestRecord,
  type ManifestToolHandle,
  type ResourceGrantRecord,
  type SkillPin,
  type WorkforceCapabilities,
  type WorkforceStore,
} from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'

/** Mapping des risques au niveau action NAS (§4.5 : lecture de connaissances et partage externe doivent être des permissions distinctes). */
const NAS_WRITE_ACTIONS = new Set(['write', 'share'])

function parseJson<T>(text: string, fallback: T): T {
  try {
    const value = JSON.parse(text) as T
    return value ?? fallback
  } catch {
    return fallback
  }
}

export class CapabilityManifestService extends Service implements WorkforceCapabilities {
  static readonly provide = 'workforceCapabilities'

  constructor(ctx: Context) {
    super(ctx, 'workforceCapabilities')
  }

  private get store(): WorkforceStore {
    const store = (this.ctx as unknown as { workforceStore?: WorkforceStore }).workforceStore
    if (!store || typeof store.txn !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceStore 未就绪（迁移未完成）'), 503)
    }
    return store
  }

  /** Sonde de la capacité de verrouillage de version de skillHub (additive groupe 5 : resolveSkillPin(skillId, version?)). */
  private resolveSkillPin(skillId: string, version?: string): SkillPin {
    const skillHub = (this.ctx as unknown as {
      skillHub?: { resolveSkillPin?: (skillId: string, version?: string) => SkillPin }
    }).skillHub
    if (!skillHub || typeof skillHub.resolveSkillPin !== 'function') {
      // fail-closed : sans capacité de verrouillage de version, aucune nomination ne peut être activée (§4.4/D09 — installer ne vaut pas chargement vérifiable)
      throw new Error(t('skillHub 未提供版本锁定能力，任用无法激活'))
    }
    return skillHub.resolveSkillPin(skillId, version)
  }

  // -- Construction -------------------------------------------------------------

  buildForAppointment(appointmentId: string): ManifestRecord {
    const store = this.store
    const appointment = store.appointments.get(appointmentId)
    if (!appointment) throw new WorkforceError('APPOINTMENT_NOT_EFFECTIVE', t('任用不存在：{id}', { id: appointmentId }))
    // Ne consomme que les autorisations en vigueur (ref reconstitué après succès des sondes) ; les autorisations preparing/failed ne produisent pas de poignée
    const grants = store.grants.findWhere({ appointmentId }).filter((grant) => grant.status === 'effective')

    const tools: ManifestToolHandle[] = []
    const skillPins: SkillPin[] = []
    for (const grant of grants) {
      const actions = parseJson<string[]>(grant.actionsJson, [])
      const constraints = parseJson<Record<string, unknown>>(grant.constraintsJson, {})
      if (grant.kind === 'skill') {
        // skill : verrouillage de version figée (version spécifiable via grant.constraints.version, défaut = version publiée courante)
        const pin = this.resolveSkillPin(grant.registryId, typeof constraints['version'] === 'string' ? constraints['version'] as string : undefined)
        skillPins.push(pin)
        // Descend simultanément une poignée de chargement (§4.4 type instruction : charge le texte à version figée, n'exécute pas de programme)
        tools.push({
          handle: `${grant.registryId}.load`,
          kind: 'skill',
          resourceRef: `skill:${grant.registryId}`,
          registryId: grant.registryId,
          action: 'load',
          risk: 'read',
          constraints: { version: pin.version, contentHash: pin.contentHash },
          description: t('加载技能 {skillId} 固定版本 {version} 的指令文本（不执行程序）', { skillId: grant.registryId, version: pin.version }),
        })
        continue
      }
      if (grant.kind === 'model') {
        // Modèle : poignée unique invoke ; la contrainte allowedModels descend avec la poignée et est vérifiée des deux côtés port/adaptateur
        tools.push({
          handle: `${grant.registryId}.invoke`,
          kind: 'model',
          resourceRef: `model:${grant.registryId}`,
          registryId: grant.registryId,
          action: 'invoke',
          risk: grant.risk,
          constraints,
          description: t('调用模型 {modelId}（密级与预算经模型网关原有链路）', { modelId: grant.registryId }),
        })
        continue
      }
      if (grant.kind === 'nas') {
        // NAS : poignée par action (graduation des risques read/search/list/write/share)
        for (const action of actions) {
          const risk = NAS_WRITE_ACTIONS.has(action) ? (grant.risk === 'admin' ? 'admin' : 'write') : 'read'
          tools.push({
            handle: `${grant.registryId}.${action}`,
            kind: 'nas',
            resourceRef: `nas:${grant.registryId}`,
            registryId: grant.registryId,
            action,
            risk,
            constraints,
            description: t('NAS 文件动作 {action}（目录范围约束服务端执行）', { action }),
          })
        }
        continue
      }
      // mcp / connector / app : poignée par action
      for (const action of actions) {
        tools.push({
          handle: `${grant.registryId}.${action}`,
          kind: grant.kind,
          resourceRef: `${grant.kind}:${grant.registryId}`,
          registryId: grant.registryId,
          action,
          risk: grant.risk,
          constraints,
        })
      }
    }

    return store.txn(() => {
      const existing = store.manifests.findWhere({ appointmentId })
      const version = existing.reduce((max, item) => Math.max(max, item.version), 0) + 1
      // Les anciens inventaires actifs passent retired (roulement de versions : après mutation/montée en grade des autorisations, les anciennes poignées ne sont plus utilisables)
      for (const item of existing.filter((manifest) => manifest.status === 'active')) {
        store.manifests.update(item.id, { status: 'retired' })
      }
      return store.manifests.insert({
        id: `wfmanifest_${appointmentId}_v${version}`,
        appointmentId,
        version,
        toolsJson: JSON.stringify(tools),
        skillPinsJson: JSON.stringify(skillPins),
        status: 'active',
        createdAt: new Date().toISOString(),
      })
    })
  }

  // -- Requêtes -------------------------------------------------------------

  get(manifestId: string): ManifestRecord {
    const manifest = this.store.manifests.get(manifestId)
    if (!manifest) throw new WorkforceError('TOOL_UNKNOWN', t('能力清单不存在：{id}', { id: manifestId }), 404)
    return manifest
  }

  activeForAppointment(appointmentId: string): ManifestRecord | undefined {
    return this.store.manifests.findWhere({ appointmentId })
      .filter((manifest) => manifest.status === 'active')
      .sort((a, b) => b.version - a.version)[0]
  }

  toolsFor(manifestId: string): ManifestToolHandle[] {
    return parseJson<ManifestToolHandle[]>(this.get(manifestId).toolsJson, [])
  }

  /** Résolution de poignée : handle de la forme `<registryId>.<action>`, correspondance seulement si kind/registryId/action concordent tous (§9.2). */
  resolveTool(manifestId: string, handle: string): ManifestToolHandle | undefined {
    return this.toolsFor(manifestId).find((tool) => tool.handle === handle
      && `${tool.registryId}.${tool.action}` === handle)
  }

  /** Enregistrement actuellement en vigueur de la nomination (pour la vérification combinée de l'admission). */
  appointmentOf(appointmentId: string): AppointmentRecord | undefined {
    return this.store.appointments.get(appointmentId)
  }

  /** Lecture des grants (la reconstitution du ref par la sonde est consommée par appointment-service, ici à des fins de diagnostic). */
  grantsFor(appointmentId: string): ResourceGrantRecord[] {
    return this.store.grants.findWhere({ appointmentId })
  }
}
