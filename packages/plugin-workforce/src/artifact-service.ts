/**
 * Service d'artefacts contrôlés (chemin d'implémentation §4.5/§D.12 : les entrées/sorties de fichiers de l'employé passent toujours par le staging contrôlé,
 * pas de chemin local de plateforme ouvert — le chemin local d'un runtime distant n'est ni un chemin de la plateforme, et ne doit pas non plus
 * procurer ainsi la capacité de lire un fichier arbitraire de la plateforme).
 *
 * Le contenu entre par base64 dans le corps de requête vers le répertoire contrôlé du serveur ; le nettoyage du nom de fichier interdit les séparateurs de chemin et `..` ;
 * l'employé ne peut écrire que des artefacts de son propre run ; lecture autorisée = lui-même ou workforce.read de la même organisation.
 */
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId } from '../../platform-core/src/ids.ts'
import type {
  ArtifactRecord,
  PermitRecord,
  WorkforceArtifacts,
  WorkforceIdentityResolver,
  WorkforcePermits,
  WorkforceStore,
} from './contract.ts'
import { WorkforceError, ARTIFACT_MAX_BYTES } from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type { WorkCallerRef } from '../../platform-core/src/workforce-port.ts'

export class ArtifactService extends Service implements WorkforceArtifacts {
  static readonly provide = 'workforceArtifacts'

  /** Répertoire staging contrôlé : même base que SQLite (config.dataDir ?? <cwd>/data). */
  private readonly stagingDir: string

  constructor(ctx: Context, config: { dataDir?: string } = {}) {
    super(ctx, 'workforceArtifacts')
    this.stagingDir = join(config.dataDir ?? join(process.cwd(), 'data'), 'workforce-artifacts')
    mkdirSync(this.stagingDir, { recursive: true })
  }

  // -- Dépendances -------------------------------------------------------------

  private get store(): WorkforceStore {
    const store = (this.ctx as unknown as { workforceStore?: WorkforceStore }).workforceStore
    if (!store || typeof store.txn !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceStore 未就绪（迁移未完成）'), 503)
    }
    return store
  }

  private get identity(): WorkforceIdentityResolver {
    const resolver = (this.ctx as unknown as { workforceIdentity?: WorkforceIdentityResolver }).workforceIdentity
    if (!resolver || typeof resolver.resolveByCaller !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceIdentity 未就绪'), 503)
    }
    return resolver
  }

  private get permits(): WorkforcePermits {
    const permits = (this.ctx as unknown as { workforcePermits?: WorkforcePermits }).workforcePermits
    if (!permits || typeof permits.activeForRun !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforcePermits 未就绪'), 503)
    }
    return permits
  }

  // -- Téléversement contrôlé -----------------------------------------------------------

  async createUpload(caller: WorkCallerRef, input: { name: string; contentType: string; contentBase64: string; runId?: string }): Promise<ArtifactRecord> {
    // Identité : seuls les employés numériques gérés peuvent écrire (D12)
    const resolution = await this.identity.resolveByCaller(caller)
    if (!resolution) throw new WorkforceError('EMPLOYEE_NOT_ACTIVE', t('非受管数字员工，不能写入 artifact'))
    // Taille : plafond dur (8 Mo par défaut)
    const buffer = Buffer.from(input.contentBase64, 'base64')
    if (buffer.length > ARTIFACT_MAX_BYTES) {
      throw new WorkforceError('ARTIFACT_SCOPE_DENIED', t('超出 artifact 大小上限（{max} 字节）', { max: ARTIFACT_MAX_BYTES }))
    }
    // Rattachement au run : si runId est porté, il doit exister un permit valide émis pour cet employé et lié à ce run (V06 : refus inter-run)
    if (input.runId) {
      const permit = this.permits.activeForRun(input.runId)
      if (!permit || permit.employeeId !== resolution.employee.id) {
        throw new WorkforceError('ARTIFACT_SCOPE_DENIED', t('该 run 不归属当前员工，拒绝写入 artifact'))
      }
    }
    // Nettoyage du nom de fichier : séparateurs de chemin et .. interdits (V15 : aucun localFile arbitraire exposé à l'employé)
    const safeName = this.sanitizeName(input.name)
    const id = newId('art')
    const storagePath = join(this.stagingDir, `${id}__${safeName}`)
    writeFileSync(storagePath, buffer)
    // TableStore.insert renvoie void (effet de bord d'écriture) — l'enregistrement est renvoyé via la variable locale, jamais le résultat d'insert()
    const record: ArtifactRecord = {
      id,
      employeeId: resolution.employee.id,
      runId: input.runId ?? '',
      orgId: resolution.employee.orgId,
      name: safeName,
      contentType: input.contentType || 'application/octet-stream',
      sizeBytes: buffer.length,
      sha256: createHash('sha256').update(buffer).digest('hex'),
      storagePath,
      source: 'upload',
      createdAt: new Date().toISOString(),
    }
    this.store.artifacts.insert(record)
    return record
  }

  /** Nettoyage du nom de fichier : supprime séparateurs de chemin, octets nuls et séquences .. ; nom vide remplacé par artifact. */
  private sanitizeName(name: string): string {
    const cleaned = String(name ?? '')
      .replace(/[\\/\x00]/g, '_')
      .replace(/\.{2,}/g, '_')
      .replace(/[\r\n\t]/g, '_')
      .trim()
    return cleaned || 'artifact'
  }

  // -- Lecture ---------------------------------------------------------------

  async get(caller: WorkCallerRef, artifactId: string): Promise<ArtifactRecord> {
    const record = this.store.artifacts.get(artifactId)
    if (!record) throw new WorkforceError('ARTIFACT_SCOPE_DENIED', t('artifact 不存在或无权访问'), 404)
    await this.assertReadable(caller, record)
    return record
  }

  async readBase64(caller: WorkCallerRef, artifactId: string): Promise<string> {
    const record = await this.get(caller, artifactId)
    return readFileSync(record.storagePath).toString('base64')
  }

  /** Jugement d'appartenance : l'employé lui-même, ou un human (l'entrée a déjà vérifié les points de permission) de la même organisation que l'artefact. */
  private async assertReadable(caller: WorkCallerRef, record: ArtifactRecord): Promise<void> {
    const resolution = await this.identity.resolveByCaller(caller)
    if (resolution && resolution.employee.id === record.employeeId) return
    if (caller.kind === 'human' && caller.userId) {
      const orgId = this.humanOrgId(caller)
      if (orgId !== null && orgId === record.orgId) return
    }
    throw new WorkforceError('ARTIFACT_SCOPE_DENIED', t('无权访问该 artifact（仅本人或同组织主体）'))
  }

  /** Recherche inverse de l'organisation du human (sondage structuré iam ; échec de résolution fail-closed). */
  private humanOrgId(caller: WorkCallerRef): string | null {
    try {
      const iam = (this.ctx as unknown as { iam?: { users?: () => { get(id: string): { orgId?: string } | undefined } } }).iam
      const user = typeof iam?.users === 'function' ? iam.users().get(caller.userId ?? '') : undefined
      return typeof user?.orgId === 'string' ? user.orgId : null
    } catch {
      return null
    }
  }

  /** Canal interne (consommé par l'adaptateur d'écriture NAS) : le rattachement au run est déjà vérifié par le permit, lecture directe par chemin de stockage. */
  readByPermit(permit: PermitRecord, artifactId: string): ArtifactRecord {
    const record = this.store.artifacts.get(artifactId)
    if (!record
      || record.employeeId !== permit.employeeId
      || (record.runId !== '' && record.runId !== permit.runId)) {
      throw new WorkforceError('ARTIFACT_SCOPE_DENIED', t('artifact 不存在或不属于该员工/该 run'))
    }
    return record
  }
}
