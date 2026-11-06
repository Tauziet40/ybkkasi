/**
 * @dsh-ops/plugin-nas — gestion des actifs NAS (classe FS stockage de fichiers).
 *
 * Modèle d'accès : chaque NAS est accédé via une « passerelle de fichiers MCP » (voir synology-filestation-mcp) —
 * adresse de passerelle + jeton Bearer + en-tête de routage d'appareil X-NAS-IP ; toutes les opérations de fichiers (liste/recherche/création-suppression/
 * upload/download/renommage/déplacement-copie) passent par tools/call de la passerelle, la plateforme ne se connecte jamais aux API privées DSM.
 *
 * Sur le socle resource-core (Pattern A) : table d'attributs + machine à états de cycle de vie + graphe de dépendances réutilisés,
 * cette extension apporte : client de passerelle, sondage de santé, découverte d'outils, face d'opérations de fichiers et configuration du stockage des paquets Skill.
 * Toutes les écritures de fichiers sont tracées dans l'audit ; les lectures ne sont appelables que sur les actifs en ligne ; toutes les opérations entrent au metering usage
 * (ressource nas:*, référentiel calls/bytes, tarif nul par défaut — l'observation d'abord, la facturation décidée par le tarif).
 */
import { mkdir, writeFile, readFile } from 'node:fs/promises'
import { join, normalize, sep } from 'node:path'
import { tmpdir } from 'node:os'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, newId, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type { ResourceEntity } from '../../plugin-resource-core/src/index.ts'
import { NasMcpClient, type McpToolInfo } from './client.ts'
import { NAS_TYPE_SPEC } from './schema.ts'
import { NasAuthzService } from './authz.ts'
import { NasShareLinkService } from './share-link.ts'
import * as nasTools from './tools.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

export interface NasHealthRecord extends RecordBase {
  nasId: string
  status: 'healthy' | 'degraded' | 'down' | 'unknown'
  latencyMs: number
  lastProbeAt: string
  consecutiveFails: number
  serverName?: string
}

export interface NasToolCacheRecord extends RecordBase {
  nasId: string
  tools: McpToolInfo[]
  syncedAt: string
}

/** Configuration du backend de stockage des paquets Skill (singleton) : local = stockage en ligne de la plateforme ; nas = upload vers l'actif NAS désigné à la publication. */
export interface SkillStorageConfigRecord extends RecordBase {
  mode: 'local' | 'nas'
  nasId?: string
  basePath?: string
  updatedAt: string
  updatedBy: string
}

/**
 * Acteur d'opération de fichiers (additive D15) : kind est explicitement marqué par la face appelante — 'machine' ne transmet jamais
 * X-On-Behalf-User (un ID de principal machine n'usurpe jamais un humain) ; par défaut (appelants internes existants), la logique de jugement d'origine est conservée.
 */
export type NasFsActor = { id: string; name: string; kind?: 'human' | 'machine' }

/**
 * Options additionnelles d'appel de fichiers (additive D15) : serviceSubject est réservé aux chemins internes de confiance — quand du code serveur le passe explicitement
 * (ex. adaptateur de poste plugin-workforce), l'exécution se fait sous le principal de service de poste lié au jeton de passerelle : sans X-On-Behalf-User,
 * sans emprunter aucune permission de données d'un humain ; le metering est attribué à svc:<serviceSubject>.
 * La face outils HTTP (nas_fs_*) interdit ce paramètre (structurellement inatteignable : fsCall est une méthode privée du service).
 */
export interface NasFsCallOptions {
  serviceSubject?: string
}

/**
 * Racine de la liste blanche du staging contrôlé de l'employé numérique géré (constantes D12/V15) : lors d'un upload par nas_fs_upload d'un passage géré,
 * localFile n'accepte que le préfixe `<dataDir>/workforce-artifacts/` (zone d'upload contrôlée des artefacts workforce),
 * tout autre chemin de la plateforme est refusé en chinois (ARTIFACT_SCOPE_DENIED), avec invitation à passer par POST /api/workforce/artifacts.
 */
export const WORKFORCE_ARTIFACTS_ROOT = join(process.cwd(), 'data', 'workforce-artifacts')

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class NasRegistryService extends Service {
  static readonly provide = 'nasRegistry'

  private clients = new Map<string, { client: NasMcpClient; signature: string }>()

  constructor(ctx: Context) {
    super(ctx, 'nasRegistry')
    ctx.resourceCore.registerType(NAS_TYPE_SPEC)
  }

  health(): CollectionLike<NasHealthRecord> {
    return this.ctx.opsStorage.collection<NasHealthRecord>('nas:health')
  }

  toolCache(): CollectionLike<NasToolCacheRecord> {
    return this.ctx.opsStorage.collection<NasToolCacheRecord>('nas:tools')
  }

  skillStorage(): CollectionLike<SkillStorageConfigRecord> {
    return this.ctx.opsStorage.collection<SkillStorageConfigRecord>('skill:storage')
  }

  // -- Enregistrement et cycle de vie -------------------------------------------------------

  register(input: { name: string; slug?: string; attrs?: Record<string, unknown>; ownerId: string; orgId: string }): ResourceEntity {
    const entity = this.ctx.resourceCore.create('nas', input)
    this.health().insert({ id: `hlt_${entity.id}`, nasId: entity.id, status: 'unknown', latencyMs: 0, lastProbeAt: '', consecutiveFails: 0 })
    this.ctx.platformBus.emit(PlatformEvents.NasRegistered, { id: entity.id, name: entity.name, slug: entity.slug, actor: input.ownerId, type: 'nas' })
    return entity
  }

  update(id: string, patch: { name?: string; attrs?: Record<string, unknown> }): ResourceEntity {
    const entity = this.ctx.resourceCore.update('nas', id, patch)
    // Invalide le client de passerelle en cache après changement des attributs d'accès (rotation de jeton/changement de passerelle à effet immédiat)
    this.clients.delete(id)
    return entity
  }

  get(id: string): ResourceEntity | undefined {
    return this.ctx.resourceCore.get('nas', id)
  }

  list(filter?: { status?: string; orgId?: string; q?: string }): ResourceEntity[] {
    return this.ctx.resourceCore.list('nas', filter)
  }

  /** Mise en ligne : d'abord un sondage initialize de la passerelle (injoignable = mise en ligne refusée), puis la transition de la machine à états et la découverte d'outils. */
  async online(id: string, actor: string): Promise<ResourceEntity> {
    const nas = this.requireNas(id)
    const probe = await this.probe(id)
    if (probe.status === 'down') {
      throw new Error(t('网关不可达，暂不能上线（{url}）', { url: String(nas.attrs['gatewayUrl'] ?? '') }))
    }
    const result = this.ctx.resourceCore.transition('nas', id, 'online', actor)
    this.ctx.platformBus.emit(PlatformEvents.NasOnlined, { id, name: result.entity.name, slug: result.entity.slug, actor, type: 'nas' })
    void this.discoverTools(id).catch(() => undefined)
    return result.entity
  }

  offline(id: string, actor: string, reason: string): ResourceEntity {
    const result = this.ctx.resourceCore.transition('nas', id, 'offline', actor, reason)
    this.ctx.platformBus.emit(PlatformEvents.NasOfflined, { id, name: result.entity.name, slug: result.entity.slug, actor, reason, type: 'nas' })
    this.clients.delete(id)
    return result.entity
  }

  archive(id: string, actor: string): ResourceEntity {
    this.clients.delete(id)
    return this.ctx.resourceCore.transition('nas', id, 'archive', actor).entity
  }

  /** Nettoyage des liaisons après suppression : dossier de santé, cache de découverte d'outils et handle du client de passerelle. */
  purge(id: string): void {
    this.clients.delete(id)
    for (const record of this.health().find((item) => item.nasId === id)) this.health().remove(record.id)
    for (const record of this.toolCache().find((item) => item.nasId === id)) this.toolCache().remove(record.id)
  }

  // -- Santé et découverte d'outils -------------------------------------------------------

  /** Sondage initialize : latence > 800 ms = degraded ; 3 échecs consécutifs = down avec alerte. */
  async probe(id: string): Promise<NasHealthRecord> {
    const nas = this.requireNas(id)
    const existing = this.health().findOne((item) => item.nasId === id)
    const started = Date.now()
    let status: NasHealthRecord['status'] = 'healthy'
    let serverName: string | undefined
    try {
      const info = await this.clientFor(nas).probe()
      serverName = info.serverInfo?.name
      if (Date.now() - started > 800) status = 'degraded'
    } catch {
      status = 'down'
    }
    const fails = status === 'down' ? (existing?.consecutiveFails ?? 0) + 1 : 0
    const record: NasHealthRecord = {
      id: existing?.id ?? `hlt_${id}`,
      nasId: id,
      status,
      latencyMs: status === 'down' ? -1 : Date.now() - started,
      lastProbeAt: new Date().toISOString(),
      consecutiveFails: fails,
      ...(serverName !== undefined ? { serverName } : {}),
    }
    this.health().update(record.id, record)
    if (fails === 3) {
      this.ctx.audit.fire({
        severity: 'warning',
        title: t('NAS「{name}」网关连续探活失败', { name: nas.name }),
        message: t('{url} 连续 3 次 initialize 探活失败，资产已标记 down，请检查网关服务与网络。', { url: String(nas.attrs['gatewayUrl'] ?? '') }),
        resourceType: 'nas',
        resourceId: id,
      })
    }
    return record
  }

  healthOf(id: string): NasHealthRecord {
    return this.health().findOne((item) => item.nasId === id)
      ?? { id: `hlt_${id}`, nasId: id, status: 'unknown', latencyMs: 0, lastProbeAt: '', consecutiveFails: 0 }
  }

  /** Découverte d'outils : le résultat tools/list de la passerelle tombe en cache (affiche la face de capacités fs_* offerte par la passerelle). */
  async discoverTools(id: string): Promise<McpToolInfo[]> {
    const nas = this.requireNas(id)
    const tools = await this.clientFor(nas).listTools()
    const existing = this.toolCache().findOne((item) => item.nasId === id)
    const record: NasToolCacheRecord = { id: existing?.id ?? `tls_${id}`, nasId: id, tools, syncedAt: new Date().toISOString() }
    if (existing) this.toolCache().update(existing.id, record)
    else this.toolCache().insert(record)
    return tools
  }

  toolsOf(id: string): McpToolInfo[] {
    return this.toolCache().findOne((item) => item.nasId === id)?.tools ?? []
  }

  // -- Face d'opérations de fichiers (tout passe par tools/call de la passerelle) -----------------------------------
  // Chaque méthode reçoit en paramètre additionnel de queue opts?: NasFsCallOptions (D15) : seul un chemin interne de confiance passant explicitement
  // serviceSubject exécute sous le principal de service de poste ; la face outils HTTP ne le passe pas, comportement strictement identique à la signature d'origine.

  async listShares(id: string, actor?: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    return await this.fsCall(id, 'fs_list_shares', { additional: ['name', 'path', 'isdir'] }, { actor }, opts)
  }

  async listFiles(id: string, path = '/', actor?: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    const fullPath = this.toFullPath(id, path)
    return await this.fsCall(id, 'fs_list', { folder_path: fullPath, additional: ['size', 'time', 'type', 'owner', 'perm'] }, { actor }, opts)
  }

  async getInfo(id: string, path: string, actor?: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    const fullPath = this.toFullPath(id, path)
    return await this.fsCall(id, 'fs_get_info', { path: [fullPath], additional: ['size', 'time', 'type', 'owner', 'perm', 'real_path'] }, { actor }, opts)
  }

  async search(id: string, pattern: string, path = '/', actor?: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    const fullPath = this.toFullPath(id, path)
    return await this.fsCall(id, 'fs_search', { folder_path: fullPath, pattern, recursive: true, limit: 200 }, { actor }, opts)
  }

  async mkdir(id: string, path: string, actor: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    const { parent, name } = this.parentAndName(id, path)
    const result = await this.fsCall(id, 'fs_create_folder', { folder_path: [parent], name: [name], force_parent: true }, { actor }, opts)
    this.fsAudit(actor, 'nas.fs.mkdir', id, path)
    return result
  }

  async rename(id: string, path: string, newName: string, actor: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    const fullPath = this.toFullPath(id, path)
    const result = await this.fsCall(id, 'fs_rename', { path: [fullPath], name: [newName] }, { actor }, opts)
    this.fsAudit(actor, 'nas.fs.rename', id, `${path} → ${newName}`)
    return result
  }

  async copyMove(id: string, paths: string[], destination: string, mode: 'copy' | 'move', actor: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    const destFolder = this.toFullPath(id, destination)
    const srcFull = paths.map((p) => this.toFullPath(id, p))
    const result = await this.fsCall(id, 'fs_copy_move', { path: srcFull, dest_folder_path: destFolder, overwrite: true, remove_src: mode === 'move' }, { actor, timeoutMs: 120_000 }, opts)
    this.fsAudit(actor, `nas.fs.${mode}`, id, `${paths.join(',')} → ${destination}`)
    return result
  }

  async delete(id: string, paths: string[], actor: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    const fullPaths = paths.map((p) => this.toFullPath(id, p))
    const result = await this.fsCall(id, 'fs_delete', { path: fullPaths, accurate_progress: false }, { actor, timeoutMs: 120_000 }, opts)
    this.fsAudit(actor, 'nas.fs.delete', id, paths.join(','))
    return result
  }

  /**
   * Upload d'un fichier vers le NAS : buffer/fichier local → répertoire staging de la plateforme → fs_upload de la passerelle (la passerelle lit le staging local).
   * Timeout relâché selon les octets (base 30 s + 1 s par Mo, plafond 10 minutes). Un déploiement multi-machines exige un volume staging partagé.
   * onBehalf=false (défaut true) = connexion directe sous l'identité de service de la plateforme : pas d'en-tête X-On-Behalf-User transmis (la passerelle juge
   * les permissions de données avec le compte lié au jeton, qui doit avoir une exception allow explicite sur le répertoire cible), l'actor n'entre que dans l'audit/le metering de la plateforme —
   * pour l'écriture dans la zone de stockage propre de la plateforme (ex. publication de paquets Skill), qui ne doit pas fluctuer avec les permissions de données personnelles de l'opérateur.
   */
  async uploadFile(id: string, input: { buffer?: Buffer; localFile?: string; destPath: string; actor: NasFsActor; onBehalf?: boolean }, opts?: NasFsCallOptions): Promise<{ path: string; sizeBytes: number }> {
    const nas = this.requireNas(id)
    let stagingFile: string
    let sizeBytes: number
    if (input.buffer !== undefined) {
      stagingFile = join(this.stagingDir(nas), input.destPath.split('/').filter(Boolean).pop() ?? `upload-${Date.now()}`)
      await mkdir(this.stagingDir(nas), { recursive: true })
      await writeFile(stagingFile, input.buffer)
      sizeBytes = input.buffer.length
    } else if (input.localFile) {
      stagingFile = this.assertLocalFileInScope(nas, input.localFile)
      sizeBytes = (await readFile(stagingFile)).length
    } else {
      throw new Error(t('uploadFile 需要 buffer 或 localFile 之一'))
    }
    const fullPath = this.toFullPath(id, input.destPath)
    const destDir = `/${fullPath.split('/').filter(Boolean).slice(0, -1).join('/')}`
    const timeoutMs = Math.min(600_000, 30_000 + Math.ceil(sizeBytes / (1024 * 1024)) * 1000)
    await this.fsCall(id, 'fs_upload', { local_file: stagingFile, dest_path: destDir || '/', create_parents: true, overwrite: true }, { actor: input.actor, bytes: sizeBytes, timeoutMs, onBehalf: input.onBehalf }, opts)
    this.fsAudit(input.actor, 'nas.fs.upload', id, `${input.destPath}（${sizeBytes}B，staging=${stagingFile}）`)
    return { path: input.destPath, sizeBytes }
  }

  /**
   * Frontière de lecture de localFile (revue de sécurité P0-04, 2026-10-31) : l'upload localFile fait lire au processus de la plateforme des fichiers locaux
   * du serveur — sans resserrement, cela constitue une face de lecture non autorisée « avec la permission d'écriture NAS, on exporte n'importe quel fichier local ». Ne sont permis que
   * ① le répertoire staging de ce NAS (fichiers produits par la plateforme), ② la zone d'artefacts contrôlée workforce (fichiers déposés par l'employé numérique géré
   * via l'interface d'upload contrôlée). Comparaison de préfixe après résolution realpath ; un lien symbolique pointant hors frontière est également refusé.
   */
  private async assertLocalFileInScope(nas: ResourceEntity, localFile: string): Promise<string> {
    const { resolve, sep } = await import('node:path')
    const candidate = resolve(String(localFile))
    const realpathOf = async (path: string): Promise<string> => {
      try {
        return await import('node:fs/promises').then((m) => m.realpath(path))
      } catch {
        return path
      }
    }
    const roots = [await realpathOf(this.stagingDir(nas))]
    const workforceRoot = await realpathOf(WORKFORCE_ARTIFACTS_ROOT)
    const inside = async (root: string): Promise<boolean> => {
      const real = await realpathOf(candidate)
      return real === root || real.startsWith(`${root}${sep}`)
    }
    if (await inside(roots[0]!)) return candidate
    if (await inside(workforceRoot)) return candidate
    throw new Error(t('上传被拒绝（LOCAL_FILE_SCOPE_DENIED）：localFile 仅允许本 NAS staging 目录或 workforce 受控 artifact 区，不接受平台任意本地路径（安全审查 P0-04）'))
  }

  /**
   * Téléchargement du NAS vers le staging de la plateforme (fs_download de la passerelle écrit côté passerelle dans dest_dir). Renvoie chemin local absolu + octets.
   * Revue de sécurité P0-04 : le saved_to reçu de la passerelle n'est plus cru comme chemin de lecture — cru seulement si son realpath tombe dans le répertoire
   * staging/downloads de ce NAS, sinon ignoré et résolu selon « le nom de dépôt attendu » ; contre une passerelle malveillante qui ferait sortir à la plateforme
   * n'importe quel fichier local via son reçu. Lecture possible seulement après résolution des liens symboliques (realpath) restant dans la frontière.
   */
  async downloadFile(id: string, path: string, actor: NasFsActor, opts?: NasFsCallOptions): Promise<{ localFile: string; bytes: number; savedTo?: string }> {
    const nas = this.requireNas(id)
    const dir = join(this.stagingDir(nas), 'downloads')
    await mkdir(dir, { recursive: true })
    const fullPath = this.toFullPath(id, path)
    const result = await this.fsCall(id, 'fs_download', { path: [fullPath], mode: 'download', local_dir: dir }, { actor, timeoutMs: 600_000 }, opts)
    const parsed = extractFirstJson(result)
    const baseName = fullPath.split('/').filter(Boolean).pop() ?? 'file'
    const declared = typeof parsed?.saved_to === 'string' ? parsed.saved_to : undefined
    const withinStaging = async (candidate: string): Promise<boolean> => {
      try {
        const fsp = await import('node:fs/promises')
        const real = await fsp.realpath(candidate)
        const realDir = await fsp.realpath(dir)
        return (real === realDir || real.startsWith(`${realDir}${sep}`)) && real !== realDir
      } catch {
        return false
      }
    }
    let candidate = join(dir, baseName)
    let savedToOut: string | undefined
    if (declared !== undefined && await withinStaging(declared)) {
      candidate = declared
      savedToOut = declared
    }
    let bytes = Number(parsed?.bytes ?? 0)
    try {
      const stat = await import('node:fs/promises').then((m) => m.stat(candidate))
      if (stat.isFile() && stat.size > 0) bytes = stat.size
      this.fsAudit(actor, 'nas.fs.download', id, `${path} → ${candidate}（${bytes}B）`)
      return { localFile: candidate, bytes, ...(savedToOut ? { savedTo: savedToOut } : {}) }
    } catch {
      this.fsAudit(actor, 'nas.fs.download', id, `${path} → ${candidate}（文件未落盘）`)
      return { localFile: candidate, bytes }
    }
  }

  async taskStatus(id: string, taskId: string, actor?: NasFsActor, opts?: NasFsCallOptions): Promise<unknown> {
    return await this.fsCall(id, 'fs_task_status', { taskid: taskId }, { actor }, opts)
  }

  /**
   * Upload en lot (structure de répertoires conservée) : files = [{ relativePath, contentBase64 | localPath }]
   * appels séquentiels à fs_upload (create_parents côté NAS suffit à créer la chaîne), renvoie chemin final/octet de chaque élément.
   */
  async uploadMany(id: string, items: Array<{ relativePath: string; contentBase64?: string; localPath?: string }>, destDir: string, actor: NasFsActor, opts?: NasFsCallOptions): Promise<{ uploaded: Array<{ path: string; sizeBytes: number }>; failed: Array<{ relativePath: string; error: string }> }> {
    const uploaded: Array<{ path: string; sizeBytes: number }> = []
    const failed: Array<{ relativePath: string; error: string }> = []
    for (const item of items) {
      const destPath = `/${destDir}/${item.relativePath}`.replace(/\\/g, '/').replace(/\/+/g, '/')
      try {
        if (item.contentBase64 !== undefined) {
          const buf = Buffer.from(item.contentBase64, 'base64')
          const result = await this.uploadFile(id, { buffer: buf, destPath, actor }, opts)
          uploaded.push(result)
        } else if (item.localPath) {
          const result = await this.uploadFile(id, { localFile: item.localPath, destPath, actor }, opts)
          uploaded.push(result)
        } else {
          failed.push({ relativePath: item.relativePath, error: t('缺少 contentBase64/localPath') })
        }
      } catch (error) {
        failed.push({ relativePath: item.relativePath, error: error instanceof Error ? error.message : String(error) })
      }
    }
    return { uploaded, failed }
  }

  /** Résout le chemin local absolu du fichier déposé par fs_download de la passerelle (sans rappeler la passerelle), pour streamReadFile de la couche HTTP. */
  async resolveDownloadedFile(id: string, path: string): Promise<{ localFile: string; bytes: number }> {
    const nas = this.requireNas(id)
    const dir = join(this.stagingDir(nas), 'downloads')
    const fullPath = this.toFullPath(id, path)
    const baseName = fullPath.split('/').filter(Boolean).pop() ?? 'file'
    const candidate = join(dir, baseName)
    let bytes = 0
    try {
      const stat = await import('node:fs/promises').then((m) => m.stat(candidate))
      bytes = stat.size
    } catch {
      throw new Error(t('网关落盘文件不存在：{file}（请先调用 downloadFile 让网关写入）', { file: candidate }))
    }
    return { localFile: candidate, bytes }
  }

  // -- Configuration du stockage des paquets Skill -----------------------------------------------------

  getSkillStorage(): SkillStorageConfigRecord {
    return this.skillStorage().get('singleton')
      ?? { id: 'singleton', mode: 'local', updatedAt: '', updatedBy: '' }
  }

  setSkillStorage(patch: { mode?: 'local' | 'nas'; nasId?: string; basePath?: string }, actor: string): SkillStorageConfigRecord {
    // REL-06 : fermeture de l'énumération mode — n'accepte que local/nas minuscules (cohérent avec le jugement runtime mode!=='nas') ;
    // auparavant "NAS"/une chaîne quelconque pouvait entrer en base, et le runtime retombait silencieusement sur le stockage local
    if (patch.mode !== undefined && patch.mode !== 'local' && patch.mode !== 'nas') {
      throw new Error(t('非法的存储模式：{value}（只允许 local 或 nas）', { value: String(patch.mode) }))
    }
    const current = this.getSkillStorage()
    const next: SkillStorageConfigRecord = {
      ...current,
      ...(patch.mode !== undefined ? { mode: patch.mode } : {}),
      ...(patch.nasId !== undefined ? { nasId: patch.nasId } : {}),
      ...(patch.basePath !== undefined ? { basePath: patch.basePath } : {}),
      updatedAt: new Date().toISOString(),
      updatedBy: actor,
    }
    if (next.mode === 'nas') {
      if (!next.nasId) throw new Error(t('NAS 存储模式必须指定 nasId（先在 NAS 存储页纳管资产）'))
      const nas = this.get(next.nasId)
      if (!nas) throw new Error(t('NAS 资产不存在：{id}', { id: next.nasId }))
      if (!next.basePath || !next.basePath.startsWith('/')) throw new Error(t('basePath 必须是以 / 开头的绝对路径'))
    }
    if (this.skillStorage().get('singleton')) return this.skillStorage().update('singleton', next)
    return this.skillStorage().insert(next)
  }

  // -- Interne -----------------------------------------------------------------

  private requireNas(id: string): ResourceEntity {
    const nas = this.ctx.resourceCore.get('nas', id)
    if (!nas) throw new Error(t('NAS 资产不存在：{id}', { id }))
    return nas
  }

  private requireOnline(id: string): ResourceEntity {
    const nas = this.requireNas(id)
    if (nas.status !== 'online') throw new Error(t('NAS「{name}」当前状态 {status}，仅已上线资产可执行文件操作', { name: nas.name, status: nas.status }))
    return nas
  }

  private clientFor(nas: ResourceEntity): NasMcpClient {
    const endpoint = String(nas.attrs['gatewayUrl'] ?? '')
    const token = String(nas.attrs['accessToken'] ?? '')
    const nasIp = String(nas.attrs['nasIp'] ?? '')
    if (!endpoint || !token || !nasIp) throw new Error(t('NAS「{name}」接入属性未配全（gatewayUrl/accessToken/nasIp）', { name: nas.name }))
    const signature = `${endpoint}|${token}|${nasIp}`
    const cached = this.clients.get(nas.id)
    if (cached && cached.signature === signature) return cached.client
    const client = new NasMcpClient(endpoint, {
      Authorization: `Bearer ${token}`,
      'X-NAS-IP': nasIp,
    })
    this.clients.set(nas.id, { client, signature })
    return client
  }

  private async fsCall(id: string, tool: string, args: Record<string, unknown>, meter?: { actor?: NasFsActor; bytes?: number; timeoutMs?: number; onBehalf?: boolean }, opts?: NasFsCallOptions): Promise<unknown> {
    const nas = this.requireOnline(id)
    // D15 : serviceSubject n'est disponible que pour un chemin interne de confiance (passé explicitement par du code serveur, ex. adaptateur de poste workforce) —
    // exécution sous le principal de service de poste lié au jeton de passerelle : sans X-On-Behalf-User, sans emprunt de permissions de données d'un humain.
    const serviceSubject = typeof opts?.serviceSubject === 'string' && opts.serviceSubject.trim() !== '' ? opts.serviceSubject.trim() : undefined
    const onBehalf = serviceSubject ? {} : (meter?.onBehalf === false ? {} : this.onBehalfHeaders(meter?.actor))
    const raw = await this.clientFor(nas).call(tool, args, {
      ...(meter?.timeoutMs ? { timeoutMs: meter.timeoutMs } : {}),
      ...(Object.keys(onBehalf).length > 0 ? { headers: onBehalf } : {}),
    })
    this.meterFsUsage(nas, meter, serviceSubject)
    return typeof raw === 'string' ? parseMaybeJson(raw) : raw
  }

  /**
   * Résolution X-On-Behalf-User (dev-plan-nas-authz §2.4 / leçon P0-2) : l'identité de l'utilisateur réel n'est transmise à la passerelle
   * que par en-tête de requête, jamais dans les paramètres d'outils de la passerelle. Priorité au userid DingTalk (recherche inverse sur la source de fait identityLinks), sinon le userId plateforme.
   * Les appels machine/de l'outil lui-même (sans utilisateur réel, ou actor non identifiant de compte, ex. nom chinois d'un système interne) ne portent pas l'en-tête —
   * la passerelle fait foi de l'identité liée au jeton (anti-falsification), et un en-tête HTTP n'accepte que des ByteString.
   * Resserrement D15 : actor.kind === 'machine' ne porte jamais l'en-tête — un ID de principal machine n'est jamais transmis comme un humain ;
   * on-behalf seulement si la chaîne d'appel a vraiment un humain vérifié (kind==='human', ou terminal humain de la chaîne OBO reconnu par la logique de vérification existante).
   * kind par défaut (appelants internes existants, ex. service d'identité REST console/skillhub) conserve le jugement d'origine.
   */
  private onBehalfHeaders(actor?: NasFsActor): Record<string, string> {
    if (!actor?.id) return {}
    if (actor.kind === 'machine') return {}
    const rawId = actor.id.startsWith('user:') ? actor.id.slice('user:'.length) : actor.id
    if (rawId.startsWith('tool:') || rawId === 'platform' || rawId.includes(':')) return {}
    try {
      const user = this.ctx.iam?.users().get(rawId)
      if (user) {
        const link = this.ctx.iam.identityLinks().findOne((item) => item.userId === user.id && item.provider === 'dingtalk')
        return { 'X-On-Behalf-User': link ? link.providerUserId : user.id }
      }
    } catch { /* IAM indisponible : pas d'en-tête d'identité (fail-closed garanti côté passerelle) */ }
    // Identifiant nu non en base : seuls les caractères ASCII imprimables peuvent servir de valeur d'en-tête (les noms chinois et autres non-identifiants de compte ne sont jamais transmis)
    if (!/^[\x21-\x7e]+$/.test(rawId)) return {}
    return { 'X-On-Behalf-User': rawId }
  }

  /** Pipeline de metering (complément d'observation) : toutes les opérations de fichiers entrent dans les événements usage (nas:* tarif nul par défaut, échec = alerte seule, pas d'interruption). */
  private meterFsUsage(nas: ResourceEntity, meter?: { actor?: NasFsActor; bytes?: number }, serviceSubject?: string): void {
    try {
      this.ctx.usage.record({
        org: nas.orgId,
        subject: serviceSubject
          ? `svc:${serviceSubject}`
          : meter?.actor ? (meter.actor.id.includes(':') ? meter.actor.id : `user:${meter.actor.id}`) : 'user:platform',
        principal: `org:${nas.orgId}`,
        resource: `nas:${nas.id}`,
        meters: [
          { key: 'calls', value: 1, unit: '次' },
          ...(meter?.bytes && meter.bytes > 0 ? [{ key: 'bytes', value: meter.bytes, unit: '字节' }] : []),
        ],
        idempotency_key: `nas:fs:${newId('nfs')}`,
      })
    } catch (error) {
      this.ctx.logger('nas').warn('usage 计量登记失败', error)
    }
  }

  /** Chemin de plateforme → « chemin absolu » du vrai contrat de passerelle (chemin complet DSM, ex. /video/folder), resserré dans le chemin racine autorisé.
   *  La vraie passerelle synology-filestation transmet sous la forme `/volume1/<share>/<sub>` ; la plateforme prend le « chemin de plateforme »
   *  directement comme chemin DSM (rootPath par défaut "/" équivaut à la racine de la liste de partages de la passerelle). */
  private toFullPath(id: string, path: string): string {
    const nas = this.requireNas(id)
    const normalized = normalize(`/${path}`).replace(/\\/g, '/').replace(/\/+$/, '') || '/'
    const root = normalize(String(nas.attrs['rootPath'] ?? '/')).replace(/\\/g, '/').replace(/\/+$/, '') || '/'
    const compareRoot = root === '/' ? '/' : root
    if (compareRoot !== '/' && !normalized.startsWith(compareRoot === '/' ? '/' : compareRoot.endsWith('/') ? compareRoot : `${compareRoot}/`) && normalized !== compareRoot) {
      throw new Error(t('路径 {path} 超出授权根路径 {root}', { path: normalized, root }))
    }
    const segments = normalized.split('/').filter(Boolean)
    if (segments.some((s) => s === '..')) throw new Error(t('路径不允许包含 ..'))
    if (segments.length === 0) return root
    return root === '/' ? `/${segments.join('/')}` : normalized
  }

  /** Résout « le chemin absolu du répertoire parent + nom de fichier » requis pour créer un répertoire, en garantissant l'intérieur du rootPath. */
  private parentAndName(id: string, path: string): { parent: string; name: string } {
    const full = this.toFullPath(id, path)
    const segments = full.split('/').filter(Boolean)
    if (segments.length < 1) throw new Error(t('新建目录必须形如 /<share>/name'))
    const name = segments.pop()!
    const parent = `/${segments.join('/')}`
    return { parent, name }
  }

  private stagingDir(nas: ResourceEntity): string {
    const configured = String(nas.attrs['stagingDir'] ?? '').trim()
    if (configured) return configured
    return join(this.ctx.opsStorage.dataDirPath, 'nas-staging')
  }

  private fsAudit(actor: { id: string; name: string }, action: string, nasId: string, detail: string): void {
    this.ctx.audit.record({
      type: 'change',
      actorType: 'human',
      actorId: actor.id,
      actorName: actor.name,
      action,
      resourceType: 'nas',
      resourceId: nasId,
      resourceName: this.get(nasId)?.name ?? nasId,
      result: 'ok',
      detail,
    })
  }
}

// Alias local des types de collections opsStorage (déclaration légère évitant le conflit avec le nom de service)
interface CollectionLike<T extends RecordBase> {
  get(id: string): T | undefined
  findOne(predicate: (item: T) => boolean): T | undefined
  insert(record: T): T
  update(id: string, patch: Partial<T>): T
}

function parseMaybeJson(text: string): unknown {
  const trimmed = text.trim()
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return text
  try {
    return JSON.parse(trimmed)
  } catch {
    return text
  }
}

/** Compatibilité avec les retours de passerelle : bloc chaîne unique / blocs en tableau / JSON imbriqué ; extrait le premier texte JSON du tableau/objet. */
function extractFirstJson(result: unknown): Record<string, unknown> | undefined {
  if (!result) return undefined
  if (typeof result === 'object' && !Array.isArray(result)) return result as Record<string, unknown>
  const text = Array.isArray(result) ? (result as Array<Record<string, unknown>>).map((b) => typeof b?.text === 'string' ? b.text : '').join('') : typeof result === 'string' ? result : ''
  const trimmed = text.trim()
  if (!trimmed.startsWith('{')) return undefined
  try { return JSON.parse(trimmed) } catch { return undefined }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    nasRegistry: NasRegistryService
  }
}

export const name = 'nas'
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'audit', 'usage', 'iam']

export function apply(ctx: Context) {
  ctx.plugin(NasRegistryService)
  ctx.plugin(NasAuthzService)
  ctx.plugin(NasShareLinkService)
  ctx.plugin(nasTools)
}
