/**
 * @dsh-ops/plugin-skillhub — marché des Skills (plan §4).
 *
 * Chaîne de soumission (pilotée par événements) : submitted → scanned (analyse statique) → approved (approbation à deux niveaux)
 *                        → published (publication versionnée).
 * - Validations préalables à la soumission : format/complétude des métadonnées, analyse statique de code malveillant, détection d'informations sensibles.
 * - Approbation à deux niveaux : responsable de domaine (pertinence métier) → admin plateforme (conformité sécurité) ;
 *   un Skill à haut risque (sorties réseau/écriture de fichiers) exige la signature additionnelle de l'équipe sécurité ; la même personne peut enchaîner les deux niveaux (double approbation par la même personne).
 * - Versions immuables : la publication d'une nouvelle version n'écrase pas l'ancienne, marque de dépréciation et retrait forcé pris en charge.
 * - Téléchargement/installation = enregistrement de la relation de dépendance (la liste des Skills liés est automatiquement remplie en retour à la connexion d'un Agent).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, createZip, newId, slugify, alignAssetCategory, withLegacyCategories, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import * as skillhubTools from './tools.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

export type SkillStatus = 'draft' | 'scanning' | 'pending_approval' | 'rejected' | 'published' | 'deprecated' | 'offline'

export interface ScanFinding {
  level: 'block' | 'warn' | 'info'
  rule: string
  message: string
}

export interface VersionApproval {
  level: 'domain' | 'security'
  approverId: string
  approverName: string
  opinion: string
  at: string
}

/** Artefact publié : emplacement et taille du paquet Skill (skill.zip) (écrit par le crochet de publication quand storage=nas). */
export interface SkillPackageInfo {
  storage: 'nas' | 'local'
  nasId?: string
  path?: string
  sizeBytes?: number
  uploadedAt?: string
}

export interface SkillVersion {
  version: string
  changelog: string
  content: string
  status: 'scanning' | 'pending_domain' | 'pending_security' | 'approved' | 'rejected' | 'published' | 'deprecated'
  submittedAt: string
  findings: ScanFinding[]
  approvals: VersionApproval[]
  publishedAt?: string
  rejectedReason?: string
  /** Contenu du paquet skill.zip optionnellement porté à la soumission (base64 ; uploadé tel quel sur NAS à la publication). */
  packageBase64?: string
  /** Emplacement du paquet écrit à la publication (chemin absolu NAS si storage=nas ; sinon inline plateforme). */
  package?: SkillPackageInfo
}

export interface SkillRecord extends RecordBase {
  name: string
  slug: string
  category: string
  tags: string[]
  summary: string
  description: string
  authorId: string
  authorName: string
  orgId: string
  visibility: 'all' | 'orgs' | 'groups'
  targetOrgs: string[]
  applicableModels: string[]
  deps: string[]
  riskLevel: 'low' | 'medium' | 'high'
  status: SkillStatus
  currentVersion: string
  versions: SkillVersion[]
  /** Motif de dépréciation/retrait forcé (référentiel d'analyse de retrait : persisté avec l'enregistrement, visible en détail et tableau de bord). */
  deprecatedReason?: string
  deprecatedAt?: string
  stats: { downloads: number; installs: number; rating: number; ratingCount: number }
  ratings: Array<{ userId: string; stars: number; at: string }>
  cover: string
}

export interface SkillDownloadRecord extends RecordBase {
  skillId: string
  version: string
  userId: string
  userName: string
}

// ---------------------------------------------------------------------------
// Analyseur statique
// ---------------------------------------------------------------------------

const BLOCK_RULES: Array<{ rule: string; pattern: RegExp; message: string }> = [
  { rule: 'destructive', pattern: /rm\s+-rf|del\s+\/[sq]/i, message: '检测到破坏性删除命令' },
  { rule: 'shell-injection', pattern: /eval\s*\(|exec\s*\(|system\s*\(/i, message: '检测到动态代码执行调用' },
  { rule: 'pipe-download', pattern: /(curl|wget)[^\n]*\|\s*(sh|bash|zsh)/i, message: '检测到下载并直接执行脚本' },
  { rule: 'secret', pattern: /(sk-[a-zA-Z0-9]{16,}|AKID[A-Za-z0-9]{12,}|api[_-]?key\s*[:=]\s*['"][^'"]{8,})/i, message: '检测到疑似密钥/凭证泄露' },
]

const WARN_RULES: Array<{ rule: string; pattern: RegExp; message: string }> = [
  { rule: 'network', pattern: /https?:\/\/(?!127\.0\.0\.1|localhost)/i, message: '包含外部网络访问，需评估数据出域风险' },
  { rule: 'fs-write', pattern: /writeFile|open\s*\(.['"]w|>\s*\/[a-z]/i, message: '包含文件写入操作' },
  { rule: 'subprocess', pattern: /child_process|subprocess|spawn/i, message: '包含子进程调用' },
]

export function scanContent(content: string): ScanFinding[] {
  const findings: ScanFinding[] = []
  for (const rule of BLOCK_RULES) {
    if (rule.pattern.test(content)) findings.push({ level: 'block', rule: rule.rule, message: t(rule.message) })
  }
  for (const rule of WARN_RULES) {
    if (rule.pattern.test(content)) findings.push({ level: 'warn', rule: rule.rule, message: t(rule.message) })
  }
  if (content.length < 40) findings.push({ level: 'warn', rule: 'too-short', message: t('SKILL.md 内容过短，请补充使用说明') })
  return findings
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class SkillHubService extends Service {
  static readonly provide = 'skillHub'

  constructor(ctx: Context) {
    super(ctx, 'skillHub')
  }

  skills(): Collection<SkillRecord> {
    return this.ctx.opsStorage.collection<SkillRecord>('skill:skills')
  }

  downloads(): Collection<SkillDownloadRecord> {
    return this.ctx.opsStorage.collection<SkillDownloadRecord>('skill:downloads')
  }

  categories(): string[] {
    // Les catégories standard (ASSET_CATEGORIES de platform-core) sont renvoyées intégralement en fixe — la barre de filtres du marché ne dérive plus avec les données ;
    // les catégories legacy encore présentes dans les données suivent les entrées standard, pour que les enregistrements existants restent filtrables avant migration.
    return withLegacyCategories(this.skills().all().map((skill) => skill.category))
  }

  // -- Soumission et analyse ---------------------------------------------------------

  submit(input: {
    name: string
    category?: string
    tags?: string[]
    summary?: string
    description?: string
    content: string
    version?: string
    changelog?: string
    authorId: string
    authorName: string
    orgId: string
    visibility?: SkillRecord['visibility']
    targetOrgs?: string[]
    applicableModels?: string[]
    deps?: string[]
    cover?: string
    /** Optionnel : contenu du paquet skill.zip (base64). À la publication, uploadé tel quel via le backend de stockage (NAS configurable). */
    packageBase64?: string
  }): SkillRecord {
    if (!input.name?.trim()) throw new Error(t('Skill 名称不能为空'))
    if (!input.content?.trim()) throw new Error(t('SKILL.md 内容不能为空'))
    if (input.packageBase64 !== undefined) validatePackageBase64(input.packageBase64)
    const slug = slugify(input.name)
    const existing = this.skills().findOne((skill) => skill.slug === slug)
    const version: SkillVersion = {
      version: input.version ?? (existing ? bumpMinor(existing.currentVersion) : '1.0.0'),
      changelog: input.changelog ?? t('首次提交'),
      content: input.content,
      status: 'scanning',
      submittedAt: now(),
      findings: [],
      approvals: [],
      ...(input.packageBase64 !== undefined ? { packageBase64: input.packageBase64 } : {}),
    }
    if (existing) {
      if (existing.versions.some((item) => item.version === version.version)) {
        throw new Error(t('版本 {version} 已存在（版本不可变原则），请递增版本号', { version: version.version }))
      }
      const updated = this.skills().update(existing.id, {
        versions: [...existing.versions, version],
        currentVersion: version.version,
        status: 'scanning',
        ...(input.summary !== undefined ? { summary: input.summary } : {}),
        ...(input.description !== undefined ? { description: input.description } : {}),
      })
      this.runScan(updated.id, version.version)
      return this.skills().get(updated.id)!
    }
    // Catégorie alignée sur le référentiel standard de la plateforme (ASSET_CATEGORIES) ; la valeur non standard est conservée dans tags sans perte d'information
    const aligned = alignAssetCategory(input.category, input.tags ?? [])
    const created = this.skills().insert({
      id: newId('skl'),
      name: input.name,
      slug,
      category: aligned.category,
      tags: aligned.tags,
      summary: input.summary ?? input.content.split('\n')[0]?.slice(0, 80) ?? '',
      description: input.description ?? '',
      authorId: input.authorId,
      authorName: input.authorName,
      orgId: input.orgId,
      visibility: input.visibility ?? 'all',
      targetOrgs: input.targetOrgs ?? [],
      applicableModels: input.applicableModels ?? ['deepseek-chat'],
      deps: input.deps ?? [],
      riskLevel: 'low',
      status: 'scanning',
      currentVersion: version.version,
      versions: [version],
      stats: { downloads: 0, installs: 0, rating: 0, ratingCount: 0 },
      ratings: [],
      cover: input.cover ?? 'spark',
    })
    this.ctx.platformBus.emit(PlatformEvents.SkillSubmitted, { skillId: created.id, name: created.name, version: version.version, author: input.authorName })
    this.runScan(created.id, version.version)
    return this.skills().get(created.id)!
  }

  /** Analyse statique : trouvailles blocking → rejet automatique ; avertissements → haut risque exige la signature sécurité. */
  runScan(skillId: string, version: string): ScanFinding[] {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version)
    if (!target) throw new Error(t('版本不存在：{version}', { version }))
    const findings = scanContent(target.content)
    const hasBlock = findings.some((finding) => finding.level === 'block')
    const hasWarn = findings.some((finding) => finding.level === 'warn')
    const versions = skill.versions.map((item) =>
      item.version === version
        ? { ...item, findings, status: hasBlock ? ('rejected' as const) : ('pending_domain' as const), rejectedReason: hasBlock ? t('静态扫描发现阻断级问题') : undefined }
        : item)
    const nextStatus: SkillStatus = hasBlock ? 'rejected' : 'pending_approval'
    this.skills().update(skillId, {
      versions: versions as SkillVersion[],
      status: nextStatus,
      riskLevel: hasWarn ? 'high' : findings.some((f) => f.level === 'info') ? 'medium' : 'low',
    })
    if (hasBlock) {
      this.ctx.audit.record({
        type: 'change', actorType: 'system', actorId: 'scanner', actorName: t('静态扫描'),
        action: 'skill.scan.rejected', resourceType: 'skill', resourceId: skillId, resourceName: skill.name,
        result: 'denied', detail: findings.filter((f) => f.level === 'block').map((f) => f.message).join('；'),
      })
    }
    return findings
  }

  // -- Approbation et publication ---------------------------------------------------------

  approve(skillId: string, version: string, level: 'domain' | 'security', approver: { id: string; name: string }, opinion: string): SkillRecord {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version)
    if (!target) throw new Error(t('版本不存在：{version}', { version }))
    if (target.status !== 'pending_domain' && target.status !== 'pending_security') {
      throw new Error(t('该版本当前状态 {status} 不可审批', { status: target.status }))
    }
    if (level === 'domain' && target.status !== 'pending_domain') throw new Error(t('领域审批已完成，当前等待安全审批'))
    if (level === 'security' && target.status !== 'pending_security') throw new Error(t('高风险 Skill 才需要安全加签，当前等待领域审批'))
    // Le passage des deux niveaux par la même personne est autorisé (l'ancien principe des quatre yeux REL-03 a été levé à la demande du métier) : le même approbateur peut enchaîner
    // domain puis security (double approbation), sans changement de personne forcé ; l'ordre des deux niveaux et la machine à états restent inchangés.
    if (target.approvals.some((item) => item.level === level && item.approverId === approver.id)) {
      throw new Error(t('同一审批人不可重复审批同一级'))
    }
    const approvals = [...target.approvals, { level, approverId: approver.id, approverName: approver.name, opinion, at: now() }]
    const needSecurity = skill.riskLevel === 'high'
    const nextVersionStatus: SkillVersion['status'] = level === 'domain' && needSecurity ? 'pending_security' : 'approved'
    const versions = skill.versions.map((item) => item.version === version ? { ...item, approvals, status: nextVersionStatus } : item)
    return this.skills().update(skillId, { versions: versions as SkillVersion[] })
  }

  reject(skillId: string, version: string, approver: { id: string; name: string }, opinion: string): SkillRecord {
    const skill = this.requireSkill(skillId)
    const versions = skill.versions.map((item) =>
      item.version === version
        ? { ...item, status: 'rejected' as const, rejectedReason: opinion, approvals: [...item.approvals, { level: item.status === 'pending_domain' ? 'domain' : 'security', approverId: approver.id, approverName: approver.name, opinion, at: now() }] }
        : item)
    return this.skills().update(skillId, { versions: versions as SkillVersion[], status: 'rejected' })
  }

  /**
   * Publication : approbation accordée → (optionnel) upload du skill.zip vers le backend de stockage NAS → version marquée published.
   * Backend de stockage nas = fail-closed : l'échec d'upload du paquet fait échouer la publication (le message d'erreur contient les pistes de vérification passerelle/répertoire de transit).
   * L'upload NAS passe par l'identité de service de la plateforme (onBehalf=false) : l'écriture dans la zone de stockage est une capacité propre de la plateforme, indépendante
   * des permissions de données NAS personnelles de l'opérateur (l'opérateur reste dans l'audit/événements de la plateforme ; côté passerelle, le jugement se fait sur le compte
   * lié au jeton, qui doit avoir une exception allow explicite sur le répertoire de stockage des skills — configurable dans la page des permissions de données).
   */
  async publish(skillId: string, version: string, actor: { id: string; name: string }): Promise<SkillRecord> {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version)
    if (!target) throw new Error(t('版本不存在：{version}', { version }))
    if (target.status !== 'approved') throw new Error(t('版本状态 {status} 不可上架（需完成审批）', { status: target.status }))
    let packageInfo: SkillPackageInfo | undefined
    const storage = this.ctx.nasRegistry.getSkillStorage()
    if (storage.mode === 'nas') {
      const nasId = storage.nasId!
      const nas = this.ctx.nasRegistry.get(nasId)
      if (!nas) throw new Error(t('Skill 包存储后端指向的 NAS 资产不存在：{id}（请在 Skill 存储配置中修正）', { id: nasId }))
      if (nas.status !== 'online') throw new Error(t('Skill 包存储后端 NAS「{name}」当前状态 {status}，上架中止（fail-closed）', { name: nas.name, status: nas.status }))
      const buffer = this.packageBufferOf(skill, target)
      const basePath = (storage.basePath ?? '/skillhub').replace(/\/+$/, '')
      const destPath = `${basePath}/${skill.slug}/${skill.slug}-${version}.zip`
      try {
        const uploaded = await this.ctx.nasRegistry.uploadFile(nasId, {
          buffer,
          destPath,
          actor,
          onBehalf: false,
        })
        packageInfo = { storage: 'nas', nasId, path: uploaded.path, sizeBytes: uploaded.sizeBytes, uploadedAt: new Date().toISOString() }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        throw new Error(t('skill.zip 上传 NAS 失败，上架中止：{reason}（排查：网关服务与令牌；若为数据权限拒绝，请在数据权限页为网关令牌绑定账号授予存储目录 {path} 的 allow 例外；或先把 Skill 存储切回 local）', { reason: message, path: basePath }))
      }
    }
    const versions = skill.versions.map((item) =>
      item.version === version
        ? { ...item, status: 'published' as const, publishedAt: now(), ...(packageInfo !== undefined ? { package: packageInfo } : {}) }
        : item)
    const updated = this.skills().update(skillId, { versions: versions as SkillVersion[], status: 'published' })
    this.ctx.platformBus.emit(PlatformEvents.SkillPublished, {
      skillId, name: updated.name, version, actor: actor.name, type: 'skill', slug: updated.slug,
      ...(packageInfo !== undefined ? { package: { storage: packageInfo.storage, path: packageInfo.path, sizeBytes: packageInfo.sizeBytes } } : {}),
    })
    return updated
  }

  /** Octets du skill.zip pour publication/téléchargement : priorité au paquet original porté à la soumission ; sinon empaquetage à la volée depuis SKILL.md + manifest. */
  packageBufferOf(skill: SkillRecord, target: SkillVersion): Buffer {
    if (target.packageBase64) return Buffer.from(target.packageBase64, 'base64')
    return createZip([
      { path: 'SKILL.md', content: target.content },
      { path: 'manifest.json', content: JSON.stringify({ name: skill.name, slug: skill.slug, version: target.version, category: skill.category, tags: skill.tags, summary: skill.summary }, null, 2) },
    ])
  }

  /** Prend le skill.zip d'une version publiée (octets locaux et artefact publié NAS de même source). */
  packageOf(skillId: string, version: string): { buffer: Buffer; filename: string; info: SkillPackageInfo } {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version && item.status === 'published')
    if (!target) throw new Error(t('已发布版本不存在：{version}', { version }))
    return {
      buffer: this.packageBufferOf(skill, target),
      filename: `${skill.slug}-${target.version}.zip`,
      info: target.package ?? { storage: 'local' },
    }
  }

  // -- Édition et re-téléversement de ressource -------------------------------------------------------

  /**
   * Édite les informations de marché d'un Skill publié (et autres états) : catégorie/étiquettes/résumé/description/visibilité/modèles applicables/dépendances/couverture.
   * Seul l'auteur lui-même ou un admin (skill.publish, jugé par la couche de routage puis passé en asAdmin) peut éditer ; le slug reste stable
   * (les Agents remplissent en retour les Skills liés par slug, un changement de nom ne casse pas la référence) ; le contenu SKILL.md ne passe pas ici — un changement de contenu
   * est une nouvelle version, qui doit repasser la chaîne soumission → analyse → approbation (principe d'immuabilité des versions).
   */
  update(skillId: string, patch: {
    name?: string
    category?: string
    tags?: string[]
    summary?: string
    description?: string
    visibility?: SkillRecord['visibility']
    targetOrgs?: string[]
    applicableModels?: string[]
    deps?: string[]
    cover?: string
    /** Nom d'affichage de l'auteur/développeur : simple affichage (signature des listes et détails), le point d'ancrage d'appartenance authorId ne change pas. */
    authorName?: string
  }, actor: { id: string; name: string }, opts?: { asAdmin?: boolean }): SkillRecord {
    const skill = this.requireSkill(skillId)
    if (skill.authorId !== actor.id && opts?.asAdmin !== true) {
      throw new Error(t('仅 Skill 作者或平台管理员可编辑该 Skill 信息'))
    }
    if (patch.name !== undefined && !patch.name.trim()) throw new Error(t('Skill 名称不能为空'))
    if (patch.authorName !== undefined && !patch.authorName.trim()) throw new Error(t('作者名称不能为空'))
    if (patch.tags !== undefined && (!Array.isArray(patch.tags) || patch.tags.some((tag) => typeof tag !== 'string'))) {
      throw new Error(t('标签格式不正确'))
    }
    if (patch.visibility !== undefined && !['all', 'orgs', 'groups'].includes(patch.visibility)) {
      throw new Error(t('可见性取值不合法：{value}', { value: String(patch.visibility) }))
    }
    if (patch.visibility === 'orgs' && patch.targetOrgs !== undefined && patch.targetOrgs.length === 0 && skill.targetOrgs.length === 0) {
      throw new Error(t('可见性为「指定组织」时须至少选择一个目标组织'))
    }
    const allowed = ['name', 'category', 'tags', 'summary', 'description', 'visibility', 'targetOrgs', 'applicableModels', 'deps', 'cover', 'authorName'] as const
    const changes = Object.fromEntries(allowed.map((key) => [key, patch[key]]).filter(([, value]) => value !== undefined))
    // Catégorie alignée sur le référentiel standard de la plateforme (ASSET_CATEGORIES) ; la valeur non standard est conservée dans tags sans perte d'information
    if (changes['category'] !== undefined || changes['tags'] !== undefined) {
      const aligned = alignAssetCategory(changes['category'] ?? skill.category, changes['tags'] ?? skill.tags)
      changes['category'] = aligned.category
      changes['tags'] = aligned.tags
    }
    if (Object.keys(changes).length === 0) return skill
    // Le nom peut changer, le slug non : le slug est la clé de référence du remplissage des dépendances d'installation (agent.attrs.skills)
    const updated = this.skills().update(skillId, {
      ...changes,
      ...(patch.name !== undefined ? { name: patch.name.trim() } : {}),
      ...(patch.authorName !== undefined ? { authorName: patch.authorName.trim() } : {}),
    })
    this.ctx.platformBus.emit(PlatformEvents.SkillUpdated, {
      skillId, name: updated.name, actor: actor.name, actorId: actor.id, asAdmin: opts?.asAdmin === true,
      fields: Object.keys(changes), type: 'skill', slug: updated.slug,
    })
    return updated
  }

  /**
   * Re-téléversement manuel du paquet de ressources skill.zip de la version publiée courante : remplacement sur place (numéro de version inchangé),
   * en storage=nas, re-transfert NAS par la même chaîne que la publication (fail-closed) ; en local, simple mise à jour du paquet inline et de l'enregistrement.
   * Seul l'auteur lui-même ou un admin peut opérer ; après remplacement, téléchargement/installation prennent le nouveau paquet (packageBufferOf priorise packageBase64).
   */
  async replacePackage(skillId: string, packageBase64: string, actor: { id: string; name: string }, opts?: { asAdmin?: boolean }): Promise<SkillRecord> {
    const skill = this.requireSkill(skillId)
    if (skill.authorId !== actor.id && opts?.asAdmin !== true) {
      throw new Error(t('仅 Skill 作者或平台管理员可更新该 Skill 资源包'))
    }
    validatePackageBase64(packageBase64)
    const target = skill.versions.find((item) => item.version === skill.currentVersion && item.status === 'published')
    if (!target) throw new Error(t('当前版本 {version} 不存在已发布产物，无法替换资源包', { version: skill.currentVersion }))
    const sizeBytes = Buffer.from(packageBase64, 'base64').length
    let packageInfo: SkillPackageInfo = { ...(target.package ?? { storage: 'local' as const }), sizeBytes, uploadedAt: new Date().toISOString() }
    const storage = this.ctx.nasRegistry.getSkillStorage()
    if (storage.mode === 'nas') {
      const nasId = storage.nasId!
      const nas = this.ctx.nasRegistry.get(nasId)
      if (!nas) throw new Error(t('Skill 包存储后端指向的 NAS 资产不存在：{id}（请在 Skill 存储配置中修正）', { id: nasId }))
      if (nas.status !== 'online') throw new Error(t('Skill 包存储后端 NAS「{name}」当前状态 {status}，更新中止（fail-closed）', { name: nas.name, status: nas.status }))
      const buffer = Buffer.from(packageBase64, 'base64')
      const basePath = (storage.basePath ?? '/skillhub').replace(/\/+$/, '')
      const destPath = `${basePath}/${skill.slug}/${skill.slug}-${target.version}.zip`
      try {
        const uploaded = await this.ctx.nasRegistry.uploadFile(nasId, { buffer, destPath, actor, onBehalf: false })
        packageInfo = { storage: 'nas', nasId, path: uploaded.path, sizeBytes: uploaded.sizeBytes, uploadedAt: new Date().toISOString() }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        throw new Error(t('skill.zip 上传 NAS 失败，资源包未更新：{reason}（排查：网关服务与令牌；若为数据权限拒绝，请在数据权限页为网关令牌绑定账号授予存储目录 {path} 的 allow 例外；或先把 Skill 存储切回 local）', { reason: message, path: basePath }))
      }
    }
    const versions = skill.versions.map((item) =>
      item.version === target.version ? { ...item, packageBase64, package: packageInfo } : item)
    const updated = this.skills().update(skillId, { versions: versions as SkillVersion[] })
    this.ctx.platformBus.emit(PlatformEvents.SkillPackageReplaced, {
      skillId, name: updated.name, version: target.version, actor: actor.name, actorId: actor.id,
      asAdmin: opts?.asAdmin === true, storage: packageInfo.storage, sizeBytes: packageInfo.sizeBytes,
      type: 'skill', slug: updated.slug,
    })
    return updated
  }

  deprecate(skillId: string, actor: string, note: string, force?: boolean): { skill: SkillRecord; referencingAgents: Array<{ id: string; name: string; owner: string }> } {
    const skill = this.requireSkill(skillId)
    if (!note?.trim()) throw new Error(t('弃用必须填写原因（护栏要求）'))
    if (skill.status !== 'published') throw new Error(t('仅已上架 Skill 可弃用'))
    const versions = skill.versions.map((item) => item.status === 'published' ? { ...item, status: 'deprecated' as const } : item)
    const updated = this.skills().update(skillId, {
      versions: versions as SkillVersion[],
      status: force ? 'offline' : 'deprecated',
      deprecatedReason: note,
      deprecatedAt: new Date().toISOString(),
    })
    // Scanne les Agents référençant ce Skill, produit les alertes de références préexistantes
    const referencingAgents = this.referencingAgents(skillId)
    this.ctx.platformBus.emit(PlatformEvents.SkillDeprecated, {
      skillId, name: updated.name, actor, note, force,
      referencingAgents: referencingAgents.map((agent) => agent.id),
      type: 'skill', slug: updated.slug,
    })
    if (referencingAgents.length > 0) {
      this.ctx.audit.fire({
        severity: 'warning',
        title: force ? t('Skill「{name}」已强制下架，存在存量引用', { name: updated.name }) : t('Skill「{name}」已弃用，存在存量引用', { name: updated.name }),
        message: t('{count} 个 Agent 仍在使用该 Skill：{agents}。请通知负责人灰度迁移。', { count: referencingAgents.length, agents: referencingAgents.map((agent) => agent.name).join('、') }),
        resourceType: 'skill',
        resourceId: skillId,
      })
    }
    return { skill: updated, referencingAgents }
  }

  /** Recherche inverse du graphe de dépendances : quels Agents ont installé ce Skill. */
  referencingAgents(skillId: string): Array<{ id: string; name: string; owner: string }> {
    return this.ctx.resourceCore.dependencies()
      .find((record) => record.kind === 'skill' && record.toId === skillId)
      .map((record) => {
        const agent = this.ctx.resourceCore.collection('agent').get(record.fromId)
        return agent ? { id: agent.id, name: agent.name, owner: agent.attrs['ownerName'] ?? agent.ownerId } : null
      })
      .filter((item): item is { id: string; name: string; owner: string } => item !== null)
  }

  /** Nettoyage des liaisons après suppression : arêtes de dépendance d'installation, enregistrements de téléchargement et fiche du skill ; données d'audit conservées. */
  purge(skillId: string): void {
    for (const record of this.ctx.resourceCore.dependencies().find((item) => item.kind === 'skill' && item.toId === skillId)) {
      this.ctx.resourceCore.dependencies().remove(record.id)
    }
    for (const record of this.downloads().find((item) => item.skillId === skillId)) this.downloads().remove(record.id)
    this.skills().remove(skillId)
  }

  // -- Téléchargement / installation --------------------------------------------------------

  download(skillId: string, version: string, user: { id: string; name: string }): { content: string } {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version && item.status === 'published')
    if (!target) throw new Error(t('已发布版本不存在：{version}', { version }))
    const record = this.downloads().insert({ id: newId('dwl'), skillId, version, userId: user.id, userName: user.name })
    this.skills().update(skillId, { stats: { ...skill.stats, downloads: skill.stats.downloads + 1 } })
    this.meterSkillUsage(skill, 'downloads', `skill:dl:${record.id}`, `user:${user.id}`)
    return { content: target.content }
  }

  /** Trace de prise de paquet (2026-11-02) : téléchargement direct du skill.zip (GET /package) et téléchargement du SKILL.md enregistrés au même référentiel
   *  flux de téléchargement + statistiques + metering — auparavant, le téléchargement direct du paquet était sans trace ; les jugements d'utilisation de justificatif/autorisation (asset-reports skillGranted)
   * dépendent du flux downloads, un oubli produit « acquis mais signalé non autorisé ». */
  recordPackageFetch(skillId: string, version: string, user: { id: string; name: string }): void {
    const skill = this.requireSkill(skillId)
    const record = this.downloads().insert({ id: newId('dwl'), skillId, version, userId: user.id, userName: user.name })
    this.skills().update(skillId, { stats: { ...skill.stats, downloads: skill.stats.downloads + 1 } })
    this.meterSkillUsage(skill, 'downloads', `skill:dl:${record.id}`, `user:${user.id}`)
  }

  /** Installation sur un Agent : enregistre la relation de dépendance (remplissage automatique dans le graphe de dépendances de ressources). */
  install(skillId: string, version: string, agentId: string, actor: string): SkillRecord {
    const skill = this.requireSkill(skillId)
    const agent = this.ctx.resourceCore.collection('agent').get(agentId)
    if (!agent) throw new Error(t('Agent 不存在：{id}', { id: agentId }))
    const target = skill.versions.find((item) => item.version === version && item.status === 'published')
    if (!target) throw new Error(t('已发布版本不存在：{version}', { version }))
    this.ctx.resourceCore.addDependency({ fromType: 'agent', fromId: agentId, toType: 'skill', toId: skillId, kind: 'skill' })
    // Remplissage en retour de la liste des Skills liés dans les attributs de l'Agent
    const skillsAttr = Array.isArray(agent.attrs['skills']) ? [...agent.attrs['skills'] as string[]] : []
    if (!skillsAttr.includes(skill.slug)) {
      skillsAttr.push(skill.slug)
      this.ctx.resourceCore.collection('agent').update(agentId, { attrs: { ...agent.attrs, skills: skillsAttr } })
    }
    const updated = this.skills().update(skillId, { stats: { ...skill.stats, installs: skill.stats.installs + 1 } })
    this.meterSkillUsage(skill, 'installs', `skill:inst:${newId('uis')}`, `agent:${agentId}`)
    this.ctx.platformBus.emit(PlatformEvents.SkillInstalled, { skillId, version, agentId, agentName: agent.name, actor })
    return updated
  }

  /** Pipeline de metering (complément d'observation) : téléchargement/installation de skill dans les événements usage (skill:<ID>, le slug à nom chinois contenant du non-ASCII, d'où l'ID ;
   *  skill:* tarif nul par défaut, un échec n'alerte qu'alerte sans interrompre le flux principal. calls est la clé de tarification du tarif (usage.record exige
   *  dans sa validation dure que l'événement contienne la clé), downloads/installs conservés comme dimensions d'observation. */
  private meterSkillUsage(skill: SkillRecord, meterKey: 'downloads' | 'installs', idempotencyKey: string, subject: string): void {
    try {
      this.ctx.usage.record({
        org: skill.orgId,
        subject,
        principal: `org:${skill.orgId}`,
        resource: `skill:${skill.id}`,
        meters: [
          { key: 'calls', value: 1, unit: '次' },
          { key: meterKey, value: 1, unit: '次' },
        ],
        idempotency_key: idempotencyKey,
      })
    } catch (error) {
      this.ctx.logger('skillhub').warn('usage 计量登记失败', error)
    }
  }

  uninstall(skillId: string, agentId: string): void {
    this.ctx.resourceCore.removeDependency({ fromType: 'agent', fromId: agentId, toType: 'skill', toId: skillId })
    const agent = this.ctx.resourceCore.collection('agent').get(agentId)
    if (agent && Array.isArray(agent.attrs['skills'])) {
      const skills = (agent.attrs['skills'] as string[]).filter((slug) => slug !== this.requireSkill(skillId).slug)
      this.ctx.resourceCore.collection('agent').update(agentId, { attrs: { ...agent.attrs, skills } })
    }
  }

  rate(skillId: string, userId: string, stars: number): SkillRecord {
    const skill = this.requireSkill(skillId)
    if (stars < 1 || stars > 5 || !Number.isInteger(stars)) throw new Error(t('评分须为 1-5 的整数'))
    const ratings = [...skill.ratings.filter((item) => item.userId !== userId), { userId, stars, at: now() }]
    const rating = ratings.length === 0 ? 0 : Math.round((ratings.reduce((sum, item) => sum + item.stars, 0) / ratings.length) * 10) / 10
    return this.skills().update(skillId, { ratings, stats: { ...skill.stats, rating, ratingCount: ratings.length } })
  }

  // -- Recherche ---------------------------------------------------------------

  /**
   * Recherche : par défaut, seulement publié/déprécié ; avec includePending, les éléments en vol (en approbation/en analyse) sont aussi présentés
   * (en tête, triés par date de mise à jour, avec badge d'état) — pour que l'approbateur voie ses à-faire directement dans le marché.
   */
  search(options: { q?: string; category?: string; tag?: string; sort?: 'downloads' | 'rating' | 'updated'; viewerOrgId?: string; includePending?: boolean }): SkillRecord[] {
    let list = this.skills().find((skill) => {
      const inFlight = options.includePending === true && ['pending_approval', 'scanning'].includes(skill.status)
      if (!['published', 'deprecated'].includes(skill.status) && !inFlight) return false
      if (options.category && skill.category !== options.category) return false
      if (options.tag && !skill.tags.includes(options.tag)) return false
      if (skill.visibility === 'orgs' && options.viewerOrgId && !skill.targetOrgs.includes(options.viewerOrgId)) return false
      if (options.q) {
        // Couverture des mots-clés : nom / résumé / description / étiquettes / catégorie / auteur (référentiel de la barre de recherche du marché)
        const haystack = `${skill.name} ${skill.summary} ${skill.description} ${skill.tags.join(' ')} ${skill.category} ${skill.authorName}`.toLowerCase()
        if (!haystack.includes(options.q.toLowerCase())) return false
      }
      return true
    })
    const published = list.filter((skill) => ['published', 'deprecated'].includes(skill.status))
    const sort = options.sort ?? 'downloads'
    const sorted = published.sort((a, b) => {
      if (sort === 'rating') return b.stats.rating - a.stats.rating
      if (sort === 'updated') return b.updatedAt.localeCompare(a.updatedAt)
      return b.stats.downloads - a.stats.downloads
    })
    if (options.includePending !== true) return sorted
    const pending = list.filter((skill) => !['published', 'deprecated'].includes(skill.status))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    return [...pending, ...sorted]
  }

  detail(skillId: string): SkillRecord {
    return this.requireSkill(skillId)
  }

  private requireSkill(skillId: string): SkillRecord {
    const skill = this.skills().get(skillId)
    if (!skill) throw new Error(t('Skill 不存在：{id}', { id: skillId }))
    return skill
  }
}

function bumpMinor(version: string): string {
  const parts = version.split('.').map(Number)
  parts[1] = (parts[1] ?? 0) + 1
  parts[2] = 0
  return parts.join('.')
}

/** Validation du paquet soumis : base64 décodable, nombre magique ZIP (PK\u0003\u0004), taille ≤ 32 Mo. */
function validatePackageBase64(value: string): void {
  if (typeof value !== 'string' || value.length === 0) throw new Error(t('packageBase64 不能为空字符串'))
  if (value.length > 44_000_000) throw new Error(t('skill.zip 过大（base64 后上限 32MB）'))
  const buffer = Buffer.from(value, 'base64')
  if (buffer.length < 4 || buffer[0] !== 0x50 || buffer[1] !== 0x4b) {
    throw new Error(t('packageBase64 不是合法的 ZIP 内容（缺少 PK 魔数）'))
  }
}

function now(): string {
  return new Date().toISOString()
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    skillHub: SkillHubService
  }
}

export const name = 'skillhub'
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'audit', 'nasRegistry', 'usage']

export function apply(ctx: Context) {
  ctx.plugin(SkillHubService)
  ctx.plugin(skillhubTools)
}
