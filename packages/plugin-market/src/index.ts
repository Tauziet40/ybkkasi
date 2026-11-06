/**
 * @dsh-ops/plugin-market — marché de plugins tiers + domaine d'identité développeur (conception écosystème v1.2 étapes 3/5/7).
 *
 * Les cinq faces du contrat (L0 déclaratif, sans aucun code exécutable) :
 *   plugin.yaml                 métadonnées + capabilities_request + sandbox + contenu L0 (paquets de prompts)
 *   manifest/permissions.yaml   déclaration de permissions (requested ; à l'installation, l'entreprise approuve point par point → approved)
 *   manifest/api.yaml           face d'offre déclarative (en étape L0, simple enregistrement de description)
 *   manifest/events.yaml        déclaration d'événements (souscription/émission confinées dans l'espace de noms plugin:<id>:)
 *   manifest/billing.yaml       déclaration de metering (champ de compatibilité : seuls meter key/unité participent à l'enregistrement du metering, côté montant toujours instantané à prix zéro)
 *
 * Barrière d'entrée du marché (dure) : sandbox n'accepte que L0 — avant la livraison du bac à sable L1 à code (étape 10),
 * toute soumission de plugin avec code est rejetée d'emblée, pour exclure toute exception de « confiance interne ».
 *
 * Domaine d'identité développeur (M2) : indépendant du domaine iam des employés internes ; vérification de signature des soumissions par paire de clés Ed25519 de l'éditeur.
 * Objet signé = empreinte du contenu des cinq faces (SHA-256 de la concaténation triée par nom de fichier).
 */
import { randomBytes } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, newId, parseYaml, sha256Hex, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
// Fondation M2 : l'infrastructure de vérification Ed25519 est hissée dans platform-core (la vérification du manifeste de publication de plugin-update partage la même) ;
// ici simple ré-export aliasé dans le contexte du marché, les références existantes (scaffold dshctl, etc.) ne sont pas affectées.
import { generateEd25519KeyPair, isValidEd25519PublicKeyBase64, signEd25519, verifyEd25519 } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
export { generateEd25519KeyPair as generateDeveloperKeyPair, signEd25519 as signFingerprint, verifyEd25519 as verifySignature }
import * as marketTools from './tools.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

export interface DeveloperRecord extends RecordBase {
  username: string
  displayName: string
  email: string
  status: 'active' | 'suspended'
  passwordSalt: string
  passwordHash: string
  /** Clé publique Ed25519 de l'éditeur (SPKI DER → base64). */
  publicKey: string
  /** Espace de noms d'id de plugin (NEW-E-01 version légère) : segment d'appartenance com.<namespace>.* ; par défaut, segment de marque du compte enregistré. */
  namespace?: string
  company?: string
  /** Enregistrement du compte d'encaissement (emplacement d'enregistrement en attendant la liste des dépendances du canal financier, v1.2 §6). */
  payoutAccount?: string
  principalId: string
}

/** Résultat d'analyse des cinq faces du contrat. */
export interface PluginManifest {
  id: string
  version: string
  publisher: string
  depends: string[]
  capabilities_request: string[]
  sandbox: string
  permissions: { requested: string[] }
  api: { routes: Array<{ path: string; method: string; description: string }> }
  events: { subscribes: string[]; emits: string[] }
  billing: {
    model: string
    subscription?: { monthly: number }
    usage: Array<{ key: string; unit: string; price: number }>
    commission: string
  }
  content: {
    prompts: Array<{ name: string; description: string; template: string }>
  }
}

export type PluginStatus = 'scanning' | 'rejected' | 'pending_approval' | 'listed' | 'suspended' | 'deprecated'

export interface PluginSubmissionRecord extends RecordBase {
  pluginId: string
  version: string
  developerId: string
  developerName: string
  status: PluginStatus
  /** Texte original des cinq faces (chemin de fichier → contenu). */
  files: Record<string, string>
  parsed: PluginManifest
  fingerprint: string
  signature: string
  /** Empreinte du contenu L0 : changer prompts/configuration = changer le comportement, retour obligatoire par l'approbation (M5). */
  contentHash: string
  reviewNote?: string
  reviewedBy?: string
  installs: number
}

export interface PluginInstallRecord extends RecordBase {
  pluginId: string
  version: string
  orgId: string
  tenantId: string
  /** Sous-ensemble de capacités approuvé par l'entreprise à l'installation (approved ⊆ requested). */
  capabilities: string[]
  permissions: string[]
  status: 'running' | 'suspended' | 'uninstalled'
  installedBy: string
}

// ---------------------------------------------------------------------------
// Validation du contrat
// ---------------------------------------------------------------------------

export const REQUIRED_FILES = ['plugin.yaml', 'manifest/permissions.yaml', 'manifest/api.yaml', 'manifest/events.yaml', 'manifest/billing.yaml']

/** Règles d'analyse statique du contenu L0 (réutilise le mode de gouvernance de skillhub ; changement de contenu déclaratif = changement de comportement). */
const CONTENT_BLOCK_RULES: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /rm\s+-rf\s+\//i, reason: '疑似破坏性命令' },
  { pattern: /sk-[A-Za-z0-9]{16,}/, reason: '疑似明文密钥' },
  { pattern: /eval\s*\(|new\s+Function\s*\(/, reason: '疑似动态代码执行（L0 禁止可执行内容）' },
  { pattern: /require\s*\(|import\s*\(/, reason: '疑似模块加载（L0 禁止可执行内容）' },
]

export function fingerprintOf(files: Record<string, string>): string {
  const canonical = Object.keys(files).sort()
    .map((key) => `${key}\n${files[key] ?? ''}`)
    .join('\n---\n')
  return sha256Hex(canonical)
}

export function contentHashOf(manifest: PluginManifest): string {
  return sha256Hex(JSON.stringify(manifest.content))
}

/** Analyse et validation des cinq faces du contrat (validation structurelle + barrière d'entrée). */
export function parseManifest(files: Record<string, string>): PluginManifest {
  for (const file of REQUIRED_FILES) {
    if (typeof files[file] !== 'string' || files[file]!.trim() === '') {
      throw new Error(t('契约五面缺少文件：{file}', { file }))
    }
  }
  let root: Record<string, unknown>
  let permissions: Record<string, unknown>
  let api: Record<string, unknown>
  let events: Record<string, unknown>
  let billing: Record<string, unknown>
  try {
    root = parseYaml(files['plugin.yaml']!) as Record<string, unknown>
    permissions = parseYaml(files['manifest/permissions.yaml']!) as Record<string, unknown>
    api = parseYaml(files['manifest/api.yaml']!) as Record<string, unknown>
    events = parseYaml(files['manifest/events.yaml']!) as Record<string, unknown>
    billing = parseYaml(files['manifest/billing.yaml']!) as Record<string, unknown>
  } catch (error) {
    throw new Error(t('YAML 解析失败：{reason}', { reason: error instanceof Error ? error.message : String(error) }))
  }
  if (typeof root.id !== 'string' || !/^[a-z0-9]+(\.[a-z0-9-]+){1,3}$/.test(root.id)) {
    throw new Error(t('plugin.yaml id 格式非法（应为反向域名如 com.vendor.name）：{value}', { value: String(root.id) }))
  }
  if (typeof root.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(root.version)) throw new Error(t('plugin.yaml version 必须为语义化版本 x.y.z'))
  if (root.sandbox !== 'L0') {
    throw new Error(t('市场准入门禁：当前仅受理 sandbox: L0（声明式插件），收到 {value}。L1 有码沙箱为第 10 步交付项，交付前不开放有码插件上架。', { value: String(root.sandbox) }))
  }
  const content = (root.content ?? {}) as PluginManifest['content']
  if (!Array.isArray(content.prompts) || content.prompts.length === 0) {
    throw new Error(t('L0 插件必须在 plugin.yaml content.prompts 声明至少一个提示词包（声明式内容的唯一载体）'))
  }
  for (const prompt of content.prompts) {
    if (typeof prompt.name !== 'string' || typeof prompt.template !== 'string' || prompt.template.trim() === '') {
      throw new Error(t('提示词包 {name} 缺少 name/template', { name: String(prompt.name) }))
    }
    for (const rule of CONTENT_BLOCK_RULES) {
      if (rule.pattern.test(prompt.template)) throw new Error(t('L0 内容扫描拦截（{reason}）：提示词包 {name}', { reason: t(rule.reason), name: prompt.name }))
    }
  }
  const manifest: PluginManifest = {
    id: root.id,
    version: root.version,
    publisher: typeof root.publisher === 'string' ? root.publisher : '',
    depends: Array.isArray(root.depends) ? root.depends.map(String) : [],
    capabilities_request: Array.isArray(root.capabilities_request) ? root.capabilities_request.map(String) : [],
    sandbox: String(root.sandbox),
    permissions: { requested: permissions.requested !== undefined ? (Array.isArray(permissions.requested) ? permissions.requested.map(String) : []) : [] },
    api: {
      routes: Array.isArray(api.routes)
        ? api.routes.map((route) => route as { path: string; method: string; description: string })
        : [],
    },
    events: {
      subscribes: Array.isArray(events.subscribes) ? events.subscribes.map(String) : [],
      emits: Array.isArray(events.emits) ? events.emits.map(String) : [],
    },
    billing: {
      model: typeof billing.model === 'string' ? billing.model : 'free',
      ...(billing.subscription !== undefined && billing.subscription !== null ? { subscription: billing.subscription as { monthly: number } } : {}),
      usage: Array.isArray(billing.usage) ? billing.usage as PluginManifest['billing']['usage'] : [],
      commission: typeof billing.commission === 'string' ? billing.commission : 'platform_default',
    },
    content,
  }
  for (const emit of manifest.events.emits) {
    if (!emit.startsWith(`plugin:${manifest.id}:`)) {
      throw new Error(t('events.yaml 发射事件必须收敛在 plugin:{id}: 命名空间：{event}', { id: manifest.id, event: emit }))
    }
  }
  return manifest
}

// Le trio vérification de signature/clé/signature Ed25519 a été hissé dans platform-core (fondation M2, ré-export en tête de fichier),
// la vérification du manifeste de publication de plugin-update et celle des cinq faces du marché partagent la même infrastructure.

/** Capacité → préfixe de ressource consommable (base d'autorisation de la réconciliation à l'exécution M5). */
const CAPABILITY_RESOURCE_MAP: Record<string, string> = {
  'model-gateway.invoke': 'model:*',
  'knowledgebase.read': 'kb:*',
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class MarketService extends Service {
  static readonly provide = 'market'

  constructor(ctx: Context) {
    super(ctx, 'market')
    // La graine d'offre propre doit être faite dans le constructeur du service (dans le apply de l'extension, ctx.market n'est pas encore injecté, ligne rouge cordis).
    // Les plugins commerciaux propres ne sont injectés que dans l'environnement de démonstration DEMO_SEED=1 ; la base de production n'écrit aucun prix de facturation/offre propre.
    if (process.env.DEMO_SEED === '1') {
      seedOfficialPlugins(this)
    }
  }

  developers(): Collection<DeveloperRecord> {
    const collection = this.ctx.opsStorage.collection<DeveloperRecord>('market:developers')
    collection.uniqueOn('developer_username', (dev) => dev.username)
    return collection
  }

  submissions(): Collection<PluginSubmissionRecord> {
    const collection = this.ctx.opsStorage.collection<PluginSubmissionRecord>('market:submissions')
    collection.uniqueOn('submission_plugin_version', (item) => `${item.pluginId}@${item.version}`)
    return collection
  }

  installs(): Collection<PluginInstallRecord> {
    return this.ctx.opsStorage.collection<PluginInstallRecord>('market:installs')
  }

  // -- Domaine d'identité développeur (M2 : indépendant de l'iam des employés internes) --------------------------------

  registerDeveloper(input: { username: string; displayName: string; email: string; password: string; publicKey: string; company?: string; payoutAccount?: string; namespace?: string }): { developer: DeveloperRecord; token: string } {
    if (!/^[a-z][a-z0-9_-]{2,31}$/.test(input.username)) throw new Error(t('开发者账号格式非法（^[a-z][a-z0-9_-]{2,31}$）'))
    if (typeof input.displayName !== 'string' || input.displayName.trim() === '') throw new Error(t('开发者显示名（displayName）必填'))
    if (typeof input.email !== 'string' || input.email.trim() === '') throw new Error(t('开发者邮箱（email）必填'))
    if (typeof input.password !== 'string' || input.password.length < 8) throw new Error(t('密码至少 8 位'))
    if (!isValidEd25519PublicKeyBase64(input.publicKey)) {
      throw new Error(t('发布者公钥格式非法（应为 Ed25519 SPKI DER base64）'))
    }
    // NEW-E-01 version légère : l'enregistrement lie l'espace de noms d'id de plugin (segment d'appartenance com.<namespace>.*).
    // Par défaut, segment de marque du compte enregistré (partie avant '-', ex. acme-dev → acme) ; une valeur explicite doit rester dans le domaine de caractères légaux d'un segment d'id
    //(si le segment de marque contient des caractères illégaux pour un id — ex. souligné — il est inscrit tel quel : les soumissions com.* de ce compte seront bloquées par la barrière d'espace de noms)
    const namespace = input.namespace ?? input.username.split('-')[0]!
    if (input.namespace !== undefined && !/^[a-z0-9][a-z0-9-]{0,30}$/.test(namespace)) {
      throw new Error(t('插件 id 命名空间非法（^[a-z0-9][a-z0-9-]{0,30}$）：{namespace}', { namespace }))
    }
    const credential = this.ctx.authn.createMachineCredential({
      name: `developer:${input.username}`,
      refType: 'external',
      scopes: ['market.developer'],
    })
    const salt = randomBytes(16).toString('hex')
    const record = this.developers().insert({
      id: newId('dev'),
      username: input.username,
      displayName: input.displayName,
      email: input.email,
      status: 'active',
      passwordSalt: salt,
      passwordHash: sha256Hex(`${salt}:${input.password}`),
      publicKey: input.publicKey,
      namespace,
      ...(input.company !== undefined ? { company: input.company } : {}),
      ...(input.payoutAccount !== undefined ? { payoutAccount: input.payoutAccount } : {}),
      principalId: credential.principal.id,
    })
    this.ctx.authn.principals().update(credential.principal.id, { refId: record.id })
    // Le principal développeur reçoit par défaut la liste blanche de capacités de la plateforme (autorisation de metering, base de la réconciliation à l'exécution)
    this.ctx.usage.grantCapabilities(`developer:${record.id}`, ['plugin:*'], 'developer-register')
    return { developer: record, token: this.developerToken(record) }
  }

  loginDeveloper(username: string, password: string): { developer: DeveloperRecord; token: string } {
    const developer = this.developers().findOne((item) => item.username === username)
    if (!developer || developer.passwordHash !== sha256Hex(`${developer.passwordSalt}:${password}`)) {
      throw new Error(t('开发者账号或密码错误'))
    }
    if (developer.status !== 'active') throw new Error(t('开发者账号已停用'))
    return { developer, token: this.developerToken(developer) }
  }

  private developerToken(developer: DeveloperRecord): string {
    const { token } = this.ctx.authn.issueToken(developer.principalId, {
      kind: 'machine',
      ttlHours: 2,
      scopes: ['market.developer'],
      issuedBy: 'market-portal',
    })
    return token
  }

  /** Localise le développeur depuis le principal du jeton (authentification des routes développeur). */
  developerOfPrincipal(principalId: string): DeveloperRecord | undefined {
    return this.developers().findOne((item) => item.principalId === principalId)
  }

  // -- Soumission et approbation ------------------------------------------------------------

  submit(developer: DeveloperRecord, files: Record<string, string>, signature: string): PluginSubmissionRecord {
    const parsed = parseManifest(files)
    if (parsed.publisher !== developer.username) {
      throw new Error(t('plugin.yaml publisher 必须为提交者账号（{account}），收到 {value}', { account: developer.username, value: parsed.publisher }))
    }
    // NEW-E-01 version légère : le segment d'appartenance d'un id de plugin com.<x>.* doit coïncider avec l'espace de noms du soumetteur, contre l'usurpation com.<marque>.*.
    // Compatibilité des préexistants : pas de contrôle pour les développeurs existants sans champ namespace (la barrière d'approbation reste en l'état)
    if (parsed.id.startsWith('com.') && developer.namespace !== undefined) {
      const vendor = parsed.id.slice('com.'.length).split('.')[0] ?? ''
      if (vendor !== developer.namespace) {
        throw new Error(t('插件 id 命名空间越权：com.{vendor}.* 与开发者命名空间 com.{namespace}.* 不一致，不得提交他人品牌段下的插件 id', { vendor, namespace: developer.namespace }))
      }
    }
    const fingerprint = fingerprintOf(files)
    if (!verifyEd25519(developer.publicKey, fingerprint, signature)) {
      throw new Error(t('签名验签失败：五面指纹与发布者公钥签名不匹配'))
    }
    const duplicate = this.submissions().findOne((item) => item.pluginId === parsed.id && item.version === parsed.version)
    if (duplicate) throw new Error(t('版本不可变：{plugin}@{version} 已提交（{status}）', { plugin: parsed.id, version: parsed.version, status: duplicate.status }))
    const record = this.submissions().insert({
      id: newId('sub'),
      pluginId: parsed.id,
      version: parsed.version,
      developerId: developer.id,
      developerName: developer.displayName,
      status: 'pending_approval',
      files,
      parsed,
      fingerprint,
      signature,
      contentHash: contentHashOf(parsed),
      installs: 0,
    })
    this.ctx.platformBus.emit(PlatformEvents.PluginSubmitted, {
      pluginId: parsed.id, version: parsed.version, developer: developer.username, type: 'plugin', id: record.id,
    })
    return record
  }

  approve(id: string, approver: string, opinion: string): PluginSubmissionRecord {
    const record = this.requireSubmission(id)
    if (record.status !== 'pending_approval') throw new Error(t('当前状态 {status} 不允许审批', { status: record.status }))
    const updated = this.submissions().update(id, { status: 'listed', reviewNote: opinion, reviewedBy: approver })
    this.ctx.platformBus.emit(PlatformEvents.PluginListed, {
      pluginId: updated.pluginId, version: updated.version, approver, type: 'plugin', id: updated.id, name: updated.pluginId,
    })
    return updated
  }

  reject(id: string, approver: string, reason: string): PluginSubmissionRecord {
    const record = this.requireSubmission(id)
    if (record.status !== 'pending_approval') throw new Error(t('当前状态 {status} 不允许审批', { status: record.status }))
    return this.submissions().update(id, { status: 'rejected', reviewNote: reason, reviewedBy: approver })
  }

  /** Changement de contenu après publication (empreinte de contenu modifiée à version identique) → retour obligatoire par l'approbation : ancienne version suspendue en attente de migration. */
  suspend(id: string, reason: string): PluginSubmissionRecord {
    const record = this.requireSubmission(id)
    const updated = this.submissions().update(id, { status: 'suspended', reviewNote: reason })
    for (const install of this.installs().find((item) => item.pluginId === record.pluginId && item.status === 'running')) {
      this.installs().update(install.id, { status: 'suspended' })
    }
    return updated
  }

  listed(): PluginSubmissionRecord[] {
    return this.submissions().find((item) => item.status === 'listed')
  }

  // -- Installation (confirmation de permissions + figage des capacités + enregistrement au tarif) ------------------------------

  install(input: {
    pluginId: string
    orgId: string
    tenantId: string
    approvedCapabilities: string[]
    approvedPermissions?: string[]
    installedBy: string
  }): PluginInstallRecord {
    const submission = this.submissions().findOne((item) => item.pluginId === input.pluginId && item.status === 'listed')
    if (!submission) throw new Error(t('插件未上架或已下架：{plugin}', { plugin: input.pluginId }))
    const existing = this.installs().findOne((item) => item.pluginId === input.pluginId && item.orgId === input.orgId && item.status !== 'uninstalled')
    if (existing) throw new Error(t('组织 {org} 已安装 {plugin}（{status}）', { org: input.orgId, plugin: input.pluginId, status: existing.status }))
    for (const cap of input.approvedCapabilities) {
      if (!submission.parsed.capabilities_request.includes(cap)) {
        throw new Error(t('能力 {cap} 不在插件请求清单内（approved ⊆ requested）', { cap }))
      }
    }
    // QA E-02 : même référentiel sur la face permissions — approvedPermissions sans validation ⊆ requested permettait d'accorder des points jamais demandés par le plugin
    const requestedPermissions: string[] = submission.parsed.permissions.requested ?? []
    for (const point of input.approvedPermissions ?? []) {
      if (!requestedPermissions.includes(point)) {
        throw new Error(t('权限点 {point} 不在插件申请清单内（approved ⊆ requested，QA E-02）：请让开发者更新 manifest/permissions.yaml 后重新提交', { point }))
      }
    }
    const record = this.installs().insert({
      id: newId('ins'),
      pluginId: input.pluginId,
      version: submission.version,
      orgId: input.orgId,
      tenantId: input.tenantId,
      capabilities: input.approvedCapabilities,
      permissions: input.approvedPermissions ?? [],
      status: 'running',
      installedBy: input.installedBy,
    })
    // Figage des capacités : base de la réconciliation à l'exécution (M5) — le principal du plugin ne peut consommer que les ressources correspondant aux capacités approuvées
    const grantedResources = [`plugin:${input.pluginId}`, ...input.approvedCapabilities.map((cap) => CAPABILITY_RESOURCE_MAP[cap] ?? cap)]
    this.ctx.usage.grantCapabilities(`plugin:${input.pluginId}`, grantedResources, `market-install:${record.id}`)
    // Enregistrement au metering (convergence M0-3) : l'installation écrit le tarif, meter key pris de la déclaration billing.usage[0]
    //(le metering d'exécution L0 meterPromptUse dépend de cette clé pour la validation dure de record()) ; côté montant, toujours instantané à prix zéro —
    // les prix déclarés par les tiers n'entrent plus en compte (modèle économique : licence annuelle privatif + pack de gouvernance, ni revente avec partage ni encaissement)
    const usageEntry = submission.parsed.billing.usage[0]
    if (usageEntry) {
      this.ctx.usage.upsertPrice({
        pattern: `plugin:${input.pluginId}`,
        meter_key: usageEntry.key,
        list_cents_per_unit: 0,
        cost_cents_per_unit: 0,
        units_per_step: 1,
        tax_rate: 0.06,
        currency: 'CNY',
        rate_version: `plugin:${input.pluginId}:v${submission.version}`,
      })
    }
    this.submissions().update(submission.id, { installs: submission.installs + 1 })
    this.ctx.platformBus.emit(PlatformEvents.PluginInstalledEvent, {
      pluginId: input.pluginId, version: submission.version, orgId: input.orgId, tenantId: input.tenantId,
      capabilities: input.approvedCapabilities, installedBy: input.installedBy,
    })
    return record
  }

  uninstall(pluginId: string, orgId: string, actor: string): PluginInstallRecord {
    const record = this.installs().findOne((item) => item.pluginId === pluginId && item.orgId === orgId && item.status === 'running')
    if (!record) throw new Error(t('插件 {plugin} 未在该组织运行中', { plugin: pluginId }))
    const updated = this.installs().update(record.id, { status: 'uninstalled' })
    this.ctx.usage.grantCapabilities(`plugin:${pluginId}`, [], `market-uninstall:${actor}`)
    return updated
  }

  installedFor(orgId: string): PluginInstallRecord[] {
    return this.installs().find((item) => item.orgId === orgId && item.status === 'running')
  }

  /** Exécution L0 : lit le paquet de prompts d'un plugin installé (face de consommation de l'Agent, contenu purement déclaratif). */
  promptPacks(orgId: string): Array<{ pluginId: string; version: string; name: string; description: string; template: string }> {
    const packs: Array<{ pluginId: string; version: string; name: string; description: string; template: string }> = []
    for (const install of this.installedFor(orgId)) {
      const submission = this.submissions().findOne((item) => item.pluginId === install.pluginId && item.version === install.version)
      if (!submission) continue
      for (const prompt of submission.parsed.content.prompts) {
        packs.push({ pluginId: install.pluginId, version: install.version, name: prompt.name, description: prompt.description ?? '', template: prompt.template })
      }
    }
    return packs
  }

  /** Metering du contenu L0 : chaque reprise d'un paquet de prompts par l'Agent → événement usage (facturation L3). */
  meterPromptUse(orgId: string, pluginId: string, promptName: string, subject: string): void {
    const install = this.installs().findOne((item) => item.pluginId === pluginId && item.orgId === orgId && item.status === 'running')
    if (!install) throw new Error(t('插件 {plugin} 未在组织 {org} 安装', { plugin: pluginId, org: orgId }))
    const submission = this.submissions().findOne((item) => item.pluginId === pluginId && item.version === install.version)
    if (!submission) throw new Error(t('插件版本记录缺失'))
    if (!submission.parsed.content.prompts.some((prompt) => prompt.name === promptName)) {
      throw new Error(t('提示词包不存在：{name}', { name: promptName }))
    }
    // Clé idempotente déterministe : installation+principal+paquet de prompts+fenêtre UTC à la minute — une retry du même métier (meterPromptUse n'a pas d'ID de document
    // métier disponible) ne compte pas deux fois, des métiers différents (installation/principal/paquet/fenêtre différents) ne se collisionnent pas ; fenêtre de déduplication à la minute
    // alignée sur la clé idempotente automatique d'usage (autoIdempotencyKey)
    const dedupWindow = new Date().toISOString().slice(0, 16)
    this.ctx.usage.record({
      org: orgId,
      subject,
      principal: `plugin:${pluginId}`,
      resource: `plugin:${pluginId}`,
      tenant_id: install.tenantId,
      meters: [{ key: submission.parsed.billing.usage[0]?.key ?? 'prompts.used', value: 1, unit: submission.parsed.billing.usage[0]?.unit ?? '次' }],
      idempotency_key: `plugin-use:${install.id}:${subject}:${promptName}:${dedupWindow}`,
    })
  }

  private requireSubmission(id: string): PluginSubmissionRecord {
    const record = this.submissions().get(id)
    if (!record) throw new Error(t('提交记录不存在：{id}', { id }))
    return record
  }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    market: MarketService
  }
}

export const name = 'market'
export const inject = ['opsStorage', 'platformBus', 'authn', 'usage']

export function apply(ctx: Context) {
  ctx.plugin(MarketService)
  ctx.plugin(marketTools)
}

// ---------------------------------------------------------------------------
// Première offre propre de la plateforme (résorption M3 : creux d'offre L0 → paquets de démonstration de scénarios étalons, metering en instantané à prix zéro)
// passe par exactement la même chaîne soumission/signature/approbation que les tiers (on mange sa propre nourriture de chien).
// ---------------------------------------------------------------------------

const OFFICIAL_PLUGINS: Array<{ id: string; name: string; description: string; template: string; usageKey: string; unit: string }> = [
  {
    id: 'com.platform.contract-review', name: '合同审查提示词包', description: '按企业合同红线清单输出结构化审查意见',
    template: '你是合同审查专家。对输入合同执行：1) 标的主体与签署权限核验；2) 付款/违约/知识产权条款风险标注（高/中/低）；3) 输出结构化审查意见表。',
    usageKey: 'contract.docs', unit: '份',
  },
  {
    id: 'com.platform.weekly-report', name: '周报生成器', description: '把零散工作记录收敛为管理层周报',
    template: '你是周报整理助手。将输入的工作记录归纳为：本周进展（按优先级）/ 数据亮点 / 风险与求助 / 下周计划，保持事实忠实不夸大。',
    usageKey: 'report.count', unit: '次',
  },
  {
    id: 'com.platform.pii-mask', name: '数据脱敏模板', description: '对外输出前的 PII 脱敏规则包',
    template: '你是数据脱敏助手。按规则处理输入文本：手机号/身份证/银行卡保留前三后四；姓名保留姓；邮箱打码域名前部分；输出脱敏后文本与脱敏项清单。',
    usageKey: 'mask.count', unit: '次',
  },
]

function seedOfficialPlugins(market: MarketService): void {
  // ctx doit être pris hors du try : le catch doit aussi s'en servir pour logger (ctx défini dans le try, une graine qui jetait
  // transformait le catch lui-même en ReferenceError et élevait l'erreur en échec de construction du MarketService — l'injection
  // de console manquait alors, l'extension restait suspendue silencieusement par cordis, /api/health de l'instance en 404 sans aucun log, constat de dépannage M2 2026-09-16)
  const ctx = market.ctx
  try {
    if (market.submissions().count() > 0) return
    const keys = generateEd25519KeyPair()
    let official = market.developers().findOne((item) => item.username === 'platform-official')
    if (!official) {
      official = market.registerDeveloper({
        username: 'platform-official',
        displayName: '平台官方（自营）',
        email: 'official@platform.internal',
        password: randomBytes(24).toString('base64url'),
        publicKey: keys.publicKeyBase64,
        namespace: 'platform',
      }).developer
    }
    for (const spec of OFFICIAL_PLUGINS) {
      const files: Record<string, string> = {
        'plugin.yaml': [
          `id: ${spec.id}`,
          'version: 1.0.0',
          'publisher: platform-official',
          'depends:',
          '  - dsh-plugin-platform-core: ^1.0',
          'capabilities_request:',
          '  - knowledgebase.read',
          'sandbox: L0',
          'content:',
          '  prompts:',
          `    - name: main`,
          `      description: ${spec.description}`,
          '      template: |',
          `        ${spec.template}`,
          '',
        ].join('\n'),
        'manifest/permissions.yaml': 'requested:\n  - knowledgebase.read\n',
        'manifest/api.yaml': 'routes: []\n',
        'manifest/events.yaml': 'subscribes: []\nemits: []\n',
        'manifest/billing.yaml': [
          'model: free',
          'usage:',
          `  - key: ${spec.usageKey}`,
          `    unit: ${spec.unit}`,
          '    price: 0',
          '',
        ].join('\n'),
      }
      const signature = signEd25519(keys.privateKeyPem, fingerprintOf(files))
      const submission = market.submit(official, files, signature)
      market.approve(submission.id, 'platform-seed', '自营首批供给（M3：标杆场景打破供给空窗）')
    }
    ctx.logger('market').info(`自营首批供给已上架：${OFFICIAL_PLUGINS.length} 个 L0 插件`)
  } catch (error) {
    ctx.logger('market').warn('自营插件种子失败（跳过，不影响启动）', error)
  }
}
