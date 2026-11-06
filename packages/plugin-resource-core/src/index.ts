/**
 * @dsh-ops/plugin-resource-core — socle générique des entités de ressource.
 *
 * Les modules Agent et application IA partagent un modèle d'attributs, des permissions et une logique de cycle de vie très semblables (plan §8),
 * cette extension les abstrait en moteur « entité de ressource » :
 *   - moteur de table d'attributs : schéma déclaratif (groupes + champs), validation unifiée à la création/mise à jour,
 *     le même schéma pilote le formulaire de console et les paramètres dshctl/outils.
 *   - machine à états de cycle de vie : draft → trial → online → offline → archived,
 *     transitions avec guard, marque d'approbation, trace d'historique, et publication d'événements de plateforme.
 *   - graphe de dépendances : topologie et analyse d'impact des dépendances application → Agent → MCP/Skill.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId, slugify, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'

// ---------------------------------------------------------------------------
// DSL de schéma de table d'attributs
// ---------------------------------------------------------------------------

export type FieldType = 'string' | 'text' | 'number' | 'boolean' | 'enum' | 'tags' | 'url' | 'model'

export interface FieldSpec {
  key: string
  label: string
  type: FieldType
  group: string
  required?: boolean
  options?: Array<{ value: string; label: string; hint?: string }>
  hint?: string
  placeholder?: string
  defaultValue?: unknown
  /** Immuable après création (ex. slug). */
  immutable?: boolean
  /** Doit être complété avant la mise en ligne (online). */
  requiredForOnline?: boolean
}

export interface AttributeSchema {
  groups: Array<{ key: string; label: string; description?: string }>
  fields: FieldSpec[]
}

// ---------------------------------------------------------------------------
// Machine à états de cycle de vie
// ---------------------------------------------------------------------------

export interface LifecycleState {
  key: string
  label: string
  /** Teinte de badge d'état : ok | info | warn | danger | muted */
  tone: 'ok' | 'info' | 'warn' | 'danger' | 'muted'
  terminal?: boolean
}

export interface LifecycleTransition {
  action: string
  label: string
  from: string[]
  to: string
  /** Garde avant transition : renvoyer un libellé = refus. */
  guard?: (entity: ResourceEntity, ctx: Context) => string | undefined
  /** Les transitions à haut risque passent par le centre d'approbations (L4). */
  approval?: boolean
  /** Nom de l'événement de plateforme publié après la transition (ex. agent.offlined). */
  event?: string
}

export interface LifecycleSpec {
  initial: string
  states: LifecycleState[]
  transitions: LifecycleTransition[]
}

// ---------------------------------------------------------------------------
// Déclaration de type de ressource
// ---------------------------------------------------------------------------

export interface ResourceTypeSpec {
  type: string
  label: string
  plugin: string
  idPrefix: string
  schema: AttributeSchema
  lifecycle: LifecycleSpec
}

export interface LifecycleHistoryEntry {
  at: string
  from: string
  to: string
  action: string
  actor: string
  note?: string
}

export interface ResourceEntity extends RecordBase {
  type: string
  slug: string
  name: string
  attrs: Record<string, unknown>
  status: string
  ownerId: string
  orgId: string
  lifecycleHistory: LifecycleHistoryEntry[]
}

export interface DependencyRecord extends RecordBase {
  fromType: string
  fromId: string
  toType: string
  toId: string
  kind: string
}

export interface TransitionResult {
  entity: ResourceEntity
  event?: string
}

// ---------------------------------------------------------------------------
// Domaine des données (livraison IAW 2-1..2-4 : enregistrement de jeux de données / score qualité / lignée / dictionnaire d'indicateurs)
// ---------------------------------------------------------------------------

/** Gradation des données (même domaine de valeurs que DataClass de modelgw) : le routage par gradation de canal (1-1) sélectionne là-dessus. */
export type DatasetClassification = 'public' | 'internal' | 'secret'

/** Score qualité en quatre dimensions (PRD §7.3) : complétude/exactitude/fraîcheur/cohérence, moyenne équipondérée = overall (référentiel v1). */
export interface DatasetQualityScore {
  completeness: number
  accuracy: number
  timeliness: number
  consistency: number
  overall: number
  scoredAt: string
  note?: string
}

export interface DatasetRecord extends RecordBase {
  /** Code du jeu de données (clé métier unique, ex. ds_qb01_market). */
  code: string
  name: string
  /** Système source (ex. DingTalk/ERP/NAS/registre manuel). */
  sourceSystem: string
  classification: DatasetClassification
  /** Description de la fréquence de rafraîchissement (temps réel/horaire/quotidienne/hebdomadaire/manuel). */
  refreshFrequency?: string
  ownerOrgId?: string
  /** Code de scénario lié (ScenegraphScene.code). */
  sceneCodes: string[]
  quality?: DatasetQualityScore
  /** Numéro de version du score qualité (C-11) : incrémenté à chaque enregistrement ; la mise à jour conditionnelle expectedVersion juge le conflit là-dessus. */
  qualityRevision?: number
  note?: string
}

/**
 * Définition d'indicateur (2-4 dictionnaire d'indicateurs) : un même code d'indicateur admet plusieurs définitions coexistantes — les conflits de référentiel sont
 * intégralement comptabilisés par « enregistreur/temps » (ni écrasement ni fusion), l'action d'arbitrage pose une entrée active et passe les autres superseded.
 */
export interface MetricDefinitionRecord extends RecordBase {
  code: string
  name: string
  unit?: string
  description?: string
  /** Détail du référentiel (formule de calcul/champs de table source/fenêtre statistique, etc., contrat du producteur). */
  payload?: Record<string, unknown>
  recordedBy: string
  recordedAt: string
  status: 'active' | 'superseded'
  /** Chaîne des ids de définitions qu'elle a remplacées à l'arbitrage. */
  supersedes?: string
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class ResourceCoreService extends Service {
  static readonly provide = 'resourceCore'

  private types = new Map<string, ResourceTypeSpec>()

  constructor(ctx: Context) {
    super(ctx, 'resourceCore')
  }

  /** L'extension enregistre un type de ressource (idempotent : un double enregistrement écrase, pour le rechargement à chaud en développement). */
  registerType(spec: ResourceTypeSpec): () => void {
    this.types.set(spec.type, spec)
    return () => this.types.delete(spec.type)
  }

  typeSpec(type: string): ResourceTypeSpec | undefined {
    return this.types.get(type)
  }

  typesSpecs(): ResourceTypeSpec[] {
    return [...this.types.values()]
  }

  collection(type: string): Collection<ResourceEntity> {
    const spec = this.requireSpec(type)
    return this.ctx.opsStorage.collection<ResourceEntity>(`entity:${spec.type}`)
  }

  private requireSpec(type: string): ResourceTypeSpec {
    const spec = this.types.get(type)
    if (!spec) throw new Error(t('未注册的资源类型：{type}', { type }))
    return spec
  }

  // -- Validation d'attributs -----------------------------------------------------------

  validateAttrs(type: string, attrs: Record<string, unknown>, mode: 'create' | 'update' | 'online'): string[] {
    const spec = this.requireSpec(type)
    const errors: string[] = []
    for (const field of spec.schema.fields) {
      const value = attrs[field.key]
      const present = value !== undefined && value !== null && value !== ''
      // la mise à jour valide les attrs complets après fusion, required aussi contraignant qu'à la création — sinon un PATCH vide contourne
      // l'obligatoire de création (QA-20261014 QA-04 externe : PATCH description:'' avait renvoyé 200 en vidant la description)
      if ((mode === 'create' || mode === 'update') && field.required && !present) {
        errors.push(t('缺少必填字段「{label}」({key})', { label: field.label, key: field.key }))
      }
      if (mode === 'online' && field.requiredForOnline && !present) {
        errors.push(t('上线前必须补全「{label}」({key})', { label: field.label, key: field.key }))
      }
      if (!present) continue
      switch (field.type) {
        case 'number':
          if (typeof value !== 'number' || !Number.isFinite(value)) errors.push(t('「{label}」必须是数字', { label: field.label }))
          break
        case 'boolean':
          if (typeof value !== 'boolean') errors.push(t('「{label}」必须是布尔值', { label: field.label }))
          break
        case 'enum':
          if (!field.options?.some((option) => option.value === value)) {
            errors.push(t('「{label}」的取值必须是：{values}', { label: field.label, values: field.options?.map((o) => o.value).join(' / ') }))
          }
          break
        case 'tags':
          if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
            errors.push(t('「{label}」必须是字符串数组', { label: field.label }))
          }
          break
        case 'url':
          if (typeof value !== 'string' || !/^https?:\/\//.test(value)) errors.push(t('「{label}」必须是 http(s) 地址', { label: field.label }))
          break
        default:
          if (typeof value !== 'string') errors.push(t('「{label}」必须是字符串', { label: field.label }))
          else if (looksLikeCorruptedText(value)) {
            // test DEF-06 : les caractères moisis issus d'une erreur d'encodage côté enregistrement (ex. flux d'octets GBK décodé en UTF-8) n'entrent plus en base
            errors.push(t('「{label}」含乱码字符（疑似编码错误），请以 UTF-8 编码重新提交', { label: field.label }))
          }
      }
    }
    return errors
  }

  // -- CRUD d'entités ----------------------------------------------------------

  create(type: string, input: {
    name: string
    slug?: string
    attrs?: Record<string, unknown>
    ownerId: string
    orgId: string
  }): ResourceEntity {
    const spec = this.requireSpec(type)
    if (!input.name || !String(input.name).trim()) throw new Error(t('{label}名称不能为空', { label: spec.label }))
    const attrs: Record<string, unknown> = {}
    for (const field of spec.schema.fields) {
      const provided = input.attrs?.[field.key]
      if (provided !== undefined) attrs[field.key] = provided
      else if (field.defaultValue !== undefined) attrs[field.key] = field.defaultValue
    }
    const errors = this.validateAttrs(type, attrs, 'create')
    if (errors.length > 0) throw new Error(t('属性校验失败：{errors}', { errors: errors.join('；') }))
    const slug = input.slug || slugify(input.name)
    const collection = this.collection(type)
    if (collection.findOne((entity) => entity.slug === slug)) {
      throw new Error(t('{label}标识 {slug} 已存在', { label: spec.label, slug }))
    }
    const now = new Date().toISOString()
    return collection.insert({
      id: newId(spec.idPrefix),
      type: spec.type,
      slug,
      name: input.name,
      attrs,
      status: spec.lifecycle.initial,
      ownerId: input.ownerId,
      orgId: input.orgId,
      lifecycleHistory: [{ at: now, from: '', to: spec.lifecycle.initial, action: 'create', actor: input.ownerId }],
    })
  }

  update(type: string, id: string, patch: { name?: string; attrs?: Record<string, unknown> }): ResourceEntity {
    const spec = this.requireSpec(type)
    const collection = this.collection(type)
    const entity = collection.get(id)
    if (!entity) throw new Error(t('{label}不存在：{id}', { label: spec.label, id }))
    const mergedAttrs = { ...entity.attrs }
    if (patch.attrs) {
      for (const field of spec.schema.fields) {
        if (patch.attrs[field.key] === undefined) continue
        if (field.immutable && entity.attrs[field.key] !== patch.attrs[field.key]) {
          throw new Error(t('字段「{label}」创建后不可修改', { label: field.label }))
        }
        mergedAttrs[field.key] = patch.attrs[field.key]
      }
    }
    const errors = this.validateAttrs(type, mergedAttrs, 'update')
    if (errors.length > 0) throw new Error(t('属性校验失败：{errors}', { errors: errors.join('；') }))
    return collection.update(id, {
      attrs: mergedAttrs,
      ...(patch.name !== undefined ? { name: patch.name } : {}),
    })
  }

  get(type: string, id: string): ResourceEntity | undefined {
    return this.collection(type).get(id)
  }

  bySlug(type: string, slug: string): ResourceEntity | undefined {
    return this.collection(type).findOne((entity) => entity.slug === slug)
  }

  list(type: string, filter?: { status?: string; orgId?: string; q?: string }): ResourceEntity[] {
    const q = filter?.q?.toLowerCase()
    return this.collection(type).find((entity) => {
      if (filter?.status && entity.status !== filter.status) return false
      if (filter?.orgId && entity.orgId !== filter.orgId) return false
      if (q) {
        const haystack = `${entity.name} ${entity.slug} ${JSON.stringify(entity.attrs)}`.toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  }

  /**
   * Supprime une ressource : par défaut, seul l'état terminal est supprimable ; l'appelant peut relâcher via allowStates (ex. NAS permet la suppression directe
   * du brouillon — un brouillon jamais mis en ligne ne peut pas atteindre l'état terminal par hors ligne→archivage).
   */
  remove(type: string, id: string, opts?: { allowStates?: string[] }): boolean {
    const spec = this.requireSpec(type)
    const entity = this.collection(type).get(id)
    if (!entity) return false
    const allowed = opts?.allowStates ?? spec.lifecycle.states.filter((state) => state.terminal).map((state) => state.key)
    if (!allowed.includes(entity.status)) {
      throw new Error(t('当前状态 {status} 不可删除（可删状态：{allowed}）', { status: entity.status, allowed: allowed.join(' / ') }))
    }
    return this.collection(type).remove(id)
  }

  // -- Cycle de vie -----------------------------------------------------------

  stateLabel(type: string, status: string): { label: string; tone: string } {
    const spec = this.requireSpec(type)
    const state = spec.lifecycle.states.find((item) => item.key === status)
    return { label: state?.label ?? status, tone: state?.tone ?? 'muted' }
  }

  availableTransitions(type: string, id: string): Array<{ action: string; label: string; to: string; approval?: boolean }> {
    const spec = this.requireSpec(type)
    const entity = this.collection(type).get(id)
    if (!entity) return []
    return spec.lifecycle.transitions
      .filter((transition) => transition.from.includes(entity.status))
      .map(({ action, label, to, approval }) => ({ action, label, to, approval }))
  }

  /** Exécute une transition d'état : guard → mise à jour d'état → trace d'historique → événement de plateforme. */
  transition(type: string, id: string, action: string, actor: string, note?: string): TransitionResult {
    const spec = this.requireSpec(type)
    const collection = this.collection(type)
    const entity = collection.get(id)
    if (!entity) throw new Error(t('{label}不存在：{id}', { label: spec.label, id }))
    const transition = spec.lifecycle.transitions.find((item) => item.action === action)
    if (!transition) throw new Error(t('未知操作：{action}', { action }))
    if (!transition.from.includes(entity.status)) {
      const fromState = this.stateLabel(type, entity.status).label
      throw new Error(t('当前状态「{from}」不允许执行「{action}」', { from: fromState, action: transition.label }))
    }
    if (transition.to === 'online') {
      const errors = this.validateAttrs(type, entity.attrs, 'online')
      if (errors.length > 0) throw new Error(errors.join('；'))
    }
    if (transition.guard) {
      const reason = transition.guard(entity, this.ctx)
      if (reason) throw new Error(reason)
    }
    const entry: LifecycleHistoryEntry = {
      at: new Date().toISOString(),
      from: entity.status,
      to: transition.to,
      action,
      actor,
      ...(note !== undefined ? { note } : {}),
    }
    const updated = collection.update(id, {
      status: transition.to,
      lifecycleHistory: [...entity.lifecycleHistory, entry],
    })
    const event = transition.event
    if (event) {
      this.ctx.platformBus.emit(event, { type, id, slug: updated.slug, name: updated.name, from: entry.from, to: entry.to, actor })
    }
    return { entity: updated, event }
  }

  // -- Graphe de dépendances -------------------------------------------------------------

  dependencies(): Collection<DependencyRecord> {
    return this.ctx.opsStorage.collection<DependencyRecord>('resource:dependencies')
  }

  addDependency(input: { fromType: string; fromId: string; toType: string; toId: string; kind: string }): DependencyRecord {
    const existing = this.dependencies().findOne((record) =>
      record.fromType === input.fromType && record.fromId === input.fromId
      && record.toType === input.toType && record.toId === input.toId)
    if (existing) return existing
    return this.dependencies().insert({
      id: newId('dep'),
      fromType: input.fromType,
      fromId: input.fromId,
      toType: input.toType,
      toId: input.toId,
      kind: input.kind,
    })
  }

  removeDependency(input: { fromType: string; fromId: string; toType: string; toId: string }): void {
    const record = this.dependencies().findOne((item) =>
      item.fromType === input.fromType && item.fromId === input.fromId
      && item.toType === input.toType && item.toId === input.toId)
    if (record) this.dependencies().remove(record.id)
  }

  /** Topologie : déploie l'arbre de dépendances depuis une ressource vers le bas (application → Agent → MCP/Skill). Type non enregistré rendu comme feuille. */
  topology(type: string, id: string, depth = 4): TopologyNode {
    const spec = this.types.get(type)
    const entity = spec ? this.collection(type).get(id) : undefined
    const node: TopologyNode = {
      type,
      id,
      name: entity?.name ?? id,
      status: entity?.status ?? 'unknown',
      statusLabel: entity && spec ? this.stateLabel(type, entity.status).label : t('外部节点'),
      children: [],
    }
    if (depth <= 0) return node
    for (const record of this.dependencies().find((item) => item.fromType === type && item.fromId === id)) {
      node.children.push(this.topology(record.toType, record.toId, depth - 1))
    }
    return node
  }

  /** Impact : qui dépend directement/indirectement de cette ressource (aperçu avant mise hors ligne). Type non enregistré : id seul enregistré. */
  impact(type: string, id: string): Array<{ type: string; id: string; name: string; status: string; depth: number }> {
    const result: Array<{ type: string; id: string; name: string; status: string; depth: number }> = []
    const visit = (t: string, i: string, depth: number): void => {
      if (depth > 4) return
      for (const record of this.dependencies().find((item) => item.toType === t && item.toId === i)) {
        const spec = this.types.get(record.fromType)
        const entity = spec ? this.collection(record.fromType).get(record.fromId) : undefined
        if (result.some((item) => item.id === record.fromId)) continue
        result.push({ type: record.fromType, id: record.fromId, name: entity?.name ?? record.fromId, status: entity?.status ?? 'unknown', depth })
        visit(record.fromType, record.fromId, depth + 1)
      }
    }
    visit(type, id, 1)
    return result.sort((a, b) => a.depth - b.depth)
  }

  // -- Domaine des données (livraison IAW 2-1..2-4) ---------------------------------------

  datasets(): Collection<DatasetRecord> {
    const collection = this.ctx.opsStorage.collection<DatasetRecord>('resource:datasets')
    collection.uniqueOn('dataset_code', (item) => item.code)
    return collection
  }

  /** Enregistrement de jeu de données (upsert par code) : système source/gradation/fréquence de rafraîchissement/scénario lié (2-1). */
  upsertDataset(input: {
    code: string
    name: string
    sourceSystem: string
    classification: DatasetClassification
    refreshFrequency?: string
    ownerOrgId?: string
    sceneCodes?: string[]
    note?: string
  }): DatasetRecord {
    if (!input.code?.trim() || !/^[A-Za-z0-9._-]{2,64}$/.test(input.code)) {
      throw new Error(t('数据集 code 非法（字母/数字/._-，2-64 位）：{code}', { code: String(input.code) }))
    }
    if (!input.name?.trim()) throw new Error(t('数据集名称必填'))
    if (!input.sourceSystem?.trim()) throw new Error(t('来源系统必填（sourceSystem）'))
    if (!['public', 'internal', 'secret'].includes(input.classification)) {
      throw new Error(t('数据分级非法：{value}（public/internal/secret）', { value: String(input.classification) }))
    }
    const sceneCodes = [...new Set((input.sceneCodes ?? []).map((code) => code.trim()).filter(Boolean))]
    const existing = this.datasets().findOne((item) => item.code === input.code)
    if (existing) {
      const updated = this.datasets().update(existing.id, {
        name: input.name.trim(),
        sourceSystem: input.sourceSystem.trim(),
        classification: input.classification,
        ...(input.refreshFrequency !== undefined ? { refreshFrequency: input.refreshFrequency } : {}),
        ...(input.ownerOrgId !== undefined ? { ownerOrgId: input.ownerOrgId } : {}),
        sceneCodes,
        ...(input.note !== undefined ? { note: input.note } : {}),
      })
      this.ctx.platformBus.emit('resource.dataset.changed', { code: updated.code, action: 'updated', sceneCodes })
      return updated
    }
    const created = this.datasets().insert({
      id: newId('ds'),
      code: input.code.trim(),
      name: input.name.trim(),
      sourceSystem: input.sourceSystem.trim(),
      classification: input.classification,
      ...(input.refreshFrequency ? { refreshFrequency: input.refreshFrequency } : {}),
      ...(input.ownerOrgId ? { ownerOrgId: input.ownerOrgId } : {}),
      sceneCodes,
      ...(input.note ? { note: input.note } : {}),
    })
    this.ctx.platformBus.emit('resource.dataset.changed', { code: created.code, action: 'created', sceneCodes })
    return created
  }

  /** Liste des jeux de données (2-1, interface minimale du panneau) : filtres par scénario/gradation/organisation/mot-clé. */
  listDatasets(filter: { sceneCode?: string; classification?: string; orgId?: string; q?: string } = {}): Array<DatasetRecord & { sceneCount: number }> {
    const q = filter.q?.toLowerCase()
    return this.datasets().all()
      .filter((item) => {
        if (filter.sceneCode && !item.sceneCodes.includes(filter.sceneCode)) return false
        if (filter.classification && item.classification !== filter.classification) return false
        if (filter.orgId && item.ownerOrgId !== filter.orgId) return false
        if (q && !`${item.name} ${item.code} ${item.sourceSystem}`.toLowerCase().includes(q)) return false
        return true
      })
      .map((item) => ({ ...item, sceneCount: item.sceneCodes.length }))
      .sort((a, b) => a.code.localeCompare(b.code))
  }

  /**
   * Enregistrement d'un score qualité (2-2) : quatre dimensions 0-100, overall en moyenne équipondérée ; l'instantané enregistré ne réécrit pas les références historiques.
   * Sémantique de concurrence (C-11) : score.expectedVersion absent = dernier écrivain (appelants existants non affectés) ;
    * porté, comparé au qualityRevision courant, divergence = refus (contre l'écrasement croisé d'enregistrements concurrents).
   */
  scoreDataset(code: string, score: {
    completeness: number
    accuracy: number
    timeliness: number
    consistency: number
    note?: string
    /** Verrou optimiste : porté, doit égaler le qualityRevision courant, sinon refus. */
    expectedVersion?: number
  }): DatasetRecord {
    const dataset = this.datasets().findOne((item) => item.code === code)
    if (!dataset) throw new Error(t('数据集不存在：{code}（请先登记）', { code }))
    const dims = ['completeness', 'accuracy', 'timeliness', 'consistency'] as const
    for (const dim of dims) {
      const value = score[dim]
      if (!Number.isFinite(value) || value < 0 || value > 100) throw new Error(t('质量分 {dim} 应为 0-100，收到 {value}', { dim, value: String(value) }))
    }
    const currentRevision = dataset.qualityRevision ?? 0
    if (score.expectedVersion !== undefined && score.expectedVersion !== currentRevision) {
      throw new Error(t('质量分版本冲突：当前 revision={current}，请求基于 revision={expected}（已被并发登记更新，请读取最新分后重试）', { current: currentRevision, expected: score.expectedVersion }))
    }
    const overall = Math.round(((score.completeness + score.accuracy + score.timeliness + score.consistency) / 4) * 10) / 10
    const quality: DatasetQualityScore = {
      completeness: score.completeness, accuracy: score.accuracy,
      timeliness: score.timeliness, consistency: score.consistency,
      overall, scoredAt: new Date().toISOString(),
      ...(score.note ? { note: score.note } : {}),
    }
    const updated = this.datasets().update(dataset.id, { quality, qualityRevision: currentRevision + 1 })
    this.ctx.platformBus.emit('resource.dataset.changed', { code, action: 'quality_scored', overall, revision: currentRevision + 1 })
    return updated
  }

  /**
   * Lignée de données (2-3) : réutilise le graphe de dépendances, sémantique d'arête « ensemble dérivé --dépend de--> ensemble source » (fromType/toType='dataset', kind='lineage').
   * Trace inverse = qui dérive de moi (downstream) ; trace directe = de qui je viens (upstream).
   */
  lineage(code: string): {
    dataset: string
    upstream: Array<{ code: string; name: string; kind: string }>
    downstream: Array<{ code: string; name: string; kind: string }>
  } {
    const nameOf = (datasetCode: string): string => this.datasets().findOne((item) => item.code === datasetCode)?.name ?? datasetCode
    const collect = (edgeFrom: boolean): Array<{ code: string; name: string; kind: string }> => {
      const rows = edgeFrom
        ? this.dependencies().find((item) => item.fromType === 'dataset' && item.fromId === code)
        : this.dependencies().find((item) => item.toType === 'dataset' && item.toId === code)
      return rows.map((row) => ({ code: edgeFrom ? row.toId : row.fromId, name: nameOf(edgeFrom ? row.toId : row.fromId), kind: row.kind }))
    }
    return { dataset: code, upstream: collect(true), downstream: collect(false) }
  }

  /** Enregistre une arête de lignée (l'ensemble dérivé derived dépend de l'ensemble source). Cycle refusé (C-08) : DFS le long des arêtes de lignée dataset existantes, source déjà accessible depuis derived = cycle. */
  addLineage(derived: string, source: string, kind = 'lineage'): DependencyRecord {
    if (derived === source) throw new Error(t('血缘边两端不能是同一数据集'))
    for (const code of [derived, source]) {
      if (!this.datasets().findOne((item) => item.code === code)) throw new Error(t('数据集未登记：{code}（请先登记再建血缘）', { code }))
    }
    if (this.lineageReaches(source, derived)) {
      throw new Error(t('血缘成环拒绝：{source} 经既有血缘已可达 {derived}，再登记 {derived}→{source} 将形成循环依赖', { source, derived }))
    }
    return this.addDependency({ fromType: 'dataset', fromId: derived, toType: 'dataset', toId: source, kind })
  }

  /** DFS vers le bas le long des arêtes de dépendance dataset (from→to) : from atteint-il target (requête d'accessibilité pour le jugement de cycle). */
  private lineageReaches(from: string, target: string): boolean {
    const seen = new Set<string>([from])
    const stack = [from]
    while (stack.length > 0) {
      const current = stack.pop()!
      for (const edge of this.dependencies().find((item) => item.fromType === 'dataset' && item.fromId === current)) {
        if (edge.toId === target) return true
        if (!seen.has(edge.toId)) {
          seen.add(edge.toId)
          stack.push(edge.toId)
        }
      }
    }
    return false
  }

  metricDefinitions(): Collection<MetricDefinitionRecord> {
    return this.ctx.opsStorage.collection<MetricDefinitionRecord>('resource:metricDefinitions')
  }

  /**
   * Enregistrement d'un référentiel d'indicateur (2-4) : même code sans écrasement ni fusion — un double enregistrement de contenu identique renvoie idempotemment l'entrée existante ;
    * contenu différent = nouvelle définition coexistante (conflit de référentiel intégralement comptabilisé par enregistreur/temps), l'arbitrage décide de l'active.
   * Normalisation d'ordre des clés de l'empreinte (C-09) : le payload sérialisé après tri récursif des clés, un même contenu avec ordre de clés différent n'est plus un faux conflit de référentiel.
   */
  putMetricDefinition(input: {
    code: string
    name: string
    unit?: string
    description?: string
    payload?: Record<string, unknown>
    recordedBy: string
  }): { definition: MetricDefinitionRecord; conflict: boolean } {
    if (!input.code?.trim()) throw new Error(t('指标码 code 必填（如 gm_revenue）'))
    if (!input.name?.trim()) throw new Error(t('指标名称必填'))
    if (!input.recordedBy?.trim()) throw new Error(t('记录人 recordedBy 必填（口径问责）'))
    const fingerprint = stableStringify([input.name, input.unit ?? '', input.description ?? '', input.payload ?? {}])
    const existing = this.metricDefinitions().all().filter((item) => item.code === input.code)
    const same = existing.find((item) => stableStringify([item.name, item.unit ?? '', item.description ?? '', item.payload ?? {}]) === fingerprint)
    if (same) return { definition: same, conflict: false }
    const activeCount = existing.filter((item) => item.status === 'active').length
    const definition = this.metricDefinitions().insert({
      id: newId('mdef'),
      code: input.code.trim(),
      name: input.name.trim(),
      ...(input.unit ? { unit: input.unit } : {}),
      ...(input.description ? { description: input.description } : {}),
      ...(input.payload ? { payload: input.payload } : {}),
      recordedBy: input.recordedBy.trim(),
      recordedAt: new Date().toISOString(),
      // première définition active par défaut ; un nouveau référentiel avec active existante coexiste en superseded (en attente d'arbitrage)
      status: existing.length === 0 ? 'active' : 'superseded',
    })
    this.ctx.platformBus.emit('resource.metric.changed', { code: definition.code, definitionId: definition.id, action: 'recorded', activeCount })
    return { definition, conflict: existing.filter((item) => item.status === 'active').length > 0 }
  }

  metricDefinitionsOf(code: string): Array<MetricDefinitionRecord & { conflictCount: number }> {
    const all = this.metricDefinitions().all().filter((item) => item.code === code)
      .sort((a, b) => b.recordedAt.localeCompare(a.recordedAt))
    return all.map((item) => ({ ...item, conflictCount: all.length }))
  }

  /** Arbitrage de référentiel (2-4) : désigne une définition active, les autres définitions du même code passent superseded. */
  arbitrateMetric(code: string, definitionId: string, actor: string): { active: MetricDefinitionRecord; superseded: number } {
    const all = this.metricDefinitions().all().filter((item) => item.code === code)
    const target = all.find((item) => item.id === definitionId)
    if (!target) throw new Error(t('指标定义不存在：{id}（code={code}）', { id: definitionId, code }))
    let superseded = 0
    for (const item of all) {
      if (item.id === definitionId) continue
      // C-09 : les définitions du même code hors cible pointent uniformément supersedes vers le gagnant du jour (pointeurs périmés déjà superseded inclus)
      if (item.status !== 'superseded' || item.supersedes !== definitionId) {
        this.metricDefinitions().update(item.id, { status: 'superseded', supersedes: definitionId })
        if (item.status === 'active') superseded++
      }
    }
    this.metricDefinitions().update(definitionId, { status: 'active', supersedes: undefined })
    this.ctx.platformBus.emit('resource.metric.changed', { code, definitionId, action: 'arbitrated', actor, superseded })
    return { active: this.metricDefinitions().get(definitionId)!, superseded }
  }
}

export interface TopologyNode {
  type: string
  id: string
  name: string
  status: string
  statusLabel: string
  children: TopologyNode[]
}

/**
 * Sérialisation normalisée d'ordre des clés (C-09) : les clés d'objet triées récursivement avant sérialisation — un même payload de référentiel dont l'ordre d'insertion
 * des clés diffère n'est plus jugé en conflit de référentiel (faux conflit). Les tableaux gardent leur ordre (l'ordre des éléments porte généralement une sémantique), seules les clés d'objet sont sans ordre.
 */
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`).join(',')}}`
  }
  return JSON.stringify(value ?? null)
}

/**
 * Détection de texte moisi (test DEF-06) : identifie les textes entrés en base via une erreur d'encodage côté enregistrement.
 * Critères (une atteinte quelconque = considéré moisi) :
 *   1. caractère de remplacement U+FFFD — produit quand un flux d'octets non UTF-8 légal est décodé ;
 *   2. caractères de contrôle (hors \t \n \r) ou zone à usage privé/codepoints non-caractères — n'apparaissent pas dans des libellés métier normaux ;
 *   3. marqueurs classiques de moisi (锟斤拷/烫烫烫/?? consécutifs en placeholder).
 */
export function looksLikeCorruptedText(value: string): boolean {
  if (!value) return false
  for (const ch of value) {
    const code = ch.codePointAt(0)!
    if (code === 0xfffd) return true
    if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) return true
    if (code >= 0xe000 && code <= 0xf8ff) return true
    if (code >= 0xfff0 && code <= 0xffff) return true
  }
  return /锟斤拷|烫烫烫|\?{6,}/.test(value)
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    resourceCore: ResourceCoreService
  }
}

export const name = 'resource-core'
export const inject = ['opsStorage', 'platformBus']

export function apply(ctx: Context) {
  ctx.plugin(ResourceCoreService)
}
