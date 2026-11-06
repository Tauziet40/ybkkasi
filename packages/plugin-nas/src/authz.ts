/**
 * NasAuthzService — service de décision des permissions de données NAS (PDP, dev-plan-nas-authz §2.1/§2.3).
 *
 * Contrainte de couches (O8) : toute la logique de jugement est dans le module de fonctions pures ./authz/engine.ts (sans conteneur, sans IO),
 * ce Service ne fait que l'assemblage IO : prise de données (arbre d'organisations IAM/cartographie d'identités + actif NAS + instantané de règles) → appel du moteur → inscription des traces.
 *
 * Contraintes dures :
 * - l'identité passe toujours par l'en-tête X-On-Behalf-User/le paramètre userId (prise en charge du userId plateforme et de la recherche inverse du userid DingTalk
 *   dans identityLinks), jamais dans les paramètres d'outils de la passerelle (leçon P0-2) ;
 * - rules est un singleton à champ version ; le PUT doit porter le verrou optimiste ifVersion, conflit = RulesVersionConflictError (409) ;
 * - fail-closed : utilisateur/NAS/périmètre irrésoluble = toujours deny ; l'inscription des traces est asynchrone (fire-and-forget vers le bus),
 *   les enregistrements ordinaires sont nettoyés glissamment à 90 jours, les traces des opérations à haut risque delete/share/admin sont conservées à vie.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId, wrapPolicyDecision, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import {
  AUTHZ_OPS, HIGH_RISK_OPS,
  buildOrgIndex, check as engineCheck, deriveRole, deriveScope, effectiveMatrix, normalizePath,
  findVacantLeaderOrgs, nearestLeaderOrg, reconcileOrgDirs,
  type AuthzException, type AuthzOp, type AuthzRole, type EngineDecision,
  type EngineNas, type EngineUser, type OrgIndex,
} from './authz/engine.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

/**
 * Politique de paliers des liens de partage signés (décisions ②③ du 2026-09-21 ; accrochée au singleton de règles, même source que la face de gouvernance des permissions de données).
 * Les champs absents sont rattrapés par défaut via NasShareLinkService.policy() : plafond 30 jours / permanent fermé par défaut /
 * permanent limité à nas.authz.write.
 */
export interface ShareLinkPolicy {
  maxTtlSec: number
  allowPermanent: boolean
  permanentPermission: string
}

/** Singleton de configuration de règles (nas:authzRules ; verrou optimiste version, le PUT porte ifVersion). */
export interface AuthzRulesRecord extends RecordBase {
  id: 'singleton'
  version: number
  /** Réserve multi-tenant : fixé à t_default dans cette itération. */
  tenantId: string
  matrixOverrides?: Partial<Record<AuthzRole, Partial<Record<AuthzOp, boolean>>>>
  exceptions: AuthzException[]
  /** Ids des groupes d'utilisateurs dynamiques associés au rôle C (l'import prend en charge la résolution par nom de groupe). */
  cGroups: string[]
  externalReadPaths: Array<{ nasId: string; path: string }>
  observeOnly: boolean
  degradeAllToReadonly: boolean
  shareLinkPolicy?: ShareLinkPolicy
  updatedBy?: string
}

/** Trace de jugement (nas:authzDecisions) : trace pour les opérations à haut risque et tous les deny ; écriture asynchrone. */
export interface AuthzDecisionRecord extends RecordBase {
  nasId: string
  userId: string
  userName?: string
  op: AuthzOp
  paths: string[]
  decision: 'allow' | 'deny'
  role?: AuthzRole
  scope: string[]
  reasons: string[]
  ruleId?: string
  caller: string
  override: boolean
  observeOnly: boolean
  highRisk: boolean
  /** Expression de décision unifiée de la plateforme (contrat W3-T5 §11, additive) : id de décision obtenu en enveloppant la conclusion du moteur via wrapPolicyDecision. */
  decisionId?: string
}

/** Conflit de verrou optimiste de version (mappé 409 par la couche REST). */
export class RulesVersionConflictError extends Error {
  readonly currentVersion: number
  constructor(currentVersion: number, expected: number) {
    super(t('规则版本冲突：当前 version={current}，请求 ifVersion={expected}（请重新读取后重试）', { current: currentVersion, expected }))
    this.name = 'RulesVersionConflictError'
    this.currentVersion = currentVersion
  }
}

/**
 * Enregistrement de propriété de fichiers (ajout 2026-09-17) : l'uploadeur dispose par défaut de tous les droits sur ses propres documents (ordre de jugement ③b).
 * Seuls les chemins exacts de fichiers sont enregistrés (pas les répertoires, pour éviter qu'un créateur de répertoire n'obtienne le droit de suppression du sous-arbre) ; suppression/renommage/déplacement maintenus au fil du cycle de vie.
 */
export interface NasOwnershipRecord extends RecordBase {
  nasId: string
  path: string
  userId: string
  userName?: string
  /** Source de l'enregistrement : upload = chaîne d'upload de la plateforme, gateway:upload/gateway:copy = rapport de passerelle (hermes/MCP direct) */
  source: string
  createdAt: string
  updatedAt: string
}

const DENIED_ALERT_WINDOW_MS = 10 * 60_000
const DENIED_ALERT_THRESHOLD = 10
const DECISION_RETENTION_DAYS = 90

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class NasAuthzService extends Service {
  static readonly provide = 'nasAuthz'

  /**
   * Dépendances au niveau Service (résolution paresseuse cordis) : iam = arbre d'organisations/cartographie d'identités/groupes dynamiques (dépendance externe),
   * nasRegistry = client de passerelle de fichiers du même plugin (énumération de répertoires pour le job de réconciliation). L'inject au niveau extension ne se référence pas soi-même,
   * les services du même plugin se déclarent via Service.inject, contre l'impasse d'auto-dépendance au chargement de l'extension.
   */
  static readonly inject = ['iam', 'nasRegistry']

  private denyWindows = new Map<string, number[]>()
  private lastDecisionPruneAt = 0

  constructor(ctx: Context) {
    super(ctx, 'nasAuthz')
    // Inscription de trace asynchrone (R2) : check n'émet qu'un événement sans écrire, la souscription absorbe toutes les anomalies de stockage
    ctx.platformBus.on('nas.authz.decision', (payload) => {
      try {
        const record = payload as Omit<AuthzDecisionRecord, 'id' | 'createdAt' | 'updatedAt'>
        this.decisions().insert({ ...record, id: newId('adz') })
      } catch (error) {
        this.ctx.logger('nasAuthz').warn('判定留痕落库失败', error)
      }
    })
    // Alerte de dérive du groupe C (R5) : dérive au recalcul des groupes dynamiques IAM → centre d'alertes de la plateforme
    ctx.platformBus.on('nas.authz.cGroupDrift', (payload) => {
      const p = payload as { groupId: string; groupName: string; addedCount: number; removedCount: number; threshold: number }
      this.ctx.audit.fire({
        severity: 'warning',
        title: t('动态用户组「{name}」成员漂移', { name: p.groupName }),
        message: t('+{added}/-{removed} 人（阈值 {threshold}）。该组被 NAS 数据权限 C 角色引用，跨域只读范围可能静默变化，请复核。', { added: p.addedCount, removed: p.removedCount, threshold: p.threshold }),
        resourceType: 'iam_group',
        resourceId: p.groupId,
      })
    })
    // Job quotidien de réconciliation organisations↔répertoires (R1) + nettoyage glissant des traces ; unref pour ne pas bloquer la sortie du processus
    const daily: ReturnType<typeof setInterval> = setInterval(() => {
      void this.dailyReconcile().catch((error) => this.ctx.logger('nasAuthz').warn('对账 job 失败', error))
    }, 24 * 60 * 60_000)
    daily.unref?.()
    // Exécuteur d'approbation share : approbation accordée = écriture automatique d'une exception share de 7 jours (boucle fermée §2.7)
    this.registerShareExecutor()
  }

  // -- Collections ---------------------------------------------------------------

  rulesCollection(): Collection<AuthzRulesRecord> {
    return this.ctx.opsStorage.collection<AuthzRulesRecord>('nas:authzRules')
  }

  decisions(): Collection<AuthzDecisionRecord> {
    return this.ctx.opsStorage.collection<AuthzDecisionRecord>('nas:authzDecisions')
  }

  ownershipCollection(): Collection<NasOwnershipRecord> {
    return this.ctx.opsStorage.collection<NasOwnershipRecord>('nas:ownership')
  }

  // -- Propriété de fichiers (l'uploadeur tout-puissant par défaut, ajout 2026-09-17) -------------------------

  /** Enregistre la propriété (appelé après upload/copie réussi) : upsert par (nasId, path), le dernier écrivain détient. Utilisateur irrésoluble = ignoré (écriture anonyme/machine non enregistrée). */
  recordOwnership(input: { nasId: string; path: string; userId: string; source?: string }): NasOwnershipRecord | undefined {
    const user = this.resolveUser(input.userId)
    if (!user) return undefined
    const nas = this.nasDescriptor(input.nasId)
    const nasId = nas?.id ?? input.nasId
    let path: string
    try {
      path = normalizePath(input.path)
    } catch {
      return undefined
    }
    const existing = this.ownershipCollection().findOne((item) => item.nasId === nasId && item.path === path)
    const now = new Date().toISOString()
    if (existing) {
      const updated: NasOwnershipRecord = { ...existing, userId: user.id, userName: user.displayName, source: input.source ?? existing.source, createdAt: now, updatedAt: now }
      this.ownershipCollection().update(existing.id, updated)
      return updated
    }
    return this.ownershipCollection().insert({ id: newId('own'), nasId, path, userId: user.id, userName: user.displayName, source: input.source ?? 'upload', createdAt: now, updatedAt: now })
  }

  /** Retire la propriété (appelé après suppression réussie, sous-arbre inclus). Renvoie le nombre de retraits. */
  removeOwnershipFor(nasIdInput: string, paths: string[]): number {
    const nas = this.nasDescriptor(nasIdInput)
    const nasId = nas?.id ?? nasIdInput
    const targets = paths.map((p) => { try { return normalizePath(p) } catch { return '' } }).filter(Boolean)
    if (targets.length === 0) return 0
    let removed = 0
    for (const record of this.ownershipCollection().find((item) => item.nasId === nasId)) {
      if (targets.some((target) => record.path === target || record.path.startsWith(`${target}/`))) {
        this.ownershipCollection().remove(record.id)
        removed++
      }
    }
    return removed
  }

  /** Réécrit les chemins de propriété (appelé après renommage/déplacement réussi, réécriture des préfixes de sous-arbre incluse). Renvoie le nombre de réécritures. */
  rewriteOwnershipFor(nasIdInput: string, fromPath: string, toPath: string): number {
    const nas = this.nasDescriptor(nasIdInput)
    const nasId = nas?.id ?? nasIdInput
    let from: string
    let to: string
    try {
      from = normalizePath(fromPath)
      to = normalizePath(toPath)
    } catch {
      return 0
    }
    let rewritten = 0
    for (const record of this.ownershipCollection().find((item) => item.nasId === nasId)) {
      if (record.path === from || record.path.startsWith(`${from}/`)) {
        this.ownershipCollection().update(record.id, { ...record, path: `${to}${record.path.slice(from.length)}`, updatedAt: new Date().toISOString() })
        rewritten++
      }
    }
    return rewritten
  }

  listOwnership(filter?: { nasId?: string; userId?: string; path?: string }): NasOwnershipRecord[] {
    return this.ownershipCollection().find((item) => {
      if (filter?.nasId && item.nasId !== filter.nasId) return false
      if (filter?.userId && item.userId !== filter.userId) return false
      if (filter?.path) {
        try {
          return item.path === normalizePath(filter.path)
        } catch {
          return false
        }
      }
      return true
    })
  }

  /** Pour check : les propriétés détenues par l'utilisateur demandeur sur ces chemins (correspondance de chemin exact, identité résolue doublement plateforme/DingTalk). */
  private ownedPathsFor(nasIdInput: string, rawUserId: string, paths: string[]): string[] {
    const user = this.resolveUser(rawUserId)
    if (!user) return []
    const nas = this.nasDescriptor(nasIdInput)
    const nasId = nas?.id ?? nasIdInput
    const wanted = new Set(paths.map((p) => { try { return normalizePath(p) } catch { return '' } }).filter(Boolean))
    if (wanted.size === 0) return []
    return this.ownershipCollection().find((item) => item.nasId === nasId && item.userId === user.id && wanted.has(item.path)).map((item) => item.path)
  }

  // -- Règles -----------------------------------------------------------------

  getRules(): AuthzRulesRecord {
    const existing = this.rulesCollection().get('singleton')
    if (existing) return existing
    return this.rulesCollection().insert({
      id: 'singleton',
      version: 1,
      tenantId: 't_default',
      exceptions: [],
      cGroups: [],
      externalReadPaths: [],
      observeOnly: true,
      degradeAllToReadonly: false,
      shareLinkPolicy: { maxTtlSec: 2592000, allowPermanent: false, permanentPermission: 'nas.authz.write' },
    })
  }

  /**
   * Met à jour les règles (verrou optimiste) : ifVersion doit égaler le version courant, sinon jette RulesVersionConflictError.
   * cGroups accepte les références par nom de groupe dynamique (comme l'import, supprimant le couplage d'IDs entre déploiements ; un nom irrésoluble = erreur directe).
   * Le changement tombe dans l'audit (changeLog de l'appelant complété par la couche REST) ; la variation des références aux groupes C réécrit la marque du groupe iam (couplage drift).
   */
  updateRules(patch: {
    matrixOverrides?: Partial<Record<AuthzRole, Partial<Record<AuthzOp, boolean>>>>
    exceptions?: AuthzException[]
    cGroups?: string[]
    externalReadPaths?: Array<{ nasId: string; path: string }>
    observeOnly?: boolean
    degradeAllToReadonly?: boolean
    shareLinkPolicy?: ShareLinkPolicy
  }, ifVersion: number, actor: string): AuthzRulesRecord {
    const current = this.getRules()
    if (typeof ifVersion !== 'number' || ifVersion !== current.version) {
      throw new RulesVersionConflictError(current.version, ifVersion)
    }
    let cGroups = current.cGroups
    if (patch.cGroups !== undefined) {
      const { ids, unresolved } = this.resolveCGroupNames(patch.cGroups)
      if (unresolved.length > 0) throw new Error(t('C 关联动态用户组不存在：{names}（请先在组织账号创建同名动态组）', { names: unresolved.join('、') }))
      cGroups = ids
    }
    const next: AuthzRulesRecord = {
      ...current,
      ...(patch.matrixOverrides !== undefined ? { matrixOverrides: patch.matrixOverrides } : {}),
      ...(patch.exceptions !== undefined ? { exceptions: this.normalizeExceptions(patch.exceptions, current, actor) } : {}),
      cGroups,
      ...(patch.externalReadPaths !== undefined ? { externalReadPaths: patch.externalReadPaths } : {}),
      ...(patch.observeOnly !== undefined ? { observeOnly: patch.observeOnly } : {}),
      ...(patch.degradeAllToReadonly !== undefined ? { degradeAllToReadonly: patch.degradeAllToReadonly } : {}),
      ...(patch.shareLinkPolicy !== undefined ? { shareLinkPolicy: patch.shareLinkPolicy } : {}),
      updatedBy: actor,
    }
    next.version = current.version + 1
    this.syncCGroupFlags(next.cGroups)
    const saved = this.rulesCollection().update('singleton', next)
    this.ctx.platformBus.emit('nas.authz.rulesChanged', { version: saved.version, actor })
    return saved
  }

  /**
   * Import de graines (idempotent) : instantané de règles équivalent à hermes_nas_rbac_rules.json.
   * cGroups prend en charge la résolution par nom de groupe dynamique ; contenu identique aux règles courantes = pas de montée de version (idempotent).
   */
  importRules(seed: {
    matrixOverrides?: Partial<Record<AuthzRole, Partial<Record<AuthzOp, boolean>>>>
    exceptions?: Array<Partial<AuthzException> & { effect: 'allow' | 'deny'; nasId: string; path: string; ops: AuthzOp[] }>
    cGroups?: string[]
    externalReadPaths?: Array<{ nasId: string; path: string }>
    observeOnly?: boolean
    degradeAllToReadonly?: boolean
  }, actor: string): { changed: boolean; version: number; unresolvedGroups: string[] } {
    const current = this.getRules()
    const { ids: groupIds, unresolved } = this.resolveCGroupNames(seed.cGroups ?? [])
    const mergedExceptions = seed.exceptions !== undefined
      ? this.normalizeExceptions(seed.exceptions.map((exception) => ({
          ...exception,
          id: exception.id ?? `exc_${newId('e').slice(4)}`,
        } as AuthzException)), current, actor)
      : current.exceptions
    const candidate = {
      matrixOverrides: seed.matrixOverrides ?? current.matrixOverrides ?? {},
      exceptions: mergedExceptions,
      cGroups: seed.cGroups !== undefined ? groupIds : current.cGroups,
      externalReadPaths: seed.externalReadPaths ?? current.externalReadPaths,
      observeOnly: seed.observeOnly ?? current.observeOnly,
      degradeAllToReadonly: seed.degradeAllToReadonly ?? current.degradeAllToReadonly,
    }
    const unchanged = JSON.stringify(candidate.matrixOverrides ?? {}) === JSON.stringify(current.matrixOverrides ?? {})
      && JSON.stringify(candidate.exceptions) === JSON.stringify(current.exceptions)
      && JSON.stringify(candidate.cGroups) === JSON.stringify(current.cGroups)
      && JSON.stringify(candidate.externalReadPaths) === JSON.stringify(current.externalReadPaths)
      && candidate.observeOnly === current.observeOnly
      && candidate.degradeAllToReadonly === current.degradeAllToReadonly
    if (unchanged) return { changed: false, version: current.version, unresolvedGroups: unresolved }
    const saved = this.updateRules(candidate, current.version, actor)
    return { changed: true, version: saved.version, unresolvedGroups: unresolved }
  }

  /** Ajoute une exception (produit d'approbation share / autorisation manuelle d'exploitation), montée de version automatique. */
  addException(exception: Omit<AuthzException, 'id' | 'createdAt'> & { id?: string }, actor: string): AuthzException {
    const current = this.getRules()
    const record: AuthzException = {
      ...exception,
      id: exception.id ?? `exc_${newId('e').slice(4)}`,
      createdAt: new Date().toISOString(),
    }
    this.updateRules({ exceptions: [...current.exceptions, record] }, current.version, actor)
    return record
  }

  listExceptions(): AuthzException[] {
    return this.getRules().exceptions
  }

  // -- Jugement -----------------------------------------------------------------

  /**
   * Jugement en cinq étapes (entrée) : résolution d'identité (userId plateforme / recherche inverse userid DingTalk) → assemblage des données → moteur de fonctions pures → trace.
   * fail-closed : tout échec de prise de données (utilisateur inexistant/NAS inexistant/périmètre non atteint) produit un deny motivé.
   */
  check(input: { nasId: string; userId: string; paths: string[]; op: AuthzOp; override?: boolean; caller?: string }): EngineDecision & { userName?: string; nasName?: string } {
    const caller = input.caller ?? 'unknown'
    const op = AUTHZ_OPS.includes(input.op) ? input.op : undefined
    const rules = this.getRules()
    const paths = (Array.isArray(input.paths) ? input.paths : [input.paths]).map(String).filter(Boolean)
    const unsupportedReason = t('op.unsupported：未知操作 {op}', { op: input.op })
    const base = {
      observeOnly: rules.observeOnly,
      override: input.override === true,
      cTag: false,
      scope: [] as string[],
      reasons: [] as string[],
      perPath: [],
      decision: 'deny' as const,
    }
    if (!op) return { ...base, reasons: [unsupportedReason], perPath: paths.map((path) => ({ path, decision: 'deny' as const, reasons: [unsupportedReason] })) }
    const user = this.resolveUser(input.userId)
    const nas = this.nasDescriptor(input.nasId)
    // Le rappel de passerelle sert de nasId à l'IP NAS (elle ne connaît naturellement que l'IP) : convergence uniforme vers l'ID d'actif plateforme,
    // pour garantir que les nasId des exceptions/règles atteignent la clé (sinon l'IP littérale ≠ ID d'actif, l'autorisation explicite ne prend jamais effet).
    const canonicalNasId = nas?.id ?? input.nasId
    const orgIndex = this.orgIndex()
    const ownedPaths = this.ownedPathsFor(canonicalNasId, input.userId, paths)
    const engineUser: EngineUser | undefined = user
      ? { id: user.id, displayName: user.displayName, orgId: user.orgId, ...(user.primaryOrgId !== undefined ? { primaryOrgId: user.primaryOrgId } : {}), ...(user.accountType !== undefined ? { accountType: user.accountType } : {}), status: user.status }
      : undefined
    const decision = engineCheck(
      { userId: input.userId, nasId: canonicalNasId, paths, op, ...(input.override !== undefined ? { override: input.override } : {}) },
      {
        orgIndex,
        ...(engineUser !== undefined ? { user: engineUser } : {}),
        ...(nas !== undefined ? { nas } : {}),
        rules,
        cGroupHits: this.cGroupHits(user?.id ?? input.userId, rules.cGroups),
        ...(ownedPaths.length > 0 ? { ownedPaths: ownedPaths } : {}),
      },
    )
    const enriched = { ...decision, ...(user ? { userName: user.displayName } : {}), ...(nas?.name ? { nasName: nas.name } : {}) }
    // Expression de décision unifiée (contrat W3-T5 §11) : la conclusion du moteur enveloppée par wrapPolicyDecision prend un decisionId,
    // inscrit avec la trace de jugement existante (nas.authz.decision → nas:authzDecisions) — sans réécrire le moteur, la décision reste consultable
    const policyDecision = wrapPolicyDecision(decision.decision === 'allow', decision.reasons)
    // Trace et alerte (fire-and-forget ; tous les deny, toutes les opérations à haut risque tracés)
    const highRisk = HIGH_RISK_OPS.has(op)
    if (decision.decision === 'deny' || highRisk) {
      this.ctx.platformBus.emit('nas.authz.decision', {
        nasId: canonicalNasId, userId: user?.id ?? input.userId, ...(user ? { userName: user.displayName } : {}),
        op, paths, decision: decision.decision, ...(decision.role !== undefined ? { role: decision.role } : {}),
        scope: decision.scope, reasons: decision.reasons, ...(decision.ruleId !== undefined ? { ruleId: decision.ruleId } : {}),
        caller, override: input.override === true, observeOnly: rules.observeOnly, highRisk,
        decisionId: policyDecision.decisionId,
      } satisfies Omit<AuthzDecisionRecord, 'id' | 'createdAt' | 'updatedAt'>)
    }
    if (decision.decision === 'deny' && rules.observeOnly === false) {
      this.trackDeniedBurst(user?.id ?? input.userId, { nasId: canonicalNasId, op, paths })
      this.ctx.platformBus.emit('nas.authz.denied', {
        userId: user?.id ?? input.userId, userName: user?.displayName ?? input.userId,
        nasId: input.nasId, op, paths, reasons: decision.reasons, caller,
      })
    }
    this.pruneDecisionsIfNeeded()
    return enriched
  }

  /** Requête scope (hermes/console resserrent le périmètre d'énumération list/search ; aussi la source de données de l'instantané de repli de la passerelle). */
  scopeOf(nasId: string, userId: string): { role?: AuthzRole; special?: string; cTag: boolean; scope: string[]; matrix: Record<AuthzRole, Record<AuthzOp, boolean>>; observeOnly: boolean; degradeAllToReadonly: boolean; reasons: string[]; nasName?: string; userName?: string } {
    const rules = this.getRules()
    const user = this.resolveUser(userId)
    const nas = this.nasDescriptor(nasId)
    if (!user || !nas) {
      return {
        cTag: false, scope: [], matrix: effectiveMatrix(rules), observeOnly: rules.observeOnly,
        degradeAllToReadonly: rules.degradeAllToReadonly,
        reasons: [!user ? t('user-not-found：账号不存在或未同步') : t('nas-not-found：NAS 资产不存在')],
      }
    }
    const orgIndex = this.orgIndex()
    const engineUser: EngineUser = { id: user.id, displayName: user.displayName, orgId: user.orgId, ...(user.primaryOrgId !== undefined ? { primaryOrgId: user.primaryOrgId } : {}), ...(user.accountType !== undefined ? { accountType: user.accountType } : {}), status: user.status }
    const derived = deriveRole(engineUser, orgIndex)
    const scope = deriveScope(engineUser, nas, orgIndex)
    const reasons: string[] = []
    if (scope.via === 'none') reasons.push(t('nas.no-scope：未命中该 NAS 的接入组织锚点（{reason}）', { reason: scope.reason }))
    if (derived.special) reasons.push(t('account.special：特殊账号态 {special}', { special: derived.special }))
    return {
      ...(derived.role !== undefined ? { role: derived.role } : {}),
      ...(derived.special !== undefined ? { special: derived.special } : {}),
      cTag: this.cGroupHits(user.id, rules.cGroups).length > 0,
      scope: scope.prefixes,
      matrix: effectiveMatrix(rules),
      observeOnly: rules.observeOnly,
      degradeAllToReadonly: rules.degradeAllToReadonly,
      reasons,
      ...(nas.name ? { nasName: nas.name } : {}),
      userName: user.displayName,
    }
  }

  // -- Gouvernance : responsable vacant / réconciliation organisation-répertoire / approbation share ------------------------------

  /** Scan des responsables vacants : leaderUserIds vide (limité aux organisations portant des comptes) → événement leaderVacant + alerte. */
  scanLeaderVacancy(): Array<{ orgId: string; orgName: string }> {
    const iam = this.ctx.iam
    const withUsers = new Set(iam.users().all().map((user) => user.orgId))
    const orgIndex = this.orgIndex()
    const vacant = findVacantLeaderOrgs(orgIndex, { withUserOrgIds: withUsers })
    for (const org of vacant) {
      this.ctx.platformBus.emit('nas.authz.leaderVacant', { orgId: org.id, orgName: org.name })
      this.ctx.audit.fire({
        severity: 'info',
        title: t('组织「{name}」负责人悬空', { name: org.name }),
        message: t('leaderUserIds 为空：该部门 delete/share 按矩阵无人可执行。可在控制台「组织与账号」选中该组织 →「设置负责人」手动绑定（锁定后不被连接器同步覆盖，清空即恢复跟随同步），或在钉钉侧配置部门负责人后触发同步。'),
        resourceType: 'org',
        resourceId: org.id,
      })
    }
    return vacant.map((org) => ({ orgId: org.id, orgName: org.name }))
  }

  /** Réconciliation organisations↔répertoires (job quotidien ; aussi déclenchement manuel REST) : compare les répertoires de premier niveau et l'arbre d'organisations pour les NAS en ligne. */
  async dailyReconcile(): Promise<Array<{ nasId: string; nasName: string; findings: ReturnType<typeof reconcileOrgDirs>; error?: string }>> {
    const report: Array<{ nasId: string; nasName: string; findings: ReturnType<typeof reconcileOrgDirs>; error?: string }> = []
    const orgIndex = this.orgIndex()
    for (const nasEntity of this.ctx.resourceCore.list('nas', { status: 'online' })) {
      const nas = this.nasDescriptor(nasEntity.id)
      if (!nas) continue
      let dirNames: string[] = []
      try {
        const shares = await this.ctx.nasRegistry.listShares(nasEntity.id) as unknown
        dirNames = this.extractDirNames(shares)
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        this.ctx.logger('nasAuthz').warn(`对账：NAS ${nasEntity.name} 目录枚举失败`, error)
        report.push({ nasId: nasEntity.id, nasName: nasEntity.name, findings: [], error: message })
        continue
      }
      const findings = reconcileOrgDirs(dirNames, nas, orgIndex)
      if (findings.length > 0) {
        this.ctx.platformBus.emit('nas.authz.dirOrphan', { nasId: nasEntity.id, nasName: nasEntity.name, findings })
        this.ctx.audit.fire({
          severity: 'info',
          title: t('NAS「{name}」组织目录对账发现 {count} 处不匹配', { name: nasEntity.name, count: findings.length }),
          message: findings.map((finding) => finding.detail).join('；'),
          resourceType: 'nas',
          resourceId: nasEntity.id,
        })
      }
      report.push({ nasId: nasEntity.id, nasName: nasEntity.name, findings })
    }
    this.pruneDecisionsIfNeeded()
    return report
  }

  /**
   * Demande share (dev-plan-nas-authz §2.7) : initiée via hermes/console après refus du share d'un membre T/M,
   * le routage automatique de l'approbateur remonte la chaîne d'organisations du demandeur vers le premier responsable non vide, sinon escalade au repli resource_admin.
   */
  async requestShareApproval(input: { nasId: string; userId: string; path: string; reason?: string; requesterName?: string }): Promise<{ approvalId: string; approverSuggestion: { orgId?: string; orgName?: string; leaderUserIds: string[] }; escalated: boolean }> {
    const iam = this.ctx.iam
    const user = this.resolveUser(input.userId)
    if (!user) throw new Error(t('申请账号不存在：{id}', { id: input.userId }))
    const orgIndex = this.orgIndex()
    const nearest = nearestLeaderOrg(orgIndex, user.primaryOrgId ?? user.orgId)
    let approverSuggestion: { orgId?: string; orgName?: string; leaderUserIds: string[] } = { leaderUserIds: [] }
    let escalated = false
    let approverNameHint: string
    if (nearest) {
      approverSuggestion = { orgId: nearest.orgId, orgName: nearest.orgName, leaderUserIds: nearest.leaderUserIds }
      approverNameHint = t('自动路由：{org} 负责人', { org: nearest.orgName })
    } else {
      escalated = true
      const admins = iam.users().all().filter((candidate) => candidate.status === 'active' && candidate.roleIds.some((roleId) => iam.roles().get(roleId)?.code === 'resource_admin'))
      approverSuggestion = { leaderUserIds: admins.map((admin) => admin.id) }
      approverNameHint = t('未找到组织链负责人，升级 resource_admin 兜底（{names}）', { names: admins.map((admin) => admin.displayName).join('、') || t('暂无') })
    }
    const nas = this.ctx.resourceCore.get('nas', input.nasId)
    const approval = this.ctx.audit.createApproval({
      kind: 'nas.share',
      // WP-10/L1 (QA A-06) : L4 haut risque unifié — l'approbation exige double confirmation + marqueur de revue finale société
      riskLevel: 'high',
      title: t('NAS 分享申请：{user} → {nas} {path}', { user: user.displayName, nas: nas?.name ?? input.nasId, path: input.path }),
      payload: {
        nasId: input.nasId, path: input.path, userId: user.id, userName: user.displayName,
        ...(input.reason ? { reason: input.reason } : {}),
        approverSuggestion, escalated, approverNameHint,
      },
      requesterId: user.id,
      requesterName: input.requesterName ?? user.displayName,
    })
    return { approvalId: approval.id, approverSuggestion, escalated }
  }

  /** Enregistre l'exécuteur d'approbation share : approbation accordée → écriture d'une exception allow share valide 7 jours (motif tracé). */
  registerShareExecutor(): () => void {
    return this.ctx.audit.registerExecutor('nas.share', async (payload) => {
      const { nasId, path, userId, userName, reason } = payload as { nasId: string; path: string; userId: string; userName?: string; reason?: string }
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60_000).toISOString()
      const exception = this.addException({
        effect: 'allow', nasId, path, ops: ['share'], userIds: [userId],
        ...(expiresAt ? { expiresAt } : {}), note: reason ? t('share 审批通过：{reason}', { reason }) : t('share 审批通过'), createdBy: 'approval:nas.share',
      }, 'approval:nas.share')
      this.ctx.audit.record({
        type: 'authz', actorType: 'system', actorId: 'nasAuthz', actorName: t('NAS 数据权限'),
        action: 'nas.authz.share_granted', resourceType: 'nas', resourceId: nasId,
        resourceName: this.ctx.resourceCore.get('nas', nasId)?.name ?? nasId,
        result: 'ok', detail: t('{user} 获得 {path} 分享授权（例外 {id}，{expiresAt} 到期）', { user: userName ?? userId, path, id: exception.id, expiresAt }),
      })
      return { exceptionId: exception.id, expiresAt }
    })
  }

  // -- Assemblage interne -------------------------------------------------------------

  /** Résolution d'identité : userId plateforme prioritaire, sinon recherche inverse du userid tierce (DingTalk, etc.) dans identityLinks (source de fait). */
  private resolveUser(userId: string): { id: string; displayName: string; orgId: string; primaryOrgId?: string; accountType?: string; status: string } | undefined {
    const iam = this.ctx.iam
    const direct = iam.users().get(userId)
    if (direct) return { id: direct.id, displayName: direct.displayName, orgId: direct.orgId, ...(direct.primaryOrgId !== undefined ? { primaryOrgId: direct.primaryOrgId } : {}), ...(direct.accountType !== undefined ? { accountType: direct.accountType } : {}), status: direct.status }
    const link = iam.identityLinks().findOne((item) => item.providerUserId === userId)
    if (!link) return undefined
    const user = iam.users().get(link.userId)
    if (!user) return undefined
    return { id: user.id, displayName: user.displayName, orgId: user.orgId, ...(user.primaryOrgId !== undefined ? { primaryOrgId: user.primaryOrgId } : {}), ...(user.accountType !== undefined ? { accountType: user.accountType } : {}), status: user.status }
  }

  private orgIndex(): OrgIndex {
    const iam = this.ctx.iam
    return buildOrgIndex(iam.orgs().all().map((org) => ({ id: org.id, name: org.name, parentId: org.parentId, leaderUserIds: iam.leadersOf(org.id) })))
  }

  /** Descripteur NAS pour le moteur : rootPath/orgRoot/orgPathOverrides (attributs du groupe access ; la table de correspondance est texte ou objet JSON).
   *  nasId admet deux formes : ID d'actif plateforme, ou IP NAS naturellement détenue côté passerelle (recherche inverse par attrs.nasIp). */
  private nasDescriptor(nasId: string): EngineNas | undefined {
    let entity = this.ctx.resourceCore.get('nas', nasId)
    if (!entity && /\d+(\.\d+){3}$/.test(nasId.trim())) {
      entity = this.ctx.resourceCore.list('nas').find((candidate) => String(candidate.attrs['nasIp'] ?? '') === nasId.trim())
    }
    if (!entity) return undefined
    const rawOverrides = entity.attrs['orgPathOverrides']
    let overrides: Record<string, string> | undefined
    if (typeof rawOverrides === 'string' && rawOverrides.trim()) {
      try {
        const parsed = JSON.parse(rawOverrides)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) overrides = Object.fromEntries(Object.entries(parsed).map(([key, value]) => [key, String(value)]))
      } catch {
        throw new Error(t('NAS「{name}」orgPathOverrides 不是合法 JSON', { name: entity.name }))
      }
    } else if (rawOverrides && typeof rawOverrides === 'object' && !Array.isArray(rawOverrides)) {
      overrides = Object.fromEntries(Object.entries(rawOverrides as Record<string, unknown>).map(([key, value]) => [key, String(value)]))
    }
    return {
      id: entity.id,
      name: entity.name,
      rootPath: String(entity.attrs['rootPath'] ?? '/'),
      ...(entity.attrs['orgRoot'] !== undefined && String(entity.attrs['orgRoot']).trim() !== '' ? { orgRoot: String(entity.attrs['orgRoot']).trim() } : {}),
      ...(overrides !== undefined ? { orgPathOverrides: overrides } : {}),
    }
  }

  private cGroupHits(userId: string, cGroups: string[]): string[] {
    if (cGroups.length === 0) return []
    const iam = this.ctx.iam
    return cGroups.filter((groupId) => {
      try {
        return iam.resolveGroupMembers(groupId).some((member) => member.id === userId)
      } catch {
        return false
      }
    })
  }

  private trackDeniedBurst(userId: string, context: { nasId: string; op: AuthzOp; paths: string[] }): void {
    const now = Date.now()
    const times = (this.denyWindows.get(userId) ?? []).filter((time) => now - time < DENIED_ALERT_WINDOW_MS)
    times.push(now)
    this.denyWindows.set(userId, times)
    if (times.length > DENIED_ALERT_THRESHOLD) {
            // evaluateAlerts lit uniformément context.value pour une métrique personnalisée (count fournisynchroneement pour faciliter le libellé d'alerte)
      this.ctx.audit.evaluateAlerts('nas_authz_denied', { value: times.length, count: times.length, userId, ...context, resourceType: 'nas', resourceId: context.nasId })
    }
  }

  /** Politique de conservation des traces : enregistrements ordinaires nettoyés glissamment à 90 jours ; delete/share/admin à haut risque conservés à vie. Throttle horaire. */
  private pruneDecisionsIfNeeded(): void {
    const now = Date.now()
    if (now - this.lastDecisionPruneAt < 60 * 60_000) return
    this.lastDecisionPruneAt = now
    try {
      const cutoff = new Date(now - DECISION_RETENTION_DAYS * 24 * 60 * 60_000).toISOString()
      for (const record of this.decisions().find((item) => !item.highRisk && item.createdAt < cutoff)) {
        this.decisions().remove(record.id)
      }
    } catch (error) {
      this.ctx.logger('nasAuthz').warn('判定留痕清理失败', error)
    }
  }

  private normalizeExceptions(exceptions: AuthzException[], current: AuthzRulesRecord, actor: string): AuthzException[] {
    for (const exception of exceptions) {
      if (!exception.effect || !['allow', 'deny'].includes(exception.effect)) throw new Error(t('例外 effect 非法：{value}', { value: String(exception.effect) }))
      if (!exception.nasId) throw new Error(t('例外必须指定 nasId'))
      if (!exception.path) throw new Error(t('例外必须指定 path'))
      if (!Array.isArray(exception.ops) || exception.ops.length === 0 || exception.ops.some((op) => !AUTHZ_OPS.includes(op))) {
        throw new Error(t('例外 ops 非法：{value}', { value: JSON.stringify(exception.ops) }))
      }
      if (exception.expiresAt !== undefined && Number.isNaN(Date.parse(exception.expiresAt))) throw new Error(t('例外 expiresAt 非法：{value}', { value: String(exception.expiresAt) }))
    }
    // Sémantique de fusion : même id écrasé, ajouts apposés, les exceptions existantes absentes du patch conservées (import idempotent par comparaison de contenu)
    const byId = new Map(current.exceptions.map((exception) => [exception.id, exception]))
    for (const exception of exceptions) {
      byId.set(exception.id, { ...byId.get(exception.id), ...exception, createdBy: byId.get(exception.id)?.createdBy ?? actor })
    }
    return [...byId.values()]
  }

  /** Résolution nom de groupe C → id de groupe (référence par nom à l'import/mise à jour, supprimant le couplage d'IDs entre déploiements). */
  private resolveCGroupNames(names: string[]): { ids: string[]; unresolved: string[] } {
    const iam = this.ctx.iam
    const ids: string[] = []
    const unresolved: string[] = []
    for (const nameOrId of names) {
      const byId = iam.groups().get(nameOrId)
      if (byId) {
        ids.push(byId.id)
        continue
      }
      const byName = iam.groups().findOne((group) => group.name === nameOrId)
      if (byName) {
        ids.push(byName.id)
        continue
      }
      unresolved.push(nameOrId)
    }
    return { ids, unresolved }
  }

  /** Réécrit la marque authzRoleC du groupe dynamique (couplage d'alerte drift : toute dérive d'un groupe associé C alerte). */
  private syncCGroupFlags(cGroups: string[]): void {
    const iam = this.ctx.iam
    const referenced = new Set(cGroups)
    for (const group of iam.groups().all()) {
      const shouldBeMarked = referenced.has(group.id)
      if (shouldBeMarked && group.authzRoleC !== true) iam.groups().update(group.id, { authzRoleC: true })
      if (!shouldBeMarked && group.authzRoleC === true) iam.groups().update(group.id, { authzRoleC: false })
    }
  }

  /** Extrait les noms de répertoires de premier niveau de la réponse fs_list_shares de la passerelle (tolérant : tableau de blocs content / texte JSON / objet). */
  private extractDirNames(payload: unknown): string[] {
    const collect = (input: unknown): Array<{ name?: string; path?: string }> => {
      if (typeof input === 'string') {
        try { return collect(JSON.parse(input)) } catch { return [] }
      }
      if (Array.isArray(input)) return input.flatMap((item) => collect(item))
      if (input && typeof input === 'object') {
        const record = input as Record<string, unknown>
        if (Array.isArray(record['shares'])) return record['shares'] as Array<{ name?: string }>
        if (Array.isArray(record['files'])) return record['files'] as Array<{ name?: string }>
        return [record]
      }
      return []
    }
    return collect(payload)
      .map((item) => String(item?.name ?? item?.path ?? '').replace(/^.*\//, '').trim())
      .filter(Boolean)
  }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    nasAuthz: NasAuthzService
  }
}

export { WRITE_OPS, HIGH_RISK_OPS } from './authz/engine.ts'
export type { AuthzOp, AuthzRole, EngineDecision } from './authz/engine.ts'
