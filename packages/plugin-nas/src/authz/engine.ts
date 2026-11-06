/**
 * Moteur de jugement des permissions de données NAS (module de fonctions pures, contrainte de couches dev-plan-nas-authz §2.1).
 *
 * - Ne dépend pas du conteneur de Service, ne fait aucun IO : en entrée, des instantanés déjà pris (arbre d'organisations / utilisateur / actif NAS / règles),
 *   en sortie un résultat de jugement (avec reasons). La couche Service (../authz.ts) ne fait que l'assemblage des données et l'inscription des traces.
 * - L'ordre de jugement est un portage de la sémantique de saas-permission-service (service B) : seul le sémantique est porté, pas le déploiement :
 *   ① règles spéciales de compte (externe/suspect/racine/sans groupe/poste cumul lecture seule)
 *   ② deny explicite au niveau ressource (nasId+chemin avec joker de queue, userIds possible)
 *   ③ allow explicite au niveau ressource (liste blanche inter-domaines C, autorisation temporaire, expiresAt possible)
 *      ③b propriété de fichier (ajout 2026-09-17) : l'uploadeur tout-puissant par défaut sur ses documents (admin excepté, le deny explicite reste prioritaire)
 *   ④ matrice de rôles MATRIX[role][op] × frontière de périmètre
 *   ⑤ deny par défaut
 * - Le selftest teste ce module directement (contrainte de couches du moteur O8).
 */
import { t } from '../../../platform-i18n/src/index.ts'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Sept classes d'opérations (dimension matrice d'opérations de l'annexe 4 ; share/admin n'existent pas sur la face outils de la passerelle, toujours deny côté passerelle). */
export type AuthzOp = 'read' | 'download' | 'write' | 'modify' | 'delete' | 'share' | 'admin'

export const AUTHZ_OPS: AuthzOp[] = ['read', 'download', 'write', 'modify', 'delete', 'share', 'admin']

/** Opérations d'écriture (sémantique readonly = read/download passants, écritures refusées). */
export const WRITE_OPS: ReadonlySet<AuthzOp> = new Set<AuthzOp>(['write', 'modify', 'delete', 'share', 'admin'])

/** Opérations à haut risque (traces de jugement conservées à vie ; enregistrements ordinaires nettoyés glissamment à 90 jours). */
export const HIGH_RISK_OPS: ReadonlySet<AuthzOp> = new Set<AuthzOp>(['delete', 'share', 'admin'])

/** Rôle principal (C est une marque additive, ne participe pas à l'ordre des rôles principaux). */
export type AuthzRole = 'P' | 'D' | 'T' | 'M'

export interface EngineOrgNode {
  id: string
  name: string
  parentId: string | null
  /** Profondeur dans l'arbre d'organisations : racine=1 (niveau plateforme), 2=niveau département, ≥3=niveau groupe fonctionnel/équipe. */
  depth: number
  leaderUserIds: string[]
}

/** Index d'instantané de l'arbre d'organisations : orgId → nœud (depth inclus, précalculé par buildOrgIndex). */
export type OrgIndex = Map<string, EngineOrgNode>

export interface EngineUser {
  id: string
  displayName: string
  /** Organisation d'attache ; différente de primaryOrgId, le sous-arbre orgId est traité comme cumul en lecture seule. */
  orgId: string
  /** Organisation de rattachement principale (sémantique de cumul) ; par défaut la plus profonde de la chaîne (mono-rattachement = orgId). */
  primaryOrgId?: string
  accountType?: 'internal' | 'external' | 'suspended-review'
  status?: string
}

export interface EngineNas {
  id: string
  name?: string
  /** Chemin racine autorisé au niveau actif (attribut rootPath actuel). */
  rootPath: string
  /** Ancre d'organisation d'accès : nom d'organisation de niveau plateforme ou orgId (ancre de dérivation du périmètre de permissions de données). */
  orgRoot?: string
  /** Correspondance explicite organisation → préfixe de répertoire (prioritaire sur la dérivation par nom ; renommage/fusion d'organisation sans dérive). */
  orgPathOverrides?: Record<string, string>
}

/** Exception au niveau ressource : allow/deny explicite, resserrable par personne, expirable (sémantique service B). */
export interface AuthzException {
  id: string
  effect: 'allow' | 'deny'
  nasId: string
  /** Préfixe de chemin ; `/*` en queue joker du sous-arbre, `*` joker total. */
  path: string
  ops: AuthzOp[]
  /** Défaut = s'applique à tous les utilisateurs (exception au niveau ressource par chemin). */
  userIds?: string[]
  /** Temps ISO ; expirée = sans effet (l'ordre de jugement reste en place, simplement plus atteint). */
  expiresAt?: string
  note?: string
  createdBy?: string
  createdAt?: string
}

/** Instantané de configuration de règles (projection visible du moteur sur le singleton nas:authzRules). */
export interface AuthzRulesSnapshot {
  version: number
  /** Éléments de couverture de matrice : true = relâché en allow, false = resserré en deny (rustine sur la matrice intégrée). */
  matrixOverrides?: Partial<Record<AuthzRole, Partial<Record<AuthzOp, boolean>>>>
  exceptions: AuthzException[]
  /** Ensemble d'ids de groupes d'utilisateurs dynamiques associés au rôle C (pas de seconde liste de personnel). */
  cGroups: string[]
  /** Répertoires en liste blanche des comptes externes (périmètre lecture seule external). */
  externalReadPaths: Array<{ nasId: string; path: string }>
  /** Mode observation : résultat de jugement inchangé, simple marque (le deny de la passerelle alerte sans bloquer). */
  observeOnly: boolean
  /** Rétrogradation intégrale en lecture seule : tout allow traité comme readonly (gradation G3). */
  degradeAllToReadonly: boolean
}

export interface EngineCheckInput {
  userId: string
  nasId: string
  paths: string[]
  op: AuthzOp
  /** Effraction : passe le jugement P et force la trace (doit détenir nas.authz.write, la couche Service vérifie puis transmet). */
  override?: boolean
  now?: string
}

export interface EnginePathVerdict {
  path: string
  decision: 'allow' | 'deny'
  reasons: string[]
}

export interface EngineDecision {
  decision: 'allow' | 'deny'
  /** Rôle principal (P/D/T/M) ; défaut pour un compte spécial sans rôle principal. */
  role?: AuthzRole
  /** Si la marque additive C est posée (membre d'un groupe d'utilisateurs dynamique). */
  cTag: boolean
  /** Liste des préfixes de périmètre au jugement (référentiel plateforme, réutilisé par la requête scope et l'instantané de repli). */
  scope: string[]
  reasons: string[]
  /** Ids des exceptions explicites atteintes (allow/deny tous renseignés, pour l'attribution d'audit). */
  ruleId?: string
  perPath: EnginePathVerdict[]
  observeOnly: boolean
  override: boolean
}

// ---------------------------------------------------------------------------
// Matrice intégrée et fonctions utilitaires
// ---------------------------------------------------------------------------

/**
 * Matrice d'opérations intégrée (valeurs par défaut de l'annexe 4) :
 * - P responsable plateforme : tout passe ;
 * - D responsable de département : tous droits sur le sous-arbre du département (admin est le point de permission de gestion de règles de la plateforme, matrice toujours deny, passe par le point de permission plutôt que le répertoire) ;
 * - T responsable d'équipe : écrit sans supprimer (delete/share passent par l'exception d'approbation) ;
 * - M membre ordinaire : lit et écrit les fichiers, sans modifier la structure (rename/copy/compress), sans supprimer ;
 * - C marque additive : lecture seule inter-domaines (réalisée dans check comme extension du périmètre read/download).
 */
export const MATRIX_DEFAULT: Record<AuthzRole, Record<AuthzOp, boolean>> = {
  P: { read: true, download: true, write: true, modify: true, delete: true, share: true, admin: true },
  D: { read: true, download: true, write: true, modify: true, delete: true, share: true, admin: false },
  T: { read: true, download: true, write: true, modify: true, delete: false, share: false, admin: false },
  M: { read: true, download: true, write: true, modify: false, delete: false, share: false, admin: false },
}

/** Fusionne les couvertures de matrice (les règles resserrent/relâchent des cases ; admin exige toujours le point de permission de la plateforme, couvrir sa matrice est sans effet côté passerelle). */
export function effectiveMatrix(rules: Pick<AuthzRulesSnapshot, 'matrixOverrides'>): Record<AuthzRole, Record<AuthzOp, boolean>> {
  const matrix = structuredClone(MATRIX_DEFAULT)
  const overrides = rules.matrixOverrides ?? {}
  for (const role of Object.keys(overrides) as AuthzRole[]) {
    for (const op of Object.keys(overrides[role] ?? {}) as AuthzOp[]) {
      const value = overrides[role]?.[op]
      if (typeof value === 'boolean') matrix[role][op] = value
    }
  }
  return matrix
}

/** Normalisation de chemin : absolutisation, retrait des barres de queue, `..` interdit ; racine = '' (référentiel de comparaison interne, la couche d'affichage rajoute `/`). */
export function normalizePath(path: string): string {
  const normalized = `/${path}`.replace(/\\/g, '/').replace(/\/+$/, '')
  const segments = normalized.split('/').filter(Boolean)
  if (segments.some((segment) => segment === '..')) throw new Error(t('路径不允许包含 ..'))
  return `/${segments.join('/')}`
}

/** Atteinte de préfixe de périmètre : path === prefix ou path dans le sous-arbre de prefix. */
export function pathWithin(path: string, prefix: string): boolean {
  const p = normalizePath(path)
  const f = normalizePath(prefix)
  if (f === '/') return true
  return p === f || p.startsWith(`${f}/`)
}

/** Atteinte de joker de chemin d'exception : `*` tout ; queue `/*` sous-arbre ; le reste préfixe exact (sémantique de sous-arbre). */
export function matchExceptionPath(exceptionPath: string, path: string): boolean {
  const trimmed = exceptionPath.trim()
  if (trimmed === '*') return true
  if (trimmed.endsWith('/*')) return pathWithin(path, trimmed.slice(0, -2))
  return pathWithin(path, trimmed)
}

/** Construction d'instantané de l'arbre d'organisations : calcule depth depuis un tableau plat d'OrgRecord (nœud orphelin replié à profondeur 1). */
export function buildOrgIndex(records: Array<{ id: string; name: string; parentId: string | null; leaderUserIds?: string[] }>): OrgIndex {
  const index: OrgIndex = new Map()
  for (const record of records) {
    index.set(record.id, { id: record.id, name: record.name, parentId: record.parentId, depth: 0, leaderUserIds: record.leaderUserIds ?? [] })
  }
  for (const node of index.values()) {
    let cursor: string | null = node.id
    let depth = 0
    const guard = new Set<string>()
    while (cursor && index.has(cursor) && !guard.has(cursor)) {
      guard.add(cursor)
      depth++
      cursor = index.get(cursor)!.parentId
    }
    node.depth = depth || 1
  }
  return index
}

/** Chaîne d'ancêtres d'organisation (soi → racine, référentiel plateforme). */
export function orgChain(orgIndex: OrgIndex, orgId: string): EngineOrgNode[] {
  const chain: EngineOrgNode[] = []
  let cursor: string | null = orgId
  const guard = new Set<string>()
  while (cursor && orgIndex.has(cursor) && !guard.has(cursor)) {
    guard.add(cursor)
    const node = orgIndex.get(cursor)!
    chain.push(node)
    cursor = node.parentId
  }
  return chain
}

// ---------------------------------------------------------------------------
// Dérivation des rôles (annexe 3, fonctions pures, sans configuration de liste de personnel)
// ---------------------------------------------------------------------------

export interface DerivedRole {
  role?: AuthzRole
  /** Qualité de responsable sur la chaîne de rattachement principal (sémantique co-leader multi-responsables : une personne peut être à la fois D + T du sous-arbre, le rôle principal prend le plus haut). */
  leaderOf: Array<{ orgId: string; depth: number; role: AuthzRole; coLeader: boolean }>
  /** Qualité de responsable inter-branches (une personne, plusieurs rôles) : responsable de département hors de la chaîne de rattachement principal, périmètre et matrice appliqués indépendamment au sous-arbre dirigé (leaderScopes). */
  leaderOfElsewhere: Array<{ orgId: string; orgName: string; depth: number; role: AuthzRole; coLeader: boolean }>
  /** Organisation de rattachement principale (ancre de la sémantique de cumul). */
  primaryOrg?: EngineOrgNode
  /** Organisation d'attache (orgId ; différente du rattachement principal = cumul). */
  attachedOrg?: EngineOrgNode
  secondaryAffiliation: boolean
  special?: 'external' | 'suspended-review' | 'root-no-role' | 'dept-root-readonly'
}

/**
 * Dérivation des rôles :
 * - P/D/T = responsable sur la chaîne de l'organisation de rattachement principal (profondeur 1/2/≥3) ; tous les responsables dérivés (reasons marqués co-leader) ;
 * - M = membre non responsable monté sous une organisation de profondeur ≥3 ;
 * - monté à l'organisation racine (profondeur=1, non responsable) → special 'root-no-role' (deny total) ;
 * - sans équipe (monté à une racine de département de profondeur=2, non responsable) → special 'dept-root-readonly' (racine de département en lecture seule) ;
 * - external / suspended-review : voir special ;
 * - rattachement principal par défaut : le plus profond de la chaîne (orgId ≠ primaryOrgId = cumul).
 */
export function deriveRole(user: EngineUser, orgIndex: OrgIndex): DerivedRole {
  const result: DerivedRole = { leaderOf: [], leaderOfElsewhere: [], secondaryAffiliation: false }
  if (user.accountType === 'external') result.special = 'external'
  if (user.accountType === 'suspended-review') result.special = 'suspended-review'
  const attached = orgIndex.get(user.orgId)
  const primary = user.primaryOrgId ? orgIndex.get(user.primaryOrgId) : attached
  if (!attached || !primary) return result
  result.attachedOrg = attached
  result.primaryOrg = primary
  result.secondaryAffiliation = attached.id !== primary.id

  const primaryChain = orgChain(orgIndex, primary.id)
  // Qualité de responsable sur la chaîne de rattachement principal (tous les niveaux de la chaîne, tous les responsables dérivés)
  for (const node of primaryChain) {
    const coLeader = node.leaderUserIds.length > 1 && node.leaderUserIds.includes(user.id)
    if (node.leaderUserIds.includes(user.id)) {
      const role: AuthzRole = node.depth === 1 ? 'P' : node.depth === 2 ? 'D' : 'T'
      result.leaderOf.push({ orgId: node.id, depth: node.depth, role, coLeader })
    }
  }
  // Qualité de responsable inter-branches (une personne, plusieurs rôles, multi-attaches) : non fusionnée dans la dérivation du rôle principal (pour ne pas surélever le palier de matrice du rattachement),
  // check applique la matrice indépendamment par sous-arbre de département dirigé via leaderScopes — les permissions multi-identités coexistent sans conflit.
  for (const node of orgIndex.values()) {
    if (!node.leaderUserIds.includes(user.id)) continue
    if (primaryChain.some((onChain) => onChain.id === node.id)) continue
    const role: AuthzRole = node.depth === 1 ? 'P' : node.depth === 2 ? 'D' : 'T'
    result.leaderOfElsewhere.push({ orgId: node.id, orgName: node.name, depth: node.depth, role, coLeader: node.leaderUserIds.length > 1 })
  }
  // Le rôle principal prend le rôle de responsable le plus haut de la chaîne ; sans qualité de responsable, dérivation selon la profondeur de montage
  if (result.leaderOf.length > 0) {
    result.role = result.leaderOf.reduce((best, item) => (item.role === 'P' || (best !== 'P' && item.role === 'D') ? item.role : best), result.leaderOf[0]!.role)
  } else if (primary.depth >= 3) {
    result.role = 'M'
  } else if (primary.depth === 1) {
    result.special = 'root-no-role'
  } else {
    result.special = 'dept-root-readonly'
  }
  return result
}

// ---------------------------------------------------------------------------
// Dérivation du périmètre (table de correspondance prioritaire, dérivation par nom par défaut, supprimant la fragilité du point unique « chemin = permission »)
// ---------------------------------------------------------------------------

export interface DerivedScope {
  /** Organisation ancre atteinte (nœud correspondant à orgRoot). */
  anchor?: EngineOrgNode
  /** Liste des préfixes de périmètre (chemins absolus au référentiel plateforme, incluant le resserrement rootPath du NAS). */
  prefixes: string[]
  /** Mode de résolution : override = table de correspondance atteinte ; name = dérivation par nom ; none = non atteint (deny intégral sur ce NAS). */
  via: 'override' | 'name' | 'none'
  reason?: string
}

/**
 * Dérivation du périmètre (dev-plan-nas-authz §2.1 révisé) :
 * 1. la chaîne d'ancêtres (ancre → racine) atteint `orgPathOverrides[orgId]` → préfixe de correspondance (renommage/fusion d'organisation sans dérive) ;
 * 2. sinon dérivation par nom : la chaîne atteint `orgRoot` (orgId ou nom d'organisation) → sous-arbre de répertoires = rootPath + concaténation des noms depuis l'ancre ;
 * 3. non atteint → none (deny intégral sur ce NAS).
 */
export function deriveScope(user: EngineUser, nas: EngineNas, orgIndex: OrgIndex): DerivedScope {
  const root = normalizePath(nas.rootPath || '/')
  const primary = orgIndex.get(user.primaryOrgId ?? user.orgId) ?? orgIndex.get(user.orgId)
  if (!primary) return { prefixes: [], via: 'none', reason: 'user-org-not-found' }
  // Alignement rôle et périmètre : si, sur la chaîne de rattachement principal, la personne dirige un département (plus superficiel) — le département principal d'un responsable monté dans une équipe subordonnée est la norme
  // (DingTalk dept_id_list[0] est le département principal, la fonction de direction est au département supérieur) — l'ancre de périmètre remonte au plus haut département dirigé,
  // sinon le rôle D/P tomberait dans un périmètre subordonné plus étroit et le passage de la matrice serait lettre morte.
  const primaryChain = orgChain(orgIndex, primary.id)
  const ledAnchor = primaryChain
    .filter((node) => node.leaderUserIds.includes(user.id))
    .reduce<EngineOrgNode | undefined>((best, node) => (!best || node.depth < best.depth ? node : best), undefined)
  const anchor = ledAnchor ?? primary
  const chain = orgChain(orgIndex, anchor.id)
  const overrides = nas.orgPathOverrides ?? {}
  // ① table de correspondance prioritaire : de l'ancre vers la racine, la première correspondance explicite (la correspondance de l'ancre elle-même a la plus haute priorité)
  for (const node of chain) {
    const mapped = overrides[node.id]
    if (mapped) {
      const below = chain.slice(0, chain.indexOf(node)).reverse().map((item) => item.name)
      const prefix = joinPaths(root, [mapped.trim(), ...below].filter(Boolean).join('/'))
      return { anchor: node, prefixes: [prefix], via: 'override' }
    }
  }
  // ② dérivation par nom : recherche d'orgRoot dans la chaîne (correspondance exacte orgId prioritaire, puis nom d'organisation ; prise de l'atteinte la plus superficielle = la plus proche du niveau plateforme)
  if (nas.orgRoot) {
    const byId = chain.find((node) => node.id === nas.orgRoot)
    const byName = chain.find((node) => node.name === nas.orgRoot)
    const hit = byId ?? byName
    if (hit) {
      // L'organisation ancre elle-même (le responsable plateforme P dépend directement de l'ancre) : le périmètre est la racine d'autorisation entière du NAS
      const below = chain.slice(0, chain.indexOf(hit)).reverse().map((item) => item.name)
      const prefix = hit.id === anchor.id ? root : joinPaths(root, [hit.name, ...below].join('/'))
      return { anchor: hit, prefixes: [prefix], via: 'name' }
    }
  }
  // ③ aucune ancre atteinte → deny intégral sur ce NAS
  return { prefixes: [], via: 'none', reason: nas.orgRoot ? 'org-root-not-on-chain' : 'nas-org-root-not-configured' }
}

function joinPaths(root: string, suffix: string): string {
  const normalizedSuffix = `/${suffix}`.replace(/\\/g, '/').replace(/\/+$/, '')
  const segments = normalizedSuffix.split('/').filter(Boolean)
  if (root === '/' || root === '') return `/${segments.join('/')}`
  return `${root.replace(/\/+$/, '')}/${segments.join('/')}`
}

// ---------------------------------------------------------------------------
// Ordre de jugement (portage de la sémantique du service B, chaque étape produit des reasons)
// ---------------------------------------------------------------------------

export interface EngineCheckContext {
  orgIndex: OrgIndex
  user?: EngineUser
  nas?: EngineNas
  rules: Pick<AuthzRulesSnapshot, 'version' | 'matrixOverrides' | 'exceptions' | 'cGroups' | 'externalReadPaths' | 'observeOnly' | 'degradeAllToReadonly'>
  /** Ids des groupes dynamiques associés C atteints (résolus par les règles côté Service puis transmis, le moteur ne fait pas d'IO). */
  cGroupHits: string[]
  /** Chemins de propriété de fichiers détenus par l'utilisateur demandeur (chemins exacts, résolus par la couche Service depuis l'enregistrement de propriété ; ajout 2026-09-17). */
  ownedPaths?: string[]
}

const OP_LABEL: Record<AuthzOp, string> = {
  read: '读取', download: '下载', write: '写入', modify: '改动', delete: '删除', share: '分享', admin: '管理',
}

/** Ordre de jugement en cinq étapes (fonction pure). Chemins multiples = décision la plus stricte (un deny quelconque = deny), reasons produits par chemin. */
export function check(input: EngineCheckInput, ctx: EngineCheckContext): EngineDecision {
  const now = input.now ?? new Date().toISOString()
  const base: EngineDecision = { decision: 'deny', cTag: false, scope: [], reasons: [], perPath: [], observeOnly: ctx.rules.observeOnly, override: input.override === true }
  const denyAll = (reasons: string[]): EngineDecision => {
    base.decision = 'deny'
    base.reasons = reasons
    base.perPath = input.paths.map((path) => ({ path, decision: 'deny' as const, reasons }))
    return base
  }

  const user = ctx.user
  if (!user) return denyAll([t('user-not-found：账号不存在或未同步')])
  if (ctx.nas === undefined) return denyAll([t('nas-not-found：NAS 资产不存在')])

  // Marque additive C (base de l'extension de périmètre de l'ordre ④)
  const cTag = ctx.rules.cGroups.some((groupId) => ctx.cGroupHits.includes(groupId))
  base.cTag = cTag
  base.scope = deriveScope(user, ctx.nas, ctx.orgIndex).prefixes

  // ① règles spéciales de compte
  const derived = deriveRole(user, ctx.orgIndex)
  base.role = derived.role
  if (derived.special === 'suspended-review') {
    return denyAll([t('account.suspended-review：账号带可疑标记已冻结判定，转人工复核（审计已留痕）')])
  }
  if (derived.special === 'external') {
    const verdicts = input.paths.map((path) => {
      const whitelisted = ctx.rules.externalReadPaths.some((entry) => entry.nasId === input.nasId && matchExceptionPath(entry.path, path))
      if (!whitelisted) return { path, decision: 'deny' as const, reasons: [t('account.external：外部账号仅白名单目录可读')] }
      if (WRITE_OPS.has(input.op)) return { path, decision: 'deny' as const, reasons: [t('account.external：外部账号只读（白名单目录）')] }
      return { path, decision: 'allow' as const, reasons: [t('account.external：白名单目录只读放行')] }
    })
    base.decision = verdicts.every((verdict) => verdict.decision === 'allow') ? 'allow' : 'deny'
    base.reasons = [...new Set(verdicts.flatMap((verdict) => verdict.reasons))]
    base.perPath = verdicts
    return finalize(base, ctx.rules, input)
  }
  if (derived.special === 'root-no-role') {
    // Monté à la racine = refus global par défaut (on pousse la personne vers département/équipe) ; l'unique sortie est l'exception allow explicite au niveau ressource accordée par l'admin —
    // l'autorisation du compte de service de la plateforme (identité liée au jeton de passerelle) sur sa zone de stockage propre passe par ce canal, l'exception intégralement tracée et auditable.
    const verdicts = input.paths.map((path) => {
      const rescue = ctx.rules.exceptions.find((exception) => exception.effect === 'allow'
        && exception.nasId === input.nasId
        && exception.ops.includes(input.op)
        && !expired(exception, now)
        && (!exception.userIds || exception.userIds.includes(user.id))
        && matchExceptionPath(exception.path, path))
      if (rescue) {
        return { path, decision: 'allow' as const, reasons: [t('exception.allow：显式授权规则 {id} 救援挂根账号（root-no-role）', { id: rescue.id }) + (rescue.note ? `（${rescue.note}）` : '')], ruleId: rescue.id }
      }
      return { path, decision: 'deny' as const, reasons: [t('org.root-no-role：挂根组织且非负责人，无数据权限（请落入部门/班组）')] }
    })
    base.decision = verdicts.every((verdict) => verdict.decision === 'allow') ? 'allow' : 'deny'
    base.reasons = [...new Set(verdicts.flatMap((verdict) => verdict.reasons))]
    base.perPath = verdicts
    return finalize(base, ctx.rules, input)
  }

  const scope = deriveScope(user, ctx.nas, ctx.orgIndex)
  // Sans équipe : racine de département en lecture seule (read/download passants sur le sous-arbre du département, écritures refusées)
  const deptRootReadonly = derived.special === 'dept-root-readonly'

  const matrix = effectiveMatrix(ctx.rules)
  const primaryRole = derived.role
  const coLeaderMarks = derived.leaderOf.filter((item) => item.coLeader).map((item) => `co-leader@${item.orgId}`)
  // Périmètre de direction inter-branches (une personne, plusieurs rôles) : le sous-arbre du département dirigé applique indépendamment la matrice selon le rôle de ce département (tous droits, pas une couche lecture seule),
  // coexistant avec les permissions du rattachement principal ; si le département dirigé n'atteint pas l'ancre de ce NAS, pas de périmètre (l'isolement inter-NAS inchangé).
  const leaderScopes = derived.leaderOfElsewhere.map((led) => ({
    ...led,
    prefixes: deriveScope({ ...user, primaryOrgId: led.orgId }, ctx.nas, ctx.orgIndex).prefixes,
  })).filter((led) => led.prefixes.length > 0)
  // Périmètre principal sans ancre atteinte = pas de refus anticipé : le périmètre de direction inter-branches peut encore atteindre (sinon seulement deny intégral) ;
  // quand tous les chemins demandés sont des documents possédés par l'utilisateur demandeur (propriété ③b), pas de refus anticipé non plus — la propriété est indépendante du périmètre d'organisation,
  // l'utilisateur muté/ancre réajustée conserve la propriété de ses documents uploadés (le deny explicite et la rétrogradation G3 restent prioritaires).
  const ownedPaths = ctx.ownedPaths ?? []
  const normalizedInputs = input.paths.map((p) => { try { return normalizePath(p) } catch { return '' } })
  const allOwned = input.op !== 'admin' && normalizedInputs.length > 0 && normalizedInputs.every((p) => ownedPaths.includes(p))
  if (scope.via === 'none' && leaderScopes.length === 0 && !allOwned) {
    return denyAll([t('nas.no-scope：未命中该 NAS 的接入组织锚点（{reason}）', { reason: scope.reason })])
  }
  base.scope = scope.via === 'none' ? [] : [...scope.prefixes]
  for (const led of leaderScopes) {
    if (!base.scope.some((prefix) => led.prefixes.includes(prefix))) base.scope = [...base.scope, ...led.prefixes]
  }
  // Périmètre du rattachement de cumul (couche lecture seule uniquement) : l'ancre bascule sur l'organisation d'attache et l'on redérive une fois
  const secondaryScope = derived.secondaryAffiliation
    ? deriveScope({ ...user, primaryOrgId: user.orgId }, ctx.nas, ctx.orgIndex)
    : undefined
  const secondaryPrefixes = secondaryScope && secondaryScope.via !== 'none' ? secondaryScope.prefixes : []
  if (secondaryPrefixes.length > 0) base.scope = [...base.scope, ...secondaryPrefixes]

  // Énumération en lecture seule de la chaîne d'ancêtres du périmètre (sémantique B ; version répertoire racine entérinée 2026-09-03, extension à toute la chaîne d'ancêtres entérinée 2026-09-17) :
  // un utilisateur ayant un périmètre quelconque sur ce NAS (principal/direction inter-branches/attache de cumul) voit passer ses opérations en lecture seule sur « les répertoires ancêtres d'un
  // quelconque préfixe de périmètre (racine NAS incluse) » (listage de répertoire/méta-infos) — sinon un utilisateur de périmètre profond ne pourrait pas descendre
  // niveau par niveau vers son répertoire dans le navigateur de fichiers (le parent de chaque pas serait hors frontière). L'incrément d'information du passage lecture seule de la chaîne d'ancêtres
  // égale celui du listage racine (expose seulement la hiérarchie des noms de répertoires, pas le contenu des sous-arbres) ; l'exception deny explicite reste prioritaire (ordre ② inchangé) ;
  // les écritures et les chemins hors périmètre de même niveau/hors frontière ne sont pas affectés ; un utilisateur sans aucun périmètre reste refusé intégralement.
  const nasRoot = normalizePath(ctx.nas!.rootPath || '/')
  const ancestorPrefixes = [
    ...(scope.via === 'none' ? [] : scope.prefixes),
    ...leaderScopes.flatMap((led) => led.prefixes),
    ...secondaryPrefixes,
  ]

  const verdicts: EnginePathVerdict[] = input.paths.map((rawPath) => {
    const path = normalizePath(rawPath)
    // ② deny explicite au niveau ressource (joker de queue, resserrable par personne)
    const denyHit = ctx.rules.exceptions.find((exception) => exception.effect === 'deny'
      && exception.nasId === input.nasId
      && exception.ops.includes(input.op)
      && !expired(exception, now)
      && (!exception.userIds || exception.userIds.includes(user.id))
      && matchExceptionPath(exception.path, path))
    if (denyHit) {
      return { path, decision: 'deny', reasons: [t('exception.deny：命中显式拒绝规则 {id}', { id: denyHit.id }) + (denyHit.note ? `（${denyHit.note}）` : '')], ruleId: denyHit.id }
    }
    // ③ allow explicite au niveau ressource (liste blanche inter-domaines C, autorisation temporaire ; expirable)
    const allowHit = ctx.rules.exceptions.find((exception) => exception.effect === 'allow'
      && exception.nasId === input.nasId
      && exception.ops.includes(input.op)
      && !expired(exception, now)
      && (!exception.userIds || exception.userIds.includes(user.id))
      && matchExceptionPath(exception.path, path))
    if (allowHit) {
      return { path, decision: 'allow', reasons: [t('exception.allow：命中显式授权规则 {id}', { id: allowHit.id }) + (allowHit.expiresAt ? `（${allowHit.expiresAt} 到期）` : '') + (allowHit.note ? `（${allowHit.note}）` : '')], ruleId: allowHit.id }
    }
    // ③b propriété de fichier (ajout 2026-09-17) : l'uploadeur tout-puissant par défaut sur ses documents (admin est un point de permission de la plateforme, ne suit pas la propriété).
    // L'enregistrement ne couvre que les chemins exacts de fichiers (pas les répertoires, pour éviter qu'un créateur de répertoire n'obtienne le droit de suppression du sous-arbre) ; le deny explicite reste prioritaire (ordre ②) ;
    // après allow, la rétrogradation intégrale en lecture seule (G3) du finalize contraint toujours.
    if (input.op !== 'admin' && ctx.ownedPaths?.includes(path)) {
      return { path, decision: 'allow', reasons: [t('owner.allow：文件上传者对自有文档默认放行「{op}」', { op: t(OP_LABEL[input.op]) })] }
    }
    // Énumération en lecture seule de la chaîne d'ancêtres du périmètre : l'ordre de jugement se place après les exceptions explicites, avant la frontière de périmètre (la racine NAS est un cas particulier de la chaîne d'ancêtres, reason réutilise root-listing)
    const onAncestorChain = ancestorPrefixes.some((prefix) => pathWithin(prefix, path))
    if (ancestorPrefixes.length > 0 && !WRITE_OPS.has(input.op) && onAncestorChain) {
      return path === nasRoot
        ? { path, decision: 'allow', reasons: [t('org.root-listing：本 NAS 作用域内用户的根目录只读列举放行')] }
        : { path, decision: 'allow', reasons: [t('org.ancestor-listing：作用域祖先目录只读列举放行（浏览逐级下钻）')] }
    }

    // ④ matrice de rôles × frontière de périmètre (périmètre principal / couche direction inter-branches / couche lecture seule cumul / couche lecture seule inter-domaines C)
    if (input.override === true) {
      return { path, decision: 'allow', reasons: [t('override：破窗放行（P 判定，强制留痕）')] }
    }
    const inPrimary = scope.prefixes.some((prefix) => pathWithin(path, prefix))
    const ledHits = leaderScopes.filter((led) => led.prefixes.some((prefix) => pathWithin(path, prefix)))
    const inSecondary = !inPrimary && ledHits.length === 0 && secondaryPrefixes.some((prefix) => pathWithin(path, prefix))
    const inCScope = cTag && pathWithin(path, ctx.nas!.rootPath)
    if (!inPrimary && ledHits.length === 0 && !inSecondary && !inCScope) {
      return { path, decision: 'deny', reasons: [t('path.out-of-scope：超出作用域 {scopes}', { scopes: [...scope.prefixes, ...leaderScopes.flatMap((led) => led.prefixes)].join('、') })] }
    }
    // Rôle effectif = palier le plus haut entre rôle du périmètre principal et rôle du département dirigé inter-branches (chevauchement multi-identités : prise du plus haut, sans cumul)
    const roleRank: Record<AuthzRole, number> = { P: 0, D: 1, T: 2 }
    let effRole: AuthzRole | undefined = inPrimary ? primaryRole : undefined
    let effFrom: string | undefined
    for (const led of ledHits) {
      if (!effRole || roleRank[led.role] < roleRank[effRole]) {
        effRole = led.role
        effFrom = led.orgName
      }
    }
    if (effRole) {
      const allowed = matrix[effRole][input.op]
      const sourceTag = effFrom ? t('（跨分支所领导部门「{org}」）', { org: effFrom }) : ''
      const shareHint = input.op === 'share' && (effRole === 'T' || effRole === 'M') ? t('（需走审批申请例外）') : ''
      return allowed
        ? { path, decision: 'allow', reasons: [t('matrix.allow：角色 {role}{source} 在作用域内放行「{op}」{coleader}', {
            role: roleLabel(effRole),
            source: sourceTag,
            op: t(OP_LABEL[input.op]),
            coleader: !effFrom && coLeaderMarks.length > 0 ? `（${coLeaderMarks.join('、')}）` : '',
          })] }
        : { path, decision: 'deny', reasons: [t('matrix.deny：角色 {role}{source} 对「{op}」无权限{hint}', {
            role: roleLabel(effRole),
            source: sourceTag,
            op: t(OP_LABEL[input.op]),
            hint: shareHint,
          })] }
    }
    if (deptRootReadonly) {
      return WRITE_OPS.has(input.op)
        ? { path, decision: 'deny', reasons: [t('org.dept-root-readonly：未落班组，部门根目录只读')] }
        : { path, decision: 'allow', reasons: [t('org.dept-root-readonly：部门根目录只读放行')] }
    }
    if (inSecondary) {
      return WRITE_OPS.has(input.op)
        ? { path, decision: 'deny', reasons: [t('org.secondary-readonly：兼任归属子树仅授只读（避免双写冲突）')] }
        : { path, decision: 'allow', reasons: [t('org.secondary-readonly：兼任归属子树只读放行')] }
    }
    if (inCScope) {
      return WRITE_OPS.has(input.op)
        ? { path, decision: 'deny', reasons: [t('role.c-readonly：C 跨域叠加仅只读，白名单目录写需显式授权')] }
        : { path, decision: 'allow', reasons: [t('role.c-readonly：C 动态用户组跨域只读放行')] }
    }
    return { path, decision: 'deny', reasons: [t('role.none：无法推导主角色（组织挂载异常）')] }
  })

  base.perPath = verdicts
  base.decision = verdicts.every((verdict) => verdict.decision === 'allow') ? 'allow' : 'deny'
  base.reasons = [...new Set(verdicts.flatMap((verdict) => verdict.reasons))]
  const hitRule = verdicts.find((verdict) => 'ruleId' in verdict && verdict.ruleId)
  if (hitRule) base.ruleId = (hitRule as EnginePathVerdict & { ruleId: string }).ruleId
  return finalize(base, ctx.rules, input)
}

/** Finalize : rétrogradation intégrale en lecture seule (G3) et marque de mode observation. */
function finalize(decision: EngineDecision, rules: Pick<AuthzRulesSnapshot, 'observeOnly' | 'degradeAllToReadonly'>, input: EngineCheckInput): EngineDecision {
  decision.observeOnly = rules.observeOnly
  if (decision.decision === 'allow' && rules.degradeAllToReadonly && WRITE_OPS.has(input.op) && input.override !== true) {
    decision.decision = 'deny'
    decision.reasons = [...decision.reasons, t('degrade.readonly：全量降级观察期，写类操作统一拒绝（G3）')]
    decision.perPath = decision.perPath.map((verdict) => verdict.decision === 'allow'
      ? { ...verdict, decision: 'deny' as const, reasons: [...verdict.reasons, t('degrade.readonly：全量降级观察期')] }
      : verdict)
  }
  return decision
}

function expired(exception: AuthzException, now: string): boolean {
  return exception.expiresAt !== undefined && exception.expiresAt <= now
}

function roleLabel(role: AuthzRole): string {
  return role === 'P' ? t('P(平台负责人)') : role === 'D' ? t('D(部门负责人)') : role === 'T' ? t('T(班组负责人)') : t('M(成员)')
}

// ---------------------------------------------------------------------------
// Fonctions pures de gouvernance : responsable vacant / réconciliation organisation-répertoire / routage d'approbateur
// ---------------------------------------------------------------------------

/** Détection de responsable vacant : organisations dont leaderUserIds est vide (limitation possible aux organisations portant des comptes). */
export function findVacantLeaderOrgs(orgIndex: OrgIndex, opts?: { withUserOrgIds?: Set<string> }): EngineOrgNode[] {
  return [...orgIndex.values()].filter((node) => {
    if (node.leaderUserIds.length > 0) return false
    if (opts?.withUserOrgIds && !opts.withUserOrgIds.has(node.id)) return false
    return true
  })
}

export interface DirOrphanFinding {
  kind: 'dir-without-org' | 'org-without-dir'
  name: string
  detail: string
}

/**
 * Réconciliation organisations ↔ répertoires (cœur en fonctions pures du job quotidien, dev-plan-nas-authz §2.1) :
 * - nom de répertoire de premier niveau du NAS sans organisation homonyme dans l'arbre (enfants directs du sous-arbre ancré orgRoot) → dir-without-org ;
 * - organisation enfant directe de l'ancre sans répertoire homonyme dans les répertoires de premier niveau du NAS → org-without-dir.
 * Atteinte = alerte dirOrphan ; lors d'un rename d'organisation, inviter l'admin à confirmer l'enregistrement dans orgPathOverrides.
 */
export function reconcileOrgDirs(dirNames: string[], nas: EngineNas, orgIndex: OrgIndex): DirOrphanFinding[] {
  const findings: DirOrphanFinding[] = []
  const anchor = nas.orgRoot ? ([...orgIndex.values()].find((node) => node.id === nas.orgRoot || node.name === nas.orgRoot)) : undefined
  if (!anchor) return [{ kind: 'dir-without-org', name: '*', detail: t('NAS 未配置有效 orgRoot（{orgRoot}），作用域推导处于全 deny 态', { orgRoot: nas.orgRoot ?? t('空') }) }]
  const overrides = nas.orgPathOverrides ?? {}
  const childOrgs = [...orgIndex.values()].filter((node) => node.parentId === anchor.id)
  const dirSet = new Set(dirNames)
  for (const dir of dirNames) {
    const hasOrg = childOrgs.some((node) => node.name === dir)
    const hasOverride = Object.values(overrides).some((prefix) => normalizePath(prefix) === normalizePath(`/${dir}`) || normalizePath(prefix).startsWith(normalizePath(`/${dir}`)))
    if (!hasOrg && !hasOverride) findings.push({ kind: 'dir-without-org', name: dir, detail: t('目录「/{dir}」在组织树（{org} 子级）无归属', { dir, org: anchor.name }) })
  }
  for (const org of childOrgs) {
    if (!dirSet.has(org.name)) findings.push({ kind: 'org-without-dir', name: org.name, detail: t('组织「{name}」在 NAS 上无同名目录（改名请登记 orgPathOverrides）', { name: org.name }) })
  }
  return findings
}

/**
 * Routage automatique de l'approbateur share (dev-plan-nas-authz §2.7) : remonte du sous-arbre du chemin demandé vers le premier
 * responsable non vide (recherché depuis la chaîne d'organisations du demandeur ; renvoie l'organisation la plus proche avec responsable et les personnes).
 * Introuvable = undefined (l'appelant escalade au repli resource_admin).
 */
export function nearestLeaderOrg(orgIndex: OrgIndex, userOrgId: string): { orgId: string; orgName: string; leaderUserIds: string[] } | undefined {
  for (const node of orgChain(orgIndex, userOrgId)) {
    if (node.leaderUserIds.length > 0) return { orgId: node.id, orgName: node.name, leaderUserIds: node.leaderUserIds }
  }
  return undefined
}
