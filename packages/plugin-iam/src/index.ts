/**
 * @dsh-ops/plugin-iam — gestion des comptes et organisations (IAM).
 *
 * Couvre le plan §2 : organisations/comptes, liaison d'authentification tierce, configuration des accès tierces, rôles/groupes d'utilisateurs.
 * Les connecteurs tierces (DingTalk/Feishu/WeCom) implémentent l'interface unifiée OrgConnector ; ajouter une plateforme IM = ajouter un connecteur.
 */
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  PlatformEvents, newId, sha256Hex, generateSecret, mask,
  type Collection, type RecordBase,
} from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import * as iamTools from './tools.ts'
import { DingTalkAuthAdapter, RealDingTalkAuthAdapter, type DingTalkCredentials, type IdentityProviderAdapter } from './providers.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

export interface OrgRecord extends RecordBase {
  name: string
  parentId: string | null
  order: number
  status: 'active' | 'archived'
  customFields: Record<string, string>
  /** Tenant de rattachement (jeu minimal multi-tenant, v1.2 étape 2 ; repli t_default pour les données préexistantes). */
  tenantId?: string
  /**
   * Responsable d'organisation (base de dérivation des rôles P/D/T des permissions de données NAS, dev-plan-nas-authz §2.1).
   * Source de fait : dept_manager_userid_list synchronisé par le connecteur DingTalk ; compatibilité avec l'ancien référentiel customFields['leaderUserIds'] séparé par virgules.
   * Tous les responsables sont dérivés en rôle responsable correspondant (co-leader) ; si vide, nasAuthz émet une alerte leaderVacant.
   */
  leaderUserIds?: string[]
  /**
   * Référentiel du responsable (défaut = 'sync', suit la synchronisation du connecteur) : 'manual' signifie verrouillage d'une liaison manuelle depuis la console,
   * la synchronisation du connecteur ne remplace plus le responsable de cette organisation (il sert à compléter les départements sans responsable côté distant) ; vider le responsable restaure 'sync'.
   */
  leaderSource?: 'sync' | 'manual'
}

/** Tenant (jeu minimal multi-tenant) : vecteur de la dimension tenant des rapports de metering/usage. */
export interface TenantRecord extends RecordBase {
  name: string
  status: 'active' | 'suspended'
  /** Palier d'offre (emplacement d'extension future des paliers de facturation, le schéma v1 contient déjà la dimension tenant). */
  plan: 'trial' | 'standard' | 'enterprise'
}

export const DEFAULT_TENANT_ID = 't_default'

export type UserStatus = 'pending' | 'active' | 'frozen' | 'deactivated'

export interface ThirdPartyBinding {
  provider: 'dingtalk' | 'feishu' | 'wecom'
  unionId: string
  displayName: string
  boundAt: string
  /** corpId de l'entreprise principale (dimension d'isolement multi-entité ; vide/absent = considéré comme l'ancienne entité unique). */
  corpId?: string
}

export interface UserRecord extends RecordBase {
  username: string
  displayName: string
  email: string
  phone: string
  orgId: string
  title: string
  status: UserStatus
  roleIds: string[]
  passwordSalt: string
  passwordHash: string
  bindings: ThirdPartyBinding[]
  jobNumber?: string
  lastLoginAt?: string
  frozenReason?: string
  /**
   * Type de compte (règles des comptes spéciaux des permissions de données NAS, dev-plan-nas-authz §2.1) :
   * internal = employé officiel (défaut) ; external = consultant externe/partenaire (liste blanche en lecture seule) ;
   * suspended-review = marque suspect (deny global + audit renvoyé vers revue humaine).
   */
  accountType?: 'internal' | 'external' | 'suspended-review'
  /**
   * Organisation de rattachement principale (sémantique de cumul inter-départements, dev-plan-nas-authz §2.1) : par défaut, la plus profonde de la chaîne d'organisations.
   * Quand orgId ≠ primaryOrgId, le sous-arbre de orgId ne reçoit que la lecture (cumul en lecture seule, contre les conflits de double écriture).
   */
  primaryOrgId?: string
  /**
   * Exemption de liaison tierce (capacité de déliaison 2026-10-22) : un « provider|corpId » délié/remplacé manuellement ne voit plus
   * ses liens d'identité reconstruits automatiquement par la synchronisation du connecteur.
   *
   * Pourquoi c'est indispensable : la logique de synchronisation décide de réparer le lien selon « bindings contient-il ce provider+corpId »,
   * la synchronisation suivante après déliaison (par défaut toutes les 60 minutes) relierait immédiatement l'identité DingTalk de la personne via son matricule — l'utilisateur verrait
   * « clic sans effet ». Structurellement identique au leaderSource='manual' du responsable de département : « liaison manuelle verrouillée, pas d'écrasement par la synchronisation » :
   * la décision humaine prime sur le fait de synchronisation ; pour restaurer la liaison automatique, lever explicitement l'exemption (un nouveau scan suffit à l'effacer automatiquement).
   */
  bindingExemptions?: string[]
  /**
   * Mot de passe humain connu (source de fait du garde-fou de déliaison 2026-10-22) : true seulement si « quelqu'un a déjà eu le mot de passe en clair » —
   * mot de passe explicitement fixé à la création, réinitialisé par l'admin, changé par la personne. Les comptes créés par auto-enregistrement SSO et synchronisation d'annuaire
   * ont un mot de passe aléatoire jamais distribué, cette marque est false : dans ce cas l'identité tierce est la seule voie de connexion disponible.
   */
  passwordKnown?: boolean
}

export interface RoleRecord extends RecordBase {
  code: string
  name: string
  builtin: boolean
  description: string
  /** '*' signifie tous les points de permission. */
  permissions: string[]
}

/**
 * Contexte d'opérateur des actions de gestion de comptes (QA A-03) : les entrées externes (routes REST de gestion et pont d'outils) doivent porter un actor attribuable,
 * validation du rattachement organisationnel fail-closed (N1). permissions = résultat d'analyse temps réel du jeton de l'opérateur ('*' = admin plateforme) ;
 * orgId est un rattachement organisationnel explicite (forme injectée `_actor` du pont d'outils) ; par défaut, l'organisation est retrouvée via le dossier du compte userId.
 */
export interface UserManageActor {
  userId?: string
  /** Organisation de rattachement de l'opérateur (racine du jugement de sous-arbre ; par défaut retrouvée via le dossier du compte userId). */
  orgId?: string
  permissions: string[]
}

/** Identité système interne (migrations de base/initialisation des graines/synchronisation tierce et autres chaînes internes de service) : opérateur explicite de niveau plateforme, remplaçant les passages sans attribution. */
export const SYSTEM_ACTOR: UserManageActor = { permissions: ['*'] }

/**
 * Refus d'action inter-organisations (QA A-03/N4) : la sémantique du domaine est 403 FORBIDDEN — la couche de routage de la console l'attrape et la réécrit via
 * exchange.fail(403) (le rattrapage guarded traite toute Error nue en 400 ; un refus inter-organisations n'est pas une erreur de format de requête).
 */
export class OrgScopeDeniedError extends Error {
  readonly status = 403
  readonly code = 'FORBIDDEN'

  constructor(message: string) {
    super(message)
    this.name = 'OrgScopeDeniedError'
  }
}

export interface UserGroupRule {
  orgIds?: string[]
  title?: string
}

export interface UserGroupRecord extends RecordBase {
  name: string
  type: 'static' | 'dynamic'
  rule?: UserGroupRule
  memberIds: string[]
  description: string
  /**
   * Si le groupe est un groupe d'utilisateurs dynamique lié au rôle C des permissions de données NAS (dev-plan-nas-authz §2.2).
   * Marque réécrite à l'import/mise à jour des règles nasAuthz ; au recalcul de dérive, une alerte cGroupDrift est émise quelle que soit l'amplitude.
   */
  authzRoleC?: boolean
  /** Seuil d'alerte de dérive au recalcul des membres (nombre de personnes, défaut 5 ; ne s'applique qu'aux groupes sans marque authzRoleC). */
  driftAlertThreshold?: number
}

export interface ConnectorConfigRecord extends RecordBase {
  id: string
  provider: 'dingtalk' | 'feishu' | 'wecom'
  /** Nom de l'entité (dimension d'affichage multi-entité ; défaut `${provider}-${corpId}`). */
  name: string
  enabled: boolean
  corpId: string
  appKey: string
  secretMasked: string
  secretActual?: string
  syncOrgRoot: string
  intervalMinutes: number
  callbackUrl: string
  loginEnabled: boolean
  conflictStrategy: 'third_party_wins' | 'platform_wins' | 'manual'
  /** real = OpenAPI réel ; mock = repli de démonstration (explicitement marqué). */
  mode: 'real' | 'mock'
  /** Surcharge de l'URL de base OpenAPI (tests/déploiements dédiés pointant en local). */
  apiBase?: string
  /** Surcharge de l'URL de base topapi d'annuaire (défaut https://oapi.dingtalk.com). */
  oapiBase?: string
  /** ID de l'organisation cible où monte l'arbre synchronisé (vide = racine plateforme ; chaque entité monte sur sa propre racine). */
  targetOrgId?: string
  lastSyncAt?: string
  lastSyncResult?: { ok: boolean; created: number; updated: number; conflicts: number; frozen: number; message: string }
}

/**
 * Liens d'identité tierce (fusion de la conception user_identity_links de auth-identity).
 * Les liens actifs sont uniques au niveau moteur sur (provider, corpId, providerUserId) — « une personne, un compte » isolé par entité,
 * garanti par la contrainte d'unicité ; interdiction de remplacer la contrainte par du « chercher-puis-insérer » (ligne rouge). Délier = suppression physique de l'enregistrement (équivalent d'un index unique partiel WHERE unlinked_at IS NULL).
 *
 * kind (ajouté avec la capacité de déliaison 2026-10-22) : sous un même provider+corpId, une même personne physique peut avoir simultanément deux liens,
 * d'usages différents, indépendamment préservables :
 *   - login (défaut) : lien d'identité de connexion, providerUserId est l'unionId. Sert au jugement « qui est cette personne » et à la connexion SSO.
 *   - staff : lien d'identité de fonction, providerUserId est le userid (staffId). Sert aux recherches inverses fonction/responsable d'annuaire
 *     (cartographie des responsables de département, recherche d'identité des permissions de données NAS) — il décrit « le poste de cette personne dans l'organisation », pas un identifiant de connexion.
 * La coexistence des deux relève de la conception existante (écrits simultanément à la synchronisation). Délier l'identité de connexion ne doit pas effacer le fait de fonction :
 * l'effacer casserait la recherche inversée des responsables de département et ferait retomber le routage d'approbation sur le département parent (régression constatée 2026-10-22).
 */
export interface IdentityLinkRecord extends RecordBase {
  provider: 'dingtalk' | 'feishu' | 'wecom'
  providerUserId: string
  corpId: string
  userId: string
  displayName: string
  linkedAt: string
  linkedBy: string
  /** Usage du lien : login = identité de connexion (défaut) ; staff = identité de fonction. Par défaut lu comme login (compatibilité des données préexistantes). */
  kind?: 'login' | 'staff'
}

export interface SyncConflictRecord extends RecordBase {
  provider: string
  kind: 'user_attr' | 'user_new' | 'user_left' | 'org_change'
  thirdPartyData: Record<string, unknown>
  platformData: Record<string, unknown>
  status: 'pending' | 'resolved'
  resolution?: string
  resolvedBy?: string
  resolvedAt?: string
}

/** Instantané des membres de groupes d'utilisateurs dynamiques (observabilité de la dérive du groupe C, dev-plan-nas-authz §2.2). */
export interface GroupSnapshotRecord extends RecordBase {
  groupId: string
  memberIds: string[]
  computedAt: string
}

/** Seuil par défaut de l'alerte de dérive des membres de groupe (nombre de personnes). */
export const DEFAULT_GROUP_DRIFT_THRESHOLD = 5

/** Tick d'inspection de la synchronisation automatique des connecteurs : l'échéance se juge selon l'intervalMinutes propre à chaque configuration, la période n'est pas fixée ici. */
const AUTO_SYNC_TICK_MS = 60_000
/** Délai du premier tour après démarrage : décale la fenêtre de chargement de la plateforme ; les connecteurs en retard/jamais synchronisés rattrapent au démarrage.
 * Référentiel 90 s (retour d'expérience R4 2026-10-13) : l'ancien 15 s devançait l'assertion d'échange SSO sur des environnements à boot lent et synchronisait automatiquement
 * la liste de démonstration (dd_u003 etc.) en créant des liens d'identité, polluant le jugement « billet en attente de liaison non atteint » ;
 * l'environnement de démonstration porte de toute façon un connecteur de démonstration intervalMinutes=60, son déclenchement au boot est légitime — allonger le délai laisse passer la fenêtre interactive d'abord. */
const AUTO_SYNC_BOOT_DELAY_MS = 90_000
/** Intervalle effectif minimal par connecteur (contre les mauvaises configurations à haute fréquence épuisant le quota DingTalk OpenAPI ; 0 = synchronisation automatique désactivée pour ce connecteur). */
const AUTO_SYNC_MIN_INTERVAL_MINUTES = 5

// ---------------------------------------------------------------------------
// Catalogue des points de permission
// ---------------------------------------------------------------------------

export const PermissionCatalog: Array<{ point: string; label: string; group: string }> = [
  { point: 'console.login', label: '登录控制台', group: '基础' },
  // Base en lecture seule de la console (lot mode démo 2026-10-17) : lieu de déclaration des cinq routes purement lecture
  // agrégat espace de travail/notifications/infos plateforme/catalogue d'outils/appels récents. Impliqué par console.login (règles de dérivation voir
  // IMPLIED_POINTS dans platform-core rest-gate.ts) : tout rôle connectable passe sans octroi explicite ; octroyer ce point seul ne confère pas la connexion.
  // La liste blanche en lecture seule du mode démo sans connexion inclut ce point (le visiteur peut lire l'espace de travail sans obtenir console.login lui-même).
  { point: 'console.read', label: '控制台只读（工作台/通知/平台信息/工具目录）', group: '基础' },
  { point: 'iam.org.read', label: '查看组织', group: '组织账号' },
  { point: 'iam.org.write', label: '管理组织', group: '组织账号' },
  { point: 'iam.user.read', label: '查看账号', group: '组织账号' },
  { point: 'iam.user.write', label: '管理账号', group: '组织账号' },
  { point: 'iam.user.freeze', label: '冻结/注销账号', group: '组织账号' },
  { point: 'iam.role.write', label: '管理角色', group: '组织账号' },
  { point: 'iam.connector.write', label: '管理三方接入', group: '组织账号' },
  { point: 'iam.scene.write', label: '管理场景级授权策略（场景 ABAC）', group: '组织账号' },
  { point: 'iam.roster.read', label: '读取全员名册（组织数据通道，接入应用拉取）', group: '组织账号' },
  { point: 'authn.principal.read', label: '查看身份/凭证', group: '统一认证' },
  { point: 'authn.principal.write', label: '管理机器凭证', group: '统一认证' },
  { point: 'authn.token.issue', label: '签发令牌', group: '统一认证' },
  { point: 'authn.token.revoke', label: '吊销令牌', group: '统一认证' },
  { point: 'authn.oidc.read', label: '查看 OIDC 客户端', group: '统一认证' },
  { point: 'authn.oidc.write', label: '管理 OIDC 客户端（签发/轮换/禁用）', group: '统一认证' },
  { point: 'mcp.service.read', label: '查看 MCP 服务', group: 'MCP' },
  // W3-T5 (contrat de gouvernance MCP §12/§15) : point de lecture du gabarit de scope (POST /api/mcp/perm-groups/:id/scope-template,
  // sémantique dry sans écriture) — sans ce point au catalogue, le joker mcp.* de resource_admin ne peut s'y déplier (403 intégral)
  { point: 'mcp.permgroup.read', label: '读取 MCP 权限组与 scope 模板', group: 'MCP' },
  { point: 'mcp.service.write', label: '管理 MCP 服务', group: 'MCP' },
  { point: 'mcp.service.deploy', label: '部署/灰度 MCP', group: 'MCP' },
  { point: 'mcp.service.offline', label: '下线 MCP', group: 'MCP' },
  { point: 'mcp.permgroup.write', label: '管理 MCP 权限组', group: 'MCP' },
  { point: 'mcp.invoke', label: '调用 MCP 网关', group: 'MCP' },
  // Lot W, W1 (2026-10-15, correction de racine V11) : face d'approbation de l'enregistrement des risques de confiance des outils MCP — enregistrement/approbation à deux niveaux/liste de ré-examen/retrait
  { point: 'mcp.risk.admin', label: 'MCP 工具风险登记审批（登记/两级审批/重审清单）', group: 'MCP' },
  // Gestion des connecteurs (passerelle du plan de données SaaS ; invoke en point de permission indépendant, aligné sur le précédent mcp.invoke)
  { point: 'connector.gateway.write', label: '配置连接器网关与健康操作', group: '连接器' },
  { point: 'connector.catalog.read', label: '浏览连接器目录', group: '连接器' },
  { point: 'connector.connection.read', label: '查看连接器连接（org 内）', group: '连接器' },
  { point: 'connector.connection.write', label: '创建/删除连接器连接（含 OAuth 发起）', group: '连接器' },
  { point: 'connector.invoke', label: '调用连接器 action', group: '连接器' },
  { point: 'connector.permgroup.write', label: '管理连接器权限组', group: '连接器' },
  { point: 'connector.runs.read', label: '查看连接器运行日志/对账视图', group: '连接器' },
  // connector.market.publish retiré (hygiène des points de permission E-06) : aucune barrière de consommation dans tout le dépôt (aucune référence
  // guarded/requirePermission/hasPermission), aucun rôle intégré ne le détient ; l'action de publication est portée par le contrat market.submit + le flux d'approbation du marché.
  { point: 'skill.read', label: '浏览 Skill 市场', group: 'Skill 市场' },
  { point: 'skill.submit', label: '提交 Skill', group: 'Skill 市场' },
  { point: 'skill.approve', label: '审批 Skill', group: 'Skill 市场' },
  { point: 'skill.publish', label: '上架/下架 Skill', group: 'Skill 市场' },
  { point: 'skill.install', label: '安装 Skill', group: 'Skill 市场' },
  { point: 'skill.storage.write', label: '配置 Skill 包存储后端（本地/NAS）', group: 'Skill 市场' },
  { point: 'nas.read', label: '查看 NAS 存储', group: 'NAS 存储' },
  { point: 'nas.write', label: '管理 NAS 存储（纳管/上线/文件读写）', group: 'NAS 存储' },
  // Permissions de données NAS (dev-plan-nas-authz §2.3) : check pour les appels des comptes de service dédiés passerelle/hermes, read/write pour la gestion des règles
  { point: 'nas.authz.check', label: 'NAS 数据权限判定（check/scope）', group: 'NAS 存储' },
  { point: 'nas.authz.read', label: '查看 NAS 数据权限规则与判定留痕', group: 'NAS 存储' },
  { point: 'nas.authz.write', label: '管理 NAS 数据权限规则/例外（含破窗 override）', group: 'NAS 存储' },
  // Rattrapage des points de permission orphelins (découvert au tableau R10, 2026-10-13) : déclarés dans plugin-nas/manifest/permissions.yaml,
  // réellement vérifiés par deux routes guarded de la console (enregistrement/réécriture de propriété), mais absents du catalogue jusqu'ici — les rôles personnalisés ne pouvaient pas les cocher
  { point: 'nas.ownership.write', label: '管理 NAS 文件所有权（上传登记/重命名改写/删除移除）', group: 'NAS 存储' },
  { point: 'agent.read', label: '查看 Agent', group: 'Agent 本体' },
  { point: 'agent.write', label: '管理 Agent', group: 'Agent 本体' },
  { point: 'agent.approve', label: '审批 Agent 上线', group: 'Agent 本体' },
  { point: 'agent.offline', label: '下线 Agent', group: 'Agent 本体' },
  { point: 'agent.a2a.invoke', label: 'A2A 跨运行时点名调用（IAW 7-1）', group: 'Agent 本体' },
  { point: 'app.read', label: '查看 AI 应用', group: 'AI 应用' },
  { point: 'app.write', label: '管理 AI 应用', group: 'AI 应用' },
  { point: 'app.offline', label: '下线 AI 应用', group: 'AI 应用' },
  // Lecture des valeurs des identifiants externes d'application (issue #19, 2026-10-31) : point de permission indépendant — enregistrement/rotation suivent app.write,
  // la lecture (obtenir le clair) exige une autorisation séparée + audit à chaque fois ; aucun rôle intégré par défaut (octroi explicite au besoin, surface de divulgation minimale)
  { point: 'app.credential.fetch', label: '取用应用外部凭证（每次取用落审计）', group: 'AI 应用' },
  // Domaine des données (livraison IAW 2-1..2-4) : enregistrement de jeux de données/score qualité/lignée/dictionnaire d'indicateurs
  { point: 'resource.dataset.write', label: '管理数据要素（数据集/质量分/血缘/指标字典）', group: '数据要素' },
  { point: 'audit.read', label: '查看审计日志', group: '审计' },
  { point: 'audit.rule.write', label: '管理告警规则', group: '审计' },
  { point: 'approval.read', label: '查看审批中心', group: '审批' },
  { point: 'approval.decide', label: '审批决策', group: '审批' },
  { point: 'usage.read', label: '查看计量流水', group: '用量计量' },
  { point: 'usage.write', label: '登记计量事件', group: '用量计量' },
  { point: 'usage.admin', label: '管理价格簿/对账/能力授权', group: '用量计量' },
  { point: 'modelgw.read', label: '查看模型网关', group: '模型网关' },
  { point: 'modelgw.invoke', label: '调用模型网关', group: '模型网关' },
  { point: 'modelgw.admin', label: '管理模型目录', group: '模型网关' },
  { point: 'market.read', label: '浏览插件市场', group: '插件市场' },
  // market.submit retiré (hygiène E-06) : la face de soumission POST /api/market/submit passe par l'auto-vérification d'identité développeur
  // (access=authenticated + developerCaller) ; ce point de permission est sans consommation ni détenteur de rôle dans tout le dépôt.
  { point: 'market.approve', label: '审批插件', group: '插件市场' },
  { point: 'market.install', label: '安装插件', group: '插件市场' },
  { point: 'market.developer', label: '开发者门户', group: '插件市场' },
  { point: 'connect.manage', label: '管理平台接入（接入码/远程客户端）', group: '平台接入' },
  { point: 'platform.update.read', label: '查看/触发平台更新检查', group: '平台维护' },
  { point: 'platform.update.apply', label: '执行平台升级（git pull + npm install）', group: '平台维护' },
  // Panneau départemental (review-dsh-agent-panel-v2 Phase 0 : arbitrage D3 — pas de point de permission d'événement dingtalk.*, la souscription au bus n'exige pas de point)
  { point: 'panel.read', label: '查看部门面板（会话/看板/知识/图谱）', group: '部门面板' },
  { point: 'panel.write', label: '面板协作（发消息/建频道/卡片动作/激活申请）', group: '部门面板' },
  { point: 'panel.task.write', label: '面板任务流转（创建/泳道迁移）', group: '部门面板' },
  { point: 'panel.config.write', label: '面板配置（widget/KPI 布局/图谱重载）', group: '部门面板' },
  { point: 'scenegraph.read', label: '查看行业场景图谱', group: '部门面板' },
  // scenegraph.activate retiré (hygiène E-06) : la vraie barrière de l'activation de secteur est panel.write (demande d'activation)
  // et market.approve (exécution d'approbation) ; ce point est sans consommation dans tout le dépôt ; le lot de migration org_admin le retire aussi (les points déjà
  // en base seront repris par l'admin via l'édition de rôle ; la migration ne fait que combler les manques, sans suppression ni modification).
  { point: 'dingtalk.message.send', label: '钉钉桥接消息投递（群桥绑定/推送/回决回调）', group: '部门面板' },
  // Moteur de flux de dossiers (livraison IAW 3-1..3-4, nouveau domaine hôte flow)
  { point: 'flow.read', label: '查看事务流（编排/模板/SLA）', group: '事务流' },
  { point: 'flow.write', label: '事务流流转（创建实例/步骤推进/取消）', group: '事务流' },
  { point: 'flow.admin', label: '管理事务流模板库', group: '事务流' },
  // Centre d'exécution (préambule feuille de route R5/R10 2026-10-14, domaine plugin-exec-hub) : les points de permission n'étaient auparavant déclarés que dans
  // plugin-exec-hub/plugin.yaml, absents du catalogue (rôles personnalisés incapables de les cocher, même précédent que l'orphelin nas.ownership.write)
  // — une fois recensés, rôles intégrés et personnalisés peuvent autoriser à la bonne granularité
  { point: 'exec.read', label: '查看执行中枢（目标/任务/唤醒/心跳）', group: '执行中枢' },
  { point: 'exec.write', label: '操作执行中枢任务', group: '执行中枢' },
  { point: 'exec.admin', label: '执行中枢运维（手动 tick 等）', group: '执行中枢' },
  // Domaine de l'employé numérique (lot W, plugin-workforce) : points de permission auparavant déclarés seulement dans plugin.yaml/permissions.yaml,
  // absents du catalogue (même précédent que les orphelins exec.*) — une fois recensés, les identifiants machine authn peuvent émettre des scopes workforce.*,
  // et rôles intégrés et personnalisés peuvent autoriser à la bonne granularité (face opérationnelle workforce.admin soldée dans le même lot W5)
  { point: 'workforce.read', label: '查看数字员工域（员工/任用/调用/交付）', group: '数字员工' },
  { point: 'workforce.write', label: '管理数字员工域（员工/绑定/任用）', group: '数字员工' },
  { point: 'workforce.admin', label: '数字员工运维（批量停复职/审计报表/台账清理）', group: '数字员工' },
  { point: 'workforce.invoke', label: '数字员工受控调用（认领/续租/受控执行）', group: '数字员工' },
  { point: 'workforce.accept', label: '数字员工交付验收（提交/决定）', group: '数字员工' },
]

export const BuiltinRoles: Array<Omit<RoleRecord, 'id' | 'createdAt' | 'updatedAt'>> = [
  { code: 'super_admin', name: '平台超级管理员', builtin: true, description: '拥有全部权限点', permissions: ['*'] },
  // org_admin reçoit exec.* (gestion du centre d'exécution 2026-10-14) : pleins pouvoirs de l'admin d'organisation sur le centre d'exécution (même référentiel que iam.*)
  // + workforce.* (lot W 2026-10-15) : pleins pouvoirs sur le domaine de l'employé numérique de l'organisation (synchronisés aux deux endroits avec BUILTIN_ROLE_MIGRATION)
  { code: 'org_admin', name: '组织管理员', builtin: true, description: '管理本组织账号与用户组', permissions: ['console.login', 'iam.*', 'approval.read', 'exec.*', 'workforce.*'] },
  // resource_admin reçoit exec.read + modelgw.read (2026-10-14) : l'admin de ressources peut consulter le centre d'exécution (la face de marche des Agents opérés)
  // et le catalogue de modèles (R2-B : la gradation de canaux/la gouvernance de budget exige de voir la liste des modèles, la face écriture reste modelgw.admin)
  // + workforce.read (lot W 2026-10-15) : l'admin de ressources peut consulter le domaine de l'employé numérique (les employés consomment les ressources qu'il gère, la face opérationnelle reste org_admin)
  { code: 'resource_admin', name: '资源管理员', builtin: true, description: '管理 MCP/Skill/Agent/应用/NAS/连接器资源与数据要素', permissions: ['console.login', 'mcp.*', 'skill.*', 'agent.*', 'app.*', 'nas.*', 'authn.oidc.*', 'connector.*', 'resource.dataset.write', 'panel.read', 'flow.read', 'approval.read', 'modelgw.read', 'exec.read', 'workforce.read'] },
  { code: 'developer', name: '开发者', builtin: true, description: '提交与调试资源（应用限自身 owner 范围，服务端校验）', permissions: ['console.login', 'iam.user.read', 'iam.org.read', 'mcp.service.read', 'mcp.invoke', 'skill.read', 'skill.submit', 'skill.install', 'agent.read', 'agent.write', 'app.read', 'app.write', 'nas.read', 'connector.catalog.read', 'connector.connection.read', 'connector.invoke', 'exec.read', 'exec.write'] },
  { code: 'member', name: '普通用户', builtin: true, description: '浏览市场与可用资源', permissions: ['console.login', 'skill.read', 'agent.read', 'app.read', 'panel.read', 'panel.write', 'panel.task.write', 'scenegraph.read', 'flow.read', 'flow.write', 'exec.read', 'exec.write'] },
  { code: 'auditor', name: '审计员（只读）', builtin: true, description: '全平台只读审计', permissions: ['console.login', 'iam.org.read', 'iam.user.read', 'authn.principal.read', 'authn.oidc.read', 'mcp.service.read', 'skill.read', 'agent.read', 'app.read', 'nas.read', 'audit.read', 'approval.read', 'connector.runs.read', 'connector.connection.read', 'exec.read'] },
]

/**
 * Migration de permissions unique et idempotente des rôles intégrés : ensureBuiltinRoles insère sans mettre à jour — les rôles déjà en base en production n'obtiennent
 * pas automatiquement les points de permission ajoutés dans les versions suivantes. La migration ne fait que « combler les manques », sans toucher aux rôles personnalisés ; à chaque
 * démarrage la comparaison est refaite (idempotent), les marques historiques (connector-permissions-v1) ne servent qu'à l'observation.
 */
export const BUILTIN_ROLE_MIGRATION: Record<string, string[]> = {
  // resource_admin reçoit la face lecture de gouvernance (QA-03 externe QA-20261014) : les routes de lecture jeux de données/indicateurs/lignée etc. portent panel.read,
  // modèles et instances de flux portent flow.read — l'admin de ressources pouvait « écrire (resource.dataset.write/flow.admin) sans lire »
  // + exec.read/modelgw.read (face lecture centre d'exécution et catalogue de modèles 2026-10-14, doit rester synchronisée avec BuiltinRoles aux deux endroits)
  resource_admin: ['connector.gateway.write', 'connector.catalog.read', 'connector.connection.read', 'connector.connection.write', 'connector.invoke', 'connector.permgroup.write', 'connector.runs.read', 'resource.dataset.write', 'flow.admin', 'panel.read', 'flow.read', 'modelgw.read', 'exec.read'],
  // developer reçoit agent.write : symétrique d'app.write — le développeur doit pouvoir enregistrer/déclarer la mise à jour d'un Agent (correctif 2026-08 « toujours une erreur faute de agent.write »)
  // + exec.read/exec.write (2026-10-14) : le développeur peut consulter et opérer dans le centre d'exécution les tâches qu'il a lancées
  developer: ['connector.catalog.read', 'connector.connection.read', 'connector.invoke', 'agent.write', 'panel.read', 'scenegraph.read', 'flow.read', 'exec.read', 'exec.write'],
  // auditor reçoit nas.authz.read : l'auditeur peut consulter les règles de permissions de données NAS et les traces de jugement (dev-plan-nas-authz §2.3)
  // + exec.read (2026-10-14) : les traces tâches/réveils du centre d'exécution entrent dans la face audit en lecture seule
  auditor: ['connector.runs.read', 'connector.connection.read', 'nas.authz.read', 'panel.read', 'scenegraph.read', 'flow.read', 'exec.read'],
  // Panneau départemental (review-dsh-agent-panel-v2 Phase 0) : membre métier = member utilise directement le panneau ; org_admin reçoit la configuration ;
  // les bases préexistantes reçoivent les points par migration, les bases neuves les tiennent directement de la définition BuiltinRoles (les deux endroits doivent rester synchronisés)
  // + exec.read/exec.write (2026-10-14) : l'utilisateur ordinaire peut lancer/consulter ses propres tâches dans le centre d'exécution
  member: ['panel.read', 'panel.write', 'panel.task.write', 'scenegraph.read', 'flow.read', 'flow.write', 'exec.read', 'exec.write'],
  // org_admin reçoit exec.* (2026-10-14) : pleins pouvoirs sur le centre d'exécution de l'organisation (lecture/écriture/tick opérationnel, même référentiel que le joker iam.*)
  // scenegraph.activate retiré (E-06) : point mort sans consommation dans le dépôt (voir la note interne du PermissionCatalog)
  // + workforce.* (lot W 2026-10-15) : pleins pouvoirs sur le domaine de l'employé numérique de l'organisation (face opérationnelle workforce.admin, même référentiel qu'exec.admin)
  org_admin: ['panel.read', 'panel.write', 'panel.task.write', 'panel.config.write', 'scenegraph.read', 'flow.read', 'flow.write', 'flow.admin', 'exec.*', 'workforce.*'],
}

/** Alias de compatibilité : nommage historique du canal de migration (lot connector uniquement). */
export const CONNECTOR_ROLE_MIGRATION = BUILTIN_ROLE_MIGRATION

// ---------------------------------------------------------------------------
// Autorisation au niveau scénario (livraison IAW 6-1 : rôles L1-L5 × ABAC de scénario à grain fin)
// ---------------------------------------------------------------------------

/**
 * Entrée de politique d'autorisation de scénario : ligne de règle ABAC selon rôle/utilisateur × action × allow/deny.
 * La clé d'action a la même forme qu'un point de permission (panel.read/panel.task.write…) ou une clé d'action métier personnalisée (ex. 'scene.export') ;
 * principalId='*' sert de joker.
 */
export interface ScenePolicyEntry {
  principalType: 'role' | 'user'
  principalId: string
  actions: string[]
  effect: 'allow' | 'deny'
}

/**
 * Politique d'autorisation de scénario : accrochée à la dimension sceneCode (ScenegraphScene.code, ex. QB01-A-2-5).
 * Sémantique de jugement (fail-closed) : scénario sans aucune politique → default (retombe sur le RBAC de rôle et les permissions de périmètre départemental, comportement historique inchangé) ;
 * avec politique → une entrée deny atteinte = refus ; une entrée allow atteinte = passage ; aucune atteinte = refus systématique.
 * Verrou optimiste version : l'édition concurrente se réconcilie par expectedVersion (conflit = erreur, lire-puis-écrire).
 */
export interface ScenePolicyRecord extends RecordBase {
  sceneCode: string
  /** Resserrage organisationnel (défaut = politique commune à toutes les organisations) ; un même scénario peut porter une entrée par organisation. */
  orgId?: string
  entries: ScenePolicyEntry[]
  note?: string
  version: number
}

export interface SceneCheckDecision {
  /** default = scénario sans politique configurée (retombe sur RBAC) ; allow/deny = arbitrage par la politique du scénario. */
  decision: 'allow' | 'deny' | 'default'
  reason: string
  policyId?: string
  sceneCode: string
  action: string
}

// ---------------------------------------------------------------------------
// Interface des connecteurs tierces
// ---------------------------------------------------------------------------

export interface RemoteDirectory {
  orgs: Array<{ remoteId: string; name: string; parentRemoteId: string | null; /** Liste des userId tiers des responsables de département (dept_manager_userid_list DingTalk), base de dérivation des rôles nasAuthz. */ managerRemoteIds?: string[] }>
  users: Array<{
    remoteId: string
    /** userid DingTalk (staffId) : référentiel de l'en-tête d'identité hermes X-On-Behalf-User et de dept_manager_userid_list ; coexiste avec remoteId(unionId) en deux identityLinks. */
    remoteUserId?: string
    name: string
    jobNumber: string
    title: string
    orgRemoteId: string
    /** Une personne, plusieurs départements : orgRemoteId est le rattachement principal (priorité à deptRemoteIds[0] = département principal DingTalk, sinon le premier vu dans l'annuaire), les autres départements sont notés cumul/attache (le sous-arbre orgId du moteur est en lecture de cumul). */
    extraOrgRemoteIds?: string[]
    /** Ordre original du dept_id_list DingTalk (premier = département principal), sert à corriger le rattachement principal en multi-département. */
    deptRemoteIds?: string[]
    email: string
    active: boolean
  }>
}

export interface OrgConnector {
  provider: string
  label: string
  fetchDirectory(): Promise<RemoteDirectory>
  healthCheck(): Promise<{ ok: boolean; latencyMs: number; message: string; mock?: boolean }>
}

/** Connecteur DingTalk (annuaire simulé intégré en environnement de démonstration, interface alignée sur la vraie OpenAPI). */
export class DingTalkConnector implements OrgConnector {
  provider = 'dingtalk'
  label = '钉钉'

  private directory: RemoteDirectory = {
    orgs: [
      { remoteId: 'dd_root', name: '元冰可集团', parentRemoteId: null, managerRemoteIds: ['staff_001'] },
      { remoteId: 'dd_tech', name: '技术中心', parentRemoteId: 'dd_root', managerRemoteIds: ['staff_001'] },
      { remoteId: 'dd_ai', name: 'AI 平台部', parentRemoteId: 'dd_tech', managerRemoteIds: ['staff_002'] },
      { remoteId: 'dd_be', name: '后端部', parentRemoteId: 'dd_tech', managerRemoteIds: ['staff_004'] },
      { remoteId: 'dd_fe', name: '前端部', parentRemoteId: 'dd_tech', managerRemoteIds: ['staff_005'] },
      { remoteId: 'dd_prod', name: '产品运营部', parentRemoteId: 'dd_root', managerRemoteIds: ['staff_006'] },
      { remoteId: 'dd_mkt', name: '市场部', parentRemoteId: 'dd_root', managerRemoteIds: ['staff_008'] },
    ],
    users: [
      { remoteId: 'dd_u001', remoteUserId: 'staff_001', name: '陈远舟', jobNumber: 'DD0001', title: '技术总监', orgRemoteId: 'dd_tech', email: 'chenyz@yuanbingke.com', active: true },
      { remoteId: 'dd_u002', remoteUserId: 'staff_002', name: '林小满', jobNumber: 'DD0002', title: '算法工程师', orgRemoteId: 'dd_ai', email: 'linxm@yuanbingke.com', active: true },
      { remoteId: 'dd_u003', remoteUserId: 'staff_003', name: '周既白', jobNumber: 'DD0003', title: '算法工程师', orgRemoteId: 'dd_ai', email: 'zhoujb@yuanbingke.com', active: true },
      { remoteId: 'dd_u004', remoteUserId: 'staff_004', name: '苏砚秋', jobNumber: 'DD0004', title: '后端工程师', orgRemoteId: 'dd_be', email: 'suyq@yuanbingke.com', active: true },
      { remoteId: 'dd_u005', remoteUserId: 'staff_005', name: '何青梧', jobNumber: 'DD0005', title: '前端工程师', orgRemoteId: 'dd_fe', email: 'heqw@yuanbingke.com', active: true },
      { remoteId: 'dd_u006', remoteUserId: 'staff_006', name: '顾星阑', jobNumber: 'DD0006', title: '产品经理', orgRemoteId: 'dd_prod', email: 'guxl@yuanbingke.com', active: true },
      { remoteId: 'dd_u007', remoteUserId: 'staff_007', name: '叶栖迟', jobNumber: 'DD0007', title: '运营专员', orgRemoteId: 'dd_prod', email: 'yqz@yuanbingke.com', active: true },
      { remoteId: 'dd_u008', remoteUserId: 'staff_008', name: '孟疏桐', jobNumber: 'DD0008', title: '市场专员', orgRemoteId: 'dd_mkt', email: 'mst@yuanbingke.com', active: true },
      { remoteId: 'dd_u009', remoteUserId: 'staff_009', name: '周明澜', jobNumber: 'DD0009', title: '前端工程师', orgRemoteId: 'dd_fe', extraOrgRemoteIds: ['dd_be'], email: 'zhml@yuanbingke.com', active: true },
      { remoteId: 'dd_u010', remoteUserId: 'staff_010', name: '姜叙白', jobNumber: 'DD0010', title: '数据工程师', orgRemoteId: 'dd_be', email: 'jxb@yuanbingke.com', active: false },
    ],
  }

  async fetchDirectory(): Promise<RemoteDirectory> {
    await delay(120 + Math.floor(Math.random() * 80))
    return structuredClone(this.directory)
  }

  async healthCheck(): Promise<{ ok: boolean; latencyMs: number; message: string; mock?: boolean }> {
    const started = Date.now()
    await delay(40)
    return { ok: true, latencyMs: Date.now() - started, message: t('降级模式：未配置钉钉企业凭证，使用内置演示目录'), mock: true }
  }
}

/**
 * Connecteur DingTalk (vraie OpenAPI) : tirage paginé de l'annuaire, cartographie de l'annuaire vers RemoteDirectory.
 * Chaîne : accessToken d'application interne d'entreprise (POST api.dingtalk.com/v1.0/oauth2/accessToken)
 *   → arbre des départements (oapi topapi/v2/department/listsubid + department/get, BFS depuis la racine)
 *   → membres des départements (oapi topapi/v2/user/list paginé).
 * Tout échec d'interface (HTTP non 2xx ou errcode != 0) lève une erreur portant l'errmsg —
 * leçon historique : un annuaire vide renvoyé silencieusement fait une synchronisation « réussie » mais 0 donnée, panne indétectable.
 */
export class RealDingTalkConnector implements OrgConnector {
  provider = 'dingtalk'
  label = '钉钉'
  private corpTokenCache: { token: string; expiresAt: number } | undefined
  private readonly credentials: DingTalkCredentials
  /** ID du département racine de synchronisation (défaut 1 = racine d'entreprise). */
  private readonly syncOrgRoot: string

  constructor(credentials: DingTalkCredentials, options: { syncOrgRoot?: string } = {}) {
    this.credentials = credentials
    this.syncOrgRoot = options.syncOrgRoot?.trim() || '1'
  }

  private get apiBase(): string {
    return this.credentials.apiBase ?? 'https://api.dingtalk.com'
  }

  private get oapiBase(): string {
    return this.credentials.oapiBase ?? 'https://oapi.dingtalk.com'
  }

  private async corpAccessToken(): Promise<string> {
    if (this.corpTokenCache && this.corpTokenCache.expiresAt > Date.now() + 60_000) {
      return this.corpTokenCache.token
    }
    const response = await fetch(`${this.apiBase}/v1.0/oauth2/accessToken`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ appKey: this.credentials.appKey, appSecret: this.credentials.appSecret }),
    })
    const payload = (await response.json().catch(() => ({}))) as { accessToken?: string; expireIn?: number }
    if (!response.ok || !payload.accessToken) {
      throw new Error(t('钉钉企业 accessToken 获取失败（HTTP {status}）', { status: response.status }))
    }
    this.corpTokenCache = { token: payload.accessToken, expiresAt: Date.now() + (payload.expireIn ?? 7200) * 1000 }
    return payload.accessToken
  }

  /** Appel oapi topapi : access_token en query ; errcode != 0 = erreur levée (pas d'engloutissement silencieux). */
  private async topapi<T>(path: string, body: Record<string, unknown>): Promise<T & { errcode?: number; errmsg?: string }> {
    const token = await this.corpAccessToken()
    const response = await fetch(`${this.oapiBase}${path}?access_token=${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    const payload = (await response.json().catch(() => ({}))) as T & { errcode?: number; errmsg?: string }
    if (!response.ok || (payload.errcode ?? 0) !== 0) {
      throw new Error(t('钉钉接口 {path} 调用失败（HTTP {status}，errcode {errcode}：{errmsg}）', { path, status: response.status, errcode: payload.errcode ?? '-', errmsg: payload.errmsg ?? t('无错误信息') }))
    }
    return payload
  }

  async fetchDirectory(): Promise<RemoteDirectory> {
    const rootId = this.syncOrgRoot
    const rootInfo = await this.getDepartment(rootId)
    const orgs: RemoteDirectory['orgs'] = [{ remoteId: rootId, name: rootInfo.name, parentRemoteId: null, ...(rootInfo.managerRemoteIds ? { managerRemoteIds: rootInfo.managerRemoteIds } : {}) }]
    const users: RemoteDirectory['users'] = []
    // BFS depuis le département racine (plafond 3 niveaux / 50 départements par niveau, défense contre annuaire anormal)
    let frontier = [rootId]
    for (let depth = 0; depth < 3 && frontier.length > 0; depth++) {
      const next: string[] = []
      for (const deptId of frontier.slice(0, 50)) {
        for (const childId of await this.listSubDepartmentIds(deptId)) {
          const child = await this.getDepartment(childId)
          orgs.push({ remoteId: childId, name: child.name, parentRemoteId: deptId, ...(child.managerRemoteIds ? { managerRemoteIds: child.managerRemoteIds } : {}) })
          next.push(childId)
        }
      }
      frontier = next
    }
    for (const org of orgs) {
      const members = await this.listUsers(org.remoteId)
      for (const member of members) {
        const existing = users.find((user) => user.remoteId === member.remoteId)
        if (existing) {
          // Une personne, plusieurs départements (source de la sémantique de cumul) : le premier département vu entre dans extraOrgRemoteIds, le rattachement principal est corrigé en fin selon deptRemoteIds
          if (existing.orgRemoteId !== org.remoteId && !(existing.extraOrgRemoteIds ?? []).includes(org.remoteId)) {
            existing.extraOrgRemoteIds = [...(existing.extraOrgRemoteIds ?? []), org.remoteId]
          }
          continue
        }
        users.push({ ...member, orgRemoteId: org.remoteId })
      }
    }
    // Correction du rattachement principal : le premier du dept_id_list DingTalk = département principal (l'ordre de parcours de l'annuaire ≠ l'ordre des départements de l'utilisateur, le premier vu peut induire en erreur)
    for (const user of users) {
      const deptIds = (user.deptRemoteIds ?? []).filter((id) => id === user.orgRemoteId || orgs.some((org) => org.remoteId === id))
      if (deptIds.length > 0 && deptIds[0] !== user.orgRemoteId) {
        const rest = [user.orgRemoteId, ...(user.extraOrgRemoteIds ?? [])].filter((id) => id !== deptIds[0])
        user.orgRemoteId = deptIds[0]
        user.extraOrgRemoteIds = [...new Set(rest)]
      }
    }
    return { orgs, users }
  }

  /** Détail d'un département (nom + liste de responsables ; le département racine dept_id=1 renvoie le nom de l'entreprise). */
  private async getDepartment(deptId: string): Promise<{ name: string; managerRemoteIds?: string[] }> {
    const payload = await this.topapi<{ result?: { name?: string; dept_manager_userid_list?: string[] } }>('/topapi/v2/department/get', { dept_id: Number(deptId) })
    const managerRemoteIds = (payload.result?.dept_manager_userid_list ?? []).filter((id) => Boolean(id))
    return { name: payload.result?.name ?? t('部门 {deptId}', { deptId }), ...(managerRemoteIds.length > 0 ? { managerRemoteIds } : {}) }
  }

  /** Liste des IDs des sous-départements de niveau suivant (hors limite du périmètre autorisé). */
  private async listSubDepartmentIds(deptId: string): Promise<string[]> {
    const payload = await this.topapi<{ result?: { dept_id_list?: number[] } }>('/topapi/v2/department/listsubid', { dept_id: Number(deptId) })
    return (payload.result?.dept_id_list ?? []).map(String)
  }

  private async listUsers(deptId: string): Promise<RemoteDirectory['users']> {
    const users: RemoteDirectory['users'] = []
    let cursor = 0
    for (let page = 0; page < 10; page++) {
      const payload = await this.topapi<{
        result?: {
          has_more?: boolean
          next_cursor?: number
          list?: Array<{ unionid?: string; userid?: string; dept_id_list?: number[]; name?: string; job_number?: string; title?: string; email?: string; org_email?: string; active?: boolean }>
        }
      }>('/topapi/v2/user/list', { dept_id: Number(deptId), cursor, size: 100 })
      const result = payload.result ?? {}
      for (const item of result.list ?? []) {
        const remoteId = item.unionid ?? item.userid
        if (!remoteId) continue
        const deptRemoteIds = (item.dept_id_list ?? []).map(String).filter(Boolean)
        users.push({
          remoteId,
          ...(item.userid && item.userid !== remoteId ? { remoteUserId: item.userid } : {}),
          name: item.name ?? remoteId,
          jobNumber: item.job_number || remoteId,
          title: item.title ?? '',
          orgRemoteId: deptId,
          ...(deptRemoteIds.length > 1 ? { deptRemoteIds } : {}),
          email: item.email || item.org_email || '',
          active: item.active ?? true,
        })
      }
      if (!result.has_more) break
      cursor = Number(result.next_cursor ?? cursor + 100)
    }
    return users
  }

  async healthCheck(): Promise<{ ok: boolean; latencyMs: number; message: string; mock?: boolean }> {
    const started = Date.now()
    try {
      await this.corpAccessToken()
      return { ok: true, latencyMs: Date.now() - started, message: t('钉钉 OpenAPI 连通正常（真实模式）'), mock: false }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return { ok: false, latencyMs: Date.now() - started, message, mock: false }
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms))
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class IamService extends Service {
  static readonly provide = 'iam'

  /**
   * Périmètre des implémentations de connecteurs intégrées (providers que applyConnectorMode peut instancier directement).
   * La sauvegarde de configuration est admise au titre « instanciable » et non « actuellement enregistré » — sinon la base de production (sans DEMO_SEED,
   * registre vide) verrait son premier enregistrement d'identifiants DingTalk bloqué par la garde, une impasse « il faut une config pour s'enregistrer, il faut s'enregistrer pour sauver la config ».
   */
  private static readonly BUILTIN_CONNECTOR_PROVIDERS: ReadonlySet<string> = new Set(['dingtalk'])

  /** Registre d'exécution : clé = ID d'instance de configuration (le mock intégré DEMO_SEED utilise 'demo:dingtalk'), provider ne désigne que le type de plateforme. */
  private connectors = new Map<string, OrgConnector>()
  private authProviders = new Map<string, IdentityProviderAdapter>()
  /** Déduplication de la synchronisation automatique : saute si un tour n'est pas terminé sur la même instance de configuration (une synchro plus longue que la période d'inspection n'empile pas de concurrence). */
  private autoSyncing = new Set<string>()
  private autoSyncTimer: ReturnType<typeof setInterval> | undefined

  constructor(ctx: Context) {
    super(ctx, 'iam')
    // Par défaut, aucune source d'identité tierce enregistrée : la base de production masque automatiquement l'entrée de connexion tierce (sso indisponible sans connecteur configuré).
    // L'IdP DingTalk simulé n'est enregistré que dans l'environnement de démonstration DEMO_SEED=1 explicite, pour éviter d'exposer identités de démo/inscription anonyme en base de production.
    if (process.env.DEMO_SEED === '1') {
      this.registerConnector('demo:dingtalk', new DingTalkConnector())
      this.registerAuthProvider('demo:dingtalk', new DingTalkAuthAdapter())
    }
    this.ensureDefaultTenant()
    // Le registre de connecteurs/sources d'identité ne vit qu'en mémoire : après redémarrage, il doit être reconstruit depuis la configuration persistée, sinon les
    // Real*Adapter du mode real ne se rétablissent pas (scan/synchronisation diront « non enregistré »). Multi-entité : restauration entrée par entrée selon l'id d'instance de configuration.
    for (const config of this.connectorConfigs().all()) {
      this.applyConnectorMode(config.id)
    }
    // Synchronisation automatique planifiée des connecteurs (atterrissage d'intervalMinutes) : la « fréquence de synchronisation » de la console était auparavant stockée sans s'exécuter,
    // les changements d'annuaire (arrivée/départ/mutation) n'entraient dans la plateforme qu'après un clic manuel. Après démarrage, le premier tour rattrape les configurations en retard,
    // puis inspection de l'échéance chaque minute ; IAM_CONNECTOR_AUTO_SYNC=off désactive tout (aligné sur l'usage PORTAL_SYNC).
    this.autoSyncTimer = setInterval(() => void this.runDueAutoSyncs(), AUTO_SYNC_TICK_MS)
    this.autoSyncTimer.unref?.() // OPT-P3-02
    setTimeout(() => void this.runDueAutoSyncs(), AUTO_SYNC_BOOT_DELAY_MS)
    ctx.effect(() => () => {
      if (this.autoSyncTimer) clearInterval(this.autoSyncTimer)
    })
  }

  /** Enregistre une instance de connecteur : clé = id d'instance de configuration (multi-entité : enregistrement/désactivation indépendants par entité). */
  registerConnector(key: string, connector: OrgConnector): () => void {
    this.connectors.set(key, connector)
    return () => this.connectors.delete(key)
  }

  /** Enregistre une instance d'Adapter de source d'identité : le flux principal de connexion programme contre l'interface, une nouvelle plateforme n'intruse nulle part. */
  registerAuthProvider(key: string, adapter: IdentityProviderAdapter): () => void {
    this.authProviders.set(key, adapter)
    return () => this.authProviders.delete(key)
  }

  /**
   * Source d'identité par type de plateforme (compatibilité des anciens appels ; en multi-entité, utiliser getAuthProviderByConfig).
   * Priorité à la source enregistrée par instance de configuration (la première dans l'ordre de création) ; l'enregistrement d'amorçage DEMO_SEED préfixé `demo:`
   * n'est qu'un repli pour la fenêtre « pas encore de configuration » — sinon l'instance de démo resterait en tête et masquerait l'instance réelle/nouveau mock après bascule de configuration.
   */
  getAuthProvider(type: string): IdentityProviderAdapter {
    let demoFallback: IdentityProviderAdapter | undefined
    for (const [key, adapter] of this.authProviders) {
      if (adapter.type !== type) continue
      if (key.startsWith('demo:')) {
        demoFallback ??= adapter
        continue
      }
      return adapter
    }
    if (demoFallback) return demoFallback
    throw new Error(t('未注册的身份源：{type}', { type }))
  }

  /** Source d'identité par id d'instance de configuration (connexion/liaison multi-entité initiées par entité). */
  getAuthProviderByConfig(configId: string): IdentityProviderAdapter {
    const adapter = this.authProviders.get(configId)
    if (!adapter) throw new Error(t('未注册的身份源：{type}', { type: configId }))
    return adapter
  }

  /** Collection des liens d'identité tierce (contrainte d'unicité des liens actifs : sous une même entité, une même identité tierce ne peut mapper qu'un compte plateforme). */
  identityLinks(): Collection<IdentityLinkRecord> {
    const collection = this.ctx.opsStorage.collection<IdentityLinkRecord>('iam:identityLinks')
    collection.uniqueOn('identity_link_active', (record) => `${record.provider}|${record.corpId}|${record.providerUserId}`)
    return collection
  }

  /**
   * Recherche par correspondance : localise le compte lié via le dossier normalisé.
   * Avec corpId, la correspondance exacte prime ; sans elle, repli sur la même identité tierce d'un corp quelconque — l'unionId DingTalk désigne la même personne à travers les entreprises,
   * et cela reste compatible avec la continuité d'identité d'un déploiement mono-entité basculant entre mock/real (corpId changeant). En multi-entité avec plusieurs liens pour une même identité, la correspondance exacte l'emporte.
   */
  findLinkByProfile(provider: string, providerUserId: string, corpId?: string): IdentityLinkRecord | undefined {
    const links = this.identityLinks().find((link) => link.provider === provider && link.providerUserId === providerUserId)
    if (corpId === undefined) return links[0]
    return links.find((link) => link.corpId === corpId) ?? links[0]
  }

  /** Établit un lien d'identité (contrainte d'unicité en dernier recours ; user.bindings reste une projection, pratique pour l'affichage de liste). */
  linkIdentity(userId: string, profile: { provider: IdentityLinkRecord['provider']; providerUserId: string; corpId: string; displayName: string; kind?: 'login' | 'staff' }, actor: string): IdentityLinkRecord {
    const user = this.users().get(userId)
    if (!user) throw new Error(t('账号不存在：{id}', { id: userId }))
    const link = this.identityLinks().insert({
      id: newId('idl'),
      provider: profile.provider,
      providerUserId: profile.providerUserId,
      corpId: profile.corpId,
      userId,
      displayName: profile.displayName,
      linkedAt: new Date().toISOString(),
      linkedBy: actor,
      ...(profile.kind ? { kind: profile.kind } : {}),
    })
    // L'intention de liaison manuelle recouvre la décision de déliaison antérieure : la synchronisation ne la considère plus comme une entité « que l'utilisateur ne veut pas ».
    // L'exemption n'est levée qu'en écrivant le « lien de connexion » — la synchronisation réécrivant un lien de fonction (staff) ne constitue pas une intention de liaison manuelle,
    // sinon une seule synchronisation suffirait à balayer la décision de déliaison (l'utilisateur verrait « clic sans effet »).
    if (profile.kind !== 'staff') {
      this.clearBindingExemption(userId, profile.provider, profile.corpId)
    }
    // Reconstruction de la projection (bindings n'est qu'un affichage, la source de fait est identityLinks) : toujours recalculée depuis les liens de connexion,
    // pas d'ajout incrémental ici — un ajout incrémental compterait aussi les liens de fonction (staff) comme « comptes tierces liés »,
    // et divergerait du référentiel de reconstruction post-déliaison (déliaison vide, écriture rajoute, l'utilisateur voit une déliaison sans effet).
    // Doit venir après le traitement d'exemption : la reconstruction filtre les entités selon les exemptions, il faut d'abord lever l'exemption pour afficher la nouvelle liaison.
    this.rebuildBindingsProjection(userId)
    return link
  }

  /**
   * Délie un lien d'identité (et reconstruit la projection depuis la source de fait).
   *
   * Quatre points à faire absolument juste (mise en conformité lors de la mise en ligne de la capacité de déliaison/remplacement 2026-10-22) :
   *   1. Multi-entité : un même provider peut avoir des liens de plusieurs corpId (lien unionId + lien userid),
   *      passer corpId ne supprime que les liens de cette entité ; sans corpId = suppression de tous les liens du provider (sémantique explicite, l'appelant confirme).
   *   2. Source de fait : `findOne` + `remove` ne supprime qu'un lien, les autres liens du même provider deviennent fantômes — suppression intégrale par provider
   *      (ou provider+corpId).
   *   3. Projection : bindings doit être recalculé depuis les identityLinks restants, sans filtre par provider couperet —
   *      sinon « délier une entité » effacerait aussi la ligne d'affichage de l'autre entité alors que le lien existe toujours.
   *   4. Rôle du lien : ne délier que le « lien d'identité de connexion » (kind≠staff). Le lien d'identité de fonction (staff) décrit le fait de poste
   *      de la personne dans l'organisation (cartographie des responsables de département et recherche d'identité des permissions de données NAS en dépendent), ce n'est pas un identifiant de connexion —
   *      l'effacer aussi casserait la recherche inversée des responsables et ferait retomber le routage d'approbation sur le département parent (régression constatée).
   */
  unlinkIdentity(userId: string, provider: IdentityLinkRecord['provider'], corpId?: string, kind?: 'login' | 'staff'): boolean {
    const targets = this.identityLinks().find((item) => item.userId === userId
      && item.provider === provider
      && (corpId === undefined || (item.corpId ?? '') === corpId)
      && (kind === undefined ? item.kind !== 'staff' : item.kind === kind))
    if (targets.length === 0) return false
    // Consigne l'exemption (à la granularité d'entité réellement supprimée) : sinon la synchronisation du connecteur suivante recollerait le lien via le matricule.
    const exempted = new Set<string>((this.users().get(userId)?.bindingExemptions ?? []))
    for (const link of targets) exempted.add(`${provider}|${link.corpId ?? ''}`)
    for (const link of targets) this.identityLinks().remove(link.id)
    this.users().update(userId, { bindingExemptions: [...exempted] })
    // La reconstruction de la projection exclut les entités exemptées : après déliaison, l'entité ne s'affiche plus comme « liée »,
    // même si le lien de fonction subsiste (le fait de fonction n'a pas été effacé, il n'est simplement plus affiché comme « liaison connectable »).
    this.rebuildBindingsProjection(userId)
    return true
  }

  /** Lève l'exemption de liaison (appelé en cas de succès de re-scan/liaison manuelle : l'intention de liaison humaine recouvre la décision de déliaison antérieure). */
  private clearBindingExemption(userId: string, provider: string, corpId: string): void {
    const user = this.users().get(userId)
    if (!user?.bindingExemptions?.length) return
    const key = `${provider}|${corpId}`
    if (!user.bindingExemptions.includes(key)) return
    const next = user.bindingExemptions.filter((item) => item !== key)
    this.users().update(userId, { bindingExemptions: next.length ? next : undefined })
  }

  /** Reconstruit la projection user.bindings depuis identityLinks (source de fait) : une ligne par entité provider+corpId. */
  private rebuildBindingsProjection(userId: string): void {
    const user = this.users().get(userId)
    if (!user) return
    const links = this.identityLinks().find((item) => item.userId === userId)
    // Les entités exemptées ne sont plus affichées (la décision de déliaison humaine prime sur l'existence du lien de fonction)
    const exempted = new Set<string>(this.users().get(userId)?.bindingExemptions ?? [])
    const visible = links.filter((link) => !exempted.has(`${link.provider}|${link.corpId ?? ''}`))
    // Une chaîne représentative par entité (provider+corpId) : lien de connexion prioritaire ; à défaut, repli sur le lien de fonction
    // (les données préexistantes n'ont que des liens non marqués avant le remplissage de kind ; le repli maintient la sémantique d'affichage existante « l'entité reste liée »).
    const seen = new Map<string, IdentityLinkRecord>()
    for (const link of visible) {
      const key = `${link.provider}|${link.corpId ?? ''}`
      const current = seen.get(key)
      if (!current) { seen.set(key, link); continue }
      // Lien de connexion prioritaire sur lien de fonction
      if (current.kind === 'staff' && link.kind !== 'staff') seen.set(key, link)
    }
    this.users().update(userId, {
      bindings: [...seen.values()].map((link) => ({
        provider: link.provider,
        unionId: link.providerUserId,
        displayName: link.displayName,
        boundAt: link.linkedAt,
        ...(link.corpId ? { corpId: link.corpId } : {}),
      })),
    })
  }

  /** Liste des instances de connecteurs enregistrées (multi-entité : porte configId/nom d'entité, provider ne désigne que le type de plateforme). */
  connectorProviders(): Array<{ configId: string; provider: string; label: string; name?: string }> {
    return [...this.connectors.entries()].map(([configId, connector]) => {
      const name = this.connectorConfigById(configId)?.name
      return { configId, provider: connector.provider, label: t(connector.label), ...(name !== undefined ? { name } : {}) }
    })
  }

  // -- Collections ---------------------------------------------------------------

  orgs(): Collection<OrgRecord> {
    const collection = this.ctx.opsStorage.collection<OrgRecord>('iam:orgs')
    // L'unicité de nom au même niveau est partitionnée par connecteur : les organisations manuelles/historiques (sans connectorId) gardent l'ancien référentiel,
    // les départements homonymes synchronisés par des entités différentes (deux entreprises ont souvent le même nom) tombent chacune en base sans collision de clé.
    collection.uniqueOn('org_same_level_name', (org) => `${String(org.customFields['connectorId'] ?? '')}|${org.parentId ?? '-'}|${org.name}`)
    return collection
  }

  users(): Collection<UserRecord> {
    const collection = this.ctx.opsStorage.collection<UserRecord>('iam:users')
    collection.uniqueOn('user_username', (user) => user.username)
    return collection
  }

  roles(): Collection<RoleRecord> {
    return this.ctx.opsStorage.collection<RoleRecord>('iam:roles')
  }

  groups(): Collection<UserGroupRecord> {
    return this.ctx.opsStorage.collection<UserGroupRecord>('iam:groups')
  }

  connectorConfigs(): Collection<ConnectorConfigRecord> {
    const collection = this.ctx.opsStorage.collection<ConnectorConfigRecord>('iam:connectors')
    // Multi-entité : un même provider peut connecter plusieurs entreprises, mais provider|corpId est unique au niveau moteur (entité dupliquée rejetée)
    collection.uniqueOn('connector_provider_corp', (config) => `${config.provider}|${config.corpId}`)
    return collection
  }

  conflicts(): Collection<SyncConflictRecord> {
    return this.ctx.opsStorage.collection<SyncConflictRecord>('iam:conflicts')
  }

  tenants(): Collection<TenantRecord> {
    const collection = this.ctx.opsStorage.collection<TenantRecord>('iam:tenants')
    collection.uniqueOn('tenant_name', (tenant) => tenant.name)
    return collection
  }

  /** Jeu minimal multi-tenant : tenant par défaut de repli (toutes les données préexistantes tombent dans t_default). */
  ensureDefaultTenant(): TenantRecord {
    const existing = this.tenants().get(DEFAULT_TENANT_ID)
    if (existing) return existing
    return this.tenants().insert({
      id: DEFAULT_TENANT_ID,
      name: '默认租户',
      status: 'active',
      plan: 'standard',
    })
  }

  // -- Autorisation au niveau scénario (livraison IAW 6-1) ---------------------------------------------

  scenePolicies(): Collection<ScenePolicyRecord> {
    const collection = this.ctx.opsStorage.collection<ScenePolicyRecord>('iam:scenePolicies')
    collection.uniqueOn('scene_org', (policy) => `${policy.sceneCode}|${policy.orgId ?? ''}`)
    return collection
  }

  /**
   * Enregistre une politique d'autorisation de scénario (upsert par sceneCode+orgId, verrou optimiste version) :
   * refuse si expectedVersion diffère du version existant (réconciliation d'éditions concurrentes) ; la création ne porte pas expectedVersion.
   */
  upsertScenePolicy(input: { sceneCode: string; orgId?: string; entries: ScenePolicyEntry[]; note?: string; expectedVersion?: number }): ScenePolicyRecord {
    if (!input.sceneCode?.trim()) throw new Error(t('场景策略 sceneCode 必填（如 QB01-A-2-5）'))
    if (!Array.isArray(input.entries) || input.entries.length === 0) throw new Error(t('场景策略 entries 至少一条（空策略请用 DELETE 移除）'))
    for (const entry of input.entries) {
      if (!['role', 'user'].includes(entry.principalType)) throw new Error(t('策略条目 principalType 非法：{value}（role/user）', { value: entry.principalType }))
      if (!entry.principalId?.trim()) throw new Error(t('策略条目 principalId 必填（roleId/userId/*）'))
      if (!Array.isArray(entry.actions) || entry.actions.length === 0) throw new Error(t('策略条目 actions 至少一项'))
      if (!['allow', 'deny'].includes(entry.effect)) throw new Error(t('策略条目 effect 非法：{value}（allow/deny）', { value: entry.effect }))
      if (entry.principalType === 'role' && entry.principalId !== '*' && !this.roles().get(entry.principalId)) {
        throw new Error(t('策略条目引用的角色不存在：{id}', { id: entry.principalId }))
      }
      if (entry.principalType === 'user' && entry.principalId !== '*' && !this.users().get(entry.principalId)) {
        throw new Error(t('策略条目引用的用户不存在：{id}', { id: entry.principalId }))
      }
    }
    const existing = this.scenePolicies().findOne((item) => item.sceneCode === input.sceneCode && (item.orgId ?? '') === (input.orgId ?? ''))
    if (existing) {
      if (input.expectedVersion !== undefined && input.expectedVersion !== existing.version) {
        throw new Error(t('场景策略版本冲突：当前 v{current}，请求基于 v{expected}（请刷新后重试）', { current: existing.version, expected: input.expectedVersion }))
      }
      const updated = this.scenePolicies().update(existing.id, {
        entries: input.entries,
        ...(input.note !== undefined ? { note: input.note } : {}),
        version: existing.version + 1,
      })
      this.ctx.platformBus.emit(PlatformEvents.IamScenePolicyChanged, { sceneCode: input.sceneCode, orgId: input.orgId ?? null, policyId: updated.id, version: updated.version, action: 'updated' })
      return updated
    }
    const created = this.scenePolicies().insert({
      id: newId('scp'), sceneCode: input.sceneCode,
      ...(input.orgId ? { orgId: input.orgId } : {}),
      entries: input.entries,
      ...(input.note ? { note: input.note } : {}),
      version: 1,
    })
    this.ctx.platformBus.emit(PlatformEvents.IamScenePolicyChanged, { sceneCode: input.sceneCode, orgId: input.orgId ?? null, policyId: created.id, version: 1, action: 'created' })
    return created
  }

  deleteScenePolicy(id: string): { deleted: boolean } {
    const policy = this.scenePolicies().get(id)
    if (!policy) throw new Error(t('场景策略不存在：{id}', { id }))
    this.scenePolicies().remove(id)
    this.ctx.platformBus.emit(PlatformEvents.IamScenePolicyChanged, { sceneCode: policy.sceneCode, orgId: policy.orgId ?? null, policyId: id, action: 'deleted' })
    return { deleted: true }
  }

  /**
   * iam.check(scene, action) (livraison IAW 6-1) : jugement ABAC à la dimension scénario.
   * Ordre de jugement : ① scénario sans politique → default (retombe sur hasPermission, chaîne de rôles, comportement historique inchangé) ;
   * ② entrée deny atteinte (utilisateur/rôle/joker × action) → deny ; ③ entrée allow atteinte → allow ; ④ le reste → deny (fail-closed).
   * Ce jugement est un resserrage à grain fin par scénario, il ne remplace pas le RBAC de rôles : l'appelant doit aussi satisfaire hasPermission(point de permission de base).
   */
  checkScene(userId: string, sceneCode: string, action: string): SceneCheckDecision {
    const user = this.users().get(userId)
    if (!user) {
      return { decision: 'deny', reason: t('用户不存在：{userId}', { userId }), sceneCode, action }
    }
    const policies = this.scenePolicies().all().filter((item) =>
      item.sceneCode === sceneCode && ((item.orgId ?? '') === '' || item.orgId === user.orgId))
    if (policies.length === 0) {
      return { decision: 'default', reason: t('场景未配置授权策略，回落角色 RBAC 与部门范围权限（存量口径）'), sceneCode, action }
    }
    const matches = (entry: ScenePolicyEntry): boolean =>
      (entry.principalId === '*' && entry.principalType === 'role')
      || (entry.principalType === 'user' && (entry.principalId === '*' || entry.principalId === userId))
      || (entry.principalType === 'role' && user.roleIds.includes(entry.principalId))
    const actionHit = (entry: ScenePolicyEntry): boolean => entry.actions.includes('*') || entry.actions.includes(action)
    for (const policy of policies) {
      for (const entry of policy.entries) {
        if (entry.effect === 'deny' && matches(entry) && actionHit(entry)) {
          return { decision: 'deny', reason: t('场景策略 deny 命中（policy={policyId}）', { policyId: policy.id }), policyId: policy.id, sceneCode, action }
        }
      }
    }
    for (const policy of policies) {
      for (const entry of policy.entries) {
        if (entry.effect === 'allow' && matches(entry) && actionHit(entry)) {
          return { decision: 'allow', reason: t('场景策略 allow 命中（policy={policyId}）', { policyId: policy.id }), policyId: policy.id, sceneCode, action }
        }
      }
    }
    const policy = policies[0]!
    return { decision: 'deny', reason: t('场景已配置授权策略且无命中条目（fail-closed，policy={policyId}）', { policyId: policy.id }), policyId: policy.id, sceneCode, action }
  }

  createTenant(input: { name: string; plan?: TenantRecord['plan'] }): TenantRecord {
    if (!input.name?.trim()) throw new Error(t('租户名称不能为空'))
    if (this.tenants().findOne((tenant) => tenant.name === input.name)) throw new Error(t('租户已存在：{name}', { name: input.name }))
    return this.tenants().insert({
      id: newId('t'),
      name: input.name,
      status: 'active',
      plan: input.plan ?? 'trial',
    })
  }

  /** Résolution du tenant : org → tenant ; défaut t_default (entrée unifiée des rapports usage/consommation). */
  tenantOfOrg(orgId: string): string {
    return this.orgs().get(orgId)?.tenantId ?? DEFAULT_TENANT_ID
  }

  // -- Organisations ---------------------------------------------------------------

  orgTree(): OrgTreeNode[] {
    const nodes = new Map<string, OrgTreeNode>()
    for (const org of this.orgs().all()) {
      nodes.set(org.id, { ...org, children: [] })
    }
    const roots: OrgTreeNode[] = []
    for (const node of nodes.values()) {
      if (node.parentId && nodes.has(node.parentId)) {
        nodes.get(node.parentId)!.children.push(node)
      } else {
        roots.push(node)
      }
    }
    const sortRec = (list: OrgTreeNode[]): OrgTreeNode[] => {
      list.sort((a, b) => a.order - b.order || a.name.localeCompare(b.name, 'zh'))
      for (const item of list) sortRec(item.children)
      return list
    }
    return sortRec(roots)
  }

  createOrg(input: { name: string; parentId?: string | null; order?: number; customFields?: Record<string, string>; tenantId?: string; leaderUserIds?: string[] }, actor?: UserManageActor): OrgRecord {
    if (!input.name?.trim()) throw new Error(t('组织名称不能为空'))
    const parentId = input.parentId ?? null
    if (parentId && !this.orgs().get(parentId)) throw new Error(t('父组织不存在：{id}', { id: parentId }))
    // Le point de montage est contraint au sous-arbre organisationnel de l'opérateur (même référentiel que la gestion de comptes N1) ; les organisations de premier niveau (parentId=null) ne sont créables que par l'admin plateforme
    this.assertManageScope(actor, parentId ?? undefined, t('创建组织'))
    // Détection des doublons homonymes au même niveau selon le même référentiel que la clé unique moteur : partition par rattachement connecteur (les organisations manuelles sans connectorId forment une partition).
    const ownerKey = input.customFields?.['connectorId'] ?? ''
    const duplicate = this.orgs().findOne((org) => org.name === input.name && org.parentId === parentId
      && (org.customFields['connectorId'] ?? '') === ownerKey)
    if (duplicate) throw new Error(t('同级下已存在同名组织「{name}」', { name: input.name }))
    const record = this.orgs().insert({
      id: newId('org'),
      name: input.name.trim(),
      parentId,
      order: input.order ?? this.orgs().count() + 1,
      status: 'active',
      customFields: input.customFields ?? {},
      ...(input.tenantId !== undefined ? { tenantId: input.tenantId } : {}),
      ...(input.leaderUserIds !== undefined ? { leaderUserIds: input.leaderUserIds, leaderSource: 'manual' } : {}),
    })
    this.ctx.platformBus.emit(PlatformEvents.OrgChanged, { kind: 'create', orgId: record.id, name: record.name })
    return record
  }

  /** Maintient le responsable d'organisation (complétion console / issue de sortie après alerte leaderVacant). Un tableau vide vide le champ et restaure le suivi de synchronisation. */
  setOrgLeaders(id: string, leaderUserIds: string[]): OrgRecord {
    this.requireOrg(id)
    const unique = [...new Set(leaderUserIds)]
    for (const userId of unique) {
      if (!this.users().get(userId)) throw new Error(t('负责人账号不存在：{id}', { id: userId }))
    }
    // Liaison manuelle = verrouillage : la synchronisation du connecteur ne remplace plus (il sert à compléter les départements sans responsable côté DingTalk) ; vider = restaure le suivi de synchronisation.
    return unique.length > 0
      ? this.orgs().update(id, { leaderUserIds: unique, leaderSource: 'manual' })
      : this.orgs().update(id, { leaderUserIds: [], leaderSource: 'sync' })
  }

  /** Lecture de compatibilité : ancien référentiel du responsable customFields['leaderUserIds'] (séparé par virgules), le champ structuré prime. */
  leadersOf(orgId: string): string[] {
    const org = this.orgs().get(orgId)
    if (!org) return []
    if (Array.isArray(org.leaderUserIds)) return org.leaderUserIds
    const legacy = String(org.customFields?.['leaderUserIds'] ?? '').trim()
    return legacy ? legacy.split(',').map((item) => item.trim()).filter(Boolean) : []
  }

  renameOrg(id: string, name: string, actor?: UserManageActor): OrgRecord {
    const org = this.requireOrg(id)
    this.assertManageScope(actor, id, t('重命名组织'))
    if (!name?.trim()) throw new Error(t('组织名称不能为空'))
    const trimmed = name.trim()
    // Détection de doublons même référentiel que createOrg : refus des homonymes seulement au sein de la même partition de rattachement connecteur.
    const duplicate = this.orgs().findOne((item) => item.id !== id && item.name === trimmed && item.parentId === org.parentId
      && (item.customFields['connectorId'] ?? '') === (org.customFields['connectorId'] ?? ''))
    if (duplicate) throw new Error(t('同级下已存在同名组织「{name}」', { name: trimmed }))
    const updated = this.orgs().update(id, { name: trimmed })
    this.ctx.platformBus.emit(PlatformEvents.OrgChanged, { kind: 'rename', orgId: id, name: trimmed })
    return updated
  }

  /** Déplace une organisation (glisser-déposer de mutation), détection de cycle incluse ; l'organisation et le nouveau parent doivent tomber dans le sous-arbre de l'opérateur (contre le montage hors périmètre par déplacement). */
  moveOrg(id: string, newParentId: string | null, actor?: UserManageActor): OrgRecord {
    this.requireOrg(id)
    this.assertManageScope(actor, id, t('移动组织'))
    this.assertManageScope(actor, newParentId ?? undefined, t('移动组织到目标上级'))
    if (newParentId) {
      if (newParentId === id) throw new Error(t('不能将组织移动到自身之下'))
      // Validation d'existence du parent (QA SEC-03) : s'il n'existe pas, la détection de cycle ci-dessous laisserait passer silencieusement et produirait un parentId suspendu
      if (!this.orgs().get(newParentId)) throw new Error(t('父组织不存在：{id}', { id: newParentId }))
      let cursor: string | null = newParentId
      while (cursor) {
        if (cursor === id) throw new Error(t('不允许形成组织环'))
        cursor = this.orgs().get(cursor)?.parentId ?? null
      }
    }
    const updated = this.orgs().update(id, { parentId: newParentId })
    this.ctx.platformBus.emit(PlatformEvents.OrgChanged, { kind: 'move', orgId: id })
    return updated
  }

  /**
   * Supprime une organisation. Par défaut, seules les organisations vides sont permises (sans sous-organisations ni comptes directs) ;
   * cascade=true supprime tout le sous-arbre : les organisations du sous-arbre sont retirées, les comptes directement montés remontent vers
   * la plus proche organisation parente survivante (le parent de la racine supprimée ; en supprimant une organisation racine, remonte vers la première racine survivante).
   */
  deleteOrg(id: string, options?: { cascade?: boolean }, actor?: UserManageActor): { deleted: boolean; removedOrgs: number; movedUsers: number; fallbackOrgId?: string } {
    const org = this.requireOrg(id)
    this.assertManageScope(actor, id, t('删除组织'))
    if (!options?.cascade) {
      if (this.orgs().find((item) => item.parentId === id).length > 0) throw new Error(t('存在子组织，无法删除；请改用「连同子组织一键删除」'))
      if (this.users().find((user) => user.orgId === id).length > 0) throw new Error(t('组织下仍有账号，无法删除；请改用「连同子组织一键删除」（账号将上移到上级组织）'))
      this.orgs().remove(id)
      this.ctx.platformBus.emit(PlatformEvents.OrgChanged, { kind: 'delete', orgId: id, name: org.name })
      return { deleted: true, removedOrgs: 1, movedUsers: 0 }
    }
    const subtree = this.orgSubtreeIds(id)
    const subtreeSet = new Set(subtree)
    // Destination des comptes : le parent de la racine supprimée est nécessairement hors sous-arbre (arbre sans cycle) ; en supprimant une racine, les comptes tombent sur la première racine survivante
    const fallbackOrgId = org.parentId ?? this.orgs().find((item) => !subtreeSet.has(item.id) && !item.parentId)[0]?.id ?? null
    const movedUsers = this.users().find((user) => subtreeSet.has(user.orgId))
    if (!fallbackOrgId && movedUsers.length > 0) throw new Error(t('删除后将没有任何组织可挂载账号，请先把账号迁移到其他组织再删除'))
    if (fallbackOrgId) {
      for (const user of movedUsers) this.users().update(user.id, { orgId: fallbackOrgId })
    }
    for (const orgId of subtree) {
      if (this.orgs().get(orgId)) this.orgs().remove(orgId)
    }
    this.ctx.platformBus.emit(PlatformEvents.OrgChanged, {
      kind: 'delete', orgId: id, name: org.name, cascade: true,
      removedOrgs: subtree.length, movedUsers: movedUsers.length,
    })
    return { deleted: true, removedOrgs: subtree.length, movedUsers: movedUsers.length, ...(fallbackOrgId ? { fallbackOrgId } : {}) }
  }

  private requireOrg(id: string): OrgRecord {
    const org = this.orgs().get(id)
    if (!org) throw new Error(t('组织不存在：{id}', { id }))
    return org
  }

  /** Ensemble des ids du sous-arbre organisationnel (périmètre des permissions de données). */
  orgSubtreeIds(rootId: string): string[] {
    const result: string[] = [rootId]
    const walk = (parentId: string): void => {
      for (const org of this.orgs().find((item) => item.parentId === parentId)) {
        result.push(org.id)
        walk(org.id)
      }
    }
    walk(rootId)
    return result
  }

  // -- Comptes ---------------------------------------------------------------

  /**
   * Validation du rattachement organisationnel (QA A-03/N1 fail-closed) : un non-admin plateforme (sans '*') ne gère que les comptes/organisations de son sous-arbre ;
   * les principaux machine et quiconque sans organisation localisable sont refusés. actor.orgId (injection `_actor` du pont d'outils)
   * prime ; à défaut, organisation retrouvée via le dossier du compte userId. Actor absent = refus systématique : les entrées externes (routes REST de gestion et pont d'outils)
   * doivent porter l'identité réelle de l'appelant ; les chaînes internes de service (graines/synchronisation tierce/auto-enregistrement SSO) passent explicitement SYSTEM_ACTOR.
   */
  private assertManageScope(actor: UserManageActor | undefined, targetOrgId: string | undefined, action: string): void {
    if (!actor) {
      throw new OrgScopeDeniedError(t('账号管理操作缺少操作者身份（{action}）：外部入口必须携带可归因调用者，内部系统链路请显式传入系统身份（组织隔离，QA A-03）', { action }))
    }
    if (actor.permissions.includes('*')) return
    const actorOrgId = actor.orgId ?? (actor.userId ? this.users().get(actor.userId)?.orgId : undefined)
    if (!actorOrgId || !targetOrgId || !this.orgSubtreeIds(actorOrgId).includes(targetOrgId)) {
      throw new OrgScopeDeniedError(t('跨组织账号操作被拒绝（{action}）：目标不在操作者的组织子树内（组织隔离，QA A-03）', { action }))
    }
  }

  /** Robustesse du mot de passe (QA A-08) : référentiel unifié création/réinitialisation — ≥8 caractères sans chinois (la création n'avait auparavant aucun contrôle, '123' était créable et connectable). */
  private assertPasswordStrength(password: string): void {
    if (password.trim().length < 8) throw new Error(t('口令长度不得少于 8 位'))
    if (/[\u4e00-\u9fff]/.test(password)) throw new Error(t('口令不得包含中文'))
  }

  /** Crée un compte : sans mot de passe explicite, génère un mot de passe initial aléatoire (renvoyé une seule fois à cet appel, à transmettre sûrement à la personne). */
  createUser(input: {
    username: string
    displayName: string
    orgId: string
    email?: string
    phone?: string
    title?: string
    roleIds?: string[]
    password?: string
    jobNumber?: string
  }, actor?: UserManageActor): { user: UserRecord; initialPassword?: string } {
    if (!input.username?.trim()) throw new Error(t('用户名不能为空'))
    if (!/^[a-z0-9_.-]+$/i.test(input.username)) throw new Error(t('用户名仅支持字母、数字与 _ . -'))
    if (this.users().findOne((user) => user.username === input.username)) throw new Error(t('用户名已存在：{username}', { username: input.username }))
    if (!this.orgs().get(input.orgId)) throw new Error(t('组织不存在：{id}', { id: input.orgId }))
    this.assertManageScope(actor, input.orgId, t('创建账号'))
    // P0-02 : la création de compte avec roleIds subit aussi le plafond d'autorisabilité (sinon contournement d'assignRoles en écriture directe de rôles)
    if (input.roleIds?.length) this.assertGrantCeiling(actor, this.resolveRolePermissions(input.roleIds), t('创建账号'))
    if (input.password !== undefined) this.assertPasswordStrength(input.password)
    const password = input.password ?? generateSecret('init')
    const user = this.users().insert({
      id: newId('usr'),
      username: input.username,
      displayName: input.displayName || input.username,
      email: input.email ?? `${input.username}@yuanbingke.com`,
      phone: input.phone ?? '',
      orgId: input.orgId,
      title: input.title ?? '',
      status: 'pending',
      roleIds: input.roleIds ?? [],
      passwordSalt: '',
      passwordHash: hashPasswordScrypt(password),
      bindings: [],
      // Marqué seulement si l'appelant a explicitement donné un mot de passe (quelqu'un a le clair) ; un initial aléatoire non distribué ne compte pas comme connu
      ...(input.password !== undefined ? { passwordKnown: true } : {}),
      ...(input.jobNumber !== undefined ? { jobNumber: input.jobNumber } : {}),
    })
    return input.password ? { user } : { user, initialPassword: password }
  }

  /** Réinitialise le mot de passe : sans password, génère un initial aléatoire ; avec, fixe le mot de passe indiqué (le clair n'est renvoyé que cette fois dans les deux cas). */
  resetPassword(id: string, password?: string, actor?: UserManageActor): { user: UserRecord; initialPassword: string } {
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('重置口令'))
    if (user.status === 'deactivated') throw new Error(t('账号已注销，无法重置口令'))
    if (password !== undefined) this.assertPasswordStrength(password)
    const next = password ?? generateSecret('init')
    // Le clair du mot de passe réinitialisé est réaffiché une fois à l'opérateur (transmis par un humain), donc considéré « mot de passe connu »
    this.users().update(id, { passwordSalt: '', passwordHash: hashPasswordScrypt(next), passwordKnown: true })
    // P1-08 (revue de sécurité 2026-10-31) : la réinitialisation révoque en cascade toutes les sessions existantes du compte — l'ancien access expire immédiatement,
    // l'ancien refresh ne peut plus échanger de jeton, les jetons délégués adossés sont révoqués dans le même lot. Découplé par événement de plateforme (le couplage
    // inter-plugins ne se câble pas en direct, authn souscrit puis exécute la révocation avec audit), même canal que « geler = révoquer ».
    this.ctx.platformBus.emit(PlatformEvents.UserPasswordReset, { userId: id, username: user.username })
    return { user: this.users().get(id)!, initialPassword: next }
  }

  importUsers(items: Array<{ username: string; displayName: string; orgId: string; title?: string; email?: string }>, actor?: UserManageActor): { created: UserRecord[]; skipped: string[] } {
    const created: UserRecord[] = []
    const skipped: string[] = []
    for (const item of items) {
      if (this.users().findOne((user) => user.username === item.username)) {
        skipped.push(item.username)
        continue
      }
      created.push(this.createUser(item, actor).user)
    }
    return { created, skipped }
  }

  activateUser(id: string, actor?: UserManageActor): UserRecord {
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('激活账号'))
    if (user.status !== 'pending') throw new Error(t('仅待激活账号可激活'))
    return this.users().update(id, { status: 'active' })
  }

  freezeUser(id: string, reason: string, actor?: UserManageActor): UserRecord {
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('冻结账号'))
    if (!reason?.trim()) throw new Error(t('冻结必须填写原因（审计要求）'))
    const updated = this.users().update(id, { status: 'frozen', frozenReason: reason })
    this.ctx.platformBus.emit(PlatformEvents.UserFrozen, { userId: id, username: updated.username, reason })
    return updated
  }

  unfreezeUser(id: string, actor?: UserManageActor): UserRecord {
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('解冻账号'))
    const updated = this.users().update(id, { status: 'active', frozenReason: undefined })
    this.ctx.platformBus.emit(PlatformEvents.UserActivated, { userId: id })
    return updated
  }

  deactivateUser(id: string, reason: string, actor?: UserManageActor): UserRecord {
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('注销账号'))
    if (!reason?.trim()) throw new Error(t('注销必须填写原因'))
    const updated = this.users().update(id, { status: 'deactivated', frozenReason: reason })
    this.ctx.platformBus.emit(PlatformEvents.UserFrozen, { userId: id, username: updated.username, reason: t('注销：{reason}', { reason }) })
    return updated
  }

  updateUser(id: string, patch: Partial<Pick<UserRecord, 'displayName' | 'email' | 'phone' | 'title' | 'orgId' | 'accountType' | 'primaryOrgId'>>, actor?: UserManageActor): UserRecord {
    // Convergence de la liste blanche (QA SEC-01) : l'édition PATCH n'accepte que les champs de dossier, cohérent avec la signature TS ci-dessus ;
    // laisser passer status/passwordHash/passwordSalt/username/id tels quels en base permettrait le changement d'état non autorisé, l'injection de mot de passe
    // (prise de contrôle du compte) — refus explicite en nommant les champs rejetés (refus honnête, pas d'ignorance silencieuse).
    const allowedFields = ['displayName', 'email', 'phone', 'title', 'orgId', 'accountType', 'primaryOrgId']
    const rejected = Object.keys(patch ?? {}).filter((key) => !allowedFields.includes(key))
    if (rejected.length > 0) {
      throw new Error(t('账号编辑不接受以下字段：{fields}（状态请走冻结/解冻/激活/注销端点，口令请走重置口令端点，角色请走角色分配接口）', { fields: rejected.join('、') }))
    }
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('修改账号'))
    if (patch.orgId) {
      if (!this.orgs().get(patch.orgId)) throw new Error(t('组织不存在：{id}', { id: patch.orgId }))
      // L'organisation cible de migration subit aussi la contrainte de sous-arbre de l'opérateur (contre le déplacement d'un compte hors du domaine d'isolement via « changer le rattachement »)
      this.assertManageScope(actor, patch.orgId, t('迁移账号组织'))
    }
    if (patch.primaryOrgId && !this.orgs().get(patch.primaryOrgId)) throw new Error(t('主归属组织不存在：{id}', { id: patch.primaryOrgId }))
    if (patch.accountType !== undefined && !['internal', 'external', 'suspended-review'].includes(patch.accountType)) {
      throw new Error(t('非法账号类型：{type}', { type: patch.accountType }))
    }
    return this.users().update(id, patch)
  }

  deleteUser(id: string, actor?: UserManageActor): boolean {
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('删除账号'))
    if (user.status !== 'deactivated') throw new Error(t('仅已注销账号可物理删除'))
    return this.users().remove(id)
  }

  /**
   * Lie une identité tierce : la source de fait est identityLinks (contrainte d'unicité moteur), user.bindings est une projection.
   *
   * Revue de sécurité P1-05 (2026-10-31) :
   *   ① La liaison pour autrui est resserrée au super-admin plateforme ('*') — la liaison manuelle écrit un unionId quelconque déclaré par l'appelant,
   *      si un admin d'organisation pouvait accrocher sa propre identité tierce au compte d'autrui, il pourrait prendre ce compte via la connexion tierce (super-admin inclus).
   *      La voie conforme de l'admin d'organisation est le scan d'autorisation (/api/auth/sso/bind/authorize, l'identité liée = la personne qui scanne)
   *      et la synchronisation du connecteur ; l'auto-liaison sur ce endpoint (id = l'opérateur lui-même) n'est pas limitée.
   *   ② Suppression du faux « code de vérification secondaire » — l'ancienne logique ne vérifiait que '000000'/6 chiffres, sans jamais correspondre à un défi réel
   *      (le code ne servait à rien). Le paramètre verifyCode reste reçu (compatibilité front), sans sémantique de sécurité déclarée.
   */
  bindThirdParty(id: string, binding: { provider: ThirdPartyBinding['provider']; unionId: string; displayName: string; corpId?: string; verifyCode?: string }, actor?: UserManageActor): UserRecord {
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('绑定三方身份'))
    const selfBind = actor?.userId !== undefined && actor.userId === id
    if (!selfBind && !actor?.permissions.includes('*')) {
      throw new OrgScopeDeniedError(t('为其他账号手工绑定三方身份仅限平台超级管理员（防借三方登录接管他人账号，安全审查 P1-05）；请走扫码授权或连接器同步通道'))
    }
    // corpId prend par défaut le corpId de l'entité déjà configurée du provider (la liaison manuelle de la console vise une entité déjà connectée),
    // garantissant la contrainte d'unicité « une personne, un compte » (provider|corpId|providerUserId) vis-à-vis des liens existants.
    const corpId = binding.corpId ?? this.connectorConfig(binding.provider)?.corpId ?? ''
    // Le jugement d'occupation se fonde sur les « liens de connexion » d'identityLinks (la projection peut être en retard après reconstruction de déliaison) :
    // un lien de connexion existant pour le même provider+corpId = déjà lié. Le lien de fonction (staff) n'occupe pas —
    // il décrit un fait de poste ; après déliaison de l'identité de connexion, relier une nouvelle identité de connexion est permis (le lien de fonction reste intact).
    const occupied = this.identityLinks().findOne((link) => link.userId === id
      && link.provider === binding.provider
      && link.kind !== 'staff'
      && (link.corpId ?? '') === corpId)
    if (occupied) {
      throw new Error(t('该账号已绑定{provider}身份，请先解绑', { provider: binding.provider }))
    }
    // Une personne, un compte : si l'identité tierce cible est déjà liée à un autre compte, erreur lisible dès maintenant (la contrainte moteur reste en dernier recours).
    // Ne regarder que le lien de connexion : le lien de fonction (staff) est un fait de poste, la même personne physique apparaissant chez un autre entité/poste est normal,
    // en juger « une personne, un compte » dessus produirait des faux positifs.
    const taken = this.identityLinks().findOne((link) => link.provider === binding.provider
      && link.providerUserId === binding.unionId
      && link.kind !== 'staff'
      && (link.corpId ?? '') === corpId)
    if (taken && taken.userId !== id) {
      throw new Error(t('该三方身份已绑定其他平台账号（一人一号），请先解除对方绑定'))
    }
    // Le conflit de contrainte d'unicité est rattrapé par le moteur de stockage (une même identité tierce sous une même entité ne mappe qu'un compte)
    this.linkIdentity(id, {
      provider: binding.provider,
      providerUserId: binding.unionId,
      corpId,
      displayName: binding.displayName,
    }, 'console')
    return this.users().get(id)!
  }

  /**
   * Délie une liaison tierce (face gestion). corpId par défaut = toutes les entités du provider (l'admin choisit explicitement « délier DingTalk »).
   * La déliaison écrit une exemption, pour éviter que la synchronisation du connecteur recolle automatiquement le lien.
   * Revue de sécurité P1-05 : suppression du faux code de vérification (l'ancienne logique ne vérifiait qu'un format à 6 chiffres, sans défi réel) ; la déliaison elle-même
   * n'accorde pas d'accès (elle ne touche qu'une voie de connexion, et le garde-fou anti-verrouillage « dernière voie de connexion exige d'abord un mot de passe » est dans performUnbind),
   * une fois bindThirdParty resserrée à '*', la déliaison ne constitue plus un maillon d'une chaîne de prise de contrôle.
   */
  unbindThirdParty(id: string, provider: ThirdPartyBinding['provider'], verifyCode: string, actor?: UserManageActor, corpId?: string): UserRecord {
    const user = this.requireUser(id)
    this.assertManageScope(actor, user.orgId, t('解绑三方身份'))
    void verifyCode
    return this.performUnbind(user, provider, corpId)
  }

  /**
   * Auto-déliaison par la personne (un collègue métier sans iam.user.write délie son propre DingTalk dans le panneau).
   * Seule différence avec unbindThirdParty : pas de validation de sous-arbre — l'objet opéré est toujours l'appelant lui-même,
   * userId tiré de la session par la couche de routage (le corps de requête ne peut pas le désigner), donc pas de surface d'élévation.
   */
  unbindOwnThirdParty(userId: string, provider: ThirdPartyBinding['provider'], verifyCode: string, corpId?: string): UserRecord {
    const user = this.requireUser(userId)
    if (!verifyCode || verifyCode.length !== 6) throw new Error(t('解绑需二次验证（6 位验证码）'))
    return this.performUnbind(user, provider, corpId)
  }

  /** Exécution réelle de la déliaison (avec garde-fou anti-verrouillage : juger avant de supprimer, sans état intermédiaire). */
  private performUnbind(user: UserRecord, provider: ThirdPartyBinding['provider'], corpId?: string): UserRecord {
    const targets = this.identityLinks().find((link) => link.userId === user.id
      && link.provider === provider
      && (corpId === undefined || (link.corpId ?? '') === corpId)
      && link.kind !== 'staff')
    if (targets.length === 0) {
      throw new Error(t('该账号未绑定{provider}身份', { provider }))
    }
    // Garde-fou anti-verrouillage : l'identité tierce est le seul identifiant de connexion connu des comptes auto-enregistrés SSO/synchronisés d'annuaire
    // (le mot de passe aléatoire de création n'a jamais été distribué). Si après déliaison il ne reste ni liaison tierce ni mot de passe connu,
    // le compte devient définitivement inconnectable et sans recours admin — on bloque ici, en invitant à définir d'abord un mot de passe.
    const remainingLinks = this.identityLinks().find((link) => link.userId === user.id
      && link.kind !== 'staff'
      && !targets.some((target) => target.id === link.id))
    if (remainingLinks.length === 0 && !this.hasUsablePassword(user)) {
      throw new Error(t('这是该账号唯一的登录方式，解绑后将无法登录。请先为账号设置口令（管理员重置口令），再解绑三方身份'))
    }
    this.unlinkIdentity(user.id, provider, corpId)
    return this.users().get(user.id)!
  }

  /**
   * Si le compte dispose d'un mot de passe utilisable (connexion compte-mot de passe possible).
   * Fondé sur la marque passwordKnown (quelqu'un a eu le clair), pas sur la forme de l'identifiant — les comptes créés par synchronisation d'annuaire
   * ont un identifiant matricule et un mot de passe tout aussi aléatoire ; juger sur la forme les classerait à tort « mot de passe connu » et laisserait passer la déliaison.
   */
  private hasUsablePassword(user: UserRecord): boolean {
    return Boolean(user.passwordHash) && user.passwordKnown === true
  }

  /**
   * Liste des comptes (resserrage de la face lecture N3 admin d'organisation) : orgId étendu en filtre de sous-arbre ; scopeOrgIds (ensemble d'organisations visible
   * de l'appelant, calculé côté console par scopedOrgIdsOf) intersecte quand il est passé — un non-admin plateforme ne voit que les comptes de son sous-arbre.
   * Absents l'un et l'autre = pas de filtre (admin plateforme/appel interne de service, l'ancien référentiel intégral est maintenu).
   */
  listUsers(input: { orgId?: string; status?: string; q?: string; scopeOrgIds?: string[] } = {}): UserRecord[] {
    const orgScope = input.orgId ? new Set(this.orgSubtreeIds(input.orgId)) : undefined
    const allowScope = input.scopeOrgIds ? new Set(input.scopeOrgIds) : undefined
    const q = input.q?.toLowerCase()
    return this.users().find((user) => {
      if (input.status && user.status !== input.status) return false
      if (orgScope && !orgScope.has(user.orgId)) return false
      if (allowScope && !allowScope.has(user.orgId)) return false
      if (q && !`${user.displayName}${user.username}${user.email}`.toLowerCase().includes(q)) return false
      return true
    }).sort((a, b) => a.createdAt.localeCompare(b.createdAt))
  }

  verifyPassword(username: string, password: string): UserRecord {
    const user = this.users().findOne((item) => item.username === username)
    if (!user) throw new Error(t('用户名或密码错误'))
    if (!verifyPasswordHash(user, password)) throw new Error(t('用户名或密码错误'))
    // Montée transparente (A-09) : l'ancien format (sha256 nu) qui vérifie est immédiatement re-haché en scrypt — migration invisible des utilisateurs existants,
    // le nouveau format prend effet à la connexion suivante ; un échec de montée ne bloque pas la connexion (nouvelle tentative la fois suivante).
    if (!user.passwordHash.startsWith(SCRYPT_PREFIX)) {
      try {
        this.users().update(user.id, { passwordSalt: '', passwordHash: hashPasswordScrypt(password) })
      } catch { /* échec de mise à niveau : conserve l'ancien hachage, la vérification ayant réussi ne bloque pas */ }
    }
    if (user.status === 'frozen') throw new Error(t('账号已冻结：{reason}', { reason: user.frozenReason ?? t('联系管理员') }))
    if (user.status === 'deactivated') throw new Error(t('账号已注销'))
    if (user.status === 'pending') throw new Error(t('账号待激活，请联系管理员'))
    return user
  }

  markLogin(id: string): void {
    this.users().update(id, { lastLoginAt: new Date().toISOString() })
  }

  private requireUser(id: string): UserRecord {
    const user = this.users().get(id)
    if (!user) throw new Error(t('账号不存在：{id}', { id }))
    return user
  }

  // -- Rôles ---------------------------------------------------------------

  /**
   * Remplissage rétroactif de la connaissance du mot de passe des comptes existants (idempotent, volet du garde-fou de déliaison 2026-10-22) :
   * `passwordKnown` est un champ nouveau du lot ; les comptes existants ne l'ont pas. Traiter « champ absent » comme false
   * classerait tous les comptes existants « only connexion tierce », leur refusant la déliaison de bout en bout.
   *
   * Référentiel de remplissage (prudent penché vers l'utilisabilité, sans relâcher la vraie face de risque) :
   *   - compte avec liaison tierce quelconque → non marqué (le garde-fou de déliaison s'applique normalement, ne bloque que si c'est la seule voie) ;
   *   - compte sans aucune liaison tierce → marqué true (il ne peut se connecter que par mot de passe, donc le mot de passe est connu).
   */
  backfillPasswordKnown(): number {
    const collection = this.ctx.opsStorage.collection<RecordBase & { key: string }>('iam:migrations')
    if (collection.findOne((item) => item.key === 'password-known-v1')) return 0
    let touched = 0
    for (const user of this.users().all()) {
      if (user.passwordKnown !== undefined) continue
      if ((user.bindings ?? []).length === 0 && user.passwordHash) {
        this.users().update(user.id, { passwordKnown: true })
        touched++
      }
    }
    collection.insert({ id: newId('mig'), key: 'password-known-v1', note: `backfilled ${touched}` })
    return touched
  }

  /**
   * Remplissage rétroactif du kind des liens d'identité existants (idempotent, volet de la capacité de déliaison 2026-10-22).
   *
   * Ce lot a ajouté le champ kind distinguant « lien de connexion » et « lien de fonction » ; les liens existants ne l'ont pas. Le remplissage s'appuie sur deux faits :
   *   1. sous un même (provider, corpId, userId), s'il y a plusieurs liens, le lien de connexion a la forme unionId, le lien de fonction la forme userid
   *      (l'unionId DingTalk ressemble à dd_uXXX, le userid à staff_XXX) — convention existante d'écriture des liens à la synchronisation ;
   *   2. critère de forme en dernier recours : providerUserId atteignant la liste des userid de responsables d'un département de l'entité (managerRemoteIds) → lien de fonction.
   * Après remplissage, la déliaison ne touche que le lien de connexion ; le lien de fonction (recherche inversée de responsables, recherche d'identité des permissions de données NAS) reste intact.
   */
  backfillIdentityLinkKinds(): number {
    const links = this.identityLinks().all()
    const groupOf = (link: IdentityLinkRecord) => `${link.provider}|${link.corpId ?? ''}|${link.userId}`
    const groups = new Map<string, IdentityLinkRecord[]>()
    for (const link of links) {
      const key = groupOf(link)
      const list = groups.get(key) ?? []
      list.push(link)
      groups.set(key, list)
    }
    // Le responsable de département référence des userid tierces (référentiel managerRemoteIds) → ces ids relèvent du lien de fonction
    const staffIds = new Set<string>()
    for (const org of this.orgs().all()) {
      for (const id of this.leadersOf(org.id)) {
        // Responsable déjà résolu en userId plateforme, indécidable ici ; on ne collecte que les ids tierces en staff_ (résidu de l'ancien référentiel d'avant synchronisation)
        if (/^(staff|user|ou_)/i.test(id)) staffIds.add(id)
      }
    }
    let touched = 0
    for (const group of groups.values()) {
      // Groupe multi-liens : forme unionId = lien de connexion, le reste = lien de fonction
      const isUnionShape = (id: string) => /^(dd_u|ou_|union)/i.test(id) || !/^(staff|user)/i.test(id)
      for (const link of group) {
        if (link.kind !== undefined) continue
        const kind: 'login' | 'staff' = (group.length > 1 && !isUnionShape(link.providerUserId))
          || staffIds.has(link.providerUserId)
          ? 'staff' : 'login'
        this.identityLinks().update(link.id, { kind })
        touched++
      }
    }
    return touched
  }

  ensureBuiltinRoles(): void {
    for (const role of BuiltinRoles) {
      if (!this.roles().findOne((item) => item.code === role.code)) {
        this.roles().insert({ id: newId('rol'), ...role })
      }
    }
  }

  /**
   * Migration de permissions idempotente des rôles intégrés : complète pour resource_admin/developer/auditor déjà en base les points de permission
   * de gestion des connecteurs. Ne fait que combler les manques ; la marque de migration entre dans la collection iam:migrations pour observation (correctif P2 ⑯).
   */
  ensureConnectorPermissionsMigration(): { applied: boolean; touched: string[] } {
    const collection = this.ctx.opsStorage.collection<RecordBase & { key: string; note?: string }>('iam:migrations')
    const marker = collection.findOne((item) => item.key === 'connector-permissions-v1')
    const touched: string[] = []
    for (const [code, additions] of Object.entries(BUILTIN_ROLE_MIGRATION)) {
      const role = this.roles().findOne((item) => item.code === code)
      if (!role) continue
      const missing = additions.filter((point) => !role.permissions.includes(point))
      if (missing.length > 0) {
        this.roles().update(role.id, { permissions: [...role.permissions, ...missing] })
        this.ctx.platformBus.emit(PlatformEvents.PermissionChanged, { kind: 'builtin_role_migration', roleId: role.id })
        touched.push(`${code}+${missing.join(',')}`)
      }
    }
    // Revue de la sémantique joker : quand resource_admin détient un joker de forme mcp.*, userPermissions déplie déjà connector.*
    // (l'ancien stock ne contient pas connector.*), d'où la fusion explicite de ce joker pour éviter un ajout point par point.
    const resourceAdmin = this.roles().findOne((item) => item.code === 'resource_admin')
    if (resourceAdmin && !resourceAdmin.permissions.includes('connector.*')) {
      this.roles().update(resourceAdmin.id, { permissions: [...resourceAdmin.permissions, 'connector.*'] })
      this.ctx.platformBus.emit(PlatformEvents.PermissionChanged, { kind: 'builtin_role_migration', roleId: resourceAdmin.id })
      touched.push('resource_admin+connector.*')
    }
    if (!marker) {
      collection.insert({
        id: newId('mig'), key: 'connector-permissions-v1',
        ...(touched.length > 0 ? { note: touched.join('; ') } : {}),
      })
    }
    return { applied: marker === undefined || touched.length > 0, touched }
  }

  /**
   * Plafond des permissions autorisables (revue de sécurité P0-02, 2026-10-31) : un opérateur non super-admin plateforme (sans '*')
   * ne peut octroyer/gérer que les points de permission qu'il détient lui-même — un admin d'organisation (iam.*) ne peut élever aucun compte en super-admin,
   * ni octroyer une capacité inter-domaine qu'il n'a pas, ni créer/éditer un rôle contenant '*' ou dépassant son propre jeu de permissions.
   * actor.permissions est le jeu littéral résolu ('*' détenu seulement par le super-admin) ; requested admet la forme joker,
   * comparé après dépliage point par point. Toutes les entrées externes (REST, pont d'outils, etc.) partagent ce point unique (arbitrage unique en couche service).
   */
  private assertGrantCeiling(actor: UserManageActor | undefined, requested: string[], action: string): void {
    if (!actor) {
      throw new OrgScopeDeniedError(t('角色管理操作缺少操作者身份（{action}）：外部入口必须携带可归因调用者，内部系统链路请显式传入系统身份（防提权，安全审查 P0-02）', { action }))
    }
    if (actor.permissions.includes('*')) return
    const owned = new Set(actor.permissions)
    for (const permission of requested) {
      if (permission === '*') {
        throw new OrgScopeDeniedError(t('仅平台超级管理员可授予/配置全量权限「*」（{action}，防提权）', { action }))
      }
      if (permission.endsWith('.*')) {
        const prefix = permission.slice(0, -2)
        const leaked = PermissionCatalog.filter((item) => item.point.startsWith(`${prefix}.`) && !owned.has(item.point)).map((item) => item.point)
        if (leaked.length > 0) {
          throw new OrgScopeDeniedError(t('超出可授权上限（{action}）：操作者未持有 {points}（不可授予自身没有的权限，防提权）', { action, points: leaked.slice(0, 5).join('、') }))
        }
      } else if (!owned.has(permission)) {
        throw new OrgScopeDeniedError(t('超出可授权上限（{action}）：操作者未持有权限点 {point}（不可授予自身没有的权限，防提权）', { action, point: permission }))
      }
    }
  }

  /** Un non-super-admin ne peut modifier « un rôle encore porté par des comptes hors de son sous-arbre » — contre l'influence sur les autres détenteurs via l'édition d'un rôle partagé (P0-02). */
  private assertRoleHolderScope(actor: UserManageActor | undefined, roleId: string, action: string): void {
    if (!actor || actor.permissions.includes('*')) return
    const actorOrgId = actor.orgId ?? (actor.userId ? this.users().get(actor.userId)?.orgId : undefined)
    if (!actorOrgId) throw new OrgScopeDeniedError(t('角色管理操作缺少操作者组织归属（{action}）', { action }))
    const allowed = new Set(this.orgSubtreeIds(actorOrgId))
    const outside = this.users().find((user) => user.roleIds.includes(roleId) && !allowed.has(user.orgId))
    if (outside.length > 0) {
      throw new OrgScopeDeniedError(t('该角色仍被本组织子树外的账号挂载（{action}被拒绝）：{names} 等——请由平台超级管理员处理', { action, names: outside.slice(0, 3).map((user) => user.displayName).join('、') }))
    }
  }

  createRole(input: { code: string; name: string; description?: string; permissions: string[] }, actor?: UserManageActor): RoleRecord {
    if (!input.code || !/^[a-z0-9_]+$/.test(input.code)) throw new Error(t('角色 code 仅支持小写字母/数字/下划线'))
    if (this.roles().findOne((role) => role.code === input.code)) throw new Error(t('角色 code 已存在：{code}', { code: input.code }))
    this.assertPermissions(input.permissions)
    this.assertGrantCeiling(actor, input.permissions, t('创建角色'))
    return this.roles().insert({
      id: newId('rol'),
      code: input.code,
      name: input.name,
      builtin: false,
      description: input.description ?? '',
      permissions: input.permissions,
    })
  }

  updateRole(id: string, patch: { name?: string; description?: string; permissions?: string[] }, actor?: UserManageActor): RoleRecord {
    const role = this.roles().get(id)
    if (!role) throw new Error(t('角色不存在：{id}', { id }))
    if (role.builtin && patch.permissions) throw new Error(t('内置角色的权限不可修改'))
    if (patch.permissions) this.assertPermissions(patch.permissions)
    if (patch.permissions) {
      // P0-02 : éditer un rôle équivaut à changer les permissions de tous les détenteurs d'un coup — le contrôle de plafond arbitre sur « le jeu de permissions après modification »,
      // et refuse de modifier un rôle encore porté par des comptes hors du sous-arbre (contre l'élévation inter-organisation via un rôle partagé)
      this.assertGrantCeiling(actor, patch.permissions, t('编辑角色'))
      this.assertRoleHolderScope(actor, id, t('编辑角色'))
    }
    const updated = this.roles().update(id, patch)
    this.ctx.platformBus.emit(PlatformEvents.PermissionChanged, { kind: 'role', roleId: id })
    return updated
  }

  /**
   * Supprime un rôle personnalisé (complément de la face suppression feuille de route R4, 2026-10-14) : la gouvernance des rôles n'ajoutait auparavant que sans modifier ni supprimer —
   * les rôles morts nés d'essais/démonstrations s'accumulaient à vie. Triple garde-fou :
   *   ① les rôles intégrés sont non supprimables (base de plateforme, les supprimer ferait diverger la face RBAC des bases neuves et existantes) ;
   *   ② non supprimable tant que des comptes le portent (le supprimer ferait s'évaporer toutes leurs permissions, délier d'abord) ;
   *   ③ inexistant = refus (même référentiel qu'updateRole, pas de succès silencieux).
   */
  deleteRole(id: string, actor?: UserManageActor): void {
    const role = this.roles().get(id)
    if (!role) throw new Error(t('角色不存在：{id}', { id }))
    if (role.builtin) throw new Error(t('内置角色「{name}」不可删除（平台基线；如需收敛权限请走角色编辑）', { name: role.name }))
    // P0-02 : contrôle du périmètre des détenteurs avant suppression (passe toujours sans porteur ; même référentiel que l'édition, contre l'interférence de gouvernance inter-organisation)
    this.assertRoleHolderScope(actor, id, t('删除角色'))
    const holders = this.users().all().filter((user) => user.roleIds.includes(id))
    if (holders.length > 0) {
      throw new Error(t('角色「{name}」仍被 {count} 个账号挂载（{names} 等），请先在账号管理中解除后再删除', { name: role.name, count: holders.length, names: holders.slice(0, 5).map((user) => user.displayName).join('、') }))
    }
    this.roles().remove(id)
    this.ctx.platformBus.emit(PlatformEvents.PermissionChanged, { kind: 'role', roleId: id })
  }

  private assertPermissions(permissions: string[]): void {
    for (const permission of permissions) {
      if (permission === '*' || permission.endsWith('.*')) continue
      if (!PermissionCatalog.some((item) => item.point === permission)) {
        throw new Error(t('未知权限点：{permission}', { permission }))
      }
    }
  }

  assignRoles(userId: string, roleIds: string[], actor?: UserManageActor): UserRecord {
    const user = this.requireUser(userId)
    this.assertManageScope(actor, user.orgId, t('调整角色'))
    for (const roleId of roleIds) {
      if (!this.roles().get(roleId)) throw new Error(t('角色不存在：{id}', { id: roleId }))
    }
    // P0-02 : l'arbitrage du plafond d'autorisabilité se fonde sur « les points de permission réels après résolution du rôle » — la granularité rôle ne contourne pas (attribuer super_admin
    // ou tout rôle contenant des points que l'opérateur ne détient pas à un compte de l'organisation est refusé ici ; un rôle contenant '*' se résout en '*')
    this.assertGrantCeiling(actor, this.resolveRolePermissions(roleIds), t('分配角色'))
    const updated = this.users().update(userId, { roleIds })
    this.ctx.platformBus.emit(PlatformEvents.PermissionChanged, { kind: 'user_roles', userId })
    return updated
  }

  /** Résout le jeu de points de permission réels d'un ensemble de rôles (union, joker supporté) ; humains et machines partagent la même règle de résolution. */
  resolveRolePermissions(roleIds: string[]): string[] {
    const result = new Set<string>()
    for (const roleId of roleIds) {
      const role = this.roles().get(roleId)
      if (!role) continue
      if (role.permissions.includes('*')) return ['*']
      for (const permission of role.permissions) {
        if (permission.endsWith('.*')) {
          const prefix = permission.slice(0, -2)
          for (const item of PermissionCatalog) {
            if (item.point.startsWith(`${prefix}.`)) result.add(item.point)
          }
        } else {
          result.add(permission)
        }
      }
    }
    return [...result]
  }

  /** Calcule le jeu de points de permission effectifs d'un utilisateur (union de rôles, joker supporté). */
  userPermissions(userId: string): string[] {
    const user = this.users().get(userId)
    if (!user) return []
    return this.resolveRolePermissions(user.roleIds)
  }

  hasPermission(userId: string, point: string): boolean {
    const permissions = this.userPermissions(userId)
    return permissions.includes('*') || permissions.includes(point)
  }

  // -- Groupes d'utilisateurs ---------------------------------------------------------------

  createGroup(input: { name: string; type: 'static' | 'dynamic'; rule?: UserGroupRule; memberIds?: string[]; description?: string }): UserGroupRecord {
    if (!input.name?.trim()) throw new Error(t('用户组名称不能为空'))
    if (this.groups().findOne((group) => group.name === input.name)) throw new Error(t('用户组已存在：{name}', { name: input.name }))
    if (input.type === 'dynamic' && !input.rule) throw new Error(t('动态用户组必须提供圈人规则'))
    return this.groups().insert({
      id: newId('grp'),
      name: input.name,
      type: input.type,
      ...(input.rule !== undefined ? { rule: input.rule } : {}),
      memberIds: input.type === 'static' ? (input.memberIds ?? []) : [],
      description: input.description ?? '',
    })
  }

  updateGroup(id: string, patch: { name?: string; memberIds?: string[]; rule?: UserGroupRule; description?: string }): UserGroupRecord {
    const group = this.groups().get(id)
    if (!group) throw new Error(t('用户组不存在：{id}', { id }))
    return this.groups().update(id, patch)
  }

  deleteGroup(id: string): boolean {
    return this.groups().remove(id)
  }

  /** Résout les membres d'un groupe (les groupes dynamiques cerclent les personnes selon la règle en temps réel). */
  resolveGroupMembers(id: string): UserRecord[] {
    const group = this.groups().get(id)
    if (!group) throw new Error(t('用户组不存在：{id}', { id }))
    if (group.type === 'static') {
      return group.memberIds
        .map((memberId) => this.users().get(memberId))
        .filter((user): user is UserRecord => Boolean(user) && user!.status === 'active')
    }
    const rule = group.rule ?? {}
    const orgIds = rule.orgIds?.length ? new Set(this.orgSubtreeIds(rule.orgIds[0]!).concat(rule.orgIds)) : undefined
    return this.users().find((user) => {
      if (user.status !== 'active') return false
      if (orgIds && !orgIds.has(user.orgId)) return false
      if (rule.title && user.title !== rule.title) return false
      return true
    })
  }

  groupsOfUser(userId: string): UserGroupRecord[] {
    return this.groups().find((group) => {
      if (group.type === 'static') return group.memberIds.includes(userId)
      return this.resolveGroupMembers(group.id).some((user) => user.id === userId)
    })
  }

  /** Instantané des membres de groupes dynamiques (dev-plan-nas-authz §2.2 : le recalcul tombe dans un instantané, la dérive est observable). */
  groupSnapshots(): Collection<GroupSnapshotRecord> {
    return this.ctx.opsStorage.collection<GroupSnapshotRecord>('iam:groupSnapshots')
  }

  /**
   * Recalcule tous les membres de groupes dynamiques et compare avec l'instantané (clôture de synchronisation de connecteur / déclenchement manuel REST).
   * Dérive ≥ seuil (driftAlertThreshold du groupe, défaut 5) ou groupe marqué groupe C NAS (authzRoleC)
   * → émission de `nas.authz.cGroupDrift` — contre les changements silencieux du périmètre de lecture inter-domaine par les ajustements RH.
   * Renvoie la liste des groupes ayant dérivé (détail des ajouts/retraits inclus), pour affichage/assertion par l'appelant.
   */
  refreshGroupSnapshots(actor: string): Array<{ groupId: string; groupName: string; added: string[]; removed: string[]; threshold: number; alerted: boolean }> {
    const drifts: Array<{ groupId: string; groupName: string; added: string[]; removed: string[]; threshold: number; alerted: boolean }> = []
    for (const group of this.groups().find((item) => item.type === 'dynamic')) {
      const memberIds = this.resolveGroupMembers(group.id).map((user) => user.id).sort()
      const existing = this.groupSnapshots().findOne((item) => item.groupId === group.id)
      const previous = existing?.memberIds ?? null
      if (previous !== null) {
        const prevSet = new Set(previous)
        const nextSet = new Set(memberIds)
        const added = memberIds.filter((id) => !prevSet.has(id))
        const removed = previous.filter((id) => !nextSet.has(id))
        if (added.length > 0 || removed.length > 0) {
          const threshold = group.driftAlertThreshold ?? DEFAULT_GROUP_DRIFT_THRESHOLD
          // Un groupe associé C alerte sur toute dérive (sensibilité du périmètre de lecture inter-domaine) ; les autres selon le seuil
          const alerted = group.authzRoleC === true || (added.length + removed.length) >= threshold
          if (alerted) {
            this.ctx.platformBus.emit('nas.authz.cGroupDrift', {
              groupId: group.id, groupName: group.name, added, removed,
              addedCount: added.length, removedCount: removed.length, threshold, actor,
            })
          }
          drifts.push({ groupId: group.id, groupName: group.name, added, removed, threshold, alerted })
        }
      }
      const record: GroupSnapshotRecord = { id: existing?.id ?? `gsn_${group.id}`, groupId: group.id, memberIds, computedAt: new Date().toISOString() }
      if (existing) this.groupSnapshots().update(existing.id, record)
      else this.groupSnapshots().insert(record)
    }
    return drifts
  }

  // -- Accès tierce ---------------------------------------------------------------

  /** Première configuration par type de plateforme (compatibilité des anciens appels ; en multi-entité, utiliser connectorConfigById/resolveConnectorConfig). */
  connectorConfig(provider: string): ConnectorConfigRecord | undefined {
    return this.connectorConfigs().findOne((config) => config.provider === provider)
  }

  /** Adressage par id d'instance de configuration (multi-entité : l'instance est adressée par ConnectorConfigRecord.id, provider ne désigne que le type de plateforme). */
  connectorConfigById(id: string): ConnectorConfigRecord | undefined {
    return this.connectorConfigs().get(id)
  }

  /** Résout l'instance de configuration : d'abord par id, sinon la première par provider (enabled prioritaire) — entrée de compatibilité des anciens paramètres REST. */
  resolveConnectorConfig(idOrProvider: string): ConnectorConfigRecord | undefined {
    const byId = this.connectorConfigById(idOrProvider)
    if (byId) return byId
    const candidates = this.connectorConfigs().find((config) => config.provider === idOrProvider)
    return candidates.find((config) => config.enabled) ?? candidates[0]
  }

  /** Met à jour/crée une configuration d'accès : avec id, mise à jour par id ; sans id, l'ancien comportement (mise à jour de la première par provider, création si absente). */
  upsertConnectorConfig(input: {
    /** Id de l'instance de configuration (multi-entité : mise à jour par id ; défaut = l'ancienne sémantique première-par-provider). */
    id?: string
    provider: 'dingtalk' | 'feishu' | 'wecom'
    /** Nom de l'entité (défaut `${provider}-${corpId}`). */
    name?: string
    corpId: string
    appKey: string
    appSecret?: string
    enabled?: boolean
    syncOrgRoot?: string
    intervalMinutes?: number
    callbackUrl?: string
    loginEnabled?: boolean
    conflictStrategy?: ConnectorConfigRecord['conflictStrategy']
    /** real = vraie OpenAPI (identifiants d'entreprise réels requis) ; mock = repli de démonstration. */
    mode?: 'real' | 'mock'
    /** Surcharge de l'URL de base OpenAPI (tests/déploiement dédié). */
    apiBase?: string
    /** Surcharge de l'URL de base topapi d'annuaire (défaut https://oapi.dingtalk.com). */
    oapiBase?: string
    /** ID de l'organisation cible du montage de l'arbre synchronisé (vide = racine plateforme). */
    targetOrgId?: string
  }): ConnectorConfigRecord {
    if (!IamService.BUILTIN_CONNECTOR_PROVIDERS.has(input.provider)) throw new Error(t('未注册的连接器：{provider}', { provider: input.provider }))
    let existing: ConnectorConfigRecord | undefined
    if (input.id !== undefined) {
      existing = this.connectorConfigById(input.id)
      if (!existing) throw new Error(t('接入配置不存在：{id}', { id: input.id }))
    } else {
      existing = this.connectorConfig(input.provider)
    }
    const secret = input.appSecret ?? existing?.secretActual ?? 'demo-secret'
    // Une configuration neuve à clé non-démo est real par défaut (le formulaire ne collecte pas le mode, déduit de la forme de la clé ; préfixe demo- = repli de démonstration).
    const mode = input.mode ?? (secret.startsWith('demo-') ? 'mock' : existing?.mode ?? 'real')
    const payload = {
      provider: input.provider,
      name: input.name ?? existing?.name ?? `${input.provider}-${input.corpId}`,
      enabled: input.enabled ?? existing?.enabled ?? true,
      corpId: input.corpId,
      appKey: input.appKey,
      secretMasked: mask(secret, 4),
      secretActual: secret,
      syncOrgRoot: input.syncOrgRoot ?? existing?.syncOrgRoot ?? '',
      intervalMinutes: input.intervalMinutes ?? existing?.intervalMinutes ?? 60,
      callbackUrl: input.callbackUrl ?? existing?.callbackUrl ?? '',
      loginEnabled: input.loginEnabled ?? existing?.loginEnabled ?? false,
      conflictStrategy: input.conflictStrategy ?? existing?.conflictStrategy ?? 'manual',
      mode,
      ...(input.apiBase !== undefined ? { apiBase: input.apiBase } : existing?.apiBase !== undefined ? { apiBase: existing.apiBase } : {}),
      ...(input.oapiBase !== undefined ? { oapiBase: input.oapiBase } : existing?.oapiBase !== undefined ? { oapiBase: existing.oapiBase } : {}),
      ...(input.targetOrgId !== undefined ? { targetOrgId: input.targetOrgId } : existing?.targetOrgId !== undefined ? { targetOrgId: existing.targetOrgId } : {}),
    }
    const saved = existing
      ? this.connectorConfigs().update(existing.id, payload)
      : this.connectorConfigs().insert({ id: newId('conn'), ...payload })
    this.applyConnectorMode(saved.id)
    return saved
  }

  /** Crée une instance de configuration d'accès (multi-entité : un même provider peut connecter plusieurs entreprises, provider|corpId rejeté en doublon par la contrainte moteur). */
  createConnectorConfig(input: {
    provider: 'dingtalk' | 'feishu' | 'wecom'
    /** Nom de l'entité (défaut `${provider}-${corpId}`). */
    name?: string
    corpId: string
    appKey: string
    appSecret?: string
    enabled?: boolean
    syncOrgRoot?: string
    intervalMinutes?: number
    callbackUrl?: string
    loginEnabled?: boolean
    conflictStrategy?: ConnectorConfigRecord['conflictStrategy']
    /** real = vraie OpenAPI (identifiants d'entreprise réels requis) ; mock = repli de démonstration. */
    mode?: 'real' | 'mock'
    /** Surcharge de l'URL de base OpenAPI (tests/déploiement dédié). */
    apiBase?: string
    /** Surcharge de l'URL de base topapi d'annuaire (défaut https://oapi.dingtalk.com). */
    oapiBase?: string
    /** ID de l'organisation cible du montage de l'arbre synchronisé (vide = racine plateforme). */
    targetOrgId?: string
  }): ConnectorConfigRecord {
    if (!IamService.BUILTIN_CONNECTOR_PROVIDERS.has(input.provider)) throw new Error(t('未注册的连接器：{provider}', { provider: input.provider }))
    const secret = input.appSecret ?? 'demo-secret'
    // Même déduction qu'upsert : clé préfixe demo- = repli de démonstration (mock), les autres configurations neuves sont real par défaut.
    const mode = input.mode ?? (secret.startsWith('demo-') ? 'mock' : 'real')
    const saved = this.connectorConfigs().insert({
      id: newId('conn'),
      provider: input.provider,
      name: input.name ?? `${input.provider}-${input.corpId}`,
      enabled: input.enabled ?? true,
      corpId: input.corpId,
      appKey: input.appKey,
      secretMasked: mask(secret, 4),
      secretActual: secret,
      syncOrgRoot: input.syncOrgRoot ?? '',
      intervalMinutes: input.intervalMinutes ?? 60,
      callbackUrl: input.callbackUrl ?? '',
      loginEnabled: input.loginEnabled ?? false,
      conflictStrategy: input.conflictStrategy ?? 'manual',
      mode,
      ...(input.apiBase !== undefined ? { apiBase: input.apiBase } : {}),
      ...(input.oapiBase !== undefined ? { oapiBase: input.oapiBase } : {}),
      ...(input.targetOrgId !== undefined ? { targetOrgId: input.targetOrgId } : {}),
    })
    this.applyConnectorMode(saved.id)
    return saved
  }

  /** Supprime une instance de configuration d'accès : désactive en même temps l'inscription runtime du connecteur/de la source d'identité (erreur si absente). */
  deleteConnectorConfig(id: string): void {
    if (!this.connectorConfigById(id)) throw new Error(t('接入配置不存在：{id}', { id }))
    this.connectorConfigs().remove(id)
    this.connectors.delete(id)
    this.authProviders.delete(id)
  }

  /** Instancie pour une instance de configuration l'implémentation real/mock de l'Adapter connecteur/source d'identité (étape 0 : mise en réalité du connecteur ; multi-entité : enregistrement par configId). */
  applyConnectorMode(configId: string): void {
    const config = this.connectorConfigById(configId)
    if (!config) return
    if (config.provider === 'dingtalk') {
      if (config.mode === 'real' && config.secretActual) {
        const credentials: DingTalkCredentials = {
          corpId: config.corpId,
          appKey: config.appKey,
          appSecret: config.secretActual,
          ...(config.apiBase !== undefined ? { apiBase: config.apiBase } : {}),
          ...(config.oapiBase !== undefined ? { oapiBase: config.oapiBase } : {}),
        }
        this.registerConnector(config.id, new RealDingTalkConnector(credentials, { syncOrgRoot: config.syncOrgRoot }))
        this.registerAuthProvider(config.id, new RealDingTalkAuthAdapter(credentials))
      } else if (config.mode === 'mock') {
        // Déclaration explicite de mock (démo/intégration) : seuls les environnements DEMO_SEED peuvent enregistrer une source d'identité mock,
        // la base de production interdit d'exposer un mock comme source d'identité connectable.
        if (process.env.DEMO_SEED === '1') {
          this.registerConnector(config.id, new DingTalkConnector())
          this.registerAuthProvider(config.id, new DingTalkAuthAdapter())
        } else {
          this.registerConnector(config.id, new DingTalkConnector())
        }
      }
    }
  }

  async testConnector(idOrProvider: string): Promise<{ ok: boolean; latencyMs: number; message: string }> {
    const config = this.resolveConnectorConfig(idOrProvider)
    const connector = config ? this.connectors.get(config.id) : undefined
    if (!connector) throw new Error(t('未注册的连接器：{provider}', { provider: idOrProvider }))
    return connector.healthCheck()
  }

  /** Synchronisation intégrale : cartographie d'annuaire + mise en file des conflits + couplage des départs. Un échec tombe aussi dans lastSyncResult (ok:false), contre le « clic sans effet ». */
  async syncConnector(idOrProvider: string, actor: string): Promise<{ created: number; updated: number; conflicts: number; frozen: number; message: string }> {
    const config = this.resolveConnectorConfig(idOrProvider)
    if (!config || !config.enabled) throw new Error(t('连接器未启用：{provider}', { provider: idOrProvider }))
    const connector = this.connectors.get(config.id)
    if (!connector) throw new Error(t('未注册的连接器：{provider}', { provider: idOrProvider }))
    try {
      return await this.runSync(config.provider, actor, config, connector)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      const result = { ok: false, created: 0, updated: 0, conflicts: 0, frozen: 0, message: t('同步失败：{message}', { message }) }
      this.connectorConfigs().update(config.id, { lastSyncAt: new Date().toISOString(), lastSyncResult: result })
      throw error
    }
  }

  private async runSync(provider: ConnectorConfigRecord['provider'], actor: string, config: ConnectorConfigRecord, connector: OrgConnector): Promise<{ created: number; updated: number; conflicts: number; frozen: number; message: string }> {
    const directory = await connector.fetchDirectory()

    const remoteOrgToId = new Map<string, string>()
    let created = 0
    let updated = 0
    for (const remoteOrg of directory.orgs) {
      // Multi-entité : la racine de l'arbre synchronisé monte sur config.targetOrgId (vide = racine plateforme)
      const parent = remoteOrg.parentRemoteId ? remoteOrgToId.get(remoteOrg.parentRemoteId) : (config.targetOrgId ?? null)
      if (parent === undefined && remoteOrg.parentRemoteId) continue
      // Double clé de rattachement de département customFields { remoteId, connectorId } : les vieilles données n'ayant que remoteId sont considérées sans connecteur, sans risque de faux appariement
      const local = this.orgs().findOne((org) => org.customFields['remoteId'] === remoteOrg.remoteId && org.customFields['connectorId'] === config.id)
        // Le rattrapage par nom ne réclame que les organisations « sans rattachement (manuelles/historiques) ou de ce connecteur » — les homonymes sous d'autres entités ne fusionnent pas
        ?? this.orgs().findOne((org) => org.name === remoteOrg.name && org.parentId === parent
          && (org.customFields['connectorId'] === undefined || org.customFields['connectorId'] === config.id))
      if (local) {
        // Réclamer = tamponner : l'organisation sans rattachement atteinte par le rattrapage par nom reçoit remoteId/connectorId,
        // après quoi le rattrapage par nom des autres entités ne peut plus l'atteindre (sinon la seconde entité fusionnerait dans l'arbre de la première).
        if (local.customFields['connectorId'] !== config.id || local.customFields['remoteId'] !== remoteOrg.remoteId) {
          this.orgs().update(local.id, { customFields: { ...local.customFields, remoteId: remoteOrg.remoteId, connectorId: config.id } })
        }
        remoteOrgToId.set(remoteOrg.remoteId, local.id)
      } else {
        const record = this.createOrg({ name: remoteOrg.name, parentId: parent, customFields: { remoteId: remoteOrg.remoteId, connectorId: config.id } }, SYSTEM_ACTOR)
        remoteOrgToId.set(remoteOrg.remoteId, record.id)
        created++
      }
    }

    let conflicts = 0
    let frozen = 0

    for (const remoteUser of directory.users) {
      const orgId = remoteOrgToId.get(remoteUser.orgRemoteId)
      if (!orgId) continue
      // Une personne, plusieurs départements (sémantique de cumul, dev-plan-nas-authz §2.1) : rattachement principal = orgId (premier département), attache = première atteinte d'extraOrgRemoteIds.
      // Côté moteur, primaryOrgId = ancre du rattachement principal, le sous-arbre orgId est en lecture de cumul — les permissions des deux identités coexistent sans conflit.
      const secondaryOrgId = (remoteUser.extraOrgRemoteIds ?? []).map((remoteOrgId) => remoteOrgToId.get(remoteOrgId)).find(Boolean)
// Multi-entité : l'appariement d'identité fait foi sur identityLinks (source de fait), bindings n'est qu'une projection de compatibilité ;
      // la réclamation par matricule n'a lieu qu'après double échec — après déliaison, bindings est reconstruit vide ; ne considérer que la projection ferait passer à tort pour un nouveau compte en double.
      // Note : ne reconnaître que le lien d'identité de connexion (kind≠staff) — le lien de fonction est un fait de poste, il ne peut pas servir à localiser « qui va lier une identité de connexion ».
      let local = this.users().get(this.identityLinks().findOne((link) => link.provider === provider
        && link.providerUserId === remoteUser.remoteId
        && link.kind !== 'staff'
        && (link.corpId ?? '') === config.corpId)?.userId ?? '')
        ?? this.users().findOne((user) => user.bindings.some((binding) => binding.provider === provider && binding.unionId === remoteUser.remoteId && (binding.corpId ?? '') === config.corpId))
        ?? this.users().findOne((user) => user.jobNumber === remoteUser.jobNumber)
      if (!local) {
        const { user: record } = this.createUser({
          username: remoteUser.jobNumber.toLowerCase(),
          displayName: remoteUser.name,
          orgId,
          title: remoteUser.title,
          email: remoteUser.email,
          jobNumber: remoteUser.jobNumber,
        }, SYSTEM_ACTOR)
        this.users().update(record.id, secondaryOrgId ? { status: 'active', primaryOrgId: orgId, orgId: secondaryOrgId } : { status: 'active' })
        this.linkIdentity(record.id, { provider, providerUserId: remoteUser.remoteId, corpId: config.corpId, displayName: remoteUser.name, kind: 'login' }, 'connector-sync')
        // Lien d'identité de fonction (staff) : écrit au même référentiel que l'utilisateur existant — la cartographie des responsables de département et la recherche d'identité NAS en dépendent
        if (remoteUser.remoteUserId) {
          try {
            this.linkIdentity(record.id, { provider, providerUserId: remoteUser.remoteUserId, corpId: config.corpId, displayName: remoteUser.name, kind: 'staff' }, 'connector-sync')
          } catch {
            // Conflit d'unicité : ce userid est déjà lié à un autre compte, ignoré
          }
        }
        created++
        continue
      }
      // Réparation de lien à la liaison : les entités déliées manuellement (bindingExemptions contient provider|corpId) voient leur lien d'identité de connexion sauté —
      // sinon la déliaison serait silencieusement annulée à la synchronisation suivante (60 min par défaut), l'utilisateur verrait « clic sans effet ».
      // Le lien d'identité de fonction (staff) n'est pas soumis à l'exemption : il décrit « le poste de cette personne dans l'organisation », fait d'organisation et non identifiant de connexion,
      // l'exempter casserait la recherche inversée des responsables de département et la recherche d'identité des permissions de données NAS.
      const exemptKey = `${provider}|${config.corpId ?? ''}`
      const exempted = (local.bindingExemptions ?? []).includes(exemptKey)
      const hasLinkForSubject = (providerUserId: string) => Boolean(this.identityLinks().findOne((link) => link.provider === provider
        && link.userId === local!.id
        && link.providerUserId === providerUserId
        && (link.corpId ?? '') === config.corpId))
      if (!exempted && !hasLinkForSubject(remoteUser.remoteId)) {
        try {
          this.linkIdentity(local.id, { provider, providerUserId: remoteUser.remoteId, corpId: config.corpId, displayName: remoteUser.name, kind: 'login' }, 'connector-sync')
        } catch {
          // Conflit d'unicité : cette identité tierce est déjà liée à un autre compte (une personne, un compte), ignoré en conservant la sémantique de conflit
        }
      }
      // Liens d'identité opérationnelle (nasAuthz P0) : l'unionId sert à l'appariement SSO, le userid à la recherche d'identité nasAuthz
      // (référentiel userid remonté par hermes X-On-Behalf-User) et à la cartographie des responsables dept_manager_userid_list — les deux liens coexistent sans s'écraser.
      if (remoteUser.remoteUserId && !hasLinkForSubject(remoteUser.remoteUserId)) {
        try {
          this.linkIdentity(local.id, { provider, providerUserId: remoteUser.remoteUserId, corpId: config.corpId, displayName: remoteUser.name, kind: 'staff' }, 'connector-sync')
        } catch {
          // Conflit d'unicité : ce userid est déjà lié à un autre compte, ignoré (sémantique du lien unionId reprise)
        }
      }
      // Le rattachement de cumul est un fait d'organigramme (multi-départements DingTalk), hors mécanisme de conflit d'attributs, tombé directement en base :
      // primaryOrgId ancre le rattachement principal, orgId bascule sur l'attache de cumul (le moteur n'y accorde que la lecture du sous-arbre)
      if (secondaryOrgId && (local.primaryOrgId !== orgId || local.orgId !== secondaryOrgId)) {
        this.users().update(local.id, { primaryOrgId: orgId, orgId: secondaryOrgId })
        local = this.users().get(local.id) ?? local
      }
      if (!remoteUser.active) {
        if (local.status === 'active' || local.status === 'pending') {
          this.freezeUser(local.id, t('三方同步：{provider} 通讯录已离职', { provider }), SYSTEM_ACTOR)
          frozen++
        }
        continue
      }
      const attrDiffers = local.displayName !== remoteUser.name || local.title !== remoteUser.title || local.orgId !== (secondaryOrgId ?? orgId)
      if (attrDiffers) {
        if (config.conflictStrategy === 'third_party_wins') {
          this.users().update(local.id, { displayName: remoteUser.name, title: remoteUser.title, orgId: secondaryOrgId ?? orgId })
          updated++
        } else if (config.conflictStrategy === 'platform_wins') {
          updated++
        } else {
          this.conflicts().insert({
            id: newId('cfl'),
            provider,
            kind: 'user_attr',
            thirdPartyData: { displayName: remoteUser.name, title: remoteUser.title, orgId, orgName: this.orgs().get(orgId)?.name },
            platformData: { displayName: local.displayName, title: local.title, orgId: local.orgId, orgName: this.orgs().get(local.orgId)?.name },
            status: 'pending',
          })
          conflicts++
        }
      }
    }

    // Synchronisation des responsables (dev-plan-nas-authz étape 1) : dept_manager_userid_list → userId plateforme (recherche inverse identityLinks).
    // Placée après la boucle utilisateurs : les liens d'identité userid tombent en base d'abord dans le même tour, sinon les responsables ne se cartographient pas (la liste DingTalk est au référentiel userid).
    // Une liste vide explicite côté distant = vider les responsables ; champ absent = ne pas toucher le local (compatibilité des anciennes sources d'annuaire). Un responsable distant sans cartographie est écarté (pas d'ID suspendu).
    // Les organisations à verrou manuel (leaderSource='manual', complétion console) sont sautées en bloc — les départements sans responsable côté distant reposent sur la complétion manuelle.
    // Compléter d'abord le kind des liens existants : les liens écrits dans ce tour se mêlent aux liens existants dans le même groupe (provider,corpId,userId) des vieilles données,
    // sans kind, impossible de distinguer lien de connexion et lien de fonction (la déliaison effacerait le fait de fonction).
    this.backfillIdentityLinkKinds()
    let leaderSynced = 0
    let leaderPinned = 0
    for (const remoteOrg of directory.orgs) {
      if (!Array.isArray(remoteOrg.managerRemoteIds)) continue
      const localOrgId = remoteOrgToId.get(remoteOrg.remoteId)
      if (!localOrgId) continue
      const localOrg = this.orgs().get(localOrgId)
      if (localOrg?.leaderSource === 'manual') { leaderPinned++; continue }
      const leaderUserIds = remoteOrg.managerRemoteIds
        .map((remoteUserId) => this.identityLinks().findOne((link) => link.provider === provider && link.providerUserId === remoteUserId && (link.corpId ?? '') === config.corpId)?.userId)
        .filter((id): id is string => Boolean(id))
      this.orgs().update(localOrgId, { leaderUserIds, leaderSource: 'sync' })
      leaderSynced++
    }

    // Instantané du recalcul des groupes dynamiques + alerte de dérive (dev-plan-nas-authz §2.2) : après un ajustement RH de title/org,
    // les membres de groupe peuvent changer silencieusement ; la clôture de synchronisation recalcule tout et compare à l'instantané, dérive au-delà du seuil ou touchant un groupe C = alerte.
    const drifts = this.refreshGroupSnapshots('connector-sync')

    const result = { ok: true, created, updated, conflicts, frozen, message: t('同步完成：新建 {created}，更新 {updated}，冲突 {conflicts}，离职冻结 {frozen}{leaderSyncedPart}{leaderPinnedPart}{driftsPart}', { created, updated, conflicts, frozen, leaderSyncedPart: leaderSynced > 0 ? t('，负责人 {n}', { n: leaderSynced }) : '', leaderPinnedPart: leaderPinned > 0 ? t('，手动锁定 {n}', { n: leaderPinned }) : '', driftsPart: drifts.length > 0 ? t('，组漂移 {n}', { n: drifts.length }) : '' }) }
    this.connectorConfigs().update(config.id, { lastSyncAt: new Date().toISOString(), lastSyncResult: result })
    this.ctx.platformBus.emit(PlatformEvents.ConnectorSynced, { provider, actor, ...result })
    return result
  }

  resolveConflict(id: string, keep: 'third_party' | 'platform', actor: string): SyncConflictRecord {
    const conflict = this.conflicts().get(id)
    if (!conflict) throw new Error(t('冲突记录不存在：{id}', { id }))
    if (conflict.status === 'resolved') throw new Error(t('该冲突已处理'))
    if (conflict.kind === 'user_attr') {
      const jobNumber = String(conflict.thirdPartyData.jobNumber ?? '')
      const local = this.users().findOne((user) => user.bindings.some((binding) => binding.provider === conflict.provider && binding.unionId === conflict.thirdPartyData.unionId))
        ?? (jobNumber ? this.users().findOne((user) => user.jobNumber === jobNumber) : undefined)
      if (local) {
        const source = keep === 'third_party' ? conflict.thirdPartyData : conflict.platformData
        this.users().update(local.id, {
          displayName: String(source.displayName ?? local.displayName),
          title: String(source.title ?? local.title),
          orgId: String(source.orgId ?? local.orgId),
        })
      }
    }
    return this.conflicts().update(id, {
      status: 'resolved',
      resolution: keep,
      resolvedBy: actor,
      resolvedAt: new Date().toISOString(),
    })
  }

  /**
   * Inspection de la synchronisation automatique des connecteurs (le minuteur appelle chaque minute ; POST /api/iam/connectors/auto-sync en est le déclencheur manuel) :
   * parmi les instances actives, celle dont lastSyncAt dépasse l'intervalle effectif (intervalMinutes, plancher 5 minutes ; 0 = synchronisation automatique fermée)
   * est synchronisée intégralement — un connecteur jamais synchronisé compte comme échu (rattrapage dès le démarrage). actor noté 'auto-sync' pour se distinguer de la synchro manuelle ;
   * l'échec d'une configuration n'arrête pas les autres (l'échec est déjà dans lastSyncResult), renvoie le résultat entrée par entrée.
   */
  async runDueAutoSyncs(now = Date.now()): Promise<Array<{ configId: string; provider: string; name: string; message: string; ok: boolean }>> {
    if (process.env.IAM_CONNECTOR_AUTO_SYNC === 'off') return []
    const handled: Array<{ configId: string; provider: string; name: string; message: string; ok: boolean }> = []
    for (const config of this.connectorConfigs().all()) {
      const intervalMinutes = config.intervalMinutes ?? 0
      if (!config.enabled || intervalMinutes <= 0) continue
      if (config.lastSyncAt && now - new Date(config.lastSyncAt).getTime() < Math.max(intervalMinutes, AUTO_SYNC_MIN_INTERVAL_MINUTES) * 60_000) continue
      if (this.autoSyncing.has(config.id)) continue
      this.autoSyncing.add(config.id)
      try {
        const result = await this.syncConnector(config.id, 'auto-sync')
        handled.push({ configId: config.id, provider: config.provider, name: config.name, ok: true, message: result.message })
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        this.ctx.logger('iam').warn(`连接器自动同步失败（${config.name}）：${message}`)
        handled.push({ configId: config.id, provider: config.provider, name: config.name, ok: false, message })
      } finally {
        this.autoSyncing.delete(config.id)
      }
    }
    if (handled.length > 0) {
      this.ctx.logger('iam').info(`连接器自动同步巡检：本次处理 ${handled.length} 条（${handled.filter((item) => item.ok).length} 成功）`)
    }
    return handled
  }

  /**
   * Nom complet des effectifs (canal de données d'organisation) : permet aux applications externes connectées (RH/performance, etc.) avec des identifiants machine
   * (scope iam.roster.read, autorisation ajoutée via la console à l'enregistrement de l'application) de tirer en une fois les comptes en poste et l'arbre d'organisations,
   * pour déployer des tâches de saisie et la cartographie sub → rôle métier ; l'id est le sub du userinfo (clé d'association stable).
   * Minimisation des PII : sans numéro de mobile ; les comptes fermés absents du registre ; chaque tirage est audité par la couche console (invoke).
   */
  roster(): {
    generatedAt: string
    orgs: Array<{ id: string; name: string; parentId: string | null; status: string; leaderUserIds: string[] }>
    users: Array<{ id: string; username: string; displayName: string; email: string; jobNumber: string; title: string; orgId: string; orgName: string; primaryOrgId?: string; status: UserStatus; accountType?: UserRecord['accountType'] }>
  } {
    const orgNames = new Map(this.orgs().all().map((org) => [org.id, org.name]))
    return {
      generatedAt: new Date().toISOString(),
      orgs: this.orgs().all().map((org) => ({
        id: org.id,
        name: org.name,
        parentId: org.parentId,
        status: org.status,
        leaderUserIds: this.leadersOf(org.id),
      })),
      users: this.users().all()
        .filter((user) => user.status !== 'deactivated')
        .map((user) => ({
          id: user.id,
          username: user.username,
          displayName: user.displayName,
          email: user.email,
          jobNumber: user.jobNumber ?? '',
          title: user.title,
          orgId: user.orgId,
          orgName: orgNames.get(user.orgId) ?? '',
          ...(user.primaryOrgId !== undefined ? { primaryOrgId: user.primaryOrgId } : {}),
          status: user.status,
          ...(user.accountType !== undefined ? { accountType: user.accountType } : {}),
        })),
    }
  }
}

export interface OrgTreeNode extends OrgRecord {
  children: OrgTreeNode[]
}

// -- Hachage de mot de passe (A-09 : KDF scrypt + comparaison à temps constant) ---------------------------------------------

/** Préfixe du format de stockage scrypt : `scrypt$<N>$<r>$<p>$<saltB64>$<hashB64>` (paramètres autodescriptifs avec le hachage, ajustable en douceur). */
const SCRYPT_PREFIX = 'scrypt$'
/** Palier plancher recommandé OWASP (N=2^14, r=8, p=1), environ 16 MiB de mémoire par dérivation. */
const SCRYPT_N = 16_384
const SCRYPT_R = 8
const SCRYPT_P = 1
const SCRYPT_KEYLEN = 64

/** Hachage de mot de passe au nouveau format (scrypt, sel aléatoire de 16 octets). */
function hashPasswordScrypt(password: string): string {
  const salt = randomBytes(16)
  const hash = scryptSync(password, salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P })
  return `${SCRYPT_PREFIX}${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64')}$${hash.toString('base64')}`
}

/** Hachage de mot de passe à l'ancien format (sha256 nu, référentiel des bases existantes ; uniquement pour la vérification de montée invisible, plus jamais en nouvelle écriture). */
function hashPassword(password: string, salt: string): string {
  return sha256Hex(`${salt}:${password}`)
}

/**
 * Vérification du mot de passe (comparaison à temps constant, timingSafeEqual) : le nouveau format recalcule avec les paramètres scrypt ;
 * l'ancien format (sha256 hex nu) est recalculé à l'ancien algorithme puis comparé à même précision — aucun des deux chemins ne retourne plus tôt sur différence de premier octet.
 */
function verifyPasswordHash(record: { passwordHash: string; passwordSalt: string }, password: string): boolean {
  if (record.passwordHash.startsWith(SCRYPT_PREFIX)) {
    const [n, r, p, saltB64, hashB64] = record.passwordHash.slice(SCRYPT_PREFIX.length).split('$')
    const expected = Buffer.from(hashB64 ?? '', 'base64')
    if (expected.length === 0 || !Number(n) || !Number(r) || !Number(p)) return false
    try {
      const actual = scryptSync(password, Buffer.from(saltB64 ?? '', 'base64'), expected.length, { N: Number(n), r: Number(r), p: Number(p) })
      return timingSafeEqual(expected, actual)
    } catch {
      return false
    }
  }
  const expected = Buffer.from(record.passwordHash, 'utf8')
  const actual = Buffer.from(hashPassword(password, record.passwordSalt), 'utf8')
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    iam: IamService
  }
}

export const name = 'iam'
export const inject = ['opsStorage', 'platformBus']

export function apply(ctx: Context) {
  ctx.plugin(IamService)
  ctx.plugin(iamTools)
}
