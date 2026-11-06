/**
 * @ybkk/plugin-panel-core — service de domaine du panneau départemental (review-dsh-agent-panel-v2 Phase 1/2).
 *
 * Plan de données (collections opsStorage ; la plateforme n'avait pas auparavant de modèle channel/message, l'une des plus grosses lacunes atterrit ici) :
 *   panel:deptConfigs   département↔thème/mode de collaboration/ligne-up d'Agents/KPI/disposition widget (habillage piloté par les données, un squelette, cinq habillages)
 *   panel:channels      canaux de collaboration
 *   panel:messages      messages (quatre classes de bulles + carte d'opération Agent + état de synchronisation DingTalk ; uniqueKey soutient la déduplication du pont)
 *   panel:tasks         machine à états des couloirs de tâches (todo/doing/review/done, point d'atterrissage des actions de carte)
 *   panel:artifacts     savoir départemental (dépôt des productions d'Agent, réutilisation par référence)
 *   panel:readCursors   curseurs de non-lu
 *   panel:activations   activation de secteur (org×secteur, deux états active/locked en base ; pending = dossier en cours au centre d'approbations)
 *
 * panelAgentRuntime (MVP tour unique, review Phase 1 item 8) : @Agent invoqué → lit l'actif Agent
 * (model/systemPrompt) → modelgw.invoke en tour unique → la production écrite dans messages/artifacts → metering usage
 * (panel:<dept>.<code secteur>, format de clé de l'arbitrage D1) → émet panel.message.created.
 * Orientation du modèle : la bascule explicite de la boîte de dialogue (modelOverride) prime, sinon suit l'attribut model de l'actif Agent ;
 * passerelle de modèles non configurée = dégradation honnête (tâche escaladée à l'humain), pas de completion fabriquée (aligné sur les principes de modelgw).
 *
 * Évaluation des widgets resolveWidgetSource : adaptation aux quatre sources connector/mcp/manual/mock, dégradation indépendante par widget
 * (recopie du paradigme portal.board()) ; le badge de source (connecteur/manuel/simulé) est un DoD dur de gouvernance.
 */
import { createHash } from 'node:crypto'
import { Service } from '@deepseek-ai/cordis'
import type { Collection, RecordBase } from '../../platform-core/src/storage.ts'
import { PlatformEvents } from '../../platform-core/src/bus.ts'
import type { SceneActivity, ScenegraphPack } from '../../platform-core/src/scenegraph.ts'
import { ACTIVITY_LABELS } from '../../platform-core/src/scenegraph.ts'
import type { WorkforcePolicyRegistry } from '../../platform-core/src/workforce-port.ts'
import { newId } from '../../platform-core/src/ids.ts'
import { resolvePanelModelGateway } from './llm-bridge.ts'
import type { AuditLogRecord } from '../../plugin-audit/src/index.ts'

/**
 * Annotation de typage question-réponse V16/D08 (additive) : l'appel de modèle en tour unique du panneau/A2A est une « question-réponse », il ne constitue pas une exécution de tâche.
 * Quand l'Agent cible atteint un employé numérique géré (recherche inverse serveur du port workforce), ce champ accompagne la réponse ;
 * port non prêt/non atteint = absent (sémantique legacy, consommateur rétrocompatible).
 */
export interface PanelWorkforceNotice {
  managed: true
  employeeId: string
  /** Libellé de référentiel fixe : un résultat de question-réponse ne constitue ni exécution de tâche ni acceptance de livrable (typage intégral question-réponse vs exécution). */
  notice: string
}

/** Chargement probant des skills V16/D08 (lien D09, additive) : un appel direct réussi renvoie avec la réponse l'empreinte de version du skill réellement chargé. */
export interface PanelSkillLoad {
  skillId: string
  version: string
  /** Résumé du contenu d'instructions de la version courante (sha256 hex) : version installée, résumé de chargement et usage réel sont réconciliables (D09). */
  contentHash?: string
}

// ---------------------------------------------------------------------------
// Modèle d'enregistrements
// ---------------------------------------------------------------------------

export interface DeptAgent {
  /** Nom d'affichage du panneau (clé d'invocation @). */
  name: string
  desc: string
  icon: string
  busy?: boolean
  /** Référence de l'actif Agent lié (agent:<idOrSlug>) ; défaut = non géré, dégradation honnête à l'exécution. */
  agentRef?: string
}

export interface DeptKpi {
  label: string
  value: string
  /** Badge de source (DoD de gouvernance) : manual manuel / mock démo / connector connecteur métier. */
  source: 'manual' | 'mock' | 'connector'
}

export type WidgetType = 'bars' | 'funnel' | 'alerts' | 'todos' | 'feeds'

export interface DeptWidget {
  id: string
  type: WidgetType
  title: string
  live?: boolean
  /** Badge de source (DoD de gouvernance) : quatre sources connector/mcp/manual/mock. */
  source: 'manual' | 'mock' | 'connector' | 'mcp'
  /** Référence de la source connector/mcp (action de connecteur / nom d'outil MCP) ; v1, en l'absence de connecteur métier, l'évaluation se dégrade. */
  ref?: string
  /** Données de lignes (structure propre à chacun des cinq types, cohérente avec le contrat de rendu du front). */
  rows: unknown[][]
}

export interface DeptConfigRecord extends RecordBase {
  id: string
  label: string
  icon: string
  theme: string
  collab: string
  /** Clé d'activité métier montée (cartographie ACT du scénario, ex. le département mfg monte mfg+scm). */
  acts: string[]
  colors: { accent: string; soft: string; deep: string }
  agents: DeptAgent[]
  kpis: DeptKpi[]
  widgets: DeptWidget[]
  /**
   * Organisation de la plateforme liée (interconnexion comptes-organisations) : posée, les permissions de périmètre départemental prennent effet — seuls les membres
   * du sous-arbre de cette organisation (et l'admin '*', les identifiants machine) peuvent accéder au panneau du département ; défaut = ouvert aux détenteurs de panel.read.
   */
  orgId?: string
}

export interface ChannelRecord extends RecordBase {
  dept: string
  name: string
  desc?: string
  createdBy: string
}

export interface MessageCardOp {
  id: string
  label: string
  style?: 'primary' | 'dd' | 'plain'
  /** Comportement du bouton : task.create crée une tâche / task.transition migre de couloir / approval.request passe la chaîne d'approbation / dd.push pousse DingTalk / ack trace seulement. */
  action?: 'task.create' | 'task.transition' | 'approval.request' | 'dd.push' | 'ack'
  /** Couloir cible de task.transition. */
  lane?: 'todo' | 'doing' | 'review' | 'done'
  /** Niveau de risque d'approval.request (high = double confirmation forcée au centre d'approbations). */
  risk?: 'high' | 'medium' | 'low'
}

export interface MessageRecord extends RecordBase {
  channelId: string
  dept: string
  senderType: 'human' | 'agent' | 'system'
  senderId?: string
  senderName: string
  senderIcon?: string
  /** Texte (rendu en liste blanche côté front : après échappement, seuls <b> et le span @mention passent). */
  text: string
  mentions: string[]
  card?: { title: string; ops: MessageCardOp[]; done: string[] }
  /** État de synchronisation DingTalk : none fermé / pending en attente de livraison par le pont / sent livré / failed échec / origin venant de DingTalk. */
  ddSync: 'none' | 'pending' | 'sent' | 'failed' | 'origin'
  agentName?: string
  /** Slug du modèle réellement utilisé par la réponse de l'Agent (bascule de la boîte de dialogue ou résolution de l'actif Agent) ; absent des messages humains. */
  model?: string
  sceneCode?: string
  /** Clé de déduplication entrante du pont (unique au niveau moteur quand le sender la fournit). */
  uniqueKey?: string
}

export interface TaskRecord extends RecordBase {
  dept: string
  title: string
  detail?: string
  lane: 'todo' | 'doing' | 'review' | 'done'
  assigneeType: 'human' | 'agent'
  assigneeName?: string
  sceneCode?: string
  messageId?: string
  createdBy: string
  /** ── Lignée du centre d'exécution (additive DSH issue#3, 2026-10-29) : panneau = projection du centre d'exécution, pas de copie de l'état d'autorité ── */
  /** Tâche exec-hub liée (exec:issues.id) ; portée = « la migration de couloir du panneau se ré-écrit en miroir vers exec-hub ». */
  execIssueId?: string
  /** Objectif racine de lignée (exec:goals.id, délivré redondamment avec execIssueId pour éviter une seconde recherche inverse). */
  goalId?: string
  /** Références du paquet de preuves (tableau d'URI produits NAS/approbation/audit, pour la réconciliation d'acceptance). */
  evidenceRefs?: string[]
  /** Conclusion d'acceptance : accepted = fermeture signée / rework = renvoi reprise (point d'atterrissage de l'action de signature du panneau, ré-écriture en miroir vers exec-hub). */
  verdict?: 'accepted' | 'rework'
  verdictBy?: string
  verdictAt?: string
  verdictOpinion?: string
  /** Lignée de renvoi (de quelle tâche provient la présente tâche renvoyée). */
  reworkOf?: string
}

export interface ArtifactRecord extends RecordBase {
  dept: string
  kind: 'report' | 'order' | 'quote' | 'diagnosis' | 'other'
  title: string
  content: string
  agentName?: string
  sceneCode?: string
  channelId?: string
  createdBy: string
}

export interface ReadCursorRecord extends RecordBase {
  userId: string
  channelId: string
  at: string
}

export interface ActivationRecord extends RecordBase {
  code: string
  orgId: string
  status: 'active'
  activatedAt: string
  approvalId?: string
  activatedBy?: string
}

/** Enregistrement d'un secteur non activé (paquet de cartographie absent = même activation erronée sans cartographie rendable, fail-closed). */
export interface IndustryRegistryEntry {
  code: string
  name: string
  icon: string
  sub: string
}

/**
 * Enregistrement intégré des secteurs (refonte IAW 2026-09-11) : les 14 secteurs prioritaires du « référentiel (édition 2025) » du ministère de l'Industrie tous enregistrés,
 * codes en correspondance un-un avec les paquets de cartographie de scénarios (scenegraphs/*.json). Les paquets QB01/YB01/JB01 sont distribués avec la plateforme ;
 * les autres paquets sont également intégrés, l'activation passe par la chaîne d'autorisation de la plateforme hôte (approbation + metering usage + trace d'audit).
 */
export const INDUSTRY_REGISTRY: IndustryRegistryEntry[] = [
  { code: 'YB01', name: '钢铁行业', icon: '🏭', sub: '铁前/炼铁/炼钢/轧钢 · 一图四清单 · 98 场景' },
  { code: 'SH01', name: '石化行业', icon: '🛢️', sub: '炼制/有机化学品/高分子 · 一图四清单 · 90 场景' },
  { code: 'JB01', name: '工程机械行业', icon: '🚜', sub: '研发设计/零部件/总装/营销服务 · 一图四清单 · 46 场景' },
  { code: 'QC01', name: '新能源汽车行业', icon: '🚗', sub: '基础材料/三电/整车/智能网联 · 一图四清单 · 96 场景' },
  { code: 'JB02', name: '机器人行业', icon: '🤖', sub: '核心零部件/本体/集成应用 · 一图四清单 · 75 场景' },
  { code: 'WS01', name: '医疗装备行业', icon: '🏥', sub: '材料/部件/整机/服务 · 一图四清单 · 117 场景' },
  { code: 'QB01', name: '家电行业', icon: '📺', sub: '整机/结构件/交互感知/电控/核心零部件 · 一图四清单 · 73 场景' },
  { code: 'QB02', name: '制糖行业', icon: '🍬', sub: '糖料/压榨/制炼/成品流通 · 一图四清单 · 22 场景' },
  { code: 'QB03', name: '白酒行业', icon: '🍶', sub: '制曲/酿造/储存/包装/供应链 · 一图四清单 · 44 场景' },
  { code: 'QB04', name: '美妆日化行业', icon: '💄', sub: '产品开发/生产制造/渠道运营 · 一图四清单 · 32 场景' },
  { code: 'SJ01', name: '锂电池行业', icon: '🔋', sub: '锂盐/主材/电芯/电池包 · 一图四清单 · 73 场景' },
  { code: 'SJ02', name: '印制板行业', icon: '🟩', sub: '覆铜板/PCB 制造/PCBA · 一图四清单 · 43 场景' },
  { code: 'SJ03', name: '智能移动终端行业', icon: '📱', sub: '研发设计/生产准备/组件/整机 · 一图四清单 · 61 场景' },
  { code: 'WJ01', name: '民爆行业', icon: '⚠️', sub: '原材/组件/雷管装配/销售仓储 · 一图四清单 · 15 场景' },
]

export const TASK_LANES = ['todo', 'doing', 'review', 'done'] as const
export type TaskLane = (typeof TASK_LANES)[number]
export const LANE_LABELS: Record<TaskLane, string> = { todo: '待办', doing: '进行中', review: '待审', done: '完成' }

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class PanelService extends Service {
  static readonly provide = 'panel'

  private streamSubscribers = new Map<string, Set<(event: { name: string; payload: unknown }) => void>>()

  constructor(ctx: Context, config: Record<string, never> = {}) {
    super(ctx, 'panel')
    void config
  }

  /**
   * Lecture douce des services d'hôte optionnels (amincissement plan-gate01 Phase 2) : cordis 4.x n'a pas de syntaxe d'inject optionnel,
   * l'accès ctx.<clé> à une clé non déclarée jette durement sans inject dans un plugin activé (entériné par le spike) — les 9 clés optionnelles
   * (iam/authn/audit/usage/modelGateway/resourceCore/behavior/mcpRegistry/skillHub) passent uniformément par
   * ctx.reflect.get(clé, false) : avec fournisseur = instance (sémantique de la forme complète inchangée), sans = undefined
   * (dégradation à deux niveaux de l'état démo porte 01 : enregistrement nul pour les types registre / dégradation honnête pour les types capacité), jamais d'accès nu.
   */
  soft<T = any>(key: string): T | undefined {
    return this.ctx.reflect.get(key, false) as T | undefined
  }

  // -- Collections -----------------------------------------------------------------

  deptConfigs(): Collection<DeptConfigRecord> {
    return this.ctx.opsStorage.collection<DeptConfigRecord>('panel:deptConfigs')
  }

  channels(): Collection<ChannelRecord> {
    return this.ctx.opsStorage.collection<ChannelRecord>('panel:channels')
  }

  messages(): Collection<MessageRecord> {
    const collection = this.ctx.opsStorage.collection<MessageRecord>('panel:messages')
    collection.uniqueOn('bridge-dedup', (m) => (m.uniqueKey ? `${m.channelId}:${m.uniqueKey}` : `id:${m.id}`))
    return collection
  }

  tasks(): Collection<TaskRecord> {
    return this.ctx.opsStorage.collection<TaskRecord>('panel:tasks')
  }

  artifacts(): Collection<ArtifactRecord> {
    return this.ctx.opsStorage.collection<ArtifactRecord>('panel:artifacts')
  }

  readCursors(): Collection<ReadCursorRecord> {
    const collection = this.ctx.opsStorage.collection<ReadCursorRecord>('panel:readCursors')
    collection.uniqueOn('user-channel', (r) => `${r.userId}:${r.channelId}`)
    return collection
  }

  activations(): Collection<ActivationRecord> {
    return this.ctx.opsStorage.collection<ActivationRecord>('panel:activations')
  }

  // -- Départements et secteurs ------------------------------------------------------------

  dept(dept: string): DeptConfigRecord {
    const config = this.deptConfigs().get(dept)
    if (!config) throw new Error(`部门不存在：${dept}`)
    return config
  }

  /** Clé primaire d'organisation pour metering/activation : organisation de la personne connectée (la normalisation vers la racine de l'arbre org est garantie existante par l'appelant). */
  activeIndustry(orgId: string): { code: string; name: string } | undefined {
    const activation = this.activations().findOne((item) => item.orgId === orgId && item.status === 'active')
    if (!activation) return undefined
    const registry = INDUSTRY_REGISTRY.find((item) => item.code === activation.code)
    return { code: activation.code.toLowerCase(), name: registry?.name ?? activation.code }
  }

  // -- Interconnexion comptes-organisations : département ↔ organisation de la plateforme ---------------------------------

  /** Jugement d'inclusion de sous-arbre d'organisation (orgId remonte parentId jusqu'à rootId). Catalogue d'organisations absent (état démo) = fail-closed. */
  orgSubtreeContains(rootId: string, orgId: string): boolean {
    const iam = this.soft('iam')
    if (!iam) return false
    let current = iam.orgs().get(orgId)
    let guard = 0
    while (current && guard++ < 32) {
      if (current.id === rootId) return true
      current = current.parentId ? iam.orgs().get(current.parentId) : undefined
    }
    return false
  }

  /** Informations de l'organisation liée (nom résolu en temps réel, le renommage d'organisation ne laisse pas de données périmées). Catalogue absent = affichage honnête non lié. */
  deptOrg(dept: DeptConfigRecord): { id: string; name: string } | undefined {
    if (!dept.orgId) return undefined
    const org = this.soft('iam')?.orgs().get(dept.orgId)
    return org ? { id: org.id, name: org.name } : undefined
  }

  /**
   * Permissions de périmètre départemental (double canal contrôle d'accès × rattachement d'organisation) : l'admin '*' et les identifiants machine (face d'intégration autorisée via scope)
   * passent direct ; après liaison d'organisation, l'humain doit appartenir au sous-arbre ; département non lié = ouvert à tous les détenteurs de panel.read.
   * Le rôle org_admin bénéficie d'une exemption de gouvernance inter-départements (cohérente avec la sémantique de gouvernance de iam.*).
   */
  deptScopeAllowed(exchangeCaller: { kind: string; userId?: string; permissions: string[] }, dept: DeptConfigRecord): boolean {
    if (exchangeCaller.permissions.includes('*')) return true
    if (exchangeCaller.kind === 'machine') return true
    if (!dept.orgId) return true
    if (exchangeCaller.userId) {
      const iam = this.soft('iam')
      const user = iam?.users().get(exchangeCaller.userId)
      if (user) {
        const isOrgAdmin = user.roleIds.some((roleId) => iam?.roles().get(roleId)?.code === 'org_admin')
        if (isOrgAdmin) return true
        return this.orgSubtreeContains(dept.orgId, user.orgId)
      }
    }
    return false
  }

  /** Registre du département : membres du sous-arbre de l'organisation liée (ou repli toutes organisations) (PII minimales : nom/fonction/nom d'organisation). Catalogue absent (état démo) → registre vide. */
  deptMembers(dept: DeptConfigRecord, limit = 50): Array<{ id: string; name: string; title?: string; orgName?: string }> {
    const iam = this.soft('iam')
    if (!iam) return []
    const orgRoot = dept.orgId ?? iam.orgs().find((org) => org.parentId === null).at(0)?.id
    if (!orgRoot) return []
    const inScope = (orgId: string): boolean => this.orgSubtreeContains(orgRoot, orgId)
    const orgName = (orgId: string): string => iam.orgs().get(orgId)?.name ?? ''
    return iam.users().all()
      .filter((user) => user.status === 'active' && inScope(user.orgId))
      .slice(0, limit)
      .map((user) => ({ id: user.id, name: user.displayName, ...(user.title ? { title: user.title } : {}), orgName: orgName(user.orgId) }))
  }

  /** Clé de metering (arbitrage D1) : panel:<dept>.<code secteur en minuscules> ; sans secteur activé, repli panel:<dept>.core. */
  meterResource(dept: string, orgId: string): string {
    const industry = this.activeIndustry(orgId)
    return `panel:${dept}.${industry?.code ?? 'core'}`
  }

  /** Trois états de secteur (sélecteur) : active activé / pending approbation en cours / locked en attente d'autorisation. */
  industryStates(orgId: string, pendingCodes: string[]): Array<IndustryRegistryEntry & { state: 'active' | 'pending' | 'locked'; graphLoaded: boolean }> {
    return INDUSTRY_REGISTRY.map((entry) => {
      const active = this.activations().findOne((item) => item.orgId === orgId && item.code === entry.code && item.status === 'active')
      const graphLoaded = this.ctx.scenegraphs.get(entry.code) !== undefined
      // Activé mais paquet de cartographie absent (ex. retiré) → toujours affiché active mais graphLoaded=false, la page de scénario se dégrade honnêtement
      const pending = !active && pendingCodes.includes(entry.code)
      return { ...entry, state: active ? 'active' : pending ? 'pending' : 'locked', graphLoaded }
    })
  }

  /**
   * Exécuteur d'activation de secteur (exécuteur d'approbations audit) : approbation accordée → pose active + grantCapabilities + événement.
   * Arbitrage review D6 : réutilisation de la chaîne d'approbation + autorisation de capacités ; la chaîne d'émission de licence (clé privée Ed25519 de la plateforme) attend Phase 4.
   */
  buildActivationExecutor(): (payload: Record<string, unknown>, approverId: string) => Promise<unknown> {
    return async (payload, approverId) => {
      const code = String(payload.code ?? '')
      const orgId = String(payload.orgId ?? '')
      if (!code || !orgId) throw new Error('行业激活审批单缺少 code/orgId')
      if (!INDUSTRY_REGISTRY.some((item) => item.code === code)) throw new Error(`未登记行业：${code}`)
      const existing = this.activations().findOne((item) => item.orgId === orgId && item.code === code)
      if (existing) {
        this.activations().update(existing.id, { status: 'active', activatedAt: new Date().toISOString(), activatedBy: approverId })
      } else {
        this.activations().insert({ id: newId('act'), code, orgId, status: 'active', activatedAt: new Date().toISOString(), approvalId: String(payload.approvalId ?? ''), activatedBy: approverId })
      }
      try {
        this.soft('usage')?.grantCapabilities(`org:${orgId}`, [`panel:${code.toLowerCase()}`], 'industry-activation')
      } catch { /* une panne de metering à l'exécution ne bloque pas l'activation (dégradation indépendante du plan de facturation) */ }
      this.ctx.platformBus.emit(PlatformEvents.PanelIndustryActivated, { code, orgId, activatedBy: approverId })
      return { code, orgId, status: 'active' }
    }
  }

  /** Ligne-up d'Agents × interconnexion avec les actifs Agent : l'existence et l'état de cycle de vie de l'actif lié sont résolus en temps réel (face en ligne des employés numériques hôtes). Catalogue d'actifs absent (état démo) → affichage non lié. */
  agentWithAsset(agentCard: DeptAgent): DeptAgent & { asset?: { id: string; slug?: string; name: string; status: string; model?: string } } {
    const ref = agentCard.agentRef?.replace(/^agent:/, '') ?? ''
    if (!ref) return { ...agentCard }
    const asset = this.soft('resourceCore')?.list('agent').find((item) => item.id === ref || item.slug === ref || item.name === ref)
    if (!asset) return { ...agentCard }
    const attrs = asset.attrs as Record<string, unknown> | undefined
    return {
      ...agentCard,
      asset: {
        id: asset.id, ...(asset.slug ? { slug: asset.slug } : {}), name: asset.name,
        status: String(asset.status ?? 'draft'), ...(attrs?.model ? { model: String(attrs.model) } : {}),
      },
    }
  }

  // -- Évaluation des widgets (recopie du paradigme de dégradation indépendante par source de portal.board()) -------------------

  resolveWidgetSource(widget: DeptWidget): { rows: unknown[][]; degraded: boolean; sourceLabel: string } {
    const labels = { manual: '手工登记', mock: '模拟数据', connector: '连接器', mcp: 'MCP' }
    if (widget.source === 'manual' || widget.source === 'mock') {
      return { rows: widget.rows, degraded: false, sourceLabel: labels[widget.source] }
    }
    // v1, écosystème de connecteurs métier absent (revue section C : en période de démo, 100% manual/mock + badge de source),
    // les widgets de source connector/mcp se dégradent explicitement, jamais de fausses données se faisant passer pour une vraie face métier
    return {
      rows: [],
      degraded: true,
      sourceLabel: `${labels[widget.source]}（${widget.ref ?? '未配置'}）暂不可用——等待业务连接器接入`,
    }
  }

  /** Agrégat du tableau de bord départemental : tous les widgets évalués avec dégradation indépendante (une tuile en panne ne coule pas le tableau). */
  board(dept: DeptConfigRecord): Array<{ id: string; type: WidgetType; title: string; live?: boolean; source: string; degraded: boolean; rows: unknown[][] }> {
    return dept.widgets.map((widget) => {
      try {
        const resolved = this.resolveWidgetSource(widget)
        return { id: widget.id, type: widget.type, title: widget.title, ...(widget.live ? { live: true } : {}), source: resolved.sourceLabel, degraded: resolved.degraded, rows: resolved.rows }
      } catch {
        return { id: widget.id, type: widget.type, title: widget.title, source: '求值失败', degraded: true, rows: [] as unknown[][] }
      }
    })
  }

  // -- Messages et canaux --------------------------------------------------------------

  /** Non-lus : nombre de messages d'autrui postérieurs au lastReadAt du canal. */
  unreadCount(userId: string, channelId: string): number {
    const cursor = this.readCursors().findOne((item) => item.userId === userId && item.channelId === channelId)
    const since = cursor?.at ?? ''
    return this.messages().find((m) => m.channelId === channelId && m.createdAt > since && m.senderId !== userId).length
  }

  markRead(userId: string, channelId: string): void {
    const at = new Date().toISOString()
    const cursor = this.readCursors().findOne((item) => item.userId === userId && item.channelId === channelId)
    if (cursor) this.readCursors().update(cursor.id, { at })
    else this.readCursors().insert({ id: newId('cur'), userId, channelId, at })
  }

  /**
   * Envoi d'un message : inscription → avance du curseur → événement (le pont DingTalk souscrit et livre) → invocation @Agent.
   * Renvoie le message inscrit ; la réponse de l'Agent s'ajoute en asynchrone (l'appelant tire ensuite).
   */
  async sendMessage(input: {
    dept: string
    channelId: string
    senderType: 'human' | 'agent' | 'system'
    senderId?: string
    senderName: string
    text: string
    ddSync: boolean
    card?: MessageRecord['card']
    sceneCode?: string
    uniqueKey?: string
    /** Bascule de modèle de la boîte de dialogue : modèle spécifié pour cette session (défaut : suit l'attribut model de chaque actif Agent). */
    modelOverride?: string
    /** Pour la trace de l'appel direct slash de skill : n'inscrit que le message sans invoquer @Agent (le même texte ne repasse pas par le canal Agent). */
    skipAgentDispatch?: boolean
    /** Champs d'affichage de la réponse de type agent (senderIcon/agentName/modèle réellement utilisé), portés seulement si senderType='agent'. */
    senderIcon?: string
    agentName?: string
    replyModel?: string
  }): Promise<MessageRecord> {
    const channel = this.channels().get(input.channelId)
    if (!channel || channel.dept !== input.dept) throw new Error(`频道不存在或不属于该部门：${input.channelId}`)
    const mentions = extractMentions(input.text)
    const record = this.messages().insert({
      id: newId('pmsg'),
      channelId: input.channelId,
      dept: input.dept,
      senderType: input.senderType,
      ...(input.senderId ? { senderId: input.senderId } : {}),
      senderName: input.senderName,
      text: input.text,
      mentions,
      ...(input.senderType === 'agent' && input.senderIcon ? { senderIcon: input.senderIcon } : {}),
      ...(input.senderType === 'agent' && input.agentName ? { agentName: input.agentName } : {}),
      ...(input.senderType === 'agent' && input.replyModel ? { model: input.replyModel } : {}),
      ...(input.card ? { card: { ...input.card, done: [] } } : {}),
      ddSync: input.senderType === 'system' ? 'none' : input.ddSync ? 'pending' : 'none',
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}),
      ...(input.uniqueKey ? { uniqueKey: input.uniqueKey } : {}),
    })
    if (input.senderId) this.markRead(input.senderId, input.channelId)
    this.ctx.platformBus.emit(PlatformEvents.PanelMessageCreated, {
      messageId: record.id, dept: input.dept, channelId: input.channelId,
      senderName: input.senderName, text: input.text, ddSync: record.ddSync,
      card: record.card, title: record.card?.title ?? '',
    })
    if (input.senderType === 'human' && input.skipAgentDispatch !== true) void this.dispatchAgentMentions(record, input.modelOverride)
    return record
  }

  /**
   * panelAgentRuntime MVP (tour unique) : @Agent invoqué → actif Agent → modelgw en tour unique → réponse inscrite.
   * Orientation du modèle : le modelOverride explicitement spécifié dans la boîte de dialogue prime, sinon suit l'attribut model de l'actif Agent.
   * Pas d'actif lié/aucun modèle disponible → message de dégradation honnête + à-faire escaladé à l'humain, pas de réponse fabriquée.
   */
  async dispatchAgentMentions(message: MessageRecord, modelOverride?: string): Promise<void> {
    const dept = this.dept(message.dept)
    for (const agentCard of dept.agents) {
      // Correspondance par nom complet du registre (le nom d'Agent contient souvent des espaces, ex. « Agent d'analyse qualité »), une regex générique ne suffit pas
      if (!message.text.includes(`@${agentCard.name}`)) continue
      await this.invokeAgent(dept, agentCard, message, modelOverride)
    }
  }

  /** Inscription de la réponse de l'Agent + diffusion d'événement (partagé invokeAgent / streamAgentReply ; l'annotation de typage V16/D08 transparaît avec l'événement). */
  private async insertAgentReply(
    dept: DeptConfigRecord, agentCard: DeptAgent, trigger: MessageRecord, text: string,
    card?: MessageRecord['card'], usedModel?: string, workforce?: PanelWorkforceNotice,
  ): Promise<MessageRecord> {
    const record = this.messages().insert({
      id: newId('pmsg'), channelId: trigger.channelId, dept: dept.id,
      senderType: 'agent', senderName: agentCard.name, senderIcon: agentCard.icon,
      text, mentions: [], ...(card ? { card: { ...card, done: [] } } : {}),
      ddSync: 'none', agentName: agentCard.name, ...(usedModel ? { model: usedModel } : {}),
      ...(trigger.sceneCode ? { sceneCode: trigger.sceneCode } : {}),
    })
    this.ctx.platformBus.emit(PlatformEvents.PanelMessageCreated, {
      messageId: record.id, dept: dept.id, channelId: trigger.channelId,
      senderName: agentCard.name, text, ddSync: 'none', card: record.card, title: record.card?.title ?? '',
      // Annotation de typage additive V16/D08 (n'apparaît qu'en cas d'employé géré atteint ; l'éventail SSE du panneau transmet tel quel, le front consomme au besoin)
      ...(workforce ? { workforce } : {}),
    })
    return record
  }

  /**
   * Résolution préalable de l'appel d'Agent (partagée invokeAgent / streamAgentReply) : liaison d'actif → orientation de modèle →
   * assemblage du contexte de canal + résumé de cartographie de scénario du département. Quand ok:false, reason est un libellé de dégradation honnête affichable ;
   * la charge ok porte asset (base du resourceId d'audit et de la détection de typage V16/D08).
   */
  private prepareAgentInvocation(
    dept: DeptConfigRecord,
    agentCard: DeptAgent,
    trigger: MessageRecord,
    modelOverride?: string,
    contextNote?: string,
  ): { ok: true; model: string; systemPrompt: string; userText: string; asset: { id: string } } | { ok: false; reason: string } {
    const channel = this.channels().get(trigger.channelId)
    const ref = agentCard.agentRef?.replace(/^agent:/, '') ?? ''
    const asset = ref ? this.soft('resourceCore')?.list('agent').find((item) => item.id === ref || item.slug === ref || item.name === ref) : undefined
    if (!asset) return { ok: false, reason: '未绑定 Agent 资产（请在控制台「Agent 本体」登记并在此配置 agentRef）' }
    // Orientation du modèle (relâchement 2026-09-11) : bascule explicite de la boîte de dialogue > attribut model de l'actif Agent > premier modèle en ligne du catalogue.
    // Motif du relâchement : l'énumération de modèles du schéma d'actif (série deepseek) et le catalogue réellement disponible (MiniMax / provider:model du pont dsh)
    // s'accordent rarement — l'ancienne logique jugeait directement « modèle non configuré » et escaladait à l'humain, @collègue numérique restait sans réponse. Le repli ne fabrique rien :
    // la réponse est annotée du modèle réellement utilisé (champ model + badge 🧠 du front), catalogue vide = refus honnête d'origine maintenu.
    const preferred = modelOverride ?? String((asset.attrs as Record<string, unknown> | undefined)?.model ?? '')
    const resolved = resolvePanelModelGateway(this.ctx)
    const catalog = resolved?.gateway.models?.().all?.() ?? []
    const online = catalog.filter((item: { status: string }) => item.status === 'online')
    let model = preferred
    if (!model || !catalog.some((item: { slug: string }) => item.slug === model)) {
      if (online.length > 0) model = online[0]!.slug
      else if (resolved?.kind === 'dsh') model = 'default' // catalogue paresseux du pont DSH : default suit la résolution de la configuration dsh
    }
    if (!model) return { ok: false, reason: 'Agent 资产未配置模型（model 属性为空），且本次会话未指定模型' }
    // Assemble le contexte de canal (8 derniers messages) + résumé de cartographie de scénario du département
    const recent = this.messages().find((m) => m.channelId === trigger.channelId).slice(-8)
    const contextText = recent.map((m) => `${m.senderName}: ${m.text}`).join('\n')
    const sceneSummary = this.sceneSummaryForDept(dept)
    const systemPrompt = [
      String((asset.attrs as Record<string, unknown> | undefined)?.systemPrompt ?? `你是企业部门协作面板中的数字同事「${agentCard.name}」（${agentCard.desc}）。`),
      sceneSummary ? `本部门挂载的行业场景图谱要点：\n${sceneSummary}` : '',
      contextNote ?? '',
      channel ? `以下是频道「${channel.name}」最近对话：\n${contextText}` : '',
    ].filter(Boolean).join('\n\n')
    return { ok: true, model, systemPrompt, userText: trigger.text, asset: { id: asset.id } }
  }

  /** Metering de collaboration post-appel de l'Agent (format de clé de l'arbitrage D1 ; saute seulement si la chaîne de repli org échoue à résoudre, un échec de metering ne bloque pas la face collaboration). */
  private meterAgentCall(dept: DeptConfigRecord, trigger: MessageRecord, agentCard: DeptAgent): void {
    const orgId = this.resolveOrgId(trigger.senderId, dept).orgId
    if (!orgId) return
    try {
      this.soft('usage')?.record({
        org: orgId,
        subject: trigger.senderId ? `user:${trigger.senderId}` : 'panel:runtime',
        principal: `org:${orgId}`,
        resource: this.meterResource(dept.id, orgId),
        meters: [{ key: 'calls', value: 1, unit: 'call' }],
        idempotency_key: `panel:agent:${trigger.id}:${agentCard.name}`,
      })
    } catch { /* échec de metering ne bloque pas la réponse */ }
  }

  async invokeAgent(dept: DeptConfigRecord, agentCard: DeptAgent, trigger: MessageRecord, modelOverride?: string): Promise<void> {
    const reply = (text: string, card?: MessageRecord['card'], usedModel?: string, workforce?: PanelWorkforceNotice) =>
      this.insertAgentReply(dept, agentCard, trigger, text, card, usedModel, workforce)
    const fallbackToHuman = async (reason: string) => {
      await reply(`「${agentCard.name}」暂不能自主应答：${reason}已转人工待办，请相关同事跟进。`)
      this.tasks().insert({
        id: newId('ptask'), dept: dept.id, title: `跟进：${trigger.text.slice(0, 40)}`,
        detail: `Agent「${agentCard.name}」不可用（${reason}），由消息 ${trigger.id} 转人工`,
        lane: 'todo', assigneeType: 'human', createdBy: `agent:${agentCard.name}`, messageId: trigger.id,
      })
    }
    const prepared = this.prepareAgentInvocation(dept, agentCard, trigger, modelOverride)
    if (!prepared.ok) return void fallbackToHuman(prepared.reason)
    // Détection de typage question-réponse V16/D08 : employé géré atteint → annotation additive de l'événement et de l'audit (question-réponse ≠ exécution de tâche)
    const workforce = await this.managedWorkforceOf(prepared.asset.id)
    // #17 : chaîne de repli d'organisation (caller→dept.orgId→organisation racine) — un principal machine/canal externe sans rattachement utilisateur ne perce plus le metering avec une chaîne vide
    const { orgId, orgSource } = this.resolveOrgId(trigger.senderId, dept)
    try {
      const gateway = resolvePanelModelGateway(this.ctx)?.gateway
      if (!gateway) throw new Error('模型网关未接入（01门演示态）——连接宿主后可用')
      const result = await gateway.invoke({
        model: prepared.model,
        orgId,
        subject: trigger.senderId ? `user:${trigger.senderId}` : 'panel:runtime',
        messages: [
          { role: 'system', content: prepared.systemPrompt },
          { role: 'user', content: prepared.userText },
        ],
      })
      await reply(stripThink(result.content), undefined, result.model, workforce)
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: `agent:${agentCard.name}`, actorName: agentCard.name,
        action: 'panel.agent.invoke', resourceType: 'agent', resourceId: prepared.asset.id, resourceName: agentCard.name,
        // V16 : référentiel d'audit = question-réponse/collaboration (panel.agent.invoke n'est pas une chaîne d'exécution) ; employé géré atteint = annotation de typage dans detail
        result: 'ok', detail: `model=${result.model} tokens=${result.inputTokens}/${result.outputTokens} org=${orgSource}${workforce ? `；workforce=受管员工(${workforce.employeeId})，${workforce.notice}` : ''}`,
        ...(trigger.sceneCode ? { sceneCode: trigger.sceneCode } : {}),
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      await fallbackToHuman(`模型网关调用失败（${message}）。`)
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: `agent:${agentCard.name}`, actorName: agentCard.name,
        action: 'panel.agent.invoke', resourceType: 'agent', resourceId: prepared.asset.id, resourceName: agentCard.name,
        result: 'error', detail: `model=${prepared.model} 失败：${message}`,
        ...(trigger.sceneCode ? { sceneCode: trigger.sceneCode } : {}),
      })
    } finally {
      this.meterAgentCall(dept, trigger, agentCard)
    }
  }

  /**
   * Réponse en flux de l'Agent (besoin utilisateur 2026-09-11 : @collègue numérique dans le canal → carte incrémentale SSE) :
   * onEvent reçoit {type:'start'|'delta'|'done'|'fallback'} ; le pont de modèles dsh suit le flux natif text-delta,
   * modelgw (invoke en tour unique) envoie le segment entier comme delta unique — capacités de canal différentes, sémantique de flux identique.
   * Une fois terminé, inscription et diffusion comme d'habitude (les autres bouts reçoivent le message persistant par SSE) ; dégradation et escalade humaine identiques à invokeAgent.
   */
  async streamAgentReply(
    dept: DeptConfigRecord,
    agentCard: DeptAgent,
    trigger: MessageRecord,
    modelOverride: string | undefined,
    onEvent: (event: { type: 'start' | 'delta' | 'done' | 'fallback'; text?: string; agent?: string; icon?: string; model?: string; reason?: string }) => void,
  ): Promise<void> {
    onEvent({ type: 'start', agent: agentCard.name, icon: agentCard.icon })
    const fallback = async (reason: string) => {
      onEvent({ type: 'fallback', agent: agentCard.name, reason })
      await this.insertAgentReply(dept, agentCard, trigger, `「${agentCard.name}」暂不能自主应答：${reason}已转人工待办，请相关同事跟进。`)
      this.tasks().insert({
        id: newId('ptask'), dept: dept.id, title: `跟进：${trigger.text.slice(0, 40)}`,
        detail: `Agent「${agentCard.name}」不可用（${reason}），由消息 ${trigger.id} 转人工`,
        lane: 'todo', assigneeType: 'human', createdBy: `agent:${agentCard.name}`, messageId: trigger.id,
      })
      onEvent({ type: 'done', agent: agentCard.name })
    }
    const prepared = this.prepareAgentInvocation(dept, agentCard, trigger, modelOverride)
    if (!prepared.ok) return void fallback(prepared.reason)
    // Détection de typage question-réponse V16/D08 + chaîne de repli d'organisation #17 (même règle qu'invokeAgent)
    const workforce = await this.managedWorkforceOf(prepared.asset.id)
    const { orgId, orgSource } = this.resolveOrgId(trigger.senderId, dept)
    try {
      const resolved = resolvePanelModelGateway(this.ctx)
      if (!resolved) throw new Error('模型网关未接入（01门演示态）——连接宿主后可用')
      const gateway = resolved.gateway as {
        invoke(input: Record<string, unknown>): Promise<{ content: string; model: string }>
        streamEvents?(input: Record<string, unknown>): AsyncIterable<{ delta?: string; model?: string }>
      }
      const messages = [
        { role: 'system', content: prepared.systemPrompt },
        { role: 'user', content: prepared.userText },
      ]
      let content = ''
      let usedModel = ''
      const gatedDelta = createThinkGate((text) => {
        onEvent({ type: 'delta', agent: agentCard.name, text, model: usedModel || undefined })
      })
      if (typeof gateway.streamEvents === 'function') {
        for await (const chunk of gateway.streamEvents({
          model: prepared.model,
          orgId,
          messages,
          subject: trigger.senderId ? `user:${trigger.senderId}` : 'panel:runtime',
        })) {
          if (chunk.model) usedModel = chunk.model
          if (chunk.delta) {
            content += chunk.delta
            gatedDelta(chunk.delta)
          }
        }
      } else {
        // Forme modelgw en tour unique : le segment entier comme delta unique (pas de fausse animation de flux, la capacité du canal est présentée telle quelle)
        const result = await gateway.invoke({
          model: prepared.model,
          orgId,
          subject: trigger.senderId ? `user:${trigger.senderId}` : 'panel:runtime',
          messages,
        })
        content = result.content
        usedModel = result.model
        gatedDelta(result.content)
      }
      const finalContent = stripThink(content)
      if (!finalContent) {
        await fallback('模型只输出了思考过程（<think> 未闭合或正文为空），没有可展示的应答。')
        return
      }
      await this.insertAgentReply(dept, agentCard, trigger, finalContent, undefined, usedModel || undefined, workforce)
      onEvent({ type: 'done', agent: agentCard.name })
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: `agent:${agentCard.name}`, actorName: agentCard.name,
        action: 'panel.agent.invoke', resourceType: 'agent', resourceId: prepared.asset.id, resourceName: agentCard.name,
        result: 'ok', detail: `model=${usedModel || prepared.model} stream=1 org=${orgSource}${workforce ? `；workforce=受管员工(${workforce.employeeId})，${workforce.notice}` : ''}`,
        ...(trigger.sceneCode ? { sceneCode: trigger.sceneCode } : {}),
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      await fallback(`模型网关调用失败（${message}）。`)
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: `agent:${agentCard.name}`, actorName: agentCard.name,
        action: 'panel.agent.invoke', resourceType: 'agent', resourceId: prepared.asset.id, resourceName: agentCard.name,
        result: 'error', detail: `model=${prepared.model} 失败：${message}`,
        ...(trigger.sceneCode ? { sceneCode: trigger.sceneCode } : {}),
      })
    } finally {
      this.meterAgentCall(dept, trigger, agentCard)
    }
  }

  private callerOrgId(userId?: string): string {
    if (!userId) return ''
    const user = this.soft('iam')?.users().get(userId)
    return user?.orgId ?? ''
  }

  /** Première organisation racine de la plateforme (sans organisation parente) ; undefined si l'arbre d'organisations n'est pas ensemencé (état démo porte 01). */
  private rootOrgId(): string | undefined {
    try {
      return this.soft('iam')?.orgs().all().find((org: { parentId?: string | null }) => !org.parentId)?.id
    } catch {
      return undefined
    }
  }

  /**
   * Chaîne de repli de résolution du rattachement d'organisation (#17, replanté du socle 2026-10-29) : organisation de l'utilisateur appelant → organisation liée du département (R11) → organisation racine de la plateforme.
   * Principaux machine / canaux d'outils externes sans rattachement utilisateur : auparavant orgId chaîne vide allait droit à modelgw — après réponse du modèle, à l'inscription du metering,
    * l'erreur « org obligatoire dans l'événement usage », payer d'abord erreur ensuite ; désormais le vrai rattachement est résolu avant l'appel, orgSource tracé dans l'audit.
   */
  private resolveOrgId(userId: string | undefined, dept?: { id: string; orgId?: string }): { orgId: string; orgSource: string } {
    const caller = this.callerOrgId(userId)
    if (caller) return { orgId: caller, orgSource: 'caller' }
    const deptOrg = dept?.orgId ?? ''
    if (deptOrg) return { orgId: deptOrg, orgSource: `dept:${dept!.id}` }
    const root = this.rootOrgId()
    if (root) return { orgId: root, orgSource: 'platform-root' }
    return { orgId: '', orgSource: 'unresolved' }
  }

  /**
   * Détection structurée V16/D08 de l'employé numérique géré : recherche inverse serveur de l'agentId cible via le port étroit workforce
   * (ctx.workforcePolicy.port()?.describeManagedAgent). Port non prêt → undefined (statu quo legacy),
   * non atteint → undefined ; exception d'exécution du port → undefined (face question-réponse fail-open, une panne du port de gouvernance
   * ne bloque pas la réponse du panneau). Le jugement ne se fonde que sur la recherche inverse serveur, indépendamment de la présence d'un contexte work dans la requête (contrat gelé).
   */
  private async managedWorkforceOf(agentId: string): Promise<PanelWorkforceNotice | undefined> {
    try {
      const registry = (this.ctx as unknown as { workforcePolicy?: WorkforcePolicyRegistry }).workforcePolicy
      const port = registry?.port?.() ?? null
      if (!port) return undefined
      const managed = await port.describeManagedAgent(agentId)
      if (!managed) return undefined
      return { managed: true, employeeId: managed.employeeId, notice: '问答结果，不构成任务执行或交付验收' }
    } catch {
      return undefined
    }
  }

  /**
   * Question-réponse nominative à l'Agent du panneau (M3 : primitive de service de l'outil panel_agent_invoke — canal principal de collaboration du dialogue standard dsh).
   * Partage avec invokeAgent la résolution d'actif/l'orientation de modèle/l'assemblage du résumé de scénario, mais renvoie synchroniquement le texte de réponse, sans inscrire de message de canal
   * (l'appelant décide de tracer via panel_msg_send). Un échec renvoie honnêtement ok:false + reason, sans réponse fabriquée.
   */
  async askAgent(
    deptId: string,
    agentName: string,
    question: string,
    options: { userId?: string; modelOverride?: string; contextNote?: string; sceneCode?: string } = {},
  ): Promise<{ ok: true; reply: string; model: string; workforce?: PanelWorkforceNotice } | { ok: false; reason: string }> {
    const dept = this.dept(deptId)
    const agentCard = dept.agents.find((card) => card.name === agentName)
    if (!agentCard) {
      const names = dept.agents.map((card) => card.name)
      return { ok: false, reason: `部门 ${dept.id}（${dept.label}）名册无此 Agent。可用阵容：${names.join('、') || '（无）'}` }
    }
    const ref = agentCard.agentRef?.replace(/^agent:/, '') ?? ''
    const asset = ref ? this.soft('resourceCore')?.list('agent').find((item) => item.id === ref || item.slug === ref || item.name === ref) : undefined
    if (!asset) return { ok: false, reason: `Agent「${agentName}」未绑定 Agent 资产（agentRef），无法自主应答` }
    const model = options.modelOverride ?? String((asset.attrs as Record<string, unknown> | undefined)?.model ?? '')
    if (!model) return { ok: false, reason: `Agent「${agentName}」未配置模型（model 属性为空），且本次未指定模型` }
    // Détection de typage question-réponse V16/D08 : employé géré atteint → la réponse porte additive l'annotation workforce (question-réponse ≠ exécution de tâche) ;
    // pas de création de run, pas de changement d'état de tâche (typage intégral question-réponse vs exécution).
    const workforce = await this.managedWorkforceOf(asset.id)
    // #17 : chaîne de repli d'organisation (caller→dept.orgId→organisation racine), l'appel nominatif machine ne perce plus le metering avec une chaîne vide
    const { orgId, orgSource } = this.resolveOrgId(options.userId, dept)
    const sceneSummary = this.sceneSummaryForDept(dept)
    const systemPrompt = [
      String((asset.attrs as Record<string, unknown> | undefined)?.systemPrompt ?? `你是企业部门协作面板中的数字同事「${agentCard.name}」（${agentCard.desc}）。`),
      sceneSummary ? `本部门挂载的行业场景图谱要点：\n${sceneSummary}` : '',
      options.contextNote ?? '',
    ].filter(Boolean).join('\n\n')
    try {
      const gateway = resolvePanelModelGateway(this.ctx)?.gateway
      if (!gateway) throw new Error('模型网关未接入（01门演示态）——连接宿主后可用')
      const result = await gateway.invoke({
        model, orgId, subject: options.userId ? `user:${options.userId}` : 'panel:tool',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: question },
        ],
      })
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: `agent:${agentName}`, actorName: agentName,
        action: 'panel.agent.invoke', resourceType: 'agent', resourceId: asset.id, resourceName: agentName,
        // V16 : référentiel d'audit = question-réponse/collaboration ; employé géré atteint = annotation de typage dans detail
        result: 'ok', detail: `model=${result.model}（askAgent 直答）org=${orgSource}${workforce ? `；workforce=受管员工(${workforce.employeeId})，${workforce.notice}` : ''}`,
        ...(options.sceneCode ? { sceneCode: options.sceneCode } : {}),
      })
      return {
        ok: true, reply: stripThink(result.content), model: result.model,
        // Champ de typage additive V16/D08 : n'apparaît qu'en cas d'employé numérique géré atteint (le chemin legacy n'a pas cette clé)
        ...(workforce ? { workforce } : {}),
      } as { ok: true; reply: string; model: string; workforce?: PanelWorkforceNotice }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.auditSafe({
        type: 'invoke', actorType: 'machine', actorId: `agent:${agentName}`, actorName: agentName,
        action: 'panel.agent.invoke', resourceType: 'agent', resourceId: asset.id, resourceName: agentName,
        result: 'error', detail: `model=${model} 失败：${message}`,
        ...(options.sceneCode ? { sceneCode: options.sceneCode } : {}),
      })
      return { ok: false, reason: `模型网关调用失败（${message}）` }
    } finally {
      // Metering de collaboration au même style qu'invokeAgent (clé primaire org absente = saut ; un échec ne bloque pas la réponse)
      if (orgId) {
        try {
          this.soft('usage')?.record({
            org: orgId,
            subject: options.userId ? `user:${options.userId}` : 'panel:tool',
            principal: `org:${orgId}`,
            resource: this.meterResource(dept.id, orgId),
            meters: [{ key: 'calls', value: 1, unit: 'call' }],
            idempotency_key: `panel:ask:${dept.id}:${agentName}:${newId('ask')}`,
          })
        } catch { /* échec de metering ne bloque pas le jeu de questions-réponses */ }
      }
    }
  }

  // -- Appel direct de skill (C1-2 / face consommatrice J1 : canal principal @nom-de-skill/commande slash de la boîte de dialogue) ----------------------------

  /**
   * Liste des skills publiés directement appelables par le panneau (skillhub published + visibles par l'organisation de l'appelant).
   * Même référentiel de visibilité que skillhub.search (visibility=orgs filtre par l'organisation de l'appelant) ;
   * seuls les published sont directement appelables (deprecated/offline ne se laissent pas citer nominativement par le panneau).
   */
  listInvokeableSkills(viewerOrgId?: string): Array<{ id: string; name: string; slug: string; summary: string; category: string; version: string }> {
    const hub = this.soft('skillHub')
    if (!hub) return []
    return hub.skills().all()
      .filter((skill) => {
        if (skill.status !== 'published') return false
        if (skill.visibility === 'orgs') {
          if (!viewerOrgId || !skill.targetOrgs.includes(viewerOrgId)) return false
        }
        return true
      })
      .sort((a, b) => b.stats.downloads - a.stats.downloads)
      .map((skill) => ({
        id: skill.id, name: skill.name, slug: skill.slug,
        summary: skill.summary, category: skill.category, version: skill.currentVersion,
      }))
  }

  /**
   * Appel direct nominatif de skill du panneau (C1-2 : primitive de service partagée par l'outil panel_skill_invoke et la boîte de dialogue du panneau).
   * Sémantique : skill publié (published) de skillhub → prend le contenu de la version courante comme contexte d'instructions → réponse en tour unique de la passerelle de modèles.
   * Un échec renvoie honnêtement ok:false + reason (inexistant/non publié/invisible/sans contenu/échec de passerelle), sans réponse fabriquée, sans silence.
   * Même style qu'askAgent : pas d'inscription de message de canal, l'appelant décide de tracer via sendMessage.
   */
  async invokeSkill(
    skillName: string,
    message: string,
    options: { userId?: string; modelOverride?: string; contextNote?: string; sceneCode?: string } = {},
  ): Promise<{ ok: true; reply: string; model: string; skill: { name: string; version: string }; skillLoad?: PanelSkillLoad } | { ok: false; reason: string }> {
    const name = skillName.trim()
    if (!name) return { ok: false, reason: '技能名为空（用 /技能名 或 panel_skill_invoke 点名）' }
    // #17 : l'organisation racine ne sert qu'au rattachement du metering (correctif de sécurité PR #18) ; un principal machine sans organisation utilisateur
    // ne doit pas obtenir, par le repli de metering, la visibilité des skills restreints de l'organisation racine — la visibilité se juge sur l'organisation du vrai appelant.
    const { orgId } = this.resolveOrgId(options.userId)
    const viewerOrg = this.callerOrgId(options.userId)
    const invokeable = this.listInvokeableSkills(viewerOrg || undefined)
    // Correspondance prioritaire par nom complet, slug en repli (le nom de skill contient souvent chinois et espaces, une regex générique ne suffit pas)
    const skill = invokeable.find((item) => item.name === name) ?? invokeable.find((item) => item.slug === name)
    if (!skill) {
      const hint = this.soft('skillHub')?.skills().all().find((item) => item.status === 'published' && (item.name === name || item.slug === name))
      if (hint) return { ok: false, reason: `技能「${name}」未对当前用户组织开放（visibility=${hint.visibility}），无法直调` }
      const names = invokeable.slice(0, 8).map((item) => item.name)
      return { ok: false, reason: `没有已上架且对您开放的技能「${name}」。可用技能：${names.join('、') || '（无）'}` }
    }
    const record = this.soft('skillHub')?.skills().get(skill.id)
    const version = record?.versions.find((item) => item.version === skill.version && item.status === 'published')
    const content = version?.content?.trim() ?? ''
    if (!content) return { ok: false, reason: `技能「${skill.name}」当前版本（${skill.version}）无指令内容，无法直调` }
    // Chargement probant D09/V16 (additive) : l'ID/la version/le résumé de contenu du skill réellement chargé accompagnent la réponse,
    // pour la réconciliation en trois « version installée ↔ résumé de chargement ↔ usage réel » (résumé calculé à la volée, sans inscription ni modification du schéma skillhub).
    const skillLoad: PanelSkillLoad = {
      skillId: skill.id,
      version: skill.version,
      contentHash: createHash('sha256').update(content).digest('hex'),
    }
    // Orientation du modèle : explicite prioritaire ; à défaut, ne suit pas l'actif Agent (un skill n'a pas d'actif), prend automatiquement le premier modèle en ligne du catalogue
    // (un chef d'équipe qui n'a jamais choisi de modèle doit pouvoir appeler du premier coup — catalogue vide = seul cas de refus honnête)
    let model = options.modelOverride?.trim() ?? ''
    if (!model) {
      // Ne choisir automatiquement qu'un modèle « en ligne et avec endpoint configuré » — un modèle sans endpoint échoue forcément à l'appel et ne doit pas être choisi (durcissement J1)
      // (l'endpoint d'une entrée du catalogue du pont dsh est le placeholder non vide « canal intégré » → naturellement sélectionnable, exactement le comportement attendu en état installé porte 01)
      const online = resolvePanelModelGateway(this.ctx)?.gateway.models().all()
        .filter((item: { status: string; endpoint: string }) => item.status === 'online' && item.endpoint.trim() !== '') ?? []
      if (online.length === 0) return { ok: false, reason: '模型目录暂无在线模型——请管理员在「模型管理」中接入后再直调技能' }
      model = online[0]!.slug
    }
    const systemPrompt = [
      `你在执行企业技能平台上架的技能「${skill.name}」（${skill.summary}）。严格按以下技能指令完成任务：`,
      content,
      options.contextNote ?? '',
    ].filter(Boolean).join('\n\n')
    try {
      const gateway = resolvePanelModelGateway(this.ctx)?.gateway
      if (!gateway) throw new Error('模型网关未接入（01门演示态）——连接宿主后可用')
      const result = await gateway.invoke({
        model, orgId, subject: options.userId ? `user:${options.userId}` : 'panel:tool',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: message || '（无附加输入，按技能指令执行）' },
        ],
      })
      this.auditSafe({
        type: 'invoke', actorType: options.userId ? 'human' : 'machine', actorId: options.userId ?? 'panel:tool',
        actorName: options.userId ?? 'panel:tool',
        action: 'panel.skill.invoke', resourceType: 'skill', resourceId: skill.id, resourceName: skill.name,
        result: 'ok', detail: `model=${result.model} version=${skill.version} contentHash=${skillLoad.contentHash}`,
        ...(options.sceneCode ? { sceneCode: options.sceneCode } : {}),
      })
      return {
        ok: true, reply: stripThink(result.content), model: result.model, skill: { name: skill.name, version: skill.version },
        // D09/V16 additive : empreinte du chargement probant (skillId/version/contentHash)
        skillLoad,
      }
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      this.auditSafe({
        type: 'invoke', actorType: options.userId ? 'human' : 'machine', actorId: options.userId ?? 'panel:tool',
        actorName: options.userId ?? 'panel:tool',
        action: 'panel.skill.invoke', resourceType: 'skill', resourceId: skill.id, resourceName: skill.name,
        result: 'error', detail: `model=${model} 失败：${reason}`,
        ...(options.sceneCode ? { sceneCode: options.sceneCode } : {}),
      })
      return { ok: false, reason: `模型网关调用失败（${reason}）` }
    } finally {
      // Metering de collaboration au même style qu'askAgent (clé primaire org absente = saut ; un échec ne bloque pas la réponse)
      if (orgId) {
        try {
          this.soft('usage')?.record({
            org: orgId,
            subject: options.userId ? `user:${options.userId}` : 'panel:tool',
            principal: `org:${orgId}`,
            // Alignement sur le contrat J1 v1 : la clé de ressource du metering emploie skill:<ID> (le slug peut contenir du non-ASCII et ne passe pas la validation de ressource usage)
            resource: `skill:${skill.id}`,
            meters: [{ key: 'calls', value: 1, unit: 'call' }],
            idempotency_key: `panel:skill:${skill.id}:${newId('inv')}`,
          })
        } catch { /* échec de metering ne bloque pas l'appel direct */ }
      }
    }
  }

  /** Résumé de cartographie de scénario de l'activité montée sur le département (injecté dans le prompt système de l'Agent ; chaîne vide si la cartographie n'est pas chargée). */
  sceneSummaryForDept(dept: DeptConfigRecord): string {
    try {
      const orgId = this.soft('iam')?.orgs().all()[0]?.id ?? ''
      const active = this.activeIndustry(orgId)
      if (!active) return ''
      const pack = this.ctx.scenegraphs.get(active.code.toUpperCase())
      if (!pack) return ''
      return dept.acts.flatMap((act) => (pack.activities[act as SceneActivity] ?? [])
        .map((scene) => `${scene.code} ${scene.name}（现状 ${'★'.repeat(scene.s)}${'☆'.repeat(4 - scene.s)}，痛点：${scene.pain}）`)).join('\n')
    } catch {
      return ''
    }
  }

  // -- Actions de carte (chaîne plateforme pure : point d'atterrissage des tâches / chaîne d'approbation / poussé DingTalk) -----------------------

  async cardAction(input: { messageId: string; opId: string; actorId: string; actorName: string; reason?: string }): Promise<{ message: MessageRecord; result: string }> {
    const message = this.messages().get(input.messageId)
    if (!message?.card) throw new Error(`消息不存在或无操作卡片：${input.messageId}`)
    const op = message.card.ops.find((item) => item.id === input.opId)
    if (!op) throw new Error(`操作项不存在：${input.opId}`)
    if (message.card.done.includes(input.opId)) throw new Error('该操作已执行过（幂等保护）')
    let result = '已记录'
    const action = op.action ?? 'ack'
    if (action === 'task.create') {
      this.tasks().insert({
        id: newId('ptask'), dept: message.dept, title: message.card.title,
        detail: `来自消息卡片（${input.actorName} 确认）`, lane: 'todo', assigneeType: 'human',
        sceneCode: message.sceneCode, createdBy: input.actorId, messageId: message.id,
      })
      result = `已生成任务：${message.card.title}`
    } else if (action === 'task.transition') {
      const task = this.tasks().find((item) => item.messageId === message.id).at(-1)
        ?? this.tasks().find((item) => item.dept === message.dept && item.lane !== 'done').at(-1)
      if (!task) throw new Error('没有可流转的关联任务')
      this.transitionTask(task.id, op.lane ?? 'doing', input.actorId)
      result = `任务 ${task.title} → ${LANE_LABELS[op.lane ?? 'doing']}`
    } else if (action === 'approval.request') {
      const audit = this.soft('audit')
      if (!audit) throw new Error('审批中心未接入（01门演示态）——连接宿主后可走审批链')
      const approval = audit.createApproval({
        kind: 'panel.card-action',
        title: `${message.card.title} · ${op.label}`,
        payload: { messageId: message.id, dept: message.dept, opId: op.id, opLabel: op.label, reason: input.reason ?? '' },
        requesterId: input.actorId, requesterName: input.actorName,
        // QA A-06 : une carte sans niveau de risque déclaré vaut high par défaut (fail-closed), fini le « un seul approve et ça exécute »
        riskLevel: op.risk ?? 'high',
      })
      result = `已提交审批（${approval.id}），在审批中心跟进`
    } else if (action === 'dd.push') {
      // Le pont souscrit panel.card.action (action=dd.push) et exécute la livraison ; ici, simple pose d'intention et trace
      result = '已请求推送钉钉'
    }
    const done = [...message.card.done, input.opId]
    this.messages().update(message.id, { card: { ...message.card, done } })
    const updated = this.messages().get(message.id)!
    this.ctx.platformBus.emit(PlatformEvents.PanelCardAction, {
      messageId: message.id, dept: message.dept, opId: op.id, opLabel: op.label, action,
      title: message.card.title, text: message.text, actorId: input.actorId, actorName: input.actorName,
      ddPush: action === 'dd.push', channelName: this.channels().get(message.channelId)?.name ?? '',
    })
    return { message: updated, result }
  }

  // -- Tâches -------------------------------------------------------------------

  /** Trace d'audit (livraison IAW 5-2) : tâches/appels directs d'Agent inscrits dans la ligne de temps d'audit avec la dimension sceneCode ; un échec ne bloque pas la chaîne principale du panneau. */
  private auditSafe(entry: Omit<AuditLogRecord, 'id' | 'createdAt' | 'updatedAt'>): void {
    try {
      // Lecture soft (référentiel d'amincissement plan-gate01) : l'état installé 5 clés porte 01 n'a pas de face audit — absent = saut silencieux (dégradation indépendante de la face audit) ;
      // la forme complète inscrit normalement dans l'audit. Interdit d'écrire this.ctx.audit : l'accès à une clé non injectée de cordis jette, et la forme complète serait aussi avalée.
      const audit = this.ctx.reflect.get('audit', false)
      audit?.record(entry)
    } catch { /* dégradation indépendante du plan d'audit */ }
  }

  createTask(input: {
    dept: string; title: string; detail?: string; lane?: TaskLane
    assigneeType?: 'human' | 'agent'; assigneeName?: string; sceneCode?: string; createdBy: string
    execIssueId?: string; goalId?: string; evidenceRefs?: string[]; reworkOf?: string
  }): TaskRecord {
    this.dept(input.dept)
    // Lignée du centre d'exécution (révision DSH issue#3, 2026-10-29) : panneau = projection du centre d'exécution — quand execIssueId est porté,
    // il doit être atteint dans exec:issues (ligne rouge de la source de fait unique des tâches) ; exec-hub absent (état démo porte 01) = refus honnête.
    if (input.execIssueId) {
      const hub = this.execHub()
      if (!hub) throw new Error('执行中枢未接入（01门演示态）——携带 execIssueId 的任务需要宿主执行中枢')
      if (!hub.issues().get(input.execIssueId)) throw new Error(`执行中枢任务不存在：${input.execIssueId}`)
    }
    if (input.reworkOf && !this.tasks().get(input.reworkOf)) throw new Error(`返工来源任务不存在：${input.reworkOf}`)
    const record = this.tasks().insert({
      id: newId('ptask'), dept: input.dept, title: input.title,
      ...(input.detail ? { detail: input.detail } : {}),
      lane: input.lane ?? 'todo',
      assigneeType: input.assigneeType ?? 'human',
      ...(input.assigneeName ? { assigneeName: input.assigneeName } : {}),
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}),
      ...(input.execIssueId ? { execIssueId: input.execIssueId } : {}),
      ...(input.goalId ? { goalId: input.goalId } : {}),
      ...(input.evidenceRefs?.length ? { evidenceRefs: input.evidenceRefs } : {}),
      ...(input.reworkOf ? { reworkOf: input.reworkOf } : {}),
      createdBy: input.createdBy,
    })
    this.auditSafe({
      type: 'change', actorType: input.createdBy.startsWith('agent:') ? 'machine' : 'human',
      actorId: input.createdBy, actorName: input.createdBy,
      action: 'panel.task.create', resourceType: 'panel_task', resourceId: record.id, resourceName: input.title,
      result: 'ok', detail: `泳道 ${input.lane ?? 'todo'}${input.assigneeName ? `，指派 ${input.assigneeName}` : ''}${input.execIssueId ? `，血缘 exec:${input.execIssueId}` : ''}`,
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}),
    })
    return record
  }

  /** Lecture douce d'exec-hub (projection du centre d'exécution) : absent (état démo porte 01) → undefined, dégradation honnête au niveau endpoint. */
  private execHub(): any | undefined {
    return this.soft('execHub')
  }

  /** Miroir couloir du panneau → état de tâche exec-hub (todo/doing/review/done ↔ todo/in_progress/review/done). */
  private laneToIssueStatus(lane: TaskLane): 'todo' | 'in_progress' | 'review' | 'done' {
    return lane === 'doing' ? 'in_progress' : lane
  }

  transitionTask(taskId: string, lane: TaskLane, actorId: string): TaskRecord {
    const task = this.tasks().get(taskId)
    if (!task) throw new Error(`任务不存在：${taskId}`)
    if (!TASK_LANES.includes(lane)) throw new Error(`非法泳道：${lane}`)
    const updated = this.tasks().update(taskId, { lane })
    // La migration de couloir se ré-écrit en miroir vers exec-hub (source de fait unique ; best-effort + trace d'audit fidèle, ne bloque pas la transition locale)
    let mirror = ''
    if (task.execIssueId) {
      const hub = this.execHub()
      if (!hub) mirror = '；exec-hub 缺席，仅本地流转'
      else {
        try {
          hub.transitionIssue(task.execIssueId, this.laneToIssueStatus(lane), `panel:${actorId}`)
          mirror = `；镜像 exec:${task.execIssueId} → ${this.laneToIssueStatus(lane)}`
        } catch (error) {
          mirror = `；镜像失败：${error instanceof Error ? error.message : String(error)}`
        }
      }
    }
    this.ctx.platformBus.emit(PlatformEvents.PanelTaskUpdated, { taskId, dept: task.dept, lane, actorId, title: task.title })
    this.auditSafe({
      type: 'change', actorType: actorId.startsWith('agent:') ? 'machine' : 'human',
      actorId, actorName: actorId,
      action: 'panel.task.transition', resourceType: 'panel_task', resourceId: taskId, resourceName: task.title,
      result: 'ok', detail: `${task.lane} → ${lane}${mirror}`,
      ...(task.sceneCode ? { sceneCode: task.sceneCode } : {}),
    })
    return updated
  }

  /**
   * Verdict d'acceptance (révision DSH issue#4, 2026-10-29) : fermeture signée (accepted) / renvoi reprise (rework).
   * La conclusion tombe dans la tâche du panneau + ré-écriture en miroir vers exec-hub (accepted→done ; rework→in_progress réouverture pour reprise) ;
   * la même tâche ne peut être jugée deux fois ; un échec du miroir est tracé fidèlement sans bloquer la conclusion (la réconciliation s'appuie sur audit detail).
   */
  taskVerdict(taskId: string, verdict: 'accepted' | 'rework', input: { actorId: string; opinion?: string }): TaskRecord {
    const task = this.tasks().get(taskId)
    if (!task) throw new Error(`任务不存在：${taskId}`)
    if (task.verdict) throw new Error(`任务已有验收结论（${task.verdict === 'accepted' ? '签认' : '返工'}），不可重复裁决`)
    const updated = this.tasks().update(taskId, {
      verdict,
      verdictBy: input.actorId,
      verdictAt: new Date().toISOString(),
      ...(input.opinion ? { verdictOpinion: input.opinion } : {}),
    })
    let mirror = 'exec-hub 缺席，仅本地落结论'
    const hub = task.execIssueId ? this.execHub() : undefined
    if (hub && task.execIssueId) {
      const target = verdict === 'accepted' ? 'done' : 'in_progress'
      try {
        hub.transitionIssue(task.execIssueId, target, `panel:${input.actorId}`)
        mirror = `镜像 exec:${task.execIssueId} → ${target}`
      } catch (error) {
        mirror = `镜像失败：${error instanceof Error ? error.message : String(error)}`
      }
    }
    this.ctx.platformBus.emit(PlatformEvents.PanelTaskUpdated, {
      taskId, dept: task.dept, lane: updated.lane, actorId: input.actorId, title: task.title,
      verdict, ...(task.execIssueId ? { execIssueId: task.execIssueId } : {}),
    })
    this.auditSafe({
      type: 'change', actorType: input.actorId.startsWith('agent:') ? 'machine' : 'human',
      actorId: input.actorId, actorName: input.actorId,
      action: 'panel.task.verdict', resourceType: 'panel_task', resourceId: taskId, resourceName: task.title,
      result: 'ok',
      detail: `验收结论 ${verdict === 'accepted' ? '签认关闭' : '打回返工'}${input.opinion ? `（${input.opinion}）` : ''}；${mirror}`,
      ...(task.sceneCode ? { sceneCode: task.sceneCode } : {}),
    })
    return updated
  }

  /**
   * Projection des objectifs du département (révision DSH issue#4, 2026-10-29) : lit au travers d'exec-hub (pas de copie de l'état d'autorité) —
   * objectifs (base/valeur cible metric incluses) + tâches (lignée goalAncestry/verrou d'exécution incluses) + IDs des tâches liées côté panneau.
   * Périmètre : département lié à une organisation → sous-arbre de celle-ci ; non lié → intégral (même référentiel que les permissions de périmètre départemental).
   * exec-hub absent → null (l'appelant dégrade honnêtement en 503 DEGRADED).
   */
  deptGoalsProjection(dept: DeptConfigRecord): { goals: unknown[]; issues: unknown[] } | null {
    const hub = this.execHub()
    if (!hub) return null
    const iam = this.soft('iam')
    const orgScoped = dept.orgId && iam
      ? (orgId: string): boolean => this.orgSubtreeContains(dept.orgId!, orgId)
      : (): boolean => true
    const panelTaskByIssue = new Map<string, string[]>()
    for (const task of this.tasks().find((item) => item.dept === dept.id)) {
      if (!task.execIssueId) continue
      panelTaskByIssue.set(task.execIssueId, [...(panelTaskByIssue.get(task.execIssueId) ?? []), task.id])
    }
    const goals = hub.goals().all()
      .filter((goal: { orgId: string }) => orgScoped(goal.orgId))
      .map((goal: Record<string, unknown>) => ({ ...goal }))
    const issues = hub.issues().all()
      .filter((issue: { orgId: string }) => orgScoped(issue.orgId))
      .map((issue: Record<string, unknown>) => ({
        ...issue,
        panelTaskIds: panelTaskByIssue.get(String(issue.id)) ?? [],
      }))
    return { goals, issues }
  }

  // -- Diagnostic de scénario (interconnexion session × cartographie) -------------------------------------------------

  /** Référence canonique de code de scénario (ex. QB01-A-2-5) — point d'interconnexion où les productions de session se déposent dans la feuille de route de transformation. */
  sceneContext(code: string): { pack: ScenegraphPack; activityLabel: string; sceneLabel: string } {
    const hit = this.ctx.scenegraphs.findScene(code)
    if (!hit) throw new Error(`场景编号在已装载图谱中不存在：${code}`)
    return { pack: hit.pack, activityLabel: ACTIVITY_LABELS[hit.activity], sceneLabel: `${hit.scene.name}（现状 ${'★'.repeat(hit.scene.s)}${'☆'.repeat(4 - hit.scene.s)}）` }
  }

  async diagnose(input: { dept: string; sceneCode: string; actorId: string; actorName: string }): Promise<{ message: MessageRecord; task: TaskRecord }> {
    const dept = this.dept(input.dept)
    const { pack, sceneLabel } = this.sceneContext(input.sceneCode)
    const channel = this.channels().find((item) => item.dept === input.dept).at(0)
    if (!channel) throw new Error(`部门 ${dept.label} 暂无协作频道，请先建频道`)
    const agentCard = dept.agents[0]
    const text = `@${agentCard.name} 请对「${pack.name}」场景「${sceneLabel}」（${input.sceneCode}）做数字化诊断，按一图四清单框架评估差距/选型/优先级。`
    const message = await this.sendMessage({
      dept: input.dept, channelId: channel.id, senderType: 'human', senderId: input.actorId,
      senderName: input.actorName, text, ddSync: false, sceneCode: input.sceneCode,
    })
    const task = this.createTask({
      dept: input.dept, title: `场景诊断：${input.sceneCode} ${sceneLabel}`,
      detail: `派 ${agentCard.name} 按一图四清单框架诊断（来自场景图谱 ${pack.code}）`,
      lane: 'todo', assigneeType: 'agent', assigneeName: agentCard.name,
      sceneCode: input.sceneCode, createdBy: input.actorId,
    })
    return { message, task }
  }

  // -- Registre d'abonnements SSE -----------------------------------------------------------

  subscribeStream(dept: string, listener: (event: { name: string; payload: unknown }) => void): () => void {
    const set = this.streamSubscribers.get(dept) ?? new Set()
    set.add(listener)
    this.streamSubscribers.set(dept, set)
    return () => set.delete(listener)
  }

  /** Événements de la plateforme → éventail vers les abonnés SSE (panel.* / flow.* / dingtalk-bridge.delivered). */
  wireEventBus(): void {
    const forward = (name: string) => (payload: unknown) => {
      const dept = (payload as { dept?: string } | undefined)?.dept
      const targets = dept ? [dept] : [...this.streamSubscribers.keys()]
      for (const target of targets) {
        for (const listener of this.streamSubscribers.get(target) ?? []) {
          try { listener({ name, payload }) } catch { /* la défaillance d'un seul abonné n'interrompt pas la chaîne */ }
        }
      }
    }
    this.ctx.platformBus.on(PlatformEvents.PanelMessageCreated, forward(PlatformEvents.PanelMessageCreated))
    this.ctx.platformBus.on(PlatformEvents.PanelTaskUpdated, forward(PlatformEvents.PanelTaskUpdated))
    this.ctx.platformBus.on(PlatformEvents.PanelCardAction, forward(PlatformEvents.PanelCardAction))
    this.ctx.platformBus.on(PlatformEvents.PanelIndustryActivated, forward(PlatformEvents.PanelIndustryActivated))
    this.ctx.platformBus.on(PlatformEvents.DingtalkDelivered, forward(PlatformEvents.DingtalkDelivered))
    this.ctx.platformBus.on(PlatformEvents.ScenegraphUpdated, forward(PlatformEvents.ScenegraphUpdated))
    // Moteur de flux de dossiers (livraison IAW 3-1) : les événements de la machine à états des étapes TF suivent l'éventail SSE du panneau (un TF sans dept est diffusé à tous les abonnés)
    this.ctx.platformBus.on(PlatformEvents.FlowCreated, forward(PlatformEvents.FlowCreated))
    this.ctx.platformBus.on(PlatformEvents.FlowStepUpdated, forward(PlatformEvents.FlowStepUpdated))
    this.ctx.platformBus.on(PlatformEvents.FlowCompleted, forward(PlatformEvents.FlowCompleted))
    // QA E-03 : les événements de type échec de miroir du connecteur ne faisaient auparavant que la moitié du bus — l'éventail SSE du panneau les diffuse aussi (sans dept, diffusion à tous),
    // le panneau de permanence voit l'état fail-closed
    this.ctx.platformBus.on(PlatformEvents.ConnectorPolicyMirrorFailed, forward(PlatformEvents.ConnectorPolicyMirrorFailed))
    this.ctx.platformBus.on(PlatformEvents.ConnectorPolicySnapshotDrifted, forward(PlatformEvents.ConnectorPolicySnapshotDrifted))
  }
}

/**
 * Analyse des @mentions (pour affichage) : correspondance des pseudos chinois/anglais/chiffres. La correspondance par nom complet du registre d'Agents (espaces compris) se fait
 * dans dispatchAgentMentions sur le littéral du nom ; ici seulement les candidats génériques de surlignage.
 */
export function extractMentions(text: string): string[] {
  const mentions = new Set<string>()
  for (const match of text.matchAll(/@([\p{L}\p{N}·]{2,20})/gu)) mentions.add(match[1]!)
  return [...mentions]
}

/**
 * Retrait des blocs <think> des modèles de raisonnement (constat E2E 2026-09-11) : des modèles de raisonnement type MiniMax-M3 émettent le processus de réflexion
 * mélangé au corps sous forme <think>…</think> — la réflexion n'est pas un contenu pour les lecteurs du canal ; l'inscription/l'affichage ne gardent
 * que le corps. Ne traite que le bloc de réflexion en tête (position conventionnelle des modèles) ; non fermé (réflexion tronquée avant la fin) = considéré sans corps.
 */
const THINK_BLOCK = /^\s*<think>[\s\S]*?<\/think>/
const THINK_OPEN_UNTERMINATED = /^\s*<think>[\s\S]*$/

export function stripThink(text: string): string {
  let out = text.replace(THINK_BLOCK, '')
  if (THINK_OPEN_UNTERMINATED.test(out)) out = ''
  return out.trimStart()
}

/** Porte de blocage think sur l'incrément de flux : avant la fermeture du bloc de réflexion, on retient ; après fermeture, on laisse passer ce qui suit (vaut aussi pour la forme delta unique). */
export function createThinkGate(emit: (text: string) => void): (text: string) => void {
  let hold = ''
  let passed = false
  return (text) => {
    if (passed) { emit(text); return }
    hold += text
    if (hold.trimStart().startsWith('<think>')) {
      const close = hold.indexOf('</think>')
      if (close === -1) return // réflexion non terminée, continuer à retenir
      passed = true
      const rest = hold.slice(close + '</think>'.length)
      hold = ''
      if (rest) emit(rest)
      return
    }
    passed = true
    const all = hold
    hold = ''
    emit(all)
  }
}
