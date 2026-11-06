/**
 * Graines du panneau (review-dsh-agent-panel-v2 Phase 1, items 5-10) :
 * - base (premier démarrage, panel:deptConfigs vide) : squelettes de configuration des cinq départements (un socle de données, un squelette, cinq habillages,
 *   DEPT_META tiré du prototype) + activation intégrée des secteurs (paquets de cartographie QB01/YB01/JB01 distribués avec la plateforme → autorisation par défaut à l'organisation racine, convergence idempotente).
 * - démonstration (DEMO_SEED=1) : s'ajoutent KPI/widget des cinq départements (badges de source mock/manuel)/canaux/sessions d'exemple/tâches/savoir départemental —
 *   tout vient de demo-content.json (données APPLIANCE du prototype, détachement déterministe par scripts/extract-panel-seed.mjs).
 * Les cartes d'Agent des sessions de démonstration ne pré-lient pas agentRef (l'agentRef de la ligne-up du panneau est lié par l'admin via PUT /api/panel/:dept/agents
 * à un vrai actif Agent — non lié à l'exécution, dégradation honnête vers l'humain, pas de réponse fabriquée).
 */
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import { newId } from '../../../platform-core/src/ids.ts'
import type { DeptAgent, DeptKpi, DeptWidget, MessageCardOp, PanelService } from '../service.ts'

/** Squelettes des cinq départements (DEPT_META du prototype un-un : la couleur de thème est l'identité du département). */
const DEPT_META: Array<Pick<import('../service.ts').DeptConfigRecord, 'id' | 'label' | 'icon' | 'theme' | 'collab' | 'acts' | 'colors'>> = [
  { id: 'rd', label: '研发部', icon: '🔬', theme: '深空蓝 · 项目工程风', collab: '任务驱动 · 评审协同', acts: ['rd'], colors: { accent: '#4f46e5', soft: '#e0e7ff', deep: '#3730a3' } },
  { id: 'mfg', label: '制造部', icon: '🏭', theme: '工业青 · 产线实时风', collab: '异常驱动 · 工单闭环', acts: ['mfg', 'scm'], colors: { accent: '#0f766e', soft: '#ccfbf1', deep: '#115e59' } },
  { id: 'sales', label: '销售部', icon: '💼', theme: '暖阳橙 · 赢单作战风', collab: '客户驱动 · 服务一体', acts: ['svc', 'mkt'], colors: { accent: '#ea580c', soft: '#ffedd5', deep: '#9a3412' } },
  { id: 'strategy', label: '战略部', icon: '🧭', theme: '深紫 · 洞察研判风', collab: '情报驱动 · 研判共创', acts: ['mgmt'], colors: { accent: '#7c3aed', soft: '#ede9fe', deep: '#5b21b6' } },
  { id: 'fin', label: '财务部', icon: '💳', theme: '墨绿金 · 严谨合规风', collab: '流程驱动 · 审批留痕', acts: ['fin'], colors: { accent: '#047857', soft: '#d1fae5', deep: '#064e3b' } },
]

/** Correspondance boutons de carte → actions de la chaîne plateforme (les cartes de démo tombent sémantiquement en chaîne plateforme pure ; les poussements type DingTalk passent par dd.push). */
function mapOps(labels: string[]): MessageCardOp[] {
  return labels.map((label, index) => {
    const style: MessageCardOp['style'] = label.includes('钉钉') ? 'dd' : 'primary'
    let action: MessageCardOp['action'] = 'ack'
    if (/生成任务卡|确认派单|确认返修|拉评审会|生成申报方案|生成专项报告|查看进度|发起调整流程|生成诊断/.test(label)) action = 'task.create'
    else if (/提交审批|推送钉钉卡片审批|推送客户钉钉|推送钉钉给/.test(label)) action = 'approval.request'
    else if (/推送钉钉卡片$/.test(label)) action = 'dd.push'
    return { id: `op${index + 1}`, label, style, action, ...(action === 'approval.request' ? { risk: 'high' as const } : {}) }
  })
}

/** Clé primaire de l'organisation de démonstration (rattachement activation/metering en forme installée porte 01 sans catalogue d'organisations, même valeur que le repli orgIdOf de index.ts). */
export const DEMO_ORG_ID = 'demo-org'

export function seedPanel(ctx: Context, panel: PanelService, autoDemo = false): void {
  const logger = ctx.logger('panel-seed')
  // Double entrée idempotente : premier démarrage (collection vide) sème base+démo ; en forme installée demoAuth, le rechargement à chaud du loader rejoue apply
  // avec une config vide — la base du squelette est semée d'abord, l'autoDemo arrivé après doit pouvoir compléter le contenu de démo (constat machine réelle gate01-npm)
  if (panel.deptConfigs().count() > 0) {
    // Déploiement existant : l'activation intégrée des secteurs continue de converger idempotemment au démarrage (une montée de version donne les droits par défaut des nouveaux codes intégrés),
    // squelettes de départements/contenu de démo non re-semés
    seedBuiltInActivations(ctx, panel, logger, autoDemo)
    if (autoDemo) seedDemoContent(ctx, panel, logger)
    return
  }

  // -- Base : squelettes des cinq départements + activation intégrée + liaison automatique par nom d'organisation (interconnexion comptes-organisations) ------------
  // Catalogue d'organisations absent (état démo porte 01) → départements non liés à une organisation (permissions de périmètre toutes ouvertes) + saut de l'enregistrement d'activation intégrée,
  // squelette et contenu de démo semés comme d'habitude (décision 2 de plan-gate01 : tableau de bord démo intégré quand l'hôte n'est pas connecté)
  // Note : le service panel doit passer les paramètres explicitement (le ctx proxy du loader dsh jette without inject sur l'accès nu à une clé non déclarée —
   // panel ne peut pas s'auto-injecter, même leçon que soft() de service.ts, constat machine réelle gate01-local).
  const iam = ctx.reflect.get('iam', false) as any | undefined
  for (const meta of DEPT_META) {
    // Liaison automatique quand nom d'organisation = nom de département (un déploiement réel qui nomme l'arbre d'organisations de l'entreprise obtient l'interconnexion sans configuration) ;
    // en cas de divergence, l'admin lie à la main via PUT /api/panel/:dept/config
    const matchedOrg = iam?.orgs().findOne((org: { name: string }) => org.name === meta.label)
    panel.deptConfigs().insert({ id: meta.id, ...meta, agents: [], kpis: [], widgets: [], ...(matchedOrg ? { orgId: matchedOrg.id } : {}) })
  }
  // Les actifs de cartographie intégrés (packages/platform-core/scenegraphs/ distribués avec la plateforme) sont autorisés par défaut à l'organisation racine ;
  // les autres organisations/secteurs passent par la chaîne « demande → approbation (industry.activation, high) → activation »
  seedBuiltInActivations(ctx, panel, logger, autoDemo)
  logger.info('面板基线：五部门骨架 + 内置行业激活（QB01/YB01/JB01）完成')

  // Porte du contenu de démo : DEMO_SEED=1 (démo explicite en forme complète) ou autoDemo (démo automatique en forme installée demoAuth porte 01)
  if (process.env.DEMO_SEED !== '1' && !autoDemo) return
  seedDemoContent(ctx, panel, logger)
}

/**
 * Convergence de l'activation intégrée des secteurs (exécutée idempotemment à chaque démarrage, refonte IAW 2026-09-11) :
 * - convergence au démarrage plutôt que semis au seul premier démarrage — un déploiement existant qui monte de version (nouveaux codes intégrés) obtient les droits par défaut au redémarrage ;
 * - la résolution de l'organisation racine a une retry différée : en forme installée, la graine du panneau et la base iam sont en course au démarrage (constat machine réelle gate01-local :
 *   la graine panneau précède l'organisation racine iam d'environ 500 ms, l'activation se raccrochait à tort à demo-org alors que l'utilisateur nommé résout la vraie racine → tous les secteurs verrouillés) ;
 * - seulement si iam est absent (forme purement démo) tombe-t-on sur le repli demo-org.
 */
function seedBuiltInActivations(ctx: Context, panel: PanelService, logger: { info(msg: string): void }, autoDemo: boolean): void {
  const iam = ctx.reflect.get('iam', false) as any | undefined
  const findRootOrgId = (): string | undefined =>
    iam?.orgs().find((org: { parentId: string | null }) => org.parentId === null).at(0)?.id
  const seedTo = (orgId: string): void => {
    seedActivations(panel, orgId)
    logger.info(`内置行业激活（QB01/YB01/JB01）已收敛至组织 ${orgId}`)
  }
  const rootOrgId = findRootOrgId()
  if (rootOrgId) { seedTo(rootOrgId); return }
  if (!iam) {
    // Chargement concurrent du loader dsh : le service iam peut publier après cette extension (même leçon que la retry différée de la graine admin ci-dessus,
    // constat machine réelle gate01-local — l'activation se raccrochait immédiatement à tort à demo-org, et après résolution de la vraie racine par l'utilisateur nommé, tous les secteurs verrouillés).
    // En forme installée demoAuth, scrutin d'attente d'iam (≤10 s), convergence dès l'organisation racine obtenue ; en forme non démo sans iam, sémantique d'origine maintenue (pas de semis).
    if (!autoDemo) return
    let tries = 0
    const timer = setInterval(() => {
      const iamNow = ctx.reflect.get('iam', false) as any | undefined
      const orgId = iamNow?.orgs().find((org: { parentId: string | null }) => org.parentId === null).at(0)?.id
      if (orgId) { clearInterval(timer); seedTo(orgId); return }
      if (++tries >= 20) {
        clearInterval(timer)
        logger.info('iam 10s 未就绪，内置行业激活回落 demo-org（下次启动重试收敛）')
        seedTo(DEMO_ORG_ID)
      }
    }, 500)
    try { timer.unref?.() } catch { /* hors Node : ignoré */ }
    return
  }
  // iam présent mais base non prête (course au démarrage) : retry chaque seconde jusqu'à 15 s au plus, au final autoDemo tombe sur le repli demo-org
  let tries = 0
  const timer = setInterval(() => {
    const orgId = findRootOrgId()
    if (orgId) { clearInterval(timer); seedTo(orgId); return }
    if (++tries >= 15) {
      clearInterval(timer)
      logger.info('iam 根组织 15s 未就绪，内置行业激活回落 demo-org（下次启动重试收敛）')
      if (autoDemo) seedTo(DEMO_ORG_ID)
    }
  }, 1_000)
  try { timer.unref?.() } catch { /* hors Node : ignoré */ }
}

/**
 * Complétion idempotente du contenu de démo (décision 2 de plan-gate01) : complète en KPI/ligne-up d'Agents/widget/canaux/sessions/tâches/savoir les départements
 * « encore squelettes ». « le département a-t-il déjà un canal » sert de marque de contenu de démo déjà semé (canal non vide = saut de toute la démo
 * de ce département), agents/kpis/widgets jugés séparément sur la vacuité — rejouer apply / rechargement à chaud / rejeu partiellement échoué, tout est sûr.
 */
/** Enregistrement idempotent de l'activation intégrée (QB01 électroménager / YB01 acier / JB01 machines de chantier autorisés par défaut ; les 11 autres secteurs passent par demande-approbation) :
 *  en forme installée demoAuth, repli demo-org, rejeu sûr. */
function seedActivations(panel: PanelService, orgId: string): void {
  for (const code of ['QB01', 'YB01', 'JB01']) {
    if (panel.activations().findOne((item) => item.orgId === orgId && item.code === code)) continue
    panel.activations().insert({
      id: newId('act'), code, orgId, status: 'active',
      activatedAt: new Date().toISOString(), activatedBy: 'seed（内置资产包默认授权）',
    })
  }
}

function seedDemoContent(ctx: Context, panel: PanelService, logger: { info(msg: string): void; warn(msg: string): void }): void {
  type DemoMsg = { t: string; n?: string; icon?: string; x: string; dd?: boolean | string; card?: { t: string; ops: string[] } }
  type DemoDept = {
    kpis: Array<[string, string]>
    agents: Array<{ n: string; d: string; icon: string; busy?: boolean }>
    chans: Array<[string, number, boolean]>
    widgets: Array<{ t: string; title: string; live?: boolean; rows: unknown[][] }>
    msgs: DemoMsg[]
  }
  const demoPath = join(dirname(fileURLToPath(import.meta.url)), 'demo-content.json')
  const demo = JSON.parse(readFileSync(demoPath, 'utf8')) as { depts: Record<string, DemoDept> }

  // Complétion idempotente de la face d'activation des secteurs (l'état intermédiaire « squelette sans activation » — ex. hôte tué brutalement perdant une partie de la persistance — se rétablit aussi)
  const iam = ctx.reflect.get('iam', false) as any | undefined
  const demoOrgId = iam?.orgs().find((org: { parentId: string | null }) => org.parentId === null).at(0)?.id ?? DEMO_ORG_ID
  seedActivations(panel, demoOrgId)

  for (const [deptId, content] of Object.entries(demo.depts)) {
    const config = panel.deptConfigs().get(deptId)
    if (!config) continue
    // Marque idempotente : le département a déjà un canal = contenu de démo (canaux/sessions/tâches/savoir) déjà semé, ne compléter que la face configuration
    const alreadySeeded = panel.channels().find((item) => item.dept === deptId).length > 0

    if (config.agents.length === 0 && config.kpis.length === 0) {
      const agents: DeptAgent[] = content.agents.map((agent) => ({
        name: agent.n, desc: agent.d, icon: agent.icon, ...(agent.busy ? { busy: true } : {}),
      }))
      const kpis: DeptKpi[] = content.kpis.map(([label, value]) => ({ label, value, source: 'mock' }))
      const widgets: DeptWidget[] = content.widgets.map((widget, index) => ({
        id: `w${index + 1}`,
        type: widget.t as DeptWidget['type'],
        title: widget.title,
        ...(widget.live ? { live: true } : {}),
        // DoD dur de gouvernance : tous les tableaux de bord de démo portent le badge de source « données simulées », jamais d'usurpation d'une vraie face métier
        source: 'mock',
        rows: widget.rows,
      }))
      panel.deptConfigs().update(config.id, { agents, kpis, widgets })
    }

    if (alreadySeeded) continue
    for (const [name] of content.chans) {
      panel.channels().insert({ id: newId('pchan'), dept: deptId, name, createdBy: 'seed' })
    }
    const channels = panel.channels().find((item) => item.dept === deptId)
    const mainChannel = channels.at(0)

    for (const msg of content.msgs) {
      if (!mainChannel) break
      const ddSync = msg.dd === 'origin' ? 'origin' as const : msg.dd === true ? 'sent' as const : 'none' as const
      const senderType = msg.t === 'sys' ? 'system' as const : msg.t === 'agent' ? 'agent' as const : 'human' as const
      try {
        panel.messages().insert({
          id: newId('pmsg'), channelId: mainChannel.id, dept: deptId,
          senderType,
          ...(msg.n ? { senderName: msg.n } : {}),
          ...(msg.icon ? { senderIcon: msg.icon } : {}),
          text: msg.x,
          mentions: [...msg.x.matchAll(/@([\p{L}\p{N}·]{2,20})/gu)].map((m) => m[1]!),
          ...(msg.card ? { card: { title: msg.card.t, ops: mapOps(msg.card.ops), done: [] } } : {}),
          ddSync, agentName: senderType === 'agent' ? msg.n : undefined,
        })
      } catch (error) {
        logger.warn(`演示消息播种跳过（${deptId}）：${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Démo du tableau des tâches (machine à états des couloirs todo/doing/review/done ; les références de codes de scénario se déposent dans la cartographie)
    const demoTasks: Array<[string, string, 'todo' | 'doing' | 'review' | 'done', string?]> = [
      ['rd', '低温启动需求拆解（V2.5-REQ-018）', 'doing', 'QB01-B-1-1'],
      ['rd', '!482 电机驱动过流保护评审', 'review'],
      ['mfg', 'WO-2611 风扇组件 ×3200', 'doing'],
      ['mfg', '3# 冲床油温异常维修工单（WX-0912）', 'todo', 'QB01-A-2-5'],
      ['mfg', 'M-2207 物料缺口补齐', 'todo', 'QB01-G-4-1'],
      ['sales', 'QT-2689 延保打包版报价审批', 'review'],
      ['sales', 'SV-3318 冰箱异响工单闭环', 'doing', 'QB01-F-3-1'],
      ['strategy', '设备联网率 52%→60% Q4 专项立项', 'todo', 'QB01-B-2-1'],
      ['strategy', '试点申报一页纸简报（周五经营会）', 'doing'],
      ['fin', '制造费用摊销调整流程', 'review', 'QB01-H-5-3'],
      ['fin', '8 张单据预审退回复核', 'todo'],
    ]
    for (const [dept, title, lane, sceneCode] of demoTasks) {
      if (dept !== deptId) continue
      panel.tasks().insert({
        id: newId('ptask'), dept: deptId, title, lane, assigneeType: 'human',
        ...(sceneCode ? { sceneCode } : {}), createdBy: 'seed',
      })
    }

    // Démo du savoir départemental (dépôt des productions d'Agent)
    const demoArtifacts: Array<[string, string, string, string?]> = [
      ['rd', 'diagnosis', 'V2.5 低温启动需求拆解纪要', '6 任务 / 34 人日 / 关键路径可靠性试验 10 天'],
      ['mfg', 'order', '维修工单 WX-0912', '3# 冲床液压油温超阈值；对应 QB01-A-2-5 建议列入改造清单'],
      ['sales', 'quote', '报价单 QT-2688 / QT-2689', '标准版 ¥118万（毛利 31.2%）· 延保打包版 ¥128万（毛利 33.5%）'],
      ['strategy', 'report', '政策申报可行性初判', '匹配度 92%；缺口：设备联网率 52%→60%；投入产出比 1:2.4'],
      ['fin', 'report', '预算偏差分析 · 制造费用', '78% 执行领先进度 10pp；主因 8 月设备大修一次性计入 ¥56 万'],
    ]
    for (const [dept, kind, title, contentText] of demoArtifacts) {
      if (dept !== deptId) continue
      panel.artifacts().insert({
        id: newId('part'), dept: deptId, kind: kind as 'report' | 'order' | 'quote' | 'diagnosis' | 'other',
        title, content: contentText ?? '', createdBy: 'seed',
      })
    }
  }
  logger.info('面板演示数据初始化完成（五部门频道/会话/任务/知识/看板）')
}
