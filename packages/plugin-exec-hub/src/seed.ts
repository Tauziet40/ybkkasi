/**
 * Graines de démonstration du centre d'exécution (G3) : quand DEMO_SEED=1 et exec:goals est vide, dépose idempotemment un lot
 * d'exemples d'objectifs/projets/tâches/routines/battements dans le contexte manufacturier à trois départements — « voir d'emblée la boucle complète ».
 * Base de production (sans DEMO_SEED) : zéro écriture ; n'écrase pas les données existantes (idempotent : la collection vide sert de porte).
 */
import type { Context } from '@deepseek-ai/cordis'
import { newId } from '../../platform-core/src/index.ts'
import type { ExecutionHubService, HeartbeatRecord } from './index.ts'

export function seedExecHub(ctx: Context, hub: ExecutionHubService): void {
  if (process.env.DEMO_SEED !== '1') return
  if (hub.goals().all().length > 0) return
  // Dépend de la graine console pour poser d'abord l'Agent (ordre de boot garanti) ; introuvable = abandon du lot entier (pas d'écriture partielle)
  const agent = ctx.resourceCore.list('agent').find((item) => item.status === 'online')
  const orgId = agent?.orgId ?? ctx.iam.orgs().all()[0]?.id ?? ''
  const now = Date.now()
  const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString()

  const root = hub.createGoal({
    orgId, title: 'Q4 制造运营效率提升',
    description: '演示数据：公司级季度目标（父目标），子目标按产线拆解。',
    metric: '综合运营效率指数', metricBaseline: 72, metricTarget: 85, metricUnit: '分',
    periodStart: '2026-10-01', periodEnd: '2026-12-31',
  })
  const child = hub.createGoal({
    orgId, title: '产线质检人效提升', parentGoalId: root.id,
    description: '演示数据：子目标——人均质检量提升 33%。',
    metric: '人均日质检量', metricBaseline: 1200, metricTarget: 1600, metricUnit: '件/日',
    periodStart: '2026-10-01', periodEnd: '2026-12-31',
  })

  const projectA = hub.createProject({
    orgId, goalId: child.id, name: '产线视觉质检改造',
    description: '演示数据：视觉质检模型与采集通道改造。',
    repos: ['https://github.com/01men/qc-vision'],
  })
  hub.createProject({
    orgId, goalId: child.id, name: '质检知识库建设',
    description: '演示数据：SOP 与缺陷样本知识沉淀。',
  })

  const i1 = hub.createIssue({
    orgId, projectId: projectA.id, title: '产线图像采集通道打通',
    detail: '演示数据：打通 3 号产线相机到平台的数据通道。',
    priority: 'P1', createdBy: 'seed',
    ...(agent ? { assigneeAgentId: agent.id } : {}),
  })
  const i2 = hub.createIssue({
    orgId, projectId: projectA.id, title: '质检缺陷分类模型迭代 v2',
    detail: '演示数据：前置依赖采集通道；执行需走 P0 审批门禁演示。',
    priority: 'P0', blockerIds: [i1.id], createdBy: 'seed',
    ...(agent ? { assigneeAgentId: agent.id } : {}),
  })
  hub.createIssue({
    orgId, projectId: projectA.id, title: '采集数据管道联调',
    priority: 'P2', blockerIds: [i1.id], createdBy: 'seed',
  })
  // Démonstration de cycle de vie : une chaîne complète todo → in_progress → review → done
  const done = hub.createIssue({
    orgId, projectId: projectA.id, title: '质检看板埋点补齐', priority: 'P3', createdBy: 'seed',
  })
  hub.transitionIssue(done.id, 'in_progress', 'seed')
  hub.transitionIssue(done.id, 'review', 'seed')
  hub.transitionIssue(done.id, 'done', 'seed')

  // Règle de routine : inspection des tâches à faire matinales (intervalle 240 minutes)
  if (agent) {
    hub.routines().insert({
      id: newId('rtn'), orgId, agentId: agent.id,
      name: '晨间待办巡检（演示）', kind: 'interval', intervalMinutes: 240,
      enabled: true, createdBy: 'seed',
    })
    // Traçabilité des battements : les deux derniers tours (un tour de réveil, un tour sans tâche à faire) soutiennent la carte santé
    const heartbeats = hub.heartbeats()
    const rows: Array<Omit<HeartbeatRecord, 'id' | 'createdAt' | 'updatedAt'>> = [
      { agentId: agent.id, orgId, at: iso(-50 * 60_000), outcome: 'woken', detail: '3 项待办', issueCount: 3 },
      { agentId: agent.id, orgId, at: iso(-10 * 60_000), outcome: 'skipped_no_todo', detail: '例行巡检' },
    ]
    for (const row of rows) heartbeats.insert({ id: newId('hb'), ...row })
  }

  ctx.logger('exec-hub').info('演示种子已落（目标/项目/任务/例行/心跳）')
}
