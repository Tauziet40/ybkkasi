/**
 * @ybkk/plugin-panel-core — panneau de l'espace de travail Agent départemental (review-dsh-agent-panel-v2 Phase 1/2).
 *
 * Responsabilités :
 *   - hébergement statique du SPA panneau (/panel, exposé via dsh-bridge en /gate01/panel/ ; ligne d'airain diff=0 du web hôte)
 *   - REST /api/panel/* (guarded + point de permission ; les routes auto-enregistrées vont dans httpServer.routeMatrix, registre partagé,
 *     pour préserver le réseau d'assertions RBAC 100% hors-permission du selftest — dette comblée Phase 0)
 *   - SSE /api/panel/stream (EventSource ne peut pas porter de Bearer → endpoint public + auto-vérification interne ?token= fail-closed ;
 *     repli par scrutin GET /api/panel/:dept/poll — ligne d'airain du repli par scrutin 30 s de la webview DingTalk)
 *   - exécuteur d'approbation d'activation de secteur (approbations d'audit : demande→approbation→pose active+grantCapabilities ; chaîne d'émission de licence Phase 4)
 *   - face catalogue de modèles (GET/POST/DELETE /api/panel/models + test de connectivité :slug/test) : partage avec le service dsh
 *     la source de fait unique modelgw ; la boîte de dialogue de session collaborative bascule de modèle via le paramètre model de messages (panelAgentRuntime prioritaire)
 *   - famille d'outils panel_* (enregistrée sur la clé tools partagée, sous dsh ToolRuntime natif appelable par le modèle)
 *   - graines : base = squelettes de configuration des cinq départements + activation intégrée des secteurs ; DEMO_SEED=1 ajoute sessions/tâches/savoir/tableaux de démo
 */
import { join, dirname } from 'node:path'
import { existsSync, writeFileSync } from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import type { HttpExchange } from '../../platform-core/src/index.ts'
import { PlatformEvents } from '../../platform-core/src/bus.ts'
import { newId } from '../../platform-core/src/ids.ts'
import { PanelService, TASK_LANES, type TaskLane, type DeptWidget, type DeptKpi, type DeptAgent } from './service.ts'
import { CardpackService, CARD_PLATFORMS, filterCards, type CardPlatform } from './cardpacks.ts'
export { CardpackService, CARD_PLATFORMS, filterCards } from './cardpacks.ts'
import { seedPanel, DEMO_ORG_ID } from './seed/seed.ts'
import { resolvePanelModelGateway } from './llm-bridge.ts'
import { DwsCli } from './dws.ts'
import { applyMfgModule } from './mfg/module.ts'

/**
 * Version de contrat du panneau (#13, 2026-10-29, replanté depuis le socle) : version sémantique de l'ensemble des familles de capacités du panneau — incrémentée à chaque famille ajoutée/famille de routes retirée.
 * Le socle est propriétaire du contrat : /api/health expose via contract.panel cette version et la liste des capacités dérivée en temps réel,
 * le front (DeptAI-UI-DSH, etc.) s'aligne dessus ; un écart de combinaison de versions est fail-visible et non un 404 silencieux.
 */
export const PANEL_CONTRACT_VERSION = 1

export const name = 'panel-core'
// Amincissement plan-gate01 Phase 2 : les dépendances dures ne gardent que les 5 clés du socle du plan de données (fournies par platform-core / natif dsh).
// Les 9 autres clés (iam/authn/audit/usage/modelGateway/resourceCore/behavior/mcpRegistry/skillHub)
// passent par la lecture souple soft() — l'inject de cordis est une dépendance dure d'avant-chargement (sans fournisseur = suspension permanente,
// entériné par le spike) ; déclarer exige la présence du fournisseur ; en forme installée porte 01, sans pain de l'hôte, ces clés doivent pouvoir manquer.
// Note : le service panel ne peut pas s'auto-injecter (auto-dépendance = suspension permanente) — usage interne direct new PanelService(ctx).
export const inject = [
  'httpServer', 'opsStorage', 'platformBus', 'tools', 'scenegraphs',
]

/** Configuration d'assemblage de panel-core. */
export interface PanelConfig {
  /**
   * Interrupteur d'authentification de démonstration (fail-closed, défaut false = authentification stricte) : seul l'assemblage 01-gate 4-entry
   * de cordis.patch.yml déclare true — laisse passer les verbes en lecture (GET/HEAD/OPTIONS) sous l'identité de visiteur de démo lisant les données
   * de démo intégrées, les verbes d'écriture toujours 403 ; la forme complète (cordis.yml / boot-all) ne le déclare jamais, authentification stricte par le middleware console.
   * Interdiction absolue de sonder à l'exécution la présence d'authn pour laisser passer — cela jugerait « middleware non couvert de la forme complète » à tort comme un état démo (fail-open).
   */
  demoAuth?: boolean
  /**
   * Interrupteur de normalisation de l'atterrissage (défaut false) : seul l'état installé porte 01 (cordis.patch.yml) déclare true — l'assemblage n'a pas de console,
   * la racine n'a pas de console où atterrir, le repli SPA enverrait au navigateur la page coquille sans console (ressources relatives 404 → repli HTML →
   * écran blanc d'erreur MIME module). Déclaré, GET / 302 vers ${externalBase}/panel/ ; la forme complète ne le déclare jamais,
   * l'atterrissage racine reste console (comportement inchangé).
   */
  landingRedirect?: boolean
}

/** Identité du visiteur de démo (points de permission en lecture : lecture panneau + lecture cartographie de scénarios). */
const DEMO_PRINCIPAL = {
  kind: 'human' as const,
  principalId: 'demo-visitor',
  name: '演示访客',
  permissions: ['panel.read', 'scenegraph.read'],
  actChain: [],
}

/** Lecture douce des services d'hôte optionnels (même règle que PanelService.soft ; niveau module pour la face routes). */
const soft = (ctx: Context, key: string): any => ctx.reflect.get(key, false)

interface CallerInfo {
  kind: 'human' | 'machine'
  principalId: string
  userId?: string
  name: string
  permissions: string[]
  actChain: Array<{ name: string; type: string }>
}

const DEPT_RE = /^[a-z]{2,12}$/

export function apply(ctx: Context, config: PanelConfig = {}) {
  const demoAuth = config.demoAuth === true
  const http = ctx.httpServer
  ctx.plugin(PanelService)
  // Service de paquets de cartes (migration à double voie depuis l'assemblage platform-core) : le panneau est l'unique consommateur et hôte du domaine tableaux de bord/paquets de cartes (pas d'auto-inject, usage de PanelService)
  ctx.plugin(CardpackService)
  const cardpacks = new CardpackService(ctx)
  const panel = new PanelService(ctx)

  const caller = (exchange: HttpExchange): CallerInfo => exchange.principal as CallerInfo

  // Même requirePermission que console : permission manquante = 403 + trace audit.authz.denied (face de jugement de la sonde RBAC).
  // Trois préalables (plan-gate01 Phase 2.2 + ouverture du canal d'écriture 2026-09-11) :
  //   1. auto-vérification Bearer — le middleware d'authentification vit dans plugin-console (l'état installé 4+2 entry porte 01 n'a pas de console),
  //      le panneau établit lui-même le principal des requêtes portant un Bearer via authn.verify (même règle que le canal SSE ?token=) ;
  //      un jeton présenté mais invalide → 401 propre, jamais rétrogradé en visiteur de démo (fail-closed) ;
  //   2. en mode strict, repli de principal — sans identifiant et hors état démo → 401 ;
  //   3. demoAuth (défaut false) laisse passer la démo — n'intervient que « sans principal valide » : verbes de lecture sous l'identité de démo
  //      rendant les données de démo intégrées, verbes d'écriture 403 ; un utilisateur connecté (avec principal) n'est pas soumis à la restriction lecture. Cet interrupteur
  //      n'est déclaré que par l'assemblage patch porte 01, jamais par la forme complète.
  const requirePermission = (exchange: HttpExchange, point: string): boolean => {
    if (!exchange.principal) {
      const header = String(exchange.headers['authorization'] ?? '')
      if (header.startsWith('Bearer ')) {
        const authn = soft(ctx, 'authn')
        if (!authn) {
          exchange.fail(401, 'UNAUTHENTICATED', '认证中心未接入，无法校验所出示的令牌')
          return false
        }
        try {
          const verified = authn.verify(header.slice(7))
          exchange.principal = {
            kind: verified.principal.type,
            principalId: verified.principal.id,
            ...(verified.principal.type === 'human' && verified.principal.refId ? { userId: verified.principal.refId } : {}),
            ...(verified.principal.type === 'machine' ? { refType: verified.principal.refType, refId: verified.principal.refId } : {}),
            name: verified.principal.name,
            permissions: verified.scopes,
            actChain: verified.actChain,
          }
        } catch (error) {
          exchange.fail(401, 'TOKEN_INVALID', `令牌无效：${error instanceof Error ? error.message : String(error)}`)
          return false
        }
      }
    }
    if (demoAuth && !exchange.principal) {
      if (!['GET', 'HEAD', 'OPTIONS'].includes(exchange.method.toUpperCase())) {
        exchange.fail(403, 'DEMO_READONLY', '演示数据只读：连接宿主并登录后解锁写操作')
        return false
      }
      exchange.principal = DEMO_PRINCIPAL
    } else if (!exchange.principal) {
      exchange.fail(401, 'UNAUTHENTICATED', '未认证：请先登录（鉴权中间件未覆盖该请求）')
      return false
    }
    const info = caller(exchange)
    if (info.permissions.includes('*') || info.permissions.includes(point)) return true
    ctx.platformBus.emit('audit.authz.denied', {
      actorId: info.userId ?? info.principalId,
      actorName: info.name,
      point,
      path: exchange.path,
    })
    exchange.fail(403, 'FORBIDDEN', `缺少权限点 ${point}，请联系管理员调整角色`, { permission: point })
    return false
  }

  /** Dégradation honnête au niveau endpoint d'un service optionnel de type capacité absent (état démo) : 503 DEGRADED (ni 500, ni données vides silencieuses). */
  const degraded = (exchange: HttpExchange, capability: string): null => {
    exchange.fail(503, 'DEGRADED', `「${capability}」能力未接入（01门演示态）——连接宿主后可用`)
    return null
  }

  const guarded = (method: string, path: string, permission: string, handler: (exchange: HttpExchange) => unknown | Promise<unknown>): void => {
    // H5 : les déclarations sont automatiquement fondues via http.register dans le registre partagé routeMatrix (une déclaration manquante à l'enregistrement = erreur levée)
    http.register(method, path, async (exchange) => {
      if (!requirePermission(exchange, permission)) return
      try {
        const result = await handler(exchange)
        if (!exchange.res.writableEnded) {
          // Marque d'état démo (plan-gate01 Phase 4) : seules les réponses en lecture « effectivement laissées passer sous l'identité du visiteur de démo » portent demo:true —
          // l'utilisateur connecté lit des données réelles, plus de marquage erroné (resserrage de sémantique accompagnant l'ouverture du canal d'écriture 2026-09-11)
          const isDemoPrincipal = caller(exchange)?.principalId === DEMO_PRINCIPAL.principalId
          const demoMarked = demoAuth && isDemoPrincipal && result !== null && typeof result === 'object' && !Array.isArray(result)
            ? { ...result, demo: true }
            : result
          exchange.ok(demoMarked)
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        exchange.fail(400, 'BAD_REQUEST', message)
      }
    }, { access: 'guarded', permission })
  }

  const body = <T extends Record<string, any>>(exchange: HttpExchange): T => (exchange.body ?? {}) as T
  const changeLog = (exchange: HttpExchange, action: string, resourceType: string, resourceId: string, resourceName: string, detail = ''): void => {
    const info = caller(exchange)
    // Centre d'audit absent (état démo porte 01) → enregistrement nul (dégradation null-object) : l'opération s'exécute normalement
    soft(ctx, 'audit')?.record({
      type: 'change',
      actorType: info.kind === 'human' ? 'human' : 'machine',
      actorId: info.userId ?? info.principalId,
      actorName: info.name,
      action,
      resourceType,
      resourceId,
      resourceName,
      result: 'ok',
      detail,
      ...(info.actChain.length > 0 ? { actChain: info.actChain } : {}),
    })
  }

  /** Résolution du paramètre département + validation d'appartenance (permissions de périmètre départemental : après liaison, seuls sous-arbre d'organisation/admin/identifiants machine peuvent accéder). */
  const deptOf = (exchange: HttpExchange) => {
    const dept = String(exchange.params.dept ?? '')
    if (!DEPT_RE.test(dept)) throw new Error(`部门标识非法：${dept}`)
    const config = panel.dept(dept)
    if (!panel.deptScopeAllowed(caller(exchange), config)) {
      exchange.fail(403, 'FORBIDDEN', `部门范围受限：${config.label} 已绑定组织治理，仅该组织子树成员可访问`, { permission: 'panel.read', deptScope: config.orgId })
      throw new Error('部门范围受限')
    }
    return config
  }

  const orgIdOf = (exchange: HttpExchange): string => {
    const info = caller(exchange)
    const iam = soft(ctx, 'iam')
    return (info.userId ? iam?.users().get(info.userId)?.orgId : undefined)
      ?? iam?.orgs().find((org) => org.parentId === null).at(0)?.id
      // Catalogue d'organisations absent (forme installée porte 01) → clé primaire de l'organisation de démo (même valeur que l'enregistrement d'activation intégré de seed.ts, la face secteur reste utilisable)
      ?? DEMO_ORG_ID
  }

  /**
   * Point d'exécution de l'autorisation au niveau scénario (verrou final du reliquat A-01, replanté du socle, structurellement identique à plugin-flow-core) : une création de tâche portant
   * un sceneCode impose l'arbitrage par la politique du scénario — deny/fail-closed (politique sans correspondance) = 403 avec audit.authz.denied ;
   * allow laisse passer ; sans sceneCode ou scénario sans politique, le passage historique est maintenu (cohérent avec la sémantique sans politique du domaine flow,
   * le garde n'interrompt pas les tâches ordinaires). Les principaux machine n'entrent pas dans le domaine scénario (le RBAC par points de permission couvre déjà), référentiel voir release-notes-2026-09-12.
   */
  const sceneGuard = (exchange: HttpExchange, sceneCode: string | undefined, action: string): boolean => {
    if (!sceneCode?.trim()) return true
    const info = caller(exchange)
    if (!info.userId) return true
    const iam = soft(ctx, 'iam')
    if (!iam) return true
    const decision = iam.checkScene(info.userId, sceneCode, action)
    if (decision.decision !== 'deny') return true
    ctx.platformBus.emit('audit.authz.denied', {
      actorId: info.userId, actorName: info.name, point: `scene:${sceneCode}#${action}`, path: exchange.path,
    })
    exchange.fail(403, 'FORBIDDEN', `场景授权拒绝（${sceneCode} · ${action}）：${decision.reason}`)
    return false
  }

  // -- Départements et vue d'ensemble -------------------------------------------------------------

  guarded('GET', '/api/panel/depts', 'panel.read', (exchange) => {
    const info = caller(exchange)
    return {
      depts: panel.deptConfigs().all().map((dept) => ({
        ...dept,
        allowed: panel.deptScopeAllowed(info, dept),
        org: panel.deptOrg(dept),
      })),
    }
  })

  // Arbre d'organisations (sélecteur de liaison département↔organisation du tiroir de configuration ; champs minimaux, face de gestion panel.config.write)
  guarded('GET', '/api/panel/orgs', 'panel.config.write', (exchange) => {
    const iam = soft(ctx, 'iam')
    if (!iam) return degraded(exchange, '组织目录')
    return { orgs: iam.orgs().all().map((org) => ({ id: org.id, name: org.name, parentId: org.parentId })) }
  })

  /** Liaison département↔organisation (action de gestion de l'interconnexion comptes-organisations) : posée, les permissions de périmètre départemental prennent effet immédiatement. */
  guarded('PUT', '/api/panel/:dept/config', 'panel.config.write', (exchange) => {
    const iam = soft(ctx, 'iam')
    if (!iam) return degraded(exchange, '组织目录')
    const dept = panel.dept(String(exchange.params.dept ?? ''))
    const input = body<{ orgId?: string | null }>(exchange)
    if (input.orgId !== undefined && input.orgId !== null && input.orgId !== '') {
      if (!iam.orgs().get(input.orgId)) throw new Error(`组织不存在：${input.orgId}`)
      ctx.panel.deptConfigs().update(dept.id, { orgId: input.orgId })
    } else {
      ctx.panel.deptConfigs().update(dept.id, { orgId: undefined })
    }
    const updated = panel.dept(dept.id)
    changeLog(exchange, 'panel.dept.bind_org', 'panel_dept', dept.id, dept.label, updated.orgId ?? '（解除绑定）')
    return { dept: { ...updated, org: panel.deptOrg(updated) } }
  })

  guarded('GET', '/api/panel/:dept/overview', 'panel.read', (exchange) => {
    const dept = deptOf(exchange)
    const info = caller(exchange)
    const orgId = orgIdOf(exchange)
    const channels = panel.channels().find((item) => item.dept === dept.id).map((channel) => ({
      ...channel,
      unread: info.userId ? panel.unreadCount(info.userId, channel.id) : 0,
    }))
    return {
      dept,
      org: panel.deptOrg(dept),
      members: panel.deptMembers(dept),
      industry: panel.activeIndustry(orgId),
      channels,
      agents: dept.agents.map((agent) => panel.agentWithAsset(agent)),
      kpis: dept.kpis,
      widgets: panel.board(dept),
      pendingActivations: soft(ctx, 'audit')?.approvals().find((item) => item.kind === 'industry.activation' && item.status === 'pending')
        .map((item) => ({ id: item.id, code: String(item.payload.code ?? ''), orgId: String(item.payload.orgId ?? '') }))
        .filter((item) => !orgId || item.orgId === orgId) ?? [],
    }
  })

  guarded('GET', '/api/panel/:dept/board', 'panel.read', (exchange) => ({
    dept: deptOf(exchange).id,
    widgets: panel.board(deptOf(exchange)),
  }))

  // -- Tiroir de configuration (widget / KPI / ligne-up d'Agents) ------------------------------------

  guarded('GET', '/api/panel/:dept/widgets', 'panel.read', (exchange) => ({ widgets: deptOf(exchange).widgets }))

  guarded('PUT', '/api/panel/:dept/widgets', 'panel.config.write', (exchange) => {
    const dept = deptOf(exchange)
    const widgets = body<{ widgets?: DeptWidget[] }>(exchange).widgets
    if (!Array.isArray(widgets)) throw new Error('body.widgets 必须是数组')
    for (const widget of widgets) {
      if (!widget.id || !widget.type || !widget.title) throw new Error('widget 必须包含 id/type/title')
      if (!['bars', 'funnel', 'alerts', 'todos', 'feeds'].includes(widget.type)) throw new Error(`widget.type 非法：${widget.type}`)
      if (!['manual', 'mock', 'connector', 'mcp'].includes(widget.source)) throw new Error(`widget.source 非法（来源徽标必填）：${widget.source}`)
    }
    ctx.panel.deptConfigs().update(dept.id, { widgets })
    changeLog(exchange, 'panel.widget.layout', 'panel_dept', dept.id, dept.label, `${widgets.length} 块 widget`)
    return { widgets }
  })

  guarded('GET', '/api/panel/:dept/kpis', 'panel.read', (exchange) => ({ kpis: deptOf(exchange).kpis }))

  guarded('PUT', '/api/panel/:dept/kpis', 'panel.config.write', (exchange) => {
    const dept = deptOf(exchange)
    const kpis = body<{ kpis?: DeptKpi[] }>(exchange).kpis
    if (!Array.isArray(kpis)) throw new Error('body.kpis 必须是数组')
    for (const kpi of kpis) {
      if (!kpi.label || kpi.value === undefined) throw new Error('kpi 必须包含 label/value')
      if (!['manual', 'mock', 'connector'].includes(kpi.source)) throw new Error(`kpi.source 非法（来源徽标必填）：${kpi.source}`)
    }
    ctx.panel.deptConfigs().update(dept.id, { kpis })
    changeLog(exchange, 'panel.kpi.layout', 'panel_dept', dept.id, dept.label, `${kpis.length} 个 KPI`)
    return { kpis }
  })

  guarded('PUT', '/api/panel/:dept/agents', 'panel.config.write', (exchange) => {
    const dept = deptOf(exchange)
    const agents = body<{ agents?: DeptAgent[] }>(exchange).agents
    if (!Array.isArray(agents) || agents.length === 0) throw new Error('body.agents 必须是非空数组')
    for (const agent of agents) {
      if (!agent.name || !agent.icon) throw new Error('agent 必须包含 name/icon')
      if (agent.agentRef && !/^agent:[A-Za-z0-9._-]+$/.test(agent.agentRef)) throw new Error(`agentRef 格式非法（agent:<idOrSlug>）：${agent.agentRef}`)
    }
    ctx.panel.deptConfigs().update(dept.id, { agents })
    changeLog(exchange, 'panel.agent.roster', 'panel_dept', dept.id, dept.label, `${agents.length} 个 Agent 阵容位`)
    return { agents }
  })

  // -- Catalogue de modèles (source de fait modelgw prioritaire ; en état installé porte 01 avec dsh, pont de modèles dsh — catalogue en lecture seule homogène avec la configuration dsh) ------

  /** Résolution de la passerelle de modèles : modelgw présent prioritaire, absent mais llm dsh présent → pont (llm-bridge.ts), ni l'un ni l'autre → undefined. */
  const modelGateway = () => resolvePanelModelGateway(ctx)

  /** Lecture du catalogue (vue panneau) : apiKey en écho masqué (référence env: affichée telle quelle, clé directe masquée), même référentiel que console. */
  const maskedModel = (model: { apiKey: string } & Record<string, unknown>) => ({
    ...model,
    apiKey: model.apiKey.startsWith('env:') ? model.apiKey : '***',
  })

  guarded('GET', '/api/panel/models', 'panel.read', async (exchange) => {
    const resolved = modelGateway()
    if (!resolved) return degraded(exchange, '模型网关')
    if (resolved.kind === 'dsh') {
      // Catalogue du pont dsh : découverte paresseuse (l'énumération des routages provider est asynchrone), default suit le modèle par défaut de dsh en tête
      const models = await resolved.gateway.ensureCatalog()
      return { models: models.map(maskedModel), source: 'dsh' }
    }
    return { models: resolved.gateway.models().all().map(maskedModel), source: 'modelgw' }
  })

  guarded('POST', '/api/panel/models', 'panel.config.write', (exchange) => {
    const resolved = modelGateway()
    if (!resolved) return degraded(exchange, '模型网关')
    if (resolved.kind === 'dsh') {
      exchange.fail(400, 'MODEL_READONLY', '模型目录由 dsh 配置托管（settings.yaml agent-default-model / llm 适配器）——01门面板只读，请在 dsh 侧增删改模型')
      return
    }
    const gateway = resolved.gateway
    const input = body<{ slug?: string; displayName?: string; provider?: string; endpoint?: string; apiKey?: string; listCentsPerKTokens?: number; costCentsPerKTokens?: number; status?: string; dataClassLimit?: string }>(exchange)
    const slug = input.slug?.trim() ?? ''
    if (!slug) throw new Error('模型 slug 必填（如 deepseek-chat）')
    if (!/^[A-Za-z0-9._-]{2,64}$/.test(slug)) throw new Error(`slug 仅允许字母/数字/._-（2-64 位）：${slug}`)
    if (!input.endpoint?.trim()) throw new Error('endpoint 必填（OpenAI 兼容基址；未配置不可调用，绝不造假回复）')
    if (!Number.isFinite(input.listCentsPerKTokens) || (input.listCentsPerKTokens ?? -1) < 0) throw new Error('listCentsPerKTokens 必须是非负数（挂牌价，分/千 tokens）')
    const status = input.status === 'offline' ? 'offline' as const : 'online' as const
    // Plafond de gradation des données (livraison IAW 1-1) : public/interne/secret, défaut internal (compatibilité des enregistrements existants)
    const dataClassLimit = input.dataClassLimit === 'public' || input.dataClassLimit === 'internal' || input.dataClassLimit === 'secret'
      ? input.dataClassLimit as 'public' | 'internal' | 'secret'
      : 'internal' as const
    // À l'édition, laisser la clé vide = conserver la clé existante (convention : le formulaire ne remplit pas la clé), ne pas écraser par la référence par défaut
    const existing = gateway.models().findOne((item) => item.slug === slug)
    const model = gateway.upsertModel({
      slug,
      displayName: input.displayName?.trim() || slug,
      provider: input.provider?.trim() || 'external',
      endpoint: input.endpoint.trim(),
      apiKey: input.apiKey?.trim() || existing?.apiKey || 'env:MODEL_API_KEY',
      listCentsPerKTokens: input.listCentsPerKTokens!,
      costCentsPerKTokens: input.costCentsPerKTokens ?? Math.floor(input.listCentsPerKTokens! / 2),
      status,
      dataClassLimit,
    })
    changeLog(exchange, 'panel.model.upsert', 'model', model.id, model.slug, `${status === 'online' ? '上线' : '下线'}，分级上限=${dataClassLimit}`)
    return maskedModel(model)
  })

  /** Suppression de l'enregistrement : retire du catalogue de modèles ; données de metering et d'audit conservées. */
  guarded('DELETE', '/api/panel/models/:id', 'panel.config.write', (exchange) => {
    const resolved = modelGateway()
    if (!resolved) return degraded(exchange, '模型网关')
    if (resolved.kind === 'dsh') {
      exchange.fail(400, 'MODEL_READONLY', '模型目录由 dsh 配置托管——01门面板只读，请在 dsh 侧增删改模型')
      return
    }
    const gateway = resolved.gateway
    const id = exchange.params['id']!
    const model = gateway.models().get(id)
    if (!model) throw new Error(`模型不存在：${id}`)
    gateway.models().remove(id)
    changeLog(exchange, 'panel.model.delete', 'model', id, model.slug)
    return { deleted: true }
  })

  /** Test de connectivité : toute la chaîne invoke réelle via la passerelle (metering modelgw / vraie sortie du pont dsh), l'échec est renvoyé tel quel, sans succès fabriqué. */
  guarded('POST', '/api/panel/models/:slug/test', 'panel.config.write', async (exchange) => {
    const resolved = modelGateway()
    if (!resolved) return degraded(exchange, '模型网关')
    const slug = String(exchange.params.slug ?? '')
    const info = caller(exchange)
    const orgId = orgIdOf(exchange)
    if (resolved.kind === 'modelgw' && !orgId) throw new Error('无法确定计费组织（orgId），无法执行真实调用测试')
    try {
      const result = await resolved.gateway.invoke({
        model: slug,
        messages: [{ role: 'user', content: '模型连通性测试，请直接回复：OK' }],
        ...(resolved.kind === 'modelgw' ? { orgId } : {}),
        subject: info.userId ? `user:${info.userId}` : `panel:${info.principalId}`,
        maxTokens: 16,
      })
      return { ok: true, model: result.model, content: result.content.slice(0, 80), outputTokens: result.outputTokens }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      // Astuce haute fréquence d'erreur : une URL de base compatible OpenAI sans le chemin /v1 donne un 404 amont (ex. « 404 page not found ») — libellé actionnable plutôt qu'un code de statut nu
      const hint = /HTTP 404/.test(message)
        ? '（提示：HTTP 404 常因 endpoint 漏了 /v1 路径——OpenAI 兼容基址应形如 https://<host>/v1）'
        : ''
      return { ok: false, error: `${message}${hint}` }
    }
  })

  // -- Tableau de bord stratégique (migration à double voie : agrégat board du portal d'origine + délivrance des paquets de cartes console /api/platform/card-packs) --
  // Lit panel.read ; la face agrégat (entonnoir/WAIC/ROI) et la face paquets de cartes (rôle×plateforme×survie de ref) délivrées par un seul endpoint.
  // Le service de paquets de cartes reste dans platform-core (identique à l'octet près à la branche principale), ce plugin est l'unique consommateur.
  const refAlive = (ref: string): boolean => {
    const colon = ref.indexOf(':')
    const type = ref.slice(0, colon)
    const id = ref.slice(colon + 1)
    const matches = (item: { id?: string; slug?: string }): boolean => item.id === id || item.slug === id
    // Catalogue d'actifs absent (état démo porte 01) → considéré vivant (toutes les cartes affichées, pas d'entrée cachée par la dégradation)
    if (!soft(ctx, 'resourceCore') && ['agent', 'app', 'nas'].includes(type)) return true
    if (!soft(ctx, 'mcpRegistry') && type === 'mcp') return true
    if (!soft(ctx, 'skillHub') && type === 'skill') return true
    if (!soft(ctx, 'iam') && type === 'kb') return true
    try {
      if (type === 'agent' || type === 'app' || type === 'nas') {
        return soft(ctx, 'resourceCore').list(type).some(matches)
      }
      if (type === 'mcp') return soft(ctx, 'mcpRegistry').services().all().some(matches)
      if (type === 'skill') return soft(ctx, 'skillHub').skills().all().some(matches)
      if (type === 'kb') return soft(ctx, 'iam').orgs().get(id) !== undefined
      return true
    } catch {
      return true
    }
  }

  guarded('GET', '/api/panel/board', 'panel.read', (exchange) => {
    const info = caller(exchange)
    // -- Face paquets de cartes (sémantique de l'ancien console /api/platform/card-packs) --
    const available = [...new Set(cardpacks.all().map((pack) => pack.platform))]
    const requested = exchange.query.get('platform') ?? process.env.RQ_PLATFORM
      ?? (available.includes('rd') ? 'rd' : available[0]) ?? 'strategy'
    if (!CARD_PLATFORMS.includes(requested as CardPlatform)) {
      exchange.fail(400, 'BAD_REQUEST', `platform 非法（应为 ${CARD_PLATFORMS.join('/')}）`)
      return
    }
    const platform = requested as CardPlatform
    const iam = soft(ctx, 'iam')
    const user = info.userId ? iam?.users().get(info.userId) : undefined
    const roles = user ? user.roleIds.map((roleId) => iam?.roles().get(roleId)?.code).filter((code): code is string => Boolean(code)) : []
    cardpacks.setRefAliveResolver(refAlive)
    const packs = cardpacks.forPlatform(platform)
    const { cards, droppedDeadRefs } = filterCards({ packs, roles, refAlive })
    if (droppedDeadRefs.length > 0) {
      ctx.platformBus.emit('audit.alert.fired', {
        id: newId('alt'), severity: 'warning', title: '卡片包含失效资产引用',
        message: `平台 ${platform} 卡片包中 ${droppedDeadRefs.length} 个 ref 已失效被过滤：${droppedDeadRefs.join('、')}（请修正 cardpacks 配置）`,
      })
    }

    // -- Face agrégat (sémantique de l'ancien board portal : entonnoir = exposition/clics→appels→achèvement ; WAIC = agrégat hebdo usage) --
    const weekAgo = new Date(Date.now() - 7 * 24 * 3600_000).toISOString()
    const behaviorCount = (type: string): number => {
      return soft(ctx, 'behavior')?.query({ type, from: weekAgo }).total ?? 0
    }
    let usageCount = 0
    let chargeCents = 0
    let byDay: Array<{ day: string; count: number; charge_cents: number }> = []
    const usageAgg = soft(ctx, 'usage')
    if (usageAgg) {
      const totals = usageAgg.totals({ from: weekAgo })
      usageCount = totals.count
      chargeCents = totals.charge_cents
      byDay = usageAgg.breakdown(weekAgo).byDay
    }
    const completedCalls = soft(ctx, 'mcpRegistry')?.calls().all()
      .filter((call) => call.ok && call.at >= weekAgo).length ?? 0

    return {
      generatedAt: new Date().toISOString(),
      windowDays: 7,
      // Face paquets de cartes (mise à plat au sommet, le consommateur de cartes de l'espace de travail console change d'endpoint sans modification)
      platform, label: packs[0]?.label ?? '', roles, cards, totalPacks: packs.length, availablePlatforms: available, droppedDeadRefs,
      // Face agrégat (tableau de bord stratégique) — catalogue d'actifs absent (état démo) → tout à 0 (dégradation honnête du tableau en vue de données de démo)
      assets: {
        appsOnline: soft(ctx, 'resourceCore')?.list('app').filter((item) => item.status === 'online').length ?? 0,
        agentsOnline: soft(ctx, 'resourceCore')?.list('agent').filter((item) => item.status === 'online').length ?? 0,
        skillsPublished: soft(ctx, 'skillHub')?.skills().all().filter((item) => item.status === 'published').length ?? 0,
        mcpServing: soft(ctx, 'mcpRegistry')?.services().all()
          .filter((service) => service.status === 'online' || service.status === 'gray').length ?? 0,
      },
      waic: { count: usageCount, chargeCents },
      byDay,
      funnel: {
        exposed: behaviorCount('card.exposed'),
        clicked: behaviorCount('card.clicked'),
        invoked: usageCount,
        completed: completedCalls,
      },
      // Modèle de coût ROI main-d'œuvre (WP-14) : la déclaration du référentiel d'estimation est délivrée avec la réponse, la face tableau doit afficher la mention « estimation ».
      roi: {
        minutesPerCallEstimate: Number(process.env.ROI_MINUTES_PER_CALL ?? 3),
        laborCostCentsPerHour: Number(process.env.ROI_LABOR_COST_CENTS_PER_HOUR ?? 5000),
        callBase: completedCalls > 0 ? completedCalls : usageCount,
        estimatedHoursSaved: Math.round(((completedCalls > 0 ? completedCalls : usageCount) * Number(process.env.ROI_MINUTES_PER_CALL ?? 3) / 60) * 100) / 100,
        estimatedLaborCostCents: Math.round((completedCalls > 0 ? completedCalls : usageCount) * Number(process.env.ROI_MINUTES_PER_CALL ?? 3) / 60 * Number(process.env.ROI_LABOR_COST_CENTS_PER_HOUR ?? 5000)),
        platformChargeCents: chargeCents,
        note: '估算口径：替代工时 = 调用次数 × 单次替代分钟 ÷ 60；人力成本 = 替代工时 × 综合人力时薪。非实测值。',
      },
    }
  })
  // -- Canaux et messages ---------------------------------------------------------------

  guarded('GET', '/api/panel/:dept/channels', 'panel.read', (exchange) => {
    const dept = deptOf(exchange)
    const info = caller(exchange)
    return {
      channels: panel.channels().find((item) => item.dept === dept.id).map((channel) => ({
        ...channel,
        unread: info.userId ? panel.unreadCount(info.userId, channel.id) : 0,
      })),
    }
  })

  guarded('POST', '/api/panel/:dept/channels', 'panel.write', (exchange) => {
    const dept = deptOf(exchange)
    const input = body<{ name?: string; desc?: string }>(exchange)
    if (!input.name?.trim()) throw new Error('频道名必填')
    const info = caller(exchange)
    const channel = panel.channels().insert({
      id: newId('pchan'), dept: dept.id, name: input.name.trim(),
      ...(input.desc ? { desc: input.desc.trim() } : {}), createdBy: info.userId ?? info.principalId,
    })
    changeLog(exchange, 'panel.channel.create', 'panel_channel', channel.id, channel.name)
    return { channel }
  })

  guarded('GET', '/api/panel/:dept/messages', 'panel.read', (exchange) => {
    const dept = deptOf(exchange)
    const channelId = exchange.query.get('channelId') ?? ''
    const after = exchange.query.get('after') ?? ''
    // Garde limit (QA T-05) : non numérique/négatif/valeur énorme converge vers [1,200], fini le NaN→renvoi intégral
    const limitRaw = Number(exchange.query.get('limit') ?? 80)
    const limit = Math.min(Math.max(Number.isFinite(limitRaw) ? Math.floor(limitRaw) : 80, 1), 200)
    let rows = panel.messages().find((m) => m.dept === dept.id && (channelId ? m.channelId === channelId : true))
    if (after) rows = rows.filter((m) => m.createdAt > after)
    return { messages: rows.slice(-limit) }
  })

  guarded('POST', '/api/panel/:dept/messages', 'panel.write', async (exchange) => {
    const dept = deptOf(exchange)
    const input = body<{ channelId?: string; text?: string; ddSync?: boolean; uniqueKey?: string; model?: string; streamAgent?: boolean }>(exchange)
    if (!input.text?.trim()) throw new Error('消息内容必填')
    // Plafond de longueur (QA T-06) : corps du message convergé à 10k caractères, fini l'impact en chaîne d'un payload énorme sur l'inscription/SSE/scrutin
    if (input.text.length > 10_000) throw new Error('消息内容过长（上限 10000 字符）')
    const channelId = input.channelId || panel.channels().find((item) => item.dept === dept.id).at(0)?.id
    if (!channelId) throw new Error('部门暂无频道，请先创建')
    // Bascule de modèle de la boîte de dialogue : un model explicitement spécifié doit être un slug enregistré au catalogue (sinon suit la configuration de l'actif Agent)
    const requestedModel = input.model?.trim() ?? ''
    if (requestedModel && !modelGateway()?.gateway.models().findOne((item) => item.slug === requestedModel)) {
      throw new Error(`模型未在目录登记：${requestedModel}（可在「🧠 模型」中登记）`)
    }
    const info = caller(exchange)
    const message = await panel.sendMessage({
      dept: dept.id, channelId, senderType: 'human', senderId: info.userId,
      senderName: info.name, text: input.text.trim(), ddSync: input.ddSync === true,
      ...(input.uniqueKey ? { uniqueKey: input.uniqueKey } : {}),
      ...(requestedModel ? { modelOverride: requestedModel } : {}),
      // streamAgent (carte de réponse en flux 2026-09-11) : @collègue numérique est piloté par l'endpoint de flux du front, saut du dispatch implicite anti double exécution ;
      // endpoint de flux indisponible = le front retombe sur le tirage, une réponse manquante peut être redéclenchée par renvoi de l'utilisateur (dégradation honnête, sans simulation de saisie)
      ...(input.streamAgent === true ? { skipAgentDispatch: true } : {}),
    })
    return { message }
  })

  /**
   * Réponse en flux de l'Agent (SSE-sur-POST, besoin utilisateur 2026-09-11 : @collègue numérique → rendu incrémental de la carte) :
   * transmet événement par événement {type:start|delta|done|fallback|end} ; une fois terminé, la réponse est inscrite et diffusée comme d'habitude
   * via panel.message.created (les autres bouts reçoivent le message persistant par le canal SSE existant). Authentification et validation de périmètre départemental
   * aux mêmes règles que la face REST (requirePermission + deptOf), un échec de permission reste un 403/401 propre.
   */
  http.register('POST', '/api/panel/:dept/agent-stream', async (exchange) => {
    if (!requirePermission(exchange, 'panel.write')) return
    const res = exchange.res
    const sse = (payload: Record<string, unknown>) => {
      try { res.write(`data: ${JSON.stringify(payload)}\n\n`) } catch { /* connexion déjà fermée */ }
    }
    try {
      const dept = deptOf(exchange)
      const input = body<{ messageId?: string; model?: string }>(exchange)
      const message = input.messageId ? panel.messages().get(input.messageId) : undefined
      if (!message || message.dept !== dept.id || message.senderType !== 'human') {
        exchange.fail(400, 'BAD_REQUEST', '消息不存在或不属于该部门')
        return
      }
      if (res.headersSent) return
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' })
      const mentioned = dept.agents.filter((agent) => message.text.includes(`@${agent.name}`))
      if (mentioned.length === 0) {
        sse({ type: 'end', note: '消息未点名任何数字同事' })
        res.end()
        return
      }
      const requestedModel = input.model?.trim() || undefined
      for (const agentCard of mentioned) {
        await panel.streamAgentReply(dept, agentCard, message, requestedModel, sse)
      }
      sse({ type: 'end' })
      res.end()
    } catch (error) {
      // Flux ouvert : l'erreur ne peut être signalée que dans le flux ; flux non ouvert → enveloppe d'erreur standard
      const message = error instanceof Error ? error.message : String(error)
      if (res.headersSent) {
        sse({ type: 'end', error: message })
        res.end()
      } else {
        exchange.fail(400, 'BAD_REQUEST', message)
      }
    }
  }, { access: 'guarded', permission: 'panel.write' })

  guarded('POST', '/api/panel/channels/:id/read', 'panel.read', (exchange) => {
    const info = caller(exchange)
    if (!info.userId) throw new Error('仅平台账号可推进已读游标')
    panel.markRead(info.userId, String(exchange.params.id))
    return { ok: true }
  })

  guarded('POST', '/api/panel/messages/:id/card-action', 'panel.write', async (exchange) => {
    const input = body<{ opId?: string; reason?: string }>(exchange)
    if (!input.opId) throw new Error('opId 必填')
    const info = caller(exchange)
    const result = await panel.cardAction({
      messageId: String(exchange.params.id), opId: input.opId,
      actorId: info.userId ?? info.principalId, actorName: info.name, ...(input.reason ? { reason: input.reason } : {}),
    })
    changeLog(exchange, 'panel.card.action', 'panel_message', result.message.id, result.message.card?.title ?? '', result.result)
    return result
  })

  // -- Appel direct de Skill (face consommatrice du contrat J1 v1 : @nom-de-skill/commande slash dans la boîte de dialogue) ---------------------------------

  guarded('GET', '/api/panel/:dept/skills', 'panel.read', (exchange) => {
    deptOf(exchange)
    return { skills: panel.listInvokeableSkills(orgIdOf(exchange)) }
  })

  /**
   * Appel direct nominatif de Skill (le serveur de /nom-de-skill question). Sémantique de dégradation honnête (contrat J1 v1) : les échecs prévisibles
   * (skill inexistant/non publié/invisible/échec de passerelle) répondent HTTP 200 + ok:false + reason —
   * la dégradation est une donnée, pas une erreur de transport ; les échecs d'authentification/périmètre départemental restent en 403/400.
   * Trace : le texte slash original tombe d'abord dans le canal (skipAgentDispatch : le même texte ne redéclenche pas @Agent) ;
   * succès tombe dans la réponse du skill (message de type agent), échec dans une ligne système — la raison d'échec est visible dans tout le canal, consultable, pas silencieuse.
   */
  guarded('POST', '/api/panel/:dept/skills/invoke', 'panel.write', async (exchange) => {
    const dept = deptOf(exchange)
    const input = body<{ skill?: string; message?: string; channelId?: string; model?: string; uniqueKey?: string }>(exchange)
    const skillName = input.skill?.trim() ?? ''
    const message = input.message?.trim() ?? ''
    if (!skillName) throw new Error('skill 必填（技能名或 slug）')
    if (!message) throw new Error('message 必填（要交给技能的输入/问题）')
    if (message.length > 10_000) throw new Error('消息内容过长（上限 10000 字符）')
    const channelId = input.channelId || panel.channels().find((item) => item.dept === dept.id).at(0)?.id
    if (!channelId) throw new Error('部门暂无频道，请先创建')
    const requestedModel = input.model?.trim() ?? ''
    if (requestedModel && !modelGateway()?.gateway.models().findOne((item) => item.slug === requestedModel)) {
      throw new Error(`模型未在目录登记：${requestedModel}（可在「🧠 模型」中登记）`)
    }
    const info = caller(exchange)
    const trace = await panel.sendMessage({
      dept: dept.id, channelId, senderType: 'human', senderId: info.userId,
      senderName: info.name, text: `/${skillName} ${message}`, ddSync: false,
      ...(requestedModel ? { modelOverride: requestedModel } : {}),
      ...(input.uniqueKey ? { uniqueKey: input.uniqueKey } : {}),
      skipAgentDispatch: true,
    })
    changeLog(exchange, 'panel.skill.invoke', 'panel_message', trace.id, skillName, message.slice(0, 200))
    const result = await panel.invokeSkill(skillName, message, {
      userId: info.userId, ...(requestedModel ? { modelOverride: requestedModel } : {}),
    })
    if (!result.ok) {
      await panel.sendMessage({
        dept: dept.id, channelId, senderType: 'system', senderName: '01门',
        text: `⚡ 技能「${skillName}」调用失败：${result.reason}`, ddSync: false,
      })
      return { ok: false as const, reason: result.reason, message: trace }
    }
    const reply = await panel.sendMessage({
      dept: dept.id, channelId, senderType: 'agent', senderName: `⚡ ${result.skill.name}`,
      senderIcon: '⚡', agentName: result.skill.name, text: result.reply,
      ddSync: false, ...(result.model ? { replyModel: result.model } : {}),
      ...(trace.sceneCode ? { sceneCode: trace.sceneCode } : {}),
    })
    return { ok: true as const, reply: result.reply, model: result.model, skill: result.skill, message: trace, replyMessage: reply, skillLoad: result.skillLoad }
  })

  // -- Tableau des tâches -----------------------------------------------------------------

  guarded('GET', '/api/panel/:dept/tasks', 'panel.read', (exchange) => ({
    tasks: panel.tasks().find((item) => item.dept === deptOf(exchange).id),
  }))

  guarded('POST', '/api/panel/:dept/tasks', 'panel.task.write', (exchange) => {
    const dept = deptOf(exchange)
    const input = body<{ title?: string; detail?: string; lane?: string; assigneeName?: string; assigneeType?: string; sceneCode?: string; execIssueId?: string; goalId?: string; evidenceRefs?: string[]; reworkOf?: string }>(exchange)
    if (!input.title?.trim()) throw new Error('任务标题必填')
    if (input.lane !== undefined && !TASK_LANES.includes(input.lane as TaskLane)) throw new Error(`非法泳道：${input.lane}`)
        // A-01 : une tâche rattachée à un scénario voit sa création arbitrée par la politique du scénario (deny/fail-closed → 403), sans politique le passage est maintenu
    if (!sceneGuard(exchange, input.sceneCode, 'panel.task.create')) return
    const info = caller(exchange)
    const task = panel.createTask({
      dept: dept.id, title: input.title.trim(),
      ...(input.detail ? { detail: input.detail } : {}),
      ...(input.lane ? { lane: input.lane as TaskLane } : {}),
      ...(input.assigneeType === 'agent' ? { assigneeType: 'agent' as const } : {}),
      ...(input.assigneeName ? { assigneeName: input.assigneeName } : {}),
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}),
      // Lignée centre d'exécution (révision DSH issue#3) : portée = projection de l'autorité exec-hub, absente/inexistante = 400 honnête
      ...(input.execIssueId?.trim() ? { execIssueId: input.execIssueId.trim() } : {}),
      ...(input.goalId?.trim() ? { goalId: input.goalId.trim() } : {}),
      ...(Array.isArray(input.evidenceRefs) && input.evidenceRefs.length ? { evidenceRefs: input.evidenceRefs.map(String) } : {}),
      ...(input.reworkOf?.trim() ? { reworkOf: input.reworkOf.trim() } : {}),
      createdBy: info.userId ?? info.principalId,
    })
    return { task }
  })

  guarded('POST', '/api/panel/tasks/:id/transition', 'panel.task.write', (exchange) => {
    const lane = body<{ lane?: string }>(exchange).lane
    if (!lane || !TASK_LANES.includes(lane as TaskLane)) throw new Error(`非法泳道：${lane}`)
    const info = caller(exchange)
    return { task: panel.transitionTask(String(exchange.params.id), lane as TaskLane, info.userId ?? info.principalId) }
  })

  // -- Projection du centre d'exécution (révision DSH issue#3/#4, 2026-10-29) -----------------------------------------
  // Le panneau ne copie pas l'état d'autorité : objectifs/tâches lus au travers d'exec-hub, les migrations de couloir et conclusions d'acceptance sont ré-écrites en miroir (source de fait unique des tâches).

  /** Projection des objectifs du département : objectifs (base/valeur cible metric) + tâches (lignée goalAncestry/verrou d'exécution) + IDs des tâches liées au panneau. */
  guarded('GET', '/api/panel/:dept/goals', 'panel.read', (exchange) => {
    const dept = deptOf(exchange)
    const projection = panel.deptGoalsProjection(dept)
    if (!projection) return degraded(exchange, '执行中枢')
    return projection
  })

  /** Verdict d'acceptance : signature-fermeture (accepted)/renvoi-reprise (rework) ; avec lignée exec, ré-écriture en miroir vers exec-hub. */
  guarded('POST', '/api/panel/tasks/:id/verdict', 'panel.task.write', (exchange) => {
    const input = body<{ verdict?: string; opinion?: string }>(exchange)
    if (input.verdict !== 'accepted' && input.verdict !== 'rework') throw new Error("verdict 必填且只能是 'accepted'（签认关闭）或 'rework'（打回返工）")
    const info = caller(exchange)
    return { task: panel.taskVerdict(String(exchange.params.id), input.verdict, { actorId: info.userId ?? info.principalId, ...(input.opinion ? { opinion: input.opinion } : {}) }) }
  })

  // -- Savoir départemental ----------------------------------------------------------------

  guarded('GET', '/api/panel/:dept/artifacts', 'panel.read', (exchange) => ({
    artifacts: panel.artifacts().find((item) => item.dept === deptOf(exchange).id).slice(-100).reverse(),
  }))

  guarded('POST', '/api/panel/:dept/artifacts', 'panel.write', (exchange) => {
    const dept = deptOf(exchange)
    const input = body<{ title?: string; content?: string; kind?: string; sceneCode?: string }>(exchange)
    if (!input.title?.trim() || !input.content?.trim()) throw new Error('标题与内容必填')
    const kind = (['report', 'order', 'quote', 'diagnosis', 'other'].includes(input.kind ?? '') ? input.kind : 'other') as 'report' | 'order' | 'quote' | 'diagnosis' | 'other'
    const info = caller(exchange)
    const artifact = panel.artifacts().insert({
      id: newId('part'), dept: dept.id, kind, title: input.title.trim(), content: input.content.trim(),
      ...(input.sceneCode ? { sceneCode: input.sceneCode } : {}), createdBy: info.userId ?? info.principalId,
    })
    changeLog(exchange, 'panel.artifact.create', 'panel_artifact', artifact.id, artifact.title)
    return { artifact }
  })

  // -- Interconnexion avec la cartographie de scénarios ----------------------------------------------------------------

  guarded('POST', '/api/panel/:dept/scenes/:code/diagnose', 'panel.write', async (exchange) => {
    const info = caller(exchange)
    return panel.diagnose({
      dept: String(exchange.params.dept), sceneCode: String(exchange.params.code),
      actorId: info.userId ?? info.principalId, actorName: info.name,
    })
  })

  guarded('POST', '/api/panel/:dept/scenes/:code/sync-dingtalk', 'panel.write', (exchange) => {
    const dept = deptOf(exchange)
    const code = String(exchange.params.code)
    const { pack, sceneLabel } = panel.sceneContext(code)
    const info = caller(exchange)
    ctx.platformBus.emit(PlatformEvents.PanelCardAction, {
      dept: dept.id, opId: 'scene-sync', opLabel: '同步钉钉群', action: 'dd.push', ddPush: true,
      title: `🗺 ${pack.name}场景卡：${sceneLabel}`,
      text: `【${pack.name} · ${code}】${sceneLabel}\n痛点与四清单详见部门面板「场景图谱」页。`,
      actorId: info.userId ?? info.principalId, actorName: info.name, channelName: '',
    })
    changeLog(exchange, 'panel.scene.sync_dingtalk', 'panel_scene', code, sceneLabel)
    return { ok: true, note: '已请求钉钉桥接投递（未绑定群桥时投递失败会留痕告警）' }
  })

  // -- Trois états de secteur + demande d'activation + cartographie -----------------------------------------------------

  guarded('GET', '/api/panel/industries', 'panel.read', (exchange) => {
    const orgId = orgIdOf(exchange)
    const pendingCodes = soft(ctx, 'audit')?.approvals()
      .find((item) => item.kind === 'industry.activation' && item.status === 'pending' && String(item.payload.orgId ?? '') === orgId)
      .map((item) => String(item.payload.code ?? '')) ?? []
    return { industries: panel.industryStates(orgId, pendingCodes) }
  })

  guarded('POST', '/api/panel/industries/:code/activate-requests', 'panel.write', (exchange) => {
    const audit = soft(ctx, 'audit')
    if (!audit) return degraded(exchange, '审批中心')
    const code = String(exchange.params.code ?? '').toUpperCase()
    const registry = panel.industryStates('', []).find((item) => item.code === code)
    if (!registry) throw new Error(`未登记行业：${code}`)
    const orgId = orgIdOf(exchange)
    if (!orgId) throw new Error('无法确定所属组织（组织账号缺失）')
    const existing = panel.activations().findOne((item) => item.orgId === orgId && item.code === code && item.status === 'active')
    if (existing) throw new Error(`行业 ${code} 对本组织已是激活态`)
    const info = caller(exchange)
    const approval = audit.createApproval({
      kind: 'industry.activation',
      // WP-10/L1 (QA A-06) : L4 haut risque unifié — l'approbation exige double confirmation + marqueur de revue finale société
      riskLevel: 'high',
      title: `行业功能包授权激活：${registry.name}（${code}）`,
      payload: { code, orgId, requestedBy: info.name, sub: registry.sub, graphLoaded: registry.graphLoaded },
      requesterId: info.userId ?? info.principalId,
      requesterName: info.name,
      riskLevel: 'high',
    })
    changeLog(exchange, 'panel.industry.activate_request', 'panel_industry', code, registry.name, `审批单 ${approval.id}`)
    return { approval }
  })

  guarded('GET', '/api/panel/scenegraph', 'scenegraph.read', (exchange) => {
    const code = (exchange.query.get('industry') ?? '').toUpperCase()
    const pack = ctx.scenegraphs.get(code)
    if (!pack) throw new Error(`场景图谱未装载或未激活：${code}（已装载：${ctx.scenegraphs.all().map((item) => item.code).join('/') || '无'}）`)
    return { pack, problems: ctx.scenegraphs.loadProblems() }
  })

  guarded('POST', '/api/panel/scenegraphs/reload', 'panel.config.write', async (exchange) => {
    const result = await ctx.scenegraphs.reloadFromDir()
    changeLog(exchange, 'panel.scenegraph.reload', 'scenegraph', 'all', `${result.packs} 包`, `问题 ${result.problems.length} 项`)
    return result
  })

  // -- Repli par scrutin + SSE (ligne d'airain du double canal webview DingTalk) --------------------------------------

  guarded('GET', '/api/panel/:dept/poll', 'panel.read', (exchange) => {
    const dept = deptOf(exchange)
    const info = caller(exchange)
    const since = exchange.query.get('since') ?? ''
    const messages = panel.messages().find((m) => m.dept === dept.id && (since ? m.createdAt > since : true)).slice(-50)
    return {
      at: new Date().toISOString(),
      messages,
      tasks: panel.tasks().find((item) => item.dept === dept.id),
      unread: info.userId
        ? panel.channels().find((item) => item.dept === dept.id).map((channel) => ({ channelId: channel.id, unread: panel.unreadCount(info.userId, channel.id) }))
        : [],
    }
  })

  // -- Ticket de flux SSE (liste de passation H4 / convergence architecturale P2-O-5) ---------------------------
  // EventSource ne peut pas porter d'en-tête Authorization ; un access token longue durée via ?token= finirait dans les logs de proxy/d'accès.
  // Remplacé par POST (Bearer + point de permission + validation de périmètre départemental) échangeant un ticket à usage unique ≤60 s, consommé au GET :
  // seuls des identifiants courts à usage unique apparaissent dans l'URL. L'ancien canal ?token= est conservé (fail-closed aux mêmes règles) pour la transition des consommateurs non montés de version.

  /** Ticket de flux SSE : sha256(ticketRaw) → {principal, dept, expiration}. Consommé = supprimé ; l'émission profite du nettoyage des expirés. */
  const streamTickets = new Map<string, { principal: CallerInfo; dept: string; expiresAt: number }>()
  const STREAM_TICKET_TTL_MS = 60_000

  const issueStreamTicket = (principal: CallerInfo, dept: string): string => {
    const now = Date.now()
    for (const [key, value] of streamTickets) if (value.expiresAt < now) streamTickets.delete(key)
    const raw = 'stk_' + randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '')
    streamTickets.set(createHash('sha256').update(raw).digest('hex'), { principal, dept, expiresAt: now + STREAM_TICKET_TTL_MS })
    return raw
  }

  guarded('POST', '/api/panel/stream-ticket', 'panel.read', (exchange) => {
    const dept = String(body<{ dept?: string }>(exchange).dept ?? '')
    if (!DEPT_RE.test(dept)) throw new Error(`部门标识非法：${dept}`)
    const deptConfig = panel.dept(dept)
    if (!panel.deptScopeAllowed(caller(exchange), deptConfig)) {
      exchange.fail(403, 'FORBIDDEN', `部门范围受限：${deptConfig.label} 已绑定组织治理，仅该组织子树成员可访问`, { permission: 'panel.read', deptScope: deptConfig.orgId })
      return
    }
    return { ticket: issueStreamTicket(caller(exchange), dept), expiresInSeconds: STREAM_TICKET_TTL_MS / 1000 }
  })

  // SSE : chemin public (liste blanche console) + ?ticket= (préféré, consommation unique) ou ?token= (ancien canal) auto-vérifiés, fail-closed
  http.register('GET', '/api/panel/stream', (exchange) => {
    const fail = (status: number, message: string) => exchange.fail(status, 'STREAM_AUTH_FAILED', message)
    let dept = exchange.query.get('dept') ?? ''
    const ticketRaw = exchange.query.get('ticket') ?? ''
    if (!ticketRaw && !exchange.query.get('token')) return fail(401, '缺少 ticket/token 查询参数')
    if (ticketRaw) {
      // Canal ticket : authentification + point de permission + validation de périmètre départemental déjà faits à l'émission, ici simple consommation unique (brûlé à l'échange)
      const key = createHash('sha256').update(ticketRaw).digest('hex')
      const entry = streamTickets.get(key)
      if (!entry || entry.expiresAt < Date.now()) {
        streamTickets.delete(key)
        return fail(401, 'ticket 无效或已过期，请重新获取')
      }
      streamTickets.delete(key)
      const queryDept = dept
      dept = entry.dept
      if (queryDept && queryDept !== dept) return fail(400, `dept 查询参数与 ticket 签发部门不一致：${queryDept} ≠ ${dept}`)
      exchange.principal = entry.principal
      if (!requirePermission(exchange, 'panel.read')) return
    } else {
      const token = exchange.query.get('token') ?? ''
      if (!token) return fail(401, '缺少 token 查询参数')
      if (!DEPT_RE.test(dept)) return fail(400, `部门标识非法：${dept}`)
      const authn = soft(ctx, 'authn')
      if (!authn) return fail(401, '认证中心未接入（01门演示态）——连接宿主后可订阅实时流')
      try {
        const verified = authn.verify(token)
        // Forme du principal identique au middleware d'authentification console (human → userId=refId) : le jugement
        // de sous-arbre d'organisation de deptScopeAllowed dépend du userId ; sans lui, tout utilisateur humain serait jugé à tort sans rattachement.
        exchange.principal = {
          kind: verified.principal.type,
          principalId: verified.principal.id,
          ...(verified.principal.type === 'human' && verified.principal.refId ? { userId: verified.principal.refId } : {}),
          ...(verified.principal.type === 'machine' ? { refType: verified.principal.refType, refId: verified.principal.refId } : {}),
          name: verified.principal.name,
          permissions: verified.scopes,
          actChain: verified.actChain,
        }
      } catch (error) {
        return fail(401, `令牌无效：${error instanceof Error ? error.message : String(error)}`)
      }
      if (!requirePermission(exchange, 'panel.read')) return
    }
        // Validation de périmètre départemental (QA 2026-09-08 BUG-A-01/T-01, mêmes règles pour les deux canaux) : exécutée à la poignée de main stream, au même référentiel que deptOf
    // de la face REST — cet endpoint avait échappé au réseau d'assertions RBAC via l'auto-vérification ?token=, un utilisateur à organisation restreinte recevait
    // en direct les messages du département restreint ; désormais la poignée de main coupe immédiatement, jamais d'abonnement d'abord.
    const deptConfig = (() => {
      try { return panel.dept(dept) } catch { return undefined }
    })()
    if (!deptConfig) return fail(404, `部门不存在：${dept}`)
    if (!panel.deptScopeAllowed(caller(exchange), deptConfig)) {
      exchange.fail(403, 'FORBIDDEN', `部门范围受限：${deptConfig.label} 已绑定组织治理，仅该组织子树成员可访问`, { permission: 'panel.read', deptScope: deptConfig.orgId })
      return
    }
    const res = exchange.res
    if (res.headersSent) return
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    })
    res.write('retry: 5000\n\n')
    // Nom d'événement dans data (EventSource.onmessage ne reçoit que l'événement par défaut ; le front répartit selon payload.name)
    const unsubscribe = panel.subscribeStream(dept, (event) => {
      try {
        res.write(`data: ${JSON.stringify({ name: event.name, payload: event.payload })}\n\n`)
      } catch { /* connexion déjà fermée, cleanup en rattrapage */ }
    })
    const heartbeat: ReturnType<typeof setInterval> = setInterval(() => {
      try { res.write(': ping\n\n') } catch { /* ignore */ }
    }, 25_000)
    exchange.raw.on('close', () => {
      clearInterval(heartbeat)
      unsubscribe()
    })
  }, { access: 'public', selfValidated: true })

  // -- Exécuteur d'approbation d'activation de secteur (approbation accordée → pose active + grantCapabilities + événement) ----------------

  // Centre d'approbations absent (état démo porte 01) → pas d'exécuteur enregistré (fonction de désactivation no-op idempotente)
  const offExecutor = soft(ctx, 'audit')?.registerExecutor('industry.activation', panel.buildActivationExecutor()) ?? (() => {})

  // Éventail d'événements (source de données SSE) + couplage du reçu du pont (ré-écriture de l'état ddSync)
  panel.wireEventBus()
  const offDelivered = ctx.platformBus.on(PlatformEvents.DingtalkDelivered, (payload) => {
    const { messageId, ok, error } = (payload ?? {}) as { messageId?: string; ok?: boolean; error?: string }
    if (!messageId) return
    const message = panel.messages().get(messageId)
    if (!message) return
    // Livraison réussie : état terminal sent ; failed→sent doit être atteignable (QA BUG-A-02 : après échec puis re-livraison réussie, l'interface affichait encore l'échec)
    if (ok) {
      if (message.ddSync !== 'sent') panel.messages().update(messageId, { ddSync: 'sent' })
      return
    }
    // Échec de livraison : seul pending passe à failed (failed est déjà terminal, les échecs répétés ne clignotent pas) ; l'alerte n'est tracée qu'au premier échec
    if (message.ddSync !== 'pending') return
    panel.messages().update(messageId, { ddSync: 'failed' })
    if (error) {
      soft(ctx, 'audit')?.fire({ severity: 'warning', title: '钉钉桥接投递失败', message: `消息 ${messageId} 投递失败：${error}`, resourceType: 'panel_message', resourceId: messageId })
    }
  })

  ctx.effect(() => () => {
    offExecutor()
    offDelivered()
  })

  // -- Bouclages de l'état installé porte 01 (trio canal d'écriture/modèles/DingTalk 2026-09-11) -----------------------------------
  // Le loader dsh charge en concurrence les patch entry (app-boot §mountRootInclude) — « lecture souple des services frères à l'apply »
  // est une écriture en course ; toute cette section devient indépendante de l'ordre :
  //   a. la face connexion est enregistrée inconditionnellement dans l'espace de noms propre du panneau (/api/panel/auth/*, sans conflit avec /api/auth/*
  //      de console) ; authn absent = 503 honnête à la requête — console/authn présents ou non, le comportement est correct ;
  //   b. le pont CLI dws est monté sur /api/panel/ddws/* (de même sans toucher /api/dingtalk/*) ; le crochet de livraison ddSync ne re-vérifie
  //      dingtalkBridge qu'au moment de l'événement, cédant la place si le pont est présent, excluant la double livraison ;
  //   c. graine de l'admin de base à retry différée (semis dès publication d'iam, saut idempotent si orgs non vide ; double exécution sûre avec la graine console).

  /** Face connexion dans l'espace de noms du panneau : authn présent = transfert (forme de la réponse identique champ à champ à console, zéro cas particulier front). */
  const loginViaAuthn = () => {
    const authn = soft(ctx, 'authn')
    const iam = soft(ctx, 'iam')
    if (!authn || !iam) return undefined
    return {
      login: (username: string, password: string) => {
        const result = authn.login(username, password)
        const user = iam.users().get(result.userId)!
        return {
          token: result.token,
          refreshToken: result.refreshToken,
          expiresAt: result.record.expiresAt,
          user: {
            id: user.id, username: user.username, displayName: user.displayName,
            orgId: user.orgId, roleIds: user.roleIds,
            roles: user.roleIds.map((roleId: string) => iam.roles().get(roleId)?.name).filter(Boolean),
            permissions: iam.userPermissions(user.id),
          },
        }
      },
      refresh: (refreshToken: string) => authn.refreshSession(refreshToken),
    }
  }
  http.register('POST', '/api/panel/auth/login', (exchange) => {
    const backend = loginViaAuthn()
    if (!backend) {
      exchange.fail(503, 'AUTHN_UNAVAILABLE', '认证面未就绪（本机形态未装配认证中心）——请从宿主/控制台登录')
      return
    }
    const { username, password } = body<{ username?: string; password?: string }>(exchange)
    if (!username || !password) {
      exchange.fail(400, 'BAD_REQUEST', '用户名与密码必填')
      return
    }
    try {
      exchange.ok(backend.login(username, password))
    } catch (error) {
      exchange.fail(401, 'LOGIN_FAILED', error instanceof Error ? error.message : String(error))
    }
  }, { access: 'public' })
  http.register('POST', '/api/panel/auth/refresh', (exchange) => {
    const backend = loginViaAuthn()
    if (!backend) {
      exchange.fail(503, 'AUTHN_UNAVAILABLE', '认证面未就绪（本机形态未装配认证中心）')
      return
    }
    const { refreshToken } = body<{ refreshToken?: string }>(exchange)
    if (!refreshToken) {
      exchange.fail(400, 'BAD_REQUEST', 'refreshToken 必填')
      return
    }
    try {
      const result = backend.refresh(refreshToken)
      exchange.ok({ token: result.token, refreshToken: result.refreshToken })
    } catch (error) {
      exchange.fail(401, 'REFRESH_FAILED', error instanceof Error ? error.message : String(error))
    }
  }, { access: 'public' })

  const dingtalkBridgePresent = Boolean(soft(ctx, 'dingtalkBridge'))
  // -- Face DingTalk locale porte 01 (CLI dws) — enregistrée inconditionnellement (depuis 2026-09-11, plus de préalable « pont absent ») --------------
  // Ligne d'airain d'espace de noms inchangée : toute la face dws pend sous /api/panel/ddws/* (jamais /api/dingtalk/*, qui est
  // la face de routes de plugin-dingtalk-bridge). Quand le pont hôte est présent, cette face coexiste comme « connexion DingTalk locale directe » — l'utilisateur peut,
  // sans passer par la plateforme hôte (connecteur/scan iam), utiliser directement son DingTalk via dws ; l'appartenance de la livraison de message est arbitrée au moment de l'événement (voir le crochet ci-dessous).
  {
    const dws = new DwsCli(ctx)
    guarded('GET', '/api/panel/ddws/status', 'panel.read', async () => {
      const status = await dws.status()
      return {
        ...status,
        via: 'dws-cli',
        // Compatibilité de forme (consommée par app.js renderTopRight) : bound=false | {displayName,...}
        bound: status.bound && status.group ? { displayName: status.group, via: 'dws-cli' } : false,
        connector: { configured: status.installed, name: `dws CLI${status.version ? ` ${status.version}` : ''}`, mode: status.installed ? 'real' : 'mock' },
      }
    })
    guarded('POST', '/api/panel/ddws/install', 'panel.config.write', async () => dws.install())
    // Face connexion-autorisation (besoin utilisateur 2026-09-11 : sans liaison avec la plateforme hôte, le panneau initie localement la connexion dws) :
    // POST lance la connexion par flux d'appareil (renvoie l'instruction d'activation : lien d'autorisation + code utilisateur, pop-up front directe) ;
    // GET scrute l'état de la session (scrutin front 3 s, autorisation faite = authenticated:true) ;
    // DELETE annule la connexion en cours. L'état d'autorisation appartient au CLI dws lui-même (ligne d'airain : ce panneau est sans identifiants).
    guarded('POST', '/api/panel/ddws/login', 'panel.config.write', async () => dws.startLogin())
    guarded('GET', '/api/panel/ddws/login', 'panel.read', async () => dws.loginState())
    guarded('DELETE', '/api/panel/ddws/login', 'panel.config.write', () => {
      dws.cancelLogin()
      return { cancelled: true }
    })
    guarded('PUT', '/api/panel/ddws/bind', 'panel.config.write', (exchange) => {
      const group = body<{ group?: string }>(exchange).group?.trim() ?? ''
      const record = dws.bind(group, caller(exchange).userId ?? caller(exchange).principalId)
      return { bound: true, group: record.group }
    })
    guarded('DELETE', '/api/panel/ddws/bind', 'panel.config.write', () => {
      dws.unbind()
      return { bound: false }
    })
    guarded('POST', '/api/panel/ddws/test', 'panel.write', async (exchange) => {
      const text = body<{ text?: string }>(exchange).text?.trim() || '01门面板 dws 连通性测试'
      try {
        const sent = await dws.sendToGroup(text)
        return { ok: true, group: sent.group }
      } catch (error) {
        return { ok: false, error: error instanceof Error ? error.message : String(error) }
      }
    })
    // Tirage entrant (besoin utilisateur 2026-09-11 « tirer automatiquement les derniers messages ») : dws +chat-messages lit les derniers messages du groupe lié,
    // déduplication idempotente par messageId à l'inscription dans le canal courant (senderType=human + ddSync='origin' + uniqueKey comme clé de déduplication).
    // Un échec de tirage répond ok:false + error (HTTP 200, la dégradation est une donnée, pas une erreur de transport), le front peut réessayer.
    // L'orientation département remonte du canal (le front ne passe que channelId ; correctif du portage : l'implémentation d'origine résolvait via le paramètre
    // de chemin :dept, et sous le chemin aplati /api/panel/ddws/pull, params.dept toujours vide = 400 inévitable — corrigé à l'intégration).
    guarded('POST', '/api/panel/ddws/pull', 'panel.write', async (exchange) => {
      const input = body<{ channelId?: string; limit?: number }>(exchange)
      if (!input.channelId?.trim()) throw new Error('channelId 必填（拉取落入的目标频道）')
      const channel = panel.channels().get(input.channelId)
      if (!channel) throw new Error(`频道不存在：${input.channelId}`)
      const dept = panel.dept(channel.dept)
      if (!panel.deptScopeAllowed(caller(exchange), dept)) {
        exchange.fail(403, 'FORBIDDEN', `部门范围受限：${dept.label} 已绑定组织治理，仅该组织子树成员可访问`, { permission: 'panel.read', deptScope: dept.orgId })
        return
      }
      const channelId = channel.id
      const info = caller(exchange)
      try {
        const incoming = await dws.pullLatestMessages(Math.floor(Number(input.limit) || 20))
        let inserted = 0
        for (const item of incoming) {
          const uniqueKey = `dws:${item.messageId}`
          if (panel.messages().findOne((m) => m.channelId === channelId && m.uniqueKey === uniqueKey)) continue
          await panel.sendMessage({
            dept: dept.id, channelId, senderType: 'human',
            senderId: info.userId, senderName: `${item.sender} · 钉钉`,
            text: item.text, ddSync: false, sceneCode: undefined,
            uniqueKey,
          })
          inserted += 1
        }
        return { ok: true, inserted, fetched: incoming.length, group: channel.name }
      } catch (error) {
        return { ok: false as const, inserted: 0, error: error instanceof Error ? error.message : String(error) }
      }
    })
    // Crochet sortant ddSync des messages (appartenance de la livraison arbitrée au moment de l'événement — l'ordre d'assemblage n'est pas fiable, la sonde à l'apply ne compte pas) :
    //   a. pont hôte présent avec pont de groupe channel → le pont prend tout en charge (ce crochet cède : le pont se vérifie avant deliver, excluant la double livraison) ;
    //   b. sinon ce crochet assume : groupe dws lié → livraison dws ; pas de groupe lié → reçu d'échec honnête (la sémantique QA T-04 « reçu même sans pont de groupe »
    //      est reprise par ce crochet — le pont DingTalk sans pont de groupe channel n'émet plus de lui-même ok:false, voir son service.ts).
    ctx.platformBus.on(PlatformEvents.PanelMessageCreated, (payload) => {
      const data = (payload ?? {}) as { messageId?: string; ddSync?: string; text?: string }
      if (!data.messageId || data.ddSync !== 'pending') return
      const bridgeSvc = soft(ctx, 'dingtalkBridge') as { bridgeChannels?: () => { find: (fn: (item: { purpose: string }) => boolean) => Array<{ purpose: string }> } } | undefined
      if (bridgeSvc?.bridgeChannels?.().find((item) => item.purpose === 'channel').length > 0) return
      void dws.sendToGroup(String(data.text ?? '')).then(
        (sent) => ctx.platformBus.emit(PlatformEvents.DingtalkDelivered, { messageId: data.messageId, ok: true, via: 'dws-cli', group: sent.group }),
        (error) => ctx.platformBus.emit(PlatformEvents.DingtalkDelivered, {
          messageId: data.messageId, ok: false,
          error: error instanceof Error ? error.message : String(error),
        }),
      )
    })
    ctx.logger('panel-core').info(`01门本地钉钉面已挂载：dws CLI 桥（/api/panel/ddws/*，宿主桥${dingtalkBridgePresent ? '在场共存' : '缺席独任'}；ddSync 投递按群桥归属裁决）`)
  }

  // Graine de l'admin de base (retry différée, uniquement en état installé porte 01) : iam présent et catalogue d'organisations vide (premier démarrage porte 01+authn) →
  // initialisation au même référentiel que la graine console. Sous chargement concurrent du loader, iam peut publier après cette extension ; scrutin d'attente
  // jusqu'à disponibilité (plafond 30 s). Quand console est présent (forme complète), la graine console est responsable — la présente graine est sous porte demoAuth
  // (replanté du socle 2026-10-29) : en forme complète, l'assemblage du panneau et de console, bien que séquentiel, pourrait voir la graine console s'exécuter
  // en différé ; une course de doubles graines ferait dépendre nom d'organisation/politique de mot de passe de l'ordre de chargement — ligne d'airain unifiée : en forme complète, le droit de graine appartient à console.
  if (demoAuth) {
    let seedTries = 0
    const seedTimer = setInterval(() => {
      seedTries += 1
      const iamNow = soft(ctx, 'iam')
      if (!iamNow) {
        if (seedTries >= 60) {
          clearInterval(seedTimer)
          ctx.logger('panel-core').info('iam 未就绪，跳过 01门基线管理员种子（纯演示态）')
        }
        return
      }
      clearInterval(seedTimer)
      if (iamNow.orgs().count() > 0) return
      try {
        iamNow.ensureBuiltinRoles()
        const root = iamNow.createOrg({ name: process.env.ORG_NAME ?? '元冰可集团' })
        const roleSuper = iamNow.roles().findOne((role: { code: string }) => role.code === 'super_admin')!
        const { user, initialPassword } = iamNow.createUser({
          username: 'admin',
          displayName: '平台管理员',
          orgId: root.id,
          title: '平台管理员',
          roleIds: [roleSuper.id],
          password: process.env.ADMIN_PASSWORD,
        })
        iamNow.users().update(user.id, { status: 'active' })
        void user
        if (initialPassword) {
          const file = join(ctx.opsStorage.dataDirPath, 'admin-initial-password.txt')
          if (!existsSync(file)) {
            writeFileSync(file, `平台管理员 admin 的初始口令（仅生成一次；首次登录后请妥善保管并删除本文件）：\n${initialPassword}\n`, 'utf8')
          }
        }
        ctx.logger('panel-core').info('01门装态基线种子完成：内置角色 + 根组织 + 平台管理员 admin（初始口令见 data/admin-initial-password.txt）')
      } catch (error) {
        ctx.logger('panel-core').warn(`01门装态基线种子失败（不阻断装配）：${error instanceof Error ? error.message : String(error)}`)
      }
    }, 500)
    ctx.effect(() => () => clearInterval(seedTimer))
  }

  // -- Hébergement statique (/panel → exposé /gate01/panel/) ----------------------------------------

  const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public')
  if (existsSync(publicDir)) {
    // Normalisation de l'atterrissage en état installé porte 01 (config.landingRedirect, correctif de l'écran blanc MIME constaté par l'utilisateur 2026-09-11) : sans console
    // à l'assemblage, la racine n'a pas de console où atterrir — 302 vers le panneau, excluant que le repli SPA envoie au navigateur « la page coquille sans ressources ».
    if (config.landingRedirect) {
      http.register('GET', '/', (exchange) => {
        exchange.res.writeHead(302, { location: `${http.externalBase}/panel/` }).end()
      })
    }
    // Normalisation en forme répertoire : /panel (sans barre de queue) sert index.html puis les ressources relatives ./js/* se résoudraient en /js/* (404→repli SPA→écran blanc),
    // même sémantique que le 302 /gate01→/gate01/ de dsh-bridge ; Location porte externalBase (forme montée = /gate01/panel/).
    // Note : les routes s'apparient par split('/').filter(Boolean), /panel et /panel/ atteignent le même nœud de route —
    // une requête avec barre de queue doit servir index.html sur place, jamais 302 (boucle auto-référente).
    http.register('GET', '/panel', (exchange) => {
      if (exchange.path.endsWith('/')) {
        exchange.file(join(publicDir, 'index.html'))
        return
      }
      exchange.res.writeHead(302, { location: `${http.externalBase}/panel/` }).end()
    })
    http.serveStatic('/panel', publicDir, '/index.html')
  }

  // -- Graines (squelettes de base + contenu de démo DEMO_SEED=1) ---------------------------------------

  // Semis du contenu de démo : démo automatique en état installé demoAuth (décision 2), la forme complète garde la porte explicite DEMO_SEED=1
  void seedPanel(ctx, panel, demoAuth)

  // -- Famille d'outils panel_* (clé tools partagée, sous dsh ToolRuntime natif) ------------------------

  const renderJson = (args: unknown, value: unknown) => [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }]

  ctx.tools.register({
    name: 'panel_agents_list',
    description: '列出部门面板的 Agent 阵容（名称/职责/绑定资产），用于选择协作对象',
    permission: 'panel.read',
    parameters: { type: 'object', properties: { dept: { type: 'string', description: '部门标识（rd/mfg/sales/strategy/fin），缺省列出全部部门' } } },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args) {
      const dept = (args as { dept?: string }).dept
      const configs = dept ? [panel.dept(dept)] : panel.deptConfigs().all()
      return configs.map((config) => ({ dept: config.id, label: config.label, agents: config.agents }))
    },
  })

  ctx.tools.register({
    name: 'panel_msg_send',
    description: '向部门协作频道发消息（可选 --sync-dingtalk 语义：sync_dingtalk=true 时经钉钉桥接同步到群）',
    permission: 'panel.write',
    parameters: {
      type: 'object',
      properties: {
        dept: { type: 'string', description: '部门标识' },
        channel_id: { type: 'string', description: '频道 id，缺省取部门首个频道' },
        text: { type: 'string', description: '消息文本（支持 @Agent名 唤起）' },
        sync_dingtalk: { type: 'boolean', description: '是否同步到钉钉群（需已绑定群桥）' },
      },
      required: ['dept', 'text'],
    },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args, exec) {
      const input = args as { dept: string; channel_id?: string; text: string; sync_dingtalk?: boolean }
      const channelId = input.channel_id || panel.channels().find((item) => item.dept === input.dept).at(0)?.id
      if (!channelId) throw new Error(`部门 ${input.dept} 暂无频道`)
      const message = await panel.sendMessage({
        dept: input.dept, channelId, senderType: 'human',
        senderId: exec.principal?.userId, senderName: exec.principal?.name ?? '工具调用',
        text: input.text, ddSync: input.sync_dingtalk === true,
      })
      return { messageId: message.id, ddSync: message.ddSync }
    },
  })

  ctx.tools.register({
    name: 'panel_task_create',
    description: '在部门任务看板创建任务卡（泳道 todo/doing/review/done，缺省 todo）',
    permission: 'panel.task.write',
    parameters: {
      type: 'object',
      properties: {
        dept: { type: 'string', description: '部门标识' },
        title: { type: 'string', description: '任务标题' },
        detail: { type: 'string', description: '任务详情' },
        lane: { type: 'string', enum: ['todo', 'doing', 'review', 'done'], description: '目标泳道' },
        scene_code: { type: 'string', description: '关联场景图谱编号（如 QB01-A-2-5）' },
      },
      required: ['dept', 'title'],
    },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args, exec) {
      const input = args as { dept: string; title: string; detail?: string; lane?: TaskLane; scene_code?: string }
      const task = panel.createTask({
        dept: input.dept, title: input.title, ...(input.detail ? { detail: input.detail } : {}),
        ...(input.lane ? { lane: input.lane } : {}), ...(input.scene_code ? { sceneCode: input.scene_code } : {}),
        createdBy: exec.principal?.userId ?? exec.principal?.principalId ?? 'tool',
      })
      return { taskId: task.id, lane: task.lane }
    },
  })

  ctx.tools.register({
    name: 'panel_task_transition',
    description: '迁移部门任务到指定泳道（todo/doing/review/done）',
    permission: 'panel.task.write',
    parameters: {
      type: 'object',
      properties: { task_id: { type: 'string', description: '任务 id' }, lane: { type: 'string', enum: ['todo', 'doing', 'review', 'done'], description: '目标泳道' } },
      required: ['task_id', 'lane'],
    },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args, exec) {
      const input = args as { task_id: string; lane: TaskLane }
      const task = panel.transitionTask(input.task_id, input.lane, exec.principal?.userId ?? 'tool')
      return { taskId: task.id, lane: task.lane }
    },
  })

  ctx.tools.register({
    name: 'panel_scene_diag',
    description: '对行业场景图谱中的场景发起数字化诊断（生成诊断任务并进入协作会话）',
    permission: 'panel.write',
    parameters: {
      type: 'object',
      properties: { dept: { type: 'string', description: '部门标识' }, scene_code: { type: 'string', description: '场景编号（如 QB01-A-2-5）' } },
      required: ['dept', 'scene_code'],
    },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args, exec) {
      const input = args as { dept: string; scene_code: string }
      const result = await panel.diagnose({
        dept: input.dept, sceneCode: input.scene_code,
        actorId: exec.principal?.userId ?? 'tool', actorName: exec.principal?.name ?? '工具调用',
      })
      return { messageId: result.message.id, taskId: result.task.id }
    },
  })

  ctx.tools.register({
    name: 'panel_widget_data',
    description: '读取部门看板 widget 数据（含来源徽标与降级标记）',
    permission: 'panel.read',
    parameters: {
      type: 'object',
      properties: { dept: { type: 'string', description: '部门标识' }, widget_id: { type: 'string', description: 'widget id，缺省返回全部' } },
      required: ['dept'],
    },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args) {
      const input = args as { dept: string; widget_id?: string }
      const dept = panel.dept(input.dept)
      const widgets = panel.board(dept)
      return input.widget_id ? widgets.filter((widget) => widget.id === input.widget_id) : widgets
    },
  })

  // -- Contrat J1 v1 : le dialogue standard dsh appelle nominativement la ligne-up d'Agents du panneau et les Skills publiés (canal principal de collaboration avec les autres Agents) --
  ctx.tools.register({
    name: 'panel_agent_invoke',
    description: '点名调用部门面板的某个 Agent 提问并同步取回应答（dsh 标准对话协作主通道）：按部门名册全名匹配，'
      + '经面板 Agent 资产（agentRef/model/systemPrompt）+ 行业场景摘要组装上下文，单轮调用模型网关。'
      + '应答不落频道消息；如需留痕请配合 panel_msg_send。失败诚实返回 ok:false（不造假回复）。',
    permission: 'panel.write',
    parameters: {
      type: 'object',
      properties: {
        dept: { type: 'string', description: '部门标识（rd/mfg/sales/strategy/fin）' },
        agent: { type: 'string', description: 'Agent 名册全名（可用 panel_agents_list 查询，如「质量分析 Agent」）' },
        message: { type: 'string', description: '要问该 Agent 的问题/指令' },
        context_note: { type: 'string', description: '附加上下文说明（可选，拼入系统提示）' },
      },
      required: ['dept', 'agent', 'message'],
    },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args, exec) {
      const input = args as { dept: string; agent: string; message: string; context_note?: string }
      return await panel.askAgent(input.dept, input.agent, input.message, {
        userId: exec.principal?.userId,
        ...(input.context_note ? { contextNote: input.context_note } : {}),
      })
    },
  })

  ctx.tools.register({
    name: 'panel_skill_invoke',
    description: '点名调用技能平台上架的某个 Skill 并同步取回执行结果（面板对话框 /技能名 直调的同一服务原语）：'
      + '按技能名或 slug 全名匹配（须为已上架且对调用人组织开放的技能），取当前版本指令内容组装上下文，单轮调用模型网关。'
      + '失败诚实返回 ok:false + 原因（不存在/未上架/不可见/无内容/网关失败），不造假回复。',
    permission: 'panel.write',
    parameters: {
      type: 'object',
      properties: {
        skill: { type: 'string', description: '技能名或 slug（已上架 published 技能）' },
        message: { type: 'string', description: '要交给技能的输入/问题' },
        context_note: { type: 'string', description: '附加上下文说明（可选，拼入系统提示）' },
      },
      required: ['skill', 'message'],
    },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args, exec) {
      const input = args as { skill: string; message: string; context_note?: string }
      return await panel.invokeSkill(input.skill, input.message, {
        userId: exec.principal?.userId,
        ...(input.context_note ? { contextNote: input.context_note } : {}),
      })
    },
  })

  // -- Ouverture du dialogue M3 : résumé agrégé du tableau de bord stratégique (lecture légère ancrée dans la conversation) --
  ctx.tools.register({
    name: 'panel_board_digest',
    description: '读取战略看板聚合摘要（近 7 天）：资产在线数、调用漏斗（曝光→点击→调用→完成）、计量与 ROI 估算、'
      + '指定平台卡片包标题清单。给对话/Agent 做看板接地的事实源（完整数据走 GET /api/panel/board）。',
    permission: 'panel.read',
    parameters: {
      type: 'object',
      properties: { platform: { type: 'string', description: `卡片包平台（${CARD_PLATFORMS.join('/')}），缺省 rd` } },
    },
    output: { schema: { type: 'object' }, render: renderJson },
    async execute(args, exec) {
      const input = args as { platform?: string }
      const available = [...new Set(cardpacks.all().map((pack) => pack.platform))]
      const requested = input.platform ?? process.env.RQ_PLATFORM ?? (available.includes('rd') ? 'rd' : available[0]) ?? 'strategy'
      if (!CARD_PLATFORMS.includes(requested as CardPlatform)) {
        throw new Error(`platform 非法（应为 ${CARD_PLATFORMS.join('/')}）`)
      }
      const platform = requested as CardPlatform
      const info = exec.principal as { userId?: string } | undefined
      const iam = soft(ctx, 'iam')
      const user = info?.userId ? iam?.users().get(info.userId) : undefined
      const roles = user ? user.roleIds.map((roleId) => iam?.roles().get(roleId)?.code).filter((code): code is string => Boolean(code)) : []
      cardpacks.setRefAliveResolver(refAlive)
      const packs = cardpacks.forPlatform(platform)
      const { cards } = filterCards({ packs, roles, refAlive })

      const weekAgo = new Date(Date.now() - 7 * 24 * 3600_000).toISOString()
      const behaviorCount = (type: string): number => {
        return soft(ctx, 'behavior')?.query({ type, from: weekAgo }).total ?? 0
      }
      const usageTotals = soft(ctx, 'usage')?.totals({ from: weekAgo })
      const usageCount = usageTotals?.count ?? 0
      const chargeCents = usageTotals?.charge_cents ?? 0
      const completedCalls = soft(ctx, 'mcpRegistry')?.calls().all().filter((call) => call.ok && call.at >= weekAgo).length ?? 0
      const minutesPerCall = Number(process.env.ROI_MINUTES_PER_CALL ?? 3)
      const callBase = completedCalls > 0 ? completedCalls : usageCount
      return {
        generatedAt: new Date().toISOString(),
        windowDays: 7,
        platform,
        assets: {
          appsOnline: soft(ctx, 'resourceCore')?.list('app').filter((item) => item.status === 'online').length ?? 0,
          agentsOnline: soft(ctx, 'resourceCore')?.list('agent').filter((item) => item.status === 'online').length ?? 0,
          skillsPublished: soft(ctx, 'skillHub')?.skills().all().filter((item) => item.status === 'published').length ?? 0,
          mcpServing: soft(ctx, 'mcpRegistry')?.services().all().filter((service) => service.status === 'online' || service.status === 'gray').length ?? 0,
        },
        funnel: {
          exposed: behaviorCount('card.exposed'),
          clicked: behaviorCount('card.clicked'),
          invoked: usageCount,
          completed: completedCalls,
        },
        waic: { count: usageCount, chargeCents },
        roiEstimate: {
          callBase,
          estimatedHoursSaved: Math.round((callBase * minutesPerCall / 60) * 100) / 100,
          note: '估算口径（非实测）：替代工时 = 调用次数 × 单次替代分钟 ÷ 60',
        },
        cards: cards.map((card) => ({ id: card.id, title: card.title, badge: card.badge })),
      }
    },
  })

  // -- Boîte à outils manufacture (intégrée depuis « jeu d'outils IA manufacture », 2026-10-19) --------------------------
  // 13 noyaux de calcul déterministes + 3 outils IA (régime de libération des Skills) + liste des 100 sujets.
  // Routes : /api/panel/mfg/* (lecture panel.read / exécution panel.write / libération panel.config.write) ;
  // outils : panel_mfg_* (clé tools partagée → sous dsh, ToolRuntime natif).
  // Face modèle via la passerelle de la plateforme (modelgw / pont llm dsh), panneau sans clé ; sans passerelle, les outils IA répondent honnêtement 503.
  applyMfgModule(ctx, { guarded, changeLog, renderJson })
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    panel: PanelService
  }
}
