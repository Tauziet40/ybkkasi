/**
 * @dsh-ops/plugin-connect — extension d'accès distant (un même code, deux rôles).
 *
 * - role=host (par défaut pour l'hôte autonome) : fournit les endpoints et outils côté gestion
 *   des codes d'accès / enroll / gestion des clients,
 *   permettant à un runtime dsh distant (forme installée via le marché de plugins) de demander
 *   des identifiants machine à cette plateforme.
 * - role=client (forme installée via dsh.bundle) : demande à l'hôte et conserve les identifiants machine ;
 *   une fois configuré, l'exécution de tous les outils d'exploitation de la plateforme est automatiquement
 *   transférée à l'hôte (exécution locale maintenue tant que non configuré, rétrocompatible ;
 *   depuis OPT-P1-03 le proxy s'appuie sur les points d'extension officiels tools.intercept/decorate,
 *   échec de transfert = fail-closed avec alerte explicite) ;
 *   démarre aussi une page de configuration accessible uniquement depuis la machine locale
 *   (par défaut http://127.0.0.1:7390) pour saisir/mettre à jour la configuration à la main,
 *   et expose les outils connect_* au modèle, permettant à l'Agent d'accomplir en langage naturel
 *   « demander des identifiants / modifier la configuration / se déconnecter ».
 */
import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '../../platform-core/src/index.ts'
import { t as translate } from '../../platform-i18n/src/index.ts'
import { ConnectClientService, isProxiedTool } from './client.ts'
import { ConnectConfigServer } from './config-page.ts'
import { connectHostApi, connectHostTools } from './host.ts'

export * from './client.ts'
export * from './config-page.ts'
export * from './host.ts'

export interface ConnectConfig {
  /** host = côté hôte (endpoints de gestion) ; client = côté dsh distant (demande d'identifiants + proxy distant d'outils). */
  role?: 'host' | 'client'
  /** Répertoire du fichier de configuration client (par défaut, même répertoire que le stockage local). */
  dataDir?: string
  /** Écoute de la page de configuration locale du client (par défaut 127.0.0.1:7390 ; host=0.0.0.0 pour un accès LAN). */
  configServer?: { port?: number; host?: string }
  /** Intervalle de battement de cœur en minutes (par défaut 5 ; 0 = désactive l'envoi des battements). */
  heartbeatIntervalMinutes?: number
}

export const name = 'connect'
export const inject = ['tools', 'httpServer', 'opsStorage', 'platformBus']

export function apply(ctx: Context, config: ConnectConfig = {}) {
  if (config.role === 'client') {
    applyClient(ctx, config)
    return
  }
  // Rôle host : endpoints de gestion (une fois authn/iam/audit prêts) + outils de gestion des accès côté hôte
  ctx.plugin(connectHostApi)
  ctx.plugin(connectHostTools)
}

// ---------------------------------------------------------------------------
// Rôle client
// ---------------------------------------------------------------------------

function applyClient(ctx: Context, config: ConnectConfig): void {
  const client = new ConnectClientService(ctx, { dataDir: config.dataDir })

  // Proxy distant des outils (OPT-P1-03) : accroché sur les points d'extension officiels tools.intercept/decorate (plus de monkey-patch de prototype),
  // les outils métier (préfixe autre que connect_) sont transférés à l'hôte /api/tools/execute une fois connecté ;
  // échec de transfert = erreur explicite + événement connect.degraded (fail-closed), jamais de repli local silencieux.
  // L'installation doit rester antérieure à l'enregistrement des plugins métier (interception des nouveaux enregistrements à l'entrée), les outils préexistants sont couverts par decorate.
  const proxied = installToolProxy(ctx, client)

  // Page de configuration locale (accessible uniquement depuis la machine ; entrée de configuration visuelle de l'utilisateur en dehors de l'interface dsh)
  const server = new ConnectConfigServer(ctx, client, config.configServer ?? {})
  void server.start().then(() => {
    ctx.logger('connect').info(
      `接入配置页已就绪：http://${server.host}:${server.port}${proxied ? '（当前工具为本地执行，接入后自动切换远程）' : '（远程转发不可用：运行时缺少工具扩展点，已显式降级本地，connect_status 可查）'}`,
    )
  }, (error: unknown) => {
    ctx.logger('connect').error(`接入配置页启动失败（端口 ${server.port}）：`, error)
  })

  // -- Envoi des battements de cœur : une fois connecté, remonte périodiquement à l'hôte l'état de vie et les métadonnées d'exécution (supervision des accès côté hôte) ------
  // Un tour toutes les 5 minutes par défaut, heartbeatIntervalMinutes=0 désactive ; silencieusement ignoré tant que non connecté, un échec ne fait que renseigner lastError.
  const heartbeatMinutes = config.heartbeatIntervalMinutes ?? 5
  if (heartbeatMinutes > 0) {
    const bootAt = Date.now()
    const beat = (): void => {
      if (!client.hasHub()) return
      let tools = 0
      try { tools = ctx.tools.schemas?.().length ?? 0 } catch { /* repli à 0 en cas d'écart d'interface du runtime dsh natif */ }
      void client.heartbeat({ tools, version: process.version, uptimeSec: Math.floor((Date.now() - bootAt) / 1000) })
        .catch((error: unknown) => client.noteError(`heartbeat: ${error instanceof Error ? error.message : String(error)}`))
    }
    const timer = setInterval(beat, heartbeatMinutes * 60_000)
    timer.unref?.()
    const first = setTimeout(beat, 10_000) // premier envoi dans les 10 s suivant la configuration de l'accès, visible immédiatement côté hôte
    first.unref?.()
    // cordis ctx.effect(fn) : fn renvoie une fonction de nettoyage, il faut une double flèche (sinon exécution dès l'enregistrement)
    ctx.effect(() => () => { clearInterval(timer); clearTimeout(first) })
  }

  // -- Outils Agent : une fois l'extension installée, l'Agent peut demander des identifiants et mettre à jour la configuration en langage naturel ----
  const t = ctx.tools
  t.register(defineTool({
    name: 'connect_status',
    description: '查看当前与宿主平台的接入状态（是否已配置、宿主可达性、机器令牌状态、工具执行模式 local/remote、最近错误）。',
    permission: 'console.login',
    parameters: {},
    output: { type: 'object', additionalProperties: true },
    async execute() {
      return await client.status()
    },
  }))

  t.register(defineTool({
    name: 'connect_setup',
    description: '向宿主平台申请口令并完成接入（安装插件后第一步）：用管理员签发的一次性接入码换取长期机器凭证并保存到本机。成功后平台运维工具自动切换为远程执行。',
    parameters: {
      hubUrl: { type: 'string', required: true, description: '宿主平台服务地址，如 http://192.168.1.5:7300' },
      enrollmentCode: { type: 'string', required: true, description: '宿主管理员在控制台「平台接入」创建的一次性接入码（enr_ 开头）' },
      clientName: { type: 'string', description: '本机名称（默认 dsh-主机名，宿主侧便于识别）' },
    },
    permission: 'console.login',
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const result = await client.enroll({
        hubUrl: String(args.hubUrl),
        enrollmentCode: String(args.enrollmentCode),
        clientName: args.clientName === undefined || args.clientName === '' ? undefined : String(args.clientName),
      })
      const probe = await client.probeHub().catch(() => null)
      return {
        ok: true,
        hubUrl: result.hubUrl,
        clientName: result.clientName,
        template: result.template,
        hubReachable: probe?.reachable === true,
        notice: translate('机器凭证已保存到本机；平台运维工具已切换为远程执行（宿主侧执行、按模板权限收敛、全程审计）'),
      }
    },
  }))

  t.register(defineTool({
    name: 'connect_login',
    description: '用已有机器凭证（ClientId/ClientSecret）配置宿主连接。适用于管理员在宿主控制台手工签发凭证后分发的场景。',
    parameters: {
      hubUrl: { type: 'string', required: true, description: '宿主平台服务地址' },
      clientId: { type: 'string', required: true, description: '机器凭证 ClientId（mc- 开头）' },
      clientSecret: { type: 'string', required: true, description: '机器凭证 ClientSecret' },
      clientName: { type: 'string', description: '本机名称（可选）' },
    },
    permission: 'console.login',
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const result = await client.loginWithCredential({
        hubUrl: String(args.hubUrl),
        clientId: String(args.clientId),
        clientSecret: String(args.clientSecret),
        clientName: args.clientName === undefined || args.clientName === '' ? undefined : String(args.clientName),
      })
      return { ok: true, hubUrl: result.hubUrl, clientName: result.clientName, notice: translate('凭证已验证并保存，工具切换为远程执行') }
    },
  }))

  t.register(defineTool({
    name: 'connect_test',
    description: '体检宿主连接：健康检查 + 机器令牌换发 + 一次真实只读调用（agent_list）。',
    permission: 'console.login',
    parameters: {},
    output: { type: 'object', additionalProperties: true },
    async execute() {
      const status = await client.status()
      if (!client.hasHub()) return { ...status, note: translate('尚未接入，先执行 connect_setup') }
      let sample: Record<string, unknown> = {}
      try {
        const value = await client.forward('agent_list', {})
        sample = { sampleCall: { tool: 'agent_list', total: (value as { total?: number })?.total } }
      } catch (error) {
        sample = { sampleCall: { tool: 'agent_list', error: error instanceof Error ? error.message : String(error) } }
      }
      return { ...status, ...sample }
    },
  }))

  t.register(defineTool({
    name: 'connect_reset',
    description: '断开宿主连接：清除本机保存的机器凭证与令牌缓存，工具回到本地执行（宿主侧凭证不受影响，回收请在宿主控制台禁用）。',
    permission: 'console.login',
    parameters: {
      reason: { type: 'string', description: '断开原因（记录到本机日志）' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const was = client.getConfig()
      client.reset()
      ctx.logger('connect').info(`已断开宿主连接${args.reason ? `：${String(args.reason)}` : ''}${was ? `（原 ${was.hubUrl}）` : ''}`)
      return { ok: true, configured: false, notice: translate('本机凭证已清除，工具回到本地执行模式') }
    },
  }))
}

/**
 * Installation du proxy distant des outils (OPT-P1-03, refonte contractuelle) :
 * - Couche d'entrée : interception à l'enregistrement via tools.intercept — les outils métier enregistrés ensuite (préfixe autre que connect_) sont remplacés par un corps d'exécution de transfert ;
 * - Couche de rattrapage : tools.decorate enveloppe un à un les outils métier préexistants enregistrés avant cette extension ;
 * - fail-closed : échec de transfert = erreur explicite + événement d'alerte throttlé connect.degraded (vers bus/audit), jamais de repli local silencieux ;
 * - Runtime dépourvu des points d'extension (forme non ToolRuntime-lite) → dégradation explicite (événement + état + log error), plus de monkey-patch de prototype.
 * Renvoie si l'installation a réussi.
 */
export function installToolProxy(ctx: Context, client: ConnectClientService): boolean {
  const tools = ctx.tools as unknown as {
    intercept?: (fn: (definition: Record<string, unknown>) => Record<string, unknown>) => () => void
    decorate?: (name: string, wrap: (execute: unknown) => unknown) => () => void
    schemas?: () => Array<{ name: string }>
  } | undefined
  if (!tools || typeof tools.intercept !== 'function' || typeof tools.decorate !== 'function') {
    ctx.logger('connect').error('运行时缺少 tools.intercept/decorate 扩展点：远程转发不可用，已显式降级为本地执行（connect.degraded 已发事件）')
    client.noteDegraded('tool_runtime_contract_missing', translate('ctx.tools 未提供 intercept/decorate 扩展点（非 ToolRuntime-lite 形态）'))
    try { ctx.platformBus?.emit('connect.degraded', { reason: 'tool_runtime_contract_missing', detail: translate('ctx.tools 未提供 intercept/decorate 扩展点（非 ToolRuntime-lite 形态）'), at: new Date().toISOString() }) } catch { /* bus non prêt : l'état est déjà consigné côté client */ }
    return false
  }

  // Corps d'exécution de transfert : connecté → transfert (échec = erreur explicite, jamais de repli local) ; non connecté → local (sémantique explicite de connect_reset, pas une dégradation)
  const makeProxied = (toolName: string, localExecute: unknown): unknown => {
    return async (args: Record<string, unknown>, exec: { signal?: AbortSignal }): Promise<unknown> => {
      if (client.hasHub()) {
        try {
          return await client.forward(toolName, args ?? {}, exec)
        } catch (error) {
          client.noteForwardFailure(toolName, error)
          throw error
        }
      }
      return await (localExecute as ((a: Record<string, unknown>, e: { signal?: AbortSignal }) => Promise<unknown>) | undefined)?.(args ?? {}, exec)
    }
  }

  const disposers: Array<() => void> = []
  // Couche d'entrée : interception à l'enregistrement (couvre tous les outils métier enregistrés ensuite) ; les outils remplacés sont consignés pour être déballés et restaurés à la désactivation
  const interceptedTools: Array<{ name: string; localExecute: unknown }> = []
  disposers.push(tools.intercept((definition) => {
    const toolName = definition?.['name']
    if (typeof toolName !== 'string' || !isProxiedTool(toolName)) return definition
    interceptedTools.push({ name: toolName, localExecute: definition['execute'] })
    return { ...definition, execute: makeProxied(toolName, definition['execute']) }
  }))
  // Couche de rattrapage : enveloppe un à un les outils métier déjà enregistrés (les outils désactivés en course sont ignorés)
  for (const schema of tools.schemas?.() ?? []) {
    if (!isProxiedTool(schema.name)) continue
    try {
      disposers.push(tools.decorate(schema.name, (execute) => makeProxied(schema.name, execute)))
    } catch { /* outil désactivé pendant la fenêtre de décoration : ignoré */ }
  }
  ctx.effect(() => () => {
    for (const off of [...disposers].reverse()) off()
    // À la désactivation, déballe les outils remplacés par la couche d'entrée pour leur rendre leur corps d'exécution local (sémantique decorate : remplace par le corps d'exécution local capturé)
    for (const item of interceptedTools) {
      try {
        tools.decorate?.(item.name, () => item.localExecute)
      } catch { /* outil déjà désactivé : ignoré */ }
    }
  })
  return true
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    connectClient: ConnectClientService
    connectConfigServer: ConnectConfigServer
  }
}
