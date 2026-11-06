/**
 * Outils exposés au modèle par l'extension iam (socle du Skill dsh-ops-iam).
 * Enregistrés dans ctx.tools : dans le dsh complet, le modèle les appelle directement ; dans l'hôte autonome, on les atteint via /api/tools/execute.
 */
import type { Context } from '@deepseek-ai/cordis'
import { defineTool, type ToolRunContext } from '../../platform-core/src/index.ts'
import { t as translate } from '../../platform-i18n/src/index.ts'
import type { UserManageActor } from './index.ts'

export const name = 'iam-tools'
export const inject = ['tools', 'iam']

/**
 * Clé d'identité réservée des outils de gestion iam (contrat inter-groupes N1) : le côté pont de l'hôte autonome (plugin-console routes/bridge.ts
 * injectToolIdentity) injecte `args._actor` avec l'identité serveur analysée du jeton ; la même clé passée côté client (actor compris)
 * est toujours retirée puis réinjectée : l'identité ne peut pas être auto-remplie par l'appelant. La forme d'appel direct de l'hôte dsh complet, sans injection de pont, retombe sur exec.principal.
 */
interface BridgeActor {
  id?: string
  name?: string
  orgId?: string
  platformAdmin?: boolean
}

/**
 * Normalisation de l'opérateur des outils de gestion (N1) : `args._actor` (injection pont, prioritaire) → exec.principal (appel direct runtime)
 * → actor anonyme sans permission (assertManageScope de la couche service iam refuse en fail-closed). Renvoie les paramètres métier
 * après retirage de `_actor` ; la clé réservée ne fuit pas dans les paramètres des méthodes de service.
 */
function manageActorOf(args: any, exec?: ToolRunContext): { actor: UserManageActor; rest: Record<string, any> } {
  const { _actor, ...rest } = args ?? {}
  const bridge = (_actor ?? undefined) as BridgeActor | undefined
  if (bridge && typeof bridge === 'object') {
    return {
      actor: {
        ...(typeof bridge.id === 'string' && bridge.id ? { userId: bridge.id } : {}),
        ...(typeof bridge.orgId === 'string' && bridge.orgId ? { orgId: bridge.orgId } : {}),
        permissions: bridge.platformAdmin === true ? ['*'] : [],
      },
      rest,
    }
  }
  const principal = exec?.principal
  return {
    actor: {
      ...(principal?.userId ? { userId: principal.userId } : {}),
      permissions: Array.isArray(principal?.permissions) ? [...principal.permissions] : [],
    },
    rest,
  }
}

export function apply(ctx: Context) {
  const t = ctx.tools

  /**
   * Sous-arbre organisationnel visible de l'appelant (revue de sécurité P1-02, 2026-10-31) : même référentiel que scopedOrgIdsOf de la face REST —
   * l'admin plateforme ('*') reçoit null (exemption intégrale) ; les autres sont resserrés au sous-arbre de l'opérateur (sans rattachement = fail-closed, ensemble vide).
   * Le pont d'outils et REST partagent la même frontière, contre le contournement « page liste resserrée, pont d'outils lisant tout ».
   */
  const scopedOrgIdsOf = (actor: UserManageActor): string[] | null => {
    if (actor.permissions.includes('*')) return null
    const orgId = actor.orgId ?? (actor.userId ? ctx.iam.users().get(actor.userId)?.orgId : undefined)
    return orgId ? ctx.iam.orgSubtreeIds(orgId) : []
  }

  t.register(defineTool({
    name: 'iam_org_tree',
    description: '获取组织架构树（含各级子组织与人数统计）。仅返回调用者组织子树内的部分。',
    permission: 'iam.org.read',
    parameters: {},
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const { actor } = manageActorOf(args, exec)
      const scope = scopedOrgIdsOf(actor)
      const decorate = (nodes: any[]): any[] => nodes.map((node) => ({
        id: node.id, name: node.name, status: node.status,
        userCount: ctx.iam.users().find((user) => user.orgId === node.id).length,
        children: decorate(node.children),
      }))
      if (scope === null) return { tree: decorate(ctx.iam.orgTree()) }
      const rootId = scope[0]
      if (!rootId) return { tree: [] }
      const prune = (nodes: any[]): any[] => nodes
        .filter((node) => scope.includes(node.id))
        .map((node) => ({ ...node, children: prune(node.children ?? []) }))
      return { tree: prune(ctx.iam.orgTree()) }
    },
  }))

  t.register(defineTool({
    name: 'iam_org_create',
    description: '创建组织（需 iam.org.write 权限）。parentId 为空表示顶级组织。',
    permission: 'iam.org.write',
    parameters: {
      name: { type: 'string', required: true, description: '组织名称' },
      parentId: { type: 'string', description: '父组织 ID' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const { actor, rest } = manageActorOf(args, exec)
      const org = ctx.iam.createOrg({ name: rest.name, parentId: rest.parentId ?? null }, actor)
      return { id: org.id, name: org.name }
    },
  }))

  t.register(defineTool({
    name: 'iam_org_update',
    description: '修改组织：重命名和/或调整上级组织（需 iam.org.write 权限）。name 与 parentId 至少提供一个；parentId 传空字符串表示提升为顶级组织。',
    permission: 'iam.org.write',
    parameters: {
      orgId: { type: 'string', required: true, description: '组织 ID' },
      name: { type: 'string', description: '新组织名称' },
      parentId: { type: 'string', description: '新父组织 ID（传空字符串表示提升为顶级组织）' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const { actor, rest } = manageActorOf(args, exec)
      if (rest.name === undefined && rest.parentId === undefined) throw new Error(translate('name 与 parentId 至少提供一个'))
      if (rest.name !== undefined) ctx.iam.renameOrg(rest.orgId, rest.name, actor)
      if (rest.parentId !== undefined) ctx.iam.moveOrg(rest.orgId, rest.parentId || null, actor)
      const org = ctx.iam.orgs().get(rest.orgId)
      return { id: org.id, name: org.name, parentId: org.parentId }
    },
  }))

  t.register(defineTool({
    name: 'iam_user_list',
    description: '查询账号列表，可按组织/状态/关键字过滤。',
    permission: 'iam.user.read',
    parameters: {
      orgId: { type: 'string', description: '限定组织（含子树）' },
      status: { type: 'string', enum: ['pending', 'active', 'frozen', 'deactivated'], description: '状态过滤' },
      q: { type: 'string', description: '姓名/用户名关键字' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const { actor } = manageActorOf(args, exec)
      // P1-02 : un non-admin plateforme est resserré au sous-arbre organisationnel de l'appelant (même référentiel que REST /api/iam/users,
      // un orgId explicite hors sous-arbre est refusé directement, sans retour silencieux d'un ensemble vide qui simulerait « personne de ce nom »)
      const scope = scopedOrgIdsOf(actor)
      const allow = scope === null ? null : new Set(scope)
      if (args.orgId && allow && !allow.has(String(args.orgId))) {
        throw new Error(translate('查询组织超出调用者的组织子树（组织隔离）'))
      }
      const users = ctx.iam.users().find((user) => {
        if (args.status && user.status !== args.status) return false
        if (args.q && !`${user.displayName}${user.username}`.includes(args.q)) return false
        if (allow && !allow.has(user.orgId)) return false
        if (args.orgId) {
          const orgScope = new Set(ctx.iam.orgSubtreeIds(String(args.orgId)))
          if (!orgScope.has(user.orgId)) return false
        }
        return true
      })
      return {
        total: users.length,
        users: users.map((user) => ({
          id: user.id, username: user.username, displayName: user.displayName,
          org: ctx.iam.orgs().get(user.orgId)?.name, title: user.title, status: user.status,
        })),
      }
    },
  }))

  t.register(defineTool({
    name: 'iam_user_create',
    description: '创建账号。未提供 password 时生成随机初始口令，仅在返回值 initialPassword 中出现一次，请安全传达给本人。',
    permission: 'iam.user.write',
    parameters: {
      username: { type: 'string', required: true, description: '登录名（字母数字）' },
      displayName: { type: 'string', required: true, description: '姓名' },
      orgId: { type: 'string', required: true, description: '所属组织 ID' },
      title: { type: 'string', description: '职位' },
      roleIds: { type: 'array', items: { type: 'string' }, description: '角色 ID 列表' },
      password: { type: 'string', description: '初始口令（缺省则随机生成，仅返回一次）' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const { actor, rest } = manageActorOf(args, exec)
      const { user, initialPassword } = ctx.iam.createUser({ ...rest, roleIds: rest.roleIds }, actor)
      return { id: user.id, username: user.username, status: user.status, ...(initialPassword ? { initialPassword } : {}) }
    },
  }))

  t.register(defineTool({
    name: 'iam_user_reset_password',
    description: '重置账号为随机初始口令（仅返回一次；请第一时间传达给本人）。',
    permission: 'iam.user.write',
    parameters: {
      userId: { type: 'string', required: true, description: '账号 ID' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const { actor, rest } = manageActorOf(args, exec)
      const { user, initialPassword } = ctx.iam.resetPassword(rest.userId, undefined, actor)
      return { id: user.id, username: user.username, initialPassword }
    },
  }))

  t.register(defineTool({
    name: 'iam_user_freeze',
    description: '冻结账号（L4 高危：必须填写 reason，将联动吊销名下全部令牌）。',
    permission: 'iam.user.freeze',
    parameters: {
      userId: { type: 'string', required: true, description: '账号 ID' },
      reason: { type: 'string', required: true, description: '冻结原因（审计留痕）' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const { actor, rest } = manageActorOf(args, exec)
      const user = ctx.iam.freezeUser(rest.userId, rest.reason, actor)
      return { id: user.id, status: user.status, note: translate('已发布 iam.user.frozen 事件，认证中心将吊销其令牌') }
    },
  }))

  t.register(defineTool({
    name: 'iam_role_list',
    description: '列出全部角色与权限点。',
    permission: 'iam.org.read',
    parameters: {},
    output: { type: 'object', additionalProperties: true },
    async execute() {
      return {
        roles: ctx.iam.roles().all().map((role) => ({ id: role.id, code: role.code, name: role.name, builtin: role.builtin, permissions: role.permissions })),
      }
    },
  }))

  t.register(defineTool({
    name: 'iam_sync_run',
    description: '触发三方通讯录全量同步（支持多主体：同一平台可接入多家企业，传 configId 指定主体实例，缺省按 provider 取第一条）。',
    permission: 'iam.connector.write',
    parameters: {
      provider: { type: 'string', enum: ['dingtalk'], description: '连接器（与 configId 至少提供一个；缺省按 provider 取第一条配置）' },
      configId: { type: 'string', description: '接入配置实例 ID（多主体时指定，优先于 provider）' },
      actor: { type: 'string', description: '操作人（审计用）' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const target = args.configId ?? args.provider
      if (!target) throw new Error(translate('provider 与 configId 至少提供一个'))
      return await ctx.iam.syncConnector(target, args.actor ?? 'agent')
    },
  }))

  t.register(defineTool({
    name: 'iam_conflict_list',
    description: '查看三方同步冲突队列（pending 未处理）。',
    permission: 'iam.org.read',
    parameters: {
      status: { type: 'string', enum: ['pending', 'resolved'], description: '默认 pending' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const conflicts = ctx.iam.conflicts().find((item) => item.status === (args.status ?? 'pending'))
      return { total: conflicts.length, conflicts }
    },
  }))
}
