/**
 * Outils exposés au modèle par l'extension nas (même contrat pour le ToolRuntime dsh / pont d'outils REST / endpoint MCP /mcp).
 * Les opérations de lecture exigent nas.read ; les écritures exigent nas.write (point de permission au niveau outil vérifié uniformément à la passerelle).
 *
 * Face de travail de l'employé numérique (D12/D15, blueprint §4.5, acceptation V14/V15) :
 *   - la détermination « géré » ne fait que rechercher le caller de confiance (gateManagedWork) : les lectures (list/search) passent le gate risk='read',
 *     les écritures (mkdir/delete/upload) passent le gate risk='write' ; le refus est un motif en chinois + code de domaine.
 *   - le passage du gate ne saute pas l'autorisation d'origine de la passerelle de fichiers : la contrainte de répertoire reste exécutée par NasAuthzService/passerelle (intersection des deux couches).
 *   - le nas_fs_upload d'un passage géré n'accepte que le répertoire staging workforce (liste blanche D12), tout autre chemin
 *     est refusé en chinois (ARTIFACT_SCOPE_DENIED) avec invitation à passer par POST /api/workforce/artifacts.
 */
import { resolve, sep } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '../../platform-core/src/index.ts'
import { t as translate } from '../../platform-i18n/src/index.ts'
import { WORK_DENY_CODE_LABELS, gateManagedWork, type WorkCallerRef, type WorkforcePolicyRegistry } from '../../platform-core/src/workforce-port.ts'
import { WORKFORCE_ARTIFACTS_ROOT } from './index.ts'

export const name = 'nas-tools'
export const inject = ['tools', 'nasRegistry', 'workforcePolicy']

export function apply(ctx: Context) {
  const t = ctx.tools

  t.register(defineTool({
    name: 'nas_list',
    description: '列出纳管的 NAS（FS 文件存储）资产（含健康状态与生命周期）。',
    permission: 'nas.read',
    parameters: {
      status: { type: 'string', enum: ['draft', 'online', 'offline', 'archived'], description: '按状态过滤' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const items = ctx.nasRegistry.list(args.status ? { status: String(args.status) } : undefined)
      return {
        total: items.length,
        items: items.map((nas) => ({
          id: nas.id, name: nas.name, slug: nas.slug, status: nas.status,
          gateway: nas.attrs['gatewayUrl'], nasIp: nas.attrs['nasIp'], rootPath: nas.attrs['rootPath'],
          health: ctx.nasRegistry.healthOf(nas.id).status,
        })),
      }
    },
  }))

  t.register(defineTool({
    name: 'nas_get',
    description: '查看 NAS 资产详情（接入信息脱敏、健康、网关工具面）。',
    permission: 'nas.read',
    parameters: {
      nasId: { type: 'string', required: true, description: 'NAS 资产 ID' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const nas = ctx.nasRegistry.get(String(args.nasId))
      if (!nas) throw new Error(translate('NAS 资产不存在：{id}', { id: String(args.nasId) }))
      return {
        id: nas.id, name: nas.name, slug: nas.slug, status: nas.status,
        attrs: { ...nas.attrs, accessToken: mask(String(nas.attrs['accessToken'] ?? '')) },
        health: ctx.nasRegistry.healthOf(nas.id),
        gatewayTools: ctx.nasRegistry.toolsOf(nas.id).map((tool) => tool.name),
        availableTransitions: nas.status,
      }
    },
  }))

  t.register(defineTool({
    name: 'nas_health_check',
    description: '对 NAS 网关执行一次健康探测（MCP initialize 握手，返回延迟与状态）。',
    permission: 'nas.read',
    parameters: {
      nasId: { type: 'string', required: true, description: 'NAS 资产 ID' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      return await ctx.nasRegistry.probe(String(args.nasId))
    },
  }))

  t.register(defineTool({
    name: 'nas_fs_list',
    description: '列出 NAS 共享目录或指定路径下的文件（fs_list / fs_list_shares）。path 省略时列出全部共享。',
    permission: 'nas.read',
    parameters: {
      nasId: { type: 'string', required: true, description: 'NAS 资产 ID' },
      path: { type: 'string', description: '绝对路径 /<共享名>/子路径；省略列出共享' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const nasId = String(args.nasId)
      const path = args.path === undefined || args.path === '' ? undefined : String(args.path)
      await gateNasWork(ctx, exec, nasId, 'read')
      return path === undefined
        ? await ctx.nasRegistry.listShares(nasId, actorOf(args, exec, ctx))
        : await ctx.nasRegistry.listFiles(nasId, path, actorOf(args, exec, ctx))
    },
  }))

  t.register(defineTool({
    name: 'nas_fs_search',
    description: '在 NAS 指定路径下按关键字/通配符检索文件（fs_search）。',
    permission: 'nas.read',
    parameters: {
      nasId: { type: 'string', required: true, description: 'NAS 资产 ID' },
      pattern: { type: 'string', required: true, description: '检索关键字或通配符' },
      path: { type: 'string', description: '起始路径（默认根 /）' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const nasId = String(args.nasId)
      await gateNasWork(ctx, exec, nasId, 'read')
      return await ctx.nasRegistry.search(nasId, String(args.pattern), args.path ? String(args.path) : '/', actorOf(args, exec, ctx))
    },
  }))

  t.register(defineTool({
    name: 'nas_fs_mkdir',
    description: '在 NAS 上创建目录（fs_create_folder），写操作审计留痕。',
    permission: 'nas.write',
    parameters: {
      nasId: { type: 'string', required: true, description: 'NAS 资产 ID' },
      path: { type: 'string', required: true, description: '目标目录绝对路径' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const nasId = String(args.nasId)
      await gateNasWork(ctx, exec, nasId, 'write')
      return await ctx.nasRegistry.mkdir(nasId, String(args.path), actorOf(args, exec, ctx))
    },
  }))

  t.register(defineTool({
    name: 'nas_fs_delete',
    description: '删除 NAS 上的文件或目录（fs_delete，可批量），写操作审计留痕。',
    permission: 'nas.write',
    parameters: {
      nasId: { type: 'string', required: true, description: 'NAS 资产 ID' },
      paths: { type: 'array', items: { type: 'string' }, required: true, description: '目标绝对路径数组' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const nasId = String(args.nasId)
      const paths = Array.isArray(args.paths) ? args.paths.map(String) : [String(args.paths)]
      await gateNasWork(ctx, exec, nasId, 'write')
      return await ctx.nasRegistry.delete(nasId, paths, actorOf(args, exec, ctx))
    },
  }))

  t.register(defineTool({
    name: 'nas_fs_upload',
    description: '上传文件到 NAS（平台侧本地路径 → staging → 网关 fs_upload）。受管数字员工仅允许从 workforce 受控 artifact 区取文件，其余本地路径拒绝。',
    permission: 'nas.write',
    parameters: {
      nasId: { type: 'string', required: true, description: 'NAS 资产 ID' },
      localFile: { type: 'string', required: true, description: '平台侧可访问的本地文件绝对路径' },
      destPath: { type: 'string', required: true, description: 'NAS 目标绝对路径 /<共享名>/…/文件名' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args, exec) {
      const nasId = String(args.nasId)
      // D12/V15 : un employé numérique géré (caller de confiance atteint) ayant passé le gate d'écriture reste interdit sur localFile pour tout chemin plateforme
      // — seul le staging contrôlé workforce est permis (préfixe WORKFORCE_ARTIFACTS_ROOT), avec invitation à passer par l'interface d'upload contrôlée ;
      // l'admin humain/le chemin legacy gardent le statu quo (gate non atteint = pas de resserrage).
      const gate = await gateNasWork(ctx, exec, nasId, 'write')
      const localFile = String(args.localFile)
      if (gate === 'managed') {
        const candidate = resolve(localFile)
        if (candidate !== WORKFORCE_ARTIFACTS_ROOT && !candidate.startsWith(`${WORKFORCE_ARTIFACTS_ROOT}${sep}`)) {
          throw new Error(
            translate('上传被拒绝（ARTIFACT_SCOPE_DENIED）：受管数字员工禁止读取平台任意本地路径，localFile 仅允许 workforce 受控目录（{root}…）；请改走 POST /api/workforce/artifacts 受控上传后引用 artifact ID',
              { root: `${WORKFORCE_ARTIFACTS_ROOT}${sep}` }),
          )
        }
      }
      return await ctx.nasRegistry.uploadFile(nasId, {
        localFile,
        destPath: String(args.destPath),
        actor: actorOf(args, exec, ctx),
      })
    },
  }))
}

/**
 * Opérateur des outils de fichiers (subject de metering et actor d'audit partagés).
 * Leçon P0-2 (dev-plan-nas-authz §2.3) : l'identité vient toujours de exec.principal analysé à l'entrée depuis le jeton,
 * interdit de la lire dans args (le schéma n'a pas de paramètre d'identité) — absente = fail-closed, pas de repli sur une identité partagée.
 *
 * Liaison de session précise D15 :
 *   - forme dsh (identityBinding présent) : ne reconnaît que la liaison explicite de la session courante (bySession atteint) ;
 *     sans contexte de session / session non liée / service de liaison invérifiable = toujours refus en chinois,
 *     interdit de retomber sur « la dernière liaison » (concurrence multi-employés sans mélange d'identité, sans usurpation).
 *   - forme autonome (sans identityBinding) : comportement inchangé (identité exec.principal) ;
 *     le principal machine est marqué kind:'machine' — onBehalfHeaders n'injecte dès lors jamais X-On-Behalf-User ;
 *     seulement quand le terminal humain réel de l'actChain peut être vérifié par la logique existante (recherche inverse IAM), ce humain devient l'opérateur.
 */
type NasToolActor = { id: string; name: string; kind: 'human' | 'machine' }

interface NasExecContext {
  callId: string
  principal?: {
    kind?: string
    userId?: string
    principalId: string
    name: string
    actChain?: Array<{ name: string; type: string; principalId?: string; userId?: string }>
  }
  agent?: { session?: { id?: string } }
}

interface NasIdentityBindingLike {
  identityForSession(sessionId?: string): { userId: string; name: string } | undefined
  /** Table de liaison de session interne dsh-bridge (pour sondage en lecture seule) : sessionId → userId. */
  bySession?: Map<string, string>
}

function actorOf(
  args: Record<string, unknown>,
  exec: NasExecContext,
  ctx?: Context,
): NasToolActor {
  void args
  // Forme hôte dsh (assemblage de plugin-dsh-bridge) : la liaison d'identité de la plateforme prime — mais seule « la liaison explicite de la session courante » compte.
  // La forme autonome n'a pas le service identityBinding, comportement inchangé (identité machine d'exec.principal).
  const binding = (ctx as { identityBinding?: NasIdentityBindingLike } | undefined)?.identityBinding
  if (binding) {
    const sessionId = exec.agent?.session?.id
    if (typeof sessionId !== 'string' || sessionId === '') {
      throw new Error(translate('文件操作被拒绝：当前调用未携带已显式绑定平台身份的 dsh 会话（D15 精确会话绑定，禁止回落「最近一次绑定」）；请先在工作台完成身份绑定后重试'))
    }
    const identity = sessionBoundIdentity(binding, sessionId)
    if (!identity) {
      throw new Error(translate('文件操作被拒绝：当前会话未显式绑定平台身份（D15 禁止按「最近一次绑定」回落执行），请重新完成身份绑定后再试'))
    }
    return { id: identity.userId, name: identity.name, kind: 'human' }
  }
  const principal = exec.principal
  if (!principal) throw new Error(translate('缺少调用者身份（exec.principal），文件操作 fail-closed 拒绝执行'))
  if (principal.kind === 'human') {
    return { id: principal.userId ?? principal.principalId, name: principal.name, kind: 'human' }
  }
  // Principal machine : jamais prendre un ID machine pour un humain ; seulement si la chaîne proxy OBO a vraiment un terminal humain vérifié,
  // et que son identité est résoluble (devra encore passer la reconnaissance par recherche inverse IAM d'onBehalfHeaders), ce humain devient l'opérateur.
  const human = humanDelegatorOf(principal, ctx)
  if (human) return { id: human.id, name: human.name, kind: 'human' }
  return { id: principal.userId ?? principal.principalId, name: principal.name, kind: 'machine' }
}

/**
 * Vérification de liaison précise de session dsh (D15) : ne reconnaît que la session courante enregistrée dans bySession, et exige
 * que identityForSession renvoie exactement l'utilisateur lié — tout repli sur « la dernière liaison » (current) est inadmissible.
 * Quand la structure interne du service de liaison change et rend la vérification impossible, traiter comme non lié (fail-closed, pas de dégradation silencieuse).
 */
function sessionBoundIdentity(binding: NasIdentityBindingLike, sessionId: string): { userId: string; name: string } | undefined {
  const sessions = binding.bySession
  if (!(sessions instanceof Map)) return undefined
  const boundUserId = sessions.get(sessionId)
  if (!boundUserId) return undefined
  const identity = binding.identityForSession(sessionId)
  return identity && identity.userId === boundUserId ? identity : undefined
}

/**
 * Résolution du terminal humain de la chaîne proxy OBO (D15) : de la queue vers la tête de la chaîne, trouve la plus récente entrée humaine et résout son ID utilisateur plateforme
 * (recherche inverse du principal authn par refId ; si l'entrée porte userId, prise directe). Irrésoluble = undefined
 * — l'appel machine garde l'attribution machine, jamais d'usurpation d'humain.
 */
function humanDelegatorOf(
  principal: NonNullable<NasExecContext['principal']>,
  ctx?: Context,
): { id: string; name: string } | undefined {
  const chain = Array.isArray(principal.actChain) ? principal.actChain : []
  for (let index = chain.length - 1; index >= 0; index--) {
    const entry = chain[index]
    if (!entry || entry.type !== 'human') continue
    if (typeof entry.userId === 'string' && entry.userId !== '') {
      return { id: entry.userId, name: entry.name || entry.userId }
    }
    const principalId = typeof entry.principalId === 'string' ? entry.principalId : ''
    if (!principalId) continue
    try {
      const authn = (ctx as { authn?: { principals(): Map<string, { refId?: string; name?: string }> } } | undefined)?.authn
      const record = authn?.principals().get(principalId)
      const userId = record?.refId
      if (userId) return { id: userId, name: entry.name || record?.name || userId }
    } catch { /* hôte autonome sans authn : entrée humaine non reconnue */ }
  }
  return undefined
}

/**
 * Admission au niveau travail de l'employé numérique géré (D12/D15/annexe D.5) : la détermination « géré » ne fait que rechercher le caller de confiance (exec.principal),
 * indépendamment des paramètres de requête. denied → refus en chinois (avec code de domaine) ; legacy → renvoie 'legacy', l'ancienne chaîne s'applique ;
 * managed → renvoie 'managed' (l'appelant peut ajouter des contraintes propres au géré, ex. liste blanche d'upload D12).
 * Note : le passage du gate ne saute pas l'autorisation d'origine de la passerelle de fichiers — la contrainte de répertoire reste exécutée par NasAuthzService/passerelle.
 */
async function gateNasWork(
  ctx: Context,
  exec: NasExecContext,
  nasId: string,
  risk: 'read' | 'write',
): Promise<'legacy' | 'managed'> {
  const registry = (ctx as { workforcePolicy?: WorkforcePolicyRegistry } | undefined)?.workforcePolicy
  const caller = workCallerOf(exec, ctx)
  const gate = await gateManagedWork(registry, caller, {
    facts: { kind: 'nas', registryId: nasId, action: risk, risk },
  })
  if (gate.mode === 'denied') {
    throw new Error(`${WORK_DENY_CODE_LABELS[gate.code]}（${gate.code}）：${gate.message}`)
  }
  return gate.mode
}

/** exec.principal → référence d'appelant de travail vérifiée (seuls champs vérifiés côté serveur ; côté machine, complétion au mieux de refType/refId pour la recherche inverse). */
function workCallerOf(exec: NasExecContext, ctx?: Context): WorkCallerRef | undefined {
  const principal = exec.principal
  if (!principal) return undefined
  if (principal.kind === 'human') {
    return {
      kind: 'human',
      principalId: principal.principalId,
      ...(principal.userId ? { userId: principal.userId } : {}),
      name: principal.name,
    }
  }
  let refType: string | undefined
  let refId: string | undefined
  try {
    const authn = (ctx as { authn?: { principals(): Map<string, { refType?: string; refId?: string }> } } | undefined)?.authn
    const record = authn?.principals().get(principal.principalId)
    if (record?.refType && record?.refId) {
      refType = record.refType
      refId = record.refId
    }
  } catch { /* hôte autonome sans authn : recherche inverse par principalId déléguée au port workforce */ }
  return {
    kind: 'machine',
    principalId: principal.principalId,
    ...(refType ? { refType } : {}),
    ...(refId ? { refId } : {}),
    name: principal.name,
  }
}

function mask(token: string): string {
  if (!token) return ''
  return token.length > 8 ? `${token.slice(0, 6)}…` : '****'
}
