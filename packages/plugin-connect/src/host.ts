/**
 * Endpoints d'accès côté hôte : plan de gestion par lequel le runtime dsh distant (forme installée via le marché de plugins) demande ses identifiants à cette plateforme.
 *
 * Déroulé (correspond à la forme C de docs/deploy-enterprise.md) :
 *   1. l'admin crée dans la console/CLI un code d'accès à usage unique (TTL + gabarit de permissions)
 *   2. une fois l'extension installée sur le dsh de l'ordinateur distant, l'Agent appelle connect_setup ou ouvre la page de configuration locale,
 *      et échange le code d'accès via POST /api/connect/enroll contre des identifiants machine (clientId/clientSecret)
 *   3. le client échange ses identifiants machine via client-credentials contre un jeton machine, tous les appels d'outils passent par
 *      /api/tools/execute et s'exécutent côté hôte (permissions resserrées selon l'instantané du gabarit)
 *
 * Base de sécurité : les codes d'accès ne sont stockés que hachés (affichage unique à la création), consommation à usage unique, TTL par défaut 15 minutes,
 * verrouillage d'échec existant de l'hôte d'accès par IP d'origine (verrouillage après 5 échecs sur une fenêtre de 15 minutes), audit de bout en bout.
 */
import type { Context } from '@deepseek-ai/cordis'
import { generateSecret, mask, newId, sha256Hex, PlatformEvents, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t as translate } from '../../platform-i18n/src/index.ts'
import { PermissionCatalog } from '../../plugin-iam/src/index.ts'
import { defineTool } from '../../platform-core/src/index.ts'

/** Enregistrement de code d'accès (le code n'est stocké que haché, la forme claire n'est renvoyée qu'une fois à la création). */
export interface EnrollCodeRecord extends RecordBase {
  codeHash: string
  codeMask: string
  template: TemplateName
  remark: string
  createdBy: string
  createdAt: string
  expiresAt: string
  usedAt?: string
  usedBy?: string
  revokedAt?: string
}

/** Enregistrement des clients connectés (principalId rattaché à l'identité machine authn). */
export interface ConnectClientRecord extends RecordBase {
  principalId: string
  clientId: string
  name: string
  template: TemplateName
  hostname: string
  platform: string
  enrolledBy: string
  enrolledAt: string
  status: 'active' | 'disabled'
  /** Horodatage du dernier battement de cœur (poussée périodique du client après connexion, pour la supervision de survie des actifs d'accès côté hôte). */
  lastHeartbeatAt?: string
  /** Métadonnées d'exécution transportées par le battement (déclarées par le client, non vérifiées, affichage d'observation uniquement). */
  heartbeat?: { tools?: number; version?: string; uptimeSec?: number }
}

export type TemplateName = 'readonly' | 'operator' | 'executor' | 'full'

export interface TemplateSpec {
  name: TemplateName
  label: string
  description: string
  scopes: string[]
}

const DEFAULT_TTL_MINUTES = 15
const MAX_TTL_MINUTES = 24 * 60

/** Gabarits de permissions : sémantique d'instantané prise à la création du code d'accès, résolue en points de permission concrets lors de l'enroll selon le catalogue de permissions courant. */
export function connectTemplates(): Array<Omit<TemplateSpec, 'scopes'>> {
  return [
    { name: 'readonly', label: translate('只读运维'), description: translate('全部查询类权限点（list/get/metrics/logs），适合只读巡检 Agent') },
    { name: 'operator', label: translate('运维（读 + 资源变更）'), description: translate('只读 + MCP/Skill/Agent/应用运维与审批决策；不含账号与凭证管理，也不含任务执行（认领走 executor）') },
    { name: 'executor', label: translate('执行方（读 + 任务执行）'), description: translate('只读 + exec.write 任务认领/执行 + usage.write 用量自报；不含账号与凭证管理，供远程 dsh/Agent 作为执行方接入（issue #9）') },
    { name: 'full', label: translate('全部权限（*）'), description: translate('等价平台管理员，仅可信环境使用') },
  ]
}

export function templateScopes(template: TemplateName): string[] {
  if (template === 'full') return ['*']
  // Le pont d'outils exige console.login ; cette permission implique aussi console.read (vue d'ensemble en lecture seule).
  if (template === 'executor') return ['console.login', 'exec.read', 'exec.write']
  const readPoints = PermissionCatalog.filter((item) => item.point.endsWith('.read') || item.point === 'console.login').map((item) => item.point)
  if (template === 'readonly') return readPoints
  if (template === 'executor') return [...new Set([...readPoints, 'exec.write', 'usage.write'])]
  const operatorExtra = [
    'mcp.service.write', 'mcp.service.deploy', 'mcp.service.offline', 'mcp.permgroup.write', 'mcp.invoke',
    'skill.submit', 'skill.install', 'agent.write', 'agent.offline', 'app.write', 'app.offline',
    'approval.decide', 'usage.write', 'audit.rule.write',
  ]
  return [...new Set([...readPoints, ...operatorExtra])]
}

export function codesCollection(ctx: Context): Collection<EnrollCodeRecord> {
  const collection = ctx.opsStorage.collection<EnrollCodeRecord>('connect:codes')
  collection.uniqueOn('connect_code_hash', (record) => record.codeHash)
  return collection
}

// ---------------------------------------------------------------------------
// Observation d'attribution D13 (chemin de transfert connect : client.forward() → hôte /api/tools/execute)
// ---------------------------------------------------------------------------

/** Durée de la fenêtre courte de détection d'attribution multi-principaux : une alerte si le même identifiant client présente plusieurs principaux distincts dans cette fenêtre. */
const FORWARD_PRINCIPAL_WINDOW_MS = 60_000

/** Un état de fenêtre par identifiant client (état d'observation en processus, non persisté ; les entrées sont remplacées à expiration de la fenêtre, taille bornée par le nombre de clients connectés). */
const forwardPrincipalWindows = new Map<string, { windowStart: number; seen: Set<string> }>()

/**
 * Détection du risque d'attribution multi-principaux sur un client d'accès partagé (D13/observation, sans blocage) :
 * lors du transfert d'un appel d'outil, le client d'accès transmet la liaison de principal via l'enveloppe meta.principal (voir client.forward) ; le pont d'outils côté hôte
 * consomme cette fonction — un même identifiant client présentant plusieurs principalId distincts dans une fenêtre courte (identifiants partagés portant plusieurs employés/runtimes)
 * → logger.warn « risque d'attribution ». Observation seule : pas de blocage de l'appel, pas de participation à l'autorisation (l'authentification reste uniquement fondée sur la vérification
 * serveur du jeton Bearer), et sans observation aucune attribution d'exécution n'est fabriquée (santé technique et avancement métier sont des dimensions distinctes, D13).
 * @param logger façade de log dotée de warn (la forme structurée de cordis ctx.logger('connect') convient)
 * @param clientPrincipalId principal machine du client vérifié côté hôte via le jeton Bearer (seul fait d'authentification)
 * @param forwardedPrincipalId principal déclaré par l'enveloppe de transfert (observation d'attribution uniquement ; à défaut, retombe sur le principal du client lui-même)
 */
export function noteForwardedPrincipal(
  logger: { warn: (message: string, ...args: unknown[]) => void },
  clientPrincipalId: string,
  forwardedPrincipalId?: string,
): void {
  const claimed = forwardedPrincipalId?.trim() || clientPrincipalId
  if (!clientPrincipalId) return
  const now = Date.now()
  const entry = forwardPrincipalWindows.get(clientPrincipalId)
  if (!entry || now - entry.windowStart > FORWARD_PRINCIPAL_WINDOW_MS) {
    forwardPrincipalWindows.set(clientPrincipalId, { windowStart: now, seen: new Set([claimed]) })
    return
  }
  entry.seen.add(claimed)
  // Alerte une unique fois quand on atteint exactement 2 principaux distincts (pas de répétition dans la fenêtre ; après expiration, la fenêtre reconstruite autorise à nouveau une alerte pour le premier nouveau principal)
  if (entry.seen.size === 2) {
    logger.warn(
      `归因风险提示：同一接入客户端凭证（${clientPrincipalId}）在 ${Math.round(FORWARD_PRINCIPAL_WINDOW_MS / 1000)} 秒窗口内出现多个不同主体（${[...entry.seen].join('、')}），`
      + '该客户端疑似共享承载多个员工/运行时，转发调用的执行归因可能失真（节点身份≠员工执行身份，建议一员工一凭证；D13 观测，不阻断）',
    )
  }
}

export function clientsCollection(ctx: Context): Collection<ConnectClientRecord> {
  const collection = ctx.opsStorage.collection<ConnectClientRecord>('connect:clients')
  collection.uniqueOn('connect_client_principal', (record) => record.principalId)
  return collection
}

// ---------------------------------------------------------------------------
// Assemblage REST (monté sur le httpServer de l'hôte ; tout sauf enroll est protégé par le middleware d'authentification console)
// ---------------------------------------------------------------------------

/** Localisation du client : aussi bien l'ID de l'enregistrement que le clientId des identifiants machine (préfixe mc-). */
function findClient(ctx: Context, key: string): ConnectClientRecord | undefined {
  const clients = clientsCollection(ctx)
  return clients.get(key) ?? clients.findOne((item) => item.clientId === key)
}

export interface ConnectHostApiConfig {
  /** Informations de présentation exposées par l'endpoint enroll. */
  hubName?: string
  hubVersion?: string
}

export const connectHostApi = {
  name: 'connect-host-api',
  inject: ['httpServer', 'opsStorage', 'platformBus', 'authn', 'iam', 'audit'],
  apply(ctx: Context, config: ConnectHostApiConfig = {}) {
    const http = ctx.httpServer

    const requireManage = (exchange: { principal?: unknown; fail: (status: number, code: string, message: string, extra?: Record<string, unknown>) => void; path: string }): boolean => {
      const info = exchange.principal as { permissions?: string[]; principalId?: string; userId?: string; name?: string } | undefined
      const permissions = info?.permissions ?? []
      if (permissions.includes('*') || permissions.includes('connect.manage')) return true
      ctx.platformBus.emit('audit.authz.denied', {
        actorId: info?.userId ?? info?.principalId ?? 'anonymous',
        actorName: info?.name ?? 'anonymous',
        point: 'connect.manage',
        path: exchange.path,
      })
      exchange.fail(403, 'FORBIDDEN', translate('缺少权限点 connect.manage，请联系平台管理员'), { permission: 'connect.manage' })
      return false
    }

    // -- Échange du code d'accès contre des identifiants machine (endpoint public, le code d'accès sert lui-même d'identifiant ; verrouillage d'échec par IP) ---------
    http.register('POST', '/api/connect/enroll', async (exchange) => {
      const input = (exchange.body ?? {}) as { enrollmentCode?: string; clientName?: string; meta?: { hostname?: string; platform?: string; node?: string } }
      const code = (input.enrollmentCode ?? '').trim()
      const ip = exchange.raw.socket.remoteAddress ?? 'unknown'
      const throttleKey = `connect-enroll:${ip}`
      const failEnroll = (message: string): void => {
        ctx.authn.recordLoginFailure(throttleKey)
        ctx.audit.record({
          type: 'auth', actorType: 'machine', actorId: ip, actorName: input.clientName ?? 'unknown-client',
          action: 'connect.enroll', resourceType: 'connect', resourceId: '-', resourceName: translate('接入申请'),
          result: 'denied', detail: message,
        })
        exchange.fail(401, 'ENROLL_FAILED', message)
      }
      try {
        ctx.authn.assertNotLocked(throttleKey)
      } catch (error) {
        exchange.fail(429, 'LOCKED', error instanceof Error ? error.message : String(error))
        return
      }
      if (!code) { failEnroll(translate('接入码必填：请在宿主控制台「平台接入」创建')); return }
      const record = codesCollection(ctx).findOne((item) => item.codeHash === sha256Hex(code))
      if (!record) { failEnroll(translate('接入码无效（不存在或已输入错误）')); return }
      if (record.revokedAt) { failEnroll(translate('接入码已作废，请联系管理员重新签发')); return }
      if (record.usedAt) { failEnroll(translate('接入码已被使用（一次性消费，防重放），请申请新码')); return }
      if (new Date(record.expiresAt).getTime() < Date.now()) { failEnroll(translate('接入码已过期，请申请新码')); return }

      ctx.authn.recordLoginSuccess(throttleKey)
      codesCollection(ctx).update(record.id, { usedAt: new Date().toISOString(), usedBy: input.clientName ?? 'unnamed' })
      const scopes = templateScopes(record.template)
      const credential = ctx.authn.createMachineCredential({
        name: input.clientName?.trim() || 'dsh-client',
        refType: 'external',
        scopes,
      })
      clientsCollection(ctx).insert({
        id: newId('ccl'),
        principalId: credential.principal.id,
        clientId: credential.clientId,
        name: input.clientName?.trim() || 'dsh-client',
        template: record.template,
        hostname: input.meta?.hostname ?? '',
        platform: [input.meta?.platform, input.meta?.node].filter(Boolean).join('/') || '',
        enrolledBy: `code:${record.codeMask}`,
        enrolledAt: new Date().toISOString(),
        status: 'active',
      })
      ctx.audit.record({
        type: 'auth', actorType: 'machine', actorId: credential.principal.id, actorName: credential.principal.name,
        action: 'connect.enroll', resourceType: 'connect', resourceId: credential.clientId,
        resourceName: credential.principal.name, result: 'ok',
        detail: translate('接入码 {code}（模板 {template}）换取机器凭证', { code: record.codeMask, template: record.template }),
      })
      ctx.platformBus.emit(PlatformEvents.ConnectClientEnrolled, {
        principalId: credential.principal.id, name: credential.principal.name, template: record.template, hostname: input.meta?.hostname ?? '',
      })
      exchange.ok({
        clientId: credential.clientId,
        clientSecret: credential.clientSecret,
        principalId: credential.principal.id,
        template: record.template,
        hub: { name: config.hubName ?? translate('元冰可|企业AI资源管理平台'), version: config.hubVersion ?? '1.0.0' },
        notice: translate('机器凭证仅本次返回，请妥善保存；后续用它在 /api/auth/client-credentials 换取机器令牌'),
      })
    }, { access: 'public', selfValidated: true })

    // -- Battement de cœur du client (poussée active de survie/métadonnées d'exécution par le côté accès ; haute fréquence hors audit pour ne pas noyer les logs) ----
    http.register('POST', '/api/connect/heartbeat', (exchange) => {
      const info = exchange.principal as { principalId?: string } | undefined
      if (!info?.principalId) { exchange.fail(401, 'UNAUTHORIZED', translate('缺少 Bearer 令牌')); return }
      const client = clientsCollection(ctx).findOne((item) => item.principalId === info.principalId)
      if (!client) { exchange.fail(404, 'NOT_FOUND', translate('该身份未登记为接入客户端（仅远程 dsh 客户端可上报心跳）')); return }
      const input = (exchange.body ?? {}) as { tools?: number; version?: string; uptimeSec?: number }
      clientsCollection(ctx).update(client.id, {
        lastHeartbeatAt: new Date().toISOString(),
        heartbeat: {
          ...(typeof input.tools === 'number' ? { tools: Math.max(0, Math.floor(input.tools)) } : {}),
          ...(typeof input.version === 'string' ? { version: input.version.slice(0, 40) } : {}),
          ...(typeof input.uptimeSec === 'number' ? { uptimeSec: Math.max(0, Math.floor(input.uptimeSec)) } : {}),
        },
      })
      exchange.ok({ ok: true, clientId: client.clientId, template: client.template })
    }, { access: 'authenticated' })

    // -- Gestion des codes d'accès ----------------------------------------------------------
    http.register('POST', '/api/connect/codes', (exchange) => {
      if (!requireManage(exchange)) return
      const input = (exchange.body ?? {}) as { template?: string; ttlMinutes?: number; remark?: string }
      const template = (['readonly', 'operator', 'executor', 'full'] as const).includes(input.template as TemplateName) ? input.template as TemplateName : 'readonly'
      const ttlMinutes = Math.min(Math.max(Math.floor(Number(input.ttlMinutes) || DEFAULT_TTL_MINUTES), 1), MAX_TTL_MINUTES)
      const code = generateSecret('enr')
      const info = exchange.principal as { userId?: string; principalId?: string; name?: string }
      const record = codesCollection(ctx).insert({
        id: newId('enc'),
        codeHash: sha256Hex(code),
        codeMask: mask(code, 6),
        template,
        remark: (input.remark ?? '').slice(0, 120),
        createdBy: info?.name ?? 'api',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + ttlMinutes * 60_000).toISOString(),
      })
      ctx.audit.record({
        type: 'change', actorType: 'human', actorId: info?.userId ?? info?.principalId ?? 'api', actorName: info?.name ?? 'api',
        action: 'connect.code.create', resourceType: 'connect', resourceId: record.id,
        resourceName: record.codeMask, result: 'ok',
        detail: translate('模板 {template}，有效期 {minutes} 分钟', { template, minutes: ttlMinutes }),
      })
      ctx.platformBus.emit(PlatformEvents.ConnectCodeCreated, { id: record.id, template, ttlMinutes })
      exchange.ok({ id: record.id, code, codeMask: record.codeMask, template, ttlMinutes, expiresAt: record.expiresAt, notice: translate('接入码仅本次返回且一次性消费，请立即复制分发') })
    }, { access: 'guarded', permission: 'connect.manage' })

    http.register('GET', '/api/connect/codes', (exchange) => {
      if (!requireManage(exchange)) return
      const now = Date.now()
      exchange.ok({
        codes: codesCollection(ctx).all()
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
          .map((record) => ({
            ...record,
            status: record.revokedAt ? 'revoked' : record.usedAt ? 'used' : new Date(record.expiresAt).getTime() < now ? 'expired' : 'active',
          })),
      })
    }, { access: 'guarded', permission: 'connect.manage' })

    http.register('DELETE', '/api/connect/codes/:id', (exchange) => {
      if (!requireManage(exchange)) return
      const record = codesCollection(ctx).get(exchange.params['id']!)
      if (!record) { exchange.fail(404, 'NOT_FOUND', translate('接入码不存在')); return }
      if (record.usedAt) { exchange.fail(400, 'BAD_REQUEST', translate('接入码已被使用，无法作废；如需回收请直接禁用对应客户端')); return }
      codesCollection(ctx).update(record.id, { revokedAt: new Date().toISOString() })
      const info = exchange.principal as { userId?: string; principalId?: string; name?: string }
      ctx.audit.record({
        type: 'change', actorType: 'human', actorId: info?.userId ?? info?.principalId ?? 'api', actorName: info?.name ?? 'api',
        action: 'connect.code.revoke', resourceType: 'connect', resourceId: record.id,
        resourceName: record.codeMask, result: 'ok', detail: '作废未使用接入码',
      })
      exchange.ok({ id: record.id, status: 'revoked' })
    }, { access: 'guarded', permission: 'connect.manage' })

    // -- Gestion des clients connectés -----------------------------------------------------
    http.register('GET', '/api/connect/clients', (exchange) => {
      if (!requireManage(exchange)) return
      const clients = clientsCollection(ctx).all()
        .sort((a, b) => b.enrolledAt.localeCompare(a.enrolledAt))
        .map((client) => {
          const principal = ctx.authn.principals().get(client.principalId)
          const activeTokens = ctx.authn.activeTokenCount(client.principalId)
          const tokens = ctx.authn.tokens().find((item) => item.principalId === client.principalId)
          const lastUsedAt = tokens
            .map((token) => token.lastUsedAt ?? '')
            .filter(Boolean)
            .sort()
            .at(-1) ?? ''
          return {
            ...client,
            scopes: principal?.scopes ?? [],
            principalStatus: principal?.status ?? 'disabled',
            activeTokens,
            lastUsedAt,
          }
        })
      exchange.ok({ clients, templates: connectTemplates() })
    }, { access: 'guarded', permission: 'connect.manage' })

    http.register('POST', '/api/connect/clients/:id/disable', (exchange) => {
      if (!requireManage(exchange)) return
      const input = (exchange.body ?? {}) as { reason?: string }
      const reason = (input.reason ?? '').trim()
      if (!reason) { exchange.fail(400, 'BAD_REQUEST', translate('禁用原因必填（留痕要求）')); return }
      const client = findClient(ctx, exchange.params["id"]!)
      if (!client) { exchange.fail(404, 'NOT_FOUND', translate('客户端不存在')); return }
      ctx.authn.disablePrincipal(client.principalId, translate('接入客户端禁用：{reason}', { reason }))
      clientsCollection(ctx).update(client.id, { status: 'disabled' })
      const info = exchange.principal as { userId?: string; principalId?: string; name?: string }
      ctx.audit.record({
        type: 'change', actorType: 'human', actorId: info?.userId ?? info?.principalId ?? 'api', actorName: info?.name ?? 'api',
        action: 'connect.client.disable', resourceType: 'connect', resourceId: client.id,
        resourceName: client.name, result: 'ok', detail: translate('原因：{reason}（联动吊销全部令牌）', { reason }),
        })
        ctx.platformBus.emit(PlatformEvents.ConnectClientDisabled, { principalId: client.principalId, name: client.name, reason })
        exchange.ok({ id: client.id, status: 'disabled' })
    }, { access: 'guarded', permission: 'connect.manage' })

    http.register('POST', '/api/connect/clients/:id/enable', (exchange) => {
      if (!requireManage(exchange)) return
      const client = findClient(ctx, exchange.params["id"]!)
      if (!client) { exchange.fail(404, 'NOT_FOUND', translate('客户端不存在')); return }
      ctx.authn.enablePrincipal(client.principalId)
      clientsCollection(ctx).update(client.id, { status: 'active' })
      const info = exchange.principal as { userId?: string; principalId?: string; name?: string }
      ctx.audit.record({
        type: 'change', actorType: 'human', actorId: info?.userId ?? info?.principalId ?? 'api', actorName: info?.name ?? 'api',
        action: 'connect.client.enable', resourceType: 'connect', resourceId: client.id,
        resourceName: client.name, result: 'ok', detail: translate('恢复接入客户端'),
      })
      exchange.ok({ id: client.id, status: 'active' })
    }, { access: 'guarded', permission: 'connect.manage' })
  },
}

// ---------------------------------------------------------------------------
// Outils exposés au modèle côté hôte (l'Agent dsh gère les accès en langage naturel côté hôte)
// ---------------------------------------------------------------------------

export const connectHostTools = {
  name: 'connect-host-tools',
  inject: ['tools', 'authn', 'audit', 'platformBus'],
  apply(ctx: Context) {
    const t = ctx.tools

    t.register(defineTool({
      name: 'connect_code_create',
      description: '创建一次性接入码（远程 dsh/Agent 凭此向本平台申请机器凭证）。默认只读模板、15 分钟有效。',
      permission: 'connect.manage',
      parameters: {
        template: { type: 'string', enum: ['readonly', 'operator', 'executor', 'full'], description: '权限模板：readonly 只读 / operator 运维（读+资源变更，不含任务执行）/ executor 执行方（读+任务认领执行）/ full 全权限' },
        ttlMinutes: { type: 'integer', description: '有效分钟数（1-1440，默认 15）' },
        remark: { type: 'string', description: '用途备注（留痕）' },
      },
      output: { type: 'object', additionalProperties: true },
      async execute(args) {
        const code = generateSecret('enr')
        const template = (args.template ?? 'readonly') as TemplateName
        const ttlMinutes = Math.min(Math.max(Math.floor(Number(args.ttlMinutes) || 15), 1), MAX_TTL_MINUTES)
        const record = codesCollection(ctx).insert({
          id: newId('enc'),
          codeHash: sha256Hex(code),
          codeMask: mask(code, 6),
          template,
          remark: String(args.remark ?? '').slice(0, 120),
          createdBy: 'tool:connect_code_create',
          createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + ttlMinutes * 60_000).toISOString(),
        })
        return {
          code, codeMask: record.codeMask, template, ttlMinutes, expiresAt: record.expiresAt,
          notice: translate('接入码仅本次返回、一次性消费：交给远程电脑执行 connect_setup { hubUrl, enrollmentCode } 即完成接入'),
        }
      },
    }))

    t.register(defineTool({
      name: 'connect_codes',
      description: '列出接入码（含使用状态：active 已用/过期/作废）。',
      permission: 'connect.manage',
      parameters: {},
      output: { type: 'object', additionalProperties: true },
      async execute() {
        const now = Date.now()
        const codes = codesCollection(ctx).all().sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        return {
          total: codes.length,
          codes: codes.map((record) => ({
            codeMask: record.codeMask, template: record.template, remark: record.remark,
            createdBy: record.createdBy, createdAt: record.createdAt, expiresAt: record.expiresAt,
            usedAt: record.usedAt ?? '', usedBy: record.usedBy ?? '',
            status: record.revokedAt ? 'revoked' : record.usedAt ? 'used' : new Date(record.expiresAt).getTime() < now ? 'expired' : 'active',
          })),
        }
      },
    }))

    t.register(defineTool({
      name: 'connect_clients',
      description: '列出已接入的远程 dsh/Agent 客户端（含权限模板、最近使用、最近心跳、令牌数）。',
      permission: 'connect.manage',
      parameters: {},
      output: { type: 'object', additionalProperties: true },
      async execute() {
        const clients = clientsCollection(ctx).all().sort((a, b) => b.enrolledAt.localeCompare(a.enrolledAt))
        return {
          total: clients.length,
          clients: clients.map((client) => ({
            name: client.name, clientId: client.clientId, template: client.template,
            hostname: client.hostname, platform: client.platform,
            enrolledAt: client.enrolledAt, status: client.status,
            lastHeartbeatAt: client.lastHeartbeatAt ?? '', heartbeat: client.heartbeat ?? {},
            activeTokens: ctx.authn.activeTokenCount(client.principalId),
          })),
        }
      },
    }))

    t.register(defineTool({
      name: 'connect_client_disable',
      description: '禁用接入客户端（联动吊销其全部令牌，远程工具调用立即失效）。必须给出 reason。',
      permission: 'connect.manage',
      parameters: {
        clientId: { type: 'string', required: true, description: '客户端 clientId（mc- 开头）' },
        reason: { type: 'string', required: true, description: '禁用原因（永久留痕）' },
      },
      output: { type: 'object', additionalProperties: true },
      async execute(args) {
        const client = clientsCollection(ctx).findOne((item) => item.clientId === String(args.clientId))
        if (!client) throw new Error(translate('接入客户端不存在：{id}', { id: String(args.clientId) }))
        ctx.authn.disablePrincipal(client.principalId, translate('接入客户端禁用：{reason}', { reason: String(args.reason) }))
        clientsCollection(ctx).update(client.id, { status: 'disabled' })
        ctx.audit.record({
          type: 'change', actorType: 'machine', actorId: 'tool:connect_client_disable', actorName: 'dsh Agent',
          action: 'connect.client.disable', resourceType: 'connect', resourceId: client.id,
          resourceName: client.name, result: 'ok', detail: translate('原因：{reason}', { reason: String(args.reason) }),
        })
        ctx.platformBus.emit(PlatformEvents.ConnectClientDisabled, { principalId: client.principalId, name: client.name, reason: String(args.reason) })
        return { id: client.id, name: client.name, status: 'disabled', note: translate('已联动吊销全部令牌') }
      },
    }))
  },
}
