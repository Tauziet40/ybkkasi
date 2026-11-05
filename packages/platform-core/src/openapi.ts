/**
 * Projection de la facette API en OpenAPI (issue #6) : transforme le registre complet des routes du httpServer (declaredRoutes, liste de passation H5)
 * en document OpenAPI 3.0.3, pour que les Agents/clients tiers découvrent de façon lisible par machine la facette REST et ses exigences d'authentification.
 *
 * Le registre est l'unique source de vérité — chaque register() y écrit une entrée, la documentation se synchronise automatiquement avec l'enregistrement des routes, sans seconde liste d'interfaces à maintenir
 * (même périmètre que /api/platform/route-matrix). Les déclarations de routes ne portent que method / path / profil d'authentification, sans schéma de
 * paramètres ni de réponses par point ; la documentation décrit donc « facette d'interfaces + exigences d'authentification + enveloppe unifiée », le contrat champ par champ reste régi par le
 * manifest de chaque plugin (api.yaml) ; les deux sont réconciliés par lint:manifests, sans modélisation dupliquée ici.
 */
import type { RouteLedgerEntry } from './http.ts'
import { t } from '../../platform-i18n/src/index.ts'

export interface OpenApiBuildOptions {
  /** Version de la plateforme (info.version, issue de platformVersionInfo().version). */
  version: string
  /** Préfixe de montage externe ('' ou '/rq', voir HttpServerConfig.externalBase), projeté en servers[0].url. */
  externalBase?: string
}

/** `/api/iam/users/:id` → `/api/iam/users/{id}`, et renvoie la liste des noms de paramètres de chemin. */
export function toOpenApiPath(pattern: string): { path: string; params: string[] } {
  const params: string[] = []
  const path = pattern.split('/').map((segment) => {
    if (!segment.startsWith(':')) return segment
    const name = segment.slice(1)
    params.push(name)
    return `{${name}}`
  }).join('/')
  return { path: path || '/', params }
}

/** Étiquette de groupe : /api/<domaine>/… → nom de domaine ; facettes de protocole hors /api (/mcp, /oauth, /docs…) → premier segment. */
function tagOf(pattern: string): string {
  const segments = pattern.split('/').filter(Boolean)
  if (segments[0] === 'api') return segments[1] ?? 'api'
  return segments[0] ?? 'root'
}

/** operationId : identifiantisation de method + chemin (les segments paramètres comme `{id}` conservent le nom du paramètre). */
function operationIdOf(method: string, openApiPath: string): string {
  const slug = openApiPath.replace(/[{}]/g, '').replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')
  return `${method.toLowerCase()}_${slug || 'root'}`
}

export function buildOpenApiDocument(routes: readonly RouteLedgerEntry[], options: OpenApiBuildOptions): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {}
  const tags = new Set<string>()
  // Sortie stable : triée par chemin puis méthode ; en cas d'enregistrements multiples du même method+path (réenregistrement idempotent), seule la première entrée est conservée
  const sorted = [...routes].sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))
  for (const route of sorted) {
    const { path, params } = toOpenApiPath(route.path)
    const method = route.method.toLowerCase()
    const item = (paths[path] ??= {})
    if (item[method] !== undefined) continue
    const tag = tagOf(route.path)
    tags.add(tag)
    const auth = route.auth
    const envelope = auth.access !== 'outside-api'
    const operation: Record<string, unknown> = {
      operationId: operationIdOf(method, path),
      tags: [tag],
      ...(params.length > 0
        ? { parameters: params.map((name) => ({ name, in: 'path', required: true, schema: { type: 'string' } })) }
        : {}),
      responses: envelope
        ? {
          '200': {
            description: t('成功：统一信封 { ok: true, data }'),
            content: { 'application/json': { schema: { $ref: '#/components/schemas/OkEnvelope' } } },
          },
          default: {
            description: t('失败：统一信封 { ok: false, error: { code, message } }（401 未认证 / 403 缺权限点 / 404 不存在 / 422 校验失败）'),
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorEnvelope' } } },
          },
        }
        : { default: { description: t('协议面响应（OAuth / MCP JSON-RPC / 文档页等，不走统一信封）') } },
      // Déclaration d'authentification précise (même périmètre que route-matrix) : guarded=protégé par point de permission ; authenticated=Bearer seul ;
      // public=sans authentification (selfValidated=le handler valide lui-même les identifiants) ; outside-api=authentification auto-gérée par la facette protocole
      'x-auth': { ...auth },
    }
    if (auth.access === 'guarded') {
      operation.security = [{ bearerAuth: [] }]
      operation['x-permission'] = auth.permission
    } else if (auth.access === 'authenticated') {
      operation.security = [{ bearerAuth: [] }]
    } else if (auth.access === 'public') {
      operation.security = []
    }
    item[method] = operation
  }
  const externalBase = (options.externalBase ?? '').replace(/\/+$/, '')
  return {
    openapi: '3.0.3',
    info: {
      title: t('元冰可 · 企业 AI 资源统一管理平台 API'),
      version: options.version,
      description: t('由运行时路由台账自动生成：覆盖全部已注册端点及其鉴权要求（x-auth / x-permission）。/api/* 响应为统一 JSON 信封；逐字段契约见各插件 manifest（api.yaml）。'),
    },
    servers: [{ url: externalBase || '/' }],
    tags: [...tags].sort().map((name) => ({ name })),
    paths,
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          description: t('平台令牌（人类账号 POST /api/auth/login 换取，或机器凭证签发）；/mcp 与 REST 共用同一套令牌'),
        },
      },
      schemas: {
        OkEnvelope: {
          type: 'object',
          required: ['ok'],
          properties: { ok: { type: 'boolean', enum: [true] }, data: {} },
        },
        ErrorEnvelope: {
          type: 'object',
          required: ['ok', 'error'],
          properties: {
            ok: { type: 'boolean', enum: [false] },
            error: {
              type: 'object',
              required: ['code', 'message'],
              properties: { code: { type: 'string' }, message: { type: 'string' } },
              additionalProperties: true,
            },
          },
        },
      },
    },
  }
}
