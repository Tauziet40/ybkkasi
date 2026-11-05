/**
 * @dsh-ops/platform-core —— pipeline d'événements comportementaux behavior (action-plan-dsh-frontend WP-03 / décisions D3, D6).
 *
 * Séparation entre l'instrumentation comportementale frontend (exposition/clic de cartes, emplacements de recommandation, tunnel d'enregistrement) et la mesure d'appels (usage) :
 *   - D3 : les événements comportementaux ont leur propre `behavior.recorded`, sans mélange dans le pipeline de mesure usage (évite de polluer le périmètre de facturation) ;
 *   - D6 : le point d'accès appartient à platform-core (ce fichier), avec la même sémantique que usage « écrire d'abord puis émettre + idempotence + lettres mortes + rejeu » ;
 *   - point de collecte write-only POST /api/behavior/events (authentification iam : 401 systématique si non authentifié,
 *     le sujet authentifié est le sujet de l'événement, empêche la falsification du flux comportemental d'autrui) ; requête en lecture GET /api/behavior/events (audit.read,
 *     facette d'abonnement audit/tableau de bord). audit et les futurs tableaux de bord s'abonnent via ctx.behavior.consume() ou platformBus.
 *
 * schema v1 (additive-only, même discipline que usage) : les champs ne font que croître, jamais modifiés ni supprimés, les consommateurs tolèrent les nouveaux champs inconnus.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId } from './ids.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type { Collection, RecordBase } from './storage.ts'

export const BEHAVIOR_SCHEMA = 'behavior.recorded'
export const BEHAVIOR_SCHEMA_VERSION = 1

/** Événement behavior.recorded v1 (append-only, interdiction de changer de version ; extension uniquement par ajout de champs optionnels). */
export interface BehaviorEvent {
  schema: typeof BEHAVIOR_SCHEMA
  schema_version: number
  event_id: string
  idempotency_key: string
  occurred_at: string
  tenant_id: string
  /** Organisation propriétaire de l'événement (nullable : un sujet machine peut manquer de contexte organisationnel). */
  org?: string
  /** Sujet de l'événement : user:<id> | agent:<id> | app:<id> | machine:<principalId>. */
  subject: string
  /** Type d'événement (clé pointue en minuscules) : card.exposed / card.clicked / funnel.step / recommend.impression … */
  type: string
  /** Plateforme/borne d'origine (cinq plateformes différenciées + trois points d'entrée) : strategy | marketing | manufacturing | rd | quality | console | portal | dingtalk | dsh */
  platform?: string
  /** Contexte métier (objet libre, ≤4 Ko) : ref de carte, étape du tunnel, cible de saut, etc. */
  payload?: Record<string, unknown>
  trace_id?: string
}

/** Paramètres d'entrée de l'enregistrement d'événement comportemental (sur la facette de collecte HTTP, subject est dérivé de force du sujet authentifié ; les entrées ne contiennent pas subject). */
export interface BehaviorRecordInput {
  org?: string
  subject?: string
  type: string
  platform?: string
  payload?: Record<string, unknown>
  idempotency_key?: string
  occurred_at?: string
  trace_id?: string
}

/** Lettres mortes (événements ayant échoué 3 fois à la consommation). */
export interface BehaviorDeadLetter extends RecordBase {
  event_id: string
  consumer: string
  error: string
  attempts: number
}

export type BehaviorConsumer = (event: BehaviorEvent) => void

const PAYLOAD_MAX_BYTES = 4096

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

const DEFAULT_TENANT = 't_default'

interface BehaviorRow {
  id: string
  idempotency_key: string
  schema_version: number
  occurred_at: string
  tenant_id: string
  org: string
  subject: string
  type: string
  platform: string
  payload_json: string
  trace_id: string
}

function behaviorRow(event: BehaviorEvent): Record<string, string | number> {
  return {
    id: event.event_id,
    idempotency_key: event.idempotency_key,
    schema_version: event.schema_version,
    occurred_at: event.occurred_at,
    tenant_id: event.tenant_id,
    org: event.org ?? '',
    subject: event.subject,
    type: event.type,
    platform: event.platform ?? '',
    payload_json: JSON.stringify(event.payload ?? {}),
    trace_id: event.trace_id ?? '',
  }
}

function rowToEvent(row: BehaviorRow): BehaviorEvent {
  return {
    schema: BEHAVIOR_SCHEMA,
    schema_version: row.schema_version,
    event_id: row.id,
    idempotency_key: row.idempotency_key,
    occurred_at: row.occurred_at,
    tenant_id: row.tenant_id,
    ...(row.org !== '' ? { org: row.org } : {}),
    subject: row.subject,
    type: row.type,
    ...(row.platform !== '' ? { platform: row.platform } : {}),
    ...(row.payload_json !== '{}' ? { payload: JSON.parse(row.payload_json) as Record<string, unknown> } : {}),
    ...(row.trace_id !== '' ? { trace_id: row.trace_id } : {}),
  }
}

export class BehaviorService extends Service {
  static readonly provide = 'behavior'
  static readonly inject = ['txnStore', 'platformBus', 'httpServer']

  private consumers = new Map<string, { handler: BehaviorConsumer; attempts: Map<string, number> }>()
  private seq = 0

  constructor(ctx: Context) {
    super(ctx, 'behavior')
    ctx.txnStore.ensureTable('behavior_events', {
      id: 'TEXT',
      idempotency_key: 'TEXT NOT NULL',
      schema_version: 'INTEGER NOT NULL',
      occurred_at: 'TEXT NOT NULL',
      tenant_id: 'TEXT NOT NULL',
      org: "TEXT NOT NULL DEFAULT ''",
      subject: 'TEXT NOT NULL',
      type: 'TEXT NOT NULL',
      platform: "TEXT NOT NULL DEFAULT ''",
      payload_json: 'TEXT NOT NULL',
      trace_id: "TEXT NOT NULL DEFAULT ''",
    }, { uniques: [['idempotency_key']], indexes: [['occurred_at'], ['type'], ['subject']] })
    // Niveau de consommation (idempotence au niveau moteur) : même discipline que usage — replay/reprise ne produit pas d'effets de bord dupliqués
    ctx.txnStore.ensureTable('behavior_consumptions', {
      consumer: 'TEXT NOT NULL',
      event_id: 'TEXT NOT NULL',
      at: 'TEXT NOT NULL',
    }, { primaryKey: ['consumer', 'event_id'] })
    this.registerHttpEndpoints(ctx)
    ctx.effect(() => () => {
      this.consumers.clear()
    })
  }

  /** Collecte write-only (route publique montée après le middleware d'authentification console ; revalidation du sujet ici, double couche fail-closed). */
  private registerHttpEndpoints(ctx: Context): void {
    const http = ctx.httpServer
    http.register('POST', '/api/behavior/events', (exchange) => {
      // Quand le middleware d'authentification console n'est pas monté (assemblage anormal), principal est toujours vide : on refuse le service plutôt que de laisser passer
      const principal = exchange.principal as { permissions?: string[]; userId?: string; kind?: string; principalId?: string } | undefined
      if (!principal || !Array.isArray(principal.permissions)) {
        exchange.fail(401, 'UNAUTHORIZED', t('缺少 Bearer 令牌，请先登录'))
        return
      }
      const input = (exchange.body ?? {}) as BehaviorRecordInput
      // Le sujet de l'événement est forcément le sujet authentifié : l'instrumentation décrit seulement « qui a fait quoi », pas d'attribution d'autrui via le corps de requête
      const subject = principal.userId ? `user:${principal.userId}` : `${principal.kind ?? 'machine'}:${principal.principalId ?? 'unknown'}`
      try {
        const result = this.record({ ...input, subject })
        exchange.ok({ event: result.event, duplicated: result.duplicated })
      } catch (error) {
        exchange.fail(400, 'BAD_REQUEST', error instanceof Error ? error.message : String(error))
      }
    }, { access: 'authenticated' })
    http.register('GET', '/api/behavior/events', (exchange) => {
      const principal = exchange.principal as { permissions?: string[] } | undefined
      if (!principal || !Array.isArray(principal.permissions)) {
        exchange.fail(401, 'UNAUTHORIZED', t('缺少 Bearer 令牌，请先登录'))
        return
      }
      if (!principal.permissions.includes('*') && !principal.permissions.includes('audit.read')) {
        ctx.platformBus.emit('audit.authz.denied', {
          actorId: (exchange.principal as { userId?: string }).userId,
          point: 'audit.read',
          path: exchange.path,
        })
        exchange.fail(403, 'FORBIDDEN', t('缺少权限点 {point}，请联系管理员调整角色', { point: 'audit.read' }), { permission: 'audit.read' })
        return
      }
      const query = exchange.query
      exchange.ok(this.query({
        ...(query.get('type') ? { type: query.get('type')! } : {}),
        ...(query.get('subject') ? { subject: query.get('subject')! } : {}),
        ...(query.get('from') ? { from: query.get('from')! } : {}),
        ...(query.get('to') ? { to: query.get('to')! } : {}),
        ...(query.get('limit') ? { limit: Number(query.get('limit')) } : {}),
      }))
    }, { access: 'guarded', permission: 'audit.read' })
  }

  /** Entrée unique d'événements comportementaux de toute la plateforme : validation → écriture (idempotente) → distribution par le bus. Renvoie duplicated pour signaler un rejeu idempotent. */
  record(input: BehaviorRecordInput): { event: BehaviorEvent; duplicated: boolean } {
    this.validate(input)
    const event: BehaviorEvent = {
      schema: BEHAVIOR_SCHEMA,
      schema_version: BEHAVIOR_SCHEMA_VERSION,
      event_id: newId('bevt'),
      idempotency_key: input.idempotency_key ?? `behavior:${input.subject}:${input.type}:${new Date().toISOString().slice(0, 16)}:${++this.seq}`,
      occurred_at: input.occurred_at ?? new Date().toISOString(),
      tenant_id: DEFAULT_TENANT,
      ...(input.org ? { org: input.org } : {}),
      subject: input.subject!,
      type: input.type,
      ...(input.platform ? { platform: input.platform } : {}),
      ...(input.payload !== undefined ? { payload: input.payload } : {}),
      ...(input.trace_id !== undefined ? { trace_id: input.trace_id } : {}),
    }
    const inserted = this.ctx.txnStore.insertOrIgnore('behavior_events', behaviorRow(event))
    if (!inserted) {
      const existing = this.ctx.txnStore.one<BehaviorRow>('behavior_events', { idempotency_key: event.idempotency_key })
      if (!existing) throw new Error(t('幂等键异常：{key} 已占用但记录缺失', { key: event.idempotency_key }))
      const sameContent = existing.subject === event.subject && existing.type === event.type
        && existing.payload_json === JSON.stringify(event.payload ?? {})
      if (!sameContent) {
        throw new Error(t('幂等键冲突：{key} 已绑定事件 {id}，同键不同内容被拒绝', { key: event.idempotency_key, id: existing.id }))
      }
      return { event: rowToEvent(existing), duplicated: true }
    }
    this.dispatch(event)
    return { event, duplicated: false }
  }

  /** Enregistre un consommateur (at-least-once ; 3 échecs → lettre morte). */
  consume(consumerId: string, handler: BehaviorConsumer): () => void {
    this.consumers.set(consumerId, { handler, attempts: new Map() })
    return () => this.consumers.delete(consumerId)
  }

  /**
   * Distribution : diffusion par le bus d'abord, puis livraison consommateur par consommateur selon le niveau (insertOrIgnore comme marque → 3 échecs → lettre morte + alerte).
   * Même « effet exactement une fois » que usage : rejeu/reprise sautés idempotemment via le niveau.
   */
  private dispatch(event: BehaviorEvent): void {
    this.ctx.platformBus.emit(BEHAVIOR_SCHEMA, event)
    for (const [consumerId, entry] of this.consumers) {
      const claimed = this.ctx.txnStore.insertOrIgnore('behavior_consumptions', {
        consumer: consumerId, event_id: event.event_id, at: new Date().toISOString(),
      })
      if (!claimed) continue
      let delivered = false
      for (let attempt = 1; attempt <= 3 && !delivered; attempt++) {
        try {
          entry.handler(event)
          entry.attempts.delete(`${consumerId}:${event.event_id}`)
          delivered = true
        } catch (error) {
          if (attempt < 3) continue
          this.ctx.txnStore.run('DELETE FROM behavior_consumptions WHERE consumer = ? AND event_id = ?', [consumerId, event.event_id])
          this.deadLetters().insert({
            id: newId('bdl'), event_id: event.event_id, consumer: consumerId,
            error: error instanceof Error ? error.message : String(error), attempts: attempt,
          })
          this.ctx.platformBus.emit('audit.alert.fired', {
            id: newId('alt'), severity: 'critical', title: t('behavior 消费死信'),
            message: t('消费方 {consumer} 处理行为事件 {id} 连续失败 {attempts} 次，已入死信，可经 behavior 重投恢复', { consumer: consumerId, id: event.event_id, attempts: attempt }),
          })
        }
      }
    }
  }

  /** Événements dans la fenêtre de rejeu (l'idempotence est garantie par le niveau de consommation). */
  replay(sinceIso: string): { replayed: number } {
    const rows = this.ctx.txnStore.sql<BehaviorRow>(
      'SELECT * FROM behavior_events WHERE occurred_at >= ? ORDER BY occurred_at',
      [sinceIso],
    )
    for (const row of rows) this.dispatch(rowToEvent(row))
    return { replayed: rows.length }
  }

  /** Reprise des lettres mortes : sortie de la file dès le succès. Renvoie {retried, remaining}. */
  retryDeadLetters(): { retried: number; remaining: number } {
    const letters = this.deadLetters().all()
    let retried = 0
    for (const letter of letters) {
      const row = this.ctx.txnStore.one<BehaviorRow>('behavior_events', { id: letter.event_id })
      if (!row) {
        this.deadLetters().remove(letter.id)
        continue
      }
      const consumer = this.consumers.get(letter.consumer)
      if (!consumer) continue
      this.deadLetters().remove(letter.id)
      try {
        const claimed = this.ctx.txnStore.insertOrIgnore('behavior_consumptions', {
          consumer: letter.consumer, event_id: letter.event_id, at: new Date().toISOString(),
        })
        if (!claimed) {
          retried++
          continue
        }
        consumer.handler(rowToEvent(row))
        retried++
      } catch (error) {
        this.deadLetters().insert({
          id: newId('bdl'), event_id: letter.event_id, consumer: letter.consumer,
          error: t('重投仍失败：{message}', { message: error instanceof Error ? error.message : String(error) }), attempts: letter.attempts + 1,
        })
      }
    }
    return { retried, remaining: this.deadLetters().count() }
  }

  /** Requête en lecture seule (facette d'abonnement audit/tableau de bord, contrôle audit.read sur le point GET). */
  query(filter: { type?: string; subject?: string; from?: string; to?: string; limit?: number } = {}): { total: number; items: BehaviorEvent[] } {
    const conditions: string[] = []
    const params: Array<string | number> = []
    if (filter.type) { conditions.push('type = ?'); params.push(filter.type) }
    if (filter.subject) { conditions.push('subject = ?'); params.push(filter.subject) }
    if (filter.from) { conditions.push('occurred_at >= ?'); params.push(filter.from) }
    if (filter.to) { conditions.push('occurred_at <= ?'); params.push(filter.to) }
    const where = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : ''
    const rows = this.ctx.txnStore.sql<BehaviorRow>(`SELECT * FROM behavior_events${where} ORDER BY occurred_at DESC LIMIT ?`, [...params, Math.min(filter.limit ?? 100, 1000)])
    const total = Number((this.ctx.txnStore.sql<{ n: number }>(`SELECT COUNT(*) AS n FROM behavior_events${where}`, params)[0] ?? { n: 0 }).n)
    return { total, items: rows.map(rowToEvent) }
  }

  deadLetters(): Collection<BehaviorDeadLetter> {
    return this.ctx.opsStorage.collection<BehaviorDeadLetter>('behavior:deadLetters')
  }

  // -- Interne -----------------------------------------------------------------

  private validate(input: BehaviorRecordInput): void {
    if (!input.type?.trim() || !/^[a-z][a-z0-9_.]*$/.test(input.type)) {
      throw new Error(t('behavior 事件 type 非法：{value}（应为点分小写键，如 card.exposed / funnel.step）', { value: String(input.type) }))
    }
    if (!input.subject?.trim() || !/^[a-z][a-z0-9]*:[A-Za-z0-9._-]+$/.test(input.subject)) {
      throw new Error(t('behavior 事件 subject 非法：{value}（应为 user:<id> / agent:<id> / machine:<principalId>）', { value: String(input.subject) }))
    }
    if (input.platform !== undefined && !/^[a-z][a-z0-9_-]*$/.test(input.platform)) {
      throw new Error(t('behavior 事件 platform 非法：{value}（小写标识，如 rd / quality / console / dingtalk）', { value: input.platform }))
    }
    if (input.payload !== undefined) {
      if (typeof input.payload !== 'object' || Array.isArray(input.payload) || input.payload === null) {
        throw new Error(t('behavior 事件 payload 必须是对象'))
      }
      if (Buffer.byteLength(JSON.stringify(input.payload), 'utf8') > PAYLOAD_MAX_BYTES) {
        throw new Error(t('behavior 事件 payload 超限（>{max} 字节），请精简上下文', { max: PAYLOAD_MAX_BYTES }))
      }
    }
    if (input.occurred_at !== undefined && Number.isNaN(new Date(input.occurred_at).getTime())) {
      throw new Error(t('behavior 事件 occurred_at 非法：{value}', { value: input.occurred_at }))
    }
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    behavior: BehaviorService
  }
}
