/**
 * NasShareLinkService — liens de partage signés NAS (URL signée HMAC + revérification de permissions + révocables).
 *
 * Fondements : liste de passation docs-20260921 « signature des liens de téléchargement NAS » (décisions ①②③ entérinées côté produit) :
 * - remplace le billet codé en dur de 10 minutes : paliers 1 h / 24 h (défaut) / 7 j / 30 j / permanent ;
 * - décision ① (généralisée à tous les paliers) : la signature emploie une **clé longue durée dédiée** (`nas-share-link-secret`)
 *   totalement découplée de la clé des jetons authn — la rotation des jetons ne perce pas les liens longs ; après rotation, l'ancienne clé entre dans l'**ensemble retraite permanente**
 *   (`nas-share-link-secret-history.json`) et continue de servir à la vérification ; les liens déjà émis ne meurent pas d'une action d'exploitation ;
 * - signature sans état (exp/sub/jti tous dans la charge, survit au redémarrage) + révocation avec état (nas:shareLinks en base) ;
 * - trois barrières fail-closed pour prendre le flux : signature → révocation → revérification de permissions (nasAuthz.check op='download', sous l'identité de l'émetteur).
 *
 * Sémantique fail-closed de la clé (décision ①) : fichier de clé absent (premier démarrage) → génération et écriture ;
 * présent mais illisible/non inscriptible → état de panne, l'émission échoue bruyamment (KEY_UNAVAILABLE), jamais de nouvelle clé en silence.
 */
import { createHmac } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { generateSecret, newId, sha256Hex, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { NasAuthzService, type ShareLinkPolicy } from './authz.ts'
import { normalizePath } from './authz/engine.ts'

// ---------------------------------------------------------------------------
// Modèle de données et paliers
// ---------------------------------------------------------------------------

/** Enregistrement d'émission (nas:shareLinks, durable : une révocation renvoyant 200 puis un crash ne doit rien perdre). L'id est le jti. */
export interface ShareLinkRecord extends RecordBase {
  nasId: string
  path: string
  /** Principal émetteur (sujet d'audit ; réutilisé comme actor à la prise de flux). */
  principalId: string
  /** userId de l'émetteur (identité de la revérification de permissions) ; une identité machine ne peut pas émettre, toujours renseigné. */
  userId: string
  userName: string
  mode: 'link'
  /** Temps ISO ; lien permanent = null (l'UI/l'audit marque explicitement « permanent », sans ambiguïté). */
  expiresAt: string | null
  /** Identifiant de la clé longue durée employée à l'émission (12 premiers caractères de sha256(secret) ; permet de localiser les liens affectés après rotation). */
  keyId: string
  note?: string
  revokedAt?: string
  revokedBy?: string
  revokeReason?: string
  lastUsedAt?: string
  useCount: number
}

export type ShareLinkTier = '1h' | '24h' | '7d' | '30d' | 'permanent' | 'custom'

/** Préréglages de paliers (décision ② : défaut 24 h ; 30 jours et permanent relèvent d'un choix explicite, ni présélection ni repli). */
export const SHARE_LINK_TTL_PRESETS: Array<{ tier: ShareLinkTier; ttlSec: number; label: string }> = [
  { tier: '1h', ttlSec: 3600, label: '1 小时' },
  { tier: '24h', ttlSec: 86400, label: '24 小时' },
  { tier: '7d', ttlSec: 604800, label: '7 天' },
  { tier: '30d', ttlSec: 2592000, label: '30 天' },
]

/** Valeurs par défaut de politique (décisions ②③ : plafond 30 jours ; permanent fermé par défaut, ouvert il est limité aux détenteurs de permanentPermission). */
export const DEFAULT_SHARE_LINK_POLICY: ShareLinkPolicy = {
  maxTtlSec: 2592000,
  allowPermanent: false,
  permanentPermission: 'nas.authz.write',
}

/** Échec d'émission porteur de sémantique (la couche REST expose httpStatus/code, sans l'avaler en un 400 générique). */
export class ShareLinkError extends Error {
  readonly code: string
  readonly httpStatus: number
  constructor(code: string, message: string, httpStatus: number = 400) {
    super(message)
    this.name = 'ShareLinkError'
    this.code = code
    this.httpStatus = httpStatus
  }
}

export type ShareLinkVerdict =
  | { outcome: 'ok'; record: ShareLinkRecord }
  | { outcome: 'invalid'; reason: string }
  | { outcome: 'forbidden'; reasons: string[] }

const EXPIRED_CLEANUP_DELAY_MS = 7 * 24 * 3600_000

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export class NasShareLinkService extends Service {
  static readonly provide = 'nasShareLinks'

  /** nasAuthz est un service du même plugin : déclaré via Service.inject (l'inject au niveau extension ne se référence pas soi-même, contre l'impasse au chargement). */
  static readonly inject = ['nasAuthz']

  private currentSecret: string | undefined
  private currentKeyId: string | undefined
  /** État de panne de la clé (présente mais illisible/non inscriptible) : posé, l'émission échoue bruyamment, la vérification pareillement fail-closed. */
  private keyError: string | undefined
  /** Ensemble des clés en retraite permanente (décision ① entérinée (a) : après rotation, l'ancienne clé reste à vie pour la vérification, les liens émis ne meurent pas de la rotation). */
  private retiredSecrets: Array<{ secret: string; keyId: string; retiredAt: number; note?: string }> = []
  private cleanupTimer: ReturnType<typeof setInterval> | undefined

  constructor(ctx: Context) {
    super(ctx, 'nasShareLinks')
    this.ctx.opsStorage.collection<ShareLinkRecord>('nas:shareLinks', { durability: 'durable' })
    this.loadKey()
    this.loadRetiredSecrets()
    this.cleanupExpired()
    // Nettoyage glissant des enregistrements expirés (sur le modèle authn : suppression physique 7 jours après expiration ; les permanents/non expirés intouchés)
    this.cleanupTimer = setInterval(() => this.cleanupExpired(), 3600_000)
    this.cleanupTimer.unref?.() // lint-timers : les formes test/intégrée permettent la sortie naturelle du processus
    ctx.effect(() => () => {
      if (this.cleanupTimer) clearInterval(this.cleanupTimer)
    })
  }

  links(): Collection<ShareLinkRecord> {
    return this.ctx.opsStorage.collection<ShareLinkRecord>('nas:shareLinks')
  }

  private get nasAuthz(): NasAuthzService {
    return this.ctx.nasAuthz
  }

  // -- Clé longue durée dédiée (décision ①) -------------------------------------------------

  private keyFilePath(): string {
    return join(this.ctx.opsStorage.dataDirPath, 'nas-share-link-secret')
  }

  private historyFilePath(): string {
    return join(this.ctx.opsStorage.dataDirPath, 'nas-share-link-secret-history.json')
  }

  private keyIdOf(secret: string): string {
    return sha256Hex(secret).slice(0, 12)
  }

  /** Générée au premier démarrage, idempotente sans écrasement ; présente mais illisible → état de panne (pas de nouvelle clé en silence, sinon tous les liens déjà émis mourraient). */
  private loadKey(): void {
    const file = this.keyFilePath()
    try {
      if (existsSync(file)) {
        const secret = readFileSync(file, 'utf8').trim()
        if (!secret) throw new Error(t('密钥文件为空'))
        this.currentSecret = secret
        this.currentKeyId = this.keyIdOf(secret)
        return
      }
      mkdirSync(this.ctx.opsStorage.dataDirPath, { recursive: true })
      const secret = generateSecret('nsl')
      writeFileSync(file, secret, { encoding: 'utf8', mode: 0o600 })
      this.currentSecret = secret
      this.currentKeyId = this.keyIdOf(secret)
    } catch (error) {
      this.keyError = error instanceof Error ? error.message : String(error)
      console.error(`[nasShareLinks] 分享链接签名密钥不可用（${this.keyError}）——签发已拒绝（fail-closed），既有链接验签同样拒绝；请修复 ${file} 后重启`, error)
    }
  }

  private loadRetiredSecrets(): void {
    try {
      const file = this.historyFilePath()
      if (!existsSync(file)) return
      const stored = JSON.parse(readFileSync(file, 'utf8')) as Array<{ secret: string; keyId?: string; retiredAt: number; note?: string }>
      this.retiredSecrets = (Array.isArray(stored) ? stored : [])
        .filter((item) => typeof item?.secret === 'string' && item.secret)
        .map((item) => ({ secret: item.secret, keyId: item.keyId ?? this.keyIdOf(item.secret), retiredAt: Number(item.retiredAt ?? 0), ...(item.note ? { note: item.note } : {}) }))
    } catch (error) {
      // Fichier d'historique corrompu : n'interrompt pas le démarrage, mais alerte bruyamment (les liens signés avec l'ancienne clé échoueront à la vérification)
      console.error('[nasShareLinks] 退役密钥历史读取失败——旧密钥签发的既有链接将验签失败（401）', error)
    }
  }

  private saveRetiredSecrets(): void {
    try {
      writeFileSync(this.historyFilePath(), JSON.stringify(this.retiredSecrets, null, 2), { encoding: 'utf8', mode: 0o600 })
    } catch (error) {
      console.error('[nasShareLinks] 退役密钥历史落盘失败（轮换后旧密钥链接将验签失败）', error)
    }
  }

  /** Rotation de la clé longue durée dédiée (action d'exploitation explicite) : la nouvelle clé tombe en fichier, l'ancienne entre dans l'ensemble retraite permanente et continue de servir. */
  rotateSecret(note?: string): { keyId: string; retiredKeyId?: string; retiredCount: number } {
    mkdirSync(this.ctx.opsStorage.dataDirPath, { recursive: true })
    const secret = generateSecret('nsl')
    try {
      writeFileSync(this.keyFilePath(), secret, { encoding: 'utf8', mode: 0o600 })
    } catch (error) {
      throw new ShareLinkError('KEY_ROTATE_FAILED', t('新密钥落盘失败（保持旧密钥不变）：{reason}', { reason: error instanceof Error ? error.message : String(error) }), 500)
    }
    const retiredKeyId = this.currentKeyId
    if (this.currentSecret && retiredKeyId) {
      this.retiredSecrets = [
        { secret: this.currentSecret, keyId: retiredKeyId, retiredAt: Date.now(), ...(note ? { note } : {}) },
        ...this.retiredSecrets,
      ]
      this.saveRetiredSecrets()
    }
    this.currentSecret = secret
    this.currentKeyId = this.keyIdOf(secret)
    this.keyError = undefined
    return { keyId: this.currentKeyId!, ...(retiredKeyId ? { retiredKeyId } : {}), retiredCount: this.retiredSecrets.length }
  }

  secretStatus(): { available: boolean; keyId?: string; error?: string; retiredCount: number } {
    return {
      available: !this.keyError && !!this.currentKeyId,
      ...(this.currentKeyId ? { keyId: this.currentKeyId } : {}),
      ...(this.keyError ? { error: this.keyError } : {}),
      retiredCount: this.retiredSecrets.length,
    }
  }

  /** Barrière de disponibilité de la clé avant émission (fail-closed, décision ①) : l'état de panne échoue bruyamment, jamais de nouvelle clé en silence. */
  private ensureKey(): void {
    if (!this.currentSecret || !this.currentKeyId || this.keyError) {
      throw new ShareLinkError('SHARE_LINK_KEY_UNAVAILABLE',
        t('分享链接签名密钥不可用（fail-closed 拒绝签发）：{reason}——请修复密钥文件后重启，或用 rotate 端点重建', { reason: this.keyError ?? t('密钥未加载') }), 500)
    }
  }

  private sign(body: string, secret: string): string {
    return createHmac('sha256', secret).update(body).digest('base64url')
  }

  /** Comparaison de signature : clé courante d'abord, puis toutes les clés en retraite permanente (décision ① (a) : les liens historiques signés par les vieilles clés restent vérifiables à vie). */
  private signatureMatches(body: string, signature: string): boolean {
    if (this.currentSecret && this.sign(body, this.currentSecret) === signature) return true
    return this.retiredSecrets.some((item) => this.sign(body, item.secret) === signature)
  }

  // -- Politique de paliers (porteur = AuthzRulesRecord.shareLinkPolicy, même source que la face de gouvernance des permissions de données) --

  policy(): ShareLinkPolicy {
    const stored = this.nasAuthz.getRules().shareLinkPolicy
    return {
      maxTtlSec: typeof stored?.maxTtlSec === 'number' && stored.maxTtlSec > 0 ? stored.maxTtlSec : DEFAULT_SHARE_LINK_POLICY.maxTtlSec,
      allowPermanent: stored?.allowPermanent === true,
      permanentPermission: stored?.permanentPermission || DEFAULT_SHARE_LINK_POLICY.permanentPermission,
    }
  }

  /** Met à jour la politique (verrou optimiste via AuthzRules ; ifVersion par défaut prend la version courante, le dernier écrivain gagne — politique basse fréquence et trace d'audit conservée). */
  updatePolicy(patch: Partial<ShareLinkPolicy>, ifVersion: number | undefined, actor: string): ShareLinkPolicy {
    if (patch.maxTtlSec !== undefined && (!Number.isInteger(patch.maxTtlSec) || patch.maxTtlSec <= 0)) {
      throw new ShareLinkError('INVALID_POLICY', t('maxTtlSec 须为正整数，收到 {value}', { value: patch.maxTtlSec }))
    }
    const current = this.policy()
    const merged: ShareLinkPolicy = {
      maxTtlSec: patch.maxTtlSec ?? current.maxTtlSec,
      allowPermanent: patch.allowPermanent ?? current.allowPermanent,
      permanentPermission: patch.permanentPermission?.trim() || current.permanentPermission,
    }
    const version = ifVersion ?? this.nasAuthz.getRules().version
    const saved = this.nasAuthz.updateRules({ shareLinkPolicy: merged }, version, actor)
    return saved.shareLinkPolicy ?? merged
  }

  // -- Émission -------------------------------------------------------------------

  /**
   * Émet un lien de partage signé. Ordre de validation (imposé serveur, indépendant de la visibilité front, décision ②) :
   * identité machine refusée → exclusion mutuelle permanent/ttlSec → interrupteur de politique permanente (prioritaire sur le point de permission) → point de permission permanente → plafond de TTL.
   */
  issue(input: {
    nasId: string
    path: string
    issuer: { principalId: string; userId?: string; userName: string }
    ttlSec?: number
    permanent?: boolean
    note?: string
    hasPermanentPermission: boolean
  }): { record: ShareLinkRecord; exp: number; sub: string; sig: string; tier: ShareLinkTier; ttlLabel: string; ttlSec: number | null } {
    if (!input.issuer.userId) {
      throw new ShareLinkError('MACHINE_ISSUANCE_UNSUPPORTED', t('签名分享链接仅支持人工身份签发（机器链路请用一次性下载票据）'), 403)
    }
    let path: string
    try {
      path = normalizePath(input.path)
    } catch (error) {
      throw new ShareLinkError('INVALID_PATH', t('path 非法：{reason}', { reason: error instanceof Error ? error.message : String(error) }))
    }
    if (input.permanent === true && input.ttlSec !== undefined) {
      throw new ShareLinkError('PERMANENT_TTL_CONFLICT', t('permanent 与 ttlSec 互斥（语义歧义不猜测）：要永久请只传 permanent:true'))
    }
    const policy = this.policy()
    let expiresAt: string | null
    let exp: number
    let tier: ShareLinkTier
    let ttlLabel: string
    let ttlSec: number | null
    if (input.permanent === true) {
      // Décision ③ : l'interrupteur de politique prime sur le point de permission — sous la forme par défaut (allowPermanent=false), il n'existe aucun lien permanent
      if (!policy.allowPermanent) {
        throw new ShareLinkError('PERMANENT_DISABLED_BY_POLICY', t('永久链接档位未开启（share-link-policy.allowPermanent=false，策略开关优先于权限点）'), 403)
      }
      if (!input.hasPermanentPermission) {
        throw new ShareLinkError('PERMANENT_REQUIRES_AUTHZ_WRITE', t('签发永久链接需要权限点 {permission}', { permission: policy.permanentPermission }), 403)
      }
      expiresAt = null
      exp = 0
      tier = 'permanent'
      ttlLabel = t('永久')
      ttlSec = null
    } else {
      ttlSec = input.ttlSec ?? 86400 // décision ② : défaut 24 heures
      if (!Number.isInteger(ttlSec) || ttlSec <= 0) {
        throw new ShareLinkError('INVALID_TTL', t('ttlSec 须为正整数（秒），收到 {value}', { value: String(input.ttlSec) }))
      }
      if (ttlSec > policy.maxTtlSec) {
        throw new ShareLinkError('TTL_EXCEEDS_POLICY', t('TTL_EXCEEDS_POLICY：ttlSec {value} 超过策略上限 {max}（明确拒绝，不回落到上限）', { value: ttlSec, max: policy.maxTtlSec }))
      }
      expiresAt = new Date(Date.now() + ttlSec * 1000).toISOString()
      exp = Math.floor(Date.now() / 1000) + ttlSec
      const preset = SHARE_LINK_TTL_PRESETS.find((item) => item.ttlSec === ttlSec)
      tier = preset?.tier ?? 'custom'
      ttlLabel = preset ? t(preset.label) : (ttlSec % 3600 === 0 ? t('{n} 小时', { n: ttlSec / 3600 }) : t('{n} 分钟', { n: Math.round(ttlSec / 60) }))
    }
    this.ensureKey()
    const jti = newId('nsl')
    const sub = input.issuer.userId
    const sig = this.sign(`${path}|${input.nasId}|${exp}|${sub}|${jti}`, this.currentSecret!)
    const record = this.links().insert({
      id: jti,
      nasId: input.nasId,
      path,
      principalId: input.issuer.principalId,
      userId: sub,
      userName: input.issuer.userName,
      mode: 'link',
      expiresAt,
      keyId: this.currentKeyId!,
      useCount: 0,
      ...(input.note ? { note: input.note } : {}),
    })
    return { record, exp, sub, sig, tier, ttlLabel, ttlSec }
  }

  // -- Liste / révocation ------------------------------------------------------------

  list(filter: { nasId?: string; userId?: string; path?: string; includeRevoked?: boolean }): Array<ShareLinkRecord & { status: 'active' | 'revoked' | 'expired'; remainingSec: number | null }> {
    return this.links().find((item) => {
      if (filter.nasId && item.nasId !== filter.nasId) return false
      if (filter.userId && item.userId !== filter.userId) return false
      if (filter.path) {
        try {
          if (item.path !== normalizePath(filter.path)) return false
        } catch {
          return false
        }
      }
      if (!filter.includeRevoked && item.revokedAt) return false
      return true
    })
      .map((item) => ({ ...item, ...this.describeStatus(item) }))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  }

  /** État et durée de validité restante (lien permanent : remainingSec=null). */
  describeStatus(record: ShareLinkRecord): { status: 'active' | 'revoked' | 'expired'; remainingSec: number | null } {
    if (record.revokedAt) return { status: 'revoked', remainingSec: 0 }
    if (record.expiresAt !== null) {
      const remaining = Math.floor((Date.parse(record.expiresAt) - Date.now()) / 1000)
      if (remaining <= 0) return { status: 'expired', remainingSec: 0 }
      return { status: 'active', remainingSec: remaining }
    }
    return { status: 'active', remainingSec: null }
  }

  /** Révoque un lien (idempotent : rappeler sur un lien déjà révoqué renvoie l'état existant, sans erreur). */
  revoke(jti: string, by: string, reason: string): { record: ShareLinkRecord; alreadyRevoked: boolean } {
    const record = this.links().get(jti)
    if (!record) throw new ShareLinkError('SHARE_LINK_NOT_FOUND', t('分享链接不存在：{id}', { id: jti }), 404)
    if (record.revokedAt) return { record, alreadyRevoked: true }
    const updated = this.links().update(jti, {
      revokedAt: new Date().toISOString(),
      revokedBy: by,
      ...(reason ? { revokeReason: reason } : {}),
    })
    return { record: updated, alreadyRevoked: false }
  }

  /** Révocation en lot (par personne/par chemin/tout ; « quelqu'un part → révoquer tous ses liens d'un coup » est le scénario le plus fréquent). */
  revokeBatch(filter: { nasId?: string; userId?: string; path?: string; all?: boolean }, by: string, reason: string): { count: number } {
    if (!filter.userId && !filter.path && filter.all !== true) {
      throw new ShareLinkError('REVOKE_CRITERIA_REQUIRED', t('批量吊销须至少给出 userId、path 之一，或显式 all:true（防误伤全量）'))
    }
    let count = 0
    for (const item of this.links().find((link) => {
      if (filter.nasId && link.nasId !== filter.nasId) return false
      if (link.revokedAt) return false
      if (filter.userId && link.userId !== filter.userId) return false
      if (filter.path) {
        try {
          if (link.path !== normalizePath(filter.path)) return false
        } catch {
          return false
        }
      }
      return true
    })) {
      this.links().update(item.id, {
        revokedAt: new Date().toISOString(),
        revokedBy: by,
        ...(reason ? { revokeReason: reason } : {}),
      })
      count++
    }
    return { count }
  }

  // -- Trois barrières de prise de flux (signature → révocation → revérification de permissions ; fail-closed, aucune ne manque) ------------------

  verifyStreamAccess(input: { nasId: string; path: string; exp: string; sub: string; jti: string; sig: string }): ShareLinkVerdict {
    const invalid = (reason: string): ShareLinkVerdict => ({ outcome: 'invalid', reason })
    if (!input.path || !input.exp || !input.sub || !input.jti || !input.sig) return invalid(t('参数缺失'))
    if (!/^\d+$/.test(input.exp)) return invalid(t('exp 非法'))
    const exp = Number(input.exp)
    // Barrière 1 : signature (clé longue durée dédiée, survit au redémarrage) + jugement d'expiration (exp=0 = permanent, sauté)
    if (!this.signatureMatches(`${input.path}|${input.nasId}|${input.exp}|${input.sub}|${input.jti}`, input.sig)) {
      return invalid(t('签名校验失败（链接被篡改或密钥不匹配）'))
    }
    if (exp !== 0 && exp * 1000 < Date.now()) return invalid(t('链接已过期'))
    // Barrière 2 : révocation (jti pointe l'enregistrement d'émission ; enregistrement inexistant/déjà révoqué/incohérent avec la charge → refus)
    const record = this.links().get(input.jti)
    if (!record) return invalid(t('链接记录不存在（伪造或已清理）'))
    if (record.revokedAt) return invalid(t('链接已被吊销（{by}）', { by: record.revokedBy ?? '-' }))
    if (record.nasId !== input.nasId || record.path !== input.path || record.userId !== input.sub) return invalid(t('链接记录与载荷不一致'))
    if (record.expiresAt !== null && Date.parse(record.expiresAt) < Date.now()) return invalid(t('链接已过期'))
    // Barrière 3 : revérification de permissions (l'incrément clé) : jugement en temps réel sous l'identité de l'émetteur, le billet n'est qu'une encapsulation « identité+fichier »
    const decision = this.nasAuthz.check({
      nasId: input.nasId,
      userId: input.sub,
      paths: [input.path],
      op: 'download',
      caller: 'nas.share-link',
    })
    if (decision.decision !== 'allow') {
      return { outcome: 'forbidden', reasons: decision.reasons.length > 0 ? decision.reasons : [t('数据权限判定未放行')] }
    }
    return { outcome: 'ok', record }
  }

  /** Profil d'usage (appelé après une prise de flux réussie ; soutient la détection d'usage anormal et le nettoyage des « liens morts jamais utilisés »). */
  recordUse(jti: string): void {
    try {
      const record = this.links().get(jti)
      if (!record) return
      this.links().update(jti, { useCount: record.useCount + 1, lastUsedAt: new Date().toISOString() })
    } catch (error) {
      this.ctx.logger('nasShareLinks').warn('分享链接使用计数失败（不影响取流）', error)
    }
  }

  /** Nettoyage glissant des enregistrements expirés : suppression physique 7 jours après expiration (fenêtre de constat ; l'audit conserve par ailleurs changeLog/decisions). */
  cleanupExpired(): number {
    const cutoff = Date.now() - EXPIRED_CLEANUP_DELAY_MS
    let removed = 0
    for (const record of this.links().all()) {
      if (record.expiresAt !== null && Date.parse(record.expiresAt) < cutoff) {
        if (this.links().remove(record.id)) removed++
      }
    }
    return removed
  }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    nasShareLinks: NasShareLinkService
  }
}
