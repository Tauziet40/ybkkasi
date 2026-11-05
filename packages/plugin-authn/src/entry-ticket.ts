/**
 * Ticket d'entrée d'autorisation directe plateforme (entry-ticket, billet d'admission à usage unique).
 *
 * Le « ouvrir l'interface / ouvrir l'application » de la console ne fait plus de saut nu : l'utilisateur connecté demande d'abord au point d'émission plateforme
 * (POST /api/agents/:id/entry-ticket, POST /api/apps/:id/entry-ticket) un billet court à usage unique,
 * l'adresse cible s'ouvre avec le fragment #entry_ticket=<ticket> ; le frontend cible lit le fragment puis échange l'identité au point public de la plateforme :
 *   POST /api/authn/entry-tickets/redeem { ticket } → { refType, refId, identity }
 * (la route publique est montée dans plugin-console — PUBLIC_PATHS et l'écriture d'audit convergent tous deux là-bas.)
 *
 * Sémantique de sécurité (complémentaire du code d'autorisation OIDC : les RP standards passent par /oauth/authorize, les entryUrl arbitraires sans modification passent par ce canal) :
 *   - usage unique (consommé au redeem, rejeu refusé) + courte durée (défaut 120 s, ajustable de 30 à 600 via ENTRY_TICKET_TTL_SECONDS) ;
 *   - le billet est une valeur aléatoire de 256 bits (non énumérable), transportée uniquement en https et jamais dans les logs de l'application cible (le fragment d'URL n'atteint pas le serveur) ;
 *   - à l'échange, l'état de l'utilisateur est vérifié en temps réel (gelé/départ = invalidation immédiate) ; les billets agent vérifient côté émission « owner / utilisateur lié / administrateur »,
 *     la réception ne fait pas d'autorisation au niveau ressource (la sémantique d'autorisation a été figée et audité à l'émission) ;
 *   - émission et échange entrent tous deux dans l'audit (chaîne d'accès directe consultable par *.entry.ticket.*).
 */
import { randomBytes } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'

export interface EntryTicketRecord extends RecordBase {
  /** Le billet lui-même est la clé primaire (etk_ + valeur aléatoire 256 bits) ; consumedAt posé immédiatement après l'échange.
   *  refType 'self' : auto-émission par l'humain connecté (retour multi-origine de la liste de passation G1), refId = userId de l'émetteur. */
  refType: 'agent' | 'app' | 'self'
  refId: string
  userId: string
  issuedBy: string
  expiresAt: string
  consumedAt?: string
  consumedIp?: string
}

export interface EntryTicketIdentity {
  sub: string
  username: string
  name: string
  org: { id: string; name: string; tenantId: string } | null
  roles: string[]
  tenant: string
}

const DEFAULT_TTL_SECONDS = 120

export class EntryTicketService extends Service {
  static readonly provide = 'entryTickets'
  static readonly inject = ['opsStorage', 'iam']

  private cleanupTimer: ReturnType<typeof setInterval> | undefined

  constructor(ctx: Context) {
    super(ctx, 'entryTickets')
    this.cleanupTimer = setInterval(() => this.cleanupExpired(), 24 * 3600_000)
    this.cleanupTimer.unref?.() // OPT-P3-02
    ctx.effect(() => () => {
      if (this.cleanupTimer) clearInterval(this.cleanupTimer)
    })
  }

  static ttlSeconds(): number {
    const raw = Number(process.env.ENTRY_TICKET_TTL_SECONDS ?? DEFAULT_TTL_SECONDS) || DEFAULT_TTL_SECONDS
    return Math.min(600, Math.max(30, Math.floor(raw)))
  }

  tickets(): Collection<EntryTicketRecord> {
    return this.ctx.opsStorage.collection<EntryTicketRecord>('authn:entryTickets')
  }

  /** Émission : l'appelant (point console) a déjà vérifié l'existence de la ressource, l'identité humaine et l'autorisation d'usage, avec audit ; ici validation de l'état de l'utilisateur.
   *  maxTtlSeconds : plafond matériel du TTL pour ce type de billet (billets self ≤ 120 s, liste de passation G1 — lève même si env augmente). */
  issue(input: { refType: 'agent' | 'app' | 'self'; refId: string; userId: string; userName: string }, options: { maxTtlSeconds?: number } = {}): { ticket: string; expiresAt: string; ttlSeconds: number } {
    const user = this.ctx.iam.users().get(input.userId)
    if (!user) throw new Error(t('用户不存在'))
    if (user.status !== 'active') throw new Error(t('账号状态异常，无法签发入场票据'))
    const ttlSeconds = Math.min(EntryTicketService.ttlSeconds(), options.maxTtlSeconds ?? EntryTicketService.ttlSeconds())
    const ticket = 'etk_' + randomBytes(32).toString('base64url')
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString()
    this.tickets().insert({
      id: ticket,
      refType: input.refType,
      refId: input.refId,
      userId: input.userId,
      issuedBy: input.userName,
      expiresAt,
    })
    return { ticket, expiresAt, ttlSeconds }
  }

  /**
   * Échange : consommation unique → validation en temps réel de l'état utilisateur → renvoi de la ressource cible et de l'identité normalisée (l'audit est écrit par la couche de routes).
   * Entropie du billet 256 bits et usage unique : pas de limitation par IP (les tentatives erronées n'offrent aucun gain de force brute, un verrouillage ne pénaliserait que les utilisateurs normaux des sorties partagées).
   */
  redeem(ticket: string, clientIp: string): { refType: EntryTicketRecord['refType']; refId: string; expiresAt: string; identity: EntryTicketIdentity } {
    const record = this.tickets().get(String(ticket ?? ''))
    if (!record) throw new Error(t('入场票据无效'))
    if (record.consumedAt) throw new Error(t('入场票据已被使用（一次性，防重放）'))
    if (new Date(record.expiresAt).getTime() < Date.now()) throw new Error(t('入场票据已过期，请从控制台重新打开'))
    this.tickets().update(record.id, { consumedAt: new Date().toISOString(), consumedIp: clientIp })
    const user = this.ctx.iam.users().get(record.userId)
    if (!user || user.status !== 'active') throw new Error(t('签发用户状态异常（冻结/离职联动失效）'))
    const org = this.ctx.iam.orgs().get(user.orgId)
    return {
      refType: record.refType,
      refId: record.refId,
      expiresAt: record.expiresAt,
      identity: {
        sub: user.id,
        username: user.username,
        name: user.displayName,
        org: org ? { id: org.id, name: org.name, tenantId: org.tenantId ?? 't_default' } : null,
        roles: user.roleIds.map((roleId) => this.ctx.iam.roles().get(roleId)?.code).filter(Boolean),
        tenant: org?.tenantId ?? 't_default',
      },
    }
  }

  /** Nettoyage des billets expirés toutes les 24 h (consommés ou non, aucune valeur de conservation). */
  private cleanupExpired(): number {
    let removed = 0
    for (const record of this.tickets().all()) {
      if (new Date(record.expiresAt).getTime() < Date.now() - 24 * 3600_000 && this.tickets().remove(record.id)) removed++
    }
    return removed
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    entryTickets: EntryTicketService
  }
}
