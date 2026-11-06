/**
 * @ybkk/plugin-panel-core — modèle et chargement des paquets de cartes (action-plan-dsh-frontend WP-05).
 *
 * Socle de configuration de l'objectif 3 (interactions différenciées multi-plateformes) : ajouter/ajuster une carte = zéro modification du code front —
 * un paquet de cartes est une pure configuration JSON (répertoire par défaut packages/platform-core/cardpacks/*.json, surchargeable via CARDPACK_DIR),
 * le serveur filtre et délivre selon « rôle × plateforme », plafond de 6 cartes en page d'accueil ; la survie des refs d'actifs est tranchée par le résolveur injecté côté endpoint
 * (platform-core ne dépend pas en retour des plugins métier, voir setRefAliveResolver ci-dessous).
 *
 * Contrat (WP-05/B1) :
 *   CardPack { platform, roles, cards[] }；Card { id, title, description, badge, href, ref?, order? }
 *   — badge est un badge de type (skill/app/mcp/nas/kb/data/model) ; ref est une référence d'actif (type:idOrSlug),
 *   une ref morte est silencieusement filtrée à la délivrance avec une alerte unique ; plafond de cartes d'accueil HOME_CARD_LIMIT=6.
 * Note d'appartenance d'endpoint (trace pour la clause d'usage D6 du plan) : le cœur du filtrage est dans ce fichier ; l'endpoint REST est, selon l'usage du dépôt, enregistré de façon
 * agrégée par console (console détient les rôles iam et les registres d'actifs, seuls capables du filtrage en trois dimensions rôle × plateforme × survie).
 */
import { readdir, readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'

export const CARDPACK_HOME_LIMIT = 6

/** Différenciation cinq plateformes (correspondance un-un des couleurs de thème WP-05/B3) : stratégie/marketing/production intelligente/R&D/qualité. */
export const CARD_PLATFORMS = ['strategy', 'marketing', 'manufacturing', 'rd', 'quality'] as const
export type CardPlatform = (typeof CARD_PLATFORMS)[number]

/** Badges de type (couverture complète des actifs de l'objectif 1, alignée sur les tuiles de la page de guidage d'enregistrement ; agent est la carte d'entrée de l'employé numérique hôte). */
export const CARD_BADGES = ['skill', 'app', 'mcp', 'nas', 'kb', 'data', 'model', 'agent'] as const
export type CardBadge = (typeof CARD_BADGES)[number]

export interface CardpackCard {
  id: string
  title: string
  /** Explication en une phrase (≤40 caractères). */
  description: string
  badge: CardBadge
  /** Cible du saut (route hash de la console ou lien externe). */
  href: string
  /** Référence d'actif (type:idOrSlug, ex. mcp:datawise / agent:dev-coder / kb:<orgId>) ; morte = filtrée. */
  ref?: string
  /** Ordre d'affichage (le plus petit devant, défaut selon l'ordre de déclaration). */
  order?: number
}

export interface CardPack {
  platform: CardPlatform
  /** Codes de rôles voyeurs ; '*' = tout le monde. */
  roles: string[]
  label?: string
  cards: CardpackCard[]
}

/** Valide un paquet : illégal = erreur levée (liste de tous les problèmes, partagé par lint:manifests et le chargement). */
export function validateCardpack(input: unknown, source = 'cardpack'): string[] {
  const errors: string[] = []
  const pack = input as CardPack
  if (pack === null || typeof pack !== 'object') return [`${source}: 不是 JSON 对象`]
  if (!CARD_PLATFORMS.includes(pack.platform)) {
    errors.push(`${source}: platform 非法（应为 ${CARD_PLATFORMS.join('/')}，收到 ${String(pack.platform)}）`)
  }
  if (!Array.isArray(pack.roles) || pack.roles.length === 0) errors.push(`${source}: roles 必填且非空（'*' 表示全员）`)
  if (!Array.isArray(pack.cards) || pack.cards.length === 0) {
    errors.push(`${source}: cards 必填且非空`)
    return errors
  }
  const seen = new Set<string>()
  pack.cards.forEach((card, index) => {
    const at = `${source}: cards[${index}]`
    if (!card?.id || typeof card.id !== 'string') errors.push(`${at}.id 必填`)
    else if (seen.has(card.id)) errors.push(`${at}.id 重复：${card.id}`)
    else seen.add(card.id)
    if (!card?.title || typeof card.title !== 'string') errors.push(`${at}.title 必填`)
    if (!card?.description || typeof card.description !== 'string' || card.description.length > 60) {
      errors.push(`${at}.description 必填且 ≤60 字（一句话说明）`)
    }
    if (!CARD_BADGES.includes(card?.badge)) errors.push(`${at}.badge 非法（应为 ${CARD_BADGES.join('/')}）`)
    if (!card?.href || typeof card.href !== 'string') errors.push(`${at}.href 必填`)
    if (card?.ref !== undefined && !/^[a-z][a-z0-9]*:[A-Za-z0-9._\p{L}-]+$/u.test(String(card.ref))) {
      errors.push(`${at}.ref 格式非法（应为 type:idOrSlug，收到 ${String(card.ref)}）`)
    }
  })
  return errors
}

/** Correspondance de rôle : le paquet déclare '*' ou une intersection avec les rôles du principal. */
export function packVisibleForRoles(pack: CardPack, roles: string[]): boolean {
  return pack.roles.includes('*') || pack.roles.some((role) => roles.includes(role))
}

/**
 * Filtrage pur : paquets visibles dans la plateforme → aplatissement en cartes (order croissant, dédoublonnage par id, refs mortes filtrées) → troncature au plafond d'accueil.
 * refAlive absent = considérée vivante (un arbre minimal sans résolveur n'est pas pénalisé).
 */
export function filterCards(input: {
  packs: CardPack[]
  roles: string[]
  refAlive?: (ref: string) => boolean
  limit?: number
}): { cards: CardpackCard[]; droppedDeadRefs: string[] } {
  const refAlive = input.refAlive ?? (() => true)
  const limit = input.limit ?? CARDPACK_HOME_LIMIT
  const droppedDeadRefs: string[] = []
  const byId = new Map<string, CardpackCard & { order: number }>()
  for (const pack of input.packs.filter((pack) => packVisibleForRoles(pack, input.roles))) {
    for (const card of pack.cards) {
      if (card.ref !== undefined && !refAlive(card.ref)) {
        droppedDeadRefs.push(card.ref)
        continue
      }
      if (!byId.has(card.id)) byId.set(card.id, { ...card, order: card.order ?? 9999 })
    }
  }
  const cards = [...byId.values()].sort((a, b) => a.order - b.order).slice(0, limit)
  return { cards, droppedDeadRefs }
}

/** Répertoire par défaut des paquets de cartes : cardpacks/ au même niveau que le présent paquet (vrai en forme source comme en forme installée). */
export function defaultCardpackDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', 'cardpacks')
}

export class CardpackService extends Service {
  static readonly provide = 'cardpacks'

  private packs: CardPack[] = []
  private loadErrors: string[] = []
  private refAliveResolver: ((ref: string) => boolean) | undefined

  constructor(ctx: Context, config: { dir?: string } = {}) {
    super(ctx, 'cardpacks')
    void this.loadFromDir(config.dir ?? process.env.CARDPACK_DIR ?? defaultCardpackDir())
  }

  /** Charge tous les *.json du répertoire : un fichier illégal est sauté et consigné (sans interrompre le démarrage), lint:manifests porte la ligne rouge. */
  async loadFromDir(dir: string): Promise<void> {
    const errors: string[] = []
    const packs: CardPack[] = []
    let entries: Array<{ name: string }> = []
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch {
      this.loadErrors = [`${dir} 不可读（无卡片包）`]
      return
    }
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue
      try {
        const parsed = JSON.parse(await readFile(join(dir, entry.name), 'utf8'))
        const packErrors = validateCardpack(parsed, entry.name)
        if (packErrors.length > 0) {
          errors.push(...packErrors)
          continue
        }
        packs.push(parsed as CardPack)
      } catch (error) {
        errors.push(`${entry.name}: JSON 解析失败（${error instanceof Error ? error.message : String(error)}）`)
      }
    }
    this.packs = packs
    this.loadErrors = errors
    if (errors.length > 0) this.ctx.logger('cardpacks').warn(`卡片包装载存在被跳过的文件：${errors.join('；')}`)
  }

  all(): CardPack[] {
    return this.packs
  }

  forPlatform(platform: CardPlatform): CardPack[] {
    return this.packs.filter((pack) => pack.platform === platform)
  }

  /** Injecte le résolveur de survie des refs d'actifs (utilisé à l'assemblage console avec iam/resourceCore/skillhub/mcp). */
  setRefAliveResolver(resolver: (ref: string) => boolean): void {
    this.refAliveResolver = resolver
  }

  refAlive(ref: string): boolean {
    return this.refAliveResolver ? this.refAliveResolver(ref) : true
  }

  /** Liste des problèmes des fichiers sautés au chargement (mauvais JSON / violation de schéma), pour observation. */
  loadProblems(): string[] {
    return this.loadErrors
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    cardpacks: CardpackService
  }
}
