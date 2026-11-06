/**
 * @dsh-ops/plugin-usage — pipeline de metering usage (conception écosystème v1.2 étape 2).
 *
 * Unique entrée de metering de la consommation de ressources de toute la plateforme :
 *   consommateur de ressources (passerelle MCP / passerelle de modèles / runtime d'extension)
 *     → usage.record() (validation schéma v1 → SQLite écrire d'abord puis envoyer → diffusion platformBus)
 *     → souscripteurs (collecte de coûts audit / débit billing / partage market / moteur de réconciliation)
 *
 * Sémantique du schéma (figée, additive-only) :
 *   - usage.recorded schema_version=1 : champs seulement ajoutés, jamais modifiés ni supprimés ; les nouveaux champs n'entrent qu'en optionnel avec une version mineure ;
 *   - les consommateurs doivent tolérer les nouveaux champs inconnus (obligation de compatibilité ascendante) ;
 *   - les champs dépréciés passent par l'événement platform.schema.deprecated, les données historiques ne sont ni migrées ni recalculées.
 * Sémantique de livraison (M8) : at-least-once + idempotence du consommateur par idempotency_key ; inscription avant distribution (aucune perte sur crash) ;
 *   3 retries d'anomalie de consommation puis lettre morte avec alerte ; rejeu par fenêtre temporelle pris en charge.
 *
 * Journal des changements de schéma (action-plan-dsh-frontend WP-03 / résolutions par défaut D1, D2, 2026-09-02) :
 *   - D1 le domaine de valeurs de resource s'enrichit de `app:<id>`, `kb:<orgId>` (additive) : le tarif sème à taux nul `app:*`/`kb:*`
 *     (meter_key=calls), la facturation éventuelle relève du retarification opérationnel ;
 *   - D2 les événements non facturables adoptent l'instantané à prix zéro : une règle à taux nul produit charge_cents=0 et rate.nonbillable=true ;
 *     UsageRecordInput.nonbillable=true est une entrée de construction commode (événements non facturables de feedback/savoir), admise seulement avec une règle à taux nul,
 *     contre la dérive de référentiel « marqué non facturable mais comptabilisé selon une règle facturable » ;
 *   - D3 (groupe 7 de la mise en conformité de l'employé numérique, 2026-10-15) association d'appel de travail (§11.3 additive-only) : UsageRecordInput /
 *     UsageEvent reçoivent l'optionnel invocationId, colonne invocation_id TEXT NOT NULL DEFAULT '' (les bases existantes reçoivent à l'amorçage
 *     la sonde pragma + migration idempotente ALTER TABLE). Sémantique : associe le présent fait de consommation à un registre
 *     d'appel de travail de workforce_invocations (index accompagnant de workforce_usage_links), référentiels d'agrégation/réconciliation inchangés, pas de double comptage ;
 *     le mécanisme de clé idempotente et la clé resource historique sans changer un mot.
 *   - C4 (collaboration intranet A2A/UHP de l'employé numérique d'entreprise, 2026-10-20) agrégation de chaîne de collaboration (additive-only, même référentiel que D3) :
 *     UsageRecordInput / UsageEvent reçoivent l'optionnel contextId, colonne context_id TEXT NOT NULL DEFAULT ''.
 *     Sémantique : tout le metering des Tasks sous un même contextId A2A (chaîne de collaboration inter-employés) s'agrège par chaîne —
 *     collaborationEvents() / collaborationSummary() fournissent l'agrégat « coût total d'une collaboration », mécanisme de clé idempotente inchangé.
 *
 * Convergence du modèle économique (plan de développement method M0, 2026-09-09) : le référentiel commercial de la plateforme est « licence annuelle privatif + pack de gouvernance »,
 * le pipeline usage se positionne comme **metering transparent de l'usage et référence de coût interne** — la face list du tarif est un instantané à prix zéro uniforme (charge_cents=0,
 * sans aucune sémantique de règlement en montant présentée à l'extérieur), la face cost conserve la référence de coût d'achat interne (référentiel du rapport de perçage des coûts, voir docs/contract-j4-usage-report.md).
 * monthlyReport() fournit l'agrégat tridimensionnel de tokens du contrat J4 (département org / Agent / Skill).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId, PlatformEvents, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { AssetUsageError, reportFingerprint, type AssetUsageReportRecord } from './asset-reports.ts'
import * as usageTools from './tools.ts'

// ---------------------------------------------------------------------------
// schéma v1 (figé)
// ---------------------------------------------------------------------------

export const USAGE_SCHEMA = 'usage.recorded'
export const USAGE_SCHEMA_VERSION = 1

/** Entrée de dictionnaire de metering extensible : remplace le trio fixe de tokens, le metering personnalisé L3 entre avec la même structure. */
export interface UsageMeter {
  key: string
  value: number
  unit: string
}

/**
 * Ligne de prix combiné (#14, 2026-10-29, additive-only) : un événement est tarifé séparément selon plusieurs clés de metering puis sommé
 * (tarification double mètre des tokens de modèle : input_tokens × taux d'entrée + output_tokens × taux de sortie).
 * Réservé aux producteurs internes de confiance de la plateforme (modelgw) ; les taux viennent toujours du tarif (modelgw lit à l'instant de l'appel),
 * l'instantané rate.line_items laisse une trace intégrale, récalculable en réconciliation/audit.
 */
export interface UsageCostLineItem {
  meter_key: string
  value: number
  cost_cents_per_unit: number
  units_per_step: number
}

/** Instantané de tarif (figé à l'instant de la facturation, recalculable historiquement). */
export interface UsagePricingSnapshot {
  currency: string
  /** Recevable de cet événement (référentiel prix catalogue, TTC). */
  charge_cents: number
  /** Coût plateforme de cet événement (référentiel : coût d'achat L1). */
  cost_cents: number
  /**
   * Annotation sémantique de coût (#14 additive) : 'not_priced' = 0 dû à un taux non configuré/taux nul —
    * « inconnu » ne se lit pas comme « vrai coût nul » ; défaut = priced (y compris le zéro honnête d'un taux non nul mais d'un montant arrondi à 0).
   */
  cost_status?: 'priced' | 'not_priced'
  /** Instantané du détail de tarification (taux + clé de metering), base de récalcul pour partage/audit ; lignes de prix combiné additive (#14). */
  rate: { pattern: string; meter_key: string; list_cents_per_unit: number; cost_cents_per_unit: number; units_per_step: number; tax_rate: number; nonbillable?: boolean; line_items?: UsageCostLineItem[] }
}

/** Événement usage.recorded v1 (append-only, interdiction de changer de version ; l'extension n'admet que de nouveaux champs optionnels). */
export interface UsageEvent {
  schema: typeof USAGE_SCHEMA
  schema_version: number
  event_id: string
  idempotency_key: string
  trace_id?: string
  /** D3 (additive) : id du registre d'appel de travail de l'employé numérique associé (workforce_invocations.id) ; absent des événements hors appel de travail. */
  invocationId?: string
  /** C4 (additive, face collaboration A2A/UHP) : id de chaîne de collaboration inter-employés (contextId A2A) — tout le metering des Tasks d'une même chaîne s'agrège dessous ; absent des événements hors collaboration. */
  contextId?: string
  occurred_at: string
  tenant_id: string
  org: string
  /** Utilisateur final/Agent (point d'arrivée du on-behalf-of) : user:<id> | agent:<id> */
  subject: string
  /** Sujet responsable de la facturation : org:<id> | plugin:<id> | app:<id> | platform */
  principal: string
  /** Ressource : model:<slug> | plugin:<id> | mcp:<slug> | skill:<id> | nas:<id> | app:<id> | kb:<orgId> (D1 additive) */
  resource: string
  meters: UsageMeter[]
  pricing: UsagePricingSnapshot
}

/** Entrée d'inscription d'événement de metering (les champs dérivés sont complétés par record() après validation du schéma). */
export interface UsageRecordInput {
  org: string
  subject: string
  principal: string
  resource: string
  meters: UsageMeter[]
  tenant_id?: string
  trace_id?: string
  /** D3 (additive, optionnel) : id du registre d'appel de travail de l'employé numérique (colonne invocation_id) ; défaut chaîne vide, référentiel d'agrégation inchangé. */
  invocationId?: string
  /** C4 (additive, optionnel) : id de chaîne de collaboration A2A (colonne context_id) ; défaut chaîne vide, référentiel d'agrégation inchangé. */
  contextId?: string
  /** Clé idempotente : apportée par l'appelant (recommandé, ex. <producteur>:<numéro de dossier métier>) ; à défaut générée par sujet+ressource+fenêtre+numéro. */
  idempotency_key?: string
  occurred_at?: string
  /**
   * Construction commode non facturable (D2 instantané à prix zéro) : true exige que la ressource atteigne une règle du tarif à taux nul,
   * l'événement est inscrit charge_cents=0 + rate.nonbillable=true (les événements d'observation feedback/savoir ne polluent pas le référentiel de facturation).
   */
  nonbillable?: boolean
  /**
   * Lignes de prix combiné (#14 additive, optionnel) : fournies, le coût de l'événement = somme des (value/step)×rate —
   * unique entrée de la tarification double mètre des tokens de modèle (input/output tarifés séparément) ; les taux sont lus dans le tarif par le producteur puis passés,
   * l'instantané rate.line_items laisse une trace intégrale. À défaut, tarification mono-mètre du tarif (comportement historique inchangé).
   */
  costLineItems?: UsageCostLineItem[]
}

/**
 * Construction commode d'instantané à prix zéro D2 : les événements d'observation non facturables (feedback/usage de paquets de savoir, etc.) sont inscrits uniformément en metering calls à taux nul.
 * La valeur de retour se donne directement à usage.record() ; la ressource doit atteindre une règle du tarif à taux nul (les préfixes app: et kb: sont semés par défaut),
 * sinon record() refuse (la marque nonbillable prévient la dérive de référentiel).
 */
export function nonbillableUsage(base: Omit<UsageRecordInput, 'meters' | 'nonbillable'> & { calls?: number }): UsageRecordInput {
  return { ...base, meters: [{ key: 'calls', value: base.calls ?? 1, unit: 'call' }], nonbillable: true }
}

/** Entrée du tarif : motif resource (exact → correspondance de préfixe) → clé de metering et taux. */
export interface PriceBookEntry extends RecordBase {
  pattern: string
  meter_key: string
  list_cents_per_unit: number
  cost_cents_per_unit: number
  units_per_step: number
  tax_rate: number
  currency: string
  /** Version du taux (référence d'instantané d'écriture, recalculable historiquement). */
  rate_version: string
}

/** Enregistrement d'autorisation de capacité (base de la réconciliation à l'exécution M5) : écrit par market à l'installation d'une extension. */
export interface CapabilityGrantRecord extends RecordBase {
  principal: string
  capabilities: string[]
  source: string
}

/** Lettres mortes (événements en échec de consommation 3 fois). */
export interface DeadLetterRecord extends RecordBase {
  event_id: string
  consumer: string
  error: string
  attempts: number
}

export type UsageConsumer = (event: UsageEvent) => void

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

const DEFAULT_TENANT = 't_default'
const WINDOW_MS = 60_000

export class UsageService extends Service {
  static readonly provide = 'usage'

  private consumers = new Map<string, { handler: UsageConsumer; attempts: Map<string, number> }>()
  private seq = 0
  /** Durcissement lecture REL-11 : clés de données sales ayant déjà émis warning (déduplication en processus, contre la tempête d'alertes). */
  private warnedDirtyKeys = new Set<string>()
  /** Jours de rétention des événements (USAGE_RETENTION_DAYS, défaut 730 = 2 ans ; 0 = rétention permanente sans nettoyage). */
  readonly retentionDays: number
  private retentionTimer: ReturnType<typeof setInterval> | undefined

  constructor(ctx: Context) {
    super(ctx, 'usage')
    ctx.txnStore.ensureTable('usage_events', {
      id: 'TEXT',
      idempotency_key: 'TEXT NOT NULL',
      schema_version: 'INTEGER NOT NULL',
      occurred_at: 'TEXT NOT NULL',
      tenant_id: 'TEXT NOT NULL',
      org: "TEXT NOT NULL DEFAULT ''",
      subject: "TEXT NOT NULL DEFAULT ''",
      principal: 'TEXT NOT NULL',
      resource: 'TEXT NOT NULL',
      meters_json: 'TEXT NOT NULL',
      pricing_json: 'TEXT NOT NULL',
      trace_id: "TEXT NOT NULL DEFAULT ''",
      // D3 (groupe 7 additive) : colonne d'association d'appel de travail de l'employé numérique — créée d'emblée en base neuve ; en base existante, migration par la sonde pragma ci-dessous
      invocation_id: "TEXT NOT NULL DEFAULT ''",
      // C4 (face collaboration A2A/UHP additive) : colonne d'association de chaîne de collaboration inter-employés — même référentiel additive-only
      context_id: "TEXT NOT NULL DEFAULT ''",
    }, { uniques: [['idempotency_key']], indexes: [['occurred_at'], ['principal'], ['tenant_id']] })
    // Migration incrémentale des bases existantes (D3, garde idempotente) : sonde pragma table_info, ALTER seulement si colonne absente —
    // additive seulement (NOT NULL avec défaut), sans toucher aux colonnes existantes, ni aux index ni à la clé idempotente
    const usageColumns = this.ctx.txnStore.sql<{ name: string }>('pragma table_info(usage_events)')
    if (!usageColumns.some((column) => column.name === 'invocation_id')) {
      this.ctx.txnStore.run("ALTER TABLE usage_events ADD COLUMN invocation_id TEXT NOT NULL DEFAULT ''")
      this.ctx.logger('usage').info('usage_events 增量迁移：已补 invocation_id 列（数字员工工作调用关联，D3 additive）')
    }
    // Migration incrémentale C4 des bases existantes (même garde idempotente que D3) : colonne d'association de chaîne de collaboration A2A
    if (!usageColumns.some((column) => column.name === 'context_id')) {
      this.ctx.txnStore.run("ALTER TABLE usage_events ADD COLUMN context_id TEXT NOT NULL DEFAULT ''")
      this.ctx.logger('usage').info('usage_events 增量迁移：已补 context_id 列（A2A 跨员工协作链关联，C4 additive）')
    }
    // Niveau de consommation (idempotence au niveau moteur) : un même consommateur ne produit qu'un seul effet de bord par événement —
    // replay()/ré-injection de lettres mortes ne provoque pas de double comptage des projections billing/audit (point de correctif d'un défaut avéré en revue).
    ctx.txnStore.ensureTable('usage_consumptions', {
      consumer: 'TEXT NOT NULL',
      event_id: 'TEXT NOT NULL',
      at: 'TEXT NOT NULL',
    }, { primaryKey: ['consumer', 'event_id'] })
    const retention = Number(process.env.USAGE_RETENTION_DAYS ?? 730)
    this.retentionDays = Number.isFinite(retention) && retention > 0 ? Math.floor(retention) : 0
    if (this.retentionDays > 0) {
      ctx.logger('usage').info(`usage 事件保留策略：${this.retentionDays} 天（USAGE_RETENTION_DAYS，0=永久）`)
      // premier tour 20 s après le démarrage + inspection toutes les 6 h (aligné sur l'usage des minuteurs de construction de la synchronisation automatique des connecteurs iam)
      const first = setTimeout(() => void this.sweepRetention(), 20_000)
      ctx.effect(() => () => clearTimeout(first))
      this.retentionTimer = setInterval(() => void this.sweepRetention(), 6 * 3_600_000)
      this.retentionTimer.unref?.() // OPT-P3-02
      ctx.effect(() => () => {
        if (this.retentionTimer) clearInterval(this.retentionTimer)
      })
    }
    this.ensureDefaultPriceBook()
  }

  /**
   * Inspection de politique de rétention : nettoie les usage_events hors fenêtre de rétention, avec niveaux de consommation et lettres mortes correspondantes.
   * Sémantique (enregistrée dans les notes de version 2026-09-11) : un événement nettoyé, un nouveau rapport de même clé idempotente sera comptabilisé comme nouvel événement —
   * la fenêtre de rétention vaut contrat de suppression ; la fenêtre du rapport mensuel J4 (13 derniers mois) est dans la fenêtre par défaut de 730 jours, non affectée.
   */
  purgeExpired(daysOverride?: number): { cutoff: string; purgedEvents: number; purgedWatermarks: number; purgedDeadLetters: number } {
    const days = daysOverride ?? this.retentionDays
    if (!(days > 0)) return { cutoff: '', purgedEvents: 0, purgedWatermarks: 0, purgedDeadLetters: 0 }
    const cutoff = new Date(Date.now() - days * 86_400_000).toISOString()
    // Les lettres mortes d'abord rapprochées : une lettre morte dont l'événement est sorti de fenêtre est retirée aussi (les garder ne ferait qu'un nettoyage passif à la ré-injection sur événement manquant)
    let purgedDeadLetters = 0
    for (const letter of this.deadLetters().all()) {
      const row = this.ctx.txnStore.one<UsageRow>('usage_events', { id: letter.event_id })
      if (row && row.occurred_at < cutoff) {
        this.deadLetters().remove(letter.id)
        purgedDeadLetters++
      }
    }
    const purgedWatermarks = this.ctx.txnStore.run(
      'DELETE FROM usage_consumptions WHERE event_id IN (SELECT id FROM usage_events WHERE occurred_at < ?)',
      [cutoff],
    )
    const purgedEvents = this.ctx.txnStore.run('DELETE FROM usage_events WHERE occurred_at < ?', [cutoff])
    if (purgedEvents > 0) {
      this.ctx.logger('usage').info(`usage 保留清理：${purgedEvents} 事件 / ${purgedWatermarks} 消费水位 / ${purgedDeadLetters} 死信（cutoff=${cutoff}）`)
    }
    return { cutoff, purgedEvents, purgedWatermarks, purgedDeadLetters }
  }

  private async sweepRetention(): Promise<void> {
    try {
      this.purgeExpired()
    } catch (error) {
      this.ctx.logger('usage').warn('usage 保留巡检失败', error)
    }
  }

  // -- Enregistrement et distribution -----------------------------------------------------------

  /** Unique point d'entrée du metering sur toute la plateforme : validation → tarification → écriture en base (idempotent) → distribution sur le bus. */
  record(input: UsageRecordInput): UsageEvent {
    this.validate(input)
    const tenant = input.tenant_id ?? this.resolveTenant(input.org)
    const price = this.priceOf(input.resource)
    // D2 construction pratique non facturable : le marqueur nonbillable n'est autorisé qu'avec une règle à taux nul (évite « marqué non facturable mais comptabilisé selon une règle facturable »)
    if (input.nonbillable === true && !(price.list_cents_per_unit === 0 && price.cost_cents_per_unit === 0)) {
      throw new Error(t('非计费事件只允许命中零费率价格簿规则：资源 {resource} 命中 {pattern}（非零费率），请去掉 nonbillable 或先调零费率', { resource: input.resource, pattern: price.pattern }))
    }
    // Ce qu'une règle à taux nul produit est précisément un événement non facturable (référentiel uniforme d'instantané à prix zéro) : charge_cents=0 + rate.nonbillable=true
    // #14 : en présence de lignes de tarification combinées, le caractère non facturable se juge sur le taux de chaque ligne (le référentiel mono-mètre du tarif n'est qu'une indication de clé primaire, n'est plus décisionnaire)
    const lineItems = (input.costLineItems ?? []).map((item) => {
      for (const [field, value, min] of [
        ['value', item.value, 0], ['cost_cents_per_unit', item.cost_cents_per_unit, 0], ['units_per_step', item.units_per_step, 1],
      ] as Array<[string, number, number]>) {
        if (!Number.isFinite(value) || value < min) {
          throw new Error(t('组合计价行字段 {field} 必须为有限数值且 ≥{min}，收到：{value}', { field, min, value: String(value) }))
        }
      }
      if (!input.meters.some((meter) => meter.key === item.meter_key)) {
        throw new Error(t('组合计价行引用了事件未携带的计量键：{key}（事件携带 [{received}]）', { key: item.meter_key, received: input.meters.map((m) => m.key).join(', ') }))
      }
      return { ...item }
    })
    const nonbillable = input.nonbillable === true
      || (lineItems.length > 0
        ? price.list_cents_per_unit === 0 && lineItems.every((item) => item.cost_cents_per_unit === 0)
        : price.list_cents_per_unit === 0 && price.cost_cents_per_unit === 0)
    // Validation dure : l'événement doit porter la clé de tarification du tarif (mieux vaut refuser qu'une facturation silencieuse à 0 —
    // le tarif est invisible pour l'appelant (usage.admin), le message d'erreur porte directement la clé attendue pour auto-correction)
    if (!input.meters.some((item) => item.key === price.meter_key)) {
      throw new Error(
        t('计量键不匹配：资源 {resource} 按价格簿 {pattern} 以「{key}」计价，收到 [{received}]。请按 {key} 重报，不要编造计量键',
          { resource: input.resource, pattern: price.pattern, key: price.meter_key, received: input.meters.map((m) => m.key).join(', ') }),
      )
    }
    const meter = input.meters.find((item) => item.key === price.meter_key)!
    // REL-11 durcissement côté lecture : un taux historique sale (non fini/négatif/pas nul) est tarifié à 0 avec un warning (évite un empoisonnement permanent) ;
    // Une valeur légale passe telle quelle, le résultat de tarification inchangé. L'instantané enregistre la valeur corrigée réellement employée (un non-fini sérialisé en null en JSON continuerait de polluer la réconciliation)
    const listRate = Number.isFinite(price.list_cents_per_unit) && price.list_cents_per_unit >= 0
      ? price.list_cents_per_unit
      : this.warnDirtyData(`pricebook:${price.pattern}:list`, t('价格簿 {pattern} 的 list_cents_per_unit={value} 为非法数值，本次计价按 0 处理；请尽快修正价格簿（REL-11）', { pattern: price.pattern, value: String(price.list_cents_per_unit) }))
    const costRate = Number.isFinite(price.cost_cents_per_unit) && price.cost_cents_per_unit >= 0
      ? price.cost_cents_per_unit
      : this.warnDirtyData(`pricebook:${price.pattern}:cost`, t('价格簿 {pattern} 的 cost_cents_per_unit={value} 为非法数值，本次计价按 0 处理；请尽快修正价格簿（REL-11）', { pattern: price.pattern, value: String(price.cost_cents_per_unit) }))
    const step = Number.isFinite(price.units_per_step) && price.units_per_step > 0
      ? price.units_per_step
      : this.warnDirtyData(`pricebook:${price.pattern}:step`, t('价格簿 {pattern} 的 units_per_step={value} 为非法数值（须为正数），本次计价按 0 处理；请尽快修正价格簿（REL-11）', { pattern: price.pattern, value: String(price.units_per_step) }))
    const charge = step > 0 ? Math.round((meter.value / step) * listRate) : 0
    // #14 : lignes de tarification combinées présentes → coût = Σ tarification des lignes (double mètre input/output) ; sinon tarif mono-mètre du livre de prix (référentiel historique inchangé)
    const cost = lineItems.length > 0
      ? lineItems.reduce((sum, item) => sum + Math.round((item.value / item.units_per_step) * item.cost_cents_per_unit), 0)
      : (step > 0 ? Math.round((meter.value / step) * costRate) : 0)
    const event: UsageEvent = {
      schema: USAGE_SCHEMA,
      schema_version: USAGE_SCHEMA_VERSION,
      event_id: newId('uevt'),
      idempotency_key: input.idempotency_key ?? this.autoIdempotencyKey(input),
      ...(input.trace_id !== undefined ? { trace_id: input.trace_id } : {}),
      // D3 (additive) : la clé n'est émise que si l'appelant la porte explicitement (compatibilité avant du schéma : les consommateurs tolèrent l'absence)
      ...(input.invocationId !== undefined ? { invocationId: input.invocationId } : {}),
      // C4 (additive) : identifiant de chaîne de collaboration A2A, émis uniquement s'il est porté explicitement
      ...(input.contextId !== undefined ? { contextId: input.contextId } : {}),
      occurred_at: input.occurred_at ?? new Date().toISOString(),
      tenant_id: tenant,
      org: input.org,
      subject: input.subject,
      principal: input.principal,
      resource: input.resource,
      meters: input.meters,
      pricing: {
        currency: price.currency,
        charge_cents: charge,
        cost_cents: cost,
        // #14 : not_priced marque un « 0 dû à un taux non configuré/nul » — l'aval ne doit pas lire l'inconnu comme un coût nul
        ...(cost === 0 && nonbillable ? { cost_status: 'not_priced' as const } : {}),
        rate: {
          pattern: price.pattern,
          meter_key: price.meter_key,
          // REL-11 : enregistre le taux corrigé réellement employé (identique à l'original pour une valeur légale)
          list_cents_per_unit: listRate,
          cost_cents_per_unit: costRate,
          units_per_step: step,
          tax_rate: price.tax_rate,
          ...(nonbillable ? { nonbillable: true } : {}),
          ...(lineItems.length > 0 ? { line_items: lineItems } : {}),
        },
      },
    }
    const inserted = this.ctx.txnStore.insertOrIgnore('usage_events', usageRow(event))
    if (!inserted) {
      const existing = this.ctx.txnStore.one<UsageRow>('usage_events', { idempotency_key: event.idempotency_key })
      if (!existing) throw new Error(t('幂等键异常：{key} 已占用但记录缺失', { key: event.idempotency_key }))
      // Référentiel idempotent feedback (groupe 4 : re-noter le même messageId ne double pas le comptage) : la clé ne contient pas de segment score, le score suit l'unité du mètre
      // tombe dans le contenu — re-noter avec la même clé est un rejeu attendu (first-write-wins, le premier score est conservé), pas de refus pour conflit de contenu
      const sameContent = existing.org === event.org
        && existing.subject === event.subject
        && existing.principal === event.principal
        && existing.resource === event.resource
        && (existing.meters_json === JSON.stringify(event.meters) || event.idempotency_key.startsWith('feedback:'))
      if (!sameContent) {
        throw new Error(t('幂等键冲突：{key} 已绑定事件 {id}，同键不同内容被拒绝', { key: event.idempotency_key, id: existing.id }))
      }
      // Rejeu idempotent : renvoie l'événement existant (l'instantané de tarification fait foi du premier enregistrement, pas de recalcul selon la variation des taux)
      return rowToEvent(existing)
    }
    this.dispatch(event)
    return event
  }

  /** Enregistre un consommateur (at-least-once ; 3 échecs = lettre morte). */
  consume(consumerId: string, handler: UsageConsumer): () => void {
    this.consumers.set(consumerId, { handler, attempts: new Map() })
    return () => this.consumers.delete(consumerId)
  }

  /**
   * Distribution : « effet exactement une fois » sous sémantique at-least-once —
   *   1. occupation préalable du niveau de consommation (INSERT OR IGNORE) : événement déjà consommé = saut direct (rejeu idempotent) ;
   *   2. échec du gestionnaire = libération du niveau, retry immédiate avec repli (exécution réelle, 3 fois au total) ;
   *   3. 3 échecs = lettre morte (persistée) avec alerte, ré-injectable manuellement via retryDeadLetters().
   */
  private dispatch(event: UsageEvent): void {
    this.ctx.platformBus.emit(USAGE_SCHEMA, event)
    for (const [consumerId, entry] of this.consumers) {
      const claimed = this.ctx.txnStore.insertOrIgnore('usage_consumptions', {
        consumer: consumerId, event_id: event.event_id, at: new Date().toISOString(),
      })
      if (!claimed) continue // déjà consommé (rejeu/ré-injection) : saut idempotent
      let delivered = false
      for (let attempt = 1; attempt <= 3 && !delivered; attempt++) {
        try {
          entry.handler(event)
          entry.attempts.delete(`${consumerId}:${event.event_id}`)
          delivered = true
        } catch (error) {
          // retry immédiate (le pipeline synchrone ne bloque pas la boucle d'événements) : au plus 3 exécutions réelles sur échec transitoire
          if (attempt < 3) continue
          // libère le niveau de consommation pour permettre une nouvelle consommation à la ré-injection manuelle
          this.ctx.txnStore.run('DELETE FROM usage_consumptions WHERE consumer = ? AND event_id = ?', [consumerId, event.event_id])
          this.deadLetters().insert({
            id: newId('dlq'), event_id: event.event_id, consumer: consumerId,
            error: error instanceof Error ? error.message : String(error), attempts: attempt,
          })
          this.ctx.platformBus.emit('audit.alert.fired', {
            id: newId('alt'), severity: 'critical', title: t('usage 消费死信'),
            message: t('消费方 {consumer} 处理事件 {id} 连续失败 {attempts} 次（含即时重试），已入死信，可通过 usage_deadletter_retry 重投', { consumer: consumerId, id: event.event_id, attempts: attempt }),
          })
        }
      }
    }
  }

  /** Rejoue les événements de la fenêtre (le niveau de consommation garantit l'idempotence : rejeus répétés sans effets de bord dupliqués). */
  replay(sinceIso: string): { replayed: number } {
    const rows = this.ctx.txnStore.sql<UsageRow>(
      'SELECT * FROM usage_events WHERE occurred_at >= ? ORDER BY occurred_at',
      [sinceIso],
    )
    for (const row of rows) this.dispatch(rowToEvent(row))
    return { replayed: rows.length }
  }

  /** Ré-injection des lettres mortes : redistribution une à une, succès = sortie de la file. Renvoie {retried, remaining}. */
  retryDeadLetters(): { retried: number; remaining: number } {
    const letters = this.deadLetters().all()
    let retried = 0
    for (const letter of letters) {
      const row = this.ctx.txnStore.one<UsageRow>('usage_events', { id: letter.event_id })
      if (!row) {
        this.deadLetters().remove(letter.id) // événement déjà inexistant (nettoyage/expiration) : la lettre morte est retirée aussi
        continue
      }
      const consumer = this.consumers.get(letter.consumer)
      if (!consumer) continue // consommateur non enregistré (extension non chargée) : lettre morte conservée
      this.deadLetters().remove(letter.id)
      try {
        const claimed = this.ctx.txnStore.insertOrIgnore('usage_consumptions', {
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
          id: newId('dlq'), event_id: letter.event_id, consumer: letter.consumer,
          error: t('重投仍失败：{message}', { message: error instanceof Error ? error.message : String(error) }), attempts: letter.attempts + 1,
        })
      }
    }
    return { retried, remaining: this.deadLetters().count() }
  }

  // -- Requêtes -----------------------------------------------------------------

  query(filter: { tenant_id?: string; principal?: string; resource?: string; from?: string; to?: string; limit?: number } = {}): { total: number; items: UsageEvent[] } {
    const conditions: string[] = []
    const params: Array<string | number> = []
    if (filter.tenant_id) { conditions.push('tenant_id = ?'); params.push(filter.tenant_id) }
    if (filter.principal) { conditions.push('principal = ?'); params.push(filter.principal) }
    if (filter.resource) { conditions.push('resource = ?'); params.push(filter.resource) }
    if (filter.from) { conditions.push('occurred_at >= ?'); params.push(filter.from) }
    if (filter.to) { conditions.push('occurred_at <= ?'); params.push(filter.to) }
    const where = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : ''
    const rows = this.ctx.txnStore.sql<UsageRow>(`SELECT * FROM usage_events${where} ORDER BY occurred_at DESC LIMIT ?`, [...params, Math.min(filter.limit ?? 100, 1000)])
    const total = Number((this.ctx.txnStore.sql<{ n: number }>(`SELECT COUNT(*) AS n FROM usage_events${where}`, params)[0] ?? { n: 0 }).n)
    return { total, items: rows.map(rowToEvent) }
  }

  totals(filter: { tenant_id?: string; principal?: string; resource?: string; from?: string; to?: string } = {}): { count: number; charge_cents: number; cost_cents: number } {
    const conditions: string[] = []
    const params: Array<string | number> = []
    if (filter.tenant_id) { conditions.push('tenant_id = ?'); params.push(filter.tenant_id) }
    if (filter.principal) { conditions.push('principal = ?'); params.push(filter.principal) }
    // QA B-03 : le filtre resource était auparavant silencieusement ignoré quand la colonne manquait en SQL (l'outil usage_query renvoyait les chiffres de toute la base) — corrigé
    if (filter.resource) { conditions.push('resource = ?'); params.push(filter.resource) }
    if (filter.from) { conditions.push('occurred_at >= ?'); params.push(filter.from) }
    if (filter.to) { conditions.push('occurred_at <= ?'); params.push(filter.to) }
    const where = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : ''
    const row = this.ctx.txnStore.sql<{ n: number; charge: number; cost: number }>(
      `SELECT COUNT(*) AS n, COALESCE(SUM(CAST(json_extract(pricing_json, '$.charge_cents') AS INTEGER)), 0) AS charge, COALESCE(SUM(CAST(json_extract(pricing_json, '$.cost_cents') AS INTEGER)), 0) AS cost FROM usage_events${where}`,
      params,
    )[0] ?? { n: 0, charge: 0, cost: 0 }
    return { count: Number(row.n), charge_cents: Number(row.charge), cost_cents: Number(row.cost) }
  }

  /**
   * Agrégats d'analyse opérationnelle (page d'exploitation des actifs/rapport de perçage des coûts) : fenêtre groupée par ressource / sujet d'imputation (organisation) / tendance journalière.
   * Un SQL prend un agrégat de chaque, pour le référentiel opérationnel « qui utilise quel actif, à quel coût interne ».
   * M0-3 : le référentiel des montants est la référence de coût interne (cost_cents) ; charge_cents instantané à prix zéro constant 0, simple champ de compatibilité de l'instantané d'événement.
   */
  breakdown(fromIso: string): {
    byResource: Array<{ resource: string; count: number; charge_cents: number; cost_cents: number }>
    byPrincipal: Array<{ principal: string; count: number; charge_cents: number; cost_cents: number }>
    byDay: Array<{ day: string; count: number; charge_cents: number; cost_cents: number }>
  } {
    const byResource = this.ctx.txnStore.sql<{ resource: string; count: number; charge_cents: number; cost_cents: number }>(
      "SELECT resource, COUNT(*) AS count, COALESCE(SUM(CAST(json_extract(pricing_json, '$.charge_cents') AS INTEGER)), 0) AS charge_cents, COALESCE(SUM(CAST(json_extract(pricing_json, '$.cost_cents') AS INTEGER)), 0) AS cost_cents FROM usage_events WHERE occurred_at >= ? GROUP BY resource ORDER BY cost_cents DESC, count DESC",
      [fromIso],
    ).map((row) => ({ resource: row.resource, count: Number(row.count), charge_cents: Number(row.charge_cents), cost_cents: Number(row.cost_cents) }))
    const byPrincipal = this.ctx.txnStore.sql<{ principal: string; count: number; charge_cents: number; cost_cents: number }>(
      "SELECT principal, COUNT(*) AS count, COALESCE(SUM(CAST(json_extract(pricing_json, '$.charge_cents') AS INTEGER)), 0) AS charge_cents, COALESCE(SUM(CAST(json_extract(pricing_json, '$.cost_cents') AS INTEGER)), 0) AS cost_cents FROM usage_events WHERE occurred_at >= ? GROUP BY principal ORDER BY cost_cents DESC, count DESC",
      [fromIso],
    ).map((row) => ({ principal: row.principal, count: Number(row.count), charge_cents: Number(row.charge_cents), cost_cents: Number(row.cost_cents) }))
    const byDay = this.ctx.txnStore.sql<{ day: string; count: number; charge_cents: number; cost_cents: number }>(
      "SELECT substr(occurred_at, 1, 10) AS day, COUNT(*) AS count, COALESCE(SUM(CAST(json_extract(pricing_json, '$.charge_cents') AS INTEGER)), 0) AS charge_cents, COALESCE(SUM(CAST(json_extract(pricing_json, '$.cost_cents') AS INTEGER)), 0) AS cost_cents FROM usage_events WHERE occurred_at >= ? GROUP BY day ORDER BY day",
      [fromIso],
    ).map((row) => ({ day: row.day, count: Number(row.count), charge_cents: Number(row.charge_cents), cost_cents: Number(row.cost_cents) }))
    return { byResource, byPrincipal, byDay }
  }

  /**
   * Matrice d'observation : nombre d'utilisations ressource×jour des ressources du préfixe dans la fenêtre (source de données de vues d'observation type carte de chaleur des skills).
   * Le préfixe est passé par l'appelant en littéral de code (ex. 'skill:'), sans joker LIKE.
   */
  matrix(fromIso: string, prefix: string): Array<{ resource: string; day: string; count: number }> {
    return this.ctx.txnStore.sql<{ resource: string; day: string; count: number }>(
      "SELECT resource, substr(occurred_at, 1, 10) AS day, COUNT(*) AS count FROM usage_events WHERE occurred_at >= ? AND resource LIKE ? GROUP BY resource, day ORDER BY day",
      [fromIso, `${prefix}%`],
    ).map((row) => ({ resource: row.resource, day: String(row.day), count: Number(row.count) }))
  }

  /**
   * Agrégat de chaîne de collaboration (additive face collaboration A2A/UHP C4) : agrège « le coût total
    * d'une collaboration inter-employés » par context_id (contextId A2A). Requête mono-chaîne = tous les événements de la chaîne (ordre chronologique) ; résumé de fenêtre = Top chaînes.
   * Référentiel des montants identique à usageReport : tokens = somme des mètres dont le nom de clé contient tokens, cost = référence de coût interne.
   */
  collaborationEvents(contextId: string): UsageEvent[] {
    if (!contextId) return []
    const rows = this.ctx.txnStore.sql<UsageRow>(
      'SELECT * FROM usage_events WHERE context_id = ? ORDER BY occurred_at ASC',
      [contextId],
    )
    return rows.map(rowToEvent)
  }

  collaborationSummary(fromIso: string, limit = 20): Array<{ contextId: string; events: number; tokens: number; cost_cents: number; charge_cents: number; firstAt: string; lastAt: string }> {
    return this.ctx.txnStore.sql<{
      context_id: string
      events: number
      tokens: number
      cost_cents: number
      charge_cents: number
      firstAt: string
      lastAt: string
    }>(
      "SELECT context_id, COUNT(*) AS events, COALESCE(SUM((SELECT SUM(CAST(json_extract(m.value, '$.value') AS INTEGER)) FROM json_each(e.meters_json) m WHERE json_extract(m.value, '$.key') LIKE '%tokens%')), 0) AS tokens, COALESCE(SUM(CAST(json_extract(e.pricing_json, '$.cost_cents') AS INTEGER)), 0) AS cost_cents, COALESCE(SUM(CAST(json_extract(e.pricing_json, '$.charge_cents') AS INTEGER)), 0) AS charge_cents, MIN(e.occurred_at) AS firstAt, MAX(e.occurred_at) AS lastAt FROM usage_events e WHERE e.occurred_at >= ? AND e.context_id != '' GROUP BY e.context_id ORDER BY tokens DESC, cost_cents DESC, events DESC, lastAt DESC, context_id ASC LIMIT ?",
      [fromIso, Math.min(Math.max(limit, 1), 100)],
    ).map((row) => ({
      contextId: row.context_id,
      events: Number(row.events),
      tokens: Number(row.tokens) || 0,
      cost_cents: Number(row.cost_cents) || 0,
      charge_cents: Number(row.charge_cents) || 0,
      firstAt: String(row.firstAt),
      lastAt: String(row.lastAt),
    }))
  }

  /**
   * Agrégat registre d'actifs/rapport d'usage (adaptation de conception 2026-10-14, lecture seule additive) :
   * fenêtre [from, to) groupée en trois dimensions ressource/département/jour : agrégat appels+tokens+coût interne.
   *
   * Référentiel calls : somme des valeurs des mètres de clé calls des événements (un metering en lot peut représenter plusieurs appels),
   * un événement sans mètre calls (ex. événements historiques mcp:/model: tarifés aux tokens) compte pour 1 —
   * « un enregistrement = un lot d'appels ». Référentiel tokens identique à summary/monthlyReport (tous les noms de clé contenant tokens cumulés).
   */
  usageReport(fromIso: string, toIso?: string): {
    byResource: Array<{ resource: string; events: number; calls: number; tokens: number; cost_cents: number }>
    byOrg: Array<{ org: string; events: number; calls: number; tokens: number; cost_cents: number }>
    byDay: Array<{ day: string; events: number; calls: number; tokens: number; cost_cents: number }>
  } {
    const tokensExpr = "COALESCE(SUM((SELECT SUM(CAST(json_extract(m.value, '$.value') AS INTEGER)) FROM json_each(e.meters_json) m WHERE json_extract(m.value, '$.key') LIKE '%tokens%')), 0)"
    const callsExpr = "COALESCE(SUM(COALESCE((SELECT SUM(CAST(json_extract(m.value, '$.value') AS INTEGER)) FROM json_each(e.meters_json) m WHERE json_extract(m.value, '$.key') = 'calls'), 1)), 0)"
    const costExpr = "COALESCE(SUM(CAST(json_extract(e.pricing_json, '$.cost_cents') AS INTEGER)), 0)"
    const window = toIso === undefined ? ' WHERE e.occurred_at >= ?' : ' WHERE e.occurred_at >= ? AND e.occurred_at < ?'
    const params = toIso === undefined ? [fromIso] : [fromIso, toIso]
    const run = <T extends Record<string, unknown>>(dimension: string): T[] =>
      this.ctx.txnStore.sql<T>(`SELECT ${dimension} AS dimension, COUNT(*) AS events, ${callsExpr} AS calls, ${tokensExpr} AS tokens, ${costExpr} AS cost_cents FROM usage_events e${window} GROUP BY ${dimension}`, params)
    const num = (value: unknown): number => Number(value) || 0
    return {
      byResource: run<{ dimension: string; events: number; calls: number; tokens: number; cost_cents: number }>('e.resource')
        .map((row) => ({ resource: String(row.dimension), events: num(row.events), calls: num(row.calls), tokens: num(row.tokens), cost_cents: num(row.cost_cents) }))
        .sort((a, b) => b.cost_cents - a.cost_cents || b.calls - a.calls),
      byOrg: run<{ dimension: string; events: number; calls: number; tokens: number; cost_cents: number }>('e.org')
        .map((row) => ({ org: String(row.dimension), events: num(row.events), calls: num(row.calls), tokens: num(row.tokens), cost_cents: num(row.cost_cents) }))
        .sort((a, b) => b.cost_cents - a.cost_cents || b.calls - a.calls),
      byDay: run<{ dimension: string; events: number; calls: number; tokens: number; cost_cents: number }>("substr(e.occurred_at, 1, 10)")
        .map((row) => ({ day: String(row.dimension), events: num(row.events), calls: num(row.calls), tokens: num(row.tokens), cost_cents: num(row.cost_cents) }))
        .sort((a, b) => a.day.localeCompare(b.day)),
    }
  }

  /**
   * Tendance ressource×jour du nombre d'appels (adaptation de conception 2026-10-14, lecture seule additive) :
   * source de données du trend[14] du registre et du heat[30] du marché ; référentiel calls identique à usageReport
   * (somme des mètres calls, événement sans ce mètre compté 1). Le préfixe est passé par l'appelant en littéral de code (comme matrix),
   * défaut toutes ressources.
   */
  callsTrend(fromIso: string, prefix?: string): Array<{ resource: string; day: string; calls: number }> {
    const conditions = ['e.occurred_at >= ?']
    const params: Array<string | number> = [fromIso]
    if (prefix !== undefined) { conditions.push('e.resource LIKE ?'); params.push(`${prefix}%`) }
    return this.ctx.txnStore.sql<{ resource: string; day: string; calls: number }>(
      "SELECT e.resource AS resource, substr(e.occurred_at, 1, 10) AS day," +
      " COALESCE(SUM(COALESCE((SELECT SUM(CAST(json_extract(m.value, '$.value') AS INTEGER)) FROM json_each(e.meters_json) m WHERE json_extract(m.value, '$.key') = 'calls'), 1)), 0) AS calls" +
      ` FROM usage_events e WHERE ${conditions.join(' AND ')} GROUP BY e.resource, substr(e.occurred_at, 1, 10)`,
      params,
    ).map((row) => ({ resource: String(row.resource), day: String(row.day), calls: Number(row.calls) || 0 }))
  }

  /**
   * Résumé coût/usage (livraison IAW 4-1 : interface minimale de requête de coût côté panneau).
   * Fenêtre [from, to) filtrée par org / sujet : nombre d'événements, coût interne (référentiel cost_cents,
   * charge_cents instantané à prix zéro constant 0), tokens en trois parts (input/output/autres) et ventilation par ressource.
   * La stratification de permissions relève de la couche HTTP : usage.read interroge tout sujet, panel.read ne lit que sa propre organisation (le resserrement de périmètre est fait à l'endpoint).
   */
  summary(filter: { from: string; to: string; org?: string; subject?: string }): UsageSummary {
    if (!filter.from || !filter.to) throw new Error(t('summary 需要 from/to 窗口'))
    const conditions = ['e.occurred_at >= ?', 'e.occurred_at < ?']
    const params: Array<string | number> = [filter.from, filter.to]
    if (filter.org) { conditions.push('e.org = ?'); params.push(filter.org) }
    if (filter.subject) { conditions.push('e.subject = ?'); params.push(filter.subject) }
    const where = ` WHERE ${conditions.join(' AND ')}`
    const whereAnd = ` AND ${conditions.join(' AND ')}`
    // QA B-01 : la sous-requête corrélée doit être enveloppée dans une fonction d'agrégation — SQLite, dans la liste SELECT d'une requête GROUP BY, n'évalue
    // la sous-requête corrélée nue que sur une ligne quelconque du groupe, les tokens ne comptaient donc qu'un événement arbitraire par groupe (rapport J4 176 fois trop petit).
    // SUM((SELECT …)) évalue la sous-requête ligne par ligne puis somme, référentiel cohérent avec le JOIN json_each et auto-cohérent en trois dimensions.
    const tokensExpr = "COALESCE(SUM((SELECT SUM(CAST(json_extract(m.value, '$.value') AS INTEGER)) FROM json_each(e.meters_json) m WHERE json_extract(m.value, '$.key') LIKE '%tokens%')), 0)"
    // #14 : not_priced = coût 0 et (annotation explicite ou instantané à taux nul) — « inconnu » et « vrai coût nul » séparés à la lecture.
    // Le jugement d'instantané à taux nul couvre deux classes : après correctif, l'événement porte l'annotation nonbillable/cost_status ; un événement existant
    // (inscrit avant l'introduction des champs d'annotation) est sans annotation, mais l'instantané rate enregistre toujours le taux réellement employé — list=0 et cost=0 =
    // taux entièrement nul, sémantiquement équivalent à l'annotation, reconnu directement à la lecture sans migration ponctuelle. Un taux configuré mais un montant arrondi à 0
    //(rate.cost>0) ne correspond pas, reste priced ; rate absent (données très anciennes) indécidable, prudent : compté priced.
    const notPricedExpr = "COALESCE(SUM(CASE WHEN CAST(json_extract(e.pricing_json, '$.cost_cents') AS INTEGER) = 0 AND (json_extract(e.pricing_json, '$.rate.nonbillable') = 1 OR json_extract(e.pricing_json, '$.cost_status') = 'not_priced' OR (json_extract(e.pricing_json, '$.rate.list_cents_per_unit') = 0 AND json_extract(e.pricing_json, '$.rate.cost_cents_per_unit') = 0)) THEN 1 ELSE 0 END), 0)"
    const byResource = this.ctx.txnStore.sql<{ resource: string; events: number; tokens: number; cost_cents: number; charge_cents: number; not_priced_events: number }>(
      `SELECT e.resource AS resource, COUNT(*) AS events, ${tokensExpr} AS tokens,` +
      " COALESCE(SUM(CAST(json_extract(e.pricing_json, '$.cost_cents') AS INTEGER)), 0) AS cost_cents," +
      " COALESCE(SUM(CAST(json_extract(e.pricing_json, '$.charge_cents') AS INTEGER)), 0) AS charge_cents," +
      ` ${notPricedExpr} AS not_priced_events` +
      ` FROM usage_events e${where} GROUP BY e.resource ORDER BY cost_cents DESC, events DESC`,
      params,
    ).map((row) => ({ resource: row.resource, events: Number(row.events), tokens: Number(row.tokens), cost_cents: Number(row.cost_cents), charge_cents: Number(row.charge_cents), not_priced_events: Number(row.not_priced_events) }))
    const tokenSplit = (key: string): number => Number((this.ctx.txnStore.sql<{ n: number }>(
      "SELECT COALESCE(SUM(CAST(json_extract(m.value, '$.value') AS INTEGER)), 0) AS n FROM usage_events e, json_each(e.meters_json) m" +
      ` WHERE json_extract(m.value, '$.key') = ?${whereAnd}`,
      [key, ...params],
    )[0] ?? { n: 0 }).n)
    return {
      from: filter.from,
      to: filter.to,
      events: byResource.reduce((sum, row) => sum + row.events, 0),
      cost_cents: byResource.reduce((sum, row) => sum + row.cost_cents, 0),
      charge_cents: byResource.reduce((sum, row) => sum + row.charge_cents, 0),
      input_tokens: tokenSplit('input_tokens'),
      output_tokens: tokenSplit('output_tokens'),
      // #14 : couverture de coût (priced = events − not_priced), la barrière en juge si « le coût est imputable »
      not_priced_events: byResource.reduce((sum, row) => sum + row.not_priced_events, 0),
      byResource,
    }
  }

  /**
   * Agrégat des retours de production (livraison IAW 4-2 : taux d'adoption des productions d'Agent).
   * Source : événements usage en instantané à prix zéro des retours 👍/👎 inscrits (préfixe de clé idempotente feedback:, référentiel D2) ;
   * score pris dans le dernier segment de la clé idempotente (:up/:down), ressource/sujet dans les champs d'événement. adoptionRate = up/(up+down), null sans retour.
   */
  feedbackStats(filter: { from?: string; to?: string; org?: string } = {}): {
    from?: string; to?: string
    up: number; down: number; total: number; adoptionRate: number | null
    byResource: Array<{ resource: string; up: number; down: number; total: number; adoptionRate: number | null }>
    byDay: Array<{ day: string; up: number; down: number }>
  } {
    const conditions = ["idempotency_key LIKE 'feedback:%'"]
    const params: Array<string | number> = []
    if (filter.from) { conditions.push('occurred_at >= ?'); params.push(filter.from) }
    if (filter.to) { conditions.push('occurred_at < ?'); params.push(filter.to) }
    if (filter.org) { conditions.push('org = ?'); params.push(filter.org) }
    // Source du score (groupe 4 : clé idempotente sans segment score) — nouveau format : score avec le contenu d'événement (meter unit=up/down) ;
    // les lignes existantes gardent le segment score en queue de clé, analyse de repli sur la queue (référentiel d'agrégation inchangé pendant la coexistence des deux générations)
    const rows = this.ctx.txnStore.sql<{ resource: string; subject: string; org: string; day: string; idempotency_key: string; meters_json: string }>(
      `SELECT resource, subject, org, substr(occurred_at, 1, 10) AS day, idempotency_key, meters_json FROM usage_events WHERE ${conditions.join(' AND ')}`,
      params,
    ).map((row) => {
      let score = ''
      try {
        const unit = JSON.parse(row.meters_json)?.[0]?.unit
        if (unit === 'up' || unit === 'down') score = unit
      } catch { /* contenu corrompu : repli sur l'analyse de la fin de clé */ }
      if (score !== 'up' && score !== 'down') score = row.idempotency_key.slice(row.idempotency_key.lastIndexOf(':') + 1)
      return { ...row, score }
    })
    const count = (score: string) => rows.filter((row) => row.score === score).length
    const rate = (up: number, total: number): number | null => (total === 0 ? null : Math.round((up / total) * 1000) / 1000)
    const resources = new Map<string, { up: number; down: number }>()
    const days = new Map<string, { up: number; down: number }>()
    for (const row of rows) {
      const bucket = resources.get(row.resource) ?? { up: 0, down: 0 }
      if (row.score === 'up') bucket.up++
      if (row.score === 'down') bucket.down++
      resources.set(row.resource, bucket)
      const day = days.get(row.day) ?? { up: 0, down: 0 }
      if (row.score === 'up') day.up++
      if (row.score === 'down') day.down++
      days.set(row.day, day)
    }
    const up = count('up')
    const down = count('down')
    return {
      ...(filter.from ? { from: filter.from } : {}),
      ...(filter.to ? { to: filter.to } : {}),
      up,
      down,
      total: rows.length,
      adoptionRate: rate(up, rows.length),
      byResource: [...resources.entries()].map(([resource, bucket]) => ({
        resource, up: bucket.up, down: bucket.down, total: bucket.up + bucket.down, adoptionRate: rate(bucket.up, bucket.up + bucket.down),
      })).sort((a, b) => b.total - a.total),
      byDay: [...days.entries()].map(([day, bucket]) => ({ day, ...bucket })).sort((a, b) => a.day.localeCompare(b.day)),
    }
  }

  /**
   * Agrégat du rapport mensuel d'usage J4 (M0-3 : rapport de metering transparent de l'usage ; référentiel du contrat voir docs/contract-j4-usage-report.md).
   * Agrégat tridimensionnel de tokens : département (champ d'imputation org) / Agent (subject=agent:*) / Skill (resource=skill:*),
   * avec dimension modèle (byModel, additive) et totaux toutes dimensions ; tokens = somme des mètres dont le nom de clé contient "tokens"
   * (input_tokens/output_tokens/tokens cumulés au même référentiel). nonbillable_events = nombre d'événements en instantané à prix zéro (D2).
   */
  monthlyReport(month?: string): MonthlyUsageReport {
    const period = month ?? new Date().toISOString().slice(0, 7)
    if (!/^\d{4}-\d{2}$/.test(period)) throw new Error(t('报表月份格式应为 YYYY-MM'))
    const [from, to] = periodBoundsIso(period)
    // QA B-01 : comme summary — la sous-requête doit être enveloppée dans SUM(), sinon sous GROUP BY chaque groupe ne compte qu'une ligne arbitraire
    const tokensExpr = "COALESCE(SUM((SELECT SUM(CAST(json_extract(m.value, '$.value') AS INTEGER)) FROM json_each(e.meters_json) m WHERE json_extract(m.value, '$.key') LIKE '%tokens%')), 0)"
    const select = (dimension: string, extraWhere: string) =>
      this.ctx.txnStore.sql<ReportRow>(
        `SELECT ${dimension} AS dimension, COUNT(*) AS events, ${tokensExpr} AS tokens,` +
        " COALESCE(SUM(CAST(json_extract(e.pricing_json, '$.charge_cents') AS INTEGER)), 0) AS charge_cents," +
        " COALESCE(SUM(CAST(json_extract(e.pricing_json, '$.cost_cents') AS INTEGER)), 0) AS cost_cents," +
        " COALESCE(SUM(CASE WHEN json_extract(e.pricing_json, '$.rate.nonbillable') = 1 THEN 1 ELSE 0 END), 0) AS nonbillable_events" +
        ` FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ?${extraWhere} GROUP BY ${dimension} ORDER BY tokens DESC, events DESC`,
        [from, to],
      ).map((row) => ({
        dimension: String(row.dimension),
        events: Number(row.events),
        tokens: Number(row.tokens),
        charge_cents: Number(row.charge_cents),
        cost_cents: Number(row.cost_cents),
        nonbillable_events: Number(row.nonbillable_events),
      }))
    const totalsRows = select("'ALL'", '')
    const totals = totalsRows[0] ?? { dimension: 'ALL', events: 0, tokens: 0, charge_cents: 0, cost_cents: 0, nonbillable_events: 0 }
    return {
      month: period,
      from,
      to,
      totals,
      byOrg: select('e.org', ''),
      byAgent: select('e.subject', " AND e.subject LIKE 'agent:%'"),
      bySkill: select('e.resource', " AND e.resource LIKE 'skill:%'"),
      byModel: select('e.resource', " AND e.resource LIKE 'model:%'"),
    }
  }

  // -- Perçage des coûts FinOps et détection de marche au vide (M2) ---------------------------------------

  /**
   * Perçage des coûts FinOps (vue CFO v1) : tableau croisé org×model sur fenêtre mensuelle + variation par rapport au mois précédent + Top sujets consommateurs.
   * Référentiel des montants identique à J4 : cost_cents référence de coût d'achat interne (charge_cents instantané à prix zéro constant 0, hors perçage).
   * matrix prend les Top 8 départements × Top 8 modèles (par coût décroissant), le reste fondu dans « autres », contre la noyade de la conclusion principale par les petits échantillons.
   */
  costPenetration(month?: string): FinOpsCostPenetration {
    const period = month ?? new Date().toISOString().slice(0, 7)
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(period)) throw new Error(t('报表月份格式应为 YYYY-MM（月份 01-12）'))
    const [from, to] = periodBoundsIso(period)
    const [prevFrom, prevTo] = month === undefined ? currentPrevMonthBoundsIso() : prevMonthBoundsIso(period)
    const tokensExpr = "COALESCE(SUM((SELECT SUM(CAST(json_extract(m.value, '$.value') AS INTEGER)) FROM json_each(e.meters_json) m WHERE json_extract(m.value, '$.key') LIKE '%tokens%')), 0)"
    const costExpr = "COALESCE(SUM(CAST(json_extract(e.pricing_json, '$.cost_cents') AS INTEGER)), 0)"

    const windowTotals = (lo: string, hi: string): { events: number; cost_cents: number; tokens: number } => {
      const row = this.ctx.txnStore.sql<{ events: number; cost_cents: number; tokens: number }>(
        `SELECT COUNT(*) AS events, ${costExpr} AS cost_cents, ${tokensExpr} AS tokens FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ?`,
        [lo, hi],
      )[0] ?? { events: 0, cost_cents: 0, tokens: 0 }
      return { events: Number(row.events), cost_cents: Number(row.cost_cents), tokens: Number(row.tokens) }
    }
    const deltaPct = (cur: number, prev: number): number | null =>
      prev === 0 ? (cur === 0 ? 0 : null) : Math.round(((cur - prev) / prev) * 1000) / 10

    const orgRows = this.ctx.txnStore.sql<{ org: string; events: number; tokens: number; cost_cents: number }>(
      `SELECT e.org AS org, COUNT(*) AS events, ${tokensExpr} AS tokens, ${costExpr} AS cost_cents FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ? GROUP BY e.org ORDER BY cost_cents DESC, events DESC`,
      [from, to],
    )
    const prevByOrg = new Map(this.ctx.txnStore.sql<{ org: string; cost_cents: number }>(
      `SELECT e.org AS org, ${costExpr} AS cost_cents FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ? GROUP BY e.org`,
      [prevFrom, prevTo],
    ).map((row) => [row.org, Number(row.cost_cents)]))
    // Top modèles par département (part de coût) — un SQL agrège org×model puis prend le Top3 en mémoire
    const orgModelRows = this.ctx.txnStore.sql<{ org: string; resource: string; cost_cents: number }>(
      `SELECT e.org AS org, e.resource AS resource, ${costExpr} AS cost_cents FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ? AND e.resource LIKE 'model:%' GROUP BY e.org, e.resource`,
      [from, to],
    )
    const modelsByOrg = new Map<string, Array<{ model: string; cost_cents: number }>>()
    for (const row of orgModelRows) {
      const list = modelsByOrg.get(row.org) ?? []
      list.push({ model: row.resource.slice('model:'.length), cost_cents: Number(row.cost_cents) })
      modelsByOrg.set(row.org, list)
    }

    const byOrg: FinOpsDimRow[] = orgRows.map((row) => {
      const cost = Number(row.cost_cents)
      const topModels = (modelsByOrg.get(row.org) ?? [])
        .sort((a, b) => b.cost_cents - a.cost_cents).slice(0, 3)
        .map((item) => ({ model: item.model, cost_cents: item.cost_cents, share: cost > 0 ? Math.round((item.cost_cents / cost) * 1000) / 10 : 0 }))
      return {
        dimension: row.org,
        events: Number(row.events),
        tokens: Number(row.tokens),
        cost_cents: cost,
        prev_cost_cents: prevByOrg.get(row.org) ?? 0,
        delta_pct: deltaPct(cost, prevByOrg.get(row.org) ?? 0),
        ...(topModels.length > 0 ? { topModels } : {}),
      }
    })

    const byModel: FinOpsDimRow[] = this.ctx.txnStore.sql<{ resource: string; events: number; tokens: number; cost_cents: number }>(
      `SELECT e.resource AS resource, COUNT(*) AS events, ${tokensExpr} AS tokens, ${costExpr} AS cost_cents FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ? AND e.resource LIKE 'model:%' GROUP BY e.resource ORDER BY cost_cents DESC, events DESC`,
      [from, to],
    ).map((row) => {
      const cost = Number(row.cost_cents)
      const prev = Number((this.ctx.txnStore.sql<{ cost_cents: number }>(
        `SELECT ${costExpr} AS cost_cents FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ? AND e.resource = ?`,
        [prevFrom, prevTo, row.resource],
      )[0] ?? { cost_cents: 0 }).cost_cents)
      return {
        dimension: row.resource.slice('model:'.length),
        events: Number(row.events),
        tokens: Number(row.tokens),
        cost_cents: cost,
        prev_cost_cents: prev,
        delta_pct: deltaPct(cost, prev),
      }
    })

    // Matrice croisée org×model (Top8×Top8, lignes et colonnes avec chacune un repli « autres » ; le total vaut toujours le coût toutes dimensions)
    const topOrgs = byOrg.slice(0, 8).map((row) => row.dimension)
    const topModels = byModel.slice(0, 8).map((row) => row.dimension)
    const orgIndex = new Map(topOrgs.map((org, i) => [org, i]))
    const modelIndex = new Map(topModels.map((model, i) => [model, i]))
    const R = topOrgs.length
    const C = topModels.length
    const byModelKey = new Map(byModel.map((row) => [row.dimension, row]))
    const cells: number[][] = Array.from({ length: R + 1 }, () => Array<number>(C + 1).fill(0))
    for (const row of orgModelRows) {
      const model = row.resource.slice('model:'.length)
      const i = orgIndex.get(row.org) ?? R
      const j = modelIndex.get(model) ?? C
      cells[i]![j]! += Number(row.cost_cents)
    }
    const totals = windowTotals(from, to)
    const prevTotals = windowTotals(prevFrom, prevTo)
    // Ligne/colonne « autres » = le plein du département/modèle dans le domaine model − la somme en angle droit du Top8 (attention : le référentiel de ligne doit aussi être le domaine model,
    // pas le coût toutes ressources de byOrg, sinon la matrice mélange des coûts non-modèle et le total fausse) ; la cellule d'angle garde l'accumulation brute de la boucle de la première étape
    // (le coût où org et model dépassent tous deux le Top8 tombe naturellement dans cells[R][C]), le total matrice vaut toujours le coût modèle toutes dimensions
    const orgModelTotal = new Map<string, number>()
    for (const row of orgModelRows) orgModelTotal.set(row.org, (orgModelTotal.get(row.org) ?? 0) + Number(row.cost_cents))
    for (let i = 0; i < R; i++) {
      cells[i]![C] = (orgModelTotal.get(topOrgs[i]!) ?? 0) - cells[i]!.slice(0, C).reduce((sum, v) => sum + v, 0)
    }
    for (let j = 0; j < C; j++) {
      const modelFull = byModelKey.get(topModels[j]!)?.cost_cents ?? 0
      cells[R]![j] = modelFull - Array.from({ length: R }, (_, i) => cells[i]![j]!).reduce((sum, v) => sum + v, 0)
    }

    const topSubjects = this.ctx.txnStore.sql<{ subject: string; org: string; events: number; cost_cents: number }>(
      `SELECT e.subject AS subject, e.org AS org, COUNT(*) AS events, ${costExpr} AS cost_cents FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ? GROUP BY e.subject, e.org ORDER BY cost_cents DESC, events DESC LIMIT 10`,
      [from, to],
    ).map((row) => ({ subject: row.subject, org: row.org, events: Number(row.events), cost_cents: Number(row.cost_cents) }))

    return {
      month: period,
      from,
      to,
      prevFrom,
      prevTo,
      totals: { ...totals, prev_cost_cents: prevTotals.cost_cents, delta_pct: deltaPct(totals.cost_cents, prevTotals.cost_cents) },
      byOrg,
      byModel,
      matrix: { orgs: topOrgs, models: topModels, cells },
      topSubjects,
    }
  }

  /**
   * Détection FinOps de marche au vide v1 (référentiel approximatif) : « appel de modèle sans appel d'action ultérieur dans la fenêtre ».
   * Référentiel planifié (M2) : marche au vide = appel sans retour de résultat métier, d'abord approximé par « sans action ultérieure » —
   *   dans les idleWindowMinutes suivant l'appel de modèle, le même sujet (subject) n'a aucune action sur ressource non-modèle
    * (skill:/mcp:/nas:/app:/connector:/kb:, etc.) et son trace_id n'est associé à aucun événement d'action → suspect de marche au vide.
   * Faux positifs connus : la pure conversation (appel de modèle directement suivi d'une réponse à l'utilisateur, sans appel d'outil) compte — la page doit porter la mention « référentiel approximatif, revue humaine requise »,
   * le référentiel exact attend l'atterrissage des retours de résultats task_success/task_fail du moteur de preuves M4 (clé de metering à taux nul) pour être remplacé.
   */
  idleAnalysis(filter: { from?: string; to?: string; month?: string; idleWindowMinutes?: number } = {}): FinOpsIdleAnalysis {
    let from = filter.from ?? ''
    let to = filter.to ?? ''
    let month = filter.month
    if (!from || !to) {
      month = month ?? new Date().toISOString().slice(0, 7)
      if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) throw new Error(t('报表月份格式应为 YYYY-MM（月份 01-12）'))
      ;[from, to] = periodBoundsIso(month)
    }
    const idleWindowMs = Math.min(Math.max(Number(filter.idleWindowMinutes ?? 30), 1), 24 * 60) * 60_000

    interface ModelEventRow { occurred_at: string; subject: string; org: string; resource: string; trace_id: string; meters_json: string; cost_cents: number }
    const costExpr = "COALESCE(CAST(json_extract(e.pricing_json, '$.cost_cents') AS INTEGER), 0)"
    const modelRows = this.ctx.txnStore.sql<ModelEventRow & { cost_cents: number }>(
      `SELECT e.occurred_at, e.subject, e.org, e.resource, e.trace_id, e.meters_json, ${costExpr} AS cost_cents FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ? AND e.resource LIKE 'model:%' ORDER BY e.subject, e.occurred_at`,
      [from, to],
    ).map((row) => ({ ...row, cost_cents: Number(row.cost_cents) }))
    // Chronologie des actions (événements non-modèle) : horodatages croissants groupés par sujet + index de trace (une action dans la trace = réputé avoir un résultat métier)
    const actionRows = this.ctx.txnStore.sql<{ subject: string; occurred_at: string; trace_id: string }>(
      "SELECT e.subject, e.occurred_at, e.trace_id FROM usage_events e WHERE e.occurred_at >= ? AND e.occurred_at < ? AND e.resource NOT LIKE 'model:%' ORDER BY e.subject, e.occurred_at",
      [from, to],
    )
    const actionsBySubject = new Map<string, number[]>()
    const tracesWithAction = new Set<string>()
    for (const row of actionRows) {
      const list = actionsBySubject.get(row.subject) ?? []
      list.push(new Date(row.occurred_at).getTime())
      actionsBySubject.set(row.subject, list)
      if (row.trace_id) tracesWithAction.add(row.trace_id)
    }
    for (const list of actionsBySubject.values()) list.sort((a, b) => a - b)

    const modelTotals = { events: modelRows.length, cost_cents: 0, tokens: 0 }
    const idle = { events: 0, cost_cents: 0, tokens: 0 }
    const byModel = new Map<string, { model: string; events: number; cost_cents: number; idle_events: number; idle_cost_cents: number }>()
    const byOrg = new Map<string, { org: string; events: number; cost_cents: number; idle_events: number; idle_cost_cents: number }>()
    const samples: FinOpsIdleAnalysis['samples'] = []
    const meterTokens = (metersJson: string): number => {
      try {
        const meters = JSON.parse(metersJson) as Array<{ key: string; value: number }>
        return meters.filter((m) => m.key.includes('tokens')).reduce((sum, m) => sum + (Number(m.value) || 0), 0)
      } catch { return 0 }
    }
    for (const row of modelRows) {
      const tokens = meterTokens(row.meters_json)
      modelTotals.cost_cents += row.cost_cents
      modelTotals.tokens += tokens
      const model = row.resource.slice('model:'.length)
      const modelBucket = byModel.get(model) ?? { model, events: 0, cost_cents: 0, idle_events: 0, idle_cost_cents: 0 }
      modelBucket.events++
      modelBucket.cost_cents += row.cost_cents
      const orgBucket = byOrg.get(row.org) ?? { org: row.org, events: 0, cost_cents: 0, idle_events: 0, idle_cost_cents: 0 }
      orgBucket.events++
      orgBucket.cost_cents += row.cost_cents

      const at = new Date(row.occurred_at).getTime()
      const timeline = actionsBySubject.get(row.subject) ?? []
      // dichotomie : le sujet a-t-il encore une action non-modèle dans [at, at+window] (bordures comprises : une action au même instant que l'appel compte comme suite)
      let followUp = false
      let lo = 0
      let hi = timeline.length
      while (lo < hi) {
        const mid = (lo + hi) >> 1
        if (timeline[mid]! < at) lo = mid + 1
        else hi = mid
      }
      for (let i = lo; i < timeline.length && timeline[i]! <= at + idleWindowMs; i++) { followUp = true; break }
      if (!followUp && row.trace_id && tracesWithAction.has(row.trace_id)) followUp = true
      if (followUp) {
        byModel.set(model, modelBucket)
        byOrg.set(row.org, orgBucket)
        continue
      }
      idle.events++
      idle.cost_cents += row.cost_cents
      idle.tokens += tokens
      modelBucket.idle_events++
      modelBucket.idle_cost_cents += row.cost_cents
      orgBucket.idle_events++
      orgBucket.idle_cost_cents += row.cost_cents
      byModel.set(model, modelBucket)
      byOrg.set(row.org, orgBucket)
      if (samples.length < 20) {
        samples.push({ occurred_at: row.occurred_at, subject: row.subject, org: row.org, resource: row.resource, cost_cents: row.cost_cents, tokens })
      }
    }
    const share = modelTotals.cost_cents > 0 ? Math.round((idle.cost_cents / modelTotals.cost_cents) * 1000) / 10 : 0
    const pick = <T extends { events: number }>(map: Map<string, T>): T[] => [...map.values()].sort((a, b) => b.idle_cost_cents - a.idle_cost_cents || b.events - a.events)
    return {
      ...(month !== undefined ? { month } : {}),
      from,
      to,
      idleWindowMinutes: Math.round(idleWindowMs / 60_000),
      totals: modelTotals,
      idle: { ...idle, share_pct: share },
      byModel: pick(byModel),
      byOrg: pick(byOrg),
      samples,
    }
  }

  // -- Tarif ---------------------------------------------------------------
  priceBook(): Collection<PriceBookEntry> {
    return this.ctx.opsStorage.collection<PriceBookEntry>('usage:priceBook')
  }

  upsertPrice(entry: Omit<PriceBookEntry, 'id' | 'createdAt' | 'updatedAt'>): PriceBookEntry {
    // REL-11 : validation numérique de l'entrée d'écriture — auparavant {"list_cents_per_unit":"abc"} entrait au tarif en 200, la tarification produisait un instantané NaN,
    // la réconciliation était constamment en mismatch avec une alerte critical à chaque fois (empoisonnement permanent par données sales existantes). Illégal = erreur levée (guarded mappe uniformément en 400)
    for (const [field, value, min] of [
      ['list_cents_per_unit', entry.list_cents_per_unit, 0],
      ['cost_cents_per_unit', entry.cost_cents_per_unit, 0],
      ['tax_rate', entry.tax_rate, 0],
      ['units_per_step', entry.units_per_step, 1], // diviseur de tarification : 0 produirait Infinity, un négatif un montant négatif
    ] as Array<[string, number, number]>) {
      if (!Number.isFinite(value) || value < min) {
        throw new Error(t('价格簿字段 {field} 必须为有限数值且 ≥{min}，收到：{value}', { field, min, value: String(value) }))
      }
    }
    const existing = this.priceBook().findOne((item) => item.pattern === entry.pattern)
    if (existing) return this.priceBook().update(existing.id, { ...entry })
    return this.priceBook().insert({ id: newId('rate'), ...entry })
  }

  /**
   * Requête en lecture du tarif (#14, pour qu'un producteur de confiance prenne les taux à l'instant de l'appel et assemble des lignes de prix combiné ; non enregistré = undefined sans lever).
   * Référentiel d'appariement identique au priceOf interne de record() : exact → joker de préfixe.
   */
  priceOfResource(resource: string): PriceBookEntry | undefined {
    try {
      return this.priceOf(resource)
    } catch {
      return undefined
    }
  }

  private priceOf(resource: string): PriceBookEntry {
    const book = this.priceBook().all()
    const exact = book.find((item) => item.pattern === resource)
    if (exact) return exact
    const prefix = book.filter((item) => item.pattern.endsWith(':*')).sort((a, b) => b.pattern.length - a.pattern.length)
      .find((item) => resource.startsWith(item.pattern.slice(0, -1)))
    if (prefix) return prefix
    throw new Error(t('资源 {resource} 无计价规则：请先在价格簿登记（usage 价格簿）', { resource }))
  }

  private ensureDefaultPriceBook(): void {
    // Semis idempotent entrée par entrée : à la montée de version d'un déploiement existant, ne comble que les règles par défaut manquantes, sans écraser les taux modifiés par l'exploitation
    const defaults: Array<Omit<PriceBookEntry, 'id' | 'createdAt' | 'updatedAt'>> = [
      // M0-3 (2026-09-09) : mcp:* devient « instantané à prix zéro + référence de coût interne » — charge toujours 0 (pas de règlement externe), cost garde le référentiel du coût d'achat
      { pattern: 'mcp:*', meter_key: 'tokens', list_cents_per_unit: 0, cost_cents_per_unit: 15, units_per_step: 1000, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.09-cost' },
      { pattern: 'platform:*', meter_key: 'calls', list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.08' },
      // Complément d'observation : skill/nas d'abord à taux nul (une règle au tarif suffit pour entrer dans le pipeline), facturation éventuelle par retarification opérationnelle
      { pattern: 'skill:*', meter_key: 'calls', list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.08' },
      { pattern: 'nas:*', meter_key: 'calls', list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.08' },
      // Gestion des connecteurs (fusion open-connector) : même départ à taux nul ; la validation dure de record() exige une règle pour entrer dans le pipeline,
      // l'exploitation ajuste au besoin un connector:<provider> particulier en taux non nul (dev-plan-connector §2.6)
      { pattern: 'connector:*', meter_key: 'calls', list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.08' },
      // D1 (WP-03) : applications et paquets de savoir entrent au pipeline en observation — départ à taux nul, l'événement automatiquement en instantané non facturable à prix zéro (D2)
      { pattern: 'app:*', meter_key: 'calls', list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.09' },
      { pattern: 'kb:*', meter_key: 'calls', list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.09' },
      // WP-07 (retour feedback) : l'employé numérique hôte comme ressource observable — départ à taux nul, ajustable par l'exploitation
      { pattern: 'agent:*', meter_key: 'calls', list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.09' },
      // Panneau départemental (arbitrage D1 de review-dsh-agent-panel-v2) : format de clé de metering panel:<dept>.<code secteur> (ex. panel:mfg.qb01),
      // les formes double deux-points/@ ne passent pas la validation dure resource de record() ; départ à taux nul, ajustable par l'exploitation par paquet de secteur
      { pattern: 'panel:*', meter_key: 'calls', list_cents_per_unit: 0, cost_cents_per_unit: 0, units_per_step: 1, tax_rate: 0.06, currency: 'CNY', rate_version: 'v2026.09' },
    ]
    for (const entry of defaults) {
      if (!this.priceBook().findOne((item) => item.pattern === entry.pattern)) this.upsertPrice(entry)
    }
    // Migration des préexistants (M0-3) : si mcp:* porte encore l'ancien prix de revente par défaut (list 30 centimes/1k tokens, non modifié par l'exploitation),
    // remis à zéro vers le référentiel « instantané à prix zéro + référence de coût » ; les entrées activement retarifiées par l'exploitation restent intactes.
    const legacyMcp = this.priceBook().findOne((item) => item.pattern === 'mcp:*')
    if (legacyMcp && legacyMcp.list_cents_per_unit === 30 && legacyMcp.cost_cents_per_unit === 15 && legacyMcp.rate_version === 'v2026.08') {
      this.priceBook().update(legacyMcp.id, { list_cents_per_unit: 0, rate_version: 'v2026.09-cost' })
    }
  }

  // -- Réconciliation (comparaison des référentiels des trois parties) -----------------------------------------------

  /**
   * Réconciliation : référentiel usage (flux d'événements) vs référentiel projeté des consommateurs enregistrés, comparaison intégrale.
   * Le consommateur enregistre à l'accrochage via consume() sa collection projetée usage:projection:<consumerId>.
   */
  reconcile(windowFromIso?: string): {
    usage: { count: number; charge_cents: number }
    projections: Array<{ consumer: string; count: number; charge_cents: number; mismatch: boolean }>
    mismatch: boolean
  } {
    const usageTotals = this.totals(windowFromIso ? { from: windowFromIso } : {})
    const projections: Array<{ consumer: string; count: number; charge_cents: number; mismatch: boolean }> = []
    for (const consumerId of this.consumers.keys()) {
      const rows = this.ctx.opsStorage.collection<ProjectionRow>(`usage:projection:${consumerId}`).all()
        .filter((row) => (windowFromIso ? row.window >= windowFromIso.slice(0, 10) : true))
      const count = rows.reduce((sum, row) => sum + row.count, 0)
      // Durcissement lecture REL-11 : les lignes sales préexistantes de la collection projetée (charge_cents non fini) comptées à 0 dans la réconciliation, fini le mismatch permanent et l'alerte en boucle
      const charge = rows.reduce((sum, row) => sum + (Number.isFinite(row.charge_cents) ? row.charge_cents
        : this.warnDirtyData(`projection-row:${consumerId}:${row.id}`, t('usage 投影 {consumer} 窗口 {window} 的 charge_cents 非有限（存量脏数据），对账按 0 计入（REL-11）', { consumer: consumerId, window: row.window }))), 0)
      projections.push({
        consumer: consumerId,
        count,
        charge_cents: charge,
        mismatch: count !== usageTotals.count || charge !== usageTotals.charge_cents,
      })
    }
    const mismatch = projections.some((item) => item.mismatch)
    if (mismatch) {
      this.ctx.platformBus.emit('audit.alert.fired', {
        id: newId('alt'), severity: 'critical', title: t('usage 对账不平'),
        message: t('usage 口径 count={count} charge={charge} 分；消费方投影存在偏差：{detail}', { count: usageTotals.count, charge: usageTotals.charge_cents, detail: JSON.stringify(projections) }),
      })
    }
    return { usage: { count: usageTotals.count, charge_cents: usageTotals.charge_cents }, projections, mismatch }
  }

  /** Accumulation de la projection consommateur (appelé à l'intérieur du rappel consume()). */
  project(consumerId: string, event: UsageEvent): void {
    const collection = this.ctx.opsStorage.collection<ProjectionRow>(`usage:projection:${consumerId}`)
    const day = event.occurred_at.slice(0, 10)
    // Durcissement lecture REL-11 : un événement sale préexistant avec charge_cents non fini est projeté à 0 (contre la distorsion continue du référentiel de réconciliation), alerte dédupliquée par événement
    const rawCharge = event.pricing.charge_cents
    const charge = Number.isFinite(rawCharge) ? rawCharge
      : this.warnDirtyData(`projection:${event.event_id}`, t('usage 事件 {id} 的 pricing.charge_cents={value} 非有限（存量脏数据），本次投影按 0 计入（REL-11）', { id: event.event_id, value: String(rawCharge) }))
    const existing = collection.findOne((row) => row.window === day)
    if (existing) {
      collection.update(existing.id, { count: existing.count + 1, charge_cents: existing.charge_cents + charge })
    } else {
      collection.insert({ id: newId('prj'), window: day, count: 1, charge_cents: charge })
    }
  }

  // -- Réconciliation à l'exécution (M5 : déclaration vs comportement) --------------------------------------

  capabilityGrants(): Collection<CapabilityGrantRecord> {
    return this.ctx.opsStorage.collection<CapabilityGrantRecord>('usage:capabilityGrants')
  }

  grantCapabilities(principal: string, capabilities: string[], source: string): CapabilityGrantRecord {
    const existing = this.capabilityGrants().findOne((item) => item.principal === principal)
    if (existing) return this.capabilityGrants().update(existing.id, { capabilities, source })
    return this.capabilityGrants().insert({ id: newId('cap'), principal, capabilities, source })
  }

  /** Détection de dérive de capacités : ressources réellement consommées dans la fenêtre vs autorisations déclarées ; toute consommation réelle non déclarée déclenche l'alerte. */
  capabilityDrift(sinceIso?: string): { drift: Array<{ principal: string; consumed: string[]; granted: string[]; ungranted: string[] }> } {
    const { items } = this.query({ from: sinceIso, limit: 1000 })
    const consumedByPrincipal = new Map<string, Set<string>>()
    for (const event of items) {
      const set = consumedByPrincipal.get(event.principal) ?? new Set<string>()
      set.add(event.resource)
      consumedByPrincipal.set(event.principal, set)
    }
    const drift: Array<{ principal: string; consumed: string[]; granted: string[]; ungranted: string[] }> = []
    for (const [principal, consumedSet] of consumedByPrincipal) {
      const grant = this.capabilityGrants().findOne((item) => item.principal === principal)
      const granted = grant?.capabilities ?? []
      const ungranted = [...consumedSet].filter((resource) => !granted.some((cap) =>
        cap === '*' || cap === resource || (cap.endsWith(':*') && resource.startsWith(cap.slice(0, -1))),
      ))
      if (ungranted.length > 0) {
        drift.push({ principal, consumed: [...consumedSet], granted, ungranted })
        this.ctx.platformBus.emit('audit.alert.fired', {
          id: newId('alt'), severity: 'critical', title: t('usage 能力漂移'),
          message: t('主体 {principal} 实际消耗了未声明授权的资源：{resources}（运行时对账 M5）', { principal, resources: ungranted.join(', ') }),
          resourceType: 'usage_capability', resourceId: principal,
        })
      }
    }
    return { drift }
  }

  deadLetters(): Collection<DeadLetterRecord> {
    return this.ctx.opsStorage.collection<DeadLetterRecord>('usage:deadLetters')
  }

  // -- Justificatifs d'utilisation d'actifs (2026-10-31) ---------------------------------------------
  // Le rapport avec le pipeline de facturation usage_events est en tête d'asset-reports.ts : le justificatif est un fait d'utilisation (les usages
  // invisibles de la plateforme comme l'exécution locale d'un skill sont rapportés activement par l'Agent), hors tarif/référentiel de coût ; la validation de la boucle d'autorisation est dans prepareAssetUsageReport
  // (orchestration partagée entre routes REST et outils MCP, ce service ne gère que stockage/idempotence/requête/agrégation).

  /** Collection des justificatifs (clé idempotente unique au niveau moteur, empêche la comptabilisation dupliquée en concurrence). */
  assetReports(): Collection<AssetUsageReportRecord> {
    const collection = this.ctx.opsStorage.collection<AssetUsageReportRecord>('usage:assetReports')
    collection.uniqueOn('idempotencyKey', (record) => record.idempotencyKey)
    return collection
  }

  /** Écriture en base (idempotente) : même clé et même contenu → renvoie le justificatif d'origine deduped=true ; même clé et contenu différent → 409 ; l'événement de bus n'est émis qu'à la première écriture (la trace d'audit, elle, est consignée à chaque fois sans gonfler au rejeu). */
  submitAssetUsageReport(prepared: Omit<AssetUsageReportRecord, 'id' | 'createdAt' | 'updatedAt'>): { report: AssetUsageReportRecord; deduped: boolean } {
    const existing = this.assetReports().findOne((item) => item.idempotencyKey === prepared.idempotencyKey)
    if (existing) {
      if (reportFingerprint(existing) !== reportFingerprint(prepared)) {
        throw new AssetUsageError(409, 'IDEMPOTENCY_CONFLICT', t('幂等键冲突：{key} 已被不同内容的凭证占用（同键必须同内容，换业务单号）', { key: prepared.idempotencyKey }))
      }
      return { report: existing, deduped: true }
    }
    const report = this.assetReports().insert({ id: newId('aur'), ...prepared })
    this.ctx.platformBus.emit(PlatformEvents.UsageAssetReported, {
      actorType: report.reporterType,
      actor: report.agentId ?? report.userId ?? report.reporterPrincipalId,
      actorName: report.reporterName,
      type: report.assetType,
      id: report.assetKey,
      name: report.assetName,
      reason: `action=${report.action} outcome=${report.outcome} occurredAt=${report.occurredAt}${report.taskId ? ` taskId=${report.taskId}` : ''}${report.note ? ` note=${report.note}` : ''}`,
    })
    return { report, deduped: false }
  }

  /** Requête de justificatifs (sortie de réconciliation d'exploitation/audit) : filtres assetType/assetKey/agentId/from/to, tri inverse sur occurredAt. */
  assetUsageReports(filters: { assetType?: string; assetKey?: string; agentId?: string; from?: string; to?: string; limit?: number } = {}): AssetUsageReportRecord[] {
    let rows = this.assetReports().all()
    if (filters.assetType) rows = rows.filter((row) => row.assetType === filters.assetType)
    if (filters.assetKey) rows = rows.filter((row) => row.assetKey === filters.assetKey)
    if (filters.agentId) rows = rows.filter((row) => row.agentId === filters.agentId)
    if (filters.from) rows = rows.filter((row) => row.occurredAt >= filters.from!)
    if (filters.to) rows = rows.filter((row) => row.occurredAt <= filters.to!)
    rows.sort((a, b) => b.occurredAt.localeCompare(a.occurredAt))
    const limit = Math.min(Math.max(filters.limit ?? 100, 1), 500)
    return rows.slice(0, limit)
  }

  /** Agrégation du nombre de justificatifs par assetKey (référentiel usageReports30d du registre : occurredAt ≥ fromISO). */
  assetUsageReportCounts(fromISO: string): Map<string, number> {
    const counts = new Map<string, number>()
    for (const row of this.assetReports().all()) {
      if (row.occurredAt < fromISO) continue
      counts.set(row.assetKey, (counts.get(row.assetKey) ?? 0) + 1)
    }
    return counts
  }

  // -- Interne -----------------------------------------------------------------

  /**
   * REL-11 durcissement côté lecture : alerte warning sur données sales (taux/montants historiques non finis), renvoie toujours 0 en repli de tarification/projection.
   * Une même clé (durée de vie du processus) n'alerte qu'une fois, contre la tempête d'alertes déclenchée par chaque événement.
   */
  private warnDirtyData(key: string, message: string): 0 {
    if (!this.warnedDirtyKeys.has(key)) {
      this.warnedDirtyKeys.add(key)
      this.ctx.platformBus.emit('audit.alert.fired', {
        id: newId('alt'), severity: 'warning', title: t('usage 脏数据按 0 兜底（REL-11）'),
        message,
      })
    }
    return 0
  }

  private validate(input: UsageRecordInput): void {
    if (!input.org?.trim()) throw new Error(t('usage 事件 org 必填'))
    if (!input.subject?.trim()) throw new Error(t('usage 事件 subject 必填（user:<id> / agent:<id>）'))
    if (!input.principal?.trim()) throw new Error(t('usage 事件 principal 必填（org:<id> / plugin:<id> / platform）'))
    if (!input.resource?.trim() || !/^[a-z]+:[A-Za-z0-9._-]+$/.test(input.resource)) {
      throw new Error(t('usage 事件 resource 格式非法：{value}（应为 model:<slug> / mcp:<slug> / plugin:<id> / skill:<id> / nas:<id> / app:<id> / kb:<orgId>）', { value: String(input.resource) }))
    }
    if (!Array.isArray(input.meters) || input.meters.length === 0) throw new Error(t('usage 事件 meters 至少一项'))
    for (const meter of input.meters) {
      if (!meter.key || !/^[a-z][a-z0-9_.]*$/.test(meter.key)) throw new Error(t('计量键非法：{key}（^[a-z][a-z0-9_.]*$）', { key: meter.key }))
      if (!Number.isFinite(meter.value) || meter.value < 0) throw new Error(t('计量值非法：{key}={value}', { key: meter.key, value: meter.value }))
    }
  }

  /** Résolution du tenant : org → tenant (jeu minimal multi-tenant, étape 2 de la v1.2). */
  private resolveTenant(orgId: string): string {
    if (!orgId || orgId === '') return DEFAULT_TENANT
    return this.ctx.iam.orgs().get(orgId)?.tenantId ?? DEFAULT_TENANT
  }

  private autoIdempotencyKey(input: UsageRecordInput): string {
    const window = new Date().toISOString().slice(0, 16)
    return `usage:${input.principal}:${input.resource}:${window}:${++this.seq}`
  }
}

interface ProjectionRow extends RecordBase {
  window: string
  count: number
  charge_cents: number
}

/** Ligne du rapport mensuel J4 (valeur de dimension + nombre d'événements + agrégation tokens + référentiel monétaire + nombre d'événements à instantané à prix zéro). */
export interface MonthlyUsageReportRow {
  dimension: string
  events: number
  tokens: number
  charge_cents: number
  cost_cents: number
  nonbillable_events: number
}

export interface MonthlyUsageReport {
  month: string
  from: string
  to: string
  totals: MonthlyUsageReportRow
  /** Dimension département (champ de rattachement org). */
  byOrg: MonthlyUsageReportRow[]
  /** Dimension Agent (subject=agent:*). */
  byAgent: MonthlyUsageReportRow[]
  /** Dimension Skill (resource=skill:*). */
  bySkill: MonthlyUsageReportRow[]
  /** Dimension modèle (resource=model:*, additive pour faciliter la pénétration des coûts). */
  byModel: MonthlyUsageReportRow[]
}

/** Résumé coûts/consommation (passage de relais IAW 4-1) : agrégation fenêtrée + tripartition des tokens + ventilation par ressource. */
export interface UsageSummary {
  from: string
  to: string
  events: number
  /** Référence de coût interne (cents) ; charge_cents est un champ de compatibilité d'instantané à prix zéro (toujours 0). */
  cost_cents: number
  charge_cents: number
  input_tokens: number
  output_tokens: number
  /**
   * Nombre d'événements non tarifés (#14 additive) : cost_cents=0 et dû à « taux non configuré/taux entièrement nul » —
   * référentiel de couverture : priced_events = events − not_priced_events ; coût 0 ≠ sans consommation.
   */
  not_priced_events: number
  byResource: Array<{ resource: string; events: number; tokens: number; cost_cents: number; charge_cents: number; not_priced_events: number }>
}

interface ReportRow {
  dimension: string
  events: number
  tokens: number
  charge_cents: number
  cost_cents: number
  nonbillable_events: number
}

/** Ligne de pénétration des coûts FinOps (dimensions département/modèle + évolution vs mois précédent + éclaté Top modèles des lignes département). */
export interface FinOpsDimRow {
  dimension: string
  events: number
  tokens: number
  cost_cents: number
  prev_cost_cents: number
  /** Pourcentage d'évolution : (période−précédente)/précédente×100, 1 décimale ; null si la période précédente vaut 0 et l'actuelle non (pas de base comparable). */
  delta_pct: number | null
  /** Éclaté Top3 modèles des lignes département (absent des lignes modèle). */
  topModels?: Array<{ model: string; cost_cents: number; share: number }>
}

/** Résultat agrégé de la pénétration des coûts FinOps (vue CFO v1). */
export interface FinOpsCostPenetration {
  month: string
  from: string
  to: string
  prevFrom: string
  prevTo: string
  totals: { events: number; cost_cents: number; tokens: number; prev_cost_cents: number; delta_pct: number | null }
  byOrg: FinOpsDimRow[]
  byModel: FinOpsDimRow[]
  /** Matrice croisée des coûts org×modèle (Top8×Top8 + ligne/colonne « autres » ; cells[org][model], en cents). */
  matrix: { orgs: string[]; models: string[]; cells: number[][] }
  topSubjects: Array<{ subject: string; org: string; events: number; cost_cents: number }>
}

/** Résultat agrégé de la détection de ralenti FinOps v1 (référentiel approximatif : « appels de modèle sans action ultérieure »). */
export interface FinOpsIdleAnalysis {
  month?: string
  from: string
  to: string
  idleWindowMinutes: number
  /** Référentiel complet des appels de modèle dans la fenêtre (dénominateur). */
  totals: { events: number; cost_cents: number; tokens: number }
  /** Synthèse du ralenti suspecté (share_pct = part du coût ralenti dans le coût total des appels de modèle). */
  idle: { events: number; cost_cents: number; tokens: number; share_pct: number }
  byModel: Array<{ model: string; events: number; cost_cents: number; idle_events: number; idle_cost_cents: number }>
  byOrg: Array<{ org: string; events: number; cost_cents: number; idle_events: number; idle_cost_cents: number }>
  /** Échantillons ralentis récents (≤20, pour revue manuelle des faux positifs du référentiel approximatif). */
  samples: Array<{ occurred_at: string; subject: string; org: string; resource: string; cost_cents: number; tokens: number }>
}

/** Bornes de la période du rapport mensuel : [1er du mois courant 00:00, 1er du mois suivant 00:00). */
function periodBoundsIso(period: string): [string, string] {
  const [year, month] = period.split('-').map(Number)
  const next = month === 12 ? `${year + 1}-01` : `${year}-${String(month + 1).padStart(2, '0')}`
  return [`${period}-01T00:00:00`, `${next}-01T00:00:00`]
}

/** Bornes de la période du mois précédent (fenêtre dénominateur de l'évolution FinOps). */
function prevMonthBoundsIso(period: string): [string, string] {
  const [year, month] = period.split('-').map(Number)
  const prev = month === 1 ? `${year - 1}-12` : `${year}-${String(month - 1).padStart(2, '0')}`
  return periodBoundsIso(prev)
}

/** Bornes du mois courant et du mois précédent (référentiel d'évolution quand month n'est pas explicitement fourni). */
function currentPrevMonthBoundsIso(): [string, string] {
  return prevMonthBoundsIso(new Date().toISOString().slice(0, 7))
}

interface UsageRow {
  id: string
  idempotency_key: string
  schema_version: number
  occurred_at: string
  tenant_id: string
  org: string
  subject: string
  principal: string
  resource: string
  meters_json: string
  pricing_json: string
  trace_id: string
  /** D3 (groupe 7, additive) : colonne inexistante avant la migration des bases existantes, la lecture tolère undefined. */
  invocation_id?: string
  /** C4 (additive) : colonne inexistante avant la migration des bases existantes, la lecture tolère undefined. */
  context_id?: string
}

function usageRow(event: UsageEvent): Record<string, string | number> {
  return {
    id: event.event_id,
    idempotency_key: event.idempotency_key,
    schema_version: event.schema_version,
    occurred_at: event.occurred_at,
    tenant_id: event.tenant_id,
    org: event.org,
    subject: event.subject,
    principal: event.principal,
    resource: event.resource,
    meters_json: JSON.stringify(event.meters),
    pricing_json: JSON.stringify(event.pricing),
    trace_id: event.trace_id ?? '',
    invocation_id: event.invocationId ?? '',
    context_id: event.contextId ?? '',
  }
}

function rowToEvent(row: UsageRow): UsageEvent {
  return {
    schema: USAGE_SCHEMA,
    schema_version: row.schema_version,
    event_id: row.id,
    idempotency_key: row.idempotency_key,
    ...(row.trace_id !== '' ? { trace_id: row.trace_id } : {}),
    // D3 synchronisation du chemin de lecture : les lignes historiques (colonne absente avant migration, défaut '') n'émettent pas la clé, les nouvelles lignes la ramètent telle quelle (rejeu/consommateurs ne perdent pas l'association)
    ...(row.invocation_id !== undefined && row.invocation_id !== '' ? { invocationId: row.invocation_id } : {}),
    // C4 synchronisation du chemin de lecture : les lignes historiques (colonne absente avant migration, défaut '') n'émettent pas la clé, les nouvelles lignes la ramètent telle quelle
    ...(row.context_id !== undefined && row.context_id !== '' ? { contextId: row.context_id } : {}),
    occurred_at: row.occurred_at,
    tenant_id: row.tenant_id,
    org: row.org,
    subject: row.subject,
    principal: row.principal,
    resource: row.resource,
    meters: JSON.parse(row.meters_json) as UsageMeter[],
    pricing: JSON.parse(row.pricing_json) as UsagePricingSnapshot,
  }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    usage: UsageService
  }
}

export const name = 'usage'
export const inject = ['opsStorage', 'platformBus', 'txnStore', 'iam']

export function apply(ctx: Context) {
  ctx.plugin(UsageService)
  ctx.plugin(usageTools)
}
