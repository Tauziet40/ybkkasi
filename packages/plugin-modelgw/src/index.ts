/**
 * @dsh-ops/plugin-modelgw — passerelle d'accès unifiée aux modèles (version metering d'usage transparent, plan de développement method M0-3).
 *
 * La plateforme mandataire uniformément les fournisseurs de modèles externes (forme OpenAI-compatible chat/completions) :
 *   transfert HTTP réel → metering usage (input/output tokens mesurés, sans fabrication) →
 *   inscription en instantané à prix zéro (charge_cents=0, aucune sémantique de règlement en montant présentée à l'extérieur) + référence de coût d'achat interne (référentiel du rapport de perçage des coûts).
 *
 * Modèle économique (convergence M0) : licence annuelle privatif + pack de gouvernance — la passerelle ne fait plus « revente/pré-contrôle/prélèvement »,
 * le tarif n'est qu'une référence de coût interne (cost_cents_per_unit), la face list toujours à prix zéro.
 *
 * Ligne rouge de véridicité (principe de l'étape 0) : appeler un modèle sans vrai endpoint configuré jette directement une erreur,
 * jamais de faux completion de remplissage — en démonstration, configurer dans le catalogue un endpoint pointant vers un stub.
 *
 * Face gouvernance (livraison IAW 2026-09-11, PRD M2/§7.2) :
 *   - routage par gradation de canal (1-1) : le modèle enregistre dataClassLimit (public/interne/secret) ; une requête de session portant dataClass
 *     filtre les candidats selon « plafond de gradation » — les données secrètes ne sont jamais routées vers un canal public, l'appel hors gradation est directement refusé (verrouillé + motif) ;
 *   - chaîne de repli (1-2) : groupe de canaux (principal/secours1/secours2/manuel) dégrade par paliers au timeout de pas, chaque dégradation émet modelgw.degraded
 *     (bandeau SSE du panneau + souscription audit) ; le crochet d'interception de sécurité de contenu attend la passerelle de sécurité de contenu externe (absence honnête) ;
 *   - télémétrie de canal (1-3) : télémétrie d'appels glissante (7 j taux de disponibilité/latence/proxy TPS/taux d'adoption) ; le TTFT exige un canal de streaming,
 *     tour unique non streamé = colonne honnêtement absente (ttft=null, référentiel selon le retour de l'endpoint) ;
 *   - disjoncteur de budget (1-4) : budget org/plateforme (jour/mois), alerte au seuil warn (modelgw.budget.warning),
 *     l'action block coupe avant l'appel — alerte dédupliquée en processus par budget (au plus une par jour naturel par budget).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  newId,
  gateManagedWork, WORK_DATA_CLASS_ORDER, WORK_DENY_CODE_LABELS,
  type Collection, type RecordBase,
  type WorkCallerRef, type WorkDataClass, type WorkExecutionContext, type WorkforcePolicyRegistry,
} from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import * as modelgwTools from './tools.ts'

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

/** Gradation des données (PRD §4.1/§7.2) : public < interne < secret ; le canal admet les données selon son plafond. */
export type DataClass = 'public' | 'internal' | 'secret'

export const DATA_CLASS_RANK: Record<DataClass, number> = { public: 0, internal: 1, secret: 2 }
export const DATA_CLASS_LABELS: Record<DataClass, string> = { public: '公开', internal: '内部', secret: '秘密' }

/**
 * Table de mise en correspondance explicite D14 gradation métier unifiée → gradation de canal de la passerelle (interdiction d'assimiler des énumérations homonymes, interdiction d'un repli implicite sur absence) :
 *   public      → public    (public→public, correspondance un à un)
 *   internal    → internal  (interne→interne, correspondance un à un)
 *   secret      → secret    (secret métier ↔ secret de canal, même niveau sémantique)
 *   confidential→ secret    (le confidentiel est bridé au plus haut niveau de la passerelle : les données confidentielles n'admettent que les canaux
 *                          du plus haut niveau ; la passerelle n'a pas de gradation supérieure à exprimer, jamais de routage vers public/internal)
 *   topsecret   → hors correspondance : un appel géré est refusé avant la mise en correspondance (l'absolu-secret interdit le traitement par employé numérique, acceptation V14 côté modèle).
 */
const WORK_DATA_CLASS_TO_GATEWAY: Record<Exclude<WorkDataClass, 'topsecret'>, DataClass> = {
  public: 'public',
  internal: 'internal',
  secret: 'secret',
  confidential: 'secret',
}

export interface ModelRecord extends RecordBase {
  slug: string
  displayName: string
  provider: string
  /** URL de base compatible OpenAI (ex. https://api.deepseek.com/v1) ; sans configuration, pas d'appel possible. */
  endpoint: string
  /** API Key (seul le nom de référence est stocké, la vraie clé injectée par variable d'environnement ; les tests peuvent remplir directement une clé stub). */
  apiKey: string
  /** Référence de coût d'achat interne (centimes/1k tokens) : uniquement pour le rapport de perçage des coûts, aucune sémantique de règlement présentée à l'extérieur. */
  costCentsPerKTokens: number
  /**
   * Référence de coût interne en entrée (centimes/1k tokens, #14 additive) : les jetons d'entrée et de sortie sont tarifés séparément
   * (la ligne de prix combiné entre dans l'événement usage) ; par défaut considéré non tarifé (coût d'entrée à 0, la sémantique not_priced de l'événement est jugée par usage).
   */
  inputCostCentsPerKTokens?: number
  status: 'online' | 'offline'
  /** Plafond de gradation des données (1-1, additive) : plus haute gradation de données que ce canal peut porter ; défaut internal (compatibilité des enregistrements existants). */
  dataClassLimit?: DataClass
}

export interface ModelInvokeInput {
  model: string
  messages: Array<{ role: string; content: string }>
  /** Organisation d'imputation de l'usage (référentiel des rapports en dimension département). */
  orgId: string
  /** Utilisateur final/Agent (point d'arrivée du on-behalf-of). */
  subject: string
  tenantId?: string
  maxTokens?: number
  temperature?: number
  /** Gradation des données de la requête de session (1-1, défaut internal) : au-dessus du plafond du canal = refus (sélecteur verrouillé + motif). */
  dataClass?: DataClass
  /**
   * Appelant de confiance (additive D10, structure alignée sur WorkCallerRef) : assemblé par l'entrée d'appel depuis le jeton/la session vérifiés,
   * interdiction de prendre un JSON homologue du corps de requête pour une identité de confiance (§10.4). Absent = passage direct legacy du chemin non géré (statu quo).
   */
  caller?: WorkCallerRef
  /**
   * Index de référence de travail (additive, §10.4) : seulement les quatre clés d'index permitId/runId/stepKey/invocationId ;
   * les faits d'autorisation (permit/nomination/bail/budget) sont toujours revérifiés côté workforce, le présent champ ne fonde pas l'autorisation.
   */
  work?: ModelWorkRef
}

/** Index de référence de travail d'un appel de modèle (aligné sur le sous-ensemble modèle du WorkRefIndex). */
export interface ModelWorkRef {
  permitId?: string
  runId?: string
  stepKey?: string
  /** ID d'appel du registre des appels contrôlés workforce : association de trace pour transmission d'usage (V23/V27, sans changer le référentiel historique de clé idempotente). */
  invocationId?: string
}

export interface ModelInvokeResult {
  ok: true
  content: string
  model: string
  inputTokens: number
  outputTokens: number
  /** Référence de coût interne (centimes, convertie selon les output tokens mesurés ; référentiel rapport uniquement, aucune participation à un règlement). */
  costCents: number
  /** Trace des passages de la chaîne de repli (1-2, renvoyée seulement sur le chemin invokeWithFallback). */
  degradations?: Array<{ from: string; reason: string; at: string }>
  /** ID d'événement usage (additive D11) : clé d'association de réconciliation entre le registre d'appels de travail et le fait de consommation (association seule, pas de double enregistrement). */
  usageEventId?: string
}

export interface ModelInvokeError extends Error {
  /** Statut HTTP amont (pour juger la dégradation sur 5xx) ; absent sur timeout/erreur réseau. */
  status?: number
  kind?: 'timeout' | 'http' | 'network'
}

/** Groupe de canaux (1-2) : déclaration de la chaîne de repli principal/secours1/secours2/manuel ; chaîne terminale manual=true signifie escalation finale vers l'humain. */
export interface ChannelGroupRecord extends RecordBase {
  slug: string
  name: string
  primary: string
  backup1?: string
  backup2?: string
  /** Escalade terminale vers l'humain (true) : à l'échec de toute la chaîne, renvoie escalated=true au lieu d'une erreur nue, le panneau insère un bandeau. */
  manual?: boolean
  /** Timeout de pas (millisecondes, référentiel PRD §4.1 8 s) ; défaut 8000. */
  stepTimeoutMs?: number
  enabled: boolean
}

/** Télémétrie d'appel (1-3) : enregistrements bruts à fenêtre glissante (conservation par défaut 8 jours, fenêtre de requête 7 j). */
export interface TelemetryRecord extends RecordBase {
  model: string
  at: string
  ok: boolean
  latencyMs: number
  outputTokens: number
  /** Marque d'appel par le chemin de la chaîne de repli (canal de secours atteint). */
  degraded?: boolean
  error?: string
}

/** Budget (1-4) : budget jour/mois au niveau org (défaut = niveau plateforme), seuil warn + disjoncteur block. */
export interface BudgetRecord extends RecordBase {
  orgId?: string
  /**
   * Périmètre de modèles (R3, 2026-10-14) : défaut = sans limite de modèle ; '*' = atteint n'importe quel modèle (sémantique joker,
   * la dépense prend le total de la fenêtre sans filtre byResource) ; tout autre littéral = seulement ce modèle.
   */
  modelSlug?: string
  /**
   * Sujet du budget (préambule R10, 2026-10-14) : de la forme 'agent:<id>' / 'app:<id>', défaut = budget au niveau organisation.
   * Même référentiel que le metering d'invoke (usage.subject), la dépense du budget de sujet s'agrège par usage.summary(subject=).
   */
  subject?: string
  /** Gel couplé au dépassement (préambule R10) : au disjoncteur de dépassement, gèle l'Agent correspondant et génère une approbation de dégel (consommé par le centre d'exécution). */
  freezeAgent?: boolean
  dailyLimitCents?: number
  monthlyLimitCents?: number
  /** Ratio de seuil d'alerte (used/limit ≥ warnRatio émet modelgw.budget.warning) ; défaut 0.8. */
  warnRatio: number
  action: 'warn' | 'block'
  enabled: boolean
}

export interface BudgetWindowStatus {
  limitCents: number
  usedCents: number
  ratio: number
  warn: boolean
  breached: boolean
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

const INVOKE_TIMEOUT_MS = 30_000
export const DEFAULT_STEP_TIMEOUT_MS = 8_000
const TELEMETRY_RETENTION_MS = 8 * 86_400_000

export class ModelGatewayService extends Service {
  static readonly provide = 'modelGateway'

  /** Déduplication en processus des alertes de budget : budgetId → dernier jour naturel d'alerte (au plus un événement warning par jour et par budget). */
  private budgetWarnDay = new Map<string, string>()

  constructor(ctx: Context) {
    super(ctx, 'modelGateway')
  }

  models(): Collection<ModelRecord> {
    const collection = this.ctx.opsStorage.collection<ModelRecord>('modelgw:models')
    collection.uniqueOn('model_slug', (item) => item.slug)
    return collection
  }

  upsertModel(input: Omit<ModelRecord, 'id' | 'createdAt' | 'updatedAt'>): ModelRecord {
    const existing = this.models().findOne((item) => item.slug === input.slug)
    if (existing) return this.models().update(existing.id, { ...input })
    const created = this.models().insert({ id: newId('mdl'), ...input })
    // Enregistrement au tarif : model:<slug> mesuré sur output_tokens — la face list toujours à prix zéro (pas de règlement externe),
    // cost est une référence de coût d'achat interne (référentiel du rapport de perçage des coûts)
    this.ctx.usage.upsertPrice({
      pattern: `model:${input.slug}`,
      meter_key: 'output_tokens',
      list_cents_per_unit: 0,
      cost_cents_per_unit: input.costCentsPerKTokens,
      units_per_step: 1000,
      tax_rate: 0.06,
      currency: 'CNY',
      rate_version: `model:${input.slug}:cost-v1`,
    })
    // #14 : le taux des jetons d'entrée s'enregistre séparément (model:<slug>:input n'est qu'un porteur de taux, la ressource de l'événement est toujours
    // model:<slug> atteignant l'entrée principale ; à l'invoke, lu via priceOfResource puis inscrit en ligne de prix combiné)
    this.ctx.usage.upsertPrice({
      pattern: `model:${input.slug}:input`,
      meter_key: 'input_tokens',
      list_cents_per_unit: 0,
      cost_cents_per_unit: input.inputCostCentsPerKTokens ?? 0,
      units_per_step: 1000,
      tax_rate: 0.06,
      currency: 'CNY',
      rate_version: `model:${input.slug}:input-cost-v1`,
    })
    return created
  }

  /** Mise à jour des modèles existants (chemin opérationnel de retarification hors seed) : les deux entrées du tarif sont rafraîchies ensemble, taux et catalogue à source de fait unique. */
  updateModelCost(slug: string, cost: { outputCostCentsPerKTokens: number; inputCostCentsPerKTokens?: number }): void {
    this.ctx.usage.upsertPrice({
      pattern: `model:${slug}`,
      meter_key: 'output_tokens',
      list_cents_per_unit: 0,
      cost_cents_per_unit: cost.outputCostCentsPerKTokens,
      units_per_step: 1000,
      tax_rate: 0.06,
      currency: 'CNY',
      rate_version: `model:${slug}:cost-v1`,
    })
    this.ctx.usage.upsertPrice({
      pattern: `model:${slug}:input`,
      meter_key: 'input_tokens',
      list_cents_per_unit: 0,
      cost_cents_per_unit: cost.inputCostCentsPerKTokens ?? 0,
      units_per_step: 1000,
      tax_rate: 0.06,
      currency: 'CNY',
      rate_version: `model:${slug}:input-cost-v1`,
    })
  }

  // -- Autorisation au niveau travail et mise en correspondance des gradations (D10/D14, additive) ---------------------------------

  /**
   * Lecture du port étroit au runtime : platform-core enregistre WorkforcePolicyRegistry à l'assemblage (provide='workforcePolicy').
   * L'appoint de type de Context est détenu côté workforce ; ici lecture défensive — service non assemblé = undefined,
   * gateManagedWork suit le chemin legacy tant que le port n'est pas prêt, le chemin non géré reste au statu quo (V29 : le nouveau chemin de travail ne laisse pas passer sans politique en silence).
   */
  private workforcePolicy(): WorkforcePolicyRegistry | undefined {
    try {
      return (this.ctx as unknown as { workforcePolicy?: WorkforcePolicyRegistry }).workforcePolicy ?? undefined
    } catch {
      return undefined
    }
  }

  /**
   * Barrière d'autorisation au niveau travail (appels de modèle d'employé numérique géré) : exécutée à l'entrée avant la vérification au niveau ressource ;
   * caller absent ou port non prêt → legacy (renvoie null, la chaîne d'origine sans y perdre une marche) ; refus → erreur en chinois + code de domaine (fail-closed).
   * Le jugement ne fait que rechercher le caller de confiance, indépendamment de la présence d'une référence work (anti-contournement D.5).
   * registryId : canal unique = slug du modèle ; chaîne de repli = slug du groupe de canaux (le canal réellement exécuté repasse un à un la vérification gradation/budget dans la chaîne).
   */
  private async gateManagedModelCall(
    caller: WorkCallerRef | undefined,
    registryId: string,
    ref?: ModelWorkRef,
  ): Promise<WorkExecutionContext | null> {
    const gate = await gateManagedWork(this.workforcePolicy(), caller, {
      facts: { kind: 'model', registryId, action: 'invoke', risk: 'read' },
      ...(ref && (ref.permitId || ref.runId || ref.stepKey) ? { ref: { permitId: ref.permitId, runId: ref.runId, stepKey: ref.stepKey } } : {}),
    })
    if (gate.mode === 'legacy') return null
    if (gate.mode === 'denied') {
      const label = t(WORK_DENY_CODE_LABELS[gate.code])
      const detail = gate.message ? t('（{message}）', { message: gate.message }) : ''
      const error = new Error(t('数字员工调用被拒绝：{message}', { message: label + detail })) as Error & { code?: string }
      error.code = gate.code
      throw error
    }
    return gate.work
  }

  /**
   * Gradation effective d'un appel géré (D14) : max(dataClass de la requête (défaut internal), plafond de gradation gelé par la nomination) —
   * en géré, il faut marcher au référentiel max, interdiction de laisser l'absence retomber implicitement sur internal, ce qui dégraderait.
   * topsecret est refusé avant la mise en correspondance explicite (l'absolu-secret interdit le traitement par employé numérique) ; le reste passe par la table de correspondance explicite vers la gradation de la passerelle.
   */
  private effectiveManagedDataClass(requested: DataClass | undefined, workCeiling: WorkDataClass): DataClass {
    const base: WorkDataClass = requested ?? 'internal'
    const effective = WORK_DATA_CLASS_ORDER[base] >= WORK_DATA_CLASS_ORDER[workCeiling] ? base : workCeiling
    if (effective === 'topsecret') {
      throw new Error(t('绝密数据禁止数字员工处理'))
    }
    return WORK_DATA_CLASS_TO_GATEWAY[effective]
  }

  // -- Routage par gradation de canal (1-1) ---------------------------------------------------

  /**
   * Filtre les canaux disponibles par gradation des données : un modèle dont la gradation dépasse le plafond du canal n'apparaît pas (en scénario secret, le sélecteur verrouille les canaux publics).
   * Renvoie une structure avec motif, pour que le front rende directement la raison du verrouillage.
   */
  resolveChannels(dataClass: DataClass, opts: { onlineOnly?: boolean } = {}): {
    dataClass: DataClass
    available: ModelRecord[]
    excluded: Array<{ slug: string; displayName: string; limit: DataClass; reason: string }>
  } {
    const rank = DATA_CLASS_RANK[dataClass] ?? DATA_CLASS_RANK.internal
    const available: ModelRecord[] = []
    const excluded: Array<{ slug: string; displayName: string; limit: DataClass; reason: string }> = []
    for (const model of this.models().all()) {
      const limit = model.dataClassLimit ?? 'internal'
      if (DATA_CLASS_RANK[limit] >= rank) {
        if (!opts.onlineOnly || (model.status === 'online' && model.endpoint.trim() !== '')) available.push(model)
        continue
      }
      excluded.push({
        slug: model.slug, displayName: model.displayName, limit,
        reason: t('渠道分级上限为「{limit}」，低于本次数据「{dataClass}」——涉密/内部数据不得路由到低分级渠道（PRD §7.2）', { limit: t(DATA_CLASS_LABELS[limit]), dataClass: t(DATA_CLASS_LABELS[dataClass]) }),
      })
    }
    return { dataClass, available, excluded }
  }

  /** Validation de dépassement de gradation : plafond du canal cible inférieur à la gradation des données de la requête = refus direct (libellé du motif inclus, pour le verrouillage du sélecteur). */
  private assertDataClassAllowed(model: ModelRecord, dataClass: DataClass | undefined): void {
    const requestClass = dataClass ?? 'internal'
    const limit = model.dataClassLimit ?? 'internal'
    if (DATA_CLASS_RANK[limit] < DATA_CLASS_RANK[requestClass]) {
      throw new Error(
        t('数据分级越界：本次会话数据为「{dataClass}」，渠道 {slug} 分级上限仅「{limit}」——已按 PRD §7.2 锁死该路由', { dataClass: t(DATA_CLASS_LABELS[requestClass]), slug: model.slug, limit: t(DATA_CLASS_LABELS[limit]) }),
      )
    }
  }

  // -- Groupe de canaux et chaîne de repli (1-2) ---------------------------------------------------

  channelGroups(): Collection<ChannelGroupRecord> {
    const collection = this.ctx.opsStorage.collection<ChannelGroupRecord>('modelgw:channelGroups')
    collection.uniqueOn('group_slug', (item) => item.slug)
    return collection
  }

  upsertChannelGroup(input: Omit<ChannelGroupRecord, 'id' | 'createdAt' | 'updatedAt'>): ChannelGroupRecord {
    for (const slug of [input.primary, input.backup1, input.backup2]) {
      if (slug !== undefined && !this.models().findOne((item) => item.slug === slug)) {
        throw new Error(t('渠道组引用了未登记的模型：{slug}（请先在模型目录登记）', { slug }))
      }
    }
    const existing = this.channelGroups().findOne((item) => item.slug === input.slug)
    if (existing) return this.channelGroups().update(existing.id, { ...input })
    return this.channelGroups().insert({ id: newId('mgrp'), ...input })
  }

  /**
   * Appel par chaîne de repli (1-2) : principal → secours1 → secours2, dégradation par paliers, chaque pas au timeout stepTimeoutMs (défaut 8 s) ;
   * HTTP 5xx / timeout / erreur réseau déclenche la dégradation, chaque dégradation émet modelgw.degraded (bandeau SSE du panneau + audit).
   * Chaîne terminale manual=true : à l'échec de toute la chaîne, renvoie escalated=true (escalade humaine) au lieu d'une erreur nue.
   * Disjoncteur de budget (1-4 / BUG-2510-B1) : re-contrôle avant chaque appel réel (même référentiel que le chemin canal unique), l'état block
   * jette directement « disjoncteur de budget » et termine toute la chaîne (pas de dégradation, pas d'appel amont, pas d'inscription).
   * Interception de sécurité de contenu : passerelle de sécurité de contenu externe non connectée (absence honnête), à raccrocher sur le chemin de retour d'invokeOnce une fois connectée.
   */
  async invokeWithFallback(input: Omit<ModelInvokeInput, 'model'> & { group: string }): Promise<ModelInvokeResult | { ok: false; escalated: true; reason: string; degradations: Array<{ from: string; reason: string; at: string }> }> {
    // Barrière d'autorisation au niveau travail (D10) : la barrière d'abord à l'entrée, le slug du groupe de canaux sert de registryId ; un refus termine toute la chaîne.
    // En géré, la gradation effective est la mise en correspondance explicite de max(requête, plafond de nomination) (D14) ; en legacy non géré, effectiveInput===input, statu quo.
    const work = await this.gateManagedModelCall(input.caller, input.group, input.work)
    const effectiveInput = work
      ? { ...input, dataClass: this.effectiveManagedDataClass(input.dataClass, work.dataClass) }
      : input
    const group = this.channelGroups().findOne((item) => item.slug === effectiveInput.group)
    if (!group) throw new Error(t('渠道组不存在：{slug}（请先登记主/备渠道组）', { slug: effectiveInput.group }))
    if (!group.enabled) throw new Error(t('渠道组已停用：{slug}', { slug: group.slug }))
    const chain = [group.primary, group.backup1, group.backup2].filter((slug): slug is string => Boolean(slug))
    const stepTimeoutMs = group.stepTimeoutMs ?? DEFAULT_STEP_TIMEOUT_MS
    const degradations: Array<{ from: string; reason: string; at: string }> = []
    let lastError = ''
    for (let index = 0; index < chain.length; index++) {
      const slug = chain[index]!
      const model = this.models().findOne((item) => item.slug === slug)
      const reject = (reason: string): void => {
        lastError = reason
        degradations.push({ from: slug, reason, at: new Date().toISOString() })
        this.recordTelemetry({ model: slug, ok: false, latencyMs: 0, outputTokens: 0, degraded: true, error: reason })
        this.ctx.platformBus.emit('modelgw.degraded', {
          group: group.slug, from: slug, to: chain[index + 1] ?? (group.manual ? t('manual:人工') : t('（链尾）')),
          reason, step: index + 1, subject: effectiveInput.subject, orgId: effectiveInput.orgId,
        })
      }
      if (!model) {
        reject(t('渠道组引用的模型未登记：{slug}', { slug }))
        continue
      }
      if (model.status !== 'online' || model.endpoint.trim() === '') {
        reject(t('备用渠道不可调用（{reason}）：{slug}', { reason: model.status === 'online' ? t('未配置 endpoint') : t('已下线'), slug }))
        continue
      }
      try {
        // Routage par gradation (1-1) vérifié pas à pas : un canal de secours de gradation inférieure à la gradation de la requête se verrouille pareil
        this.assertDataClassAllowed(model, effectiveInput.dataClass)
      } catch (error) {
        reject(error instanceof Error ? error.message : String(error))
        continue
      }
      // Disjoncteur de budget (1-4 / BUG-2510-B1) : avant chaque appel réel, re-contrôle au même référentiel que le chemin canal unique (invoke) —
      // l'inscription du metering canal par canal dans la chaîne fait avancer l'usage, le re-contrôle avant dégradation bouche l'état block qui continuerait
      // d'appeler l'amont via les canaux de secours ; évaluation selon le slug du canal courant (la sémantique d'atteinte du modèle appelé est strictement
      // identique au chemin canal unique, joker R3/sujet R10 non affectés), l'erreur de disjoncteur n'entre pas en dégradation (reject) et termine toute la chaîne — libellé d'erreur et enveloppe identiques au chemin canal unique
      try {
        this.enforceBudget({ ...effectiveInput, model: slug })
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        this.recordTelemetry({ model: slug, ok: false, latencyMs: 0, outputTokens: 0, degraded: index > 0, error: t('预算熔断：{message}', { message }) })
        throw error
      }
      try {
        const result = await this.invokeTracked(model, effectiveInput, stepTimeoutMs, index > 0)
        if (degradations.length > 0) return { ...result, degradations }
        return result
      } catch (error) {
        reject(error instanceof Error ? error.message : String(error))
      }
    }
    if (group.manual) return { ok: false, escalated: true, reason: t('渠道组 {slug} 全链失败，已按配置转人工：{message}', { slug: group.slug, message: lastError }), degradations }
    throw new Error(t('渠道组 {slug} 全链失败（无转人工配置）：{message}', { slug: group.slug, message: lastError }))
  }

  // -- Télémétrie (1-3) ------------------------------------------------------------

  telemetry(): Collection<TelemetryRecord> {
    return this.ctx.opsStorage.collection<TelemetryRecord>('modelgw:telemetry')
  }

  recordTelemetry(input: { model: string; ok: boolean; latencyMs: number; outputTokens: number; degraded?: boolean; error?: string }): void {
    const collection = this.telemetry()
    collection.insert({ id: newId('mtel'), at: new Date().toISOString(), ...input })
    // Nettoyage de la fenêtre glissante : ne conserve que 8 jours (fenêtre de requête 7 j + 1 j de marge)
    const cutoff = new Date(Date.now() - TELEMETRY_RETENTION_MS).toISOString()
    for (const stale of collection.all().filter((row) => row.at < cutoff)) collection.remove(stale.id)
  }

  /**
   * Agrégat de télémétrie de canal (référentiel fenêtre 7 j) : taux de disponibilité / latence p50 / proxy TPS (output tokens / latence totale) /
   * taux d'adoption (agrégat des retours usage, sans retour = null).
   * TTFT honnêtement absent : un tour unique non streamé ne peut pas mesurer la latence du premier jeton — ttftMs=null + note de référentiel avec la réponse,
   * vraie valeur à compléter quand le canal de streaming de la passerelle sera en ligne.
   */
  telemetryFor(slug: string, windowDays = 7): {
    model: string
    windowDays: number
    invocations: number
    failures: number
    availability: number | null
    p50LatencyMs: number | null
    avgTps: number | null
    adoptionRate: number | null
    degradedInvocations: number
    ttftMs: null
    note: string
  } {
    const from = new Date(Date.now() - windowDays * 86_400_000).toISOString()
    const rows = this.telemetry().all().filter((row) => row.model === slug && row.at >= from)
    const okRows = rows.filter((row) => row.ok)
    const latencies = rows.filter((row) => row.latencyMs > 0).map((row) => row.latencyMs).sort((a, b) => a - b)
    const tpsValues = rows.filter((row) => row.ok && row.latencyMs > 100 && row.outputTokens > 0)
      .map((row) => (row.outputTokens / row.latencyMs) * 1000)
    const feedback = this.ctx.usage.feedbackStats({ from })
    const adoption = feedback.byResource.find((row) => row.resource === `model:${slug}`)
    const percentile = (values: number[], ratio: number): number | null =>
      values.length === 0 ? null : values[Math.min(values.length - 1, Math.floor(values.length * ratio))]!
    return {
      model: slug,
      windowDays,
      invocations: rows.length,
      failures: rows.length - okRows.length,
      availability: rows.length === 0 ? null : Math.round((okRows.length / rows.length) * 1000) / 1000,
      p50LatencyMs: percentile(latencies, 0.5),
      avgTps: tpsValues.length === 0 ? null : Math.round((tpsValues.reduce((sum, value) => sum + value, 0) / tpsValues.length) * 100) / 100,
      adoptionRate: adoption?.adoptionRate ?? null,
      degradedInvocations: rows.filter((row) => row.degraded === true).length,
      ttftMs: null,
      note: t('TTFT 需流式通道（当前网关为非流式单轮）诚实缺列；TPS 为 output_tokens/总时延 的代理口径；采纳率取 model:<slug> 资源的 👍/👎 聚合'),
    }
  }

  // -- Budget et disjoncteur (1-4) --------------------------------------------------------

  budgets(): Collection<BudgetRecord> {
    return this.ctx.opsStorage.collection<BudgetRecord>('modelgw:budgets')
  }

  upsertBudget(input: Omit<BudgetRecord, 'id' | 'createdAt' | 'updatedAt'>): BudgetRecord {
    if (input.dailyLimitCents === undefined && input.monthlyLimitCents === undefined) {
      throw new Error(t('预算至少配置 dailyLimitCents / monthlyLimitCents 之一'))
    }
    // Validation du format de sujet (préambule R10) : subject doit être un sujet de metering préfixé 'agent:'/'app:',
    // contre le texte libre qui créerait une invalidation silencieuse « un budget configuré mais jamais apparié par usage »
    if (input.subject !== undefined && !/^(agent|app):.+/.test(input.subject)) {
      throw new Error(t('预算主体格式非法：{subject}（须形如 agent:<id> 或 app:<id>，与 invoke 计量主体同口径）', { subject: input.subject }))
    }
    // Clé composée (org × modèle × sujet) : les trois ensemble uniques — une même organisation peut porter simultanément budgets niveau org, par modèle, par sujet
    const existing = this.budgets().findOne((item) =>
      (item.orgId ?? '') === (input.orgId ?? '')
      && (item.modelSlug ?? '') === (input.modelSlug ?? '')
      && (item.subject ?? '') === (input.subject ?? ''))
    if (existing) return this.budgets().update(existing.id, { ...input })
    return this.budgets().insert({ id: newId('mbgt'), ...input })
  }

  /** Référentiel de dépense d'un budget atteint : agrégat de coût d'usage filtré org×modèle×sujet (référentiel de référence de coût interne cost_cents). */
  private budgetUsedCents(budget: BudgetRecord, from: string, to: string): number {
    const summary = this.ctx.usage.summary({
      from, to,
      ...(budget.orgId ? { org: budget.orgId } : {}),
      ...(budget.subject ? { subject: budget.subject } : {}),
    })
    // Joker '*' (R3) : atteint n'importe quel modèle — prend le total de la fenêtre, sans filtre byResource
    if (budget.modelSlug === '*') return summary.cost_cents
    if (budget.modelSlug) {
      const row = summary.byResource.find((item) => item.resource === `model:${budget.modelSlug}`)
      return row?.cost_cents ?? 0
    }
    return summary.cost_cents
  }

  /** État des deux fenêtres d'un budget (aujourd'hui / ce mois, jour UTC cohérent avec le référentiel des rapports usage). */
  budgetStatus(budget: BudgetRecord): { daily: BudgetWindowStatus | null; monthly: BudgetWindowStatus | null } {
    const now = new Date()
    const status = (limitCents: number | undefined, fromIso: string): BudgetWindowStatus | null => {
      if (limitCents === undefined) return null
      const usedCents = this.budgetUsedCents(budget, fromIso, now.toISOString())
      const ratio = limitCents <= 0 ? 1 : Math.round((usedCents / limitCents) * 1000) / 1000
      return { limitCents, usedCents, ratio, warn: ratio >= budget.warnRatio, breached: usedCents >= limitCents }
    }
    return {
      daily: status(budget.dailyLimitCents, `${now.toISOString().slice(0, 10)}T00:00:00.000Z`),
      monthly: status(budget.monthlyLimitCents, `${now.toISOString().slice(0, 7)}-01T00:00:00.000Z`),
    }
  }

  /**
   * Progression du budget en dimension org (source de données du chip coût du panneau / du champ budget de l'usage summary) ; sans budget = null.
   * Ne prend que les budgets niveau org « sans limite de modèle et sans périmètre de sujet » : sans limite de modèle = modelSlug non déclaré
   * ou modelSlug='*' (le joker R3 = atteint tout modèle, donc référentiel tous modèles, compté comme une progression org —
   * auparavant '*' était exclu d'un bloc avec !modelSlug, une organisation ne configurant que des budgets joker avait un budget constamment null dans le résumé, divergent de la face disjoncteur) ;
   * un budget littéral de niveau modèle est un référentiel mono-modèle, un budget de sujet est la dimension sujet (R10) — ni l'un ni l'autre n'entrent dans la progression niveau org.
   */
  budgetStatusFor(orgId: string): { orgId: string; daily: BudgetWindowStatus | null; monthly: BudgetWindowStatus | null } | null {
    const budget = this.budgets().all()
      .filter((item) => item.enabled && !item.subject && (!item.modelSlug || item.modelSlug === '*') && (item.orgId ?? '') === (orgId || ''))
      .sort((a, b) => (a.orgId ? 0 : 1) - (b.orgId ? 0 : 1))[0] // propre à l'org prioritaire sur niveau plateforme
    if (!budget) return null
    return { orgId: budget.orgId ?? t('（平台级）'), ...this.budgetStatus(budget) }
  }

  /**
   * Liste des budgets en dimension sujet (Agent/application) (préambule R10, méthode de contrat du contrôle préalable de budget du centre d'exécution) :
   * filtre les budgets enabled dont le sujet est strictement égal, sans orgId (repli niveau plateforme) ou à org concordant,
   * renvoie pour chacun l'état des deux fenêtres (daily UTC aujourd'hui / monthly ce mois, même référentiel de fenêtre que budgetStatus).
   */
  budgetStatusForSubject(subject: string, orgId?: string): Array<{ budget: BudgetRecord; daily: BudgetWindowStatus | null; monthly: BudgetWindowStatus | null }> {
    return this.budgets().all()
      .filter((item) => item.enabled
        && (item.subject ?? '') === subject
        && (!item.orgId || (orgId ?? '') === '' ? !item.orgId || (orgId ?? '') === '' : item.orgId === orgId))
      .map((budget) => ({ budget, ...this.budgetStatus(budget) }))
  }

  /** Suppression d'un budget (face suppression R4, 2026-10-14) : la gouvernance des budgets n'ajoutait auparavant que sans supprimer, un budget mal configuré ne pouvait qu'être désactivé et rester. */
  removeBudget(id: string): void {
    const budget = this.budgets().get(id)
    if (!budget) throw new Error(t('预算不存在：{id}', { id }))
    this.budgets().remove(id)
    // L'état de déduplication d'alerte en processus est aussi nettoyé, pour éviter qu'une réutilisation du même id voie l'alerte du jour avalée par le vieil état
    this.budgetWarnDay.delete(id)
  }

  /** Disjoncteur avant appel + alerte de seuil (au plus un événement warning par jour naturel et par budget). */
  private enforceBudget(input: ModelInvokeInput): void {
    const candidates = this.budgets().all().filter((item) => {
      if (!item.enabled) return false
      // Joker R3 : modelSlug='*' atteint tout modèle ; tout autre littéral en correspondance exacte
      if (item.modelSlug && item.modelSlug !== '*' && item.modelSlug !== input.model) return false
      // Sujet R10 : un budget de sujet ne prend effet que pour le même sujet (agent:<id>/app:<id>, même référentiel que le sujet de metering usage)
      if (item.subject && item.subject !== (input.subject ?? '')) return false
      if (item.orgId && item.orgId !== input.orgId) return false
      return true
    })
    for (const budget of candidates) {
      const status = this.budgetStatus(budget)
      const day = new Date().toISOString().slice(0, 10)
      for (const window of [status.daily, status.monthly]) {
        if (!window) continue
        const scope = `${budget.orgId ?? 'platform'}${budget.modelSlug ? `/${budget.modelSlug}` : ''}`
        if (window.breached && budget.action === 'block') {
          throw new Error(t('预算熔断（{scope}）：{window}成本 {used} 分已达上限 {limit} 分（action=block）。请调整预算或等待窗口重置', {
            scope,
            window: window === status.daily ? t('今日') : t('本月'),
            used: window.usedCents,
            limit: window.limitCents,
          }))
        }
        if (window.warn && this.budgetWarnDay.get(budget.id) !== day) {
          this.budgetWarnDay.set(budget.id, day)
          this.ctx.platformBus.emit('modelgw.budget.warning', {
            budgetId: budget.id, orgId: budget.orgId ?? null, modelSlug: budget.modelSlug ?? null,
            window: window === status.daily ? 'daily' : 'monthly',
            limitCents: window.limitCents, usedCents: window.usedCents, ratio: window.ratio,
            action: budget.action, at: new Date().toISOString(),
          })
        }
      }
    }
  }

  // -- Appel ---------------------------------------------------------------------

  async invoke(input: ModelInvokeInput): Promise<ModelInvokeResult> {
    // Barrière d'autorisation au niveau travail (D10) : la barrière d'abord à l'entrée, puis la vérification au niveau ressource (gradation de canal/budget/amont), intersection des deux autorisations (§9.5)
    const work = await this.gateManagedModelCall(input.caller, input.model, input.work)
    // D14 : en géré, gradation effective = max(dataClass de la requête, défaut internal, plafond gelé par la nomination), passée par la table de correspondance explicite vers la gradation de la passerelle
    // (topsecret déjà refusé avant correspondance) ; en legacy non géré, effectiveInput===input, statu quo
    const effectiveInput = work
      ? { ...input, dataClass: this.effectiveManagedDataClass(input.dataClass, work.dataClass) }
      : input
    const model = this.models().findOne((item) => item.slug === effectiveInput.model)
    if (!model) throw new Error(t('模型不存在：{slug}（请先在模型目录登记）', { slug: effectiveInput.model }))
    if (model.status !== 'online') throw new Error(t('模型已下线：{slug}', { slug: model.slug }))
    if (!model.endpoint) throw new Error(t('模型 {slug} 未配置 endpoint，拒绝调用（不生成假 completion）', { slug: model.slug }))
    // Routage par gradation (1-1) : hors gradation = refus direct (sélecteur verrouillé + motif)
    this.assertDataClassAllowed(model, effectiveInput.dataClass)
    // Disjoncteur de budget (1-4) : l'action block prend effet avant l'appel (un appel géré à budget insuffisant échoue naturellement → côté workforce, inscription BUDGET_EXCEEDED)
    try {
      this.enforceBudget(effectiveInput)
    } catch (error) {
      this.recordTelemetry({ model: model.slug, ok: false, latencyMs: 0, outputTokens: 0, error: t('预算熔断：{message}', { message: error instanceof Error ? error.message : String(error) }) })
      throw error
    }
    return this.invokeTracked(model, effectiveInput, INVOKE_TIMEOUT_MS, false)
  }

  /** Appel canal unique avec télémétrie : latence/succès/marque de repli inscrits en fenêtre glissante (source des 7 j taux de disponibilité et du proxy TPS). */
  private async invokeTracked(model: ModelRecord, input: ModelInvokeInput, timeoutMs: number, degraded: boolean): Promise<ModelInvokeResult> {
    // #17 (2026-10-29) : le rattachement organisationnel est vérifié avant l'appel amont (fail-fast) — auparavant, une chaîne vide orgId jetait « org obligatoire
    // dans l'événement usage » à l'inscription du metering, après que le modèle avait répondu et les jetons consommés (on paie d'abord, erreur ensuite, et ce coût non inscrit)
    if (!input.orgId?.trim()) {
      throw new Error(t('模型调用缺少组织归属（orgId 必填）：调用方须解析主体/部门/平台根组织后重试（#17 fail-fast）'))
    }
    const startedAt = Date.now()
    try {
      const result = await this.invokeOnce(model, input, timeoutMs)
      this.recordTelemetry({ model: model.slug, ok: true, latencyMs: Date.now() - startedAt, outputTokens: result.outputTokens, degraded })
      return result
    } catch (error) {
      this.recordTelemetry({
        model: model.slug, ok: false, latencyMs: Date.now() - startedAt, outputTokens: 0, degraded,
        error: error instanceof Error ? error.message : String(error),
      })
      throw error
    }
  }

  private async invokeOnce(model: ModelRecord, input: ModelInvokeInput, timeoutMs: number): Promise<ModelInvokeResult> {
    const apiKey = model.apiKey.startsWith('env:') ? (process.env[model.apiKey.slice(4)] ?? '') : model.apiKey
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    let payload: {
      choices?: Array<{ message?: { content?: string } }>
      usage?: { prompt_tokens?: number; completion_tokens?: number }
    }
    try {
      const response = await fetch(`${model.endpoint.replace(/\/$/, '')}/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) },
        body: JSON.stringify({
          // QA B-02 : le canal réellement appelé fait foi — l'entrée de la chaîne de repli est Omit<…,'model'>, l'écriture d'origine faisait manquer le champ model au corps transféré,
          // sous un vrai amont compatible OpenAI, les canaux de secours passaient toute la chaîne en 400
          model: model.slug,
          messages: input.messages,
          ...(input.maxTokens !== undefined ? { max_tokens: input.maxTokens } : {}),
          ...(input.temperature !== undefined ? { temperature: input.temperature } : {}),
        }),
        signal: controller.signal,
      })
      if (!response.ok) {
        const text = (await response.text()).slice(0, 300)
        const error = new Error(t('模型上游 HTTP {status}：{text}', { status: response.status, text })) as ModelInvokeError
        error.status = response.status
        error.kind = 'http'
        throw error
      }
      payload = (await response.json()) as typeof payload
    } catch (error) {
      if (error instanceof Error && (error as ModelInvokeError).kind === 'http') throw error
      const message = error instanceof Error ? (error.name === 'AbortError' ? t('模型调用超时（{ms}ms）', { ms: timeoutMs }) : error.message) : String(error)
      const wrapped = new Error(message) as ModelInvokeError
      wrapped.kind = error instanceof Error && error.name === 'AbortError' ? 'timeout' : 'network'
      throw wrapped
    } finally {
      clearTimeout(timer)
    }
    const content = payload.choices?.[0]?.message?.content ?? ''
    const inputTokens = payload.usage?.prompt_tokens ?? 0
    const outputTokens = payload.usage?.completion_tokens ?? 0

    // #14 (2026-10-29) prix combiné : input/output convertis séparément selon les taux du tarif (lus à l'instant de l'appel, le tarif reste
    // l'unique face de retarification ; le détail des lignes entre tel quel dans l'instantané usage rate.line_items, récalculable en réconciliation). Une ligne sans taux enregistré n'entre pas dans la liste
    //(côté usage, repli sur le référentiel du tarif à entrée unique ; entrée principale manquante : record refuse toujours bruyamment).
    const outputPrice = this.ctx.usage.priceOfResource(`model:${model.slug}`)
    const inputPrice = this.ctx.usage.priceOfResource(`model:${model.slug}:input`)
    const costLineItems = [
      ...(outputPrice && outputPrice.cost_cents_per_unit > 0 && outputTokens > 0
        ? [{ meter_key: 'output_tokens', value: outputTokens, cost_cents_per_unit: outputPrice.cost_cents_per_unit, units_per_step: outputPrice.units_per_step }]
        : []),
      ...(inputPrice && inputPrice.cost_cents_per_unit > 0 && inputTokens > 0
        ? [{ meter_key: 'input_tokens', value: inputTokens, cost_cents_per_unit: inputPrice.cost_cents_per_unit, units_per_step: inputPrice.units_per_step }]
        : []),
    ]

    // Metering : input/output tokens mesurés (mesurer d'abord, renvoyer ensuite) ; inscription en instantané à prix zéro (charge=0),
    // cost converti selon la référence de coût interne, pour le rapport de perçage des coûts
    const event = this.ctx.usage.record({
      org: input.orgId,
      subject: input.subject,
      principal: `org:${input.orgId}`,
      resource: `model:${model.slug}`,
      ...(input.tenantId !== undefined ? { tenant_id: input.tenantId } : {}),
      meters: [
        { key: 'input_tokens', value: inputTokens, unit: 'token' },
        { key: 'output_tokens', value: outputTokens, unit: 'token' },
      ],
      ...(costLineItems.length > 0 ? { costLineItems } : {}),
      idempotency_key: `modelgw:${newId('mi')}`,
      // Liaison de travail (additive D11/V23/V27) : sur un appel géré, l'ID d'appel workforce est ajouté comme trace unifiée —
      // la clé idempotente modelgw:<mi> et la clé historique model:<slug> restent inchangées ; les champs d'association non reconnus côté usage sont repris en incrément par le groupe 7
      ...(input.work?.invocationId ? { trace_id: input.work.invocationId } : {}),
    })

    return {
      ok: true,
      content,
      model: model.slug,
      inputTokens,
      outputTokens,
      costCents: event.pricing.cost_cents,
      // Reçu d'événement usage (additive) : pour l'association de réconciliation du registre d'appels de travail (association seule, pas de double enregistrement de consommation)
      usageEventId: event.event_id,
    }
  }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    modelGateway: ModelGatewayService
  }
}

export const name = 'modelgw'
export const inject = ['opsStorage', 'usage', 'platformBus', 'workforcePolicy']

export function apply(ctx: Context) {
  ctx.plugin(ModelGatewayService)
  ctx.plugin(modelgwTools)
}
