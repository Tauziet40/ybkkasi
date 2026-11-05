/**
 * Bus d'événements de la plateforme : la seule couche de liaison entre plugins.
 * Principe : toute modification d'état émet un événement ; les interactions inter-plugins passent uniquement par des événements ou des points d'extension, les connexions directes aux données d'autrui sont interdites.
 *
 * Validation de la source d'événement (conception écosystème v1.2 étape 3, résolution S3/F3) :
 *   - les événements de l'espace de noms plateforme (iam.* / authn.* / mcp.* …) ne peuvent être émis que depuis l'intérieur de la plateforme —
 *     toute émission portant une source plugin: est rejetée, pour empêcher les plugins tiers de falsifier des événements plateforme ;
 *   - les événements des plugins tiers doivent rester dans le préfixe plugin:<id>: et leur source doit correspondre à l'identité du plugin ;
 *   - la validation se fait dans ce bus (implémentation pub/sub autonome, sans passer par le système d'événements cordis),
 *     complétée par le proxy léger ctx (plugin-ctx.ts) et le lint/scan statique — trois lignes de défense.
 */
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'

export interface PlatformEvent {
  id: number
  name: string
  payload: unknown
  at: string
  /** Source d'événement : défaut = interne plateforme ; plugin:<id> = plugin tiers (doit correspondre au préfixe du nom d'événement). */
  source?: string
}

export type BusListener = (payload: unknown, event: PlatformEvent) => void

/** Constantes des noms d'événements plateforme (correspondent aux manifest/events.yaml de chaque plugin). */
export const PlatformEvents = {
  UserFrozen: 'iam.user.frozen',
  UserActivated: 'iam.user.activated',
  UserPasswordReset: 'iam.user.password-reset',
  OrgChanged: 'iam.org.changed',
  PermissionChanged: 'iam.permission.changed',
  TokenIssued: 'authn.token.issued',
  TokenRevoked: 'authn.token.revoked',
  McpDeployed: 'mcp.deployed',
  McpOfflined: 'mcp.offlined',
  McpUnhealthy: 'mcp.unhealthy',
  McpInvoked: 'mcp.invoked',
  // W1-T2 (gouvernance MCP §6) : traçabilité des lectures d'identifiants du Secret Broker (payload limité à serviceId/credentialRef, jamais la valeur)
  McpSecretAccess: 'mcp.secret.access',
  // Hébergement des identifiants externes d'application (issue #19) : trace de lecture (payload limité à appId/key/result, jamais la valeur)
  AppSecretAccess: 'app.secret.access',
  // Identifiants d'utilisation d'actifs (2026-10-31) : faits d'utilisation déclarés spontanément par l'Agent après usage d'un skill/MCP (comptabilisés à l'audit par abonnement, à chaque occurrence)
  UsageAssetReported: 'usage.asset.reported',
  // Traçabilité des appels d'outils plateforme (2026-11-02) : faits de chaque appel d'outil via /mcp et /api/tools/execute (succès comme échec,
  // payload incluant l'identité de l'appelant — pour un appel PAT humain, actorId = userId du membre ; abonnement audit sur tool.invoke)
  ToolInvoked: 'tool.invoked',
  // Gouvernance des connecteurs (fusion open-connector ; préfixes déjà réservés dans la liste de ce fichier)
  ConnectorOddExit: 'connector.odd_exit',
  ConnectorPolicyMirrorFailed: 'connector.policy_mirror_failed',
  ConnectorPolicySnapshotDrifted: 'connector.policy_snapshot_drifted',
  ConnectorGatewayChanged: 'connector.gateway.changed',
  ConnectorGatewaySynced: 'connector.gateway.synced',
  ConnectorGatewayUnhealthy: 'connector.gateway.unhealthy',
  ConnectorConnected: 'connector.connected',
  ConnectorDisconnected: 'connector.disconnected',
  ConnectorInvoked: 'connector.invoked',
  ConnectorPermGroupChanged: 'connector.permgroup.changed',
  NasRegistered: 'nas.registered',
  NasOnlined: 'nas.onlined',
  NasOfflined: 'nas.offlined',
  SkillSubmitted: 'skill.submitted',
  SkillPublished: 'skill.published',
  SkillDeprecated: 'skill.deprecated',
  SkillInstalled: 'skill.installed',
  SkillUpdated: 'skill.updated',
  SkillPackageReplaced: 'skill.package_replaced',
  AgentRegistered: 'agent.registered',
  AgentOnlined: 'agent.onlined',
  AgentOfflined: 'agent.offlined',
  AppRegistered: 'app.registered',
  AppOnlined: 'app.onlined',
  AppOfflined: 'app.offlined',
  AppUpdated: 'app.updated',
  AppArchived: 'app.archived',
  OidcAuthorizeGranted: 'oidc.authorize.granted',
  OidcAuthorizeDenied: 'oidc.authorize.denied',
  EntryTicketRedeemed: 'authn.entryticket.redeemed',
  ApprovalCreated: 'approval.created',
  ApprovalDecided: 'approval.decided',
  AlertFired: 'audit.alert.fired',
  ConnectorSynced: 'iam.connector.synced',
  PluginSubmitted: 'market.plugin.submitted',
  PluginListed: 'market.plugin.listed',
  PluginInstalledEvent: 'market.plugin.installed',
  WalletChanged: 'wallet.balance.changed',
  LedgerSettled: 'billing.ledger.settled',
  ConnectCodeCreated: 'connect.code.created',
  ConnectClientEnrolled: 'connect.client.enrolled',
  ConnectClientDisabled: 'connect.client.disabled',
  UpdateAvailable: 'platform.update.available',
  UpdateApplied: 'platform.update.applied',
  UpdateRolledBack: 'platform.update.rolled_back',
  // Instrumentation comportementale frontend (WP-03/D3) : indépendante du pipeline de mesure usage, abonnements audit/tableau de bord
  BehaviorRecorded: 'behavior.recorded',
  // Panneau de département (plugin-panel-core) : messages/tâches/activations sectorielles + rafraîchissement à chaud du graphe de scénarios (review-dsh-agent-panel-v2)
  PanelMessageCreated: 'panel.message.created',
  PanelCardAction: 'panel.card.action',
  PanelTaskUpdated: 'panel.task.updated',
  PanelIndustryActivated: 'panel.industry.activated',
  ScenegraphUpdated: 'scenegraph.updated',
  // Pont DingTalk (plugin-dingtalk-bridge) : accusés de distribution sortante (le panneau y met à jour l'état ddSync)
  DingtalkDelivered: 'dingtalk-bridge.delivered',
  // Gouvernance de la passerelle de modèles (IAW passation 1-2/1-4) : circulation de la chaîne de repli et alertes de seuil de budget (consommable directement en SSE par le panneau)
  ModelgwDegraded: 'modelgw.degraded',
  ModelgwBudgetWarning: 'modelgw.budget.warning',
  // Autorisation au niveau scénario (IAW passation 6-1) : changements de stratégie (liaison avec la gouvernance interne à l'organisation)
  IamScenePolicyChanged: 'iam.scene_policy.changed',
  // Domaine des données (IAW passation 2-1..2-4) : changements d'enregistrement des jeux de données/dictionnaire d'indicateurs
  DatasetChanged: 'resource.dataset.changed',
  MetricDefinitionChanged: 'resource.metric.changed',
  // Moteur de flux de transactions (IAW passation 3-1, nouveau domaine flow de l'hôte) : orchestration TF et machine à états des étapes (consommable en SSE par le panneau)
  FlowCreated: 'flow.created',
  FlowStepUpdated: 'flow.step.updated',
  FlowCompleted: 'flow.completed',
  // Alerte de stagnation TF (C-06) : état running mais 0 étape running — alerte sans relance automatique, l'avancement exige un appel explicite
  FlowStalled: 'flow.stalled',
  FlowTemplateChanged: 'flow.template.changed',
  // Domaine Agent (IAW passation 7-1) : appels A2A inter-runtimes
  AgentA2aInvoked: 'agent.a2a.invoked',
  // Gel en cascade des Agents (R10, 2026-10-14) : gel en cas de dépassement de budget (plugin-agent écrit un état soft dans attrs + approbation de dégel)
  AgentFrozen: 'agent.frozen',
  AgentUnfrozen: 'agent.unfrozen',
  // Centre d'exécution (ybkk-MATRIX objectif quatre, 2026-10-14) : lignée d'objectifs / file de réveil / clôture des run / libération des verrous / heartbeat / routines
  ExecGoalChanged: 'exec.goal.changed',
  ExecIssueChanged: 'exec.issue.changed',
  ExecWakeEnqueued: 'exec.wake.enqueued',
  ExecRunCompleted: 'exec.run.completed',
  ExecLockReclaimed: 'exec.lock.reclaimed',
  ExecHeartbeatRecorded: 'exec.heartbeat.recorded',
  ExecRoutineChanged: 'exec.routine.changed',
  // Auto-observation du bus (OPT-P1-04) : exceptions des listeners et lettres mortes — perdre un événement = perdre une preuve, les exceptions doivent être explicitement consultables
  BusListenerError: 'bus.listener_error',
  BusDeadLetter: 'bus.dead_letter',
} as const

/** Espaces de noms réservés de la plateforme : émission interdite aux plugins tiers (source=plugin:*). */
const PLATFORM_RESERVED_PREFIXES = [
  'iam.', 'authn.', 'oidc.', 'mcp.', 'nas.', 'audit.', 'skill.', 'agent.', 'app.',
  'usage.', 'billing.', 'model.', 'market.', 'developer.', 'wallet.',
  'platform.', 'approval.', 'connector.', 'console.', 'connect.', 'behavior.',
  // Panneau de département / graphe de scénarios / pont DingTalk (review-dsh-agent-panel-v2 Phase 0)
  'panel.', 'scenegraph.', 'dingtalk-bridge.',
  // Gouvernance de la passerelle de modèles / moteur de flux de transactions / données (IAW lot de passation 2026-09-11)
  'modelgw.', 'flow.', 'resource.',
  // Centre d'exécution (2026-10-14)
  'exec.',
]

// -- Paramètres du pipeline du bus (OPT-P1-04 : au niveau du pipeline usage — persistance/reprises/lettres mortes/exceptions vers l'audit) --------
/** Capacité du ring en mémoire (le journal persiste l'intégralité, le ring n'est qu'un cache chaud). */
const RING_CAPACITY = 300
/** Délai de dispatch par listener : un dépassement compte pour un échec ; lettre morte après épuisement des reprises. */
const LISTENER_TIMEOUT_MS = 5_000
/** Backoff exponentiel des reprises d'échec : 3 exécutions réelles puis lettre morte. */
const RETRY_BACKOFF_MS = [50, 200, 800]
/** Seuil de débordement de la file de dispatch : l'excédent part en lettre morte (reason=backpressure_overflow, le journal reste rejouable, aucune preuve perdue). */
const QUEUE_OVERFLOW_CAP = 10_000
/**
 * Ensemble de coupure du retour (QA C-01) : bus.listener_error / bus.dead_letter sont des événements d'auto-observation du bus.
 * Si les listeners de ces deux types d'événements échouent à leur tour, ils ne doivent **pas** le signaler par un événement (sinon le listener
 * en échec s'abonnant à lui-même forme une boucle d'amplification auto-excitée : le journal croît sans fin et, en période de pointe, accapare le dispatch des vrais événements) —
 * les exceptions continuent d'atterrir une à une en lettres mortes (preuves consultables) ; seul le chemin de rétroaction par événement est coupé.
 */
const FEEDBACK_EVENTS = new Set<string>([PlatformEvents.BusListenerError, PlatformEvents.BusDeadLetter])

interface BusDeadLetterRecord {
  id: string
  eventName: string
  payload: unknown
  listener: string
  error: string
  attempts: number
  at: string
  /** Source d'événement : défaut = interne plateforme ; plugin:<id> = plugin tiers. La reprise structurelle des lettres mortes plugin: dépend de ce champ (les enregistrements existants sans ce champ sont traités par défaut, sans erreur). */
  source?: string
}

export class PlatformBusService extends Service {
  static readonly provide = 'platformBus'

  private listeners = new Map<string, Set<BusListener>>()
  private wildcard = new Set<BusListener>()
  private seq = 0
  private ring: PlatformEvent[] = []

  // -- État du pipeline (OPT-P1-04) : dispatch asynchrone série + persistance journal + lettres mortes ----------------
  private queue: PlatformEvent[] = []
  private draining = false
  private persistenceReady = false
  private journalFile: string | undefined
  private deadLetterFile: string | undefined
  private deadLetterStore: BusDeadLetterRecord[] = []
  private journalFailures = 0

  constructor(ctx: Context, options: { dataDir?: string } = {}) {
    super(ctx, 'platformBus')
    this.preparePersistence(options.dataDir)
  }

  /**
   * Préparation de la persistance (OPT-P1-04) : fichier d'append du journal + fichier des lettres mortes + rejeu au redémarrage.
   * Source du répertoire de données : options.dataDir explicite en priorité ; sinon opsStorage.dataDirPath (hôte allégé/tests unitaires sans stockage → exécution purement en mémoire).
   * Le journal charge les RING_CAPACITY dernières entrées dans le ring (« après redémarrage, les événements récents restent rejouables ») et poursuit seq au maximum historique.
   */
  private preparePersistence(explicitDataDir?: string): void {
    if (this.persistenceReady) return
    this.persistenceReady = true
    let dataDir = explicitDataDir
    if (!dataDir) {
      try {
        dataDir = (this.ctx as { opsStorage?: { dataDirPath?: string } }).opsStorage?.dataDirPath
      } catch {
        dataDir = undefined // proxy strict cordis : erreur si le service n'est pas fourni (forme embarquée/tests unitaires) → purement en mémoire
      }
    }
    if (!dataDir) return
    this.journalFile = join(dataDir, 'bus-journal.jsonl')
    this.deadLetterFile = join(dataDir, 'bus-dead-letters.jsonl')
    try {
      const lines = readFileSync(this.journalFile, 'utf8').split('\n').filter((line) => line.trim() !== '')
      for (const line of lines.slice(-RING_CAPACITY)) {
        try {
          const event = JSON.parse(line) as PlatformEvent
          this.ring.push(event)
          if (typeof event.id === 'number' && event.id > this.seq) this.seq = event.id
        } catch { /* ligne corrompue ignorée : le journal est en append-only, une ligne abîmée ne compromet pas le reste du rejeu */ }
      }
    } catch { /* premier démarrage : pas encore de journal */ }
    try {
      for (const line of readFileSync(this.deadLetterFile, 'utf8').split('\n')) {
        if (line.trim() === '') continue
        try { this.deadLetterStore.push(JSON.parse(line) as BusDeadLetterRecord) } catch { /* ligne corrompue ignorée */ }
      }
    } catch { /* premier démarrage : pas encore de lettres mortes */ }
  }

  /** Append au journal (fail-open : en cas d'échec d'écriture, comptage + alerte console, sans bloquer le dispatch ni émettre d'événement récursivement). */
  private appendJournal(event: PlatformEvent): void {
    if (!this.journalFile) return
    try {
      appendFileSync(this.journalFile, `${JSON.stringify(event)}\n`)
    } catch (error) {
      this.journalFailures++
      if (this.journalFailures <= 3) console.error('[bus] journal 追加失败（事件仍在 ring/队列，可回放窗口受损）', error)
    }
  }

  private appendDeadLetter(record: BusDeadLetterRecord): void {
    this.deadLetterStore.push(record)
    if (!this.deadLetterFile) return
    try {
      appendFileSync(this.deadLetterFile, `${JSON.stringify(record)}\n`)
    } catch (error) {
      console.error('[bus] 死信落盘失败（内存死信仍可本进程内重投）', error)
    }
  }

  on(event: string, cb: BusListener): () => void {
    const set = this.listeners.get(event) ?? new Set()
    set.add(cb)
    this.listeners.set(event, set)
    return () => set.delete(cb)
  }

  onAny(cb: BusListener): () => void {
    this.wildcard.add(cb)
    return () => this.wildcard.delete(cb)
  }

  emit(name: string, payload: unknown, options: { source?: string } = {}): PlatformEvent {
    const source = options.source
    if (source !== undefined && source.startsWith('plugin:')) {
      // Émission tierce : l'événement doit rester dans l'espace de noms du plugin et ne pas toucher aux espaces réservés de la plateforme
      if (!name.startsWith(`${source}:`)) {
        throw new Error(`[bus] 插件 ${source} 不得发射非自有命名空间事件：${name}（允许前缀 ${source}:）`)
      }
      if (PLATFORM_RESERVED_PREFIXES.some((prefix) => name.startsWith(prefix))) {
        throw new Error(`[bus] 插件 ${source} 不得发射平台保留命名空间事件：${name}`)
      }
    } else if (name.startsWith('plugin:')) {
      // Les événements de l'espace plugin: doivent avoir une source de plugin correspondante
      const pluginId = name.slice(0, name.indexOf(':', 8) === -1 ? name.length : name.indexOf(':', 8))
      throw new Error(`[bus] 插件命名空间事件 ${name} 必须携带来源（source: plugin:…，期望 ${pluginId}）`)
    }
    const event: PlatformEvent = { id: ++this.seq, name, payload, at: new Date().toISOString(), ...(source !== undefined ? { source } : {}) }
    this.preparePersistence()
    this.ring.push(event)
    if (this.ring.length > RING_CAPACITY) this.ring.shift()
    this.appendJournal(event)
    // OPT-P1-04 : dispatch en asynchrone série — emit renvoie de façon synchrone l'objet événement (validation/comptabilisation/persistance effectuées en synchrone),
    // les listeners sont consommés en série par le scheduler via une file (FIFO préserve l'ordre), échec → reprises → lettre morte → événement d'alerte, voir deliver().
    this.queue.push(event)
    if (this.queue.length > QUEUE_OVERFLOW_CAP) {
      const dropped = this.queue.shift()
      if (dropped) {
        this.enterDeadLetter(dropped, '*', 'backpressure_overflow：派发队列越限（事件已入 journal 可回放）', 0)
      }
    }
    this.scheduleDrain()
    return event
  }

  /** Événements récents (pour l'affichage du flux d'événements plateforme ; rechargés par rejeu du journal après redémarrage, toujours les RING_CAPACITY dernières). */
  recent(limit = 50): PlatformEvent[] {
    return this.ring.slice(-limit).reverse()
  }

  /** Liste des lettres mortes (OPT-P1-04) : inclut celles d'avant redémarrage (persistées dans bus-dead-letters.jsonl). */
  deadLetters(): BusDeadLetterRecord[] {
    return [...this.deadLetterStore]
  }

  /**
   * Reprise manuelle (OPT-P1-04) : renvoi un à un sous le nom d'événement d'origine (at-least-once).
   * Correctif QA C-02 : plus de « vider puis renvoyer » — un événement non reprendable (p. ex. un événement plugin:
   * ayant perdu sa source, rejeté dès la validation emit) n'entraîne plus la perte des autres lettres mortes ; seules celles renvoyées avec succès sortent, les échecs restent en place.
   * ⚠ Différence de sémantique avec le niveau de consommation usage : le bus n'a pas de niveau par listener, la reprise redistribue aussi aux listeners déjà servis,
   * les consommateurs doivent être idempotents (les consommateurs audit/projections dédupliquent par id d'événement). Les listeners qui échouent à nouveau pendant la reprise retournent naturellement en lettre morte.
   */
  retryDeadLetters(): { attempted: number; redelivered: number; retained: number } {
    const records = [...this.deadLetterStore]
    let redelivered = 0
    const retained: BusDeadLetterRecord[] = []
    for (const record of records) {
      try {
        // Les lettres mortes plugin: dont la source a été reconstituée sont renvoyées vers leur source d'origine (reprise structurelle) ; les enregistrements sans source partent vers la source par défaut (restent en place si la validation emit échoue)
        this.emit(record.eventName, record.payload, record.source !== undefined ? { source: record.source } : {})
        redelivered++
      } catch (error) {
        // Non reprendable (échec de validation de source/paramètre invalide) : la lettre morte est conservée avec son motif, en attente de traitement manuel
        retained.push({ ...record, error: `${record.error}；重投失败：${error instanceof Error ? error.message : String(error)}` })
      }
    }
    this.deadLetterStore = retained
    if (this.deadLetterFile) {
      try { writeFileSync(this.deadLetterFile, retained.map((record) => JSON.stringify(record)).join('\n') + (retained.length > 0 ? '\n' : ''), 'utf8') } catch { /* échec d'écriture : l'état mémoire est déjà aligné, nouvelle tentative à la prochaine reprise */ }
    }
    return { attempted: records.length, redelivered, retained: retained.length }
  }

  /** Comptabilisation des lettres mortes + événement d'alerte (bus.dead_letter). Avec suppressAlert, seule la comptabilisation, sans renvoi d'événement (coupure de rétroaction, QA C-01). */
  private enterDeadLetter(event: PlatformEvent, listener: string, error: string, attempts: number, options: { suppressAlert?: boolean } = {}): void {
    const record: BusDeadLetterRecord = {
      id: `bdl-${randomUUID()}`, eventName: event.name, payload: event.payload,
      listener, error, attempts, at: new Date().toISOString(),
      ...(event.source !== undefined ? { source: event.source } : {}),
    }
    this.appendDeadLetter(record)
    if (options.suppressAlert) return
    // L'événement d'alerte suit le pipeline complet (captable par l'abonnement générique audit) ; son propre échec est rattrapé par le fallback console de deliver, sans récursion en lettre morte
    this.emit(PlatformEvents.BusDeadLetter, record)
  }

  private scheduleDrain(): void {
    if (this.draining) return
    this.draining = true
    queueMicrotask(() => { void this.drain() })
  }

  private async drain(): Promise<void> {
    try {
      while (this.queue.length > 0) {
        const event = this.queue.shift()
        if (!event) break
        await this.deliver(event)
      }
    } finally {
      this.draining = false
      if (this.queue.length > 0) this.scheduleDrain()
    }
  }

  /**
   * Dispatch d'un seul événement (C-05) : les événements restent sériels FIFO via la file (drain attend allSettled événement par événement),
   * les listeners d'un même événement sont isolés en concurrence — l'échec/blocage d'un listener (au plus LISTENER_TIMEOUT_MS) ne ralentit plus
   * les autres listeners du même événement ; chaque dépassement/exception par listener compte un échec, après 3 reprises en backoff exponentiel → lettre morte (sémantique existante inchangée).
   */
  private async deliver(event: PlatformEvent): Promise<void> {
    const targets: Array<{ cb: BusListener; label: string }> = []
    for (const cb of this.listeners.get(event.name) ?? []) targets.push({ cb, label: event.name })
    for (const cb of this.wildcard) targets.push({ cb, label: '*' })
    await Promise.allSettled(targets.map(({ cb, label }) => this.deliverToOne(event, cb, label)))
  }

  /** Chaîne de dispatch d'un listener : chaque échec écrit bus.listener_error (coupure de rétroaction, voir FEEDBACK_EVENTS), lettre morte après épuisement des reprises. */
  private async deliverToOne(event: PlatformEvent, cb: BusListener, label: string): Promise<void> {
    for (let attempt = 1; attempt <= RETRY_BACKOFF_MS.length + 1; attempt++) {
      try {
        await withTimeout(Promise.resolve(cb(event.payload, event)), LISTENER_TIMEOUT_MS)
        return
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        // Les exceptions de listeners sont toujours explicitement écrites en événement (OPT-P1-04) : consultables dans l'audit, fini le simple console.error ;
        // coupure de rétroaction (QA C-01) : l'échec des listeners des événements de feedback n'est plus rétrocédé, directement en lettre morte (sinon boucle auto-excitée)
        console.error(`[bus] 监听器处理 ${event.name}（${label}）第 ${attempt} 次失败`, error)
        if (FEEDBACK_EVENTS.has(event.name)) {
          this.enterDeadLetter(event, label, `反馈事件监听器失败（不回授，QA C-01）：${message}`, attempt, { suppressAlert: true })
          return
        }
        this.emit(PlatformEvents.BusListenerError, { event: event.name, listener: label, attempt, error: message, at: new Date().toISOString() })
        if (attempt <= RETRY_BACKOFF_MS.length) {
          await sleep(RETRY_BACKOFF_MS[attempt - 1])
        } else {
          this.enterDeadLetter(event, label, `3 次重试均失败：${message}`, attempt)
        }
      }
    }
  }
}

function withTimeout(promise: Promise<unknown>, ms: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`监听器超时（>${ms}ms）`)), ms)
    promise.then(
      () => { clearTimeout(timer); resolve() },
      (error: unknown) => { clearTimeout(timer); reject(error instanceof Error ? error : new Error(String(error))) },
    )
  })
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
