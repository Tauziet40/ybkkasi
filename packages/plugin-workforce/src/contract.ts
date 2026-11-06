/**
 * Contrat commun de plugin-workforce (version figée V1.0 · 2026-10-15).
 *
 * Ce fichier est la forme matérialisée des dix décisions de chantier de l'annexe A du
 * « Employé numérique et appels de ressources de la plateforme - corrélations techniques et chemin d'implémentation (2026-10-15) »,
 * source de fait commune à tous les lots de travail :
 * figer d'abord le contrat et les échantillons d'acceptation, puis répartir les implémentations ; un réalisateur ne doit pas inventer de protocole d'identité, de tâche ou d'appel hors de ce fichier.
 *
 * Décisions figées de l'annexe A (telles que ce contrat les reflète) :
 *   1. Identité technique employé↔Agent : liaison valide un-à-un (workforce_bindings, un seul active par Agent).
 *   2. En phase 1, l'exécution runtime externe/dsh prime, la plateforme fournit la délégation, le bail et l'appel contrôlé de ressources ; pas de boucle d'inférence intégrée.
 *   3. dispatch/claim : verrou de prélecture d'ordonnancement conservé ; réclamation = « confirmation idempotente d'un bail déjà attribué ».
 *      Le stockage de référence des baux est SQLite exec_run_leases (détenu par exec-hub), issue.executionRunId n'est qu'une projection.
 *   4. permit : identifiant aléatoire opaque émis côté serveur, lié au sujet/employé/version de nomination/inventaire de capacités/run/bail,
 *      à validité courte et révocable ; l'appel doit aussi présenter un vrai jeton machine, la chaîne permit n'est pas elle-même un justificatif.
 *   5. L'inventaire de capacités ne descend que les poignées d'outils permises par la tâche ; un outil à risque inconnu n'est pas ouvert par défaut en écriture ; les contraintes de paramètres s'exécutent côté serveur.
 *   6. Mandat humain NAS = chaîne humaine vérifiée ∩ identité de l'employé ∩ autorisation de la tâche ; sans surveillance = mapping du sujet de service de poste ;
 *      les entrées/sorties de fichiers de l'employé passent toujours par le staging contrôlé d'artefacts, pas de chemin local de plateforme ouvert.
 *   7. Stockage de référence : les tables workforce_* en SQLite (txnStore) ; l'état métier du run reste chez exec-hub,
 *      le bail a exec_run_leases pour référence, les champs d'issue sont une projection.
 *   8. Association incrémentale de l'usage : workforce_usage_links enregistre le mapping invocation↔usageEvent,
 *      sans modifier les clés de ressources historiques, sans double comptabilisation de la consommation.
 *   9. L'approbation lie faits d'action ＋ résumé de paramètres ＋ version de nomination ; toute variation de version/paramètres impose une réévaluation.
 *   10. Contrainte équivalente sur les anciennes entrées pour les employés gérés : recherche inverse par caller de confiance (platform-core/workforce-port.ts),
 *       indépendamment du fait que la requête porte un contexte work.
 */
import type { SqlValue } from '../../platform-core/src/sqlite.ts'
import type {
  ManagedEmployeeRef,
  ResourceActionFacts,
  WorkCallerRef,
  WorkDataClass,
  WorkDenyCode,
  WorkExecutionContext,
} from '../../platform-core/src/workforce-port.ts'

export type {
  ManagedEmployeeRef,
  ResourceActionFacts,
  WorkCallerRef,
  WorkDataClass,
  WorkDenyCode,
  WorkExecutionContext,
  WorkPolicyDecision,
} from '../../platform-core/src/workforce-port.ts'

// ---------------------------------------------------------------------------
// Contrat du commutateur de déploiement progressif (lot W7 de W, décision D-② : activation/désactivation au niveau organisation)
// ---------------------------------------------------------------------------

/**
 * Commutateur de déploiement progressif (contrat W7 figé 2026-10-15, D-② niveau organisation) :
 *   - grayMode='off' (défaut) : ouvert à toutes les organisations, équivalent au comportement de phase 1 ;
 *   - grayMode='allowlist' : seules les organisations de enabledOrgs peuvent emprunter le chemin de travail (réclamation/prolongation/appel contrôlé),
 *     toute organisation hors liste est refusée (WORKFORCE_DISABLED) de façon observable (événement workforce.gray.denied).
 * La sémantique de désactivation = refus explicite et non repli silencieux vers legacy (même référentiel que V29 « jamais de passage silencieux sans politique ») :
 * verrouillage synchronisé dans port.authorizeWorkAction et aux entrées de réclamation/prolongation de l'admission, le denied côté passerelle est toujours comptabilisé.
 */
export interface WorkforceGrayConfig {
  grayMode?: 'off' | 'allowlist'
  enabledOrgs?: string[]
}

/** Erreur de domaine : code est un code de refus unifié (mapping en chinois dans WORK_DENY_CODE_LABELS de platform-core). */
export class WorkforceError extends Error {
  readonly code: WorkDenyCode
  readonly httpStatus: number

  constructor(code: WorkDenyCode, message: string, httpStatus = 403) {
    super(message)
    this.name = 'WorkforceError'
    this.code = code
    this.httpStatus = httpStatus
  }
}

// ---------------------------------------------------------------------------
// Types d'enregistrements (colonnes de référence dans WORKFORCE_TABLES ; les champs tableau/objet sont stockés en JSON TEXT)
// ---------------------------------------------------------------------------

export type EmployeeStatus = 'active' | 'suspended' | 'offboarded'
export type BindingStatus = 'active' | 'inactive'
export type AppointmentStatus = 'preparing' | 'effective' | 'revoking' | 'revoked' | 'failed'
export type GrantStatus = 'preparing' | 'effective' | 'revoking' | 'revoked' | 'failed'
export type ManifestStatus = 'draft' | 'active' | 'retired'
export type PermitStatus = 'active' | 'revoked' | 'expired'
export type LeaseStatus = 'active' | 'released' | 'superseded'
export type InvocationStatus =
  | 'reserved'
  | 'completed'
  | 'denied'
  | 'approval_required'
  | 'rate_limited'
  | 'failed'
  | 'outcome_unknown'
  | 'cancelled'
export type DeliverableStatus = 'submitted' | 'accepted' | 'rejected'

/** Dossier de l'employé (§8.1) : identité métier stable de l'employé de poste, inchangée par renommage/redémarrage. */
export interface EmployeeRecord {
  id: string
  name: string
  displayName: string
  /** Organisation principale (organisation de rattachement de l'employé). */
  orgId: string
  /** Superviseur humain (userId) : responsable, ne devient pas automatiquement utilisateur mandataire. */
  supervisorUserId: string
  status: EmployeeStatus
  /** Agent de liaison actuellement valide (pointeur redondant, maintenu par le service de liaison en transaction ; '' = non lié). */
  primaryAgentId: string
  createdAt: string
  updatedAt: string
}

/** Liaison d'exécution (§8.1) : liaison valide un-à-un employé↔Agent technique. */
export interface BindingRecord {
  id: string
  employeeId: string
  agentId: string
  principalId: string
  /** dsh / external / … */
  runtime: string
  capabilityVersion: number
  status: BindingStatus
  createdAt: string
  updatedAt: string
}

/** Autorisation de ressources souhaitée (§D.4) : intention d'autorisation au sein de la version de nomination, l'effectivité réelle fait foi des configurations des passerelles ＋ sondes. */
export interface ResourceGrantSpec {
  kind: 'mcp' | 'connector' | 'model' | 'skill' | 'nas' | 'app'
  /** ID de service mcp / provider connector / slug de modèle / ID de skill / ID NAS / ID d'application. */
  registryId: string
  /** Noms d'outils/actions (les actions d'écriture doivent être listées explicitement, un outil à risque inconnu n'est pas ouvert par défaut). */
  actions: string[]
  risk: 'read' | 'write' | 'admin'
  /** Contraintes de paramètres et d'objets métier : factoryIds / pathPrefixes / maxRows / alias etc. */
  constraints?: Record<string, unknown>
}

/** Enregistrement d'effectivité d'autorisation de ressources : préparation→en vigueur→révocation→révoquée/échec de configuration (§D.4). */
export interface ResourceGrantRecord {
  id: string
  appointmentId: string
  kind: ResourceGrantSpec['kind']
  registryId: string
  actionsJson: string
  risk: ResourceGrantSpec['risk']
  constraintsJson: string
  /** Référence du vrai groupe de permissions/politique/mapping de catalogue reconstituée après mise en vigueur (pas une case cochée d'UI). */
  ref: string
  status: GrantStatus
  lastError: string
  checkedAt: string
  createdAt: string
  updatedAt: string
}

/** Version de nomination (§8.1/§8.2) : organisation de travail et frontière de permissions ; mutation/montée en grade ne réécrit pas l'historique. */
export interface AppointmentRecord {
  id: string
  employeeId: string
  version: number
  position: string
  /** Organisation de travail (organisation de rattachement des tâches ; enregistrée séparément de l'organisation de ressources et du rattachement des coûts). */
  orgId: string
  /** Plafond de classification métier figé par la nomination (référentiel unifié WorkDataClass). */
  dataClass: WorkDataClass
  effectiveFrom: string
  /** Temps ISO ; chaîne vide = à durée indéterminée. */
  effectiveUntil: string
  grantsJson: string
  approvedBy: string
  approvalRef: string
  status: AppointmentStatus
  statusReason: string
  createdAt: string
  updatedAt: string
}

/** Inventaire de capacités (§8.1/§9.2) : ensemble de poignées d'outils permises par la tâche, le serveur mappe vers les ressources réelles. */
export interface ManifestToolHandle {
  /** Poignée de présentation : `<scope>.<action>`, le runtime ne peut référencer que la poignée, pas apporter sa propre clé de ressource. */
  handle: string
  kind: ResourceGrantSpec['kind']
  /** Clé de présentation (ex. mcp:quality-gateway) ; la clé de résolution réelle est registryId. */
  resourceRef: string
  registryId: string
  action: string
  risk: ResourceGrantSpec['risk']
  constraints?: Record<string, unknown>
  /** JSON Schema de paramètres côté serveur (racine object) ; échec de validation = ARGUMENT_SCOPE_DENIED. */
  parameters?: Record<string, unknown>
  description?: string
}

export interface SkillPin {
  skillId: string
  /** Version publiée figée (sans dérive). */
  version: string
  /** Résumé de contenu/paquet (pour vérification de la preuve de chargement). */
  contentHash: string
}

export interface ManifestRecord {
  id: string
  appointmentId: string
  version: number
  toolsJson: string
  skillPinsJson: string
  status: ManifestStatus
  createdAt: string
}

/** Autorisation de travail à court terme (§8.1) : permit opaque, lie le sujet au run/bail. */
export interface PermitRecord {
  id: string
  employeeId: string
  agentId: string
  principalId: string
  appointmentId: string
  appointmentVersion: number
  manifestId: string
  issueId: string
  runId: string
  leaseId: string
  leaseVersion: number
  status: PermitStatus
  expiresAt: string
  createdAt: string
  revokedAt: string
  revokedReason: string
}

/** Bail d'exécution (§6.2/§11.6) : la table de référence exec_run_leases est détenue par exec-hub (annexe A décisions 3/7). */
export interface RunLeaseRecord {
  id: string
  issueId: string
  runId: string
  employeeId: string
  agentKey: string
  principalId: string
  leaseVersion: number
  status: LeaseStatus
  acquiredAt: string
  renewedAt: string
  expiresAt: string
  releasedAt: string
  releaseReason: string
}

/** Registre des appels de travail (§9/§11.6) : « ce que cet employé demande à cette étape et le résultat actuel ». */
export interface InvocationRecord {
  id: string
  employeeId: string
  appointmentId: string
  appointmentVersion: number
  runId: string
  permitId: string
  stepKey: string
  kind: ResourceGrantSpec['kind']
  registryId: string
  action: string
  risk: ResourceGrantSpec['risk']
  /** Hachage du résumé canonique des paramètres (jugement de conflit d'étape ; immuable). */
  argsHash: string
  argsSummaryJson: string
  status: InvocationStatus
  errorCode: string
  message: string
  /** Preuve d'appel de passerelle (callId/executionId/modèle/version etc.). */
  gatewayRefJson: string
  usageEventIdsJson: string
  approvalRef: string
  latencyMs: number
  createdAt: string
  settledAt: string
}

/** Livrable (§8.1) : la fin de l'exécution technique ne forme qu'un « livrable soumis », l'acceptation est décidée par un humain (§6.5). */
export interface DeliverableRecord {
  id: string
  runId: string
  issueId: string
  employeeId: string
  summary: string
  artifactIdsJson: string
  version: number
  status: DeliverableStatus
  submittedAt: string
  decidedAt: string
  decidedBy: string
  decisionReason: string
}

/** Association appel de travail↔fait de consommation (§11.1/§11.3) : simple mapping, pas de duplication des écritures de consommation. */
export interface UsageLinkRecord {
  id: string
  invocationId: string
  usageEventId: string
  resource: string
  createdAt: string
}

/** Métadonnées des fichiers de livraison/entrée contrôlés (§11.6) : contenu stocké dans le répertoire staging contrôlé, aucun chemin arbitraire de plateforme ouvert. */
export interface ArtifactRecord {
  id: string
  employeeId: string
  runId: string
  orgId: string
  name: string
  contentType: string
  sizeBytes: number
  sha256: string
  storagePath: string
  source: 'upload' | 'generated'
  createdAt: string
}

/** Événements à émettre en état soumis (§11.6) : clé unique d'événement, tentatives et point d'eau de consommation. */
export interface OutboxRecord {
  id: string
  eventKey: string
  type: string
  payloadJson: string
  status: 'pending' | 'sent' | 'consumed'
  attempts: number
  lastError: string
  createdAt: string
  sentAt: string
  consumedAt: string
}

// ---------------------------------------------------------------------------
// Structures de tables (DDL de référence) : consommées directement par migrations.ts ; les tables workforce_* sont détenues par cette extension
// ---------------------------------------------------------------------------

export interface WorkforceTableSpec {
  name: string
  columns: Record<string, string>
  uniques?: string[][]
  indexes?: string[][]
  /** Champs TEXT nécessitant sérialisation/désérialisation JSON. */
  jsonFields?: string[]
}

export const WORKFORCE_TABLES: Record<string, WorkforceTableSpec> = {
  workforce_employees: {
    name: 'workforce_employees',
    columns: {
      id: 'TEXT NOT NULL', name: 'TEXT NOT NULL', displayName: "TEXT NOT NULL DEFAULT ''",
      orgId: 'TEXT NOT NULL', supervisorUserId: "TEXT NOT NULL DEFAULT ''",
      status: 'TEXT NOT NULL', primaryAgentId: "TEXT NOT NULL DEFAULT ''",
      createdAt: 'TEXT NOT NULL', updatedAt: 'TEXT NOT NULL',
    },
    indexes: [['orgId'], ['status']],
  },
  workforce_bindings: {
    name: 'workforce_bindings',
    columns: {
      id: 'TEXT NOT NULL', employeeId: 'TEXT NOT NULL', agentId: 'TEXT NOT NULL',
      principalId: "TEXT NOT NULL DEFAULT ''", runtime: "TEXT NOT NULL DEFAULT 'dsh'",
      capabilityVersion: 'INTEGER NOT NULL DEFAULT 1', status: 'TEXT NOT NULL',
      createdAt: 'TEXT NOT NULL', updatedAt: 'TEXT NOT NULL',
    },
    indexes: [['employeeId'], ['agentId'], ['status']],
  },
  workforce_appointments: {
    name: 'workforce_appointments',
    columns: {
      id: 'TEXT NOT NULL', employeeId: 'TEXT NOT NULL', version: 'INTEGER NOT NULL',
      position: "TEXT NOT NULL DEFAULT ''", orgId: 'TEXT NOT NULL', dataClass: "TEXT NOT NULL DEFAULT 'internal'",
      effectiveFrom: 'TEXT NOT NULL', effectiveUntil: "TEXT NOT NULL DEFAULT ''",
      grantsJson: "TEXT NOT NULL DEFAULT '[]'", approvedBy: "TEXT NOT NULL DEFAULT ''",
      approvalRef: "TEXT NOT NULL DEFAULT ''", status: 'TEXT NOT NULL', statusReason: "TEXT NOT NULL DEFAULT ''",
      createdAt: 'TEXT NOT NULL', updatedAt: 'TEXT NOT NULL',
    },
    uniques: [['employeeId', 'version']],
    indexes: [['employeeId'], ['status']],
  },
  workforce_resource_grants: {
    name: 'workforce_resource_grants',
    columns: {
      id: 'TEXT NOT NULL', appointmentId: 'TEXT NOT NULL',
      kind: 'TEXT NOT NULL', registryId: 'TEXT NOT NULL',
      actionsJson: "TEXT NOT NULL DEFAULT '[]'", risk: "TEXT NOT NULL DEFAULT 'read'",
      constraintsJson: "TEXT NOT NULL DEFAULT '{}'", ref: "TEXT NOT NULL DEFAULT ''",
      status: 'TEXT NOT NULL', lastError: "TEXT NOT NULL DEFAULT ''", checkedAt: "TEXT NOT NULL DEFAULT ''",
      createdAt: 'TEXT NOT NULL', updatedAt: 'TEXT NOT NULL',
    },
    indexes: [['appointmentId'], ['status']],
  },
  workforce_manifests: {
    name: 'workforce_manifests',
    columns: {
      id: 'TEXT NOT NULL', appointmentId: 'TEXT NOT NULL', version: 'INTEGER NOT NULL',
      toolsJson: "TEXT NOT NULL DEFAULT '[]'", skillPinsJson: "TEXT NOT NULL DEFAULT '[]'",
      status: "TEXT NOT NULL DEFAULT 'draft'", createdAt: 'TEXT NOT NULL',
    },
    uniques: [['appointmentId', 'version']],
    indexes: [['appointmentId']],
  },
  workforce_permits: {
    name: 'workforce_permits',
    columns: {
      id: 'TEXT NOT NULL', employeeId: 'TEXT NOT NULL', agentId: 'TEXT NOT NULL', principalId: 'TEXT NOT NULL',
      appointmentId: 'TEXT NOT NULL', appointmentVersion: 'INTEGER NOT NULL',
      manifestId: 'TEXT NOT NULL', issueId: "TEXT NOT NULL DEFAULT ''", runId: "TEXT NOT NULL DEFAULT ''",
      leaseId: "TEXT NOT NULL DEFAULT ''", leaseVersion: 'INTEGER NOT NULL DEFAULT 0',
      status: 'TEXT NOT NULL', expiresAt: 'TEXT NOT NULL', createdAt: 'TEXT NOT NULL',
      revokedAt: "TEXT NOT NULL DEFAULT ''", revokedReason: "TEXT NOT NULL DEFAULT ''",
    },
    indexes: [['employeeId', 'status'], ['principalId'], ['runId']],
  },
  workforce_invocations: {
    name: 'workforce_invocations',
    columns: {
      id: 'TEXT NOT NULL', employeeId: 'TEXT NOT NULL', appointmentId: 'TEXT NOT NULL',
      appointmentVersion: 'INTEGER NOT NULL', runId: 'TEXT NOT NULL', permitId: 'TEXT NOT NULL',
      stepKey: 'TEXT NOT NULL', kind: 'TEXT NOT NULL', registryId: 'TEXT NOT NULL',
      action: 'TEXT NOT NULL', risk: "TEXT NOT NULL DEFAULT 'read'",
      argsHash: 'TEXT NOT NULL', argsSummaryJson: "TEXT NOT NULL DEFAULT '{}'",
      status: 'TEXT NOT NULL', errorCode: "TEXT NOT NULL DEFAULT ''", message: "TEXT NOT NULL DEFAULT ''",
      gatewayRefJson: "TEXT NOT NULL DEFAULT '{}'", usageEventIdsJson: "TEXT NOT NULL DEFAULT '[]'",
      approvalRef: "TEXT NOT NULL DEFAULT ''", latencyMs: 'INTEGER NOT NULL DEFAULT 0',
      createdAt: 'TEXT NOT NULL', settledAt: "TEXT NOT NULL DEFAULT ''",
    },
    // Clé d'étape unique au sein d'un même run (§11.5) ; résumé de paramètres immuable — des paramètres différents heurtant la contrainte d'unicité = STEP_ARGUMENT_CONFLICT
    uniques: [['runId', 'stepKey']],
    indexes: [['employeeId'], ['permitId'], ['status']],
  },
  workforce_usage_links: {
    name: 'workforce_usage_links',
    columns: {
      id: 'TEXT NOT NULL', invocationId: 'TEXT NOT NULL', usageEventId: 'TEXT NOT NULL',
      resource: "TEXT NOT NULL DEFAULT ''", createdAt: 'TEXT NOT NULL',
    },
    uniques: [['invocationId', 'usageEventId']],
    indexes: [['invocationId']],
  },
  workforce_artifacts: {
    name: 'workforce_artifacts',
    columns: {
      id: 'TEXT NOT NULL', employeeId: 'TEXT NOT NULL', runId: "TEXT NOT NULL DEFAULT ''",
      orgId: 'TEXT NOT NULL', name: 'TEXT NOT NULL', contentType: "TEXT NOT NULL DEFAULT 'application/octet-stream'",
      sizeBytes: 'INTEGER NOT NULL DEFAULT 0', sha256: 'TEXT NOT NULL', storagePath: 'TEXT NOT NULL',
      source: "TEXT NOT NULL DEFAULT 'upload'", createdAt: 'TEXT NOT NULL',
    },
    indexes: [['employeeId'], ['runId']],
  },
  workforce_deliverables: {
    name: 'workforce_deliverables',
    columns: {
      id: 'TEXT NOT NULL', runId: 'TEXT NOT NULL', issueId: "TEXT NOT NULL DEFAULT ''",
      employeeId: 'TEXT NOT NULL', summary: "TEXT NOT NULL DEFAULT ''",
      artifactIdsJson: "TEXT NOT NULL DEFAULT '[]'", version: 'INTEGER NOT NULL',
      status: "TEXT NOT NULL DEFAULT 'submitted'", submittedAt: 'TEXT NOT NULL',
      decidedAt: "TEXT NOT NULL DEFAULT ''", decidedBy: "TEXT NOT NULL DEFAULT ''", decisionReason: "TEXT NOT NULL DEFAULT ''",
    },
    uniques: [['runId', 'version']],
    indexes: [['employeeId'], ['issueId']],
  },
  workforce_outbox: {
    name: 'workforce_outbox',
    columns: {
      id: 'TEXT NOT NULL', eventKey: 'TEXT NOT NULL', type: 'TEXT NOT NULL',
      payloadJson: "TEXT NOT NULL DEFAULT '{}'", status: "TEXT NOT NULL DEFAULT 'pending'",
      attempts: 'INTEGER NOT NULL DEFAULT 0', lastError: "TEXT NOT NULL DEFAULT ''",
      createdAt: 'TEXT NOT NULL', sentAt: "TEXT NOT NULL DEFAULT ''", consumedAt: "TEXT NOT NULL DEFAULT ''",
    },
    uniques: [['eventKey']],
    indexes: [['status']],
  },
}

// ---------------------------------------------------------------------------
// Interfaces de dépôt (implémentées par repositories.ts ; consommées par les services)
// ---------------------------------------------------------------------------

export interface TableStore<T> {
  insert(row: T): void
  get(id: string): T | undefined
  all(): T[]
  /** Requête par égalité (champ→valeur ; pour jsonFields, l'implémentation confronte le texte JSON brut sous forme de chaîne). */
  findWhere(where: Record<string, SqlValue>): T[]
  update(id: string, patch: Partial<T>): void
  delete(id: string): void
  count(): number
}

export interface WorkforceStore {
  employees: TableStore<EmployeeRecord>
  bindings: TableStore<BindingRecord>
  appointments: TableStore<AppointmentRecord>
  grants: TableStore<ResourceGrantRecord>
  manifests: TableStore<ManifestRecord>
  permits: TableStore<PermitRecord>
  invocations: TableStore<InvocationRecord>
  usageLinks: TableStore<UsageLinkRecord>
  artifacts: TableStore<ArtifactRecord>
  deliverables: TableStore<DeliverableRecord>
  outbox: TableStore<OutboxRecord>
  /** Transaction synchrone BEGIN IMMEDIATE (enveloppe txnStore) : pour courts contrôles/réservations/validations ; tout appel réseau y est strictement interdit. */
  txn<T>(fn: () => T): T
  /** Migration : crée toutes les WORKFORCE_TABLES (idempotent). */
  migrate(): void
}

// ---------------------------------------------------------------------------
// Résolution d'identité (identity-resolver.ts)
// ---------------------------------------------------------------------------

export interface IdentityResolution {
  employee: EmployeeRecord
  binding: BindingRecord
  /** Nomination actuellement en vigueur (ne renvoie non null que si l'employé est en poste + nomination effective). */
  appointment: AppointmentRecord
}

export interface WorkforceIdentityResolver {
  /**
   * Caller de confiance → employé/liaison/nomination en vigueur.
   * Règles (§5) : machine et refType=agent → recherche inverse par binding.agentId ; human → correspondance superviseur par userId ? Non —
   * le sujet machine de l'employé n'est recherché que par la liaison agent ; human renvoie toujours null (le domaine de l'employé n'a pas de canal « l'humain est l'employé »).
   * Géré seulement si en poste (active) ＋ liaison un-à-un valide ＋ nomination effective existante ; sinon null.
   */
  resolveByCaller(caller: WorkCallerRef): Promise<IdentityResolution | null>
  describeAgent(agentId: string): Promise<ManagedEmployeeRef | null>
  /**
   * Sonde d'état de liaison de l'Agent (couverture permit du 2e item de gouvernance de la face collaboration, P2-01) : à la différence de describeAgent,
   * **elle distingue « jamais repris » de « repris mais permit invalide »** — le premier passe selon la sémantique legacy, le second doit être
   * refusé en fail-closed (employé hors poste / nomination révoquée / liaison désactivée). Ne renvoie que des faits revérifiés côté serveur.
   */
  inspectAgent(agentId: string): Promise<AgentBindingState>
}

/** État de liaison de l'Agent (valeur de retour d'inspectAgent ; bound=false signifie jamais repris). */
export interface AgentBindingState {
  agentId: string
  /** Existence d'une liaison active (fait de prise en gestion). */
  bound: boolean
  /** Les trois éléments du statut géré réunis : employé en poste + liaison valide + nomination en vigueur existante. */
  permitEffective: boolean
  employeeId?: string
  bindingId?: string
  /** Motif honnête quand permitEffective=false et bound=true (pour diagnostic et audit). */
  reason?: 'EMPLOYEE_NOT_ACTIVE' | 'NO_EFFECTIVE_APPOINTMENT'
}

// ---------------------------------------------------------------------------
// Port d'intégration exec-hub (implémenté par exec-hub ; consommé de façon structurée par workforce — pas d'import inverse)
// ---------------------------------------------------------------------------

export type EmployeeClaimResult =
  | { ok: true; issueId: string; runId: string; lease: RunLeaseRecord; created: boolean }
  | {
      ok: false
      code: 'ISSUE_NOT_FOUND' | 'ISSUE_CLOSED' | 'LEASE_HELD_BY_OTHER' | 'ADMISSION_DENIED' | 'BUDGET_EXCEEDED' | 'APPROVAL_REQUIRED' | 'EXEC_HUB_UNAVAILABLE'
      message: string
      holder?: string
    }

export type EmployeeLeaseResult =
  | { ok: true; lease: RunLeaseRecord }
  | { ok: false; code: 'LEASE_STALE' | 'RUN_NOT_OWNED' | 'EXEC_HUB_UNAVAILABLE'; message: string }

/** Chemin de travail employé d'exec-hub (annexe A décision 3 : réclamation = confirmation idempotente d'un bail déjà attribué). */
export interface ExecHubWorkIntegration {
  /**
   * Réclamation idempotente : admission unifiée (gel/budget/approbation) → get-or-create run → obtention atomique du bail.
   * Une réclamation répétée du même employé+même tâche renvoie le run/bail existant (created=false), sans rapporter « détenu par autrui » ;
   * autre employé/autre nomination/ancien bail/tâche déjà fermée : refus.
   */
  claimForEmployee(input: { issueId: string; employeeId: string; agentKey: string; principalId: string; ttlMs?: number }): Promise<EmployeeClaimResult>
  /** Prolongation/battement de progression : même sujet, même run, non révoqué, non expiré pour pouvoir prolonger. */
  renewLease(input: { runId: string; principalId: string; ttlMs?: number }): Promise<EmployeeLeaseResult>
  /** Vérification de propriété sujet/run pour exec_complete (D07) : refus inter-employés/ancien bail. */
  assertRunOwnership(input: { runId: string; principalId: string }): Promise<{ ok: true; lease: RunLeaseRecord } | { ok: false; code: WorkDenyCode; message: string }>
  /** Liaison suspension/révocation : libère le bail par run et nettoie la projection issue. */
  releaseForRun(runId: string, reason: string): void
}

// ---------------------------------------------------------------------------
// Admission et réclamation (admission-service.ts) ; permit (permit-service.ts)
// ---------------------------------------------------------------------------

export interface ClaimInput {
  issueId: string
  /** Alias de runtime (compatible avec l'agentKey d'exec_claim) ; le rattachement du sujet reste fondé sur la recherche inverse par jeton. */
  agentKey?: string
  ttlMs?: number
}

export type ClaimOutcome =
  | {
      ok: true
      employeeId: string
      agentId: string
      issueId: string
      runId: string
      lease: RunLeaseRecord
      permit: PermitRecord
      manifest: ManifestRecord
      tools: ManifestToolHandle[]
      /** Marque de rejeu idempotent : une réclamation répétée du même sujet pour la même tâche renvoie l'autorisation existante. */
      idempotent: boolean
    }
  | { ok: false; code: WorkDenyCode; message: string; holder?: string }

export interface WorkforceAdmission {
  /** Entrée unifiée de réclamation (partagée par REST /claims et l'enveloppe de compatibilité exec_claim, pas d'implémentation dupliquée). */
  claimWork(caller: WorkCallerRef, input: ClaimInput): Promise<ClaimOutcome>
  /** Prolongation/progression. */
  renewWorkLease(caller: WorkCallerRef, permitId: string, ttlMs?: number): Promise<EmployeeLeaseResult>
  /**
   * Vérification du permit : existe, active, non expiré, sujet concordant (principalId), version de nomination cohérente ;
   * avec requireRun, vérifie le rattachement run/bail. Échec lève WorkforceError.
   */
  verifyPermit(caller: WorkCallerRef, permitId: string, opts?: { requireRun?: boolean }): Promise<PermitRecord>
  /** Vérification de propriété pour exec_complete (D07) : renvoie le contexte vérifié, échec lève WorkforceError. */
  assertRunOwnership(caller: WorkCallerRef, runId: string): Promise<WorkExecutionContext>
}

export interface WorkforcePermits {
  issue(input: {
    resolution: IdentityResolution
    issueId: string
    runId: string
    lease: RunLeaseRecord
    manifestId: string
    ttlMs: number
  }): PermitRecord
  /** Vérification sujet/statut/validité/version de nomination ; discordance lève WorkforceError. */
  verify(permitId: string, caller: WorkCallerRef, opts?: { requireRun?: boolean }): PermitRecord
  revoke(permitId: string, reason: string): void
  revokeForEmployee(employeeId: string, reason: string): number
  activeForRun(runId: string): PermitRecord | undefined
}

// ---------------------------------------------------------------------------
// Inventaire de capacités (capability-manifest.ts)
// ---------------------------------------------------------------------------

export interface WorkforceCapabilities {
  /** Génère/fait évoluer la version depuis le jeu d'autorisations souhaitées de la nomination (skillPins figées en version et résumé via la sonde skillHub). */
  buildForAppointment(appointmentId: string): ManifestRecord
  get(manifestId: string): ManifestRecord
  activeForAppointment(appointmentId: string): ManifestRecord | undefined
  toolsFor(manifestId: string): ManifestToolHandle[]
  resolveTool(manifestId: string, handle: string): ManifestToolHandle | undefined
}

// ---------------------------------------------------------------------------
// Adaptateurs de ressources (adapters/*) : mappent l'appel contrôlé vers les passerelles existantes ; une capacité absente renvoie non pris en charge, sans faire passer une implémentation vide pour un succès
// ---------------------------------------------------------------------------

export interface AdapterProbeResult {
  ok: boolean
  /** Référence du vrai groupe de permissions/politique/mapping de catalogue reconstituée après mise en vigueur. */
  ref?: string
  message?: string
}

export interface AdapterInvokeInput {
  work: WorkExecutionContext
  tool: ManifestToolHandle
  args: Record<string, unknown>
  invocationId: string
}

export interface AdapterInvokeResult {
  ok: boolean
  /** Résultat métier (value/content fournis quand completed). */
  value?: unknown
  content?: string
  /** Preuve de passerelle : callId / executionId / modèle / tokens / référence de version etc. */
  gatewayRef?: Record<string, unknown>
  /** Liste des identifiants d'événements renvoyés par usage.record() (reconstitués dans usage_links si présents). */
  usageEventIds?: string[]
  /** Référence d'approbation quand approval_required. */
  approvalRef?: string
  rateLimited?: boolean
  /** Réseau déjà sollicité mais résultat incertain (timeout d'écriture etc.). */
  outcomeUnknown?: boolean
  message?: string
}

export interface ResourceAdapter {
  kind: ResourceGrantSpec['kind']
  /** Sonde d'autorisation à l'activation de la nomination (D.4) : vérification en lecture seule de la configuration réelle, pas d'élargissement automatique. */
  probeGrant(spec: ResourceGrantSpec, resolution: IdentityResolution): Promise<AdapterProbeResult>
  /** Appel contrôlé : sollicite le service de passerelle existant et reconstitue la preuve (l'adaptateur repasse par la chaîne d'autorisation propre de la passerelle). */
  invoke(input: AdapterInvokeInput): Promise<AdapterInvokeResult>
}

export interface AdapterRegistry {
  get(kind: ResourceGrantSpec['kind']): ResourceAdapter | undefined
  /** Enregistrement complet (appelé à l'assemblage dans index.ts). */
  register(adapter: ResourceAdapter): void
}

// ---------------------------------------------------------------------------
// Appel contrôlé (invocation-service.ts) : sémantique d'états §9.3
// ---------------------------------------------------------------------------

export interface InvocationRequest {
  permitId: string
  toolHandle: string
  /** Référence d'étape métier proposée par l'appelant ; le serveur vérifie longueur/caractères/périmètre run et lie le résumé de paramètres. */
  stepKey: string
  arguments?: unknown
  traceId?: string
}

export type InvocationOutcome =
  | { status: 'completed'; invocationId: string; value?: unknown; content?: string; gatewayRef?: Record<string, unknown>; work: WorkExecutionContext }
  | { status: 'denied'; invocationId: string; code: WorkDenyCode; message: string }
  | { status: 'approval_required'; invocationId: string; message: string; approvalRef?: string }
  | { status: 'rate_limited'; invocationId: string; message: string; retryAfterMs?: number }
  | { status: 'failed'; invocationId: string; message: string; code?: WorkDenyCode }
  | { status: 'outcome_unknown'; invocationId: string; message: string }
  | { status: 'cancelled'; invocationId: string; message: string }

export interface WorkforceInvocations {
  invoke(caller: WorkCallerRef, request: InvocationRequest): Promise<InvocationOutcome>
  /** Contrôle d'appartenance : l'employé lui-même ou workforce.read de la même organisation ; les résultats ne fuient pas entre organisations. */
  get(caller: WorkCallerRef, invocationId: string): InvocationRecord
  listByRun(caller: WorkCallerRef, runId: string): InvocationRecord[]
  /** Reconstitution par l'adaptateur : association aux événements usage de la passerelle (paire unique, idempotent). */
  linkUsage(invocationId: string, usageEventId: string, resource: string): void
  /** Écriture retour après vérification d'un outcome_unknown (manuel/réconciliation). */
  reconcile(id: string, status: 'completed' | 'failed', message: string, gatewayRef?: Record<string, unknown>): void
}

// ---------------------------------------------------------------------------
// Artefacts contrôlés (artifact-service.ts) et acceptation de livraison (acceptance-service.ts)
// ---------------------------------------------------------------------------

export interface WorkforceArtifacts {
  /** Téléversement contrôlé : le contenu entre par base64 dans le corps de requête vers le staging serveur, chemin local arbitraire de la plateforme interdit. */
  createUpload(caller: WorkCallerRef, input: { name: string; contentType: string; contentBase64: string; runId?: string }): ArtifactRecord
  get(caller: WorkCallerRef, artifactId: string): ArtifactRecord
  /** Lecture du contenu contrôlé par l'employé/workforce.read de la même organisation (consommée par l'adaptateur d'écriture NAS). */
  readBase64(caller: WorkCallerRef, artifactId: string): string
}

export interface WorkforceDelivery {
  /** Soumission d'une livraison structurée : vérifie le rattachement du run et des artefacts ; completeRun d'exec-hub passe la tâche en review. */
  submit(caller: WorkCallerRef, input: { permitId: string; summary: string; artifactIds: string[] }): Promise<DeliverableRecord>
  /** Acceptation/retour par un humain (workforce.accept) : accepted→done ; rejected→retour à l'exécution en conservant tous les faits d'appel. */
  decide(caller: WorkCallerRef, input: { deliverableId: string; decision: 'accepted' | 'rejected'; reason: string }): Promise<DeliverableRecord>
  get(caller: WorkCallerRef, deliverableId: string): DeliverableRecord
  listByRun(caller: WorkCallerRef, runId: string): DeliverableRecord[]
}

// ---------------------------------------------------------------------------
// Gestion des employés et nominations (employee-service.ts / appointment-service.ts)
// ---------------------------------------------------------------------------

export interface WorkforceEmployees {
  create(input: { name: string; displayName?: string; orgId: string; supervisorUserId: string; agentId: string; principalId?: string; runtime?: string }): EmployeeRecord
  get(id: string): EmployeeRecord
  list(filter?: { orgId?: string; status?: EmployeeStatus }): EmployeeRecord[]
  /** Suspension/reprise/départ : suspend·offboard entraînent révocabation des permits et libération des baux (via le port d'intégration exec-hub). */
  setStatus(caller: WorkCallerRef, id: string, status: EmployeeStatus, reason: string): EmployeeRecord
  /** Changement de liaison (l'ancienne active→inactive, la transaction garantit un seul active par Agent). */
  bindAgent(caller: WorkCallerRef, employeeId: string, agentId: string, principalId?: string, runtime?: string): BindingRecord
  bindingsFor(employeeId: string): BindingRecord[]
}

export interface WorkforceAppointments {
  create(input: {
    employeeId: string
    position: string
    orgId: string
    dataClass: WorkDataClass
    effectiveFrom: string
    effectiveUntil?: string
    grants: ResourceGrantSpec[]
    approvedBy: string
    approvalRef?: string
  }): AppointmentRecord
  /**
   * Activation (D.4) : sonde de vérification de l'autorisation réelle grant par grant ; tout passe → effective avec reconstitution du ref,
   * un seul échec → ce grant passe failed, la nomination reste preparing (aucun permit ne doit être émis).
   */
  activate(caller: WorkCallerRef, id: string): Promise<AppointmentRecord>
  /** Révocation : élève d'abord la version de politique de travail et révoque tous les permits, puis convergence asynchrone des passerelles de ressources (revoking→revoked). */
  revoke(caller: WorkCallerRef, id: string, reason: string): Promise<AppointmentRecord>
  get(id: string): AppointmentRecord
  list(filter?: { employeeId?: string; status?: AppointmentStatus }): AppointmentRecord[]
  effectiveForEmployee(employeeId: string): AppointmentRecord | undefined
}

// ---------------------------------------------------------------------------
// Outils fins d'exécution et points de permission REST (outils dans tools.ts, routes dans routes.ts)
// ---------------------------------------------------------------------------

export const WORKFORCE_TOOLS = ['workforce_claim', 'workforce_invoke', 'workforce_renew', 'workforce_submit'] as const

export const WORKFORCE_PERMISSIONS = {
  read: 'workforce.read',
  write: 'workforce.write',
  admin: 'workforce.admin',
  invoke: 'workforce.invoke',
  accept: 'workforce.accept',
} as const

/** Validité du stepKey (§9.3) : 1-96 caractères, lettres/chiffres/point/souligné/tiret. */
export const STEP_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/

/** Plafond de téléversement d'artefact (8 Mo par défaut ; répertoire staging contrôlé, anti-chemin arbitraire). */
export const ARTIFACT_MAX_BYTES = 8 * 1024 * 1024
