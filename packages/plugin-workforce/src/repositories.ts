/**
 * Stockage de référence du domaine de l'employé numérique (repositories) — toutes les tables workforce_* en SQLite txnStore (annexe A décision 7).
 *
 * Frontières de responsabilité (§11.6) :
 *   - ce service ne fait que « migration de structures de tables + CRUD de lignes + délégation de transaction », sans aucune politique métier (politiques dans domain.ts / les services) ;
 *   - les transactions sont des transactions synchrones BEGIN IMMEDIATE (node:sqlite) : tout appel réseau/asynchrone y est strictement interdit ;
 *     la validation d'unicité de domaine de tous les chemins d'écriture (ex. employee+version, run+stepKey) est précontrôlée par chaque service dans store.txn,
 *     l'index unique SQLite sert de rattrapage (un conflit d'insert lève directement, la couche service traduit en erreur de domaine en chinois) ;
 *   - l'unique source de fait des structures de tables est WORKFORCE_TABLES de contract.ts, ce fichier ne redéclare pas les colonnes.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import type { SqlValue, SqliteTxnService } from '../../platform-core/src/sqlite.ts'
import { t } from '../../platform-i18n/src/index.ts'
import { WORKFORCE_TABLES } from './contract.ts'
import type {
  AppointmentRecord,
  ArtifactRecord,
  BindingRecord,
  DeliverableRecord,
  EmployeeRecord,
  InvocationRecord,
  ManifestRecord,
  OutboxRecord,
  PermitRecord,
  ResourceGrantRecord,
  TableStore,
  UsageLinkRecord,
  WorkforceStore,
  WorkforceTableSpec,
} from './contract.ts'

/** Clé d'interface du contrat → nom de table (clé de référence de WORKFORCE_TABLES). */
const TABLE_NAMES = {
  employees: 'workforce_employees',
  bindings: 'workforce_bindings',
  appointments: 'workforce_appointments',
  grants: 'workforce_resource_grants',
  manifests: 'workforce_manifests',
  permits: 'workforce_permits',
  invocations: 'workforce_invocations',
  usageLinks: 'workforce_usage_links',
  artifacts: 'workforce_artifacts',
  deliverables: 'workforce_deliverables',
  outbox: 'workforce_outbox',
} as const

type Row = Record<string, SqlValue>

/**
 * Implémentation générique de TableStore fondée sur txnStore.
 *
 * Référentiel jsonFields (contrat WorkforceTableSpec.jsonFields) :
 *   - les champs marqués sont sérialisés en JSON à l'écriture et désérialisés à la lecture ; une valeur déjà chaîne est stockée telle quelle comme « texte déjà sérialisé » ;
 *   - actuellement, les charges utiles JSON des tables de WORKFORCE_TABLES (grantsJson/actionsJson/toolsJson/argsSummaryJson etc.)
 *     sont portées par des colonnes TEXT en *Json et les types d'enregistrement les déclarent string, donc les jsonFields de chaque table sont vides pour l'instant —
 *     le mécanisme est réservé aux futurs champs d'extension additive, sans modifier la sémantique des colonnes existantes (§11.3 additive-only) ;
 *   - findWhere confronte les jsonFields par égalité du texte stocké (pas de correspondance structurée) : le demandeur doit passer le texte
 *     sérialisé identique au stockage ; les champs non marqués sont confrontés par égalité de la valeur d'origine.
 */
class TxnTableStore<T extends { id: string }> implements TableStore<T> {
  private readonly svc: SqliteTxnService
  private readonly spec: WorkforceTableSpec

  constructor(svc: SqliteTxnService, spec: WorkforceTableSpec) {
    this.svc = svc
    this.spec = spec
  }

  /** Encodage à l'écriture : jsonFields sérialisés, le reste en valeur d'origine (undefined ramené à null). */
  private encodeField(field: string, value: unknown): SqlValue {
    if ((this.spec.jsonFields ?? []).includes(field)) {
      if (typeof value === 'string') return value
      return JSON.stringify(value ?? null)
    }
    return (value === undefined ? null : value) as SqlValue
  }

  private encodeRow(record: Record<string, unknown>): Row {
    const row: Row = {}
    for (const [key, value] of Object.entries(record)) row[key] = this.encodeField(key, value)
    return row
  }

  /** Décodage à la lecture : jsonFields désérialisés ; un mauvais JSON est conservé comme texte brut (rendu honnête, pas de réparation silencieuse). */
  private decodeRow(row: Row): T {
    const jsonFields = this.spec.jsonFields ?? []
    if (jsonFields.length === 0) return row as T
    const out: Record<string, unknown> = { ...row }
    for (const field of jsonFields) {
      const raw = out[field]
      if (typeof raw !== 'string') continue
      try {
        out[field] = JSON.parse(raw)
      } catch {
        /* texte historique non JSON valide : conservé tel quel, erreur explicite remontée par la couche supérieure */
      }
    }
    return out as T
  }

  insert(row: T): void {
    // Un conflit d'index unique/clé primaire lève directement ici ; la couche service doit précontrôler dans la txn et traduire en erreur de domaine en chinois
    this.svc.insert(this.spec.name, this.encodeRow(row as unknown as Record<string, unknown>))
  }

  get(id: string): T | undefined {
    const row = this.svc.one<Row>(this.spec.name, { id })
    return row ? this.decodeRow(row) : undefined
  }

  all(): T[] {
    return this.svc.all<Row>(this.spec.name).map((row) => this.decodeRow(row))
  }

  findWhere(where: Record<string, SqlValue>): T[] {
    const encoded: Row = {}
    for (const [key, value] of Object.entries(where)) encoded[key] = this.encodeField(key, value)
    return this.svc.all<Row>(this.spec.name, encoded).map((row) => this.decodeRow(row))
  }

  update(id: string, patch: Partial<T>): void {
    const encoded = this.encodeRow(patch as Record<string, unknown>)
    if (Object.keys(encoded).length === 0) return
    this.svc.updateByKey(this.spec.name, ['id'], [id], encoded)
  }

  delete(id: string): void {
    // Les noms de tables viennent du contrat figé (ensureTable a déjà validé par liste blanche d'identifiants), simple concaténation de constantes ici
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(this.spec.name)) throw new Error(t('非法表名：{name}', { name: this.spec.name }))
    this.svc.run(`DELETE FROM ${this.spec.name} WHERE id = ?`, [id])
  }

  count(): number {
    return this.svc.count(this.spec.name)
  }
}

export interface WorkforceStoreConfig {
  /** Réservé : alignement avec WorkforceConfig.dataDir (la base txnStore est déjà créée par platform-core selon dataDir). */
  dataDir?: string
}

/**
 * WorkforceStoreService（provide 'workforceStore'）。
 *
 * Convention de validation d'unicité de domaine (discipline du chemin d'écriture) : ce service n'embarque pas de règles métier ; la couche service doit, dans store.txn,
 * chercher avant d'écrire pour valider l'unicité de domaine et lever une erreur en chinois, par exemple :
 *   - conflit employee+version → `throw new Error('该员工已存在同名任用版本…')` (400 par la couche routes) ;
 *   - run+stepKey avec paramètres différents heurtant la contrainte unique → WorkforceError('STEP_ARGUMENT_CONFLICT') (étapes d'appel uniquement) ;
 *   - seconde liaison active du même Agent → WorkforceError('PRINCIPAL_BINDING_MISMATCH').
 */
export class WorkforceStoreService extends Service implements WorkforceStore {
  static readonly provide = 'workforceStore'

  private readonly svc: SqliteTxnService

  readonly employees: TableStore<EmployeeRecord>
  readonly bindings: TableStore<BindingRecord>
  readonly appointments: TableStore<AppointmentRecord>
  readonly grants: TableStore<ResourceGrantRecord>
  readonly manifests: TableStore<ManifestRecord>
  readonly permits: TableStore<PermitRecord>
  readonly invocations: TableStore<InvocationRecord>
  readonly usageLinks: TableStore<UsageLinkRecord>
  readonly artifacts: TableStore<ArtifactRecord>
  readonly deliverables: TableStore<DeliverableRecord>
  readonly outbox: TableStore<OutboxRecord>

  constructor(ctx: Context, config: WorkforceStoreConfig = {}) {
    super(ctx, 'workforceStore')
    void config // la base txnStore est créée par platform-core avec le même dataDir ; simple alignement de la forme de configuration ici
    // txnStore appartient à la couche de base (platform-core), déclaré dans la liste de dépendances de cette extension ; lecture structurée pour éviter le couplage d'ordre d'assemblage
    this.svc = (ctx as unknown as { txnStore: SqliteTxnService }).txnStore
    this.employees = new TxnTableStore<EmployeeRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.employees])
    this.bindings = new TxnTableStore<BindingRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.bindings])
    this.appointments = new TxnTableStore<AppointmentRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.appointments])
    this.grants = new TxnTableStore<ResourceGrantRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.grants])
    this.manifests = new TxnTableStore<ManifestRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.manifests])
    this.permits = new TxnTableStore<PermitRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.permits])
    this.invocations = new TxnTableStore<InvocationRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.invocations])
    this.usageLinks = new TxnTableStore<UsageLinkRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.usageLinks])
    this.artifacts = new TxnTableStore<ArtifactRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.artifacts])
    this.deliverables = new TxnTableStore<DeliverableRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.deliverables])
    this.outbox = new TxnTableStore<OutboxRecord>(this.svc, WORKFORCE_TABLES[TABLE_NAMES.outbox])
    // Migration dès l'assemblage (création de tables idempotente) : les services suivants peuvent lire/écrire directement, sans appeler migrate explicitement
    this.migrate()
  }

  /** Migration : parcourt WORKFORCE_TABLES pour créer toutes les tables/index uniques/index ordinaires (idempotent ; DDL inclus dans la même transaction). */
  migrate(): void {
    this.txn(() => {
      for (const spec of Object.values(WORKFORCE_TABLES)) {
        this.svc.ensureTable(spec.name, spec.columns, { uniques: spec.uniques, indexes: spec.indexes })
      }
    })
  }

  /** Transaction synchrone BEGIN IMMEDIATE (enveloppe txnStore) : pour courts contrôles/réservations/validations ; tout appel réseau y est strictement interdit. */
  txn<T>(fn: () => T): T {
    return this.svc.txn(fn)
  }
}
