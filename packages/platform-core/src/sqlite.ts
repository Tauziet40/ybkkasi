/**
 * Stockage transactionnel : socle dédié aux données de mesure et de trésorerie (conception écosystème v1.2 étape 0, résolution S1).
 *
 * Répartition avec le stockage de collections JSON (storage.ts) :
 *   - storage  : données de configuration/ressources métier (l'écriture anti-rebond suffit)
 *   - txnStore : flux de mesure / flux de trésorerie / écritures de répartition — append-only, exigeant transactions et idempotence au niveau moteur
 *
 * Basé sur node:sqlite (intégré depuis Node ≥ 22.5, zéro dépendance). Mode WAL.
 * Les tables de trésorerie n'acceptent que INSERT (la couche service n'expose pas UPDATE/DELETE sur les tables de type journal).
 */
import { DatabaseSync } from 'node:sqlite'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'

export interface TxnStoreConfig {
  /** Répertoire de données (même répertoire que storage), défaut `<cwd>/data`. */
  dataDir?: string
}

export type SqlValue = string | number | null

export class SqliteTxnService extends Service {
  static readonly provide = 'txnStore'

  readonly db: DatabaseSync
  readonly file: string

  constructor(ctx: Context, config: TxnStoreConfig = {}) {
    super(ctx, 'txnStore')
    const dataDir = config.dataDir ?? join(process.cwd(), 'data')
    this.file = join(dataDir, 'txnstore.db')
    mkdirSync(dataDir, { recursive: true })
    this.db = new DatabaseSync(this.file)
    this.db.exec('PRAGMA journal_mode = WAL')
    this.db.exec('PRAGMA synchronous = FULL')
    this.db.exec('PRAGMA foreign_keys = ON')
    ctx.effect(() => () => {
      try {
        this.db.close()
      } catch {
        /* Fermé */
      }
    })
  }

  /** Crée les tables (idempotent). columns = « nom de colonne → définition de colonne (type et contraintes inclus) ». */
  ensureTable(name: string, columns: Record<string, string>, options: { primaryKey?: string[]; uniques?: string[][]; indexes?: string[][] } = {}): void {
    const pk = options.primaryKey ?? ['id']
    const cols = Object.entries(columns).map(([key, def]) => `${quoteIdent(key)} ${def}`)
    cols.push(`PRIMARY KEY (${pk.map(quoteIdent).join(', ')})`)
    this.db.exec(`CREATE TABLE IF NOT EXISTS ${quoteIdent(name)} (${cols.join(', ')})`)
    for (const unique of options.uniques ?? []) {
      this.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ${quoteIdent(`ux_${name}_${unique.join('_')}`)} ON ${quoteIdent(name)} (${unique.map(quoteIdent).join(', ')})`)
    }
    for (const index of options.indexes ?? []) {
      this.db.exec(`CREATE INDEX IF NOT EXISTS ${quoteIdent(`ix_${name}_${index.join('_')}`)} ON ${quoteIdent(name)} (${index.map(quoteIdent).join(', ')})`)
    }
  }

  /** Insertion (conflit de clé primaire/index unique ignoré silencieusement). Renvoie si l'insertion a réellement eu lieu. */
  insertOrIgnore(table: string, row: Record<string, SqlValue>): boolean {
    const keys = Object.keys(row)
    const result = this.db
      .prepare(`INSERT OR IGNORE INTO ${quoteIdent(table)} (${keys.map(quoteIdent).join(', ')}) VALUES (${keys.map(() => '?').join(', ')})`)
      .run(...keys.map((key) => row[key] ?? null))
    return Number(result.changes) > 0
  }

  /** Insertion (lève en cas de conflit). */
  insert(table: string, row: Record<string, SqlValue>): void {
    const keys = Object.keys(row)
    this.db
      .prepare(`INSERT INTO ${quoteIdent(table)} (${keys.map(quoteIdent).join(', ')}) VALUES (${keys.map(() => '?').join(', ')})`)
      .run(...keys.map((key) => row[key] ?? null))
  }

  /** Mise à jour par clé primaire (réservée aux tables non append-only ; interdit sur les tables de type journal). */
  updateByKey(table: string, primaryKey: string[], keyValues: SqlValue[], patch: Record<string, SqlValue>): void {
    const setSql = Object.keys(patch).map((key) => `${quoteIdent(key)} = ?`).join(', ')
    const whereSql = primaryKey.map((key) => `${quoteIdent(key)} = ?`).join(' AND ')
    this.db
      .prepare(`UPDATE ${quoteIdent(table)} SET ${setSql} WHERE ${whereSql}`)
      .run(...Object.values(patch), ...keyValues)
  }

  /** Requête de table entière (ou selon condition d'égalité). */
  all<T = Record<string, SqlValue>>(table: string, where: Record<string, SqlValue> = {}): T[] {
    const keys = Object.keys(where)
    if (keys.length === 0) return this.db.prepare(`SELECT * FROM ${quoteIdent(table)}`).all() as T[]
    const whereSql = keys.map((key) => `${quoteIdent(key)} = ?`).join(' AND ')
    return this.db.prepare(`SELECT * FROM ${quoteIdent(table)} WHERE ${whereSql}`).all(...keys.map((key) => where[key] ?? null)) as T[]
  }

  one<T = Record<string, SqlValue>>(table: string, where: Record<string, SqlValue>): T | undefined {
    const rows = this.all<T>(table, where)
    return rows[0]
  }

  count(table: string, where: Record<string, SqlValue> = {}): number {
    const keys = Object.keys(where)
    if (keys.length === 0) {
      return Number((this.db.prepare(`SELECT COUNT(*) AS n FROM ${quoteIdent(table)}`).get() as { n: number }).n)
    }
    const whereSql = keys.map((key) => `${quoteIdent(key)} = ?`).join(' AND ')
    const row = this.db.prepare(`SELECT COUNT(*) AS n FROM ${quoteIdent(table)} WHERE ${whereSql}`).get(...keys.map((key) => where[key] ?? null)) as { n: number }
    return Number(row.n)
  }

  /** SQL brut (création d'index, requêtes d'agrégation, etc.). */
  sql<T = Record<string, SqlValue>>(query: string, params: SqlValue[] = []): T[] {
    return this.db.prepare(query).all(...params) as T[]
  }

  /** Écriture SQL brute (UPDATE/DELETE), renvoie le nombre de lignes affectées. */
  run(query: string, params: SqlValue[] = []): number {
    return Number(this.db.prepare(query).run(...params).changes)
  }

  /**
   * Transaction : toutes les écritures de fn sont soit toutes validées, soit toutes annulées.
   * Exécution synchrone (node:sqlite), BEGIN IMMEDIATE prend immédiatement le verrou d'écriture, évite les interblocages de montée en gamme.
   */
  txn<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const result = fn()
      this.db.exec('COMMIT')
      return result
    } catch (error) {
      try {
        this.db.exec('ROLLBACK')
      } catch {
        /* en cas d'exception de connexion, l'échec de rollback n'est que journalisé */
      }
      throw error
    }
  }
}

function quoteIdent(name: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`非法标识符：${name}`)
  return `"${name}"`
}
