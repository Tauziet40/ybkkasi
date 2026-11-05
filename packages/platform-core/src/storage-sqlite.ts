/**
 * Backend de stockage : implémentation des collections SQLite (phase 1 de l'ADR-0001).
 *
 * Strictement le même contrat Collection<T> que les collections JSON (storage.ts CollectionImpl), invisible pour les plugins métier :
 *   - les documents sont stockés dans la table unique collection_docs (name, id, doc JSON) ; chaque écriture est validée dans une transaction autonome
 *     (WAL + synchronous=FULL — après kill -9 du processus, zéro perte des transactions déjà validées).
 *   - uniqueOn → collection_uniques (name, label, key, id), vraie clé unique :
 *     la course « chercher puis insérer » est rattrapée par la contrainte au niveau moteur, pas par un scan applicatif
 *     (point d'exécution de la ligne rouge iam:identityLinks « une personne, un compte », voir recette lot 2 de l'ADR-0001).
 *   - les listeners onChange se déclenchent de façon synchrone après validation de la transaction (sémantique de diffusion des révocations authn:tokens inchangée).
 *   - le chemin de lecture résout les documents à la demande, l'empreinte mémoire ne croît pas linéairement avec le nombre d'enregistrements.
 *
 * Remplissage (backfill) : à la restauration, si la collection n'a pas encore de meta et qu'un fichier JSON homonyme existe dans le répertoire de données,
 * import de la table entière une seule fois ; le fichier JSON est conservé sans suppression comme source de retour arrière (retour vers JSON via scripts/storage-export.mjs).
 * meta.backfilled_at à NULL signifie « import non achevé » — si le processus a crashé avant la transaction d'import, nouvelle tentative au prochain démarrage,
 * l'import et le marquage se font dans la même transaction, pas d'état « à moitié chargé » possible.
 */
import { DatabaseSync } from 'node:sqlite'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { t } from '../../platform-i18n/src/index.ts'
import type { Collection, CollectionChange, RecordBase } from './storage.ts'

export class SqliteCollectionBackend {
  readonly db: DatabaseSync
  readonly file: string
  private collections = new Map<string, SqliteCollectionImpl<RecordBase>>()

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true })
    this.file = join(dataDir, 'collections.db')
    this.db = new DatabaseSync(this.file)
    this.db.exec('PRAGMA journal_mode = WAL')
    this.db.exec('PRAGMA synchronous = FULL')
    this.db.exec(`CREATE TABLE IF NOT EXISTS collection_docs (
      name TEXT NOT NULL,
      id TEXT NOT NULL,
      doc TEXT NOT NULL,
      PRIMARY KEY (name, id)
    )`)
    this.db.exec(`CREATE TABLE IF NOT EXISTS collection_uniques (
      name TEXT NOT NULL,
      label TEXT NOT NULL,
      key TEXT NOT NULL,
      id TEXT NOT NULL,
      PRIMARY KEY (name, label, key)
    )`)
    this.db.exec(`CREATE TABLE IF NOT EXISTS collection_meta (
      name TEXT PRIMARY KEY,
      backfilled_at TEXT,
      created_at TEXT NOT NULL
    )`)
  }

  /** Transaction : validation atomique de toutes les écritures de fn (BEGIN IMMEDIATE prend immédiatement le verrou d'écriture, évite les interblocages de montée en gamme). */
  txn<R>(fn: () => R): R {
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

  collection<T extends RecordBase>(name: string): Collection<T> {
    const existing = this.collections.get(name)
    if (existing) return existing as unknown as Collection<T>
    const created = new SqliteCollectionImpl<T>(this, name)
    this.collections.set(name, created as unknown as SqliteCollectionImpl<RecordBase>)
    return created
  }

  /** Noms des collections enregistrées (table meta, remplies et nouvelles incluses). */
  names(): string[] {
    return (this.db.prepare('SELECT name FROM collection_meta ORDER BY name').all() as Array<{ name: string }>).map((row) => row.name)
  }

  metaOf(name: string): { backfilled_at: string | null } | undefined {
    return this.db.prepare('SELECT backfilled_at FROM collection_meta WHERE name = ?').get(name) as { backfilled_at: string | null } | undefined
  }

  markCreated(name: string): void {
    this.db.prepare('INSERT OR IGNORE INTO collection_meta (name, backfilled_at, created_at) VALUES (?, NULL, ?)').run(name, new Date().toISOString())
  }

  /**
   * Remplissage JSON → SQLite : import seulement si la collection est actuellement vide (idempotent, anti-doublon) ; l'achèvement de l'import et la marque
   * backfilled_at prennent effet atomiquement dans la même transaction. Une collection non vide (p. ex. fenêtre extrême où la transaction d'import est validée
   * mais la marque pas encore lue) reçoit elle aussi la marque, pour éviter de re-sonder le JSON au prochain démarrage.
   *
   * Réconciliation du remplissage (lacune ② de l'ADR-0001) : le callback verify est inséré après l'import et avant la marque backfilled_at —
   * un échec de réconciliation du nombre d'entrées ou du hash des champs clés lève et annule toute la transaction (import et marque retirés ensemble, meta retournée à
   * NULL), le prochain démarrage réessaie et échoue de nouveau bruyamment ; jamais de « marque défectueuse + incohérence silencieuse ».
   */
  backfill(name: string, records: RecordBase[], verify?: (rows: Array<{ id: string; doc: string }>) => void): void {
    this.txn(() => {
      const count = Number((this.db.prepare('SELECT COUNT(*) AS n FROM collection_docs WHERE name = ?').get(name) as { n: number }).n)
      if (count === 0) {
        const ins = this.db.prepare('INSERT INTO collection_docs (name, id, doc) VALUES (?, ?, ?)')
        for (const record of records) ins.run(name, record.id, JSON.stringify(record))
      }
      // La réconciliation lit des données non validées de la même transaction : en cas d'échec → ROLLBACK, la sémantique de sécurité sur crash reste inchangée
      if (verify) verify(this.db.prepare('SELECT id, doc FROM collection_docs WHERE name = ? ORDER BY id').all(name) as Array<{ id: string; doc: string }>)
      this.db.prepare('UPDATE collection_meta SET backfilled_at = ? WHERE name = ?').run(new Date().toISOString(), name)
    })
  }

  close(): void {
    try {
      this.db.close()
    } catch {
      /* Fermé */
    }
  }
}

export class SqliteCollectionImpl<T extends RecordBase> implements Collection<T> {
  private uniques: Array<{ label: string; keyOf: (record: T) => string }> = []
  private listeners = new Set<(change: CollectionChange<T>) => void>()
  private readonly backend: SqliteCollectionBackend

  readonly name: string

  constructor(backend: SqliteCollectionBackend, name: string) {
    this.backend = backend
    this.name = name
    this.backend.markCreated(name)
  }

  private get db(): DatabaseSync {
    return this.backend.db
  }

  private txn<R>(fn: () => R): R {
    return this.backend.txn(fn)
  }

  uniqueOn(label: string, keyOf: (record: T) => string): void {
    if (this.uniques.some((unique) => unique.label === label)) return
    this.uniques.push({ label, keyOf })
    // L'enregistrement s'applique aussi aux données existantes : reconstruction complète des clés de ce label, garantissant la cohérence de la table de clés avec l'implémentation keyOf courante.
    // Les collections contraintes sont toutes de petites collections de gouvernance (utilisateurs/organisations/liens d'identité…) : reconstruction en millisecondes.
    const rows = this.db.prepare('SELECT id, doc FROM collection_docs WHERE name = ?').all(this.name) as Array<{ id: string; doc: string }>
    this.txn(() => {
      this.db.prepare('DELETE FROM collection_uniques WHERE name = ? AND label = ?').run(this.name, label)
      const ins = this.db.prepare('INSERT OR IGNORE INTO collection_uniques (name, label, key, id) VALUES (?, ?, ?, ?)')
      for (const row of rows) {
        const key = keyOf(JSON.parse(row.doc) as T)
        if (key) ins.run(this.name, label, key, row.id)
      }
    })
  }

  /** Exécution de la contrainte d'unicité (niveau moteur) : à l'update, retire d'abord sa propre ancienne clé puis occupe la nouvelle, tout conflit lève (rollback de transaction). */
  private enforceUniques(record: T, selfId?: string): void {
    for (const unique of this.uniques) {
      const key = unique.keyOf(record)
      if (!key) continue
      if (selfId !== undefined) {
        this.db.prepare('DELETE FROM collection_uniques WHERE name = ? AND label = ? AND id = ?').run(this.name, unique.label, selfId)
      }
      try {
        this.db.prepare('INSERT INTO collection_uniques (name, label, key, id) VALUES (?, ?, ?, ?)').run(this.name, unique.label, key, record.id)
      } catch {
        const other = this.db.prepare('SELECT id FROM collection_uniques WHERE name = ? AND label = ? AND key = ?').get(this.name, unique.label, key) as { id: string } | undefined
        throw new Error(t('[storage] 唯一约束冲突（{label}）：与既有记录 {id} 重复', { label: unique.label, id: other?.id ?? '?' }))
      }
    }
  }

  all(): T[] {
    const rows = this.db.prepare('SELECT doc FROM collection_docs WHERE name = ? ORDER BY rowid').all(this.name) as Array<{ doc: string }>
    return rows.map((row) => JSON.parse(row.doc) as T)
  }

  get(id: string): T | undefined {
    const row = this.db.prepare('SELECT doc FROM collection_docs WHERE name = ? AND id = ?').get(this.name, id) as { doc: string } | undefined
    return row ? JSON.parse(row.doc) as T : undefined
  }

  find(pred: (record: T) => boolean): T[] {
    return this.all().filter(pred)
  }

  findOne(pred: (record: T) => boolean): T | undefined {
    for (const record of this.all()) {
      if (pred(record)) return record
    }
    return undefined
  }

  insert(data: Omit<T, 'createdAt' | 'updatedAt'> & { createdAt?: string; updatedAt?: string }): T {
    const now = new Date().toISOString()
    const record = { createdAt: now, updatedAt: now, ...data, updatedAt: now } as T
    this.txn(() => {
      const exists = this.db.prepare('SELECT 1 FROM collection_docs WHERE name = ? AND id = ?').get(this.name, record.id)
      if (exists) throw new Error(t('[storage] 集合 {name} 中已存在 id={id}', { name: this.name, id: record.id }))
      this.enforceUniques(record)
      this.db.prepare('INSERT INTO collection_docs (name, id, doc) VALUES (?, ?, ?)').run(this.name, record.id, JSON.stringify(record))
    })
    this.emit({ kind: 'insert', record })
    return structuredClone(record)
  }

  update(id: string, patch: Partial<T>): T {
    const current = this.get(id)
    if (!current) throw new Error(t('[storage] 集合 {name} 中不存在 id={id}', { name: this.name, id }))
    const next = { ...current, ...patch, id: current.id, createdAt: current.createdAt, updatedAt: new Date().toISOString() } as T
    this.txn(() => {
      this.enforceUniques(next, id)
      this.db.prepare('UPDATE collection_docs SET doc = ? WHERE name = ? AND id = ?').run(JSON.stringify(next), this.name, id)
    })
    this.emit({ kind: 'update', record: next })
    return structuredClone(next)
  }

  remove(id: string): boolean {
    let existed = false
    this.txn(() => {
      const info = this.db.prepare('DELETE FROM collection_docs WHERE name = ? AND id = ?').run(this.name, id)
      existed = Number(info.changes) > 0
      if (existed) this.db.prepare('DELETE FROM collection_uniques WHERE name = ? AND id = ?').run(this.name, id)
    })
    if (existed) this.emit({ kind: 'remove', record: { id } as T })
    return existed
  }

  replaceAll(records: T[]): void {
    this.txn(() => {
      this.db.prepare('DELETE FROM collection_docs WHERE name = ?').run(this.name)
      this.db.prepare('DELETE FROM collection_uniques WHERE name = ?').run(this.name)
      const ins = this.db.prepare('INSERT INTO collection_docs (name, id, doc) VALUES (?, ?, ?)')
      const insKey = this.db.prepare('INSERT OR IGNORE INTO collection_uniques (name, label, key, id) VALUES (?, ?, ?, ?)')
      for (const record of records) {
        ins.run(this.name, record.id, JSON.stringify(record))
        // Aligné sur la version JSON : replaceAll ne fait pas de validation d'unicité (écriture de clé tolérante, OR IGNORE)
        for (const unique of this.uniques) {
          const key = unique.keyOf(record)
          if (key) insKey.run(this.name, unique.label, key, record.id)
        }
      }
    })
    this.emit({ kind: 'replace', record: {} as T })
  }

  count(): number {
    return Number((this.db.prepare('SELECT COUNT(*) AS n FROM collection_docs WHERE name = ?').get(this.name) as { n: number }).n)
  }

  onChange(cb: (change: CollectionChange<T>) => void): () => void {
    this.listeners.add(cb)
    return () => this.listeners.delete(cb)
  }

  private emit(change: CollectionChange<T>): void {
    for (const cb of this.listeners) {
      try {
        cb(change)
      } catch (error) {
        console.error(`[storage] ${this.name} 变更监听器异常`, error)
      }
    }
  }
}
