/**
 * Abstraction de stockage : les plugins métier ne voient que l'API Collection, sans connaître le stockage physique.
 *
 * Deux backends (ADR-0001, bascule PLATFORM_STORAGE, json par défaut pour compatibilité ascendante) :
 *   - json   : collections JSON + index en mémoire + écriture atomique anti-rebond (CollectionImpl, implémentation d'origine) ;
 *   - sqlite : collections entièrement hébergées dans SQLite (SqliteCollectionImpl, storage-sqlite.ts) —
 *             écriture = transaction, uniqueOn → index unique au niveau moteur, résident en mémoire sans croître avec le nombre d'enregistrements.
 * Les deux backends respectent strictement le même contrat Collection<T>, zéro modification du code des plugins.
 */
import { copyFile, mkdir, readdir, readFile, rename, open } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { t } from '../../platform-i18n/src/index.ts'
import { SqliteCollectionBackend, SqliteCollectionImpl } from './storage-sqlite.ts'

export interface RecordBase {
  id: string
  createdAt: string
  updatedAt: string
}

export type ChangeKind = 'insert' | 'update' | 'remove' | 'replace'

export interface CollectionChange<T> {
  kind: ChangeKind
  record: T
}

export interface Collection<T extends RecordBase> {
  readonly name: string
  all(): T[]
  get(id: string): T | undefined
  find(pred: (record: T) => boolean): T[]
  findOne(pred: (record: T) => boolean): T | undefined
  insert(data: Omit<T, 'createdAt' | 'updatedAt'> & { createdAt?: string; updatedAt?: string }): T
  update(id: string, patch: Partial<T>): T
  remove(id: string): boolean
  replaceAll(records: T[]): void
  count(): number
  onChange(cb: (change: CollectionChange<T>) => void): () => void
  /**
   * Déclare une contrainte d'unicité métier (simule un index partiellement unique de base de données).
   * Tout insert/update violant ensuite la contrainte lève directement — le « chercher puis insérer » est remplacé par un filet au niveau moteur,
   * les doublons ne peuvent plus apparaître même en concurrence et conditions de course (ligne rouge issue de la conception du module auth-identity).
   */
  uniqueOn(label: string, keyOf: (record: T) => string): void
}

/**
 * Liste d'exemptions JSON par défaut du backend sqlite (ADR-0001 §5 lot 3 « collections de configuration à basse fréquence », cherchable sous le même nom que l'ADR).
 *
 * Fondement de la liste (noms de collections réels vérifiés par grep de tous les points d'enregistrement opsStorage.collection ; dans le code, les noms utilisent `:`,
 * les noms de fichiers de données sont échappés en `~` par fileNameOf) :
 *   - resource:dependencies · update:state · platform:bootstrap — configuration à basse fréquence ;
 *   - market:* (joker de préfixe) — market:developers / market:installs / market:submissions ;
 *   - collections migrations / snapshot de chaque plugin : agent:migrations · app:migrations · iam:migrations
 *     · iam:groupSnapshots (marques d'évolution de données écrites une fois, aucun gain à les passer en DB) ;
 *   - oidc-keys — fichier de clés de signature OIDC au niveau plateforme (plugin-authn lit directement oidc-keys.json sous dataDir,
 *     ce n'est pas une collection ; le scan par nom de fichier de restoreAll la toucherait, son inscription dans la liste la laisse sur le chemin JSON et elle est sautée comme fichier plateforme,
 *     sans laisser de fausse collection dans les meta sqlite).
 *
 * Sémantique : la liste s'applique quand PLATFORM_STORAGE_JSON_KEEP **n'est pas défini** ; s'il est défini explicitement, il remplace intégralement le défaut
 * (y compris « chaîne vide explicite = aucune exemption », voir parseKeepEnv).
 */
export const DEFAULT_JSON_KEEP: readonly string[] = [
  'resource:dependencies',
  'update:state',
  'oidc-keys',
  'market:*',
  'platform:bootstrap',
  'agent:migrations',
  'app:migrations',
  'iam:migrations',
  'mcp:migrations',
  'iam:groupSnapshots',
]

export interface CollectionOptions {
  /**
   * Mode de persistance :
   *   - debounced (défaut) : fusion anti-rebond de 250 ms avant écriture ;
   *   - durable : écriture immédiate + fsync à chaque changement (collections comme les révocations d'authentification, qui ne tolèrent aucune perte sur crash).
   */
  durability?: 'debounced' | 'durable'
}

export type StorageBackendKind = 'json' | 'sqlite'

export interface StorageConfig {
  /** Répertoire de données, défaut `<cwd>/data`. */
  dataDir?: string
  /**
   * Backend de stockage des collections (json par défaut, compatibilité ascendante) :
   *   - json   : écriture dans des fichiers JSON (deux modes : anti-rebond/durable) ;
   *   - sqlite : data/collections.db, WAL + synchronous=FULL, écriture = transaction,
   *             au premier démarrage, remplissage automatique depuis les fichiers de collections JSON homonymes (fichiers conservés comme source de retour arrière).
   * Sans configuration explicite, lit la variable d'environnement PLATFORM_STORAGE (valable pour l'hôte autonome comme pour l'hôte dsh).
   */
  backend?: StorageBackendKind
}

class CollectionImpl<T extends RecordBase> implements Collection<T> {
  private records = new Map<string, T>()
  private listeners = new Set<(change: CollectionChange<T>) => void>()
  private uniques: Array<{ label: string; keyOf: (record: T) => string }> = []

  readonly name: string
  private readonly persist: (name: string) => void

  constructor(name: string, persist: (name: string) => void) {
    this.name = name
    this.persist = persist
  }

  uniqueOn(label: string, keyOf: (record: T) => string): void {
    if (this.uniques.some((unique) => unique.label === label)) return
    this.uniques.push({ label, keyOf })
  }

  /** Vérifie la contrainte d'unicité : renvoie l'enregistrement conflictuel existant (hors soi-même). */
  private conflictOf(record: T, selfId?: string): { label: string; existing: T } | undefined {
    for (const unique of this.uniques) {
      const key = unique.keyOf(record)
      if (key === '' || key === undefined) continue
      for (const other of this.records.values()) {
        if (selfId !== undefined && other.id === selfId) continue
        if (unique.keyOf(other) === key) return { label: unique.label, existing: other }
      }
    }
    return undefined
  }

  all(): T[] {
    return [...this.records.values()]
  }

  get(id: string): T | undefined {
    return this.records.get(id)
  }

  find(pred: (record: T) => boolean): T[] {
    return this.all().filter(pred)
  }

  findOne(pred: (record: T) => boolean): T | undefined {
    for (const record of this.records.values()) {
      if (pred(record)) return record
    }
    return undefined
  }

  insert(data: Omit<T, 'createdAt' | 'updatedAt'> & { createdAt?: string; updatedAt?: string }): T {
    const now = new Date().toISOString()
    const record = { createdAt: now, updatedAt: now, ...data, updatedAt: now } as T
    if (this.records.has(record.id)) throw new Error(t('[storage] 集合 {name} 中已存在 id={id}', { name: this.name, id: record.id }))
    const conflict = this.conflictOf(record)
    if (conflict) throw new Error(t('[storage] 唯一约束冲突（{label}）：与既有记录 {id} 重复', { label: conflict.label, id: conflict.existing.id }))
    this.records.set(record.id, record)
    this.emit({ kind: 'insert', record })
    this.persist(this.name)
    return structuredClone(record)
  }

  update(id: string, patch: Partial<T>): T {
    const current = this.records.get(id)
    if (!current) throw new Error(t('[storage] 集合 {name} 中不存在 id={id}', { name: this.name, id }))
    const next = { ...current, ...patch, id: current.id, createdAt: current.createdAt, updatedAt: new Date().toISOString() } as T
    const conflict = this.conflictOf(next, id)
    if (conflict) throw new Error(t('[storage] 唯一约束冲突（{label}）：与既有记录 {id} 重复', { label: conflict.label, id: conflict.existing.id }))
    this.records.set(id, next)
    this.emit({ kind: 'update', record: next })
    this.persist(this.name)
    return structuredClone(next)
  }

  remove(id: string): boolean {
    const existed = this.records.delete(id)
    if (existed) {
      this.emit({ kind: 'remove', record: { id } as T })
      this.persist(this.name)
    }
    return existed
  }

  replaceAll(records: T[]): void {
    this.records.clear()
    for (const record of records) this.records.set(record.id, record)
    this.persist(this.name)
    this.emit({ kind: 'replace', record: {} as T })
  }

  /** Restaure les données du disque (appelé uniquement au démarrage). */
  loadFrom(records: T[]): void {
    this.records.clear()
    for (const record of records) this.records.set(record.id, record)
  }

  count(): number {
    return this.records.size
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

export class StorageService extends Service {
  static readonly provide = 'opsStorage'

  private collections = new Map<string, Collection<RecordBase>>()
  private durableNames = new Set<string>()
  /** Noms des collections portées par le backend sqlite (les collections de la liste d'exemptions JSON n'y figurent pas). */
  private sqliteNames = new Set<string>()
  private sqliteBackend?: SqliteCollectionBackend
  private readonly jsonKeep: string[]
  /** La liste d'exemptions JSON vient-elle d'une variable d'environnement explicite (la liste par défaut ne déclenche pas l'alerte « inefficace sous backend json »). */
  private readonly jsonKeepExplicit: boolean
  private dirty = new Set<string>()
  private flushTimer: ReturnType<typeof setTimeout> | undefined
  /** Chaîne de sérialisation des écritures (les flushNow concurrents se mettent en file, évite la compétition sur le tmp homonyme). */
  private flushChain: Promise<void> = Promise.resolve()
  private tmpSeq = 0
  /** Fichiers corrompus découverts pendant la restauration (le JSON abîmé est sauvegardé en *.corrupt, trace dans le log de démarrage). */
  readonly corruptFiles: string[] = []
  /** Répertoire de données (emplacement des fichiers plateforme comme les clés). */
  readonly dataDirPath: string
  /** Backend de stockage des collections (config.backend ?? variable d'environnement PLATFORM_STORAGE, json par défaut). */
  readonly backend: StorageBackendKind

  constructor(ctx: Context, config: StorageConfig = {}) {
    super(ctx, 'opsStorage')
    this.dataDirPath = config.dataDir ?? join(process.cwd(), "data")
    this.backend = config.backend ?? parseBackendEnv(process.env.PLATFORM_STORAGE)
    // Liste d'exemptions : variable non définie → liste par défaut intégrée (ADR-0001 §5 lot 3) ;
    // définie explicitement → remplace intégralement le défaut (parseKeepEnv('') renvoie [], soit « aucune exemption »).
    const keepEnv = process.env.PLATFORM_STORAGE_JSON_KEEP
    this.jsonKeep = keepEnv === undefined ? [...DEFAULT_JSON_KEEP] : parseKeepEnv(keepEnv)
    this.jsonKeepExplicit = keepEnv !== undefined
    if (this.jsonKeepExplicit && this.jsonKeep.length > 0 && this.backend !== 'sqlite') {
      console.warn('[storage] PLATFORM_STORAGE_JSON_KEEP 仅在 PLATFORM_STORAGE=sqlite 下生效，当前忽略')
    }
    ctx.effect(() => () => {
      if (this.flushTimer) clearTimeout(this.flushTimer)
      void this.flushNow()
      this.sqliteBackend?.close()
    })
    this.installSignalFlush()
  }

  /**
   * Crochet d'écriture sur signal (sécurité des données forme B) : le main.ts de la forme A embarque SIGTERM/SIGINT → flushNow,
   * mais une fois monté dans l'hôte dsh (assemblage loader), il n'y a pas de crochet équivalent — les écritures de la fenêtre d'anti-rebond sont perdues si le processus est
   * tué par SIGTERM (launchd kickstart / pkill) ; de plus, la désynchronisation de SQLite (écriture immédiate) et des collections JSON (écriture anti-rebond)
   * produit un état de démarrage « à moitié chargé ». La couche de base s'installe elle-même une fois (effectif sur toutes les formes) ;
   * la double inscription est inoffensive (les handlers du main.ts forme A coexistent : flushChain en série + exit idempotent).
   */
  private installSignalFlush(): void {
    const proc = process as unknown as NodeJS.Process & Record<string, unknown>
    for (const signal of ['SIGTERM', 'SIGINT'] as const) {
      const guard = `__rqStorageFlushInstalled_${signal}`
      if (proc[guard] === true) continue
      proc[guard] = true
      process.on(signal, () => {
        void this.flushNow().finally(() => process.exit(0))
      })
    }
  }

  async start(): Promise<void> {
    await mkdir(this.dataDirPath, { recursive: true })
  }

  /** Cette collection est-elle portée par le backend sqlite (sous backend sqlite, les collections de la liste d'exemptions JSON restent en JSON). */
  private usesSqlite(name: string): boolean {
    if (this.backend !== 'sqlite') return false
    return !this.jsonKeep.some((pattern) =>
      pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern,
    )
  }

  private ensureSqliteBackend(): SqliteCollectionBackend {
    if (!this.sqliteBackend) this.sqliteBackend = new SqliteCollectionBackend(this.dataDirPath)
    return this.sqliteBackend
  }

  collection<T extends RecordBase>(name: string, options: CollectionOptions = {}): Collection<T> {
    if (options.durability === 'durable') this.durableNames.add(name)
    const existing = this.collections.get(name)
    if (existing) return existing as unknown as Collection<T>
    if (this.usesSqlite(name)) {
      this.sqliteNames.add(name)
      const created = this.ensureSqliteBackend().collection<T>(name)
      this.collections.set(name, created as unknown as Collection<RecordBase>)
      return created
    }
    const created = new CollectionImpl<T>(name, (n) => this.onPersist(n))
    this.collections.set(name, created as unknown as Collection<RecordBase>)
    return created
  }

  private onPersist(name: string): void {
    if (this.durableNames.has(name)) {
      // Collections critiques : écriture immédiate en sautant la fenêtre d'anti-rebond (revue série S : un crash après la réponse 200 de révocation ne doit rien perdre)
      this.dirty.add(name)
      void this.flushNow()
      return
    }
    this.markDirty(name)
  }

  /** Restaure au démarrage une collection donnée depuis le disque (idempotent). Le JSON corrompu est sauvegardé en *.corrupt puis on repart d'une collection vide (plus de vidage silencieux). */
  async restore<T extends RecordBase>(name: string): Promise<Collection<T>> {
    await mkdir(this.dataDirPath, { recursive: true })
    if (this.usesSqlite(name)) return this.restoreSqlite<T>(name)
    const collection = this.collection<T>(name)
    const file = join(this.dataDirPath, `${fileNameOf(name)}.json`)
    let records: T[] = []
    try {
      const raw = await readFile(file, 'utf8')
      const parsed: unknown = JSON.parse(raw)
      if (!Array.isArray(parsed)) {
        // Les fichiers plateforme (comme l'objet de clés oidc-keys.json) ne sont pas des collections : saut silencieux, pas compté comme corruption
        records = []
      } else {
        records = parsed as T[]
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code === 'ENOENT') {
        records = []
      } else {
        // Fichier présent mais corrompu : préserve la scène (sauvegarde *.corrupt), alerte explicite, jamais traité en collection vide sans trace
        await this.backupCorrupt(name, file, error)
        records = []
      }
    }
    ;(collection as unknown as CollectionImpl<T>).loadFrom(records)
    return collection
  }

  /**
   * Restauration du backend sqlite : la DB fait foi ; au premier démarrage, remplissage automatique depuis les fichiers de collections JSON homonymes (fichiers conservés comme source de retour arrière).
   * meta.backfilled_at=NULL signifie que l'import n'est pas terminé (le démarrage précédent a crashé avant la validation de la transaction d'import) — on réessaie l'import,
   * l'import et le marquage prennent effet atomiquement dans la même transaction de storage-sqlite, pas d'état « à moitié chargé » possible.
   * Après remplissage dans la transaction d'import, réconciliation préalable (nombre d'entrées + hash des champs clés, assertBackfillParity) :
   * toute divergence lève et annule l'ensemble ; la marque ne portera jamais sur des données abîmées.
   */
  private async restoreSqlite<T extends RecordBase>(name: string): Promise<Collection<T>> {
    const backend = this.ensureSqliteBackend()
    const collection = this.collection<T>(name)
    if (!backend.metaOf(name)) backend.markCreated(name)
    if (backend.metaOf(name)?.backfilled_at !== null) return collection
    const file = join(this.dataDirPath, `${fileNameOf(name)}.json`)
    let records: T[] = []
    try {
      const parsed: unknown = JSON.parse(await readFile(file, 'utf8'))
      if (Array.isArray(parsed)) records = parsed as T[]
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code !== 'ENOENT') await this.backupCorrupt(name, file, error)
    }
    backend.backfill(name, records, (rows) => assertBackfillParity(name, records, rows))
    if (records.length > 0) {
      console.log(`[storage] 集合 ${name} 已回填 ${records.length} 条至 SQLite（${file} 保留为回滚源）`)
    }
    return collection
  }

  /** Trace des JSON corrompus : sauvegarde en *.corrupt-<ts>, inscription dans corruptFiles, alerte explicite (sans bloquer le démarrage). */
  private async backupCorrupt(name: string, file: string, error: unknown): Promise<void> {
    const backup = `${file}.corrupt-${Date.now()}`
    try {
      await copyFile(file, backup)
    } catch { /* l'échec de sauvegarde ne bloque pas le démarrage, le log d'erreur suit plus bas */
    }
    console.error(`[storage] 集合 ${name} 文件损坏（${error instanceof Error ? error.message : String(error)}），已备份至 ${backup}，从空集合恢复`)
    this.corruptFiles.push(backup)
  }

  /** Scanne le répertoire de données et restaure toutes les collections (appelé une fois avant le chargement des plugins métier). */
  async restoreAll(): Promise<string[]> {
    await mkdir(this.dataDirPath, { recursive: true })
    const restored: string[] = []
    // Backend sqlite : les collections enregistrées dans les meta de la DB sont aussi à restaurer (leurs fichiers sources JSON de retour arrière peuvent déjà avoir été nettoyés)
    const names = new Set<string>(this.backend === 'sqlite' ? this.ensureSqliteBackend().names() : [])
    let files: string[] = []
    try {
      files = (await readdir(this.dataDirPath)).filter((file) => file.endsWith('.json'))
    } catch {
      files = []
    }
    for (const file of files) {
      names.add(decodeFileName(file.slice(0, -5)))
    }
    for (const name of names) {
      try {
        await this.restore(name)
        restored.push(name)
      } catch (error) {
        console.error(`[storage] 恢复集合 ${name} 失败`, error)
      }
    }
    return restored
  }

  /** Liste des noms de collections restaurées/créées (pour l'affichage des informations plateforme). */
  names(): string[] {
    return [...this.collections.keys()]
  }

  private markDirty(name: string): void {
    this.dirty.add(name)
    if (this.flushTimer) return
    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined
      void this.flushNow()
    }, 250)
  }

  /** Écrit immédiatement les collections sales (écriture atomique : tmp + fsync + rename ; sérialisation complète pour éviter les écritures concurrentes du même tmp). */
  flushNow(): Promise<void> {
    this.flushChain = this.flushChain.then(() => this.doFlush())
    return this.flushChain
  }

  private async doFlush(): Promise<void> {
    for (;;) {
      const names = [...this.dirty]
      this.dirty.clear()
      if (names.length === 0) return
      for (const name of names) {
        // Les collections sqlite valident leur transaction à chaque écriture (WAL + synchronous=FULL) : pas de fenêtre d'anti-rebond, pas de surface d'écriture JSON
        if (this.sqliteNames.has(name)) continue
        const collection = this.collections.get(name)
        if (!collection) continue
        const file = join(this.dataDirPath, `${fileNameOf(name)}.json`)
        const tmp = `${file}.${process.pid}-${Date.now()}-${++this.tmpSeq}.tmp`
        try {
          await mkdir(dirname(file), { recursive: true })
          const handle = await open(tmp, 'w')
          try {
            await handle.writeFile(JSON.stringify(collection.all(), null, 2), 'utf8')
            await handle.sync()
          } finally {
            await handle.close()
          }
          await rename(tmp, file)
        } catch (error) {
          // Bruit de rename ENOENT (course où répertoire/fichier temporaire sont recyclés de l'extérieur pendant la fenêtre d'arrêt) : l'état mémoire est intact,
          // la prochaine écriture rétablit naturellement ; une trace en niveau debug suffit, sans reprise ni alerte (évite la tempête de logs en période d'arrêt)
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
            console.debug(`[storage] 集合 ${name} 落盘 rename 竞态（ENOENT，内存态未失，下次落盘恢复）`)
          } else {
            console.error(`[storage] 集合 ${name} 落盘失败`, error)
          }
        }
      }
      // Nouvelles modifications pendant l'écriture (déclenchement immédiat en durable) : boucler jusqu'à vide
    }
  }

  /**
   * Persistance forte complète : écrit toutes les collections JSON avec fsync (appelé avant la réponse HTTP,
   * garantit qu'« un process tué après le 200 » ne perd aucune modification — point de correction de l'expérience de récupération sur crash de la revue).
   * Les collections sqlite valident leur transaction à chaque écriture, la garantie est native, hors périmètre de ce flush.
   */
  async flushDurable(): Promise<void> {
    for (const name of this.collections.keys()) {
      if (!this.sqliteNames.has(name)) this.dirty.add(name)
    }
    await this.flushNow()
  }
}


/** Nom de collection → nom de fichier (échappement des caractères réservés Windows). */
function fileNameOf(name: string): string {
  return name.replace(/[:*?"<>|]/g, '~')
}

/**
 * Réconciliation du remplissage (lacune ② de l'ADR-0001) : réconciliation entrée à entrée entre la source JSON et la base SQLite — nombre d'entrées identique +
 * hachage SHA-256 de la sérialisation normalisée (clés triées récursivement) identique pour chaque enregistrement. Toute divergence lève (échec bruyant), le message d'erreur
 * contient le nom de la collection et le nombre de différences ; combiné à la sémantique de transaction unique du backfill, une levée annule ensemble l'import et la marque meta,
 * le démarrage suivant réessaie et échoue de nouveau — jamais de remplissage achevé avec une incohérence silencieuse.
 */
function assertBackfillParity(name: string, source: RecordBase[], rows: Array<{ id: string; doc: string }>): void {
  if (rows.length !== source.length) {
    throw new Error(t('[storage] 集合 {name} 回填对账失败：条数不一致（JSON 源 {json} 条 / SQLite 落库 {sql} 条）', { name, json: source.length, sql: rows.length }))
  }
  const sourceHashes = new Map(source.map((record) => [record.id, recordHash(record)]))
  let diff = 0
  for (const row of rows) {
    const expected = sourceHashes.get(row.id)
    if (expected === undefined || expected !== recordHash(JSON.parse(row.doc) as RecordBase)) diff++
  }
  if (diff > 0) {
    throw new Error(t('[storage] 集合 {name} 回填对账失败：{count} 条记录关键字段哈希不一致', { name, count: diff }))
  }
}

/** Hachage de sérialisation stable : clés triées récursivement puis JSON sérialisé puis SHA-256 (réservé à la réconciliation, indépendant du format d'écriture du stockage). */
function recordHash(record: RecordBase): string {
  return createHash('sha256').update(canonicalJson(record)).digest('hex')
}

/** JSON normalisé : clés d'objets triées couche par couche, undefined retirés, garantit une sérialisation identique octet par octet pour des données isomorphes. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`
}

function decodeFileName(name: string): string {
  return name.replace(/~/g, ':')
}

/** Variable d'environnement PLATFORM_STORAGE → backend (json par défaut ; valeur inconnue → alerte et repli, jamais avalé en silence). */
function parseBackendEnv(value: string | undefined): StorageBackendKind {
  const normalized = (value ?? '').trim().toLowerCase()
  if (normalized === '' || normalized === 'json') return 'json'
  if (normalized === 'sqlite' || normalized === 'sqlite3' || normalized === 'db') return 'sqlite'
  console.warn(`[storage] 未知 PLATFORM_STORAGE=${value}，回退 json（可选：json | sqlite）`)
  return 'json'
}

/**
 * PLATFORM_STORAGE_JSON_KEEP : noms des collections gardant leur écriture JSON même sous backend sqlite (séparés par virgules, joker `préfixe*`).
 * Sémantique : non défini → DEFAULT_JSON_KEEP ; défini explicitement → remplace intégralement la liste par défaut —
 * une chaîne vide se parse en tableau vide, soit « chaîne vide explicite = aucune exemption, toutes les collections passent en sqlite ».
 */
function parseKeepEnv(value: string | undefined): string[] {
  if (!value) return []
  return value.split(',').map((item) => item.trim()).filter(Boolean)
}
