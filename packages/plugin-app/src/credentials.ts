/**
 * Hébergement des identifiants externes d'application (App Credential Vault, issue GitHub #19 direction A, boucle minimale).
 *
 * Scénario : un employé numérique / une application IA doit appeler un service externe interne qui s'authentifie par un identifiant fixe de longue durée
 * (token de service interne, clé API tierce, secret partagé — pas une forme OAuth autorisable). Auparavant la plateforme
 * n'avait aucun point de stockage (404 sur /api/secrets et /api/vault ; la liste blanche des attrs d'app sans champ secret ;
 * le coffre d'identifiants connector en write-only sans lecture plateforme), le clair ne pouvait que s'éparpiller dans des fichiers locaux de chaque machine,
 * sans propriété, sans convergence de rotation, avec rupture de la chaîne d'audit.
 *
 * Conception (même discipline que SecretBroker, avec chiffrement au repos en plus) :
 *   - stockage : fichier de clés dédié <dataDir>/secrets/app/<appId>.json (répertoire 0700 / fichier 0600),
 *     jamais de clair dans les collections métier ni dans une réponse API ;
 *   - chiffrement : AES-256-GCM au repos — clé maîtresse de 32 octets aléatoires, générée au premier usage dans
 *     <dataDir>/secrets/app/.master.key (0600) ; chaque entrée a son IV de 12 octets + auth tag ;
 *     même si le fichier de clés est lu, impossible de déchiffrer sans la clé maîtresse (premier emplacement de stockage chiffré de tout le dépôt plateforme) ;
 *   - autorisation : la lecture passe par le point de permission dédié app.credential.fetch (autorisation explicite par rôle/identifiant machine, aucun rôle
 *     intégré ne le détient par défaut) + contrôle au niveau objet (l'identifiant machine doit être lié à cette application ; l'humain doit être owner ou administrateur) ;
 *     enregistrement/rotation/suppression suivent app.write + garde owner (même périmètre que la liaison de capacités) ;
 *   - audit : chaque lecture émet PlatformEvents.AppSecretAccess (payload en métadonnées seules comme appId/key/result,
 *     jamais de valeur), plugin-audit s'abonne et comptabilise app.credential.access ;
 *   - écho : liste/détail ne renvoient que masked (longueur ≥ 8 : 4 derniers caractères conservés) + métadonnées comme lastRotatedAt.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { dirname, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'

/** Contraintes de nom des clés d'identifiants : sûr dans un chemin URL, 1-64 caractères (p. ex. kizuna-admin-token, github_api_key). */
const CREDENTIAL_KEY_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/
/** Plafond de longueur de la valeur d'identifiant : les identifiants longue durée (token/clé API/secret partagé) sont bien plus courts, contre le stockage d'objets géants abusifs. */
const VALUE_MAX_LENGTH = 8192
/** Plafond d'entrées d'identifiants par application (anti-gonflement anormal ; le nombre de dépendances externes d'une application en est très loin). */
const ENTRIES_CAP = 100

/** Échec de lecture : clé inexistante (mappée en 404 CREDENTIAL_NOT_FOUND à la couche REST). */
export class AppCredentialMissingError extends Error {}

/** Métadonnées de masque (partagées par liste et réponse d'enregistrement) : jamais de clair. */
export interface AppCredentialMeta {
  key: string
  /** Aperçu masqué : longueur ≥ 8 → 4 derniers caractères conservés, sinon masque intégral. */
  masked: string
  description?: string
  createdAt: string
  /** Dernière rotation (un ré-enregistrement de la même clé = rotation ; distinct de createdAt, sémantique de rotation auditable). */
  rotatedAt: string
  rotatedBy: string
}

/** Entrée chiffrée individuelle (existe uniquement dans le fichier de clés). maskedPreview est le masque calculé à l'enregistrement (écho de liste sans déchiffrement). */
interface AppCredentialEntry {
  iv: string
  tag: string
  data: string
  maskedPreview: string
  createdAt: string
  rotatedAt: string
  rotatedBy: string
  description?: string
}

/** Structure du fichier de clés (version pour l'évolution algorithmique future). */
interface AppCredentialFile {
  version: 1
  entries: Record<string, AppCredentialEntry>
  updatedAt: string
}

/** Périmètre de masquage : valeur courte entièrement masquée (pas d'ancre pour la force brute), valeur longue garde les 4 derniers caractères pour la vérification humaine de l'effet de la rotation. */
function maskValue(value: string): string {
  return value.length >= 8 ? `••••••••${value.slice(-4)}` : '••••••••'
}

function nowIso(): string {
  return new Date().toISOString()
}

function assertKeyName(key: string): void {
  if (!CREDENTIAL_KEY_RE.test(key)) {
    throw new Error(t('凭证键名非法：{key}（须为字母/数字开头，仅含字母数字._-，1-64 位）', { key }))
  }
}

function assertValue(value: string): void {
  if (typeof value !== 'string' || value.length === 0) throw new Error(t('凭证值必填（非空字符串）'))
  if (value.length > VALUE_MAX_LENGTH) {
    throw new Error(t('凭证值过长：{len} 字符（上限 {max}）', { len: value.length, max: VALUE_MAX_LENGTH }))
  }
}

export class AppCredentialService extends Service {
  static readonly provide = 'appCredentials'

  constructor(ctx: Context) {
    super(ctx, 'appCredentials')
  }

  // -- Primitives de stockage -------------------------------------------------------------

  /** Répertoire de données : même source que opsStorage (même méthode que SecretBroker) ; erreur explicite si absent chez l'hôte de test unitaire. */
  private dataDir(): string {
    try {
      const dir = (this.ctx as { opsStorage?: { dataDirPath?: string } }).opsStorage?.dataDirPath
      if (dir) return dir
    } catch { /* proxy strict cordis : lève si le service n'est pas assemblé → erreur unifiée plus bas */ }
    throw new Error(t('应用凭证托管缺少数据目录（opsStorage 未装配）'))
  }

  /** Chemin du fichier de clés de l'application (structure <dataDir>/secrets/app/). */
  fileOf(appId: string): string {
    const safe = String(appId).replace(/[^a-zA-Z0-9._-]/g, '_')
    return join(this.dataDir(), 'secrets', 'app', `${safe}.json`)
  }

  /**
   * Clé maîtresse (AES-256, 32 octets) : générée au premier usage, écrite dans <dataDir>/secrets/app/.master.key (0600).
   * Clé et chiffré dans des fichiers distincts : une sauvegarde métier qui copierait par erreur l'ensemble des fichiers de clés reste indéchiffrable sans la clé maîtresse. Perte du fichier =
   * tous les chiffrés indéchiffrables (fail-closed : erreur explicite à la lecture invitant à réenregistrer, jamais de valeur poubelle silencieuse).
   */
  private masterKey(): Buffer {
    const dir = join(this.dataDir(), 'secrets', 'app')
    const file = join(dir, '.master.key')
    if (existsSync(file)) {
      const hex = readFileSync(file, 'utf8').trim()
      const key = Buffer.from(hex, 'hex')
      if (key.length === 32) return key
      // Fichier de clé maîtresse corrompu : chiffrés indéchiffrables, erreur explicite (pas de reconstruction silencieuse — une reconstruction silencieuse ferait échouer toutes les lectures existantes plus tard et plus difficilement à diagnostiquer)
      throw new Error(t('应用凭证主密钥文件损坏（.master.key），存量密文不可解，请重新登记全部外部凭证'))
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
    const key = randomBytes(32)
    writeFileSync(file, key.toString('hex'), 'utf8')
    chmodSync(file, 0o600)
    return key
  }

  private read(appId: string): AppCredentialFile | null {
    const file = this.fileOf(appId)
    if (!existsSync(file)) return null
    try {
      const parsed = JSON.parse(readFileSync(file, 'utf8')) as AppCredentialFile
      if (!parsed || typeof parsed !== 'object' || parsed.version !== 1 || !parsed.entries || typeof parsed.entries !== 'object') return null
      return parsed
    } catch {
      // Fichier de clés corrompu traité comme « sans identifiants » (miss explicite du resolve, la chaîne d'appel ne casse pas) ; pas de réécriture silencieuse, en attente de traitement humain
      return null
    }
  }

  private write(appId: string, content: AppCredentialFile): void {
    const file = this.fileOf(appId)
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
    chmodSync(dirname(file), 0o700) // répertoire 0700 (le mode de mkdir subit umask, convergence explicite)
    writeFileSync(file, JSON.stringify(content, null, 2), 'utf8')
    chmodSync(file, 0o600) // fichier 0600 : lecture/écriture réservées au propriétaire
  }

  private metaOf(key: string, entry: AppCredentialEntry): AppCredentialMeta {
    return {
      key,
      masked: entry.maskedPreview,
      createdAt: entry.createdAt,
      rotatedAt: entry.rotatedAt,
      rotatedBy: entry.rotatedBy,
      ...(entry.description ? { description: entry.description } : {}),
    }
  }

  private encrypt(plain: string): { iv: string; tag: string; data: string; maskedPreview: string } {
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', this.masterKey(), iv)
    const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
    return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64'), maskedPreview: maskValue(plain) }
  }

  private decrypt(entry: { iv: string; tag: string; data: string }): string {
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.masterKey(), Buffer.from(entry.iv, 'base64'))
      decipher.setAuthTag(Buffer.from(entry.tag, 'base64'))
      return Buffer.concat([decipher.update(Buffer.from(entry.data, 'base64')), decipher.final()]).toString('utf8')
    } catch {
      // Échec de déchiffrement (clé maîtresse non concordante/chiffré corrompu/vérification GCM échouée) : erreur explicite fail-closed, jamais de valeur poubelle
      throw new Error(t('凭证解密失败（密文校验不通过或主密钥不匹配），请重新登记该凭证'))
    }
  }

  // -- API externe -------------------------------------------------------------

  /**
   * Enregistrement/rotation (un second put sur la même clé = rotation) : valeur chiffrée AES-256-GCM dans le fichier de clés ; renvoie les métadonnées de masque.
   * L'appelant doit avoir déjà franchi la garde app.write + owner (ce service ne revérifie pas l'identité de l'appelant, même position que
   * resourceCore.create et les autres socles — l'autorisation se conclut à la couche REST/outils).
   */
  put(appId: string, input: { key: string; value: string; description?: string; rotatedBy: string }): AppCredentialMeta {
    assertKeyName(input.key)
    assertValue(input.value)
    const existing = this.read(appId)
    const entries: Record<string, AppCredentialEntry> = { ...(existing?.entries ?? {}) }
    const prior = entries[input.key]
    const at = nowIso()
    const entry: AppCredentialEntry = {
      ...this.encrypt(input.value),
      createdAt: prior?.createdAt ?? at,
      rotatedAt: at,
      rotatedBy: input.rotatedBy,
      ...(input.description?.trim() ? { description: input.description.trim().slice(0, 200) } : (prior?.description ? { description: prior.description } : {})),
    }
    if (!prior && Object.keys(entries).length >= ENTRIES_CAP) {
      throw new Error(t('凭证条目数已达上限（{max}），请清理不再使用的凭证', { max: ENTRIES_CAP }))
    }
    entries[input.key] = entry
    this.write(appId, { version: 1, entries, updatedAt: at })
    return this.metaOf(input.key, entry)
  }

  /** Liste masquée (écho liste/détail) : métadonnées seules, jamais de clair ; tableau vide si rien d'enregistré. */
  list(appId: string): AppCredentialMeta[] {
    const stored = this.read(appId)
    if (!stored) return []
    return Object.entries(stored.entries).map(([key, entry]) => this.metaOf(key, entry))
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.key.localeCompare(b.key))
  }

  /**
   * Lecture (l'employé numérique avec son identité machine + point de permission app.credential.fetch, via GET /api/apps/:id/credentials/:key/value) :
   * en cas de correspondance, renvoie le clair et émet AppSecretAccess (payload en métadonnées seules, l'audit comptabilise à chaque occurrence) ;
   * sinon lève AppCredentialMissingError (mappé en 404 à la couche REST). Un échec de déchiffrement lève fail-closed.
   */
  resolve(appId: string, key: string, caller?: { actor: string; actorName: string }): string {
    assertKeyName(key)
    const stored = this.read(appId)
    const entry = stored?.entries[key]
    if (!entry) {
      this.emitAccess(appId, key, 'missing', caller)
      throw Object.assign(new AppCredentialMissingError(t('凭证不存在：{key}（应用 {appId} 未登记或已删除）', { key, appId })), { code: 'CREDENTIAL_NOT_FOUND' })
    }
    let value: string
    try {
      value = this.decrypt(entry)
    } catch (error) {
      this.emitAccess(appId, key, 'error', caller)
      throw error
    }
    this.emitAccess(appId, key, 'ok', caller)
    return value
  }

  /** Supprime une entrée (false si la clé n'existe pas, idempotent). */
  remove(appId: string, key: string): boolean {
    assertKeyName(key)
    const stored = this.read(appId)
    if (!stored?.entries[key]) return false
    const entries = { ...stored.entries }
    delete entries[key]
    this.write(appId, { version: 1, entries, updatedAt: nowIso() })
    return true
  }

  /**
   * Effacement en cascade à la suppression d'application (appelé par AppRegistryService.purge) : suppression du fichier de clés entier —
   * sans application, les identifiants n'ont plus de propriétaire, aucun résidu toléré (sécurité : supprimer = détruire, pas « désactiver »).
   */
  purge(appId: string): boolean {
    const file = this.fileOf(appId)
    if (!existsSync(file)) return false
    rmSync(file)
    return true
  }

  /** Traçabilité des accès (émis à chaque resolve ; payload jamais porteur de valeur, plugin-audit s'abonne et comptabilise app.credential.access). */
  private emitAccess(appId: string, key: string, result: 'ok' | 'missing' | 'error', caller?: { actor: string; actorName: string }): void {
    const appName = this.appName(appId)
    this.ctx.platformBus.emit(PlatformEvents.AppSecretAccess, {
      appId,
      key,
      result,
      at: nowIso(),
      actor: caller?.actor ?? 'unknown',
      actorName: caller?.actorName ?? 'unknown',
      type: 'app',
      id: appId,
      name: appName,
      note: result === 'ok'
        ? t('取用外部凭证 {key}（值不入事件与审计）', { key })
        : result === 'missing'
          ? t('取用外部凭证 {key}：未登记或已删除', { key })
          : t('取用外部凭证 {key}：解密失败', { key }),
    })
  }

  /** Nom de l'application (pour l'écho d'audit) ; retombe sur appId chez les hôtes extrêmes sans resourceCore, sans casser le flux principal. */
  private appName(appId: string): string {
    try {
      return (this.ctx as { resourceCore?: { get?: (type: string, id: string) => { name?: string } | undefined } }).resourceCore?.get?.('app', appId)?.name ?? appId
    } catch {
      return appId
    }
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    appCredentials: AppCredentialService
  }
}
