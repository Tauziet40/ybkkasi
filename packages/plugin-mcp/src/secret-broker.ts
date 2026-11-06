/**
 * Secret Broker (W1-T2, contrat de gouvernance MCP §6) : gardien local des références d'identifiants aval.
 *
 * Objectif : le clair des identifiants d'authentification aval ne tombe que dans le fichier de clés dédié de ce Broker (<dataDir>/secrets/mcp/<serviceId>.json,
 * fichier 0600 / répertoire 0700) ; les collections métier (mcp:services, etc.) et toute réponse d'API ne contiennent jamais le secret en clair.
 *
 * Formes de credentialRef (une référence, pas un clair) :
 *   - local:<serviceId>  — prend le stockage interne du Broker (les entrées secrets sont injectées selon headerName) ;
 *   - env:VAR            — prend la variable d'environnement VAR du processus (absente : resolve renvoie null et laisse une trace d'accès) ;
 *   - vault:/external:/autres — cette itération jette toujours CREDENTIAL_BROKER_UNSUPPORTED (interface réservée, fail-closed).
 *
 * Chaque resolve réussi émet PlatformEvents.McpSecretAccess ('mcp.secret.access'),
 * le payload ne contient que des métadonnées serviceId/credentialRef/at, jamais la valeur (plugin-audit souscrit et journalise dans l'audit).
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'

/** Référentiel de jugement des en-têtes sensibles (contrat §6) : strictement identique au maskServiceHeaders de console. */
export const SENSITIVE_HEADER_RE = /authorization|token|secret|key/i

/**
 * env: liste blanche des références d'identifiants (revue de sécurité P1-04, 2026-10-31) : MCP_ENV_SECRET_ALLOWLIST (noms de variables
 * séparés par virgules). Un utilisateur tenant mcp.service.write peut spécifier à la fois l'adresse du service et une référence env: — si les variables
 * d'environnement du processus étaient libres, le proxy de clés injecterait n'importe quelle clé du processus dans les en-têtes sortants vers ce service
 * (l'adresse d'appel sortant pouvant pointer le serveur d'un attaquant), constituant une chaîne « vol de clés du processus via l'appel sortant du service ».
 * Convergence : une référence env: n'accepte que des noms de variables explicitement enregistrés, la liste blanche est vide par défaut
 * MCP_ENV_SECRET_ALLOWLIST=TICKET_MCP_TOKEN,GITHUB_TOKEN.
 */
export function envSecretAllowlist(): Set<string> {
  return new Set(String(process.env.MCP_ENV_SECRET_ALLOWLIST ?? '')
    .split(',').map((item) => item.trim()).filter(Boolean))
}

export function envSecretAllowed(varName: string): boolean {
  return envSecretAllowlist().has(varName)
}

/** Liste des clés sensibles dans les headers d'un enregistrement de service (partagée par le scan migrate et la dette de gouvernance plainHeaderServices). */
export function sensitiveHeaderKeys(headers?: Record<string, string>): string[] {
  if (!headers) return []
  return Object.keys(headers).filter((key) => SENSITIVE_HEADER_RE.test(key))
}

/**
 * Barrière d'entrée des en-têtes sensibles en clair (contrat §6) : renvoie les clés sensibles atteintes ; env MCP_ALLOW_PLAIN_HEADERS=1
 * est la porte de secours globale de période de migration (fermée par défaut) — ouverte, renvoie un tableau vide et laisse passer, strictement pour la transition où le clair préexistant n'est pas encore migré.
 * Les chemins d'écriture REST create/update en tirent un 400 SENSITIVE_HEADERS_FORBIDDEN, invitant à passer par l'API credential.
 */
export function plainSensitiveHeaderViolation(headers?: Record<string, string>): string[] {
  if (process.env.MCP_ALLOW_PLAIN_HEADERS === '1') return []
  return sensitiveHeaderKeys(headers)
}

/** Entrée d'identifiant unique (headerName → secret ; ne vit que dans le fichier de clés du Broker et le résultat de resolve, jamais dans les collections métier). */
export interface McpCredentialEntry {
  headerName: string
  secret: string
}

/** Contenu du fichier de clés (contrat §6 simplifié : plusieurs entrées par service ; pour un credentialRef à entrées multiples, tout pend au niveau fichier/première entrée). */
export interface McpCredentialFile {
  credentialRef: string
  secrets: McpCredentialEntry[]
  updatedAt: string
}

/** Forme descriptive externe (partagée describe/écho REST) : métadonnées seules, jamais le secret en clair. */
export interface McpCredentialDescription {
  credentialRef?: string
  headerNames: string[]
  updatedAt?: string
}

function unsupportedError(credentialRef: string): Error {
  const prefix = credentialRef.includes(':') ? credentialRef.slice(0, credentialRef.indexOf(':') + 1) : credentialRef
  return Object.assign(
    new Error(t('凭证形态 {prefix}… 本期不支持（CREDENTIAL_BROKER_UNSUPPORTED）：仅支持 local:/env: 前缀，vault:/external: 留待后续接入', { prefix })),
    { code: 'CREDENTIAL_BROKER_UNSUPPORTED' },
  )
}

function nowIso(): string {
  return new Date().toISOString()
}

export class SecretBroker extends Service {
  static readonly provide = 'secretBroker'

  /** Durée de la fenêtre de déduplication des traces d'accès de sondage (W3-T5 §14) : une même clé (serviceId+credentialRef+dedupKey) n'émet qu'un événement par fenêtre. */
  protected probeDedupWindowMs = 10 * 60_000
  /** Registre des fenêtres de déduplication : key → { windowStart, count (resolves dans la fenêtre), suppressed (répétitions déjà agrégées dans la fenêtre) }. */
  private accessWindows = new Map<string, { windowStart: number; count: number; suppressed: number }>()

  constructor(ctx: Context) {
    super(ctx, 'secretBroker')
  }

  // -- Primitives de stockage -------------------------------------------------------------

  /** Répertoire de données : même source qu'opsStorage (lieu de dépôt des fichiers de clés niveau plateforme) ; hôte de tests unitaires absent = erreur explicite. */
  private dataDir(): string {
    try {
      const dir = (this.ctx as { opsStorage?: { dataDirPath?: string } }).opsStorage?.dataDirPath
      if (dir) return dir
    } catch { /* proxy strict cordis : service non assemblé → lève → remonte vers le report d'erreur unifié ci-dessous */ }
    throw new Error(t('SecretBroker 缺少数据目录（opsStorage 未装配）'))
  }

  /** Chemin du fichier de clés (serviceId sécurisé comme nom de fichier ; structure <dataDir>/secrets/mcp/). */
  private fileOf(serviceId: string): string {
    const safe = String(serviceId).replace(/[^a-zA-Z0-9._-]/g, '_')
    return join(this.dataDir(), 'secrets', 'mcp', `${safe}.json`)
  }

  private read(serviceId: string): McpCredentialFile | null {
    const file = this.fileOf(serviceId)
    if (!existsSync(file)) return null
    try {
      const parsed = JSON.parse(readFileSync(file, 'utf8')) as McpCredentialFile
      if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.secrets)) return null
      return parsed
    } catch {
      // Un fichier de clés corrompu est traité comme « sans identifiant » (resolve manque naturellement, ne fait pas sauter la chaîne d'appel) ; pas de réécriture silencieuse, attendre une intervention humaine
      return null
    }
  }

  private write(serviceId: string, content: McpCredentialFile): void {
    const file = this.fileOf(serviceId)
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
    chmodSync(dirname(file), 0o700) // répertoire 0700 (le mode de mkdir est affecté par l'umask, resserrage explicite)
    writeFileSync(file, JSON.stringify(content, null, 2), 'utf8')
    chmodSync(file, 0o600) // fichier 0600 : lisible/écrivable par le seul propriétaire
  }

  // -- API externe -------------------------------------------------------------

  /**
   * Enregistre un identifiant (re-put d'un headerName homologue = rotation) :
   *   - local:/défaut : doit porter le secret en clair, tombe dans le fichier de clés ; credentialRef par défaut local:<serviceId> ;
   *   - env:VAR : pas de clair (secret doit être absent), la valeur est lue dans la variable d'environnement du processus au resolve ;
   *   - vault:/external:/autres : jette CREDENTIAL_BROKER_UNSUPPORTED (fail-closed dès l'enregistrement).
   */
  put(input: { serviceId: string; credentialRef?: string; headerName?: string; secret?: string }): McpCredentialDescription {
    const serviceId = String(input.serviceId ?? '').trim()
    if (!serviceId) throw new Error(t('serviceId 必填'))
    const headerName = input.headerName?.trim() || 'Authorization'
    const existing = this.read(serviceId)
    const credentialRef = input.credentialRef?.trim() || existing?.credentialRef || `local:${serviceId}`
    if (credentialRef.startsWith('env:')) {
      if (input.secret) {
        throw new Error(t('env: 形态凭证不落明文：secret 必须缺省，取值来自进程环境变量 {name}', { name: credentialRef.slice(4).trim() }))
      }
    } else if (credentialRef.startsWith('local:')) {
      if (!input.secret) throw new Error(t('local: 形态凭证必须提供 secret 明文'))
    } else {
      throw unsupportedError(credentialRef)
    }
    const secrets = [...(existing?.secrets ?? [])]
    const entry: McpCredentialEntry = { headerName, secret: credentialRef.startsWith('env:') ? '' : input.secret! }
    const hit = secrets.findIndex((item) => item.headerName === headerName)
    if (hit >= 0) secrets[hit] = entry // re-put homonyme = rotation
    else secrets.push(entry)
    this.write(serviceId, { credentialRef, secrets, updatedAt: nowIso() })
    return this.describe(serviceId)!
  }

  /**
   * Résolution (injection avant transmission appel/sondage/découverte d'outils) : renvoie la liste d'entrées injectées selon headerName ;
   * sans enregistrement, renvoie null (la chaîne d'appel retombe sur les headers préexistants) ; variable env absente, renvoie null et laisse une trace d'accès.
   * vault:/external:/préfixe inconnu jette CREDENTIAL_BROKER_UNSUPPORTED (fail-closed, présenté par le try/catch existant
   * de la chaîne d'appel comme échec d'appel/échec de sondage — avoir configuré une forme d'identifiant non supportée ne doit pas partir à découvert en silence).
   *
   * options.dedupKey (agrégation d'audit de sondage W3-T5 §14, reliquat T2) : les résolutions périodiques type sondage passent une clé
   * fixe (ex. 'probe') — un même serviceId+credentialRef+dedupKey n'émet qu'un événement mcp.secret.access par fenêtre,
   * le compteur de la fenêtre est joint à l'événement à la fermeture de fenêtre (ouverture de la suivante) en suppressedCount ;
   * sans clé (vrais accès appel/découverte d'outils), trace à chaque fois, zéro modification côté audit.
   */
  resolve(serviceId: string, options: { dedupKey?: string } = {}): McpCredentialEntry[] | null {
    const stored = this.read(serviceId)
    if (!stored) return null
    const credentialRef = stored.credentialRef || `local:${serviceId}`
    const isLocal = credentialRef.startsWith('local:')
    const isEnv = credentialRef.startsWith('env:')
    if (!isLocal && !isEnv) throw unsupportedError(credentialRef)
    const deduped = typeof options.dedupKey === 'string'
    const emit = (result: 'ok' | 'missing' | 'empty'): void => {
      if (!deduped) {
        this.emitAccess(serviceId, credentialRef, result)
        return
      }
      // Déduplication par fenêtre : un seul événement par clé et par fenêtre ; le premier événement après fermeture porte le compteur agrégé de la fenêtre précédente
      const key = `${serviceId}|${credentialRef}|${options.dedupKey}`
      const nowMs = Date.now()
      const window = this.accessWindows.get(key)
      if (window && nowMs - window.windowStart < this.probeDedupWindowMs) {
        window.count++
        window.suppressed++
        return
      }
      const suppressedCount = window ? window.suppressed : 0
      this.accessWindows.set(key, { windowStart: nowMs, count: 1, suppressed: 0 })
      this.emitAccess(serviceId, credentialRef, result, suppressedCount > 0 ? suppressedCount : undefined)
    }
    if (isEnv) {
      const varName = credentialRef.slice(4).trim()
      // P1-04 : une référence env: hors liste blanche est traitée comme « identifiant manquant » (fail-closed, pas d'injection), avec trace d'accès
      if (!varName || !envSecretAllowed(varName)) {
        this.ctx.logger('mcp-secret-broker').warn(`env: 凭证引用未登记白名单（MCP_ENV_SECRET_ALLOWLIST），拒绝注入：service=${serviceId} ref=${credentialRef}`)
        emit('missing')
        return null
      }
      const value = process.env[varName]
      if (!value) {
        emit('missing')
        return null
      }
      emit('ok')
      const entries = stored.secrets.filter((item) => item.headerName)
      return entries.length > 0
        ? entries.map((item) => ({ headerName: item.headerName, secret: value }))
        : [{ headerName: 'Authorization', secret: value }]
    }
    const entries = stored.secrets.filter((item) => item.headerName && item.secret)
    if (entries.length === 0) {
      emit('empty')
      return null
    }
    emit('ok')
    return entries.map((item) => ({ headerName: item.headerName, secret: item.secret }))
  }

  /** Description (écho GET REST/face gouvernance) : métadonnées seules, jamais le secret en clair ; sans enregistrement, null. */
  describe(serviceId: string): McpCredentialDescription | null {
    const stored = this.read(serviceId)
    if (!stored) return null
    return {
      credentialRef: stored.credentialRef,
      headerNames: stored.secrets.map((item) => item.headerName),
      updatedAt: stored.updatedAt,
    }
  }

  /** Suppression (couplage suppression de service/vidage d'identifiants) : fichier inexistant = false. */
  delete(serviceId: string): boolean {
    const file = this.fileOf(serviceId)
    if (!existsSync(file)) return false
    rmSync(file)
    return true
  }

  /** Trace d'accès (contrat §6 : émise à chaque resolve ; le payload ne porte jamais la valeur du secret, audit souscrit et journalisé en mcp.credential.access).
   *  suppressedCount (W3-T5 §14, additive) : à la fermeture de la fenêtre de déduplication du sondage, nombre de lectures répétées agrégées de la fenêtre précédente. */
  private emitAccess(serviceId: string, credentialRef: string, result: 'ok' | 'missing' | 'empty', suppressedCount?: number): void {
    this.ctx.platformBus.emit(PlatformEvents.McpSecretAccess, {
      serviceId,
      credentialRef,
      result,
      at: nowIso(),
      actor: 'mcp-gateway',
      actorName: 'Secret Broker',
      type: 'mcp_service',
      ...(suppressedCount !== undefined ? { suppressedCount } : {}),
      note: result === 'ok'
        ? t('凭证读取成功（值不入事件与审计）')
        : result === 'missing'
          ? t('env 变量缺失，凭证未取到')
          : t('凭证登记存在但无有效条目'),
    })
  }
}
