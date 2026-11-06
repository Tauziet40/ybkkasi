/**
 * @dsh-ops/plugin-update — auto-mise à jour de la plateforme (vérification de version / notification de mise à jour / montée de version en un clic).
 *
 * Pour deux formes d'installation (l'amont est dans les deux cas le dépôt GitHub 01men/ybkkasi) :
 *   - source (checkout git de sources) : comparaison de versions + GitHub compare API donnant « en retard de N commits et résumé » ;
 *     montée de version en un clic depuis console/CLI/Agent prise en charge (git pull --ff-only + npm install + invitation à redémarrer),
 *     dry-run de simulation pris en charge, audit de bout en bout
 *   - bundle (installation dsh plugin add) : la comparaison de versions reste disponible ; la montée de version donne les consignes de commandes côté dsh
 *     (le processus d'extension en cours d'exécution ne réécrit pas le profil de l'hôte, frontière de sécurité délibérée)
 *
 * Politique de vérification (alignée sur les pratiques matures de npm update-notifier / Gitea) :
 *   - vérification automatique : ouverte par défaut, toutes les 24 h (première vérification 30 s après le démarrage), résultat persistant ;
 *     nouvelle version détectée → diffusion platform.update.available (trace par couplage audit) + rappel dans les logs
 *   - vérification manuelle : tiroir de console / dshctl update check / outil Agent update_check,
 *     refroidissement 60 s contre l'abus (quota GitHub API non authentifié 60 fois/heure/IP)
 *   - monter de version ou non reste toujours la décision de l'admin : la vérification automatique notifie, n'exécute jamais (une plateforme de données ne s'avance pas)
 *
 * Cohérence des trois bouts : REST (/api/update/*) · CLI (dshctl update) · outils Agent (update_*).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  PlatformEvents, defineTool, platformVersionInfo, readRootVersion, verifyEd25519, isValidEd25519PublicKeyBase64,
  type Collection, type RecordBase,
} from '../../platform-core/src/index.ts'
import { t as translate } from '../../platform-i18n/src/index.ts'
import { readGitHead, runGit, runNpm } from './git.ts'

/** Manifeste de publication (produit de scripts/release-manifest.mjs, publié avec la racine du dépôt). */
interface ReleaseManifest {
  algorithm: string
  version: string
  commit: string
  signedAt: string
  signature: string
}

// ---------------------------------------------------------------------------
// Configuration et surcharges d'environnement
// ---------------------------------------------------------------------------

export interface UpdateConfig {
  /** Vérification automatique (true par défaut ; ajustable à l'exécution via console/CLI, persisté dans update:state). */
  autoCheck?: boolean
  /** Intervalle de vérification automatique en heures (24 par défaut ; ajustable à l'exécution, 0 = vérification automatique fermée). */
  intervalHours?: number
  /** owner/name du dépôt amont (01men/ybkkasi par défaut, cohérent avec git remote / package.json.repository). */
  repo?: string
  /** Branche par défaut de l'amont (main par défaut). */
  branch?: string
  /** URL de base de l'API GitHub (https://api.github.com par défaut ; surchargeable pour miroir intranet/proxy). */
  apiBase?: string
  /** URL de base des fichiers raw (https://raw.githubusercontent.com par défaut). */
  rawBase?: string
  /** Timeout réseau d'une vérification en millisecondes (10000 par défaut). */
  timeoutMs?: number
}

export interface ResolvedSource {
  repo: string
  branch: string
  apiBase: string
  rawBase: string
  timeoutMs: number
}

const DEFAULT_REPO = '01men/ybkkasi'
const DEFAULT_BRANCH = 'main'
const DEFAULT_API_BASE = 'https://api.github.com'
const DEFAULT_RAW_BASE = 'https://raw.githubusercontent.com'
const MANUAL_CHECK_COOLDOWN_MS = 60_000
/** Initialisation différée après construction : attend la fin du chargement de la plateforme (opsStorage prêt) avant graines d'état et minuteurs. */
const BOOTSTRAP_DELAY_MS = 15_000
const AUTO_CHECK_TICK_MS = 60 * 60_000

/** Surcharge par variables d'environnement (pour stubs d'auto-test / déploiement miroir privé) : DSH_UPDATE_REPO / _BRANCH / _API_BASE / _RAW_BASE. */
export function resolveSource(config: UpdateConfig): ResolvedSource {
  return {
    repo: process.env.DSH_UPDATE_REPO ?? config.repo ?? DEFAULT_REPO,
    branch: process.env.DSH_UPDATE_BRANCH ?? config.branch ?? DEFAULT_BRANCH,
    apiBase: (process.env.DSH_UPDATE_API_BASE ?? config.apiBase ?? DEFAULT_API_BASE).replace(/\/+$/, ''),
    rawBase: (process.env.DSH_UPDATE_RAW_BASE ?? config.rawBase ?? DEFAULT_RAW_BASE).replace(/\/+$/, ''),
    timeoutMs: Math.max(Number(config.timeoutMs) || 10_000, 2_000),
  }
}

/** Forme de réponse de repli contents (GitHub contents API : contenu base64). */
interface ContentsResponse { content?: string; encoding?: string; version?: string }

/**
 * Obtention du numéro de version distant (exporté pour test direct du chemin de repli) : raw package.json prioritaire, à défaut repli
 * GitHub contents API (décodage base64). Renvoie la source réellement atteinte (github-raw / github-api-contents).
 */
export async function fetchUpstreamVersion(source: ResolvedSource, headers: Record<string, string>, signal?: AbortSignal): Promise<{ version: string; via: string }> {
  const rawUrl = `${source.rawBase}/${source.repo}/${source.branch}/package.json`
  try {
    const res = await fetch(rawUrl, { headers, signal })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const pkg = await res.json() as { version?: string }
    const version = String(pkg.version ?? '')
    if (!version) throw new Error(translate('远端 package.json 无 version 字段'))
    return { version, via: 'github-raw' }
  } catch (rawError) {
    const rawMessage = rawError instanceof Error ? rawError.message : String(rawError)
    const apiUrl = `${source.apiBase}/repos/${source.repo}/contents/package.json?ref=${encodeURIComponent(source.branch)}`
    try {
      const res = await fetch(apiUrl, { headers, signal })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json() as ContentsResponse
      if (data.encoding !== 'base64' || !data.content) throw new Error(translate('contents 响应缺少 base64 内容'))
      const pkg = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8')) as { version?: string }
      const version = String(pkg.version ?? '')
      if (!version) throw new Error(translate('远端 package.json 无 version 字段'))
      return { version, via: 'github-api-contents' }
    } catch (apiError) {
      throw new Error(translate('raw {raw} / contents 回退 {message}', { raw: rawMessage, message: apiError instanceof Error ? apiError.message : String(apiError) }))
    }
  }
}

// ---------------------------------------------------------------------------
// Persistance de l'état (enregistrement unique opsStorage)
// ---------------------------------------------------------------------------

export interface UpstreamCommit {
  sha: string
  message: string
  date: string
  author: string
}

export interface LatestSnapshot {
  version: string
  commit: string
  checkedAt: string
  /** Annotation de la source de données (github-raw / github-api), pour le dépannage. */
  sources: string[]
}

export interface UpdateStateRecord extends RecordBase {
  autoCheck: boolean
  intervalHours: number
  lastCheckedAt: string
  lastError: string
  latest: LatestSnapshot | null
  hasUpdate: boolean
  behindBy: number
  recentCommits: UpstreamCommit[]
  /** Versions ignorées (après « ignorer cette version » en console, plus de bandeau ; une nouvelle version restaure automatiquement). */
  dismissedVersion: string | null
  /** OPT-P2-03 : politique de signature — true exige que le commit cible de la montée passe git verify-commit (fermée par défaut, ouverte quand le dépôt sera signé). */
  requireSignedCommits?: boolean
  /**
   * T5 (M2) : vérification de signature du manifeste de publication — clé publique Ed25519 de l'éditeur de la plateforme (SPKI DER base64).
   * Enregistrée + avec le release-manifest.json produit par scripts/release-manifest.mjs, la montée tire le manifeste selon le commit cible
   * et vérifie la signature ; sans enregistrement, seul le chemin git verify-commit s'applique (statu quo, renforcement explicite et non dégradation silencieuse).
   */
  releasePublicKey?: string
  /** T5 (M2) : true = échec/absence de vérification du manifeste = refus de la montée (fail-closed) ; false par défaut = alerte seule et passage. */
  requireSignedManifests?: boolean
  /** OPT-P2-03 : ancre de retour arrière du dernier apply (HEAD avant la montée). */
  lastApplySnapshot?: string
  lastApplyPin?: string
  lastApplyAt?: string
  /** Dernière version pour laquelle platform.update.available a été diffusée (anti-notification en double). */
  announcedVersion: string
}

const STATE_ID = 'singleton'

export function updateStateCollection(ctx: Context): Collection<UpdateStateRecord> {
  return ctx.opsStorage.collection<UpdateStateRecord>('update:state')
}

function defaultState(autoCheck = true, intervalHours = 24): Omit<UpdateStateRecord, 'id'> {
  return {
    autoCheck,
    intervalHours,
    lastCheckedAt: '',
    lastError: '',
    latest: null,
    hasUpdate: false,
    behindBy: 0,
    recentCommits: [],
    dismissedVersion: null,
    announcedVersion: '',
  }
}

export function ensureUpdateState(ctx: Context, init?: { autoCheck: boolean; intervalHours: number }): UpdateStateRecord {
  const collection = updateStateCollection(ctx)
  const existing = collection.get(STATE_ID)
  if (existing) return existing
  const init0 = init ?? { autoCheck: true, intervalHours: 24 }
  return collection.insert({ id: STATE_ID, ...defaultState(init0.autoCheck, init0.intervalHours) })
}

// ---------------------------------------------------------------------------
// Comparaison de versions (trois segments principaux semver ; numéro non standard = 0 — mieux vaut sous-signaler que faux positif)
// ---------------------------------------------------------------------------

export function compareVersions(a: string, b: string): number {
  const parse = (value: string): number[] => {
    const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(value.trim())
    return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : []
  }
  const left = parse(a)
  const right = parse(b)
  if (!left.length || !right.length) return 0
  for (let i = 0; i < 3; i++) {
    if (left[i]! > right[i]!) return 1
    if (left[i]! < right[i]!) return -1
  }
  return 0
}

// ---------------------------------------------------------------------------
// Service de mise à jour
// ---------------------------------------------------------------------------

export interface UpdateStatus {
  currentVersion: string
  installMode: 'source' | 'bundle'
  repo: string
  branch: string
  localCommit: string
  localBranch: string
  latest: LatestSnapshot | null
  hasUpdate: boolean
  /** version = numéro de version distant plus élevé ; commits = numéro inchangé mais commits amont en avance (forme source) ; none. */
  updateKind: 'version' | 'commits' | 'none'
  behindBy: number
  recentCommits: UpstreamCommit[]
  lastCheckedAt: string
  lastError: string
  autoCheck: boolean
  intervalHours: number
  dismissedVersion: string | null
  dismissed: boolean
  canApply: boolean
  nextCheckHint: string
  /** T5 (M2) : visibilité de la configuration de vérification du manifeste de publication (l'admin voit si la validation de chaîne d'approvisionnement est active). */
  releaseKeyConfigured: boolean
  requireSignedManifests: boolean
}

export class UpdateService extends Service {
  static readonly provide = 'update'

  private readonly config0: UpdateConfig
  private readonly envAutoCheck: boolean | undefined
  readonly source: ResolvedSource
  private lastManualCheckAt = 0
  private checking = false
  private bootstrapped = false
  private tickTimer: ReturnType<typeof setInterval> | undefined

  constructor(ctx: Context, config: UpdateConfig = {}) {
    super(ctx, 'update')
    this.config0 = config
    const envAuto = process.env.DSH_UPDATE_AUTO_CHECK
    this.envAutoCheck = envAuto === undefined ? undefined : (envAuto === 'on' || envAuto === 'true' || envAuto === '1')
    this.source = resolveSource(config)
    // Cette version de cordis ne pilote pas le cycle de vie Service.start (comparer authn/mcp : initialisation à la construction) :
    // un court délai après la construction boucle un bootstrap (graines d'état + démarrage des minuteurs) ; ensuite, toute entrée déclenche aussi le rattrapage.
    setTimeout(() => {
      try { this.ensureBootstrapped() } catch { /* plateforme encore en cours de chargement : silencieux, le rattrapage se fait à la première visite */ }
    }, BOOTSTRAP_DELAY_MS)
  }

  /** Initialisation idempotente : graine de l'état persistant + démarrage du minuteur de vérification automatique (une seule exécution). */
  private ensureBootstrapped(): void {
    if (this.bootstrapped) return
    this.bootstrapped = true
    const state = ensureUpdateState(this.ctx, {
      autoCheck: this.envAutoCheck ?? this.config0.autoCheck ?? true,
      intervalHours: clampIntervalHours(this.config0.intervalHours ?? 24),
    })
    this.tickTimer = setInterval(() => void this.maybeAutoCheck(), AUTO_CHECK_TICK_MS)
    this.tickTimer.unref?.() // OPT-P3-02
    this.ctx.effect?.(() => () => {
      if (this.tickTimer) clearInterval(this.tickTimer)
    })
    if (!state.autoCheck) {
      this.ctx.logger('update').info('自动更新检查已关闭（update:state.autoCheck=false），仅手动检查')
    } else {
      // Première vérification au démarrage : dernier contrôle au-delà de l'intervalle (jamais vérifié compris) = exécution immédiate
      void this.maybeAutoCheck()
    }
  }

  private state(): UpdateStateRecord {
    this.ensureBootstrapped()
    return ensureUpdateState(this.ctx)
  }

  serverVersion(): string {
    return platformVersionInfo().version
  }

  installMode(): 'source' | 'bundle' {
    return platformVersionInfo().installMode
  }

  /** Millisecondes restantes de refroidissement de la vérification manuelle (contre l'abus du quota GitHub). */
  cooldownRemainingMs(): number {
    return Math.max(0, MANUAL_CHECK_COOLDOWN_MS - (Date.now() - this.lastManualCheckAt))
  }

  status(): UpdateStatus {
    const info = platformVersionInfo()
    const state = this.state()
    const head = info.installMode === 'source' ? readGitHead(info.rootDir) : null
    const latestVersion = state.latest?.version ?? ''
    const versionAhead = latestVersion !== '' && compareVersions(latestVersion, info.version) > 0
    const commitsAhead = state.behindBy > 0
    const hasUpdate = versionAhead || commitsAhead
    return {
      currentVersion: info.version,
      installMode: info.installMode,
      repo: this.source.repo,
      branch: this.source.branch,
      localCommit: head?.sha ?? '',
      localBranch: head?.branch ?? (head ? '(detached)' : ''),
      latest: state.latest,
      hasUpdate,
      updateKind: versionAhead ? 'version' : commitsAhead ? 'commits' : 'none',
      behindBy: state.behindBy,
      recentCommits: state.recentCommits,
      lastCheckedAt: state.lastCheckedAt,
      lastError: state.lastError,
      autoCheck: state.autoCheck,
      intervalHours: state.intervalHours,
      dismissedVersion: state.dismissedVersion,
      dismissed: hasUpdate && state.dismissedVersion === latestVersion && latestVersion !== '',
      canApply: info.installMode === 'source',
      nextCheckHint: state.autoCheck && state.intervalHours > 0
        ? translate('自动检查每 {hours}h 一次', { hours: state.intervalHours })
        : translate('自动检查已关闭，需手动检查'),
      releaseKeyConfigured: Boolean((state.releasePublicKey ?? '').trim()),
      requireSignedManifests: state.requireSignedManifests === true,
    }
  }

  /** Exécute immédiatement une vérification amont (partagé auto/manuel ; manual=true enregistre le refroidissement manuel). */
  async checkNow(options: { manual?: boolean } = {}): Promise<UpdateStatus> {
    if (options.manual) {
      const cooldown = this.cooldownRemainingMs()
      if (cooldown > 0) {
        // Le code d'erreur de la clé de protocole est jugé par la couche REST (plus de correspondance de sous-chaîne sur la traduction) : code joint pour un mapping précis en 429
        const error = new Error(translate('检查过于频繁，请 {seconds} 秒后再试', { seconds: Math.ceil(cooldown / 1000) })) as Error & { code?: string }
        error.code = 'TOO_FREQUENT'
        throw error
      }
      this.lastManualCheckAt = Date.now()
    }
    if (this.checking) throw new Error(translate('已有检查在进行中，请稍候'))
    this.checking = true
    try {
      const info = platformVersionInfo()
      const head = info.installMode === 'source' ? readGitHead(info.rootDir) : null
      const headers: Record<string, string> = {
        accept: 'application/vnd.github+json',
        'user-agent': `dsh-ops-update-checker/${info.version}`,
      }
      const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN
      if (token) headers.authorization = `Bearer ${token}`
      const signal = AbortSignal.timeout(this.source.timeoutMs)
      const sources: string[] = []
      let latestVersion = ''
      let latestCommit = ''
      let behindBy = 0
      let commits: UpstreamCommit[] = []
      const errors: string[] = []

      // 1) numéro de version distant (raw prioritaire ; raw injoignable → repli contents API — l'accessibilité réseau des deux domaines diverge souvent,
      //    constat 2026-11-02 : raw en échec mais api.github.com normal ; « échec d'obtention de version » seulement si les deux voies échouent)
      try {
        const fetched = await fetchUpstreamVersion(this.source, headers, signal)
        latestVersion = fetched.version
        sources.push(fetched.via)
      } catch (error) {
        errors.push(translate('版本获取失败：{message}', { message: error instanceof Error ? error.message : String(error) }))
      }

      // 2) écart de commits (GitHub compare API, seulement en forme source et HEAD local localisable)
      if (head?.sha) {
        try {
          const apiUrl = `${this.source.apiBase}/repos/${this.source.repo}/compare/${head.sha}...${this.source.branch}`
          const res = await fetch(apiUrl, { headers, signal })
          if (!res.ok) throw new Error(`HTTP ${res.status}`)
          const data = await res.json() as {
            behind_by?: number
            commits?: Array<{ sha?: string; commit?: { message?: string; author?: { name?: string; date?: string } } }>
          }
          behindBy = Math.max(0, Number(data.behind_by ?? 0))
          latestCommit = String(data.commits?.at(-1)?.sha ?? '')
          commits = (data.commits ?? []).slice(-10).reverse().map((item) => ({
            sha: String(item.sha ?? '').slice(0, 7),
            message: String(item.commit?.message ?? '').split('\n')[0] ?? '',
            date: String(item.commit?.author?.date ?? ''),
            author: String(item.commit?.author?.name ?? ''),
          }))
          sources.push('github-api')
        } catch (error) {
          errors.push(translate('提交对比失败：{message}', { message: error instanceof Error ? error.message : String(error) }))
        }
      }

      if (sources.length === 0) {
        const message = errors.join('；') || translate('无法访问上游（网络不可达或被限流）')
        updateStateCollection(this.ctx).update(STATE_ID, { lastError: message })
        throw new Error(message)
      }

      const prev = this.state()
      const versionAhead = latestVersion !== '' && compareVersions(latestVersion, info.version) > 0
      const hasUpdate = versionAhead || behindBy > 0
      const checkedAt = new Date().toISOString()
      const latest: LatestSnapshot = {
        version: latestVersion || prev.latest?.version || '',
        commit: latestCommit || prev.latest?.commit || '',
        checkedAt,
        sources,
      }
      updateStateCollection(this.ctx).update(STATE_ID, {
        lastCheckedAt: checkedAt,
        lastError: errors.join('；'),
        latest,
        hasUpdate,
        behindBy,
        recentCommits: commits.length > 0 ? commits : prev.recentCommits,
      })

      // Notification de nouvelle version (une seule diffusion par version ; le plugin audit souscrit au bus et trace en couplage)
      if (hasUpdate && latest.version !== '' && latest.version !== prev.announcedVersion) {
        updateStateCollection(this.ctx).update(STATE_ID, { announcedVersion: latest.version })
        this.ctx.platformBus.emit(PlatformEvents.UpdateAvailable, {
          currentVersion: info.version,
          latestVersion: latest.version,
          behindBy,
          installMode: info.installMode,
        })
        this.ctx.logger('update').info(
          `发现上游新版本：${info.version} → ${latest.version}${behindBy > 0 ? `（落后 ${behindBy} 个提交）` : ''}`,
        )
      } else if (!hasUpdate && prev.announcedVersion !== '') {
        updateStateCollection(this.ctx).update(STATE_ID, { announcedVersion: '' })
      }
      return this.status()
    } finally {
      this.checking = false
    }
  }

  private maybeAutoCheck(): void {
    try {
      const state = this.state()
      if (!state.autoCheck || state.intervalHours <= 0) return
      const elapsed = state.lastCheckedAt ? Date.now() - new Date(state.lastCheckedAt).getTime() : Infinity
      if (elapsed < state.intervalHours * 3_600_000) return
      void this.checkNow().catch((error) => {
        this.ctx.logger('update').warn(`自动更新检查失败：${error instanceof Error ? error.message : String(error)}`)
      })
    } catch { /* un état anomalique n'est pas fatal */ }
  }

  /** OPT-P2-03 : lecture de la politique de signature (fermée par défaut — l'adoption de la signature du dépôt faite, l'activation via settings la rend universellement forcée). */
  private requireSignedCommits(): boolean {
    try {
      return updateStateCollection(this.ctx).get(STATE_ID)?.requireSignedCommits === true
    } catch {
      return false
    }
  }

  /** T5 (M2) : politique forcée du manifeste de publication (true = échec/absence de vérification = refus de la montée, fail-closed). */
  private requireSignedManifests(): boolean {
    try {
      return updateStateCollection(this.ctx).get(STATE_ID)?.requireSignedManifests === true
    } catch {
      return false
    }
  }

  /**
   * T5 (M2) : tire le manifeste de publication selon le commit cible de la montée et vérifie la signature Ed25519 (réutilise l'infrastructure de signature de la plateforme, même source que la vérification des cinq faces du marché).
   * Clé publique non enregistrée → checked=false (précise explicitement que la vérification n'est pas activée, sans compter comme un échec) ; clé enregistrée → tout contrôle non passé renvoie verified=false,
   * applyUpdate décide alors du refus ou de l'acceptation avec avertissement selon requireSignedManifests (en cas d'acceptation, note remontée avec le résultat, jamais de silence).
   */
  async verifyReleaseManifest(targetResolved: string): Promise<{ checked: boolean; verified: boolean; note: string }> {
    let publicKey = ''
    try {
      publicKey = (updateStateCollection(this.ctx).get(STATE_ID)?.releasePublicKey ?? '').trim()
    } catch { /* état non prêt : traité comme non configuré */ }
    if (!publicKey) {
      return { checked: false, verified: false, note: translate('未登记 releasePublicKey：发布清单验签未启用（生成密钥：node scripts/release-manifest.mjs --generate-key）') }
    }
    const url = `${this.source.rawBase}/${this.source.repo}/${targetResolved}/release-manifest.json`
    try {
      const res = await fetch(url, {
        headers: { accept: 'application/json', 'user-agent': `dsh-ops-update/${platformVersionInfo().version}` },
        signal: AbortSignal.timeout(this.source.timeoutMs),
      })
      if (!res.ok) return { checked: true, verified: false, note: translate('发布清单不可达（HTTP {status}）：{url}', { status: res.status, url }) }
      const manifest = await res.json() as ReleaseManifest
      if (manifest.algorithm !== 'ed25519') return { checked: true, verified: false, note: translate('清单签名算法异常：{algorithm}', { algorithm: String(manifest.algorithm) }) }
      if (String(manifest.commit ?? '') !== targetResolved) {
        return { checked: true, verified: false, note: translate('清单 commit {manifest} 与升级目标 {target} 不一致', { manifest: String(manifest.commit ?? '').slice(0, 12), target: targetResolved.slice(0, 12) }) }
      }
      const verified = verifyEd25519(publicKey, String(manifest.commit), String(manifest.signature ?? ''))
      return { checked: true, verified, note: verified ? translate('发布清单验签通过（Ed25519）') : translate('发布清单签名与登记公钥不匹配') }
    } catch (error) {
      return { checked: true, verified: false, note: translate('发布清单拉取失败：{message}', { message: error instanceof Error ? error.message : String(error) }) }
    }
  }

  /**
   * OPT-P2-03 : retour arrière en un clic — git reset --hard vers le HEAD d'avant montée enregistré par le dernier apply + npm install,
   * traçabilité d'audit + événement platform.update.rolled_back ; un redémarrage du processus est nécessaire pour prendre effet. Refus s'il n'existe aucun instantané de retour.
   */
  async rollbackUpdate(options: { reason?: string; actor?: { id: string; name: string } } = {}): Promise<Record<string, unknown>> {
    const info = platformVersionInfo()
    if (info.installMode !== 'source') return { ok: false, supported: false, notice: translate('bundle 形态请在宿主 dsh 侧回退插件版本') }
    const state = updateStateCollection(this.ctx).get(STATE_ID)
    const snapshot = state?.lastApplySnapshot
    if (!snapshot) throw new Error(translate('无可回滚快照：本进程尚未执行过带 pin 的升级（OPT-P2-03）'))
    const reason = (options.reason ?? '').trim()
    if (!reason) throw new Error(translate('回滚原因必填（留痕要求）'))
    const actor = options.actor ?? { id: 'api', name: 'api' }
    const from = info.version
    await runGit(info.rootDir, ['reset', '--hard', snapshot])
    let npmFailed = false
    let npmOutput = ''
    try {
      npmOutput = await runNpm(info.rootDir, ['install', '--no-audit', '--no-fund'])
    } catch (error) {
      npmFailed = true
      npmOutput = error instanceof Error ? error.message : String(error)
    }
    const to = readRootVersion(info.rootDir)
    updateStateCollection(this.ctx).update(STATE_ID, { lastApplySnapshot: '', lastApplyPin: '', lastApplyAt: new Date().toISOString() })
    this.ctx.audit?.record({
      type: 'change', actorType: 'human', actorId: actor.id, actorName: actor.name,
      action: 'platform.update.rollback', resourceType: 'platform', resourceId: 'self', resourceName: '平台升级回滚',
      result: npmFailed ? 'partial' : 'ok', detail: `${from} → ${to}（reset ${snapshot.slice(0, 12)}），原因：${reason}`,
    })
    this.ctx.platformBus.emit(PlatformEvents.UpdateRolledBack, { from, to, snapshot, reason, actor: actor.name, npmFailed })
    return {
      ok: !npmFailed,
      supported: true,
      from,
      to,
      rolledBackTo: snapshot,
      npmFailed,
      needRestart: true,
      notice: npmFailed ? translate('代码已回退但依赖同步失败：请手动执行 npm install 后重启') : translate('已回退到升级前版本，请重启平台进程生效'),
    }
  }

  setSettings(patch: { autoCheck?: boolean; intervalHours?: number; dismissedVersion?: string | null; requireSignedCommits?: boolean; releasePublicKey?: string; requireSignedManifests?: boolean }): UpdateStatus {
    const update: Partial<UpdateStateRecord> = {}
    if (typeof patch.autoCheck === 'boolean') update.autoCheck = patch.autoCheck
    if (patch.intervalHours !== undefined) {
      update.intervalHours = clampIntervalHours(Number(patch.intervalHours))
    }
    if (patch.dismissedVersion !== undefined) {
      update.dismissedVersion = patch.dismissedVersion === null || patch.dismissedVersion === ''
        ? null
        : String(patch.dismissedVersion)
    }
    if (typeof patch.requireSignedCommits === 'boolean') update.requireSignedCommits = patch.requireSignedCommits
    // T5 (M2) : réglage de la vérification de signature des manifestes de publication — contrôle de format à l'entrée d'écriture de la clé publique (garde-fou : plutôt refuser dès l'enregistrement qu'exploser à la montée parce qu'on a collé un mauvais contenu)
    if (patch.releasePublicKey !== undefined) {
      const key = String(patch.releasePublicKey).trim()
      if (key !== '' && !isValidEd25519PublicKeyBase64(key)) {
        throw new Error(translate('releasePublicKey 格式非法：应为 Ed25519 SPKI DER base64（生成：node scripts/release-manifest.mjs --generate-key）'))
      }
      update.releasePublicKey = key
    }
    if (typeof patch.requireSignedManifests === 'boolean') {
      // garde-fou fail-closed : la vérification de signature forcée ne peut pas être activée seule sans clé publique (activée = tout refus de montée)
      if (patch.requireSignedManifests === true) {
        const existing = update.releasePublicKey ?? updateStateCollection(this.ctx).get(STATE_ID)?.releasePublicKey ?? ''
        if (!existing.trim()) throw new Error(translate('开启 requireSignedManifests 前必须先登记 releasePublicKey'))
      }
      update.requireSignedManifests = patch.requireSignedManifests
    }
    if (Object.keys(update).length > 0) updateStateCollection(this.ctx).update(STATE_ID, update)
    return this.status()
  }

  /**
   * Montée en un clic (forme source uniquement) :
   *   git pull --ff-only (espace de travail sale/divergence = échec sécurisé plutôt que modification forcée) → npm install → invitation à redémarrer.
   * La forme bundle renvoie les instructions de montée côté hôte (pas de réécriture in-process du profil dsh, frontière de sécurité).
   */
  async applyUpdate(options: { dryRun?: boolean; reason?: string; pin?: string; actor?: { id: string; name: string } } = {}): Promise<Record<string, unknown>> {
    const info = platformVersionInfo()
    const status = this.status()
    // OPT-P2-03 : pin forcé — interdit de tirer nu le dernier amont (l'épinglage de version est le prérequis du retour arrière et de l'auditabilité)
    const pin = String(options.pin ?? '').trim()
    if (info.installMode === 'source' && !options.dryRun && !pin) {
      throw new Error(translate('必须显式 pin 升级目标（tag / commit / 分支名，如 v1.1.0），禁止裸拉 main 最新（OPT-P2-03）'))
    }
    let targetResolved = ''
    let signatureVerified: boolean | undefined
    let signatureNote = ''
    let manifestCheck: Awaited<ReturnType<UpdateService['verifyReleaseManifest']>> | undefined
    if (info.installMode === 'source' && pin) {
      try {
        // E-05 : fetch n'a lieu que sur le chemin d'exécution réel (appel sortant + modification de .git) — dryRun ne sort pas et ne touche pas .git,
        // la résolution du pin/la vérification de signature s'appuient sur les refs locaux existants (refs de suivi distant et tags du dernier fetch)
        if (!options.dryRun) await runGit(info.rootDir, ['fetch', 'origin', '--tags', '--prune'])
        targetResolved = (await runGit(info.rootDir, ['rev-parse', '--verify', `${pin}^{commit}`])).trim()
      } catch (error) {
        throw new Error(translate('pin 目标无法解析：{pin}（{message}）', { pin, message: error instanceof Error ? error.message.slice(0, 160) : String(error) }))
      }
      try {
        await runGit(info.rootDir, ['verify-commit', targetResolved])
        signatureVerified = true
      } catch (error) {
        signatureVerified = false
        signatureNote = error instanceof Error ? error.message.split('\n')[0]!.slice(0, 160) : String(error)
        if (this.requireSignedCommits()) {
          throw new Error(translate('目标提交签名校验未通过（requireSignedCommits=true，OPT-P2-03）：{note}', { note: signatureNote }))
        }
      }
      // T5 (M2) : vérification de signature du manifeste de publication (Ed25519) — activée après enregistrement de releasePublicKey ; stratégie forcée activée = tout contrôle non passé est refusé
      manifestCheck = await this.verifyReleaseManifest(targetResolved)
      if (manifestCheck.checked && !manifestCheck.verified && this.requireSignedManifests()) {
        throw new Error(translate('发布清单验签未通过（requireSignedManifests=true，T5）：{note}', { note: manifestCheck.note }))
      }
    }
    const base = {
      installMode: info.installMode,
      currentVersion: info.version,
      latestVersion: status.latest?.version ?? '',
      behindBy: status.behindBy,
    }
    if (info.installMode !== 'source') {
      return {
        ...base,
        ok: false,
        supported: false,
        instructions: [
          translate('本实例为 dsh 插件市场安装形态（bundle），升级请在宿主 dsh 侧执行：'),
          translate('  dsh plugin update github:{repo}    # 或重新安装：dsh plugin add github:{repo}', { repo: this.source.repo }),
          translate('完成后重启 dsh 宿主进程生效。'),
        ].join('\n'),
      }
    }
    if (options.dryRun) {
      return {
        ...base,
        ok: true,
        supported: true,
        dryRun: true,
        ...(pin ? { pin, targetResolved, signatureVerified, ...(signatureNote ? { signatureNote } : {}), ...(manifestCheck ? { manifestCheck } : {}) } : { pin: translate('（dryRun 未指定；正式执行必须 pin，OPT-P2-03）') }),
        requireSignedCommits: this.requireSignedCommits(),
        requireSignedManifests: this.requireSignedManifests(),
        steps: [
          translate('git fetch origin --tags + verify-commit（签名核验）+ git merge --ff-only（目录 {dir}；脏工作区/分叉将安全失败）', { dir: info.rootDir }),
          translate('npm install（依赖同步，package-lock 有变化时生效）'),
          translate('重启平台进程（systemd / pm2 / 手动 node src/main.ts），新版本生效'),
        ],
        ...(status.behindBy > 0
          ? { incomingCommits: status.recentCommits.map((item) => `${item.sha} ${item.message}`) }
          : {}),
      }
    }
    const reason = (options.reason ?? '').trim()
    if (!reason) throw new Error(translate('升级原因必填（留痕要求）'))
    const actor = options.actor ?? { id: 'api', name: 'api' }
    const from = info.version
    let gitOutput = ''
    let npmOutput = ''
    let npmFailed = false
    // OPT-P2-03 : instantané du HEAD d'avant montée — échec du contrôle de santé permet un retour arrière en un clic (POST /api/update/rollback)
    const rollbackTo = (await runGit(info.rootDir, ['rev-parse', 'HEAD'])).trim()
    try {
      gitOutput = await runGit(info.rootDir, ['merge', '--ff-only', targetResolved])
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.ctx.audit?.record({
        type: 'change', actorType: 'human', actorId: actor.id, actorName: actor.name,
        action: 'platform.update.apply', resourceType: 'platform', resourceId: 'self', resourceName: '平台升级',
        result: 'failed', detail: `git pull 失败：${message.slice(0, 300)}`,
      })
      throw new Error(translate('git pull 失败（本地有未提交修改或分叉，请人工处理）：{message}', { message: message.slice(0, 300) }))
    }
    // QA E-01 : merge réussi = enregistrement immédiat de l'instantané de retour — auparavant lastApplySnapshot n'avait aucun point d'écriture dans tout le dépôt,
    // rollback répondait invariablement « aucun instantané de retour disponible », le retour en un clic était une impasse ; écrit en base avant npm install,
    // pour conserver l'ancre de retour même en cas d'échec de synchronisation des dépendances
    updateStateCollection(this.ctx).update(STATE_ID, {
      lastApplySnapshot: rollbackTo,
      lastApplyPin: pin,
      lastApplyAt: new Date().toISOString(),
    })
    try {
      npmOutput = await runNpm(info.rootDir, ['install', '--no-audit', '--no-fund'])
    } catch (error) {
      npmFailed = true
      npmOutput = error instanceof Error ? error.message : String(error)
    }
    const to = readRootVersion(info.rootDir)
    this.ctx.audit?.record({
      type: 'change', actorType: 'human', actorId: actor.id, actorName: actor.name,
      action: 'platform.update.apply', resourceType: 'platform', resourceId: 'self', resourceName: '平台升级',
      result: npmFailed ? 'partial' : 'ok',
      detail: `${from} → ${to}，原因：${reason}${npmFailed ? '；npm install 失败需人工重试' : ''}`,
    })
    this.ctx.platformBus.emit(PlatformEvents.UpdateApplied, { from, to, reason, actor: actor.name, npmFailed })
    this.ctx.logger('update').info(`平台升级完成：${from} → ${to}（请重启进程生效）`)
    return {
      ...base,
      ok: !npmFailed,
      supported: true,
      from,
      to,
      pin,
      targetResolved,
      signatureVerified,
      ...(signatureNote ? { signatureNote } : {}),
      ...(manifestCheck ? { manifestCheck } : {}),
      rollbackTo,
      gitOutput: gitOutput.slice(0, 2000),
      ...(npmOutput ? { npmOutput: npmOutput.slice(0, 2000) } : {}),
      npmFailed,
      needRestart: true,
      notice: npmFailed
        ? translate('代码已更新但依赖同步失败：请在本目录手动执行 npm install 后重启平台进程')
        : translate('升级已拉取完成，请重启平台进程（systemd/pm2 或手动重启）后生效'),
    }
  }
}

function clampIntervalHours(value: number | undefined): number {
  return Math.min(Math.max(Math.floor(Number(value) || 0), 0), 24 * 30)
}

// ---------------------------------------------------------------------------
// Assemblage REST (monté sur le httpServer partagé ; authentification prise en charge uniformément par le middleware console)
// ---------------------------------------------------------------------------

interface PrincipalInfo {
  permissions?: string[]
  principalId?: string
  userId?: string
  name?: string
}

export const updateApi = {
  name: 'update-api',
  inject: ['httpServer', 'opsStorage', 'platformBus', 'update'],
  apply(ctx: Context) {
    const http = ctx.httpServer
    const service = ctx.update

    const requirePermission = (exchange: { principal?: unknown; fail: (status: number, code: string, message: string, extra?: Record<string, unknown>) => void; path: string }, point: string): boolean => {
      const info = exchange.principal as PrincipalInfo | undefined
      const permissions = info?.permissions ?? []
      if (permissions.includes('*') || permissions.includes(point)) return true
      ctx.platformBus.emit('audit.authz.denied', {
        actorId: info?.userId ?? info?.principalId ?? 'anonymous',
        actorName: info?.name ?? 'anonymous',
        point,
        path: exchange.path,
      })
      exchange.fail(403, 'FORBIDDEN', translate('缺少权限点 {point}，请联系平台管理员', { point }), { permission: point })
      return false
    }

    const actorOf = (exchange: { principal?: unknown }): { id: string; name: string } => {
      const info = exchange.principal as PrincipalInfo | undefined
      return { id: info?.userId ?? info?.principalId ?? 'api', name: info?.name ?? 'api' }
    }

    // État ouvert à tous les utilisateurs connectés (bandeau de montée visible par tous en barre supérieure ; sans information sensible)
    http.register('GET', '/api/update/status', (exchange) => {
      exchange.ok(service.status())
    }, { access: 'authenticated' })

    http.register('POST', '/api/update/check', async (exchange) => {
      if (!requirePermission(exchange, 'platform.update.read')) return
      try {
        exchange.ok(await service.checkNow({ manual: true }))
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        // TOO_FREQUENT est marqué par checkNow via error.code (évite toute correspondance de sous-chaîne sur la traduction localisée)
        if ((error as { code?: string }).code === 'TOO_FREQUENT') {
          exchange.fail(429, 'TOO_FREQUENT', message)
        } else {
          exchange.fail(502, 'UPSTREAM_ERROR', message)
        }
      }
    }, { access: 'guarded', permission: 'platform.update.read' })

    http.register('POST', '/api/update/settings', (exchange) => {
      if (!requirePermission(exchange, 'platform.update.apply')) return
      const input = (exchange.body ?? {}) as { autoCheck?: boolean; intervalHours?: number; dismissedVersion?: string | null; releasePublicKey?: string; requireSignedManifests?: boolean }
      try {
        exchange.ok(service.setSettings(input))
      } catch (error) {
        exchange.fail(400, 'BAD_REQUEST', error instanceof Error ? error.message : String(error))
      }
    }, { access: 'guarded', permission: 'platform.update.apply' })

    http.register('POST', '/api/update/apply', async (exchange) => {
      if (!requirePermission(exchange, 'platform.update.apply')) return
      const input = (exchange.body ?? {}) as { dryRun?: boolean; reason?: string; pin?: string }
      try {
        exchange.ok(await service.applyUpdate({ dryRun: input.dryRun === true, reason: input.reason, pin: input.pin, actor: actorOf(exchange) }))
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        exchange.fail(400, 'APPLY_FAILED', message)
      }
    }, { access: 'guarded', permission: 'platform.update.apply' })
    http.register('POST', '/api/update/rollback', async (exchange) => {
      if (!requirePermission(exchange, 'platform.update.apply')) return
      const input = (exchange.body ?? {}) as { reason?: string }
      try {
        exchange.ok(await service.rollbackUpdate({ reason: input.reason, actor: actorOf(exchange) }))
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        exchange.fail(400, 'ROLLBACK_FAILED', message)
      }
    }, { access: 'guarded', permission: 'platform.update.apply' })
  },
}

// ---------------------------------------------------------------------------
// Outils Agent (en session dsh, le langage naturel suffit pour vérifier/mettre à jour la plateforme)
// ---------------------------------------------------------------------------

export const updateTools = {
  name: 'update-tools',
  inject: ['tools', 'opsStorage', 'platformBus', 'update'],
  apply(ctx: Context) {
    const service = ctx.update
    const t = ctx.tools

    t.register(defineTool({
      name: 'update_status',
      description: '查看平台版本与上游更新状态：当前版本、安装形态（source=git 检出 / bundle=市场安装）、最新版本、是否落后及落后提交数、最近检查时间与自动检查设置。',
      permission: 'platform.update.read',
      parameters: {},
      output: { type: 'object', additionalProperties: true },
      async execute() {
        return service.status()
      },
    }))

    t.register(defineTool({
      name: 'update_check',
      description: '立即向上游仓库（GitHub）发起一次更新检查并返回最新状态（60 秒冷却）。发现新版本会广播平台事件并留审计记录。',
      permission: 'platform.update.read',
      parameters: {},
      output: { type: 'object', additionalProperties: true },
      async execute() {
        return await service.checkNow({ manual: true })
      },
    }))

    t.register(defineTool({
      name: 'update_apply',
      description: '执行平台升级（仅 source 安装形态）：git pull --ff-only + npm install，完成后需重启进程生效。dryRun=true 只预演不执行。bundle 形态返回宿主侧升级命令指引。reason 必填（永久留痕）。',
      permission: 'platform.update.apply',
      parameters: {
        dryRun: { type: 'boolean', description: '预演模式：只返回将执行的步骤，不做任何变更' },
        reason: { type: 'string', description: '升级原因（留痕要求，正式执行时必填）' },
        pin: { type: 'string', description: '升级目标钉扎（tag/commit/分支，如 v1.1.0）；正式执行必填，禁止裸拉最新（OPT-P2-03）' },
      },
      output: { type: 'object', additionalProperties: true },
      async execute(args) {
        const dryRun = args.dryRun === true
        const reason = String(args.reason ?? '')
        if (!dryRun && !reason.trim()) throw new Error(translate('正式执行升级必须给出 reason（留痕要求）'))
        return await service.applyUpdate({ dryRun, reason, pin: args.pin === undefined ? undefined : String(args.pin), actor: { id: 'tool:update_apply', name: 'dsh Agent' } })
      },
    }))
  },
}

// ---------------------------------------------------------------------------
// Entrée de l'extension
// ---------------------------------------------------------------------------

export const name = 'update'
export const inject = ['httpServer', 'opsStorage', 'platformBus', 'tools', 'audit']

export function apply(ctx: Context, config: UpdateConfig = {}) {
  // Le service lui-même (vérification automatique planifiée au démarrage du service)
  ctx.plugin(UpdateService, config)
  // REST + outils Agent (la sous-extension réutilise la même instance via la clé de service ctx.update)
  ctx.plugin(updateApi)
  ctx.plugin(updateTools)
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    update: UpdateService
  }
}
