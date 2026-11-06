/**
 * Pont dws vers le CLI DingTalk (repli de connexion DingTalk en forme installée porte 01) : l'outil officiel en ligne de commande DingTalk (dingtalk-workspace-cli,
 * préfixe de commande dws) sert de canal sortant de messages en forme installée porte 01 — quand le connecteur/pont DingTalk de la face hôte
 * (plugin-dingtalk-bridge) est absent, la « synchronisation DingTalk » du panneau passe par ce pont en commandes dws chat ; CLI non installé = installation en un clic et état honnête.
 *
 * Motivation (besoin utilisateur 2026-09-11) : la connexion DingTalk du panneau utilise directement le CLI dws ; s'il n'est pas installé sur la machine du client, installation par défaut ;
 * le panneau prend en charge l'interaction CLI-appel-messages. Frontières de conception :
 *   - ce pont est sans identifiants : l'état d'autorisation côté DingTalk appartient au CLI dws lui-même ; le panneau peut « initier pour le compte de » la connexion (dws auth login --device
 *     flux d'appareil, boucle bouclée 2026-09-11) — l'instruction d'activation (lien d'autorisation + code utilisateur) est montrée à l'utilisateur, l'autorisation faite = état de connexion local effectif ;
 *   - plugin-dingtalk-bridge présent (forme complète) → routage/événements entièrement au pont, ce module ne s'enregistre ni ne souscrit ;
 *   - un échec d'envoi est renvoyé tel quel (fin de stdout/stderr), jamais de succès fabriqué ;
 *   - entrant (DingTalk→panneau) : dws chat +chat-messages tire les derniers messages du groupe lié (déduplication idempotente par messageId à l'inscription).
 */
import { spawn } from 'node:child_process'
import type { Context } from '@deepseek-ai/cordis'

/** Configuration de liaison dws (collection opsStorage à enregistrement unique). */
export interface DwsBindingRecord {
  id: string
  /** Groupe DingTalk cible (nom de groupe ou openConversationId, résolu par le CLI dws). */
  group?: string
  boundAt?: string
  boundBy?: string
}

export interface DwsAuthSummary {
  authenticated: boolean
  corpName?: string
  userName?: string
  userId?: string
  expiresAt?: string
  /** Fin de sortie brute en cas d'échec de sonde/non connecté (présentation honnête, jamais d'état de connexion inventé). */
  raw?: string
}

export interface DwsStatus {
  installed: boolean
  version?: string
  mode: 'dws-cli'
  bound: boolean
  group?: string
  installHint: string
  lastError?: string
  auth: DwsAuthSummary
}

/** Instruction d'activation du flux d'appareil (produit de l'analyse du stdout d'dws auth login --device, sortie directe en pop-up). */
export interface DeviceFlowInfo {
  /** Page de vérification de base (sans code utilisateur). */
  link?: string
  userCode?: string
  /** Lien direct en une étape avec user_code (le bouton principal de la pop-up pointe dessus). */
  verifyUrl?: string
  expiresInSeconds?: number
}

const INSTALL_CMD = 'npm install -g dingtalk-workspace-cli'
const INSTALL_HINT = `未检测到 dws CLI（钉钉官方命令行）。一键安装（本面板按钮）或手动执行：${INSTALL_CMD}；安装后在面板「钉钉连接」发起登录（设备码授权）完成钉钉授权。`
const SPAWN_TIMEOUT_MS = 20_000
const INSTALL_TIMEOUT_MS = 240_000
const OUTPUT_CAP = 8_000
/** Validité du code d'autorisation du flux d'appareil : 900 s (déclaré par la sortie du CLI) ; le timeout du processus laisse large marge, expiration = kill anti-suspension. */
const LOGIN_TIMEOUT_MS = 960_000
/** Après lancement de la connexion, plafond d'attente de l'apparition de l'instruction d'activation (lien+code utilisateur) dans le stdout. */
const LOGIN_INFO_WAIT_MS = 25_000
/** Cache de sonde dws auth status : le positif prévient les spawns à haute fréquence ; le scrutin d'état terminal force toujours. */
const AUTH_CACHE_MS = 15_000

/** Session de connexion par flux d'appareil (handle de processus + tampon de sortie progressif ; l'état d'autorisation reste au CLI dws, le panneau n'observe que). */
interface LoginSession {
  child?: ReturnType<typeof spawn>
  stdout: string
  stderr: string
  startedAt: number
  exited: boolean
  exitOk: boolean
  timer?: ReturnType<typeof setTimeout>
}

/** Stockage de liaison dws (enregistrement unique, id fixe 'dws'). */
export function dwsBinding(ctx: Context) {
  return ctx.opsStorage.collection<DwsBindingRecord>('panel:dingtalk')
}

function readBinding(ctx: Context): DwsBindingRecord | undefined {
  return dwsBinding(ctx).get('dws')
}

/** Assemblage de ligne de commande sûr par référence (règles de guillemets cmd Windows : envelopper de guillemets doubles suffit quand le contenu n'en contient pas). */
const quote = (value: string): string => (/[^\w@%+=:,./-]/.test(value) ? `"${value.replace(/"/g, '')}"` : value)

function exec(command: string, args: string[], timeoutMs: number): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const line = [command, ...args.map(quote)].join(' ')
    const child = spawn(line, [], {
      shell: true,
      windowsHide: true,
      env: { ...process.env },
    })
    let stdout = ''
    let stderr = ''
    let settled = false
    const finish = (ok: boolean) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ ok, stdout: stdout.slice(-OUTPUT_CAP), stderr: stderr.slice(-OUTPUT_CAP) })
    }
    const timer = setTimeout(() => {
      try { child.kill() } catch { /* processus déjà terminé */ }
      finish(false)
    }, timeoutMs)
    child.stdout?.on('data', (chunk) => { stdout += String(chunk) })
    child.stderr?.on('data', (chunk) => { stderr += String(chunk) })
    child.on('error', (error) => {
      stderr += String(error)
      finish(false)
    })
    child.on('close', (code) => finish(code === 0))
  })
}

/**
 * Analyse de la sortie d'dws auth login --device (fonction pure, testée directement par selftest) : extrait l'instruction
 * d'activation d'une sortie progressive lisible par l'humain. Forme constatée (dws v1.0.61) :
 *   link: https://login.dingtalk.com/oauth2/device/verify.htm
 *   authorization code: VSGN-KGWV
 *   https://login.dingtalk.com/oauth2/device/verify.htm?user_code=VSGN-KGWV
 *   Authorization code will expire in 900 seconds.
 */
export function parseDeviceFlowOutput(text: string): DeviceFlowInfo {
  const link = text.match(/link:\s*(https?:\/\/\S+)/)?.[1]
  const userCode = text.match(/authorization code:\s*([A-Za-z0-9-]+)/i)?.[1]
    ?? text.match(/user_code=([A-Za-z0-9-]+)/)?.[1]
  const expiresInSeconds = Number(text.match(/expire in (\d+) seconds/i)?.[1] ?? 0) || undefined
  const combined = text.match(/https?:\/\/\S*user_code=[A-Za-z0-9-]+/)?.[0]
  if (link && userCode) return { link, userCode, verifyUrl: `${link}?user_code=${userCode}`, ...(expiresInSeconds ? { expiresInSeconds } : {}) }
  // Repli : certaines versions ne donnent qu'un lien complet avec user_code
  if (combined) return { verifyUrl: combined, ...(userCode ? { userCode } : {}), ...(expiresInSeconds ? { expiresInSeconds } : {}) }
  return {
    ...(link ? { link } : {}),
    ...(userCode ? { userCode } : {}),
    ...(expiresInSeconds ? { expiresInSeconds } : {}),
  }
}

/** Sortie dws auth status --format json → résumé d'autorisation (échec/non connecté = toujours authenticated:false + fin de raw). */
export function parseAuthStatus(text: string): DwsAuthSummary {
  try {
    const parsed = JSON.parse(text) as {
      authenticated?: boolean
      corp_name?: string
      user_name?: string
      user_id?: string | number
      expires_at?: string
    }
    if (parsed?.authenticated !== true) return { authenticated: false, ...(text.trim() ? { raw: text.slice(-400) } : {}) }
    return {
      authenticated: true,
      ...(parsed.corp_name ? { corpName: parsed.corp_name } : {}),
      ...(parsed.user_name ? { userName: parsed.user_name } : {}),
      ...(parsed.user_id !== undefined ? { userId: String(parsed.user_id) } : {}),
      ...(parsed.expires_at ? { expiresAt: parsed.expires_at } : {}),
    }
  } catch {
    return { authenticated: false, ...(text.trim() ? { raw: text.slice(-400) } : {}) }
  }
}

/** Disponibilité du CLI dws (sonde de version, résultat en cache 30 s — la sonde est en millisecondes mais évite les spawns à haute fréquence). */
export class DwsCli {
  private versionCache: { at: number; installed: boolean; version?: string } | undefined
  private authCache: { at: number; auth: DwsAuthSummary } | undefined
  /** Session de login par flux d'appareil en cours (au plus une à la fois sur la machine ; relancer évince l'ancienne). */
  private loginSession: LoginSession | undefined

  private readonly ctx: Context

  constructor(ctx: Context) {
    this.ctx = ctx
  }

  async probe(force = false): Promise<{ installed: boolean; version?: string }> {
    const cached = this.versionCache
    if (!force && cached && Date.now() - cached.at < 30_000) return cached
    const result = await exec('dws', ['--version'], 10_000)
    const version = result.ok ? result.stdout.trim().split(/\r?\n/)[0]?.trim() : undefined
    const probed = { at: Date.now(), installed: result.ok && Boolean(version), version }
    this.versionCache = probed
    return probed
  }

  /**
   * Sonde d'état d'autorisation (dws auth status). Non installé/non connecté/sortie anormale = toujours authenticated:false + fin de raw,
   * jamais « échec de sonde » maquillé en « connecté » ni l'inverse. Résultat en cache 15 s ; le jugement d'état terminal de connexion force.
   */
  async authStatus(force = false): Promise<DwsAuthSummary> {
    const cached = this.authCache
    if (!force && cached && Date.now() - cached.at < AUTH_CACHE_MS) return cached.auth
    const result = await exec('dws', ['auth', 'status', '--format', 'json', '--timeout', '15'], 20_000)
    // Non connecté, le CLI peut sortir en code non nul mais émettre quand même le JSON — stdout analysé inconditionnellement, code de sortie purement indicatif
    const auth = parseAuthStatus(result.stdout || result.stderr)
    this.authCache = { at: Date.now(), auth }
    return auth
  }

  /** Face état (consommée par la pastille du panneau/la pop-up de liaison). */
  async status(): Promise<DwsStatus> {
    const { installed, version } = await this.probe()
    const binding = readBinding(this.ctx)
    const auth = installed
      ? await this.authStatus().catch(() => ({ authenticated: false } as DwsAuthSummary))
      : { authenticated: false }
    return {
      installed,
      ...(version ? { version } : {}),
      mode: 'dws-cli',
      bound: Boolean(binding?.group),
      ...(binding?.group ? { group: binding.group } : {}),
      installHint: installed ? '' : INSTALL_HINT,
      auth,
    }
  }

  /** Installation en un clic (npm -g pour le CLI officiel) ; déjà installé = succès direct. Long, la face appelante doit exiger panel.config.write. */
  async install(): Promise<{ ok: boolean; message: string }> {
    const { installed, version } = await this.probe(true)
    if (installed) return { ok: true, message: `dws CLI 已安装（${version}），无需重复安装` }
    const result = await exec(INSTALL_CMD, [], INSTALL_TIMEOUT_MS)
    const tail = (result.stdout + result.stderr).trim().split(/\r?\n/).slice(-6).join('\n')
    const after = await this.probe(true)
    if (after.installed) {
      return { ok: true, message: `dws CLI 安装完成（${after.version}）。可在面板「钉钉连接」直接发起登录（设备码授权），或终端执行 dws auth login` }
    }
    return {
      ok: false,
      message: `dws CLI 自动安装失败（npm 退出码非 0）。请手动执行：${INSTALL_CMD}\n${tail}`,
    }
  }

  // -- Face connexion-autorisation (besoin utilisateur 2026-09-11 : le panneau initie la connexion dws, non connecté = pop-up de l'instruction d'activation) ---------------

  /**
   * Connexion initiée pour le compte de (dws auth login --device flux d'appareil) : le CLI monte un scrutin local et imprime l'instruction d'activation (lien d'autorisation +
   * code utilisateur), le panneau la montre à l'utilisateur ; dès que l'utilisateur autorise sur un appareil quelconque, le scrutin du CLI obtient le token, l'état de connexion local prend effet.
   * Déjà connecté → already:true court-circuit idempotent ; session déjà en cours → réutilisation directe (idempotent, pas de double processus).
   */
  async startLogin(): Promise<
    | { started: true; verifyUrl: string; userCode?: string; expiresInSeconds?: number }
    | { started: false; already?: true; auth?: DwsAuthSummary; message?: string }
  > {
    const auth = await this.authStatus(true)
    if (auth.authenticated) return { started: false, already: true, auth }
    // Session existante avec instruction d'activation déjà sortie → réutilisation idempotente (clics répétés du bouton de scrutin front sûrs)
    const existing = this.loginSession
    if (existing && !existing.exited) {
      const info = parseDeviceFlowOutput(existing.stdout)
      if (info.verifyUrl) {
        return { started: true, verifyUrl: info.verifyUrl, ...(info.userCode ? { userCode: info.userCode } : {}), ...(info.expiresInSeconds ? { expiresInSeconds: info.expiresInSeconds } : {}) }
      }
      // L'instruction n'est pas encore sortie : continuer à attendre (pas de double processus)
      const waited = await this.waitForLoginInfo(existing)
      if (waited.verifyUrl) return { started: true, verifyUrl: waited.verifyUrl, ...(waited.userCode ? { userCode: waited.userCode } : {}), ...(waited.expiresInSeconds ? { expiresInSeconds: waited.expiresInSeconds } : {}) }
      if (!existing.exited) return { started: false, message: 'dws 登录进程在位但激活指令未就绪，请稍后在状态轮询中重试' }
    }
    this.cancelLogin()
    const { installed } = await this.probe()
    if (!installed) return { started: false, message: INSTALL_HINT }
    const session: LoginSession = { stdout: '', stderr: '', startedAt: Date.now(), exited: false, exitOk: false }
    const line = ['dws', 'auth', 'login', '--device'].join(' ')
    const child = spawn(line, [], { shell: true, windowsHide: true, env: { ...process.env } })
    session.child = child
    child.stdout?.on('data', (chunk) => { session.stdout += String(chunk) })
    child.stderr?.on('data', (chunk) => { session.stderr += String(chunk) })
    child.on('error', (error) => { session.stderr += String(error); session.exited = true })
    child.on('close', (code) => { session.exited = true; session.exitOk = code === 0 })
    session.timer = setTimeout(() => {
      try { child.kill() } catch { /* processus déjà terminé */ }
      session.exited = true
    }, LOGIN_TIMEOUT_MS)
    this.loginSession = session
    const info = await this.waitForLoginInfo(session)
    if (info.verifyUrl) {
      return { started: true, verifyUrl: info.verifyUrl, ...(info.userCode ? { userCode: info.userCode } : {}), ...(info.expiresInSeconds ? { expiresInSeconds: info.expiresInSeconds } : {}) }
    }
    if (session.exited) {
      const tail = (session.stderr || session.stdout).trim().split(/\r?\n/).slice(-4).join('；')
      this.loginSession = undefined
      return { started: false, message: `dws 登录进程启动失败：${tail || '退出码非 0'}` }
    }
    return { started: false, message: 'dws 登录进程已启动但激活指令迟迟未输出（请检查 dws 版本 ≥1.0），稍后可在状态面重试' }
  }

  /** Attend l'instruction d'activation dans le tampon de sortie (pas de 300 ms, plafond LOGIN_INFO_WAIT_MS). */
  private waitForLoginInfo(session: LoginSession): Promise<DeviceFlowInfo> {
    return new Promise((resolve) => {
      const deadline = Date.now() + LOGIN_INFO_WAIT_MS
      const step = () => {
        const info = parseDeviceFlowOutput(session.stdout)
        if (info.verifyUrl) return resolve(info)
        if (session.exited || Date.now() > deadline) return resolve(info)
        setTimeout(step, 300)
      }
      step()
    })
  }

  /**
   * État de la session de connexion (scrutin front 3 s) : processus en place → active + instruction d'activation ; processus sorti → re-contrôle forcé de l'autorisation
   * et consommation de la session sur place (succès/échec tous deux terminaux, pas de suspension).
   */
  async loginState(): Promise<{ active: boolean; authenticated: boolean; verifyUrl?: string; userCode?: string; expiresInSeconds?: number; message?: string; auth?: DwsAuthSummary }> {
    const session = this.loginSession
    const auth = await this.authStatus(session?.exited === true)
    if (!session) return { active: false, authenticated: auth.authenticated, auth }
    const info = parseDeviceFlowOutput(session.stdout)
    if (!session.exited) {
      return { active: true, authenticated: auth.authenticated, ...(info.verifyUrl ? { verifyUrl: info.verifyUrl } : {}), ...(info.userCode ? { userCode: info.userCode } : {}), ...(info.expiresInSeconds ? { expiresInSeconds: info.expiresInSeconds } : {}), auth }
    }
    // Processus déjà sorti : re-contrôler l'état terminal et consommer la session
    this.loginSession = undefined
    clearTimeout(session.timer)
    if (auth.authenticated) return { active: false, authenticated: true, auth }
    const tail = (session.stderr || session.stdout).trim().split(/\r?\n/).slice(-3).join('；')
    return { active: false, authenticated: false, auth, message: session.exitOk ? 'dws 登录进程已结束但授权态未生效（可能授权码过期），请重新发起' : `dws 登录未完成：${tail || '进程非正常退出，请重新发起'}` }
  }

  /** Annule la connexion en cours (kill du processus + nettoyage ; sans session = no-op idempotent). */
  cancelLogin(): void {
    const session = this.loginSession
    if (!session) return
    this.loginSession = undefined
    clearTimeout(session.timer)
    try { session.child?.kill() } catch { /* processus déjà terminé */ }
  }

  /** Lie/re-lie le groupe cible (nom de groupe ou ID de conversation stocké, résolu par dws à la livraison). */
  bind(group: string, boundBy: string): DwsBindingRecord {
    const trimmed = group.trim()
    if (!trimmed) throw new Error('群名/会话 ID 必填')
    const collection = dwsBinding(this.ctx)
    const existing = collection.get('dws')
    const record = existing
      ? collection.update('dws', { group: trimmed, boundAt: new Date().toISOString(), boundBy })
      : collection.insert({ id: 'dws', group: trimmed, boundAt: new Date().toISOString(), boundBy })
    return record
  }

  unbind(): void {
    const binding = readBinding(this.ctx)
    if (binding) dwsBinding(this.ctx).remove('dws')
  }

  /**
   * Livraison sortante : dws chat +send-to-group --group <groupe> --content <texte> (--format json pour juger structuré du résultat).
   * Échec = erreur levée (l'appelant inscrit audit/événement pour trace), jamais silencieux.
   */
  async sendToGroup(text: string, group?: string): Promise<{ group: string; version?: string }> {
    // Le contrôle préalable de liaison (lecture synchrone sans coût) précède la sonde par sous-processus probe : cette méthode est appelée en fire-and-forget
    // par le crochet d'événement panel.message.created, la latence du reçu détermine directement la vitesse d'écriture de l'état terminal ddSync du panneau —
    // groupe non lié est l'état d'échec le plus fréquent, il ne mérite pas un spawn dws --version gratuit (plusieurs secondes sous charge, racine de la course QA T-04).
    const target = group?.trim() || readBinding(this.ctx)?.group
    if (!target) throw new Error('未绑定钉钉群：请先在面板「钉钉」绑定目标群')
    const { installed, version } = await this.probe()
    if (!installed) throw new Error(`dws CLI 未安装，无法投递。${INSTALL_HINT}`)
    const result = await exec('dws', ['chat', '+send-to-group', '--group', target, '--content', text, '--format', 'json'], SPAWN_TIMEOUT_MS)
    if (!result.ok) {
      const tail = (result.stderr || result.stdout).trim().split(/\r?\n/).slice(-4).join('；')
      throw new Error(`dws 投递失败：${tail || 'dws 命令退出码非 0（请检查 dws login 授权态与群名）'}`)
    }
    // Quand dws --format json produit {ok:false}, le code de sortie de la commande peut rester 0 — juger sur le retour réel
    try {
      const parsed = JSON.parse(result.stdout) as { ok?: boolean; error?: { message?: string } | string }
      if (parsed && parsed.ok === false) {
        const reason = typeof parsed.error === 'string' ? parsed.error : parsed.error?.message
        throw new Error(`dws 投递失败：${reason ?? 'CLI 返回 ok:false'}`)
      }
    } catch (error) {
      if (error instanceof SyntaxError) { /* sortie non JSON (ancienne CLI) → on s'en tient au code de sortie, considéré comme succès */ } else { throw error }
    }
    return { group: target, ...(version ? { version } : {}) }
  }

  /**
   * Tirage entrant : dws chat +chat-messages lit les derniers messages du groupe lié (par défaut --limit messages en remontant depuis maintenant).
   * Renvoie des messages normalisés (createTime analysé du fuseau local de la sortie dws en ISO) ; échec = erreur levée, jamais silencieux.
   */
  async pullLatestMessages(limit = 20, group?: string): Promise<Array<{ messageId: string; sender: string; text: string; createdAt: string }>> {
    const { installed } = await this.probe()
    if (!installed) throw new Error(`dws CLI 未安装，无法拉取。${INSTALL_HINT}`)
    const target = group?.trim() || readBinding(this.ctx)?.group
    if (!target) throw new Error('未绑定钉钉群：请先在面板「钉钉」绑定目标群')
    const capped = Math.min(Math.max(Math.floor(limit) || 20, 1), 50)
    const result = await exec('dws', ['chat', '+chat-messages', '--group', target, '--limit', String(capped), '--no-reactions', '--format', 'json'], SPAWN_TIMEOUT_MS)
    if (!result.ok) {
      const tail = (result.stderr || result.stdout).trim().split(/\r?\n/).slice(-4).join('；')
      throw new Error(`dws 拉取失败：${tail || 'dws 命令退出码非 0（请检查 dws login 授权态与群名）'}`)
    }
    let parsed: {
      ok?: boolean
      error?: { message?: string } | string
      messages?: Array<{ messageId?: string; sender?: string; text?: string; createTime?: string }>
    }
    try {
      parsed = JSON.parse(result.stdout) as typeof parsed
    } catch {
      throw new Error('dws 拉取失败：CLI 返回了无法解析的输出（请检查 dws 版本 ≥1.0）')
    }
    if (parsed && parsed.ok === false) {
      const reason = typeof parsed.error === 'string' ? parsed.error : parsed.error?.message
      throw new Error(`dws 拉取失败：${reason ?? 'CLI 返回 ok:false'}`)
    }
    return (parsed.messages ?? [])
      .filter((m) => m.messageId && (m.text ?? '').trim())
      .map((m) => ({
        messageId: String(m.messageId),
        sender: String(m.sender ?? '钉钉成员'),
        text: String(m.text ?? '').trim(),
        // dws createTime est de la forme "YYYY-MM-DD HH:mm:ss" en fuseau local → analyse en fuseau local
        createdAt: new Date(String(m.createTime ?? '').replace(' ', 'T')).toISOString(),
      }))
  }
}
