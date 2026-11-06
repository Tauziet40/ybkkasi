/**
 * Justificatif d'utilisation d'actif (2026-10-31) : fait d'utilisation rapporté activement par l'Agent après usage d'un actif de la plateforme (skill/MCP).
 *
 * Positionnement (rapport avec les événements de metering, référentiel du guide d'intégration §4.4/§4.7) :
 *   - usage_events est le pipeline de facturation (référentiel tarif/coût) : les appels via les passerelles de la plateforme sont automatiquement mesurés par la plateforme, la double poussée est interdite ;
 *   - le présent justificatif est un « fait d'utilisation » : des usages invisibles de la plateforme comme le téléchargement du skill.zip pour exécution locale sont rapportés par l'Agent à chaque fois,
 *     comme justificatif d'utilisation côté exploitation d'actif (registre usageReports30d / inscription à chaque fois dans l'audit).
 *
 * Boucle d'autorisation (pas de nouvelle primitive d'autorisation, la validation s'appuie sur les « enregistrements d'acquisition » existants) :
 *   - skill : arête de dépendance d'install (resourceCore, agent→skill) ∪ flux de downloads (skill~downloads.json,
 *     le principal machine apparie par principalId — la route download enregistre pour un appelant machine exactement le principalId) ;
 *   - mcp : même référentiel que le plan de données — un groupe de permissions dont les subjects contiennent cet agent et dont les policies couvrent le service cible.
 * Un principal machine qui rapporte sans avoir acquis → 403 (passer d'abord par la chaîne d'acquisition) ; un human tenant usage.write peut rapporter pour autrui (attribution human).
 *
 * Direction des dépendances : ce module n'accède à skillHub/mcpRegistry/resourceCore qu'à l'exécution via ctx (pas d'inject au niveau extension) —
 * skillhub/mcp/agent injectent tous usage, une dépendance inverse d'UsageService ferait une boucle ; les routes REST et l'outil MCP partagent cette orchestration.
 */
import { t } from '../../platform-i18n/src/index.ts'
import type { CallerInfo, Collection, RecordBase } from '../../platform-core/src/index.ts'

/** Domaine d'actif rapporté (v1 : skill/MCP ; étendre additive de nouveaux types sans changer la sémantique des champs existants). */
export type AssetUsageAssetType = 'skill' | 'mcp'

/** Enregistrement de flux de justificatif (collection usage:assetReports, append-only ; unicité de la clé idempotente). */
export interface AssetUsageReportRecord extends RecordBase {
  assetType: AssetUsageAssetType
  /** Référence d'actif au moment du rapport conservée telle quelle (id ou slug). */
  assetRef: string
  /** Même clé que la clé de registre (skill:<id> / mcp:<slug>) — ligne de registre et flux de justificatif s'interrogent directement. */
  assetKey: string
  assetName: string
  assetVersion?: string
  action: string
  occurredAt: string
  outcome: 'success' | 'failure'
  durationMs?: number
  tokens?: number
  taskId?: string
  note?: string
  /** Clé idempotente globalement unique (convention <identifiant-agent>:<numéro de dossier métier>, rejeu de même clé même contenu sûr, même clé contenu différent refusé). */
  idempotencyKey: string
  /** Si occurredAt a été explicitement fourni par l'appelant (l'heure générée implicitement côté serveur n'entre pas dans l'empreinte idempotente, garantissant le rejeu sûr des essais sans occurredAt). */
  occurredAtExplicit?: boolean
  reporterType: 'machine' | 'human'
  reporterPrincipalId: string
  reporterName: string
  /** Renseigné quand machine et refType=agent (attribution par Agent côté exploitation). */
  agentId?: string
  /** Renseigné lors d'un rapport pour autrui par un human. */
  userId?: string
}

/** Entrées REST/outils (tout champ optionnel est complété par la validation de prepare). */
export interface AssetUsageReportInput {
  assetType?: string
  assetRef?: string
  assetVersion?: string
  action?: string
  occurredAt?: string
  outcome?: string
  durationMs?: number
  tokens?: number
  taskId?: string
  note?: string
  idempotencyKey?: string
}

/** Face d'accès inter-domaines minimale requise par l'orchestration prepare (passée à l'exécution via ctx, sans inject au niveau extension — contre la dépendance circulaire). */
export interface AssetUsageCheckCtx {
  skillHub: {
    skills(): Collection<{ id: string; slug: string; name: string; currentVersion: string }>
    downloads(): Collection<{ skillId: string; version: string; userId: string }>
  }
  mcpRegistry: {
    services(): Collection<{ id: string; slug: string; name: string; currentVersion: string }>
    permGroups(): Collection<{ id: string; policies: Record<string, unknown>; subjects: Array<{ type: string; id: string }> }>
  }
  resourceCore: {
    dependencies(): Collection<{ kind: string; fromType: string; fromId: string; toType: string; toId: string }>
  }
}

/** Erreur de rapport avec code de statut : la route REST fait exchange.fail selon status, la face outils expose selon message. */
export class AssetUsageError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

/** Fenêtre de complément : le justificatif est un fait d'utilisation, le complément n'est permis que sur les 30 derniers jours (contre la dilution du référentiel d'exploitation par un rétroadage massif). */
const BACKFILL_WINDOW_MS = 30 * 86_400_000
/** Léger décalage d'horloge toléré sur occurredAt (dans les 5 minutes à venir = dérive d'horloge, plus de refus strict). */
const CLOCK_SKEW_MS = 5 * 60_000
/** Forme de la liste blanche d'action : lettre minuscule en tête, minuscules/chiffres/soulignés, ≤32 caractères. */
const ACTION_PATTERN = /^[a-z][a-z0-9_]{0,31}$/

/** Empreinte idempotente : comparaison après normalisation des champs sémantiques (même clé même contenu rejoué → deduped ; même clé contenu différent → 409).
 *  occurredAt n'entre en compte que s'il est explicitement fourni par l'appelant — l'implicite « heure serveur du moment » diffère nécessairement à la retry,
 *  l'inclure dans l'empreinte ferait juger « contenu différent » un rejeu légitime sans occurredAt (enfreignant la promesse de rejeu sûr). */
export function reportFingerprint(report: Pick<AssetUsageReportRecord, 'assetType' | 'assetKey' | 'assetVersion' | 'action' | 'occurredAt' | 'occurredAtExplicit' | 'outcome' | 'durationMs' | 'tokens' | 'taskId' | 'note'>): string {
  return JSON.stringify([
    report.assetType, report.assetKey, report.assetVersion ?? '', report.action,
    report.occurredAtExplicit ? report.occurredAt : '', report.outcome, report.durationMs ?? -1, report.tokens ?? -1,
    report.taskId ?? '', report.note ?? '',
  ])
}

/**
 * Orchestration du rapport : validation des champs → existence de l'actif (contre l'invention) → relation d'autorisation (boucle d'acquisition) → normalisation.
 * Renvoie après passage une charge d'enregistrement directement inscriptible (sans id/createdAt/updatedAt — complétés par submitAssetUsageReport à l'inscription dans la collection).
 */
export function prepareAssetUsageReport(ctx: AssetUsageCheckCtx, input: AssetUsageReportInput, caller: CallerInfo): Omit<AssetUsageReportRecord, 'id' | 'createdAt' | 'updatedAt'> {
  // -- 1. validation des champs -----------------------------------------------------------
  const assetType = input.assetType
  if (assetType !== 'skill' && assetType !== 'mcp') {
    throw new AssetUsageError(400, 'INVALID_ASSET_TYPE', t('assetType 必须是 skill 或 mcp（收到：{value}）', { value: String(assetType ?? '') }))
  }
  const assetRef = String(input.assetRef ?? '').trim()
  if (assetRef === '' || assetRef.length > 200) {
    throw new AssetUsageError(400, 'INVALID_ASSET_REF', t('assetRef 必填（skill 的 id 或 slug / mcp 的 slug），长度 1~200'))
  }
  const action = input.action === undefined || String(input.action).trim() === '' ? 'invoke' : String(input.action).trim()
  if (!ACTION_PATTERN.test(action)) {
    throw new AssetUsageError(400, 'INVALID_ACTION', t('action 只允许小写字母开头、字母/数字/下划线且 ≤32 字符（收到：{value}）', { value: action }))
  }
  const occurredAtExplicit = !(input.occurredAt === undefined || String(input.occurredAt).trim() === '')
  const occurredAt = occurredAtExplicit ? String(input.occurredAt).trim() : new Date().toISOString()
  const occurred = Date.parse(occurredAt)
  if (Number.isNaN(occurred)) {
    throw new AssetUsageError(400, 'INVALID_OCCURRED_AT', t('occurredAt 必须是 ISO8601 时间（收到：{value}）', { value: occurredAt }))
  }
  const now = Date.now()
  if (occurred > now + CLOCK_SKEW_MS) {
    throw new AssetUsageError(400, 'OCCURRED_AT_IN_FUTURE', t('occurredAt 不允许晚于当前时间（收到：{value}）', { value: occurredAt }))
  }
  if (now - occurred > BACKFILL_WINDOW_MS) {
    throw new AssetUsageError(400, 'OCCURRED_AT_OUT_OF_WINDOW', t('occurredAt 超出补录窗口（仅允许近 30 天，收到：{value}）', { value: occurredAt }))
  }
  const outcome = input.outcome === undefined || String(input.outcome).trim() === '' ? 'success' : String(input.outcome).trim()
  if (outcome !== 'success' && outcome !== 'failure') {
    throw new AssetUsageError(400, 'INVALID_OUTCOME', t('outcome 只允许 success 或 failure（收到：{value}）', { value: outcome }))
  }
  for (const [field, value] of [['durationMs', input.durationMs], ['tokens', input.tokens]] as const) {
    if (value !== undefined && (!Number.isFinite(value) || !Number.isInteger(value) || value < 0)) {
      throw new AssetUsageError(400, `INVALID_${field.toUpperCase()}`, t('{field} 必须是非负整数（收到：{value}）', { field, value: String(value) }))
    }
  }
  const idempotencyKey = String(input.idempotencyKey ?? '').trim()
  if (idempotencyKey === '' || idempotencyKey.length > 200) {
    throw new AssetUsageError(400, 'INVALID_IDEMPOTENCY_KEY', t('idempotencyKey 必填（约定 <agent标识>:<业务单号>），长度 1~200'))
  }
  const textOf = (value: string | undefined, field: string, max: number): string | undefined => {
    if (value === undefined) return undefined
    const trimmed = String(value).trim()
    if (trimmed === '') return undefined
    if (trimmed.length > max) throw new AssetUsageError(400, `INVALID_${field.toUpperCase()}`, t('{field} 长度不得超过 {max}', { field, max: String(max) }))
    return trimmed
  }
  const assetVersion = textOf(input.assetVersion, 'assetVersion', 64)
  const taskId = textOf(input.taskId, 'taskId', 200)
  const note = textOf(input.note, 'note', 500)

  // -- 2. existence de l'actif (un actif inexistant ne peut être rapporté, contre les justificatifs inventés) -----------------------
  let assetKey: string
  let assetName: string
  let skillId: string | undefined
  let mcpSlug: string | undefined
  if (assetType === 'skill') {
    const skill = ctx.skillHub.skills().all().find((item) => item.id === assetRef || item.slug === assetRef)
    if (!skill) throw new AssetUsageError(404, 'ASSET_NOT_FOUND', t('Skill 不存在：{ref}（先在 Skill 市场确认资产已上架，再走获取链路）', { ref: assetRef }))
    // la clé de metering/registre d'un skill emploie toujours l'ID (le slug contient du non-ASCII, voir la note meterSkillUsage de plugin-skillhub)
    assetKey = `skill:${skill.id}`
    assetName = skill.name
    skillId = skill.id
  } else {
    const service = ctx.mcpRegistry.services().all().find((item) => item.id === assetRef || item.slug === assetRef)
    if (!service) throw new AssetUsageError(404, 'ASSET_NOT_FOUND', t('MCP 服务不存在：{ref}（先确认服务已纳管，再走获取链路）', { ref: assetRef }))
    assetKey = `mcp:${service.slug}`
    assetName = service.name
    mcpSlug = service.slug
  }

  // -- 3. relation d'autorisation (le principal machine doit avoir acquis l'actif ; le human tenant usage.write rapportant pour autrui est dispensé de validation) -----
  const base = {
    assetType, assetRef, assetKey, assetName,
    ...(assetVersion !== undefined ? { assetVersion } : {}),
    action,
    occurredAt: new Date(occurred).toISOString(),
    ...(occurredAtExplicit ? { occurredAtExplicit: true } : {}),
    outcome: outcome as 'success' | 'failure',
    ...(input.durationMs !== undefined ? { durationMs: input.durationMs } : {}),
    ...(input.tokens !== undefined ? { tokens: input.tokens } : {}),
    ...(taskId !== undefined ? { taskId } : {}),
    ...(note !== undefined ? { note } : {}),
    idempotencyKey,
  }
  if (caller.kind !== 'machine') {
    return { ...base, reporterType: 'human', reporterPrincipalId: caller.principalId, reporterName: caller.name, ...(caller.userId !== undefined ? { userId: caller.userId } : {}) }
  }
  if (caller.refType !== 'agent' || !caller.refId) {
    throw new AssetUsageError(403, 'NO_GRANT', t('机器主体（{refType}）暂不支持凭证提报：本能力面向 Agent 机器身份（refType=agent）', { refType: caller.refType ?? 'unknown' }))
  }
  const agentId = caller.refId
  const granted = assetType === 'skill'
    ? skillGranted(ctx, skillId!, agentId, caller.principalId)
    : mcpGranted(ctx, mcpSlug!, agentId)
  if (!granted) {
    throw new AssetUsageError(403, 'NO_GRANT', t('本 Agent 尚未获取该资产，使用凭证被拒：先完成获取（skill 走 install/download；MCP 走权限组绑定），再提报'))
  }
  return { ...base, reporterType: 'machine', reporterPrincipalId: caller.principalId, reporterName: caller.name, agentId }
}

/** Autorisation skill : arête de dépendance d'install (agent→skill) ∪ flux de downloads (le principal machine apparie par principalId). */
function skillGranted(ctx: AssetUsageCheckCtx, skillId: string, agentId: string, principalId: string): boolean {
  const installed = ctx.resourceCore.dependencies().all().some((edge) =>
    edge.kind === 'skill' && edge.fromType === 'agent' && edge.fromId === agentId && edge.toId === skillId)
  if (installed) return true
  return ctx.skillHub.downloads().all().some((record) => record.skillId === skillId && record.userId === principalId)
}

/** Autorisation mcp : même référentiel que le plan de données — il existe un groupe de permissions dont les subjects contiennent cet agent et dont les policies couvrent le service cible.
 *  Note : ne pas lire attrs.mcpPermGroupIds (champ d'affichage redondant, pouvant dériver des subjects ; le jugement de la passerelle ne reconnaît aussi que les subjects). */
function mcpGranted(ctx: AssetUsageCheckCtx, slug: string, agentId: string): boolean {
  const service = ctx.mcpRegistry.services().all().find((item) => item.slug === slug)
  if (!service) return false
  return ctx.mcpRegistry.permGroups().all().some((group) =>
    group.subjects.some((subject) => subject.type === 'agent' && subject.id === agentId)
    && Object.keys(group.policies).includes(service.id))
}
