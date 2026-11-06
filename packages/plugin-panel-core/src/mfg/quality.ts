/**
 * Boîte à outils manufacture — passe de libération des Skills et contrôles qualité à l'exécution (intégrée depuis « jeu d'outils IA manufacture » server/quality.ts).
 *
 * Lois d'airain du projet source (docs/skill-quality.md, sémantique inchangée après intégration) :
 *   1. avoir configuré un modèle ≠ ouvrir les outils IA. Il faut vraie évaluation par modèle → revue par un métier → libération versionnée, les trois pas réunis avant l'appel ordinaire ;
 *   2. les contrôles automatiques structure/citations ne valent pas justesse d'un jugement professionnel, le rapport le dit honnêtement ;
 *   3. tout échec de contrôle qualité est livré en erreur (502), jamais rétrogradé en résultat « en apparence réussi ».
 *
 * Points d'adaptation de l'intégration (mise en forme plateforme, consignés dans docs/plan-mfg-toolkit-fusion-20261019.md) :
 *   - l'enregistrement de libération passe du fichier `.local/quality/releases.json` du projet source à une collection de stockage du panneau (interface ReleaseStore,
 *     implémentée par index.ts avec opsStorage ; implémentation mémoire pour les tests) — en forme plateforme, plus de notion de « .local local » ;
 *   - la « dimension protocole » du projet source (une libération par openai/anthropic) converge vers la dimension identifiant de modèle de la plateforme : choix du modèle,
 *     clés et sortie appartiennent désormais à la passerelle de modèles (modelgw / pont llm dsh), le panneau ne détient plus de configuration de protocole ;
 *   - la face d'appel de l'évaluation passe du client env du projet source à la passerelle de modèles de la plateforme (voir evaluate.ts),
 *     le panneau ne détient aucune clé (la frontière « clés seulement côté serveur » du projet source est resserrée en forme plateforme en « clés seulement dans la plateforme »).
 */
import { createHash } from 'node:crypto'
import { skills } from './skills.ts'
import { checkModelOutputSchema, fail, type ModelOutput } from './validate.ts'

/** Empreinte du contenu du Skill : changer le noyau change l'empreinte → la libération existante est immédiatement invalidée. */
export const skillHash = (id: string): string =>
  createHash('sha256').update(JSON.stringify(skills[id] ?? null)).digest('hex')

/** Empreinte de l'identifiant du modèle : changer le nom du modèle ou l'adresse de service change l'empreinte → la libération existante est immédiatement invalidée. */
export const modelIdentityHash = (identity: { model: string; endpoint?: string }): string =>
  createHash('sha256').update(JSON.stringify({ model: identity.model, endpoint: identity.endpoint ?? '' })).digest('hex')

/** Enregistrement de libération : empreinte de rapport + empreinte Skill + empreinte modèle + réviseur + échéance (toute divergence = invalidation). */
export type SkillRelease = {
  skillId: string
  skillHash: string
  modelHash: string
  reportHash: string
  approvedBy: string
  reviewKind: 'domain' | 'technical'
  approvedAt: string
  expiresAt: string
}

/** Rapport d'évaluation sur vrai modèle : un rapport mock live=false ne suffit jamais à libérer. */
export type EvalReport = {
  skillId: string
  skillHash: string
  modelHash: string
  model: string
  protocol: string
  status: 'passed' | 'failed'
  live: boolean
  repetitions: number
  cases: Array<{ id: string; passed: boolean; missing: string[]; forbidden: string[]; durationMs: number }>
  startedAt: string
  finishedAt: string
}

/** Face de stockage des enregistrements de libération (index.ts l'implémente avec une collection opsStorage ; implémentation mémoire pour les tests). */
export interface ReleaseStore {
  get(skillId: string): SkillRelease | undefined
  put(release: SkillRelease): void
  remove(skillId: string): void
  list(): SkillRelease[]
}

/** Implémentation mémoire (tests unitaires et forme sans stockage). */
export class MemoryReleaseStore implements ReleaseStore {
  private map = new Map<string, SkillRelease>()
  get(skillId: string): SkillRelease | undefined { return this.map.get(skillId) }
  put(release: SkillRelease): void { this.map.set(release.skillId, release) }
  remove(skillId: string): void { this.map.delete(skillId) }
  list(): SkillRelease[] { return [...this.map.values()] }
}

/** Durée de libération par défaut (30 jours aussi dans le projet source). */
export const RELEASE_TTL_DAYS = 30

/**
 * Jugement de libération (fail-closed) : empreinte de rapport, marque d'appel réel, statut de passage, empreinte Skill, empreinte modèle, réviseur,
 * échéance — tout manquement = non libéré. C'est le point de contrainte à l'exécution de « configurer un modèle n'ouvre pas automatiquement ».
 */
export function releaseReady(
  store: ReleaseStore,
  skillId: string,
  identity: { model: string; endpoint?: string },
  now = Date.now(),
): { ready: boolean; reason?: string } {
  const release = store.get(skillId)
  if (!release) return { ready: false, reason: '尚无放行记录：需先完成真实模型评估与领域审阅' }
  if (release.skillHash !== skillHash(skillId)) return { ready: false, reason: 'Skill 内核已变更，原放行记录失效，需重新评估' }
  if (release.modelHash !== modelIdentityHash(identity)) return { ready: false, reason: '模型配置已变更，原放行记录失效，需重新评估' }
  if (!release.approvedBy?.trim()) return { ready: false, reason: '放行记录缺少审核人' }
  const expires = Date.parse(release.expiresAt)
  if (!Number.isFinite(expires) || expires <= now) return { ready: false, reason: '放行记录已到期，需重新评估与审阅' }
  return { ready: true }
}

/**
 * Génère un enregistrement de libération à partir du rapport d'évaluation + signature du réviseur.
 * Faces de refus (équivalent d'approve-skill du projet source) : rapport non passé, appel non réel, empreinte divergente, répétitions insuffisantes, réviseur vide.
 */
export function buildRelease(
  report: EvalReport,
  reportText: string,
  reviewer: string,
  reviewKind: 'domain' | 'technical',
  now = Date.now(),
): SkillRelease {
  if (!reviewer?.trim() || reviewer.startsWith('--')) fail('REVIEW_REQUIRED', '审核人不能为空', 400)
  if (report.status !== 'passed') fail('REPORT_NOT_PASSED', '评估报告未通过，拒绝放行', 400)
  if (report.live !== true) fail('REPORT_NOT_LIVE', '报告非真实模型调用产生（mock 或未执行），拒绝放行', 400)
  if (report.repetitions < 3) fail('REPORT_INSUFFICIENT', '评估重复次数不足（每用例至少 3 次），拒绝放行', 400)
  if (report.skillHash !== skillHash(report.skillId)) fail('REPORT_STALE', '报告中的 Skill 指纹与当前内核不符，拒绝放行', 400)
  const reportHash = createHash('sha256').update(reportText).digest('hex')
  return {
    skillId: report.skillId,
    skillHash: report.skillHash,
    modelHash: report.modelHash,
    reportHash,
    approvedBy: reviewer.trim(),
    reviewKind,
    approvedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + RELEASE_TTL_DAYS * 86400000).toISOString(),
  }
}

/** Prompt de la passe de sortie (mot pour mot comme le projet source : sections fixes + preuves littérales + points à confirmer + HTML interdit). */
export function qualityInstructions(skillId: string): string {
  const skill = skills[skillId]
  if (!skill) fail('SKILL_NOT_FOUND', `未找到工具对应的 Skill：${skillId}`, 404)
  return `你必须只输出一个 JSON 对象，不输出 Markdown 代码围栏。格式：{"sections":[{"title":"章节名","content":"纯文本内容","evidence":["输入中的逐字证据片段"]}],"missingInformation":["需要补充或确认的信息"]}。\nsections 必须依次包含且仅包含这些章节：${skill.sections.join('、')}。evidence 必须逐字摘自用户输入；假设或建议可以为空数组，不能虚构引文；整份结果至少一处输入证据。信息不足时明确写待确认，并填入 missingInformation。禁止 HTML。`
}

/**
 * Contrôle de sortie à l'exécution (équivalent du checkModelOutput du projet source) : structure → sections complètes et ordonnées → citations localisables dans l'entrée
 * → HTML interdit. Toute non-conformité lève 502, le résultat n'est pas livré.
 */
export function checkModelOutput(skillId: string, raw: unknown, source: string): ModelOutput {
  const parsed = checkModelOutputSchema(raw)
  const skill = skills[skillId]
  if (!skill) fail('SKILL_NOT_FOUND', `未找到工具对应的 Skill：${skillId}`, 404)
  if (parsed.sections.map((section) => section.title).join('\n') !== skill.sections.join('\n')) {
    fail('QUALITY_SECTIONS', '模型输出缺少必需章节或顺序不正确，本次结果未交付。', 502)
  }
  const evidence = parsed.sections.flatMap((section) => section.evidence)
  if (evidence.length === 0 || evidence.some((quote) => !source.includes(quote))) {
    fail('QUALITY_EVIDENCE', '模型引用无法在输入中定位，本次结果未交付。', 502)
  }
  if (parsed.sections.some((section) => /<\/?[a-z][^>]*>/i.test(section.content))) {
    fail('QUALITY_CONTENT', '模型输出包含不允许的 HTML，本次结果未交付。', 502)
  }
  return parsed
}