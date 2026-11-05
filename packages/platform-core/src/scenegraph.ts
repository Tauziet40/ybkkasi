/**
 * @dsh-ops/platform-core —— modèle et chargement du graphe de scénarios sectoriels (scenegraph) (review-dsh-agent-panel-v2 Phase 2).
 *
 * Socle de données « un graphe, quatre listes » (en écho aux Référentiels du MIIT pour la transformation numérique des industries clés par scénarios et graphes, édition 2025) :
 *   1 fil principal (chains, filières sectorielles) + 5 types d'activités métier (activities, R&D et conception/production/fourniture/exploitation-maintenance/marketing numérique/
 *   gestion d'entreprise/juridique-fiscal-financier et coûts) + N scénarios (cartes scene : numéro/notation de l'existant/étiquettes de valeur/points de douleur) + 4 types d'éléments numériques
 *   (logiciels-outils tools / modèles de connaissance models / données data / compétences talent).
 *
 * Même arbitrage que cardpacks (revue D5/D6) : v1 passe par le canal d'actifs intégrés (répertoire par défaut packages/platform-core/scenegraphs/,
 * remplaçable via SCENEGRAPH_DIR), la mise en place marketplace (extension du contrat content.scenegraph) attend la Phase 4 ; le lint du validateur et
 * l'exécution partagent les deux bouts ; rafraîchissement à chaud = reloadFromDir + PlatformEvents.ScenegraphUpdated.
 */
import { readdir, readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { t } from '../../platform-i18n/src/index.ts'

/**
 * Étiquettes de valeur (liste de passation F, section M, 2026-09-11) : le périmètre du texte original du MIIT est réduction des coûts/qualité/efficacité/revenus/sécurité/écologie/nouveaux modes ;
 * « économie d'énergie » est conservé pour compatibilité avec le paquet qb01 existant (absent du texte original, les graphes existants passent la validation sans aucun changement).
 */
export const SCENE_TAGS = ['提质', '降本', '增效', '节能', '新模式', '增收', '安全', '环保'] as const
export type SceneTag = (typeof SCENE_TAGS)[number]

/** Clés d'activités métier (mapping ACT : R&D-conception rd / production mfg / fourniture scm / exploitation-maintenance svc / marketing numérique mkt / gestion d'entreprise mgmt / juridique-fiscal fin). */
export const SCENE_ACTIVITIES = ['rd', 'mfg', 'scm', 'svc', 'mkt', 'mgmt', 'fin'] as const
export type SceneActivity = (typeof SCENE_ACTIVITIES)[number]

export const ACTIVITY_LABELS: Record<SceneActivity, string> = {
  rd: '研发设计',
  mfg: '生产制造',
  scm: '供应链管理',
  svc: '运维服务',
  mkt: '数字营销',
  mgmt: '经营管理',
  fin: '法财税与成本',
}

export interface ScenegraphScene {
  /** Numéro de scénario (p. ex. QB01-A-2-5), unique dans tout le graphe. */
  code: string
  name: string
  type: '主场景' | '细分场景'
  /** Notation de l'existant 1-5 étoiles (auto-évaluation de l'entreprise, base de priorité de transformation : en dessous de 3 étoiles, transformation prioritaire recommandée). */
  s: number
  tags: SceneTag[]
  pain: string
  tools: string[]
  models: string[]
  data: string[]
  talent: string[]
}

export interface ScenegraphPack {
  /** Code sectoriel (codage des graphes du « Référentiel (édition 2025) » du MIIT, p. ex. QB01 électroménager / JB01 engins de chantier). */
  code: string
  name: string
  icon: string
  /** Version du paquet de graphe (mises à jour de données via reloadFromDir + rafraîchissement à chaud scenegraph.updated). */
  version: string
  /** Filière principale sectorielle (un seul fil conducteur). */
  chains: string
  /**
   * Chaîne des maillons sectoriels (liste de passation F, section M, 2026-09-11, optionnel) : le graphe original est organisé par maillon sectoriel (p. ex. acier A amont du haut fourneau/B fonte…) ;
   * une chaîne chains en simple chaîne ne se consomme pas de façon structurée. En cas d'absence, le frontend déduit du troisième segment du numéro de scénario (le paquet qb01 existant n'a pas besoin de changement).
   * Le validateur ne contrôle pas fortement ce champ (contrat du producteur).
   */
  links?: Array<{ key: string; name: string }>
  /** Activité métier → liste de scénarios (rattachement des 5 types d'activités métier à N scénarios). */
  activities: Partial<Record<SceneActivity, ScenegraphScene[]>>
}

/** Valide un paquet : renvoie tous les problèmes (sans lever), partagé par lint:manifests et le chargement. */
export function validateScenegraph(input: unknown, source = 'scenegraph'): string[] {
  const errors: string[] = []
  const pack = input as ScenegraphPack
  if (pack === null || typeof pack !== 'object') return [t('{source}: 不是 JSON 对象', { source })]
  if (!pack.code || typeof pack.code !== 'string' || !/^[A-Z][A-Z0-9]{2,9}$/.test(pack.code)) {
    errors.push(t('{source}: code 必填（行业图谱编码，大写字母开头 3-10 位，收到 {value}）', { source, value: String(pack.code) }))
  }
  if (!pack.name || typeof pack.name !== 'string') errors.push(t('{source}: name 必填', { source }))
  if (!pack.icon || typeof pack.icon !== 'string') errors.push(t('{source}: icon 必填', { source }))
  if (!pack.version || typeof pack.version !== 'string') errors.push(t('{source}: version 必填', { source }))
  if (!pack.chains || typeof pack.chains !== 'string') errors.push(t('{source}: chains（行业链条主线）必填', { source }))
  if (!pack.activities || typeof pack.activities !== 'object' || Array.isArray(pack.activities)) {
    errors.push(t('{source}: activities 必填（业务活动 → 场景清单）', { source }))
    return errors
  }
  const seen = new Set<string>()
  let total = 0
  for (const [activity, scenes] of Object.entries(pack.activities)) {
    if (!SCENE_ACTIVITIES.includes(activity as SceneActivity)) {
      errors.push(t('{source}: activities.{activity} 非法（应为 {expected}）', { source, activity, expected: SCENE_ACTIVITIES.join('/') }))
      continue
    }
    if (!Array.isArray(scenes) || scenes.length === 0) {
      errors.push(t('{source}: activities.{activity} 必须是非空场景数组', { source, activity }))
      continue
    }
    scenes.forEach((scene, index) => {
      total++
      const at = `${source}: activities.${activity}[${index}]`
      if (!scene?.code || typeof scene.code !== 'string') errors.push(t('{at}.code 必填', { at }))
      else if (seen.has(scene.code)) errors.push(t('{at}.code 全图重复：{code}', { at, code: scene.code }))
      else seen.add(scene.code)
      if (!scene?.name || typeof scene.name !== 'string') errors.push(t('{at}.name 必填', { at }))
      if (scene?.type !== '主场景' && scene?.type !== '细分场景') errors.push(t('{at}.type 非法（主场景/细分场景）', { at }))
      if (!Number.isInteger(scene?.s) || scene.s < 1 || scene.s > 5) errors.push(t('{at}.s 现状评级须为 1-5 整数', { at }))
      // tags peut être un tableau vide (liste de passation F, section M, 2026-09-11) : une proportion notable des scénarios du texte original n'a pas d'étiquette de valeur explicite
      // (mesuré : 504 scénarios sans étiquette sur 807) — la seule conformité possible auparavant était d'inventer des étiquettes, violant la ligne rouge « pas de fausses données » ;
      // après assouplissement, chargement fidèle au texte original ; les vues de scénarios filtrées par étiquette excluent naturellement les scénarios sans étiquette
      if (!Array.isArray(scene?.tags) || scene.tags.some((tag) => !SCENE_TAGS.includes(tag))) {
        errors.push(t('{at}.tags 非法（应为 {expected} 的子集，可为空数组）', { at, expected: SCENE_TAGS.join('/') }))
      }
      if (!scene?.pain || typeof scene.pain !== 'string') errors.push(t('{at}.pain 必填', { at }))
      for (const list of ['tools', 'models', 'data', 'talent'] as const) {
        if (!Array.isArray(scene?.[list]) || scene[list].length === 0) {
          errors.push(t('{at}.{field} 必填且非空（四清单缺一不可）', { at, field: list }))
        }
      }
    })
  }
  if (total === 0) errors.push(t('{source}: 图谱至少要有一个场景', { source }))
  return errors
}

/** Répertoire de graphes par défaut : scenegraphs/ au même niveau que ce paquet (valable en forme source comme en forme installée). */
export function defaultScenegraphDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', 'scenegraphs')
}

export class ScenegraphService extends Service {
  static readonly provide = 'scenegraphs'

  private packs: ScenegraphPack[] = []
  private loadErrors: string[] = []

  constructor(ctx: Context, config: { dir?: string } = {}) {
    super(ctx, 'scenegraphs')
    void this.loadFromDir(config.dir ?? process.env.SCENEGRAPH_DIR ?? defaultScenegraphDir())
  }

  /** Charge tous les *.json du répertoire : fichier invalide sauté et consigné (ne bloque pas le démarrage), lint:manifests garde la ligne rouge. */
  async loadFromDir(dir: string): Promise<void> {
    const errors: string[] = []
    const packs: ScenegraphPack[] = []
    let entries: Array<{ name: string }> = []
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch {
      this.loadErrors = [t('{dir} 不可读（无场景图谱包）', { dir })]
      return
    }
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue
      try {
        const parsed = JSON.parse(await readFile(join(dir, entry.name), 'utf8'))
        const packErrors = validateScenegraph(parsed, entry.name)
        if (packErrors.length > 0) {
          errors.push(...packErrors)
          continue
        }
        packs.push(parsed as ScenegraphPack)
      } catch (error) {
        errors.push(t('{name}: JSON 解析失败（{message}）', { name: entry.name, message: error instanceof Error ? error.message : String(error) }))
      }
    }
    this.packs = packs
    this.loadErrors = errors
    if (errors.length > 0) this.ctx.logger('scenegraphs').warn(`场景图谱装载存在被跳过的文件：${errors.join('；')}`)
  }

  /** Rafraîchissement à chaud : rechargement du répertoire puis émission de scenegraph.updated (le panneau rafraîchit sa page de scénarios ; review Phase 2 point 11). */
  async reloadFromDir(dir?: string): Promise<{ packs: number; problems: string[] }> {
    await this.loadFromDir(dir ?? process.env.SCENEGRAPH_DIR ?? defaultScenegraphDir())
    this.ctx.platformBus.emit(PlatformEvents_ScenegraphUpdated, { packs: this.packs.length, problems: this.loadErrors.length })
    return { packs: this.packs.length, problems: this.loadErrors }
  }

  all(): ScenegraphPack[] {
    return this.packs
  }

  get(code: string): ScenegraphPack | undefined {
    return this.packs.find((pack) => pack.code === code)
  }

  /** Recherche inverse par numéro de scénario (références de session reversées dans le graphe : p. ex. QB01-A-2-5). */
  findScene(code: string): { pack: ScenegraphPack; activity: SceneActivity; scene: ScenegraphScene } | undefined {
    for (const pack of this.packs) {
      for (const [activity, scenes] of Object.entries(pack.activities)) {
        const hit = (scenes ?? []).find((scene) => scene.code === code)
        if (hit) return { pack, activity: activity as SceneActivity, scene: hit }
      }
    }
    return undefined
  }

  /** Liste des problèmes des fichiers sautés au chargement, pour l'observation. */
  loadProblems(): string[] {
    return this.loadErrors
  }
}

/** Constante indépendante pour éviter le couplage à l'ordre d'export de index.ts (valeur identique à PlatformEvents.ScenegraphUpdated). */
const PlatformEvents_ScenegraphUpdated = 'scenegraph.updated'

declare module '@deepseek-ai/cordis' {
  interface Context {
    scenegraphs: ScenegraphService
  }
}
