/**
 * Couche de cartographie du contrat du portail (api.md v1.0 « portail numérique IA · document d'interconnexion des interfaces de données ») :
 * unique point de mise en correspondance ressources plateforme → JSON lecture seule du portail.
 *
 * Contraintes de conception (le portail et le mode de poussée peuvent changer, cette capacité est une interconnexion externe, pas un cœur de plateforme) :
 *   - quand le contrat de champs du portail change, ne modifier que ce fichier (changer de source/ajouter des champs), sans impact sur les endpoints ni les traces d'événements ;
 *   - tout en fonctions pures, toute valeur vide retombe sur chaîne vide (convention du contrat : pas de null / pas de champ absent).
 */
import type { ResourceEntity } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'

// ---- Contrat de champs du portail (api.md §4) ------------------------------------------------

export interface PortalApp {
  id: string
  tag: string
  name: string
  desc: string
  dept: string
  version: string
  accent: string
  link: string
  launchDate: string
}

export interface PortalEmployee {
  id: string
  name: string
  role: string
  avatar: string
  skills: string
  dept: string
  link: string
  launchDate: string
}

export interface PortalSolution {
  id: string
  icon: string
  title: string
  desc: string
  cases: string
  link: string
  launchDate: string
}

export interface PortalTool {
  id: string
  name: string
  desc: string
  category: string
  link: string
  icon: string
  dept: string
  pinned: boolean
}

export interface PortalSkill {
  id: string
  name: string
  tag: string
  desc: string
  dept: string
  version: string
  downloadUrl: string
  launchDate: string
}

export interface PortalStat {
  value: string
  unit: string
  label: string
}

/** Structure minimale requise pour la cartographie d'un enregistrement de skill publié (type structuré, évitant le couplage de types inter-plugins). */
export interface PortalSkillSource {
  id: string
  name: string
  category: string
  tags: string[]
  summary: string
  description: string
  orgId: string
  authorName: string
  status: string
  currentVersion: string
  versions: Array<{ status: string; publishedAt?: string }>
}

/** Contexte de cartographie : les services inter-domaines (nom d'organisation/nom de skill/adresse de téléchargement) sont injectés par rappel, les fonctions de cartographie restent sans dépendance et testables. */
export interface PortalMappingContext {
  deptName: (orgId: string) => string
  skillName: (skillId: string) => string
  /** Adresse publique de téléchargement du paquet de skill (endpoint de téléchargement sans authentification du portail). */
  skillDownloadUrl: (skillId: string) => string
  /** Les applications de niveau secret ne sortent pas vers le portail (PORTAL_HIDE_CONFIDENTIAL=1, fermé par défaut). */
  hideConfidential: boolean
}

// ---- Aides de cartographie ----------------------------------------------------------------

const s = (value: unknown): string => (value === undefined || value === null ? '' : String(value))

const tags = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])

/** Forme d'application → étiquette de catégorie du portail (le portail filtre par tag ; sans canal de publication enregistré, repli sur l'étiquette de forme). */
const APP_TYPE_LABELS: Record<string, string> = {
  web: 'Web',
  h5: 'H5',
  miniapp: '小程序',
  desktop: '桌面端',
  api: 'API',
}

/**
 * Masquage des liens publics du portail (revue de sécurité P1-03, 2026-10-31) : quand link/entryUrl pointe une adresse de bouclage/réseau privé/lien local
 * ou un nom d'hôte interne sans point, n'entre pas dans la liste anonyme — contre l'énumération de la topologie interne par un visiteur public. Renvoie chaîne vide (le contrat
 * admet un link absent, le portail affiche « pas encore d'entrée »), sans impact sur les autres champs.
 */
export function publicLink(value: unknown): string {
  const raw = s(value).trim()
  if (!raw) return ''
  let parsed: URL
  try { parsed = new URL(raw) } catch { return '' }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return ''
  const host = parsed.hostname.toLowerCase()
  if (host === 'localhost' || host === '::1' || host.endsWith('.local') || host.endsWith('.internal')
    || host.endsWith('.lan') || !host.includes('.')) return ''
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
    || /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
    || /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)
    || /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(host)
    || host === '0.0.0.0') return ''
  return raw
}

/** Palette de teintes de thème des cartes (le contrat exige #RRGGBB ; la plateforme n'a pas cet attribut, couleur par hachage stable de l'id, constante pour une même application). */
const ACCENTS = ['#00AECC', '#7C3AED', '#059669', '#D97706', '#DB2777', '#0891B2', '#6366F1', '#F97316']

export function accentFor(id: string): string {
  let hash = 0
  for (const ch of id) hash = (hash * 31 + (ch.codePointAt(0) ?? 0)) >>> 0
  return ACCENTS[hash % ACCENTS.length]!
}

/** Date de la dernière entrée en online dans l'historique de cycle de vie (YYYY-MM-DD) ; jamais mise en ligne = chaîne vide (contrat : « non mise en ligne »). */
export function lastOnlineDate(entity: Pick<ResourceEntity, 'lifecycleHistory'>): string {
  const at = (entity.lifecycleHistory ?? []).filter((entry) => entry.to === 'online').at(-1)?.at ?? ''
  return /^\d{4}-\d{2}-\d{2}/.test(at) ? at.slice(0, 10) : ''
}

// ---- Cartographie des endpoints ----------------------------------------------------------------

/**
 * Applications IA mises en ligne → portail /apps.
 * « mise en ligne » = visible du portail : après mise en ligne L4 de l'application, seul status=online entre dans la liste (non mise en ligne ne sort pas vers le portail).
 */
export function mapApps(entities: ResourceEntity[], mctx: PortalMappingContext): PortalApp[] {
  return entities
    .filter((app) => app.status === 'online')
    .filter((app) => !mctx.hideConfidential || app.attrs['dataClass'] !== 'confidential')
    .map((app) => {
      const typeLabel = APP_TYPE_LABELS[s(app.attrs['appType'])]
      return {
        id: app.id,
        tag: s(tags(app.attrs['channels'])[0]) || (typeLabel !== undefined ? t(typeLabel) : '') || s(app.attrs['appType']),
        name: app.name,
        desc: s(app.attrs['description']),
        dept: mctx.deptName(app.orgId),
        version: s(app.attrs['publishVersion']),
        accent: accentFor(app.id),
        link: publicLink(app.attrs['url']),
        launchDate: lastOnlineDate(app),
      }
    })
}

/** Agents mis en ligne → portail /employees (employés numériques). */
export function mapEmployees(entities: ResourceEntity[], mctx: PortalMappingContext): PortalEmployee[] {
  return entities
    .filter((agent) => agent.status === 'online')
    .filter((agent) => !mctx.hideConfidential || agent.attrs['dataClass'] !== 'confidential')
    .map((agent) => {
      const skillNames = tags(agent.attrs['skills']).map((id) => mctx.skillName(s(id))).filter(Boolean)
      return {
        id: agent.id,
        name: agent.name,
        role: s(agent.attrs['description']),
        avatar: s(agent.attrs['avatar']) || '🤖',
        skills: (skillNames.length > 0 ? skillNames : tags(agent.attrs['tags']).map(s)).join(','),
        dept: mctx.deptName(agent.orgId),
        link: publicLink(agent.attrs['entryUrl']),
        launchDate: lastOnlineDate(agent),
      }
    })
}

/** Skills publiés → portail /skills (launchDate prend la date de publication de la dernière version). */
export function mapSkills(skills: PortalSkillSource[], mctx: PortalMappingContext): PortalSkill[] {
  return skills
    .filter((skill) => skill.status === 'published')
    .map((skill) => {
      const publishedAt = skill.versions
        .filter((version) => version.status === 'published' && version.publishedAt)
        .map((version) => String(version.publishedAt))
        .sort()
        .at(-1) ?? ''
      return {
        id: skill.id,
        name: skill.name,
        tag: s(skill.category) || s(skill.tags[0]),
        desc: s(skill.summary) || s(skill.description),
        dept: mctx.deptName(skill.orgId) || s(skill.authorName),
        version: s(skill.currentVersion),
        // Endpoint public de téléchargement des paquets de skills publiés (téléchargeable sans authentification par le portail, metering de téléchargement enregistré côté plateforme)
        downloadUrl: mctx.skillDownloadUrl(s(skill.id)),
        launchDate: /^\d{4}-\d{2}-\d{2}/.test(publishedAt) ? publishedAt.slice(0, 10) : '',
      }
    })
}

/** 4 cartes statistiques de la page d'accueil (contrat : value doit être une chaîne, le portail rend 4 cartes d'indicateurs dans l'ordre du tableau). */
export function mapStats(counts: { apps: number; employees: number; skills: number; mcp: number }): PortalStat[] {
  return [
    { value: String(counts.apps), unit: '+', label: t('已上线AI应用') },
    { value: String(counts.employees), unit: '+', label: t('数字员工') },
    { value: String(counts.skills), unit: '+', label: t('上架技能') },
    { value: String(counts.mcp), unit: '+', label: t('在线MCP服务') },
  ]
}

/** /solutions : la plateforme n'a pas encore de source de données, renvoie un tableau vide (contrat §5 : le portail dégrade en affichant ses gabarits intégrés). */
export function emptySolutions(): PortalSolution[] {
  return []
}

/** /tools : idem (quand la source de données sera claire, il suffira d'ajouter une fonction map dans mapping.ts). */
export function emptyTools(): PortalTool[] {
  return []
}
