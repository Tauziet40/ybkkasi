/**
 * platform-i18n —— noyau multilingue de la plateforme (globalisation UI, lot 2026-10-16).
 *
 * Responsabilité (unique, réutilisable par tout plugin / CLI / pipeline de dictionnaire frontend) :
 *   - résolution de locale et chaîne de repli : requête ?lang= > Cookie rq_lang > Accept-Language > PLATFORM_LOCALE > zh-CN
 *   - chargement des dictionnaires : locales/<locale>/*.json fusionnés superficiellement dans l'ordre des noms de fichiers
 *     (plusieurs équipes maintiennent des fichiers en parallèle sans se écraser mutuellement) ;
 *   - t() : requête de traduction dont **la clé est le texte source chinois** (zh-CN renvoyé tel quel ⇒ zéro impact sur les assertions selftest existantes) ;
 *     en cas d'absence du dictionnaire, repli sur le texte source chinois (le dictionnaire se complète par incrément, l'exécution ne casse jamais faute de traduction)
 *   - interpolation {name} + localisation Intl des dates/nombres
 *
 * Contrat protocolaire (compatibilité R10) : nouvelles clés de protocole ASCII — paramètre de requête ?lang=, cookie rq_lang,
 * variables d'environnement PLATFORM_LOCALE / DSHCTL_LANG / I18N_EXTRA_DIR ; les noms d'événements, points de permission,
 * API (ok/data/error) restent inchangés. Signification des clés de protocole : voir docs/协议键中文对照总表.md.
 *
 * Modèle d'exécution : la couche de dispatch HTTP (platform-core/src/http.ts dispatch) utilise AsyncLocalStorage
 * pour établir un contexte de locale par requête ; tout code de route/service, quelle que soit sa profondeur, appelle t() et obtient la langue de la requête courante ;
 * hors contexte HTTP (tâches planifiées/consommation d'événements/CLI), PLATFORM_LOCALE est utilisée (la CLI a en plus DSHCTL_LANG).
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { AsyncLocalStorage } from 'node:async_hooks'

/** Langues prises en charge (globalisation UI : chinois simplifié par défaut + anglais + japonais + français ; ajouter une langue = ajouter un répertoire + une entrée). */
export const SUPPORTED_LOCALES = ['zh-CN', 'en-US', 'ja-JP', 'fr-FR'] as const
export type Locale = (typeof SUPPORTED_LOCALES)[number]
export const DEFAULT_LOCALE: Locale = 'zh-CN'

/** Tag Intl et nom d'affichage de chaque langue (consommés directement par le sélecteur, pour éviter un doublon côté frontend). */
export const LOCALE_DISPLAY_NAMES: Record<Locale, { native: string; en: string; intl: string }> = {
  'zh-CN': { native: '简体中文', en: 'Simplified Chinese', intl: 'zh-CN' },
  'en-US': { native: 'English (US)', en: 'English (US)', intl: 'en-US' },
  'ja-JP': { native: '日本語', en: 'Japanese', intl: 'ja-JP' },
  'fr-FR': { native: 'Français', en: 'French', intl: 'fr-FR' },
}

const LANG_PREFIX_MAP: Array<{ prefix: string; locale: Locale }> = [
  { prefix: 'zh', locale: 'zh-CN' },
  { prefix: 'en', locale: 'en-US' },
  { prefix: 'ja', locale: 'ja-JP' },
  { prefix: 'fr', locale: 'fr-FR' },
]

/** Normalisation tolérante BCP47 : 'en'/'en-GB' → en-US, 'ja' → ja-JP, 'fr'/'fr-CA' → fr-FR, 'zh'/'zh-SG' → zh-CN ; renvoie null si non pris en charge. */
export function normalizeLocale(input?: string | null): Locale | null {
  if (!input) return null
  const lower = String(input).trim().toLowerCase()
  if (lower === '') return null
  for (const { prefix, locale } of LANG_PREFIX_MAP) {
    if (lower === prefix || lower.startsWith(`${prefix}-`)) return locale
  }
  return null
}

/** Analyse de l'en-tête Cookie (IncomingMessage.headers.cookie peut être string | string[] | undefined). */
export function parseCookieHeader(header?: string | string[] | undefined): Record<string, string> {
  const raw = Array.isArray(header) ? header[0] : header
  if (!raw) return {}
  const out: Record<string, string> = {}
  for (const pair of String(raw).split(';')) {
    const eq = pair.indexOf('=')
    if (eq <= 0) continue
    const key = pair.slice(0, eq).trim()
    if (key !== '') out[key] = decodeURIComponent(pair.slice(eq + 1).trim())
  }
  return out
}

/** Analyse de l'en-tête Accept-Language : renvoie les tags de langue triés par q décroissant (segments invalides ignorés). */
export function parseAcceptLanguage(header?: string | string[] | undefined): string[] {
  const raw = Array.isArray(header) ? header.join(',') : header
  if (!raw) return []
  return String(raw)
    .split(',')
    .map((part) => {
      const [tag, ...params] = part.trim().split(';')
      let q = 1
      for (const param of params) {
        const match = /q\s*=\s*([\d.]+)/.exec(param)
        if (match) q = Number(match[1])
      }
      return { tag: (tag ?? '').trim(), q: Number.isFinite(q) ? q : 0 }
    })
    .filter((item) => item.tag !== '' && item.tag !== '*')
    .sort((a, b) => b.q - a.q)
    .map((item) => item.tag)
}

export interface ResolveLocaleInput {
  query?: string | null
  cookie?: string | null
  acceptLanguage?: string | null
  env?: string | null
}

/**
 * Résolution de locale (fonction pure, testée directement par selftest). Priorité : query explicite > cookie utilisateur >
 * langue du navigateur > variable d'environnement d'installation > zh-CN. Chaque niveau non pris en charge passe au suivant.
 */
export function resolveRequestLocale(input: ResolveLocaleInput): Locale {
  return normalizeLocale(input.query)
    ?? normalizeLocale(input.cookie)
    ?? parseAcceptLanguage(input.acceptLanguage)
      .map((tag) => normalizeLocale(tag))
      .find((locale): locale is Locale => locale !== null)
    ?? normalizeLocale(input.env)
    ?? DEFAULT_LOCALE
}

// ------------------------------------------------------------------ Chargement des dictionnaires

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

/** Cache des dictionnaires : locale → vue fusionnée (chargé une fois par processus ; un changement d'I18N_EXTRA_DIR exige un redémarrage, même règle que pour les autres variables d'env). */
const catalogCache = new Map<Locale, Record<string, string>>()

/** Lecture d'un répertoire de dictionnaire (<dir>/*.json fusionné superficiellement par ordre de nom). Réutilisé par le point de fusion /locales de la console et la CLI. */
export function readCatalogDir(dir: string): Record<string, string> {
  if (!existsSync(dir)) return {}
  const merged: Record<string, string> = {}
  const files = readdirSync(dir).filter((name) => name.endsWith('.json')).sort()
  for (const name of files) {
    try {
      const parsed = JSON.parse(readFileSync(join(dir, name), 'utf8')) as unknown
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) continue
      for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof value === 'string') merged[key] = value
      }
    } catch {
      // Un fichier de dictionnaire corrompu ne bloque pas le démarrage : on l'ignore (fail-soft, équivalent à un repli chinois faute de traduction)
    }
  }
  return merged
}

/** Fusionne toutes les couches de dictionnaire d'une locale donnée : répertoire du noyau (plusieurs fichiers par ordre de nom) + couche de personnalisation entreprise (I18N_EXTRA_DIR). */
export function localeCatalog(locale: Locale): Record<string, string> {
  const cached = catalogCache.get(locale)
  if (cached) return cached
  const merged = readCatalogDir(join(PACKAGE_ROOT, 'locales', locale))
  const extraRoot = process.env.I18N_EXTRA_DIR ?? ''
  if (extraRoot !== '') Object.assign(merged, readCatalogDir(join(extraRoot, locale)))
  catalogCache.set(locale, merged)
  return merged
}

// ------------------------------------------------------------------ Contexte de locale par requête

const requestLocaleStorage = new AsyncLocalStorage<Locale>()

/** Langue par défaut au niveau installation (PLATFORM_LOCALE, zh-CN par défaut) : langue de t() hors contexte HTTP (tâches planifiées/consommation d'événements). */
export function installLocale(): Locale {
  return normalizeLocale(process.env.PLATFORM_LOCALE) ?? DEFAULT_LOCALE
}

/** Langue actuellement effective : contexte de requête > PLATFORM_LOCALE > zh-CN. */
export function currentLocale(): Locale {
  return requestLocaleStorage.getStore() ?? installLocale()
}

/** Exécute fn dans le contexte de langue donné (la couche de dispatch HTTP enveloppe toute la chaîne middleware+handlers ; les tests l'utilisent aussi directement). */
export function runWithLocale<T>(locale: Locale, fn: () => T): T {
  return requestLocaleStorage.run(locale, fn)
}

// ------------------------------------------------------------------ t() et interpolation

const INTERP = /\{(\w+)\}/g

function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template
  return template.replace(INTERP, (whole, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : whole)
}

/**
 * Traduit un libellé dans le contexte courant : la clé est le texte source chinois ; renvoie la traduction si présente dans le dictionnaire, sinon le texte chinois tel quel
 * (le dictionnaire se complète par incrément, l'exécution n'échoue jamais faute de traduction) ; l'interpolation {name} est appliquée dans les deux langues.
 */
export function t(zhText: string, params?: Record<string, string | number>): string {
  const locale = currentLocale()
  if (locale === DEFAULT_LOCALE) return interpolate(zhText, params)
  const translated = localeCatalog(locale)[zhText]
  return interpolate(translated ?? zhText, params)
}

/** t() avec langue explicite (côté consommation d'événements, pour rejouer un libellé selon la langue d'émission de l'événement ou la préférence du destinataire). */
export function tIn(locale: Locale, zhText: string, params?: Record<string, string | number>): string {
  if (locale === DEFAULT_LOCALE) return interpolate(zhText, params)
  const translated = localeCatalog(locale)[zhText]
  return interpolate(translated ?? zhText, params)
}

// ------------------------------------------------------------------ Localisation Intl

/** Localisation date/heure (par défaut date medium + heure medium ; en contexte technique, continuer à utiliser ISO 8601 tel quel). */
export function formatDateValue(value: string | number | Date, locale?: Locale, opts?: Intl.DateTimeFormatOptions): string {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  const tag = LOCALE_DISPLAY_NAMES[locale ?? currentLocale()].intl
  return new Intl.DateTimeFormat(tag, opts ?? { dateStyle: 'medium', timeStyle: 'medium' }).format(date)
}

/** Localisation des nombres (séparateurs de milliers/décimal selon la langue ; la sémantique pourcentage/montant est fournie par l'appelant via les opts Intl). */
export function formatNumberValue(value: number, locale?: Locale, opts?: Intl.NumberFormatOptions): string {
  const tag = LOCALE_DISPLAY_NAMES[locale ?? currentLocale()].intl
  return new Intl.NumberFormat(tag, opts).format(value)
}
