/**
 * Localisation de la version plateforme : remonte depuis le fichier de plugin en cours d'exécution jusqu'à la racine du dépôt (package.json name=dsh-enterprise-ops),
 * pour obtenir le numéro de version unique et faisant autorité ainsi que la forme d'installation. Formes couvertes toutes deux : extraction source / installation via le marketplace de plugins dsh (installation git pnpm, structure de répertoire isomorphe)
 * — auparavant le numéro de version était dispersé et désynchronisé entre package.json, gen-manifests et /api/platform/info ;
 * l'auto-mise à niveau faisant désormais de la comparaison de versions un comportement produit, tout doit converger vers une source de vérité unique.
 */
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Nom du paquet plateforme (name du package.json racine, valable aussi en forme installée). */
export const PLATFORM_PACKAGE = 'dsh-enterprise-ops'

export type InstallMode = 'source' | 'bundle'

export interface PlatformVersionInfo {
  /** Racine du dépôt/paquet (contient package.json et src/). */
  rootDir: string
  /** version du package.json racine (lecture seule à l'exécution, cache dans le processus). */
  version: string
  /** source=extraction git des sources (.git présent, mise à niveau en un clic possible) ; bundle=installation via dsh plugin add. */
  installMode: InstallMode
}

let cached: PlatformVersionInfo | undefined

/** Résout les informations de version de la plateforme (cache dans le processus ; après exécution d'une mise à niveau, relire le disque via readRootVersion). */
export function platformVersionInfo(): PlatformVersionInfo {
  if (cached) return cached
  let dir = dirname(fileURLToPath(import.meta.url))
  let rootDir = ''
  for (let depth = 0; depth < 8; depth++) {
    let pkg: { name?: string } | undefined
    try {
      pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name?: string }
    } catch { /* pas de package.json à ce niveau, on continue de remonter */ }
    if (pkg) {
      if (!rootDir) rootDir = dir // repli : le répertoire le plus récent contenant un package.json
      if (pkg.name === PLATFORM_PACKAGE) {
        rootDir = dir
        break
      }
    }
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  if (!rootDir) rootDir = dir
  let version = '0.0.0'
  try {
    version = String((JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8')) as { version?: string }).version ?? '0.0.0')
  } catch { /* filet : 0.0.0 */ }
  const gitPath = join(rootDir, '.git')
  let hasGit = false
  try {
    hasGit = existsSync(gitPath) && (statSync(gitPath).isDirectory() || statSync(gitPath).isFile())
  } catch { /* traité comme absence de .git */ }
  cached = { rootDir, version, installMode: hasGit ? 'source' : 'bundle' }
  return cached
}

/** Lit la version du package.json racine sans cache (nécessaire pour la nouvelle version après git pull, plutôt que le cache du processus). */
export function readRootVersion(rootDir: string): string {
  try {
    return String((JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8')) as { version?: string }).version ?? '0.0.0')
  } catch {
    return '0.0.0'
  }
}

export function platformVersion(): string {
  return platformVersionInfo().version
}

export function platformRootDir(): string {
  return platformVersionInfo().rootDir
}

export function platformInstallMode(): InstallMode {
  return platformVersionInfo().installMode
}
