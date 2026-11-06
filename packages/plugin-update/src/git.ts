/**
 * Lecture des faits git locaux et exécution sûre (dédié à platform-update, pas d'enveloppe git générique).
 * Lit les fichiers .git plutôt que de spawner `git` — le repérage de HEAD au démarrage doit être zéro sous-processus, zéro dépendance,
 * et rester utilisable dans les environnements où git n'est pas dans le PATH (certains conteneurs/installations minimales).
 */
import { existsSync, readFileSync, statSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

export interface LocalGitInfo {
  sha: string
  branch: string
  /** false en detached HEAD ou nom de branche méconnaissable. */
  onBranch: boolean
}

/** Lit le HEAD courant de l'arbre de travail (sha + branche). Illisible (installation bundle/clone superficiel anormal) = null. */
export function readGitHead(rootDir: string): LocalGitInfo | null {
  const dotGit = join(rootDir, '.git')
  let gitDir = dotGit
  try {
    const stat = statSync(dotGit)
    if (stat.isFile()) {
      // worktree/submodule : .git est un fichier pointeur vers le gitdir principal
      const target = readFileSync(dotGit, 'utf8').trim().match(/^gitdir:\s*(\S+)/)?.[1]
      if (!target) return null
      gitDir = isAbsolute(target) ? target : join(rootDir, target)
    } else if (!stat.isDirectory()) {
      return null
    }
  } catch {
    return null
  }
  try {
    const head = readFileSync(join(gitDir, 'HEAD'), 'utf8').trim()
    const refMatch = head.match(/^ref:\s*refs\/heads\/(.+)$/)
    if (!refMatch) {
      return /^[0-9a-f]{40}$/.test(head) ? { sha: head, branch: '', onBranch: false } : null
    }
    const branch = refMatch[1]!
    const refPath = join(gitDir, 'refs', 'heads', ...branch.split('/'))
    if (existsSync(refPath)) {
      const sha = readFileSync(refPath, 'utf8').trim()
      if (/^[0-9a-f]{40}$/.test(sha)) return { sha, branch, onBranch: true }
    }
    // repli packed-refs quand la référence de branche n'est pas expansée
    if (existsSync(join(gitDir, 'packed-refs'))) {
      const packed = readFileSync(join(gitDir, 'packed-refs'), 'utf8')
      const line = packed.split('\n').find((row) => row.endsWith(` refs/heads/${branch}`))
      const sha = line?.split(' ')[0]
      if (sha && /^[0-9a-f]{40}$/.test(sha)) return { sha, branch, onBranch: true }
    }
    return null
  } catch {
    return null
  }
}

/** Exécute une commande git dans le répertoire indiqué (protection de timeout ; retour stdout+stderr tronqué). */
export async function runGit(rootDir: string, args: string[], timeoutMs = 120_000): Promise<string> {
  const { stdout, stderr } = await execFileAsync('git', args, { cwd: rootDir, timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 })
  return `${stdout}${stderr ? `\n${stderr}` : ''}`.trim()
}

/** Exécute une commande npm dans le répertoire indiqué. Sous Windows, npm est un script .cmd, l'appel doit passer par le shell. */
export async function runNpm(rootDir: string, args: string[], timeoutMs = 600_000): Promise<string> {
  const { stdout, stderr } = await execFileAsync('npm', args, {
    cwd: rootDir,
    timeout: timeoutMs,
    maxBuffer: 8 * 1024 * 1024,
    ...(process.platform === 'win32' ? { shell: true } : {}),
  })
  return `${stdout}${stderr ? `\n${stderr}` : ''}`.trim()
}
