/**
 * Scan d'hygiène des minuteurs (OPT-P3-02, 2026-09-12) :
 * chaque appel setInterval( sous packages doit satisfaire l'une des conditions suivantes, sinon infraction :
 *   a) suivi proche (dans les 3 lignes suivantes) de .unref() / .unref?.() ;
 *   b) le fichier contient clearInterval (cycle de vie enregistré) ;
 *   c) commentaire « keepalive » proche (exemption explicite de maintien en vie, motif obligatoire).
 * Toute infraction = rouge (exit 1) — les formes embarquées/test n'admettent pas de suspension implicite de la boucle d'événements.
 */
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'

const UNREF_RE = /\.unref\(\)|\.unref\?\.\(\)/

export async function scanTimerHygiene(packagesDir) {
  const messages = []
  let total = 0
  let violations = 0
  let entries
  try {
    entries = await readdir(packagesDir, { withFileTypes: true })
  } catch {
    return { total, violations, messages }
  }
  for (const pkg of entries) {
    if (!pkg.isDirectory()) continue
    let files = []
    try {
      files = await readdir(join(packagesDir, pkg.name, 'src'), { recursive: true })
    } catch {
      continue
    }
    for (const rel of files) {
      if (!rel.endsWith('.ts')) continue
      const file = join(packagesDir, pkg.name, 'src', rel)
      let text = ''
      try {
        text = await readFile(file, 'utf8')
      } catch {
        continue
      }
      if (!text.includes('setInterval(')) continue
      const hasClear = text.includes('clearInterval')
      const lines = text.split(/\r?\n/)
      for (let i = 0; i < lines.length; i++) {
        if (!lines[i].includes('setInterval(')) continue
        total++
        const near = lines.slice(i, i + 7).join('\n')
        const keepalive = /keepalive/i.test(near)
        if (!UNREF_RE.test(near) && !hasClear && !keepalive) {
          violations++
          messages.push(`${pkg.name}/src/${rel}:${i + 1}：setInterval 既未 unref 也无 clearInterval 生命周期登记`)
        }
      }
    }
  }
  return { total, violations, messages }
}
