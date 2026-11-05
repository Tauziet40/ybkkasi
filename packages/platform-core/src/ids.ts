/** Identifiants et utilitaires de texte : ID préfixés unifiés, slugification, masquage. */
import { createHash, randomBytes } from 'node:crypto'

let counter = Math.floor(Math.random() * 1e6)

/** Génère un ID court : `<prefix>_<base36 temporel><aléatoire>`, strictement croissant dans le processus, lisible et triable. */
export function newId(prefix: string): string {
  const t = Date.now().toString(36)
  const r = (counter++).toString(36)
  const rand = Math.floor(Math.random() * 1679616).toString(36)
  return `${prefix}_${t}${r.padStart(4, '0')}${rand.padStart(4, '0')}`
}

/** Convertit un nom en slug compatible URL. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[\s_]+/g, '-')
    .replace(/[^\p{L}\p{N}-]+/gu, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') || newId('slug')
}

/** Masquage simple : conserve keep caractères au début et à la fin. */
export function mask(value: string | undefined, keep = 3): string {
  if (!value) return ''
  if (value.length <= keep * 2) return '*'.repeat(value.length)
  return value.slice(0, keep) + '*'.repeat(Math.min(8, value.length - keep * 2)) + value.slice(-keep)
}

/** Génère une clé client (affichée une seule fois, seul le hash est stocké en base). */
export function generateSecret(prefix = 'sk'): string {
  return `${prefix}_${randomBytes(24).toString('base64url')}`
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}
