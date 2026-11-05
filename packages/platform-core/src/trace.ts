/**
 * Primitives de trace de bout en bout (contrat de gouvernance MCP §14, W3-T5).
 *
 * Sous-ensemble minimal côté plateforme du W3C Trace Context :
 *   - newTraceId() : trace id en 32 caractères hex minuscules (128 bits, généré aléatoirement, jamais tout zéro) ;
 *   - parseTraceparent / formatTraceparent：`{version}-{trace-id}-{parent-id}-{trace-flags}`
 *     analyse et sérialisation du format à quatre segments (périmètre version=00 ; entrée invalide → null à l'analyse, lève à la sérialisation).
 *
 * Facette consommatrice : l'entrée invoke de plugin-mcp génère un trace s'il n'y en a pas (l'appelant peut le transmettre via InvokeCaller.traceId /
 * en-têtes X-Trace-Id / mcp-session-id), le transfert HTTP aval embarque l'en-tête traceparent,
 * usage/enregistrements d'appel/événements d'audit reconstituent la chaîne d'appel par association au traceId.
 */
import { randomBytes } from 'node:crypto'

const TRACEPARENT_VERSION = '00'
const TRACE_ID_RE = /^[0-9a-f]{32}$/
const PARENT_ID_RE = /^[0-9a-f]{16}$/
const FLAGS_RE = /^[0-9a-f]{2}$/

/** Génère un trace id hex de 32 caractères (128 bits aléatoires, probabilité de tout-zéro négligeable ; nouvelle tentative défensive une fois). */
export function newTraceId(): string {
  const id = randomBytes(16).toString('hex')
  return id === '0'.repeat(32) ? randomBytes(16).toString('hex') : id
}

/** Structure traceparent analysée (W3C Trace Context version 00). */
export interface Traceparent {
  version: string
  /** trace id hex de 32 caractères. */
  traceId: string
  /** parent span id hex de 16 caractères. */
  parentId: string
  /** trace flags hex de 2 caractères. */
  flags: string
}

/**
 * Analyse l'en-tête traceparent (périmètre W3C, version=00) :
 *   - quatre segments ; nombre de segments incorrect / variantes avec espaces → null ;
 *   - version doit valoir '00' (la plateforme ne produit/accepte que 00 ; 'ff' interdit par la spécification, autres versions non reconnues) ;
 *   - trace-id : 32 hex non tous zéro ; parent-id : 16 hex non tous zéro ; flags : 2 hex ;
 *   - tout élément invalide → null (l'appelant retombe sur la génération d'un nouveau trace, jamais de transmission défectueuse).
 */
export function parseTraceparent(header: string): Traceparent | null {
  if (typeof header !== 'string') return null
  const parts = header.split('-')
  if (parts.length !== 4) return null
  const [version, traceId, parentId, flags] = parts
  if (version !== TRACEPARENT_VERSION) return null
  if (!TRACE_ID_RE.test(traceId) || /^0+$/.test(traceId)) return null
  if (!PARENT_ID_RE.test(parentId) || /^0+$/.test(parentId)) return null
  if (!FLAGS_RE.test(flags)) return null
  return { version, traceId, parentId, flags }
}

/**
 * Sérialise l'en-tête traceparent : version toujours '00' ; parentId généré aléatoirement par défaut (nouveau span initié par la passerelle) ;
 * flags par défaut '01' (sampled). traceId/parentId invalides (forme ou tout zéro) → lève — les erreurs de construction
 * doivent être exposées explicitement, jamais dégradées en mauvais en-tête émis.
 */
export function formatTraceparent(traceId: string, parentId?: string, flags = '01'): string {
  if (!TRACE_ID_RE.test(traceId) || /^0+$/.test(traceId)) {
    throw new Error(`非法 traceId（须为 32 位非全零 hex）：${traceId}`)
  }
  const parent = parentId ?? randomBytes(8).toString('hex')
  if (!PARENT_ID_RE.test(parent) || /^0+$/.test(parent)) {
    throw new Error(`非法 parentId（须为 16 位非全零 hex）：${parent}`)
  }
  if (!FLAGS_RE.test(flags)) {
    throw new Error(`非法 trace flags（须为 2 位 hex）：${flags}`)
  }
  return `${TRACEPARENT_VERSION}-${traceId}-${parent}-${flags}`
}
