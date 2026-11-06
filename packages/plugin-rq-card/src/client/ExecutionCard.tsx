/**
 * Carte d'exécution à quatre états : entrée du slot clavier `tool.call.toolview` (C1/C2 du couloir C, WP-06).
 *
 * Forme d'enregistrement isomorphe au toolview atomique d'ui-tool de dsh (spike §2.3 preuve C3, §4.3 pseudo-code) :
 * enregistre une clé pour chaque nom d'outil de method, les outils non listés retombant automatiquement sur GenericToolCard (additif,
 * sans préemption d'aucune clé existante). Le jugement des quatre états passe entièrement par la fonction pure deriveExecutionState (table C2),
 * ce composant ne fait que du rendu pur :
 *   en appel       → squelette + placeholder annulable (le canal d'annulation attend le câblage de la moitié hôte, bouton désactivé avec explication)
 *   en exécution   → pulsation de progression ; degraded ajoute « un peu lent, traité en arrière-plan »
 *   terminé        → résumé du résultat + lien externe vers la page de ressource correspondante de la console /rq (same-origin avec état de connexion) + 👍/👎 (barre de feedback enregistrée séparément)
 *   bloqué anomalie → bandeau rouge + libellé métier (code de motif = clé de C3 js/errors.js) + bouton d'action
 *
 * [Défense par dégradation] tout accès à l'exécution à block/content est gardé de forme : si la structure d'instantané amont change,
 * la carte préfère rendre moins plutôt que de jeter — au-delà de la frontière slot (reportEntryError), une couche d'auto-discipline.
 * @module @dsh-ops/plugin-rq-card/client/ExecutionCard
 */

import type { ExecutionState, ExecutionStateInput } from './state.ts'
import type { ExecutionCardProps, ToolCallBlockView } from './slots.ts'
import { CONSOLE_BASE } from '../wire.ts'

/** Préfixe de nom d'outil → page de ressource de la console /rq (route hash ; préfixe non listé = repli espace de travail). */
const ROUTE_FOR_TOOL_PREFIX: Readonly<Record<string, string>> = Object.freeze({
  mcp: '#/mcp',
  nas: '#/nas',
  skill: '#/skills',
  app: '#/apps',
  agent: '#/agents',
  iam: '#/iam',
  authn: '#/authn',
  audit: '#/audit',
  connector: '#/connectors',
  billing: '#/platform',
  market: '#/assets',
  model: '#/platform',
  approval: '#/approvals',
})

/** Code de motif de blocage → page d'atterrissage du bouton d'action (colonne « bouton d'action » du module de libellés C3, same-origin avec état de connexion). */
const ROUTE_FOR_REASON: Readonly<Record<string, string>> = Object.freeze({
  'nas-authz-deny': '#/nas-authz',
  'quota-exhausted': '#/approvals',
  'pdp-unreachable': '#/dashboard',
  'breaker-open': '#/mcp',
  down: '#/mcp',
  'binding-invalid': '#/connect',
  'invoke-error': '#/dashboard',
})

/** Prend la page de ressource de la console selon le nom d'outil. */
function routeForTool(toolName: string): string {
  const prefix = toolName.split('_', 1)[0] ?? ''
  return `${CONSOLE_BASE}${ROUTE_FOR_TOOL_PREFIX[prefix] ?? '#/dashboard'}`
}

/** Plafond de troncature du texte de résultat (la carte est un résumé, pas un journal). */
const RESULT_TEXT_LIMIT = 600

/**
 * Extrait le texte du bloc de résultat définitif (garde de forme : un bloc content sans champ text est sauté).
 */
function resultText(block: { content?: unknown }): string {
  const content = block.content
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const piece of content) {
    if (typeof piece === 'object' && piece !== null
      && 'text' in piece && typeof (piece as { text: unknown }).text === 'string') {
      parts.push((piece as { text: string }).text)
    }
  }
  const text = parts.join('\n').trim()
  return text.length > RESULT_TEXT_LIMIT
    ? `${text.slice(0, RESULT_TEXT_LIMIT)}…`
    : text
}

/** Corps de la carte (partie dérivée de l'état + rendu par dictionnaire t). */
function CardBody({ state, block, toolName, t }: {
  state: ExecutionState
  block: ToolCallBlockView
  toolName: string
  t: (key: never) => string
}) {
  // Les clés de t viennent du dictionnaire rq-card (union de types à la compilation) ; à l'exécution, prise de mot par chaîne directe.
  const text = t as (key: string) => string
  switch (state.state) {
    case 'calling':
      return (
        <div className="rq-ecard-skel" aria-busy="true">
          <div className="rq-ecard-skel-line" />
          <div className="rq-ecard-skel-line" />
          <div className="rq-ecard-skel-line" />
          <div className="rq-ecard-foot">
            <button type="button" className="rq-ecard-cancel" disabled title={text('card.cancel.hint')}>
              {text('card.cancel.button')}
            </button>
          </div>
        </div>
      )
    case 'executing':
      return (
        <div aria-busy="true">
          <div className="rq-ecard-pulse" />
          {state.degraded === true && <div className="rq-ecard-degraded">⏳ {text('card.degraded.hint')}</div>}
        </div>
      )
    case 'done': {
      const settled = block as { content?: unknown }
      const summary = resultText(settled)
      return (
        <div>
          {summary !== '' && <div className="rq-ecard-result">{summary}</div>}
          <div className="rq-ecard-foot">
            <a className="rq-ecard-link" href={routeForTool(toolName)} target="_blank" rel="noreferrer">
              {text('card.console.link')} ↗
            </a>
          </div>
        </div>
      )
    }
    case 'blocked': {
      const reason = state.reason ?? 'invoke-error'
      const settled = block as { content?: unknown }
      const summary = 'kind' in block ? resultText(settled) : ''
      return (
        <div>
          <div className="rq-ecard-reason">{text(`card.blocked.${reason}`)}</div>
          {summary !== '' && <div className="rq-ecard-result">{summary}</div>}
          <div className="rq-ecard-foot">
            <a className="rq-ecard-action" href={`${CONSOLE_BASE}${ROUTE_FOR_REASON[reason] ?? '#/dashboard'}`}>
              {text(`card.action.${reason}`)}
            </a>
          </div>
        </div>
      )
    }
    default:
      return null
  }
}

/**
 * Carte d'exécution à quatre états (composant d'entrée clavier).
 * @param props - partage owner (toolName/block) + face d'injection (deriveState/healthSnapshot) + dictionnaire.
 */
export function ExecutionCard(props: ExecutionCardProps) {
  const { toolName, block, deriveState, healthSnapshot, t } = props

  // ── tirer la matière du cycle de vie du bloc d'appel (spike §2.5 preuve E3 : en cours d'exécution sans 'kind', définitif kind:'tool-result') ──
  const hasResult = typeof block === 'object' && block !== null && 'kind' in block
  const resultIsError = hasResult === true
    && typeof (block as { isError: unknown }).isError === 'boolean'
    && (block as { isError: boolean }).isError
  const invokePhase: ExecutionStateInput['invokePhase'] = hasResult ? 'idle' : 'calling'

  // ── mise en correspondance C2 : matière du cycle de vie d'appel + instantané santé de la face d'injection (vide avant câblage de la moitié hôte) ──
  const extra = healthSnapshot?.() ?? {}
  const state = deriveState({
    hasResult,
    resultIsError,
    invokePhase,
    ...extra,
  })

  const argsRaw = typeof block === 'object' && block !== null && 'argsRaw' in block
    ? String((block as { argsRaw: unknown }).argsRaw ?? '')
    : ''
  const text = t as (key: string) => string

  return (
    <div className="rq-ecard" data-state={state.state} data-tool={toolName}>
      <div className="rq-ecard-head">
        <span>{toolName}</span>
        <span className="rq-ecard-chip">{text(`card.state.${state.state}`)}</span>
      </div>
      {argsRaw !== '' && (state.state === 'calling' || state.state === 'executing') && (
        <div className="rq-ecard-args">{argsRaw}</div>
      )}
      <CardBody state={state} block={block} toolName={toolName} t={t} />
    </div>
  )
}
