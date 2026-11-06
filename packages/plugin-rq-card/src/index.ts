/**
 * @dsh-ops/plugin-rq-card — extension d'injection côté session dsh, moitié hôte (WP-06).
 *
 * Extension de pure surface UI : la moitié hôte n'enregistre aucun comportement (mode recopié sur la moitié hôte de dsh ui-message-feedback
 * — un apply vide seulement pour que l'extension apparaisse dans le graphe du loader hôte) ; la moitié navigateur est délivrée via
 * exports['./client'] (lib/client.js) et la déclaration dsh.client de package.json,
 * servie par client-modules sur /plugins/@dsh-ops/plugin-rq-card/client.js et entrée dans le
 * graphe de démarrage cordis (spike §2.1 preuves A1/A3).
 *
 * [Barrière de build (spike §4.4, contrainte dure)] un bundle manquant à l'activation jette bruyamment
 * (MissingClientBundleError → ClientPackageCompositionError → échec du démarrage de l'hôte).
 * Donc avant `dsh web`, il faut exécuter :
 *
 *     node packages/plugin-rq-card/build.mjs     # produit lib/client.js
 *
 * L'entrée name du loader de cordis.yml / cordis.patch.yml doit être le nom de paquet
 * '@dsh-ops/plugin-rq-card' (client-modules résout les métadonnées de paquet par require.resolve ;
 * un chemin de fichier source serait jugé négativement « paquet non client » et mis en cache à vie, spike §4.2).
 *
 * [Contrat de repli markdown (spike §5 plan de repli item 5, obligation côté outils de l'hôte)]
 * Le contenu textuel tool/result des outils de method doit toujours porter un résumé markdown pur + lien console /rq :
 * la carte riche du client ne fait qu'« élever » la même information ; si une montée de version amont invalide la face d'injection, l'expérience
 * utilisateur retombe automatiquement sur ce texte, sans publication de version. summarizeForToolResult() est l'implémentation de référence de ce contrat,
 * réutilisable côté outils (platform-core / plugin-mcp, etc.) lors de l'organisation des résultats — il est conseillé de placer
 * le texte de résumé dans le premier bloc du résultat, la carte riche et le texte pur lisant la même information.
 */

import { CONSOLE_BASE } from './wire.ts'
import { t } from '../../platform-i18n/src/index.ts'

/** Entrée de summarizeForToolResult. */
export interface ToolResultSummaryInput {
  /** Nom de l'outil (ex. mcp_invoke), rendu en gras en première ligne. */
  toolName: string
  /** Résumé métier en une phrase (ce qui intéresse le plus l'utilisateur). */
  summary: string
  /** Route hash de la page de ressource correspondante dans la console /rq (ex. #/mcp) ; défaut = pas de lien généré. */
  consoleHash?: string
  /** Détails clés (paires clé-valeur, rendues ligne par ligne ; rester concis, un résumé n'est pas un journal). */
  details?: Readonly<Record<string, string | number>>
  /** Si le résultat est une anomalie : la première ligne reçoit un préfixe « ⚠ », invitant l'utilisateur à traiter dans la console. */
  isError?: boolean
}

/**
 * Assemble le résumé markdown de repli d'un résultat d'outil (implémentation de référence du contrat côté outils hôte).
 *
 * Exemple de forme :
 *
 *   **mcp_invoke** ⚠ exécution entravée — pas de droit d'accès
 *   - service : inventory (online)
 *   - motif : nas-authz deny
 *   👉 [traiter dans la console method](/rq#/nas-authz)
 *
 * La valeur de retour sert directement de portion du contenu textuel tool/result (sans dépendre d'aucune extension cliente).
 */
export function summarizeForToolResult(input: ToolResultSummaryInput): string {
  const lines: string[] = []
  const flag = input.isError ? '⚠ ' : ''
  lines.push(`**${input.toolName}** ${flag}${input.summary}`)
  for (const [key, value] of Object.entries(input.details ?? {})) {
    lines.push(`- ${t('{key}：{value}', { key, value: String(value) })}`)
  }
  if (input.consoleHash !== undefined) {
    lines.push(t('👉 [到元冰可控制台处理]({url})', { url: `${CONSOLE_BASE}${input.consoleHash}` }))
  }
  return lines.join('\n')
}

/** Corps de l'extension hôte — cette extension de surface n'a aucun comportement côté hôte (la moitié navigateur porte toute l'injection). */
export function apply(): void {}
