/**
 * Boîte à outils manufacture — export des résultats (intégré depuis « jeu d'outils IA manufacture » src/core/export.ts, côté serveur).
 *
 * Le projet source téléchargeait côté navigateur via Blob ; en forme panneau, le serveur produit le texte et le navigateur l'écrit
 * (le même rendu sert l'export et « convertir le résultat en contexte pour poursuivre l'analyse », évitant toute dérive de format entre les deux).
 * Périmètre identique au projet source : JSON et Markdown, sans fabriquer d'export bureautique non implémenté.
 */
import type { ToolResult } from './types.ts'

/** ToolResult → Markdown (équivalent du markdown() du projet source, rendu bloc par bloc). */
export function toMarkdown(result: ToolResult): string {
  const body = result.blocks.map((block) => {
    switch (block.type) {
      case 'metrics':
        return block.items.map((item) => `- ${item.label}：${item.value} ${item.unit ?? ''}`).join('\n')
      case 'text':
        return `## ${block.title}\n\n${block.content}`
      case 'bars':
        return `## ${block.title}\n\n${block.items.map((item) => `- ${item.label}: ${item.value} ${block.unit ?? ''}`).join('\n')}`
      case 'table':
        return `## ${block.title}\n\n${[block.columns, block.columns.map(() => '---'), ...block.rows]
          .map((row) => `| ${row.map((cell) => String(cell).replaceAll('|', '\\|').replaceAll('\n', ' ')).join(' | ')} |`)
          .join('\n')}`
      case 'scene':
        return `## ${block.title}\n\n${block.label}：${block.dimensions.join(' × ')} mm；数量 ${block.count}。`
      default:
        return ''
    }
  }).join('\n\n')
  const warnings = result.warnings.map((warning) => `> ${warning}`).join('\n')
  return `# ${result.title}\n\n${result.createdAt}\n\n${body}\n\n${warnings}\n\n运行编号：${result.runId}\n`
}

/** Nom de fichier d'export (avec fragment d'horodatage, pour distinguer des exécutions multiples). */
export function exportFileName(result: ToolResult, extension: 'json' | 'md'): string {
  const stamp = result.createdAt.replace(/[:.]/g, '-').slice(0, 19)
  return `${result.toolId}-${stamp}.${extension}`
}