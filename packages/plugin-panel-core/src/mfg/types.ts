/**
 * Boîte à outils manufacture — protocole des résultats et définitions d'outils (intégré depuis « jeu d'outils IA manufacture », décision de fusion 2026-10-19).
 *
 * Le protocole conserve la forme v1.0 du projet source (union discriminée ToolResult/Block) — l'intégration ne change que la face porteuse
 * (Express+React → plan de données du panneau porte 01 et SPA sans build), sans toucher au contrat de données, si bien que les assertions de référence,
 * formats d'export et sémantiques de rendu du front sont sans réécriture : le coût de la fusion porte sur le câblage, pas sur le métier.
 */

export type Category =
  | '生产运营'
  | '质量工程'
  | '研发设计'
  | '供应链'
  | '设备运维'
  | '经营财务'
  | '知识与文档'

/** Champ de formulaire : la même définition génère le formulaire web, le gabarit d'import et la validation à l'exécution (source de fait unique). */
export type Field = {
  key: string
  label: string
  type: 'number' | 'text' | 'textarea'
  unit?: string
  min?: number
  max?: number
  default: string | number
  help?: string
}

export type Metric = { label: string; value: string | number; unit?: string; tone?: 'good' | 'warn' | 'neutral' }

/** Union discriminée des blocs de résultat : ces cinq classes seulement, le modèle ne peut pas émettre un HTML/JS arbitraire (liste blanche de la face de rendu). */
export type Block =
  | { type: 'metrics'; items: Metric[] }
  | { type: 'text'; title: string; content: string }
  | { type: 'table'; title: string; columns: string[]; rows: (string | number)[][] }
  | { type: 'bars'; title: string; items: { label: string; value: number }[]; unit?: string }
  | { type: 'scene'; title: string; dimensions: [number, number, number]; count: number; label: string }

export type ToolResult = {
  version: '1.0'
  runId: string
  toolId: string
  title: string
  createdAt: string
  durationMs: number
  mode: 'calculation' | 'model'
  blocks: Block[]
  warnings: string[]
  input: Record<string, unknown>
}

export type ToolDefinition = {
  id: string
  title: string
  subtitle: string
  category: Category
  icon: string
  color: string
  mode: 'calculation' | 'model'
  tags: string[]
  fields: Field[]
  /** Identifiant du noyau d'outil IA (correspond à la clé d'enregistrement skills de quality.ts). */
  skill?: string
  accepts?: string[]
}

/** Métainfos du catalogue de la boîte à outils (la face modèle est évaluée dynamiquement selon l'état de la passerelle de la plateforme, pas déclarée statiquement ici). */
export type CatalogMeta = {
  tools: ToolDefinition[]
  targetCount: number
  catalogStatus: string
}