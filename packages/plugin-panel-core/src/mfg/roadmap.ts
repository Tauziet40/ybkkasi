/**
 * Boîte à outils manufacture — liste des 100 sujets (intégrée depuis « jeu d'outils IA manufacture » src/core/roadmap.json).
 *
 * Sources et référentiel des données (docs/architecture.md du projet source, non réécrit après intégration) :
 *   - feuille Excel PMO `19_AI原生组织建设_场景清单` lignes 2–296 (295 enregistrements) ;
 *   - PDF « Referenzleitfaden (édition 2025) pour la transformation numérique sectorielle scénarisée et cartographiée », 62 pages, cadre pages 2–6,
 *     cartographie sectorielle pages 37–39 ;
 *   - les 100 items sont des « suggestions de découpe produit à partir des scénarios d'origine », et **non pas 100 outils listés un à un dans l'original** ;
 *     le statut « terminé » d'éléments du tableau d'origine n'est pas hérité comme statut de livraison du présent projet.
 *
 * Lisibilité machine de la frontière honnête : ce fichier est en lecture seule, aucune inférence automatique « planifié → implémenté » ;
 * les statuts implemented-calculation / model-validation-pending / planned de chaque entrée viennent item par item des données elles-mêmes.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export type RoadmapSource = {
  kind: string
  sheet: string
  row: number
  department: string
  originalScenario: string
  originalStatus: string
}

export type RoadmapItem = {
  id: string
  title: string
  group: string
  priority: string
  kernel: string
  renderer: string
  inputContract: string
  workflow: string
  acceptance: string
  status: 'implemented-calculation' | 'model-validation-pending' | 'planned'
  implementation?: string
  sources: RoadmapSource[]
  pdfReferences: Array<{ page: number; relation: string }>
  deliveryBoundary: string
  caveat: string
}

export type Roadmap = {
  version: string
  sourceWorkbook: string
  sourceSheet: string
  sourceRows: number
  sourceStatusCounts: Record<string, number>
  pdfSource: string
  pdfPages: number
  frameworkPages: number[]
  industryPages: number[]
  tools: RoadmapItem[]
}

let cached: Roadmap | undefined

/** Charge la liste des sujets (JSON dans le même répertoire que le paquet, résolu via import.meta — même règle que seed/demo-content.json). */
export function loadRoadmap(): Roadmap {
  if (cached) return cached
  const path = fileURLToPath(new URL('./roadmap.json', import.meta.url))
  cached = JSON.parse(readFileSync(path, 'utf8')) as Roadmap
  return cached
}

/** Liste groupée (pour la page cartographie navigant par scénario métier ; ordre d'apparition dans les données conservé). */
export function roadmapGroups(roadmap: Roadmap): string[] {
  return [...new Set(roadmap.tools.map((item) => item.group))]
}

/** Libellés chinois des statuts (source de fait unique de la couche d'affichage ; statut inconnu renvoyé tel quel, sans avaler l'erreur). */
export const ROADMAP_STATUS_LABELS: Record<string, string> = {
  'implemented-calculation': '计算内核已实现',
  'model-validation-pending': '待模型验收',
  planned: '规划中',
}