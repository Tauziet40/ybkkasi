/**
 * Classification métier unifiée des actifs plateforme (alignement des volets d'actifs, 2026-10-28).
 *
 * Marketplace de Skills / Agents / Applications IA / services MCP / annuaire de collaboration A2A partagent la même classification de domaines métier,
 * pour que les métiers retrouvent les actifs selon « mon département, mon type de problème » plutôt que selon la forme technique.
 * Périmètre fixé à 11 items : finance / administration / RH / ventes / opérations / stratégie / production / R&D / qualité / fabrication / autres.
 *
 * Les classifications héritées (« efficacité bureautique/efficacité R&D/… » de l'ancien marketplace de Skills, « ressources humaines/partenaires·… » importées de l'extérieur, etc.)
 * sont alignées vers les items standard via LEGACY_CATEGORY_MAP ; à l'alignement, la valeur d'origine est conservée dans tags, sans perte d'information
 * (le script de migration scripts/align-asset-categories.mjs et la normalize côté écriture partagent cette table).
 */

export const ASSET_CATEGORIES = ['财务', '行政', '人事', '销售', '运营', '战略', '生产', '研发', '质量', '制造', '其他'] as const

export type AssetCategory = (typeof ASSET_CATEGORIES)[number]

/** Classification de repli en cas d'absence de déclaration ou d'alignement impossible. */
export const DEFAULT_ASSET_CATEGORY: AssetCategory = '其他'

/**
 * Table d'alignement classifications héritées → classifications standard. Les clés sont les valeurs d'origine historiquement apparues (correspondance exacte, sans espaces d'extrémité) ;
 * les classifications partenaires préfixées comme « Partenaire·xxx » tombent uniformément dans « autres » par règle de préfixe (voir normalizeAssetCategory).
 */
export const LEGACY_CATEGORY_MAP: Readonly<Record<string, AssetCategory>> = {
  // Classifications intégrées de l'ancien marketplace de Skills
  '办公提效': '行政',
  '研发效能': '研发',
  '客户服务': '销售',
  '数据分析': '运营',
  '人事行政': '人事',
  '市场情报': '销售',
  '法务合规': '行政',
  '通用': '其他',
  // Classifications importées du catalogue de Skills externe
  '人力资源': '人事',
  'HR': '人事',
  '组织建设': '人事',
  '法务': '行政',
  '合规': '行政',
  '效率': '行政',
  '办公': '行政',
  '市场': '销售',
  '营销': '销售',
  '客户支持': '销售',
  '客服': '销售',
  '数据': '运营',
  '经营分析': '运营',
  '产品管理': '研发',
  '产品': '研发',
  '设计': '研发',
  '工程': '研发',
  '技术': '研发',
  '生物研究': '研发',
  '科研': '研发',
  '质检': '质量',
  '品控': '质量',
  '供应链': '生产',
  '采购': '生产',
  '企业检索': '其他',
  '插件管理': '其他',
  'PDF 工具': '其他',
  '小微企业': '其他',
  '会计': '财务',
  '税务': '财务',
}

/** Est-ce une valeur de classification standard. */
export function isAssetCategory(value: unknown): value is AssetCategory {
  return typeof value === 'string' && (ASSET_CATEGORIES as readonly string[]).includes(value)
}

/**
 * Aligne n'importe quelle entrée de classification vers la classification standard : valeur standard renvoyée telle quelle ; valeur héritée → consultation de table ; « Partenaire·… » → « autres » uniformément ;
 * le reste (valeurs vides / personnalisées inconnues) retombe sur DEFAULT_ASSET_CATEGORY.
 */
export function normalizeAssetCategory(value: unknown): AssetCategory {
  const text = String(value ?? '').trim()
  if (!text) return DEFAULT_ASSET_CATEGORY
  if (isAssetCategory(text)) return text
  if (LEGACY_CATEGORY_MAP[text]) return LEGACY_CATEGORY_MAP[text]!
  if (text.startsWith('合作方')) return DEFAULT_ASSET_CATEGORY
  return DEFAULT_ASSET_CATEGORY
}

/**
 * Alignement de classification (partagé écriture/migration) : renvoie la classification alignée, ainsi que la valeur d'origine à fusionner dans tags
 * (conservée seulement si la valeur d'origine est non vide et non standard, pour éviter un doublon entre tags et classification).
 */
export function alignAssetCategory(value: unknown, tags: readonly string[] = []): { category: AssetCategory; tags: string[] } {
  const original = String(value ?? '').trim()
  const category = normalizeAssetCategory(original)
  const nextTags = [...tags]
  if (original && !isAssetCategory(original) && !nextTags.includes(original)) nextTags.push(original)
  return { category, tags: nextTags }
}

/** Liste des classifications standard (items standard en tête) plus les valeurs héritées encore présentes dans les données (garantit la visibilité des anciens enregistrements dans les filtres). */
export function withLegacyCategories(found: Iterable<unknown>): string[] {
  const extras: string[] = []
  for (const item of found) {
    const text = String(item ?? '').trim()
    if (!text || isAssetCategory(text) || extras.includes(text)) continue
    extras.push(text)
  }
  return [...ASSET_CATEGORIES, ...extras]
}
