/**
 * 平台资产统一业务分类（各资产板块共用口径）。
 * 与后端 platform-core/src/taxonomy.ts 的 ASSET_CATEGORIES 保持同序同值；
 * 遗留分类（办公提效/研发效能…）由后端对齐迁移，前端只认标准 11 项。
 * 注意：这是与后端对齐的**数据值**（用于与 attrs.category 比对），不是 UI 文案——
 * 保持中文原值、不包 rqI18n.t（包了会破坏比对且模块加载早于词典）；展示层由 i18n DOM 引擎整词翻译（词典已含 11 项）。
 */
export const ASSET_CATEGORIES = ['财务', '行政', '人事', '销售', '运营', '战略', '生产', '研发', '质量', '制造', '其他']

/** 未声明分类时的兜底值（旧记录无分类按「其他」筛选）。 */
export const DEFAULT_ASSET_CATEGORY = '其他'

/** 资产记录的生效分类：attrs.category 缺失回落「其他」（分类字段后补的存量数据）。 */
export function assetCategory(attrs) {
  const value = String(attrs?.['category'] ?? '').trim()
  return ASSET_CATEGORIES.includes(value) ? value : DEFAULT_ASSET_CATEGORY
}
