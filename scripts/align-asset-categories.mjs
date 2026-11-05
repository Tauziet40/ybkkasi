#!/usr/bin/env node
/**
 * Migration d'alignement des classifications d'actifs (unification des classifications par étiquette des volets d'actifs, 2026-10-28) :
 * aligne dans skill~skills.json les classifications héritées (efficacité bureautique/efficacité R&D/générale/Partenaires·… etc.) vers les
 * 11 items standard de la plateforme (finance/administration/RH/ventes/opérations/stratégie/production/R&D/qualité/fabrication/autres),
 * la valeur d'origine étant conservée dans tags (sans perte d'information).
 *
 * Même périmètre que alignAssetCategory de platform-core/src/taxonomy.ts (table dupliquée ici,
 * car un script d'exécution en Node pur ne peut pas importer de TS ; les deux endroits à synchroniser en cas de modification).
 *
 * Usage : node scripts/align-asset-categories.mjs [dataDir ...] (défaut data data-demo)
 * Idempotent : les enregistrements déjà en classification standard sont sautés tels quels ; exécutions répétées sans effet de bord.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const ASSET_CATEGORIES = ['财务', '行政', '人事', '销售', '运营', '战略', '生产', '研发', '质量', '制造', '其他']

const LEGACY_CATEGORY_MAP = {
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

/** Même périmètre que normalizeAssetCategory : valeur standard telle quelle ; valeur héritée → table ; préfixe partenaire/valeur inconnue → « autres ». */
function normalizeCategory(raw) {
  const text = String(raw ?? '').trim()
  if (!text) return '其他'
  if (ASSET_CATEGORIES.includes(text)) return text
  if (LEGACY_CATEGORY_MAP[text]) return LEGACY_CATEGORY_MAP[text]
  if (text.startsWith('合作方')) return '其他'
  return '其他'
}

function alignSkillsFile(file) {
  const raw = readFileSync(file, 'utf8')
  const payload = JSON.parse(raw)
  const records = Array.isArray(payload) ? payload : payload.items
  if (!Array.isArray(records)) {
    console.log(`  跳过 ${file}（非记录数组）`)
    return
  }
  let changed = 0
  const mappingSeen = new Map()
  for (const record of records) {
    const original = String(record.category ?? '').trim()
    const next = normalizeCategory(original)
    if (original && original !== next) {
      mappingSeen.set(original, next)
      record.category = next
      const tags = Array.isArray(record.tags) ? record.tags : []
      if (!tags.includes(original)) tags.push(original)
      record.tags = tags
      changed++
    }
  }
  if (changed > 0) {
    writeFileSync(file, JSON.stringify(payload, null, 2) + '\n')
  }
  console.log(`  ${file}：对齐 ${changed}/${records.length} 条`)
  for (const [from, to] of [...mappingSeen.entries()].sort()) console.log(`    ${from} → ${to}`)
}

const dirs = process.argv.slice(2).length ? process.argv.slice(2) : ['data', 'data-demo']
for (const dir of dirs) {
  // Skill : classification héritée → classification standard (valeur d'origine conservée dans tags)
  const file = join(resolve(dir), 'skill~skills.json')
  try {
    readFileSync(file)
  } catch {
    console.log(`  跳过 ${file}（不存在）`)
    continue
  }
  alignSkillsFile(file)

  // Services MCP : enregistrements existants sans champ category → compléter « autres » (explicite, la lecture ne dépend plus du repli)
  const mcpFile = join(resolve(dir), 'mcp~services.json')
  try {
    const payload = JSON.parse(readFileSync(mcpFile, 'utf8'))
    const records = Array.isArray(payload) ? payload : payload.items
    if (Array.isArray(records)) {
      let patched = 0
      for (const record of records) {
        if (record.category === undefined) {
          record.category = normalizeCategory(record.category)
          patched++
        }
      }
      if (patched > 0) writeFileSync(mcpFile, JSON.stringify(payload, null, 2) + '\n')
      console.log(`  ${mcpFile}：补缺省分类 ${patched}/${records.length} 条`)
    }
  } catch {
    console.log(`  跳过 ${mcpFile}（不存在或非 JSON）`)
  }
}
console.log('分类对齐迁移完成。')
