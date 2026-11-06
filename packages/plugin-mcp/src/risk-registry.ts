/**
 * Enregistrement des risques de confiance des outils MCP (lot W W1 · correction de racine V11 · décisions D-① (approbation à deux niveaux)/D-⑤ (ré-examen intégral)).
 *
 * Contexte (correction V11) : la liste d'outils synchronisée depuis tools/list distant ne peut pas prouver son risque. L'ancien référentiel mappait implicitement
 * les outils non déclarés sur read (« inconnu = lisible »), une capacité d'écriture pouvait contourner l'approbation par le canal de synchronisation et entrer directement dans la face d'appel. Référentiel de racine :
 *   - la barrière de passerelle prend facts.risk toujours à « la valeur en vigueur du présent enregistrement » (effectiveRisk) ; sans enregistrement en vigueur → 'unknown' ;
 *   - l'arbitrage de 'unknown' est dans le port de politique de travail et le contexte lecture de la passerelle : contexte lecture = passage, contexte écrit = refus RISK_UNREGISTERED ;
 *   - une capacité d'écriture doit d'abord passer la machine à états « enregistrement → approbation domaine → (write/admin) approbation sécurité → en vigueur » (D-①).
 *
 * Machine à états (enregistrer = soumettre, miroir de la forme d'approbation à deux niveaux de skillhub) :
 *   pending_domain ─(domain approve, risk=read)──→ effective
 *   pending_domain ─(domain approve, risk=write|admin)──→ pending_security ─(security approve)──→ effective
 *   pending_domain / pending_security ─(reject)──→ rejected (état terminal, un nouvel enregistrement ouvre une nouvelle fiche)
 *   effective ─(retire)──→ retired (après retrait, la barrière retourne à unknown, le contexte écrit recouvre le refus — un enregistrement peut entrer en vigueur comme être retiré)
 *
 * Unicité : au plus un enregistrement non retired par (serviceId, toolName) — effective doit d'abord être retiré avant nouvel enregistrement,
 * rejected ne bloque pas un nouvel enregistrement (une conclusion de rejet ne verrouille pas l'avenir).
 * Usage d'approbation (miroir de skillhub index.ts:265-269) : la même personne peut enchaîner les deux niveaux, le même niveau refuse à la même personne.
 *
 * Liste de ré-examen (D-⑤=a : ré-examen intégral avant d'ouvrir l'écriture) : énumère les outils de tous les services external+real, réconcilie outil par outil
 * « valeur déclarée vs valeur d'enregistrement en vigueur », orphan capture les enregistrements pointant des services/outils disparus (service glissé hors external+real compris).
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type { McpServiceRecord, McpToolSpec } from './index.ts'

/** Domaine de valeurs en vigueur de l'enregistrement des risques de confiance (la valeur déclarée admet de plus 'unknown' — défaut honnête de tools/list distant). */
export type McpToolRiskLevel = 'read' | 'write' | 'admin'

/** États d'une fiche d'enregistrement : pending_* en approbation ; effective en vigueur ; rejected rejetée ; retired retirée. */
export type McpToolRiskStatus = 'pending_domain' | 'pending_security' | 'effective' | 'rejected' | 'retired'

/** Entrée de trace d'approbation (l'identité de l'approbateur vient toujours du caller analysé côté serveur, aucun paramètre de requête ne la désigne — contre l'approbation par procuration). */
export interface McpToolRiskApproval {
  level: 'domain' | 'security'
  approverId: string
  approverName: string
  opinion: string
  at: string
}

/** Fiche d'enregistrement de risque (collection opsStorage mcp:toolRisks). */
export interface McpToolRiskRecord {
  id: string
  serviceId: string
  toolName: string
  risk: McpToolRiskLevel
  status: McpToolRiskStatus
  registeredBy: string
  registeredByName: string
  registeredAt: string
  /** Motif d'enregistrement (obligatoire ; write/admin doit de plus expliquer l'usage et le périmètre d'impact). */
  reason: string
  approvals: McpToolRiskApproval[]
  effectiveAt?: string
  retiredAt?: string
  /** Motif de retrait (additive : champ de trace hors contrat de la machine à états, dont dépendent le ré-examen et la traçabilité). */
  retireReason?: string
  updatedAt: string
}

/** États d'une entrée de la liste de ré-examen : unregistered = pas d'enregistrement en vigueur (la capacité d'écriture est toujours refusée) ; registered = déclaration et enregistrement concordants (ou déclaration unknown avec enregistrement en vigueur) ; mismatch = valeur en vigueur ≠ valeur déclarée précise ; orphan = enregistrement pointant un service/outil disparu. */
export type McpToolRiskReviewState = 'unregistered' | 'registered' | 'mismatch' | 'orphan'

export interface McpToolRiskReviewItem {
  serviceId: string
  serviceName: string
  toolName: string
  /** Valeur déclarée par la liste d'outils (absente si orphan avec outil disparu). */
  declaredRisk?: McpToolSpec['riskLevel']
  /** Valeur d'enregistrement en vigueur (absente sans enregistrement en vigueur). */
  registeredRisk?: McpToolRiskLevel
  state: McpToolRiskReviewState
}

export class McpToolRiskRegistry extends Service {
  static readonly provide = 'mcpToolRisks'

  constructor(ctx: Context) {
    super(ctx, 'mcpToolRisks')
  }

  /** Collection d'enregistrements (sur le modèle de getter opsStorage de services() dans index.ts). */
  records(): Collection<McpToolRiskRecord> {
    return this.ctx.opsStorage.collection<McpToolRiskRecord>('mcp:toolRisks')
  }

  // -- Enregistrement et approbation -----------------------------------------------------------

  /**
   * Enregistrer = soumettre (D-①) : tombe toujours d'abord en pending_domain, approbation de domaine ; write/admin monte automatiquement en approbation sécurité après passage du domaine.
   * reason obligatoire (garde-fou : un enregistrement de capacité d'écriture sans motif n'est pas recevable) ; l'identité vient de l'actor analysé côté serveur, aucune autodéclaration par paramètre de requête.
   */
  submit(input: { serviceId: string; toolName: string; risk: McpToolRiskLevel; reason: string; actor: { id: string; name: string } }): McpToolRiskRecord {
    if (!input.serviceId?.trim()) throw new Error(t('serviceId 必填'))
    if (!input.toolName?.trim()) throw new Error(t('toolName 必填'))
    if (!['read', 'write', 'admin'].includes(input.risk)) throw new Error(t('risk 须为 read/write/admin，收到 {value}', { value: String(input.risk) }))
    if (!input.reason?.trim()) throw new Error(t('登记必须填写原因（write/admin 风险更须说明用途与影响面）'))
    if (!input.actor?.id) throw new Error(t('登记人身份缺失（fail-closed：身份一律来自服务端解析）'))
    const service = this.ctx.mcpRegistry.services().get(input.serviceId)
    if (!service) throw new Error(t('MCP 服务不存在：{id}', { id: input.serviceId }))
    if (!service.tools.some((tool) => tool.name === input.toolName)) {
      throw new Error(t('服务 {service} 不存在工具 {tool}（请先同步工具清单再登记）', { service: service.name, tool: input.toolName }))
    }
    // Unicité : au plus un enregistrement « sans conclusion » par (serviceId, toolName) — effective doit d'abord être retiré ;
    // pending attend l'approbation ; rejected/retired ont une conclusion, ne bloquent pas un nouvel enregistrement (les conclusions de retrait et de retrait ne verrouillent pas l'avenir).
    // findOne : le find de collection renvoie un tableau, vide il est aussi véridique ; pour un élément unique, utiliser findOne.
    const existing = this.records().findOne((item) => item.serviceId === input.serviceId && item.toolName === input.toolName
      && item.status !== 'retired' && item.status !== 'rejected')
    if (existing) {
      if (existing.status === 'effective') throw new Error(t('工具已有生效登记（risk={risk}），变更须先退场（retire）再重新登记', { risk: existing.risk }))
      throw new Error(t('工具已有进行中的登记（status={status}），请等待审批完成或先行处理原单据', { status: existing.status }))
    }
    const at = now()
    return this.records().insert({
      id: newId('mtr'),
      serviceId: input.serviceId,
      toolName: input.toolName,
      risk: input.risk,
      status: 'pending_domain',
      registeredBy: input.actor.id,
      registeredByName: input.actor.name,
      registeredAt: at,
      reason: input.reason.trim(),
      approvals: [],
      updatedAt: at,
    })
  }

  /**
   * Arbitrage de l'approbation à deux niveaux (D-①). Un level ne correspondant pas au niveau pending courant = refus (machine à états séquentielle, pas de saut de niveau) ;
   * la même personne ne peut pas approuver deux fois au même niveau (miroir skillhub : même personne enchaîne les deux niveaux, même niveau refuse à la même personne).
   */
  decide(id: string, input: { decision: 'approve' | 'reject'; level: 'domain' | 'security'; opinion?: string; actor: { id: string; name: string } }): McpToolRiskRecord {
    const record = this.requireRecord(id)
    if (record.status !== 'pending_domain' && record.status !== 'pending_security') {
      throw new Error(t('当前状态 {status} 不可审批（仅 pending 态可审批）', { status: record.status }))
    }
    if (record.status === 'pending_domain' && input.level !== 'domain') throw new Error(t('领域审批已完成，当前等待安全审批（level 须为 security）'))
    if (record.status === 'pending_security' && input.level !== 'security') throw new Error(t('当前等待安全审批（level 须为 security；write/admin 风险必须安全加签）'))
    if (!input.actor?.id) throw new Error(t('审批人身份缺失（fail-closed：身份一律来自服务端解析，防代审）'))
    if (record.approvals.some((item) => item.level === input.level && item.approverId === input.actor.id)) {
      throw new Error(t('同一审批人不可重复审批同一级'))
    }
    const approval: McpToolRiskApproval = {
      level: input.level,
      approverId: input.actor.id,
      approverName: input.actor.name,
      opinion: input.opinion ?? '',
      at: now(),
    }
    if (input.decision === 'reject') {
      // Tout état pending peut devenir rejected : l'état terminal ne bloque pas un futur nouvel enregistrement (une conclusion de rejet ne verrouille pas la vie de l'outil)
      return this.records().update(id, { status: 'rejected', approvals: [...record.approvals, approval], updatedAt: now() })
    }
    // approve : après passage du domaine, read prend directement effet / write|admin doit basculer en approbation sécurité (D-① deux niveaux) ; après passage de la sécurité, prend effet
    const nextStatus: McpToolRiskStatus = record.status === 'pending_domain'
      ? (record.risk === 'read' ? 'effective' : 'pending_security')
      : 'effective'
    const at = now()
    return this.records().update(id, {
      status: nextStatus,
      approvals: [...record.approvals, approval],
      ...(nextStatus === 'effective' ? { effectiveAt: at } : {}),
      updatedAt: at,
    })
  }

  /** Retrait (seul effective peut être retiré) : après retrait, effectiveRisk retourne à undefined, la barrière retourne à unknown — le contexte écrit recouvre immédiatement le refus. */
  retire(id: string, input: { reason: string; actor: { id: string; name: string } }): McpToolRiskRecord {
    const record = this.requireRecord(id)
    if (record.status !== 'effective') throw new Error(t('当前状态 {status} 不可退场（仅生效登记可 retire）', { status: record.status }))
    if (!input.reason?.trim()) throw new Error(t('退场必须填写原因（护栏要求，重审与追溯依赖该口径）'))
    const at = now()
    return this.records().update(id, { status: 'retired', retiredAt: at, retireReason: input.reason.trim(), updatedAt: at })
  }

  // -- Requêtes et réconciliation -----------------------------------------------------------

  get(id: string): McpToolRiskRecord | undefined {
    return this.records().get(id)
  }

  list(filter: { serviceId?: string; status?: string; toolName?: string } = {}): { total: number; items: McpToolRiskRecord[] } {
    const items = this.records().find((item) => {
      if (filter.serviceId && item.serviceId !== filter.serviceId) return false
      if (filter.status && item.status !== filter.status) return false
      if (filter.toolName && item.toolName !== filter.toolName) return false
      return true
    }).sort((a, b) => b.registeredAt.localeCompare(a.registeredAt))
    return { total: items.length, items }
  }

  /** Unique source de risque de confiance de la barrière de la passerelle : seul effective est en vigueur ; pending/rejected/retired sont tous considérés non enregistrés (unknown). */
  effectiveRisk(serviceId: string, toolName: string): McpToolRiskLevel | undefined {
    const record = this.records().findOne((item) => item.serviceId === serviceId && item.toolName === toolName && item.status === 'effective')
    return record?.risk
  }

  /**
   * Liste de ré-examen intégral (D-⑤=a : ré-examiner tout avant d'ouvrir l'écriture). Périmètre = les outils de tous les services mode==='external' && exec==='real'
   * (les faces démo/gérées ne passent pas par le vrai canal de synchronisation distant, hors périmètre de convergence V11) ; s'ajoutent en orphan les enregistrements non retired
   * pointant des services/outils disparus (les faits hors liste doivent aussi être visibles, sinon un enregistrement peut rester suspendu en silence).
   */
  reviewList(): { total: number; stats: Record<McpToolRiskReviewState, number>; items: McpToolRiskReviewItem[] } {
    const services = this.ctx.mcpRegistry.services().all()
      .filter((service: McpServiceRecord) => service.mode === 'external' && service.exec === 'real')
    const items: McpToolRiskReviewItem[] = []
    for (const service of services) {
      for (const tool of service.tools) {
        const registeredRisk = this.effectiveRisk(service.id, tool.name)
        const declared = tool.riskLevel
        // Précision sur le jugement d'état : declared==='unknown' signifie « non déclaré » (défaut honnête de la synchronisation tools/list),
        // sans relation de « contradiction » avec la valeur d'enregistrement — un enregistrement en vigueur donne registered, pas mismatch ;
        // mismatch est réservé à la vraie dérive « valeur déclarée précise ≠ valeur en vigueur » (face déclarative modifiée par un humain/enregistrement périmé).
        let state: McpToolRiskReviewState
        if (!registeredRisk) state = 'unregistered'
        else if (!declared || declared === 'unknown') state = 'registered'
        else state = declared === registeredRisk ? 'registered' : 'mismatch'
        items.push({
          serviceId: service.id,
          serviceName: service.name,
          toolName: tool.name,
          declaredRisk: declared,
          ...(registeredRisk ? { registeredRisk } : {}),
          state,
        })
      }
    }
    for (const record of this.records().all()) {
      if (record.status === 'retired') continue
      // Service hors du périmètre external+real (supprimé/passé géré/passé démo) ou outil disparu de la liste → orphan
      const service = services.find((item) => item.id === record.serviceId)
      if (service && service.tools.some((tool) => tool.name === record.toolName)) continue
      if (items.some((item) => item.serviceId === record.serviceId && item.toolName === record.toolName)) continue
      items.push({
        serviceId: record.serviceId,
        serviceName: service?.name ?? record.serviceId, // service supprimé : pas de nom disponible, on pose honnêtement l'ID
        toolName: record.toolName,
        ...(record.status === 'effective' ? { registeredRisk: record.risk } : {}),
        state: 'orphan',
      })
    }
    const stats: Record<McpToolRiskReviewState, number> = { unregistered: 0, registered: 0, mismatch: 0, orphan: 0 }
    for (const item of items) stats[item.state]++
    return { total: items.length, stats, items }
  }

  private requireRecord(id: string): McpToolRiskRecord {
    const record = this.records().get(id)
    if (!record) throw new Error(t('风险登记不存在：{id}', { id }))
    return record
  }
}

function now(): string {
  return new Date().toISOString()
}
