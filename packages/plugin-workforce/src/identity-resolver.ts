/**
 * Résolution d'identité de l'employé numérique (identity-resolver) — caller de confiance → employé/liaison/nomination en vigueur.
 *
 * Responsabilités (contrat WorkforceIdentityResolver, canevas §5/D.5) :
 *   - le sujet machine de l'employé n'est recherché que par la liaison agent : recherche inverse seulement si machine et refType=agent et refId non vide ;
 *     human renvoie toujours null — le domaine de l'employé n'a pas de canal « l'humain est l'employé » ;
 *   - les trois éléments du jugement géré sont indispensables : employé en poste (active) ＋ liaison un-à-un valide ＋ nomination en vigueur existante
 *     (effective et dans la fenêtre de validité) ; sinon renvoie null (non géré, l'ancien chemin poursuit sur la chaîne d'autorisation d'origine) ;
 *   - le jugement ne repose que sur le caller vérifié et les faits revérifiés côté serveur : les champs d'identité employeeId/appointmentId
 *     portés par la requête ne participent jamais au jugement (anti-contournement, annexe D.5).
 *
 * Le chemin de lecture n'a pas d'effet de bord d'écriture ni de besoin transactionnel (pure recherche inverse), il va directement aux tables de workforceStore.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import type { ManagedEmployeeRef, WorkCallerRef } from '../../../platform-core/src/workforce-port.ts'
import { appointmentInEffect } from './domain.ts'
import type { WorkforceIdentityResolver } from './contract.ts'
import type { AppointmentRecord, BindingRecord, IdentityResolution, AgentBindingState } from './contract.ts'
import type { WorkforceStoreService } from './repositories.ts'

export class IdentityResolverService extends Service implements WorkforceIdentityResolver {
  static readonly provide = 'workforceIdentity'

  constructor(ctx: Context) {
    super(ctx, 'workforceIdentity')
  }

  // -- Accès internes -----------------------------------------------------------

  private get store(): WorkforceStoreService {
    return this.ctx.workforceStore
  }

  /** Liaison active du même Agent (rattrapage de la discipline un-à-un : en cas de multiples, prend la plus ancienne createdAt, pas la plus récente). */
  private activeBindingByAgent(agentId: string): BindingRecord | undefined {
    return this.store.bindings
      .findWhere({ agentId, status: 'active' })
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0))[0]
  }

  /** Nomination actuellement en vigueur : status=effective et dans la fenêtre de validité (appointmentInEffect fail-closed), prend la plus récente par version décroissante. */
  private latestEffectiveAppointment(employeeId: string): AppointmentRecord | undefined {
    return this.store.appointments
      .findWhere({ employeeId })
      .filter((appt) => appointmentInEffect(appt))
      .sort((a, b) => b.version - a.version)[0]
  }

  /** Liaison → identité gérée complète : ne renvoie non null que si employé en poste + nomination en vigueur existante, sinon null (absence honnête). */
  private resolutionFor(binding: BindingRecord): IdentityResolution | null {
    const employee = this.store.employees.get(binding.employeeId)
    if (!employee || employee.status !== 'active') return null
    const appointment = this.latestEffectiveAppointment(binding.employeeId)
    if (!appointment) return null
    return { employee, binding, appointment }
  }

  // -- Implémentation du contrat -----------------------------------------------------------

  async resolveByCaller(caller: WorkCallerRef): Promise<IdentityResolution | null> {
    // human toujours null : le domaine de l'employé n'a pas de canal « l'humain est l'employé » (§5, le commentaire vaut sémantique de contrat)
    if (caller.kind !== 'machine') return null
    if (caller.refType !== 'agent') return null
    const refId = typeof caller.refId === 'string' ? caller.refId.trim() : ''
    if (refId === '') return null
    const binding = this.activeBindingByAgent(refId)
    if (!binding) return null
    return this.resolutionFor(binding)
  }

  async describeAgent(agentId: string): Promise<ManagedEmployeeRef | null> {
    const id = String(agentId ?? '').trim()
    if (id === '') return null
    const binding = this.activeBindingByAgent(id)
    if (!binding) return null
    const resolution = this.resolutionFor(binding)
    if (!resolution) return null
    // La référence gérée vient intégralement des faits revérifiés côté serveur (employé/liaison/nomination), aucun champ porté par la requête n'est répercuté
    return {
      employeeId: resolution.employee.id,
      agentId: binding.agentId,
      appointmentId: resolution.appointment.id,
      appointmentVersion: resolution.appointment.version,
      workOrgId: resolution.appointment.orgId,
      dataClass: resolution.appointment.dataClass,
    }
  }

  /**
   * Sonde à trois états de la liaison (2e item de la gouvernance de la face collaboration, P2-01) : non repris / repris mais permit invalide / permit en vigueur.
   * La dichotomie de describeAgent (null ou géré) ne distingue pas les deux premiers — la face collaboration doit les différencier :
   * « jamais repris » passe en legacy, « repris mais hors poste/sans nomination » doit être refusé en fail-closed.
   */
  async inspectAgent(agentId: string): Promise<AgentBindingState> {
    const id = String(agentId ?? '').trim()
    if (id === '') return { agentId: id, bound: false, permitEffective: false }
    const binding = this.activeBindingByAgent(id)
    if (!binding) return { agentId: id, bound: false, permitEffective: false }
    const employee = this.store.employees.get(binding.employeeId)
    if (!employee || employee.status !== 'active') {
      return {
        agentId: id, bound: true, permitEffective: false,
        employeeId: binding.employeeId, bindingId: binding.id, reason: 'EMPLOYEE_NOT_ACTIVE',
      }
    }
    const appointment = this.latestEffectiveAppointment(binding.employeeId)
    if (!appointment) {
      return {
        agentId: id, bound: true, permitEffective: false,
        employeeId: binding.employeeId, bindingId: binding.id, reason: 'NO_EFFECTIVE_APPOINTMENT',
      }
    }
    return {
      agentId: id, bound: true, permitEffective: true,
      employeeId: binding.employeeId, bindingId: binding.id,
    }
  }
}
