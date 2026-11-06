/**
 * Implémentation du port de politique de travail (ResourceExecutionPolicyPort de platform-core workforce-port.ts).
 *
 * Consommateurs : la passerelle de ressources et exec-hub obtiennent cette implémentation via ctx.workforcePolicy.port() (port étroit,
 * sans dépendance inverse). La décision ne repose que sur le caller vérifié, indépendamment du fait que la requête porte un contexte work (anti-contournement D.5) ;
 * ce port ne fait que l'autorisation au niveau travail, la chaîne d'autorisation d'origine de la passerelle de ressources reste entière (intersection des deux couches d'autorisation, §9.5).
 * Toute exception est remontée — gateManagedWork applique fail-closed (POLICY_INTERNAL_ERROR).
 */
import type { Context } from '@deepseek-ai/cordis'
import {
  appointmentInEffect,
} from './domain.ts'
import {
  WorkforceError,
  type IdentityResolution,
  type ManifestToolHandle,
  type WorkforceAdmission,
  type WorkforceCapabilities,
  type WorkforceIdentityResolver,
  type WorkforceStore,
  type WorkforceGrayConfig,
} from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type {
  ManagedEmployeeRef,
  ResourceActionFacts,
  WorkActionQuery,
  WorkCallerRef,
  WorkDataClass,
  WorkPolicyDecision,
} from '../../platform-core/src/workforce-port.ts'
import type { ResourceExecutionPolicyPort } from '../../platform-core/src/workforce-port.ts'

export function createWorkforcePolicyPort(ctx: Context, grayConfig: WorkforceGrayConfig = {}): ResourceExecutionPolicyPort {
  // -- Dépendances (sondage structuré ; le port est enregistré après l'assemblage de workforce, les dépendances sont prêtes) ----------------

  const store = (): WorkforceStore => {
    const target = (ctx as unknown as { workforceStore?: WorkforceStore }).workforceStore
    if (!target || typeof target.txn !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceStore 未就绪'), 503)
    }
    return target
  }

  const identity = (): WorkforceIdentityResolver => {
    const target = (ctx as unknown as { workforceIdentity?: WorkforceIdentityResolver }).workforceIdentity
    if (!target || typeof target.resolveByCaller !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceIdentity 未就绪'), 503)
    }
    return target
  }

  const admission = (): WorkforceAdmission => {
    const target = (ctx as unknown as { workforceAdmission?: WorkforceAdmission }).workforceAdmission
    if (!target || typeof target.verifyPermit !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceAdmission 未就绪'), 503)
    }
    return target
  }

  const capabilities = (): WorkforceCapabilities => {
    const target = (ctx as unknown as { workforceCapabilities?: WorkforceCapabilities }).workforceCapabilities
    if (!target || typeof target.toolsFor !== 'function') {
      throw new WorkforceError('WORKFORCE_NOT_READY', t('workforceCapabilities 未就绪'), 503)
    }
    return target
  }

  /** caller de confiance → référence de l'employé géré ; renvoie null pour un non-employé (l'ancien chemin poursuit sur la chaîne d'autorisation d'origine). */
  async function resolveManagedEmployee(caller: WorkCallerRef): Promise<ManagedEmployeeRef | null> {
    const resolution = await identity().resolveByCaller(caller)
    if (!resolution) return null
    return {
      employeeId: resolution.employee.id,
      agentId: resolution.binding.agentId,
      appointmentId: resolution.appointment.id,
      appointmentVersion: resolution.appointment.version,
      workOrgId: resolution.appointment.orgId,
      dataClass: resolution.appointment.dataClass,
    }
  }

  async function describeManagedAgent(agentId: string): Promise<ManagedEmployeeRef | null> {
    return identity().describeAgent(agentId)
  }

  /** Distingue les motifs de nullité de la nomination (sémantique attente vs arrêt, §13.3). */
  function assertAppointment(resolution: IdentityResolution): void {
    if (appointmentInEffect(resolution.appointment)) return
    const expired = resolution.appointment.effectiveUntil !== ''
      && resolution.appointment.effectiveUntil <= new Date().toISOString()
    throw new WorkforceError(
      expired ? 'APPOINTMENT_EXPIRED' : 'APPOINTMENT_NOT_EFFECTIVE',
      expired ? t('任用已过期') : t('任用未生效（资源授权准备未完成）'),
    )
  }

  /**
   * Jugement de correspondance d'outil (facts résolus par le service de ressources lui-même, risque auto-déclaré client/modèle non accepté, D.5) :
   * mcp/connector/nas/skill par correspondance exacte registryId+action ;
   * model par kind=model et (registryId égal ou constraints.allowedModels contenant facts.registryId).
   */
  function matchTool(tools: ManifestToolHandle[], facts: ResourceActionFacts): ManifestToolHandle | undefined {
    if (facts.kind === 'model') {
      return tools.find((tool) => tool.kind === 'model' && (
        tool.registryId === facts.registryId
        || (Array.isArray(tool.constraints?.['allowedModels'])
          && (tool.constraints['allowedModels'] as unknown[]).includes(facts.registryId))))
    }
    return tools.find((tool) =>
      tool.kind === facts.kind
      && tool.registryId === facts.registryId
      && tool.action === facts.action)
  }

  async function authorizeWorkAction(caller: WorkCallerRef, query: WorkActionQuery): Promise<WorkPolicyDecision> {
    // 1. Identité gérée (un non-employé ne devrait pas entrer dans cette branche — gateManagedWork a déjà réparti selon resolveManagedEmployee)
    const resolution = await identity().resolveByCaller(caller)
    if (!resolution) {
      return { allow: false, code: 'EMPLOYEE_NOT_ACTIVE', message: t('非受管数字员工或绑定缺失') }
    }
    // 1.5 Commutateur de déploiement progressif (contrat W7 du lot W, D-② au niveau organisation) : organisation désactivée = refus explicite (WORKFORCE_DISABLED),
    //     jamais de repli silencieux vers legacy — gateManagedWork rend le denied à la passerelle pour écriture (même référentiel V29 : refus observable)
    if ((grayConfig.grayMode ?? 'off') === 'allowlist'
      && !(grayConfig.enabledOrgs ?? []).includes(resolution.appointment.orgId)) {
      try {
        ctx.platformBus?.emit('workforce.gray.denied', {
          orgId: resolution.appointment.orgId,
          employeeId: resolution.employee.id,
          surface: 'port',
          at: new Date().toISOString(),
        })
      } catch {
        // platformBus non injecté dans la fiber courante : notification sautée (le refus lui-même n'est pas affecté)
      }
      return {
        allow: false,
        code: 'WORKFORCE_DISABLED',
        message: t('数字员工域对组织 {orgId} 处于灰度关闭（仅白名单组织开放）', { orgId: resolution.appointment.orgId }),
      }
    }
    if (resolution.employee.status !== 'active') {
      return { allow: false, code: 'EMPLOYEE_NOT_ACTIVE', message: t('数字员工不在岗（停职或已离岗）') }
    }
    // 2. Nomination en vigueur (la version est la version de politique)
    try {
      assertAppointment(resolution)
    } catch (error) {
      const e = error as WorkforceError
      return { allow: false, code: e.code, message: e.message }
    }
    // 3. permit : justificatif de l'entrée contrôlée (V28 : même avec un nom d'outil deviné, sans permit c'est refusé)
    const ref = query.ref ?? {}
    if (!ref.permitId) {
      return { allow: false, code: 'TOOL_NOT_GRANTED', message: t('数字员工必须携带工作授权 permit 经受控入口调用') }
    }
    let permit
    try {
      permit = await admission().verifyPermit(caller, ref.permitId, { requireRun: true })
    } catch (error) {
      if (error instanceof WorkforceError) {
        return { allow: false, code: error.code, message: error.message }
      }
      throw error
    }
    // Le run lié au permit coïncide avec le run référencé (la référence n'est qu'un index, les faits font foi de la revérification serveur, §10.4)
    if (ref.runId && ref.runId !== permit.runId) {
      return { allow: false, code: 'RUN_NOT_OWNED', message: t('工作引用的 run 与 permit 绑定不一致') }
    }
    // 4. Outil présent dans l'inventaire de capacités (l'inventaire serveur est l'unique fait, §9.2)
    const tool = matchTool(capabilities().toolsFor(permit.manifestId), query.facts)
    if (!tool) {
      return { allow: false, code: 'TOOL_NOT_GRANTED', message: t('工具未列入本任用能力清单') }
    }
    // 5. Intersection des risques : facts en écriture/admin alors que l'inventaire n'accorde que read → refus (annexe D.5 : le risque auto-déclaré n'est pas cru)
    //    Correction de fond V11 du lot W (contrat figé 2026-10-15) : quand facts.risk='unknown' (aucun enregistrement de risque en vigueur côté passerelle) —
    //    poignée d'inventaire accordant seulement read → passage dans le contexte lecture seule (la contrainte lecture seule de la passerelle en rattrapage, le risque résiduel est résorbé par le réexamen de l'inventaire) ;
    //    poignée accordant écriture/admin → refus RISK_UNREGISTERED : une capacité d'écriture doit d'abord passer par « enregistrement→revue→mise en vigueur ».
    if (query.facts.risk === 'unknown') {
      if (tool.risk !== 'read') {
        return {
          allow: false,
          code: 'RISK_UNREGISTERED',
          message: t('工具风险未登记生效，写能力须先经 MCP 风险登记审批（V11）'),
        }
      }
    } else if ((query.facts.risk === 'write' || query.facts.risk === 'admin') && tool.risk === 'read') {
      return { allow: false, code: 'ARGUMENT_SCOPE_DENIED', message: t('该动作为写/管理风险，超出本句柄的只读授权') }
    }
    // 6. Défense contre les conflits d'étapes (défense en profondeur : la vérification principale tient à la contrainte d'unicité d'invocation-service)
    if (query.argsHash && ref.stepKey) {
      const prior = store().invocations.findWhere({ runId: permit.runId, stepKey: ref.stepKey })[0]
      if (prior && prior.argsHash !== query.argsHash) {
        return { allow: false, code: 'STEP_ARGUMENT_CONFLICT', message: t('同一业务步骤键已绑定不同参数，冲突拒绝') }
      }
    }
    // 7. Assemble le contexte d'exécution de confiance vérifié (§8.3 : identité/organisation/version résolues côté serveur)
    return {
      allow: true,
      work: {
        employeeId: resolution.employee.id,
        agentId: resolution.binding.agentId,
        principalId: permit.principalId,
        appointmentId: permit.appointmentId,
        appointmentVersion: permit.appointmentVersion,
        workOrgId: resolution.appointment.orgId,
        dataClass: resolution.appointment.dataClass as WorkDataClass,
        issueId: permit.issueId,
        runId: permit.runId,
        leaseVersion: permit.leaseVersion,
        permitId: permit.id,
        capabilityManifestId: permit.manifestId,
        policyVersion: permit.appointmentVersion,
        // Initiateur métier d'origine : conservé uniquement pour la chaîne human (coexiste avec l'identité de l'employé sans se recouvrir, §5.3)
        ...(caller.kind === 'human' && caller.userId ? { requesterUserId: caller.userId } : {}),
        ...(ref.traceId ? { traceId: ref.traceId } : {}),
      },
    }
  }

  return {
    resolveManagedEmployee,
    describeManagedAgent,
    authorizeWorkAction,
  }
}
