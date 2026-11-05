/**
 * Port étroit de stratégie de travail des employés numériques (plan d'exécution : « Employés numériques et appel des ressources plateforme — articulation technique et chemin de mise en œuvre » 2026-10-15 §10.2, annexe D.5).
 *
 * Discipline de direction des dépendances (anti-cycle d'assemblage, annexe A décision 10) :
 *   - platform-core ne déclare que les types et l'enregistreur, n'importe aucun plugin métier en retour ;
 *   - plugin-workforce, une fois assemblé, appelle register() pour enregistrer l'implémentation réelle de la stratégie ;
 *   - les passerelles de ressources (mcp/connector/modelgw/nas/skillhub) et exec-hub ne dépendent que de ce fichier,
 *     et consomment via ctx.workforcePolicy. Si le fournisseur n'est pas enregistré, port() renvoie null :
 *     les nouveaux parcours de travail des employés numériques sont tous indisponibles (refus), jamais de passage silencieux sans stratégie (recette V29).
 *
 * Sémantique clé anti-contournement (D.5) : « est-ce un employé numérique géré » se juge uniquement par reconnexion à partir du caller vérifié,
 * indépendamment de la présence d'un contexte work dans la requête — la suppression du contexte par l'employé ne doit pas ramener vers l'ancienne branche permissive.
 * Autorisation à deux niveaux en intersection : ce port ne fait que l'autorisation de niveau travail, la chaîne d'autorisation existante des passerelles de ressources reste intégralement en place.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { t } from '../../platform-i18n/src/index.ts'

// ---------------------------------------------------------------------------
// Niveaux de confidentialité métier unifiés (D14) : sémantique différente des énumérations homonymes du schéma Agent / ModelGateway,
// toute la facette travail de la plateforme n'utilise que cette convention ; le mapping vers les anciens protocoles doit être fait explicitement par les adaptateurs, jamais de repli silencieux sur internal.
//   public      public
//   internal    interne
//   secret      secret (niveau secret métier)
//   confidential confidentiel (le traitement par Agent exige une approbation)
//   topsecret   ultra-secret (traitement direct par Agent interdit : refus direct avant tout appel de modèle/ressource)
// ---------------------------------------------------------------------------
export type WorkDataClass = 'public' | 'internal' | 'secret' | 'confidential' | 'topsecret'

export const WORK_DATA_CLASS_ORDER: Record<WorkDataClass, number> = {
  public: 0,
  internal: 1,
  secret: 2,
  confidential: 3,
  topsecret: 4,
}

/** Codes de refus du domaine (chemin de mise en œuvre §13.3 ; l'erreur doit guider « arrêter, demander, attendre, vérifier ou réessayer »). */
export type WorkDenyCode =
  | 'WORKFORCE_NOT_READY'
  | 'EMPLOYEE_NOT_ACTIVE'
  | 'APPOINTMENT_NOT_EFFECTIVE'
  | 'APPOINTMENT_EXPIRED'
  | 'PRINCIPAL_BINDING_MISMATCH'
  | 'RUN_NOT_OWNED'
  | 'LEASE_STALE'
  | 'TOOL_NOT_GRANTED'
  | 'ARGUMENT_SCOPE_DENIED'
  | 'APPROVAL_REQUIRED'
  | 'BUDGET_EXCEEDED'
  | 'STEP_ARGUMENT_CONFLICT'
  | 'OUTCOME_UNKNOWN'
  | 'ARTIFACT_SCOPE_DENIED'
  | 'RATE_LIMITED'
  | 'TOOL_UNKNOWN'
  | 'RISK_UNREGISTERED'
  | 'WORKFORCE_DISABLED'
  | 'POLICY_INTERNAL_ERROR'

export const WORK_DENY_CODE_LABELS: Record<WorkDenyCode, string> = {
  WORKFORCE_NOT_READY: '数字员工工作策略未就绪，工作路径不可用',
  EMPLOYEE_NOT_ACTIVE: '数字员工不在岗（停职或已离岗）',
  APPOINTMENT_NOT_EFFECTIVE: '任用未生效（资源授权准备未完成）',
  APPOINTMENT_EXPIRED: '任用已过期',
  PRINCIPAL_BINDING_MISMATCH: '调用主体与员工技术绑定不匹配',
  RUN_NOT_OWNED: '该 run 不归属当前调用主体',
  LEASE_STALE: '执行租约已过期或被更高版本取代',
  TOOL_NOT_GRANTED: '工具未列入本任用能力清单',
  ARGUMENT_SCOPE_DENIED: '参数超出任用边界（工厂/工单/目录等范围约束）',
  APPROVAL_REQUIRED: '该动作需要业务审批，请展示审批单并等待',
  BUDGET_EXCEEDED: '预算不足或预留失败',
  STEP_ARGUMENT_CONFLICT: '同一业务步骤键已绑定不同参数，冲突拒绝',
  OUTCOME_UNKNOWN: '外部结果不确定，请先查证核验，禁止自动重试写入',
  ARTIFACT_SCOPE_DENIED: '文件范围越界（仅允许受控 artifact 上传/读取）',
  RATE_LIMITED: '命中可重试流控，请按服务端重试策略退避',
  TOOL_UNKNOWN: '工具句柄无法解析到已登记资源',
  RISK_UNREGISTERED: '工具风险未登记生效，写能力须先经风险登记审批（V11）',
  WORKFORCE_DISABLED: '数字员工域对本组织处于灰度关闭',
  POLICY_INTERNAL_ERROR: '工作策略执行异常（fail-closed）',
}

/** Appelant vérifié : résolu par chaque point d'entrée depuis jeton/session (structure alignée sur rest-gate CallerInfo), jamais depuis les paramètres de la requête. */
export interface WorkCallerRef {
  kind: 'human' | 'machine'
  principalId: string
  userId?: string
  /** Spécifique machine : ressource liée à l'identifiant (refType=agent permet de reconnaître l'employé numérique lié). */
  refType?: string
  refId?: string
  name?: string
}

/** Référence d'employé numérique géré (résultat de reconnexion côté serveur). */
export interface ManagedEmployeeRef {
  employeeId: string
  agentId: string
  appointmentId: string
  appointmentVersion: number
  workOrgId: string
  /** Plafond de confidentialité métier du gel d'affectation. */
  dataClass: WorkDataClass
}

/** Fait d'action sur ressource : résolu par le service de ressource lui-même, jamais d'auto-rapport de risque accepté du client/du modèle (annexe D.5). */
export interface ResourceActionFacts {
  kind: 'mcp' | 'connector' | 'model' | 'skill' | 'nas' | 'app'
  /** ID de service mcp / provider connector / slug de modèle / ID de skill / ID NAS / ID d'application. */
  registryId: string
  /** Nom d'outil / ID d'action / invoke / read|write|search… selon la sémantique de chaque passerelle. */
  action: string
  /**
   * Cure V11 du lot W : risk prend la « valeur effective du registre de risques fiable » ; sans enregistrement effectif, 'unknown'
   * (ni ouverture implicite sur read, ni jugement initial aveuglément conservateur sur write).
   * L'arbitrage de 'unknown' se fait dans le port de stratégie de travail : contexte en lecture seule (handle de listing n'accordant que read / contraintes de lecture seule) → passage,
   * contexte d'écriture → toujours refus RISK_UNREGISTERED — toute capacité d'écriture doit d'abord suivre « enregistrement → revue → mise en effet ».
   */
  risk: 'read' | 'write' | 'admin' | 'unknown'
}

/** Index de référence de travail : peut être porté par la requête, uniquement comme index ; les faits d'autorisation sont toujours revérifiés côté serveur (§10.4). */
export interface WorkRefIndex {
  permitId?: string
  runId?: string
  issueId?: string
  stepKey?: string
  traceId?: string
}

export interface WorkActionQuery {
  facts: ResourceActionFacts
  ref?: WorkRefIndex
  /** Résumé normalisé des paramètres (haché), calculé par la passerelle appelante ; sert au jugement de conflit d'étapes et à l'audit. */
  argsHash?: string
}

/** Contexte d'exécution fiable après vérification serveur (§8.3) : identité, organisation, version et chaîne de délégation résolues côté serveur, pas de JSON isomorphe accepté du client. */
export interface WorkExecutionContext {
  employeeId: string
  agentId: string
  principalId: string
  appointmentId: string
  appointmentVersion: number
  workOrgId: string
  dataClass: WorkDataClass
  /** Initiateur métier d'origine (conservé s'il existe, coexiste avec l'identité de l'employé sans se recouvrir). */
  requesterUserId?: string
  actChain?: Array<{ name: string; type: string }>
  issueId?: string
  runId?: string
  leaseVersion?: number
  /** ID du permit (autorisation de travail) fondant ce passage. */
  permitId: string
  capabilityManifestId?: string
  policyVersion: number
  traceId?: string
}

export type WorkPolicyDecision =
  | { allow: true; work: WorkExecutionContext }
  | { allow: false; code: WorkDenyCode; message: string }

/** Port de stratégie avant exécution sur ressource : implémenté et enregistré par plugin-workforce ; consommé par les passerelles de ressources avant toute action réseau. */
export interface ResourceExecutionPolicyPort {
  /** Reconnaît l'employé géré à partir du caller fiable ; renvoie null si non employé (l'ancien chemin poursuit sa chaîne d'autorisation existante). */
  resolveManagedEmployee(caller: WorkCallerRef): Promise<ManagedEmployeeRef | null>
  /** Reconnaît l'employé géré à partir de l'Agent technique (scénarios comme la typologie Panel/A2A « question vs exécution »). */
  describeManagedAgent(agentId: string): Promise<ManagedEmployeeRef | null>
  /**
   * Autorisation de niveau travail : employé en poste, affectation effective, permit valide et sujet correspondant, appartenance du run/du bail,
   * outil présent dans la liste de capacités, périmètre des paramètres, état des approbations et du budget. En cas de passage, renvoie le contexte vérifié.
   */
  authorizeWorkAction(caller: WorkCallerRef, query: WorkActionQuery): Promise<WorkPolicyDecision>
}

/**
 * Enregistreur (détenu par platform-core, assemblé avant tout plugin métier).
 * plugin-workforce appelle register() une fois son assemblage terminé (migrations et services prêts).
 */
export class WorkforcePolicyRegistry extends Service {
  static readonly provide = 'workforcePolicy'

  private provider: ResourceExecutionPolicyPort | null = null

  constructor(ctx: Context) {
    super(ctx, 'workforcePolicy')
  }

  register(provider: ResourceExecutionPolicyPort): void {
    this.provider = provider
    try {
      this.ctx.platformBus?.emit('workforce.port.ready', { at: new Date().toISOString() })
    } catch {
      // Si platformBus n'est pas injecté dans le fiber courant, on saute la notification (accès strict aux services cordis)
    }
  }

  /** Non enregistré → renvoie null : les consommateurs passent alors en legacy ou refusent le nouveau parcours de travail (V29). */
  port(): ResourceExecutionPolicyPort | null {
    return this.provider
  }

  isReady(): boolean {
    return this.provider !== null
  }
}

export type ManagedWorkGate =
  | { mode: 'legacy' }
  | { mode: 'denied'; code: WorkDenyCode; message: string }
  | { mode: 'managed'; work: WorkExecutionContext }

/**
 * Aide de consommation unifiée pour les passerelles :
 *   - port non prêt ou appelant absent → legacy (le chemin non géré poursuit sa chaîne d'autorisation existante) ;
 *   - caller correspondant à un employé géré → contrôle de niveau travail ; en cas de refus → denied (fail-closed) ;
 *   - exception d'exécution du port → denied POLICY_INTERNAL_ERROR (pas de repli silencieux).
 * Le jugement ne repose que sur le caller fiable, indépendamment de la présence d'une référence work dans la requête (anti-contournement D.5).
 */
export async function gateManagedWork(
  registry: WorkforcePolicyRegistry | null | undefined,
  caller: WorkCallerRef | undefined | null,
  query: WorkActionQuery,
): Promise<ManagedWorkGate> {
  const port = registry?.port?.() ?? null
  if (!port || !caller) return { mode: 'legacy' }
  let managed: ManagedEmployeeRef | null
  try {
    managed = await port.resolveManagedEmployee(caller)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { mode: 'denied', code: 'POLICY_INTERNAL_ERROR', message: t('工作策略反查失败（fail-closed）：{message}', { message }) }
  }
  if (!managed) return { mode: 'legacy' }
  try {
    const decision = await port.authorizeWorkAction(caller, query)
    return decision.allow ? { mode: 'managed', work: decision.work } : { mode: 'denied', code: decision.code, message: decision.message }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { mode: 'denied', code: 'POLICY_INTERNAL_ERROR', message: t('工作策略校验异常（fail-closed）：{message}', { message }) }
  }
}

// Compléments de type Cordis Context : workforcePolicy est fourni par platform-core lors du premier assemblage (provide='workforcePolicy'),
// les passerelles de ressources et exec-hub consomment via ctx.workforcePolicy — inscrit dans le contrat Context pour éliminer l'angle mort de typage des lectures défensives
// (écriture alignée sur le declare module en fin de plugin-exec-hub/src/index.ts).
declare module '@deepseek-ai/cordis' {
  interface Context {
    workforcePolicy: WorkforcePolicyRegistry
  }
}
