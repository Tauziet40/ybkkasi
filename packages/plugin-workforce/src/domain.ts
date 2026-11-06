/**
 * Couche de politique pure du domaine de l'employé numérique (domain) — pas d'IO, pas d'effet de bord d'horloge, pas de base de données.
 *
 * Discipline de couche homologue de plugin-exec-hub/src/domain.ts (séparation décisions/IO Paperclip) :
 *   - ne placer ici que les tables de transition des machines à états, la politique de classification, le résumé canonique, la validation stepKey et un validateur JSON Schema minimal ;
 *   - tout « lire la base / lire l'horloge / émettre un événement » reste dans la couche service (employee/appointment/identity),
 *     qui calcule les faits (facts) avant de les fournir ;
 *   - ce fichier est consommé par tous les groupes de travail (admission, permit, registre des appels, acceptation de livraison peuvent le réutiliser), sans importer aucun service de cette extension.
 *
 * Référence de canevas : « Employé numérique et appels de ressources de la plateforme - corrélations techniques et chemin d'implémentation » 2026-10-15
 *   §D.4 (machine à états d'effectivité des autorisations de nomination), §9.3 (stepKey et résumé de paramètres), §D14 (classification métier unifiée), §11.5 (règles d'idempotence).
 */
import { sha256Hex } from '../../platform-core/src/ids.ts'
import { WORK_DATA_CLASS_ORDER, type WorkDataClass } from '../../platform-core/src/workforce-port.ts'
import { STEP_KEY_PATTERN, WorkforceError } from './contract.ts'
import { t } from '../../platform-i18n/src/index.ts'
import type {
  AppointmentRecord,
  AppointmentStatus,
  DeliverableStatus,
  EmployeeStatus,
  GrantStatus,
  InvocationStatus,
  PermitStatus,
  ResourceGrantSpec,
} from './contract.ts'

// ---------------------------------------------------------------------------
// Classification métier unifiée (D14) : référentiel unique de la face de travail de toute la plateforme, le mappage vers l'ancien protocole doit être explicite
// ---------------------------------------------------------------------------

/** Ensemble complet des classifications métier (dérivé de la table d'ordre de workforce-port, pour éviter une dérive entre deux listes). */
export const WORK_DATA_CLASS_VALUES = Object.keys(WORK_DATA_CLASS_ORDER) as WorkDataClass[]

/** Valide et normalise la classification métier (pour l'enregistrement de nomination / les paramètres de requête). Une valeur illégale lève une erreur en chinois. */
export function validateWorkDataClass(value: unknown): WorkDataClass {
  if (typeof value === 'string' && Object.hasOwn(WORK_DATA_CLASS_ORDER, value)) return value as WorkDataClass
  throw new Error(t('数据密级不合法：{value}（允许：{allowed}）', { value: String(value), allowed: WORK_DATA_CLASS_VALUES.join('/') }))
}

/**
 * Classification effective = max(classification déclarée par le demandeur, plafond figé par la nomination) (point de refonte §4.1 :
 * la classification se déduit de tâches/de politiques de données de confiance, on ne croit pas un runtime qui s'abaisse seul le dataClass).
 * Non déclarée → repli sur la valeur figée par la nomination — « non déclaré » ne vaut pas « public ».
 */
export function effectiveDataClass(requested: WorkDataClass | undefined, appointment: WorkDataClass): WorkDataClass {
  if (requested === undefined) return appointment
  return WORK_DATA_CLASS_ORDER[requested] >= WORK_DATA_CLASS_ORDER[appointment] ? requested : appointment
}

/** Top secret interdit au traitement par l'employé numérique : refus direct avant tout appel de modèle/ressource (mappage vers un canal haut niveau disponible interdit, D14). */
export function assertAgentAllowedDataClass(dataClass: WorkDataClass): void {
  if (dataClass === 'topsecret') {
    throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('绝密数据禁止数字员工处理'))
  }
}

/**
 * Classification métier → étiquette de niveau de canal modelgw (table de mappage explicite, repli silencieux vers internal interdit).
 *
 * Le DataClass de modelgw n'a que trois niveaux public/internal/secret (plugin-modelgw/src/index.ts) :
 *   - public/internal/secret homonymes et de même niveau dans ce référentiel (ici secret = « secret », cohérent avec le secret de modelgw) ;
 *   - confidential : traitement par l'Agent soumis à approbation, le niveau de canal ne sait pas l'exprimer → renvoie null, refus par l'appelant ;
 *   - topsecret : le traitement par l'Agent est interdit de toute façon (déjà bloqué par assertAgentAllowedDataClass) → renvoie null.
 * Sans correspondance, renvoie null, refus explicite par l'appelant — jamais de rétrogradation discrète en internal (acceptation V14/canevas §4.1).
 */
export function mapWorkDataClassToChannel(dataClass: WorkDataClass): 'public' | 'internal' | 'secret' | null {
  const table: Record<WorkDataClass, 'public' | 'internal' | 'secret' | null> = {
    public: 'public',
    internal: 'internal',
    secret: 'secret',
    confidential: null, // confidentiel : traitement par l'Agent soumis à approbation, le niveau de canal modelgw n'a pas ce degré, sans correspondance = refus
    topsecret: null, // top secret : traitement par l'Agent interdit, pas de mappage
  }
  return table[dataClass] ?? null
}

// ---------------------------------------------------------------------------
// Machines à états (§D.4 / §11.6) : tables de transition explicites + fonctions d'assertion (transition illégale lève une erreur en chinois)
// ---------------------------------------------------------------------------

export const EMPLOYEE_STATUS_LABELS: Record<EmployeeStatus, string> = { active: '在岗', suspended: '停职', offboarded: '离岗' }
export const APPOINTMENT_STATUS_LABELS: Record<AppointmentStatus, string> = {
  preparing: '准备中', effective: '生效', revoking: '撤销中', revoked: '已撤销', failed: '配置失败',
}
export const GRANT_STATUS_LABELS: Record<GrantStatus, string> = APPOINTMENT_STATUS_LABELS
export const PERMIT_STATUS_LABELS: Record<PermitStatus, string> = { active: '有效', revoked: '已撤销', expired: '已过期' }
export const INVOCATION_STATUS_LABELS: Record<InvocationStatus, string> = {
  reserved: '已预留', completed: '已完成', denied: '已拒绝', approval_required: '待审批',
  rate_limited: '命中限流', failed: '失败', outcome_unknown: '结果未知', cancelled: '已取消',
}
export const DELIVERABLE_STATUS_LABELS: Record<DeliverableStatus, string> = { submitted: '已提交', accepted: '已验收', rejected: '已退回' }

/** État de l'employé : active→suspended/offboarded ; suspended→active (reprise)/offboarded ; offboarded est terminal. */
export const EMPLOYEE_TRANSITIONS: Record<EmployeeStatus, EmployeeStatus[]> = {
  active: ['suspended', 'offboarded'],
  suspended: ['active', 'offboarded'],
  offboarded: [],
}

/**
 * État de nomination (§D.4) : preparing→effective (sondes toutes passées)/revoked (révocation directe sans effet)/failed (échec déclaré explicitement) ;
 * effective→revoking→revoked ; revoking est le seul état intermédiaire reprenable (un échec partiel de retrait de droits y demeure pour nouvelle tentative, D.4 5e) ;
 * failed est terminal (après correction, on ouvre une nouvelle version, on ne réécrit pas l'historique).
 */
export const APPOINTMENT_TRANSITIONS: Record<AppointmentStatus, AppointmentStatus[]> = {
  preparing: ['effective', 'revoked', 'failed'],
  effective: ['revoking'],
  revoking: ['revoked'],
  revoked: [],
  failed: [],
}

/** État d'autorisation de ressources : isomorphe à la nomination ; failed→preparing autorise une nouvelle tentative d'activation (relance après correction d'une sonde absente/en échec). */
export const GRANT_TRANSITIONS: Record<GrantStatus, GrantStatus[]> = {
  preparing: ['effective', 'failed', 'revoked'],
  effective: ['revoking'],
  revoking: ['revoked'],
  revoked: [],
  failed: ['preparing'],
}

/** Autorisation de travail : active→revoked/expired ; révoqué/expiré sont terminaux (un ancien permit ne ressuscite jamais, V07). */
export const PERMIT_TRANSITIONS: Record<PermitStatus, PermitStatus[]> = {
  active: ['revoked', 'expired'],
  revoked: [],
  expired: [],
}

/**
 * État d'appel (§9.3) : reserved est l'unique point de départ ; approval_required/rate_limited/outcome_unknown
 * sont des états intermédiaires convergents (écriture retour d'approbation/convergence sur tentative/vérification humaine) ; les autres sont terminaux.
 * outcome_unknown n'autorise que →completed/failed (après vérification humaine reconcile), nouvelle tentative d'écriture directe interdite (§11.5 4e).
 */
export const INVOCATION_TRANSITIONS: Record<InvocationStatus, InvocationStatus[]> = {
  reserved: ['completed', 'denied', 'approval_required', 'rate_limited', 'failed', 'outcome_unknown', 'cancelled'],
  approval_required: ['completed', 'denied', 'failed', 'cancelled'],
  rate_limited: ['completed', 'failed', 'cancelled'],
  outcome_unknown: ['completed', 'failed'],
  completed: [],
  denied: [],
  failed: [],
  cancelled: [],
}

/** Livrable : submitted→accepted/rejected ; rejected est terminal (retour pour refaire = nouvelle version, nouvel enregistrement, §8.2 pas de fusion de versions). */
export const DELIVERABLE_TRANSITIONS: Record<DeliverableStatus, DeliverableStatus[]> = {
  submitted: ['accepted', 'rejected'],
  accepted: [],
  rejected: [],
}

function assertTransition(labels: Record<string, string>, table: Record<string, string[]>, from: string, to: string, subject: string): void {
  const fromLabel = t(labels[from] ?? from)
  const toLabel = t(labels[to] ?? to)
  if (from === to) throw new Error(t('{subject}状态未变化（当前已是「{current}」），无需重复操作', { subject, current: fromLabel }))
  const allowed = table[from] ?? []
  if (!allowed.includes(to)) {
    const hint = allowed.length > 0
      ? t('（允许：{allowed}）', { allowed: allowed.map((s) => t(labels[s] ?? s)).join('/') })
      : t('（终态，不可再流转）')
    throw new Error(t('{subject}状态不允许从「{from}」变更为「{to}」{hint}', { subject, from: fromLabel, to: toLabel, hint }))
  }
}

/** Assertion de transition d'état de l'employé : transition illégale lève une erreur en chinois (400 par la couche routes). */
export function employeeStatusTransition(from: EmployeeStatus, to: EmployeeStatus): void {
  assertTransition(EMPLOYEE_STATUS_LABELS, EMPLOYEE_TRANSITIONS, from, to, t('员工'))
}

/** Assertion de transition d'état de nomination. */
export function appointmentStatusTransition(from: AppointmentStatus, to: AppointmentStatus): void {
  assertTransition(APPOINTMENT_STATUS_LABELS, APPOINTMENT_TRANSITIONS, from, to, t('任用'))
}

/** Assertion de transition d'état d'autorisation de ressources. */
export function grantStatusTransition(from: GrantStatus, to: GrantStatus): void {
  assertTransition(GRANT_STATUS_LABELS, GRANT_TRANSITIONS, from, to, t('资源授权'))
}

/** Assertion de transition d'état de l'autorisation de travail (permit). */
export function permitStatusTransition(from: PermitStatus, to: PermitStatus): void {
  assertTransition(PERMIT_STATUS_LABELS, PERMIT_TRANSITIONS, from, to, t('工作授权'))
}

/** Assertion de transition d'état du registre des appels. */
export function invocationStatusTransition(from: InvocationStatus, to: InvocationStatus): void {
  assertTransition(INVOCATION_STATUS_LABELS, INVOCATION_TRANSITIONS, from, to, t('工作调用'))
}

/** Assertion de transition d'état du livrable. */
export function deliverableStatusTransition(from: DeliverableStatus, to: DeliverableStatus): void {
  assertTransition(DELIVERABLE_STATUS_LABELS, DELIVERABLE_TRANSITIONS, from, to, t('交付物'))
}

// ---------------------------------------------------------------------------
// Fenêtre de validité de la nomination (appointmentInEffect)
// ---------------------------------------------------------------------------

function toMs(input: string | number | Date): number | null {
  if (typeof input === 'number') return Number.isFinite(input) ? input : null
  if (input instanceof Date) return Number.isNaN(input.getTime()) ? null : input.getTime()
  const parsed = Date.parse(input)
  return Number.isNaN(parsed) ? null : parsed
}

/**
 * La nomination est-elle dans sa fenêtre d'effectivité : status=effective et effectiveFrom ≤ now ≤ effectiveUntil (chaîne vide = à durée indéterminée).
 * Une fenêtre dont l'analyse temporelle échoue est traitée « non en vigueur » (fail-closed, absence honnête).
 */
export function appointmentInEffect(
  appt: Pick<AppointmentRecord, 'status' | 'effectiveFrom' | 'effectiveUntil'>,
  now: string | number | Date = new Date(),
): boolean {
  if (appt.status !== 'effective') return false
  const nowMs = toMs(now)
  if (nowMs === null) return false
  const fromMs = toMs(appt.effectiveFrom)
  if (fromMs === null || nowMs < fromMs) return false
  if (appt.effectiveUntil) {
    const untilMs = toMs(appt.effectiveUntil)
    if (untilMs === null || nowMs > untilMs) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// JSON canonique et résumé de paramètres (§9.3 / §11.5) : sérialisation stable par tri des clés
// ---------------------------------------------------------------------------

/**
 * JSON canonique : clés d'objet triées lexicographiquement, valeurs undefined éliminées, délimiteurs sans blanc —
 * un même objet de paramètres donne le même résumé quel que soit l'ordre des clés ; des paramètres différents donnent nécessairement des résumés différents (base du jugement de conflit d'étape).
 * N'accepte que des données exprimables en JSON (string/number/boolean/null/array/object),
 * function/symbol/bigint etc. lèvent une erreur en chinois (le résumé de paramètres ne peut pas voir sa déterminabilité falsifiée).
 */
export function canonicalJson(value: unknown): string {
  if (value === undefined || value === null) return 'null'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return Number.isFinite(value) ? JSON.stringify(value) : 'null'
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return `{${entries.map(([key, v]) => `${JSON.stringify(key)}:${canonicalJson(v)}`).join(',')}}`
  }
  throw new Error(t('参数含不可规范化数据（{type}），无法计算稳定摘要', { type: typeof value }))
}

/** Résumé de paramètres : sha256(canonicalJson). Même stepKey avec des paramètres différents → résumés différents → STEP_ARGUMENT_CONFLICT. */
export function argsHashOf(value: unknown): string {
  return sha256Hex(canonicalJson(value))
}

// ---------------------------------------------------------------------------
// Validation du stepKey (§9.3) : référence d'étape métier proposée par l'appelant, pas une identité de confiance
// ---------------------------------------------------------------------------

/**
 * Validité du stepKey : STEP_KEY_PATTERN du contrat (1-96 caractères, commence par une lettre, chiffres/point/souligné/tiret permis).
 * Illégal lève WorkforceError('ARGUMENT_SCOPE_DENIED') (même code qu'un échec de validation de schéma de paramètres, mappé 400 par la couche routes).
 */
export function assertValidStepKey(stepKey: string): void {
  if (typeof stepKey !== 'string' || !STEP_KEY_PATTERN.test(stepKey)) {
    throw new WorkforceError('ARGUMENT_SCOPE_DENIED', t('步骤键 stepKey 不合法：须为 1-96 位、字母开头，仅含字母/数字/点/下划线/连字符'))
  }
}

// ---------------------------------------------------------------------------
// Validation de l'autorisation de ressources souhaitée (ResourceGrantSpec) : contraintes structurelles minimales partagées par l'enregistrement de nomination et les adaptateurs
// ---------------------------------------------------------------------------

export const GRANT_KINDS = ['mcp', 'connector', 'model', 'skill', 'nas', 'app'] as const
export const GRANT_RISKS = ['read', 'write', 'admin'] as const

/** Valide et normalise l'autorisation souhaitée : kind/registryId/actions/risk requis ; les actions d'écriture doivent être listées explicitement dans actions (annexe A décision 5). */
export function validateGrantSpec(input: unknown): ResourceGrantSpec {
  if (!input || typeof input !== 'object') throw new Error(t('资源授权项不合法：须为对象（kind/registryId/actions/risk）'))
  const spec = input as Record<string, unknown>
  const kind = spec['kind']
  if (typeof kind !== 'string' || !(GRANT_KINDS as readonly string[]).includes(kind)) {
    throw new Error(t('资源授权项 kind 不合法：{kind}（允许：{allowed}）', { kind: String(kind), allowed: GRANT_KINDS.join('/') }))
  }
  const registryId = spec['registryId']
  if (typeof registryId !== 'string' || registryId.trim() === '') {
    throw new Error(t('资源授权项 registryId 不合法：须为非空资源登记 ID（mcp 服务/connector provider/模型 slug 等）'))
  }
  const rawActions = spec['actions']
  if (!Array.isArray(rawActions) || rawActions.length === 0 || rawActions.some((a) => typeof a !== 'string' || a.trim() === '')) {
    throw new Error(t('资源授权项 actions 不合法：须为非空动作数组（写动作必须显式列出，未知风险工具不得默认开放）'))
  }
  const risk = spec['risk']
  if (typeof risk !== 'string' || !(GRANT_RISKS as readonly string[]).includes(risk)) {
    throw new Error(t('资源授权项 risk 不合法：{risk}（允许：{allowed}）', { risk: String(risk), allowed: GRANT_RISKS.join('/') }))
  }
  const constraints = spec['constraints']
  if (constraints !== undefined && (typeof constraints !== 'object' || constraints === null || Array.isArray(constraints))) {
    throw new Error(t('资源授权项 constraints 不合法：须为对象（factoryIds/pathPrefixes/maxRows 等）'))
  }
  return {
    kind: kind as ResourceGrantSpec['kind'],
    registryId,
    actions: (rawActions as string[]).map((a) => a.trim()),
    risk: risk as ResourceGrantSpec['risk'],
    ...(constraints !== undefined ? { constraints: constraints as Record<string, unknown> } : {}),
  }
}

// ---------------------------------------------------------------------------
// Validateur JSON Schema minimal (§9.2 : contraintes de paramètres côté serveur, échec = ARGUMENT_SCOPE_DENIED)
// ---------------------------------------------------------------------------

function jsonTypeOf(value: unknown): string {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  return typeof value
}

function matchesType(value: unknown, type: string): boolean {
  switch (type) {
    case 'object': return jsonTypeOf(value) === 'object'
    case 'array': return Array.isArray(value)
    case 'string': return typeof value === 'string'
    case 'number': return typeof value === 'number' && Number.isFinite(value)
    case 'integer': return typeof value === 'number' && Number.isFinite(value) && Number.isInteger(value)
    case 'boolean': return typeof value === 'boolean'
    case 'null': return value === null
    default: return false // tout mot-clé de type inconnu ne correspond jamais (fail-closed)
  }
}

/**
 * Validateur JSON Schema minimal (suffisant pour l'usage) : prend en charge
 *   type (tableaux compris) / required / properties / additionalProperties:false / enum /
 *   items / maxRows (plafond de lignes d'un tableau, référentiel d'exemple des constraints du contrat) / minLength / maxLength / minimum / maximum.
 * Retourne null si la validation passe ; sinon la première erreur en chinois (avec chemin du paramètre).
 * Les mots-clés de schéma non pris en charge sont ignorés silencieusement — cette fonction n'applique que « les contraintes déclarées », sans se faire passer pour un JSON Schema complet.
 */
export function validateAgainstSchema(
  value: unknown,
  schema: Record<string, unknown>,
  path = '$',
): string | null {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return null

  const type = schema['type']
  if (type !== undefined) {
    const types = Array.isArray(type) ? type : [type]
    if (!types.some((t) => matchesType(value, String(t)))) {
      return t('{path} 类型应为 {types}（实际为 {actual}）', { path, types: types.map(String).join(t(' 或 ')), actual: jsonTypeOf(value) })
    }
  }

  const allowedValues = schema['enum']
  if (Array.isArray(allowedValues)) {
    let matched = false
    try {
      const actual = canonicalJson(value)
      matched = allowedValues.some((candidate) => canonicalJson(candidate) === actual)
    } catch {
      matched = false
    }
    if (!matched) return t('{path} 取值不在允许范围内（{allowed}）', { path, allowed: allowedValues.map((v) => JSON.stringify(v)).join('/') })
  }

  if (jsonTypeOf(value) === 'object') {
    const obj = value as Record<string, unknown>
    const required = schema['required']
    if (Array.isArray(required)) {
      for (const key of required) {
        if (typeof key === 'string' && !(key in obj)) return t('{path} 缺少必填参数「{key}」', { path, key })
      }
    }
    const properties = schema['properties']
    if (properties && typeof properties === 'object' && !Array.isArray(properties)) {
      const propSchemas = properties as Record<string, Record<string, unknown>>
      if (schema['additionalProperties'] === false) {
        const unknownKey = Object.keys(obj).find((key) => !(key in propSchemas))
        if (unknownKey !== undefined) return t('{path} 不允许传入未声明的参数「{key}」', { path, key: unknownKey })
      }
      for (const [key, propSchema] of Object.entries(propSchemas)) {
        if (!(key in obj)) continue
        const error = validateAgainstSchema(obj[key], propSchema ?? {}, `${path}.${key}`)
        if (error) return error
      }
    }
  }

  if (Array.isArray(value)) {
    const items = schema['items']
    if (items && typeof items === 'object' && !Array.isArray(items)) {
      for (let index = 0; index < value.length; index++) {
        const error = validateAgainstSchema(value[index], items as Record<string, unknown>, `${path}[${index}]`)
        if (error) return error
      }
    }
    const maxRows = schema['maxRows']
    if (typeof maxRows === 'number' && value.length > maxRows) {
      return t('{path} 行数 {count} 超出上限 {max}', { path, count: value.length, max: maxRows })
    }
  }

  if (typeof value === 'string') {
    const minLength = schema['minLength']
    if (typeof minLength === 'number' && value.length < minLength) return t('{path} 长度不得少于 {min}', { path, min: minLength })
    const maxLength = schema['maxLength']
    if (typeof maxLength === 'number' && value.length > maxLength) return t('{path} 长度不得超过 {max}', { path, max: maxLength })
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    const minimum = schema['minimum']
    if (typeof minimum === 'number' && value < minimum) return t('{path} 不得小于 {min}', { path, min: minimum })
    const maximum = schema['maximum']
    if (typeof maximum === 'number' && value > maximum) return t('{path} 不得大于 {max}', { path, max: maximum })
  }

  return null
}
