/**
 * Résolveur Principal unifié (contrat de gouvernance MCP §2, 2026-10-22).
 *
 * Convergence en un point unique du mapping pur « résultat de vérification de jeton (VerifiedPrincipal) → projection de l'appelant pour chaque facette consommatrice » :
 *   - le middleware d'authentification console (seul point d'écriture faisant autorité) assemble via resolveUnifiedPrincipal
 *     exchange.principal = sur-ensemble compatible CallerInfo + champs unified ;
 *   - bridge /mcp, nas OBO, a2a actChainOf, mcp invoke consomment tous unified,
 *     interdiction de déclarer une identité via paramètres de requête/headers (ligne rouge du contrat §2).
 *
 * Discipline de direction des dépendances : platform-core ne dépend pas en retour des plugins métier — le
 * VerifiedPrincipal de plugin-authn est injecté comme type structurel minimal (VerifiedPrincipalShape), la conformité structurelle suffit ;
 * la reconnexion organisation/ressource passe par le port asynchrone PrincipalLookups assemblé par l'hôte (console).
 */
import type { CallerInfo } from './rest-gate.ts'
import type { WorkCallerRef } from './workforce-port.ts'

// ---------------------------------------------------------------------------
// Types du contrat (docs/internal/mcp-governance-20261022-contracts.md §2)
// ---------------------------------------------------------------------------

/** Nœud de la chaîne act (projection unifiée d'ActEntry authn + reconnexion principal ; id = valeur originale du principalId authn). */
export interface ActChainNode { kind: 'user' | 'agent' | 'app' | 'platform-service'; id: string; name?: string; refId?: string }

/** Mode d'authentification (déduit du préfixe issuedBy du jeton, voir authMethodOf). */
export type UnifiedAuthMethod = 'oidc-code' | 'client-credentials' | 'token-exchange' | 'session' | 'entry-ticket' | 'demo'

/** Sujet unifié : source unique des faits d'identité pour chaque facette consommatrice. */
export interface UnifiedPrincipal {
  principalId: string
  kind: 'human' | 'agent' | 'app' | 'platform-service'
  userId?: string; agentId?: string; appId?: string
  orgId?: string; tenantId?: string
  authMethod: UnifiedAuthMethod
  tokenId: string                    // = token.jti
  scopes: string[]
  /** Utilisateur réel en scénario de délégation (userId de l'entrée human la plus basse de la chaîne act) */
  subjectUserId?: string
  actChain: ActChainNode[]           // mappé depuis ActEntry[] authn + reconnexion principal
  refType?: 'user' | 'agent' | 'app' | 'external'
  refId?: string
  name: string
  permissions: string[]              // conserve la sémantique CallerInfo.permissions (scopes temps réel du verify)
}

/** Port de reconnexion d'identité (assemblé par l'hôte : console l'implémente via authn.principals / iam / resourceCore). */
export interface PrincipalLookups {
  principalOf(id: string): Promise<{ refType?: string; refId?: string; name?: string; type: string } | null>
  orgOf(ref: { kind: 'user' | 'agent' | 'app'; id: string }): Promise<{ orgId?: string; tenantId?: string } | null>
}

/** Projection structurelle minimale du VerifiedPrincipal de plugin-authn (évite une dépendance inverse de platform-core vers les plugins métier). */
export interface VerifiedPrincipalShape {
  principal: {
    id: string
    type: 'human' | 'machine'
    refType?: 'user' | 'agent' | 'app' | 'external'
    refId?: string
    name: string
  }
  token: { jti: string; issuedBy?: string }
  scopes: string[]
  actChain: Array<{ principalId: string; name: string; type: 'human' | 'machine' }>
}

// ---------------------------------------------------------------------------
// Implémentation du mapping pur
// ---------------------------------------------------------------------------

/**
 * Déduction du mode d'authentification : généralisée à partir du préfixe issuedBy des points d'appel issueToken —
 *   obo: / delegate: → token-exchange；client_credentials → client-credentials；
 *   entry-ticket: → entry-ticket ; sso* (chaîne de code d'autorisation OIDC) → oidc-code ;
 *   password: / refresh-* (renouvellement de session) → session ; demo (injection en mode démo) → demo ;
 *   non déductible (p. ex. émission manuelle console) → défaut client-credentials (convention du contrat).
 */
export function authMethodOf(issuedBy: string | undefined): UnifiedAuthMethod {
  const source = issuedBy ?? ''
  if (source === 'demo') return 'demo'
  if (source.startsWith('delegate:') || source.startsWith('obo:')) return 'token-exchange'
  if (source === 'client_credentials') return 'client-credentials'
  if (source.startsWith('entry-ticket:')) return 'entry-ticket'
  if (source.startsWith('sso')) return 'oidc-code'
  if (source.startsWith('password:') || source.startsWith('refresh-')) return 'session'
  return 'client-credentials'
}

/** ActEntry.type/machine refType → kind unifié (convention de mapping du contrat). */
function kindOfRefType(refType: string | undefined): 'user' | 'agent' | 'app' | 'platform-service' {
  if (refType === 'user') return 'user'
  if (refType === 'agent') return 'agent'
  if (refType === 'app') return 'app'
  return 'platform-service' // external / absent / échec de reconnexion
}

/** Sujet de tête → kind unifié (tout sauf human est une facette machine : agent/app ont une ressource attachée, les autres sont des sujets de service plateforme). */
function kindOfPrincipal(type: string, refType: string | undefined): UnifiedPrincipal['kind'] {
  if (type === 'human') return 'human'
  if (refType === 'agent') return 'agent'
  if (refType === 'app') return 'app'
  return 'platform-service'
}

/**
 * Résout le sujet unifié : VerifiedPrincipal + reconnexion d'identité → UnifiedPrincipal.
 * L'échec de reconnexion ne bloque pas (fail-safe) : champs correspondants par défaut ; une erreur de résolution ne doit jamais amplifier ni contredire une conclusion d'authentification existante.
 */
export async function resolveUnifiedPrincipal(
  vp: VerifiedPrincipalShape,
  lookups: PrincipalLookups,
  options: { authMethod?: UnifiedAuthMethod } = {},
): Promise<UnifiedPrincipal> {
  const self = await lookups.principalOf(vp.principal.id).catch(() => null)
  const kind = kindOfPrincipal(vp.principal.type, vp.principal.refType)

  // Mapping de la chaîne act : human → user ; machine → refType reconnu via principalOf (user/agent/app/external),
  // en cas d'échec de reconnexion, kind='platform-service' sans autre champ que id (convention du contrat).
  // Le premier élément du tableau est l'initiateur (sémantique issueOnBehalfOf : chaîne parentale + sujet parent, la tête de chaîne est l'humain d'origine).
  const actChain: ActChainNode[] = []
  for (const entry of vp.actChain) {
    if (entry.type === 'human') {
      actChain.push({ kind: 'user', id: entry.principalId, name: entry.name })
      continue
    }
    const ref = await lookups.principalOf(entry.principalId).catch(() => null)
    if (!ref) {
      // Échec de reconnexion : on ne garde que id, sans les autres champs
      actChain.push({ kind: 'platform-service', id: entry.principalId })
      continue
    }
    // refId = id de la ressource liée à ce sujet (id de ressource agent/app / userId) — la correspondance des sujets de groupes de permissions se fait par id de ressource,
    // il est donc exposé avec le nœud (id conserve la valeur originale du principalId authn, les deux identifiants coexistent sans confusion).
    actChain.push({
      kind: kindOfRefType(ref.refType),
      id: entry.principalId,
      name: entry.name,
      ...(ref.refId !== undefined ? { refId: ref.refId } : {}),
    })
  }

  // Champ id du sujet de tête : human → userId, agent/app → id de ressource respective
  const ids: Pick<UnifiedPrincipal, 'userId' | 'agentId' | 'appId'> = {}
  if (kind === 'human' && vp.principal.refId) ids.userId = vp.principal.refId
  if (kind === 'agent' && vp.principal.refId) ids.agentId = vp.principal.refId
  if (kind === 'app' && vp.principal.refId) ids.appId = vp.principal.refId

  // Appartenance organisationnelle : reconnexion par userId pour human, par id de ressource pour agent/app (pas de reconnexion pour platform-service)
  let org: { orgId?: string; tenantId?: string } | null = null
  if (kind === 'human' || kind === 'agent' || kind === 'app') {
    const id = vp.principal.refId ?? vp.principal.id
    org = await lookups.orgOf({ kind, id } as { kind: 'user' | 'agent' | 'app'; id: string }).catch(() => null)
  }

  // subjectUserId : refId de l'entrée human la plus basse de la chaîne act (le premier élément du tableau est l'initiateur, sémantique issueOnBehalfOf : chaîne parentale + sujet parent) ;
  // si le sujet lui-même est human, c'est son propre refId (le jeton délégué obtenu par l'identifiant machine pour le compte de l'utilisateur a sub= cet utilisateur).
  let subjectUserId: string | undefined
  if (vp.principal.type === 'human') {
    subjectUserId = vp.principal.refId
  } else {
    const firstHuman = actChain.find((node) => node.kind === 'user')
    if (firstHuman) {
      const ref = await lookups.principalOf(firstHuman.id).catch(() => null)
      subjectUserId = ref?.refId
    }
  }

  return {
    principalId: vp.principal.id,
    kind,
    ...ids,
    ...(org?.orgId !== undefined ? { orgId: org.orgId } : {}),
    ...(org?.tenantId !== undefined ? { tenantId: org.tenantId } : {}),
    authMethod: options.authMethod ?? authMethodOf(vp.token.issuedBy),
    tokenId: vp.token.jti,
    scopes: [...vp.scopes],
    ...(subjectUserId !== undefined ? { subjectUserId } : {}),
    actChain,
    ...(vp.principal.refType !== undefined ? { refType: vp.principal.refType } : {}),
    ...(vp.principal.refId !== undefined ? { refId: vp.principal.refId } : {}),
    name: self?.name ?? vp.principal.name,
    permissions: [...vp.scopes],
  }
}

/**
 * Sujet unifié → CallerInfo (projection rétrocompatible, champs strictement équivalents aux produits existants du middleware d'authentification console) :
 *   kind : tout sauf human compte comme machine ; actChain projeté {principalId,name,type} (type re-projeté human|machine,
 *   identique à l'ancienne forme ActEntry, chaîne d'audit inchangée) ; permissions=unified.permissions (scopes temps réel du verify).
 */
export function toCallerInfo(p: UnifiedPrincipal): CallerInfo {
  return {
    kind: p.kind === 'human' ? 'human' : 'machine',
    principalId: p.principalId,
    ...(p.kind === 'human' && p.userId !== undefined ? { userId: p.userId } : {}),
    ...(p.kind !== 'human' ? { refType: p.refType, refId: p.refId } : {}),
    name: p.name,
    permissions: p.permissions,
    actChain: p.actChain.map((node) => ({
      principalId: node.id,
      ...(node.name !== undefined ? { name: node.name } : { name: node.id }),
      type: node.kind === 'user' ? 'human' : 'machine',
    })),
  } as CallerInfo
}

/**
 * Référence d'appelant de la facette invoke (même convention que resolveMcpCaller de plugin-mcp, consommée unifiée depuis W2-T3).
 *
 * subjects (additif, W4 audit sécurité P0-3) : **ensemble des sujets pouvant correspondre au groupe de permissions** —
 * le sujet lui-même (côté sub : humain/agent/app) + les acteurs app/agent apparaissant dans la chaîne de délégation.
 * Sémantique de délégation : quand User → App/Agent → MCP, ce sont les agent/app de la chaîne qui exécutent réellement l'action,
 * le groupe de permissions qui leur est accordé doit donc leur être effectif ; sinon l'identité Agent ne correspondrait jamais aux groupes de permissions à sujet agent,
 * et le chemin d'intégration standard (l'Agent échange son propre identifiant) obtiendrait silencieusement un ensemble d'outils vide.
 */
export function toInvokeCaller(p: UnifiedPrincipal): {
  type: 'user' | 'agent' | 'app'; id: string; name: string
  onBehalfOf?: string; actChain?: Array<{ name: string; type: string }>
  subjects?: Array<{ type: 'user' | 'agent' | 'app'; id: string }>
} {
  const type = p.kind === 'human' ? 'user' : p.kind === 'agent' ? 'agent' : 'app'
  const id = p.userId ?? p.agentId ?? p.appId ?? p.principalId
  const delegated = isDelegated(p)
  const subjects: Array<{ type: 'user' | 'agent' | 'app'; id: string }> = [{ type, id }]
  for (const node of p.actChain) {
    if (node.kind === 'user') {
      // Humain réel de la chaîne : évité en double quand le sujet est déjà la personne elle-même ; en délégation pour compte d'autrui, la personne est le sujet
      if (!subjects.some((item) => item.type === 'user')) subjects.push({ type: 'user', id: node.refId ?? node.id })
      continue
    }
    if (node.kind === 'agent' || node.kind === 'app') {
      // Les sujets de groupes de permissions correspondent par id de ressource (refId prioritaire ; repli sur principalId en cas d'échec de reconnexion)
      const actorId = node.refId ?? node.id
      if (!subjects.some((item) => item.type === node.kind && item.id === actorId)) {
        subjects.push({ type: node.kind, id: actorId })
      }
    }
  }
  return {
    type,
    id,
    name: p.name,
    ...(delegated && p.actChain.length > 0 ? { onBehalfOf: p.actChain[0]!.name ?? p.actChain[0]!.id } : {}),
    ...(delegated ? { actChain: p.actChain.map((node) => ({ name: node.name ?? node.id, type: node.kind === 'user' ? 'human' : 'machine' })) } : {}),
    subjects,
  }
}

/** Référence d'appelant du port étroit de stratégie de travail (WorkCallerRef ; rest-gate.workCallerOf délègue à cette implémentation). */
export function toWorkCallerRef(p: UnifiedPrincipal): WorkCallerRef {
  return {
    kind: p.kind === 'human' ? 'human' : 'machine',
    principalId: p.principalId,
    ...(p.userId !== undefined ? { userId: p.userId } : {}),
    ...(p.kind !== 'human' && p.refType !== undefined ? { refType: p.refType } : {}),
    ...(p.kind !== 'human' && p.refId !== undefined ? { refId: p.refId } : {}),
    ...(p.name ? { name: p.name } : {}),
  }
}

/**
 * Scénario de délégation ? : la chaîne act non vide suffit (chaîne act vide en session ordinaire ; les jetons OBO/délégation ont toujours une chaîne).
 */
export function isDelegated(p: UnifiedPrincipal): boolean {
  return p.actChain.length > 0
}

/**
 * Vrai initiateur de la chaîne de délégation (entrée human la plus basse de la chaîne act, le premier élément du tableau est l'initiateur) :
 *   - sujet machine : première entrée user de la chaîne (subjectUserId absent = échec de reconnexion, renvoie null fail-safe) ;
 *   - sujet humain avec chaîne (jeton délégué obtenu par identifiant machine pour son compte, sub= cet utilisateur) : s'il n'y a pas d'entrée user dans la chaîne, c'est le sujet lui-même ;
 *   - sujet humain sans chaîne (session ordinaire) : null (pas de délégation, le consommateur retombe sur sa source de faits existante).
 */
export function humanDelegatorOf(p: UnifiedPrincipal): { userId: string; name?: string } | null {
  if (p.actChain.length === 0) return null
  const firstHuman = p.actChain.find((node) => node.kind === 'user')
  if (firstHuman) {
    if (p.subjectUserId === undefined) return null
    return { userId: p.subjectUserId, ...(firstHuman.name !== undefined ? { name: firstHuman.name } : {}) }
  }
  if (p.kind === 'human' && p.subjectUserId !== undefined) {
    return { userId: p.subjectUserId, name: p.name }
  }
  return null
}

// ---------------------------------------------------------------------------
// Aides d'assemblage hôte (partagées par le middleware d'authentification console et bridge /mcp, pour concentrer le câblage des reconnexions)
// ---------------------------------------------------------------------------

/** Hôte structurel : les services existants de la console sont injectés par forme (platform-core ignore les plugins concrets). */
export interface PrincipalLookupHost {
  /** authn.principals().get(id) */
  principalsGet(id: string): { refType?: string; refId?: string; name?: string; type: string } | undefined
  /** iam.users().get(id) */
  iamUserGet(id: string): { orgId?: string } | undefined
  /** resourceCore.get(kind, id) */
  resourceGet(kind: 'agent' | 'app', id: string): { orgId?: string } | undefined
  /** iam.tenantOfOrg(orgId) */
  tenantOfOrg(orgId: string): string | undefined
}

/** Assemble le port de reconnexion standard depuis l'hôte structurel (partagé par console index.ts et bridge.ts, évite de dupliquer le câblage). */
export function lookupsFromHost(host: PrincipalLookupHost): PrincipalLookups {
  return {
    async principalOf(id) {
      return host.principalsGet(id) ?? null
    },
    async orgOf(ref) {
      if (ref.kind === 'user') {
        const user = host.iamUserGet(ref.id)
        if (!user) return null
        return { orgId: user.orgId, tenantId: host.tenantOfOrg(user.orgId) }
      }
      const resource = host.resourceGet(ref.kind, ref.id)
      if (!resource?.orgId) return null
      return { orgId: resource.orgId, tenantId: host.tenantOfOrg(resource.orgId) }
    },
  }
}

/**
 * CallerInfo (produit existant console) → projection inverse minimale en UnifiedPrincipal.
 * Servi uniquement à l'alignement de forme quand rest-gate.workCallerOf délègue à toWorkCallerRef (les champs propres à unified absents ne participent pas au mapping).
 */
export function unifiedFromCaller(info: CallerInfo): UnifiedPrincipal {
  return {
    principalId: info.principalId,
    kind: info.kind === 'human' ? 'human' : 'platform-service',
    ...(info.userId !== undefined ? { userId: info.userId } : {}),
    ...(info.refType !== undefined ? { refType: info.refType as UnifiedPrincipal['refType'] } : {}),
    ...(info.refId !== undefined ? { refId: info.refId } : {}),
    authMethod: 'client-credentials',
    tokenId: '',
    scopes: [...info.permissions],
    actChain: info.actChain.map((entry) => ({
      kind: entry.type === 'human' ? 'user' : 'platform-service',
      id: (entry as { principalId?: string }).principalId ?? entry.name,
      name: entry.name,
    })),
    name: info.name,
    permissions: [...info.permissions],
  }
}
