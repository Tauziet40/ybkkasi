/**
 * Génération de l'Agent Card / signature et vérification JWS(Ed25519) (plan de collaboration §5.2).
 *
 * La déclaration a l'autorisation pour autorité : le contenu de la carte est projeté par f(ensemble d'autorisations + attrs d'actif), toute modification manuelle est interdite —
 * l'appelant (ou la passerelle de bord) vérifie la signature avant de faire confiance à la carte lors de l'enregistrement/de la découverte ; échec de vérification = hors annuaire + alerte audit.
 * La signature réutilise l'infrastructure Ed25519 au niveau plateforme extraite de plugin-market (platform-core/src/signature.ts),
 * sans nouveau composant cryptographique. Format de signature : JWS compact (alg=EdDSA), entrée de signature = `${protected}.${payload}`,
 * réutilisant la sémantique de signature brute de signEd25519 sur les « octets de la chaîne ».
 */
import { signEd25519, verifyEd25519 } from '../../platform-core/src/signature.ts'

// ---------------------------------------------------------------------------
// Structure de la carte (les clés de protocole restent ASCII ; signification en chinois : voir la Table de correspondance des clés de protocole)
// ---------------------------------------------------------------------------

export interface AgentCardSkill {
  id: string
  name: string
  description?: string
  tags: string[]
}

export interface AgentCardGovernanceExtension {
  uri: 'urn:ybk:ext:governance:v1'
  params: {
    autonomy: string
    runtime: string
    dataClassCeiling: string
    /** Sujet de mesure de cet employé (côté appelé). */
    meteringSubject: string
    /** Sujet de mesure des appels de collaboration (côté initiateur) ; le réconciliateur externe en tire les comptes des deux côtés (Q-32/E-7). */
    callerMeteringSubject?: string
  }
}

/** Extensions de la facette protocole (Q-31) : version du protocole, facette de méthodes, transport en flux et points de découverte — un Agent externe peut collaborer avec la seule carte. */
export interface AgentCardProtocolExtension {
  uri: 'urn:ybk:ext:protocol:v1'
  params: {
    protocol: string
    protocolVersion: string
    transport: string
    methods: string
    streamingTransport: string
    sseAuth: string
    wellKnown: string
    directory: string
    uhpDiscovery: string
    uhpVersion: string
    envelope: string
  }
}

/** Corps de carte non signé (payload). */
export interface AgentCardBody {
  name: string
  description: string
  url: string
  version: string
  capabilities: { streaming: boolean; pushNotifications: boolean; stateTransitionHistory: boolean }
  defaultInputModes: string[]
  defaultOutputModes: string[]
  skills: AgentCardSkill[]
  /** Points de permission requis pour l'appel (securitySchemes.*.scopes). */
  securitySchemes: Record<string, Record<string, unknown>>
  /** Adresse du flux d'événements de tâche (le modèle contient {taskId}). */
  eventsUrl?: string
  extensions: Array<AgentCardGovernanceExtension | AgentCardProtocolExtension>
}

export interface CardSignature {
  protected: string
  signature: string
  keyId: string
}

export type SignedAgentCard = AgentCardBody & { signatures: CardSignature[] }

// ---------------------------------------------------------------------------
// Outils base64url (encodage JWS compact ; Buffer Node en base64url sans remplissage)
// ---------------------------------------------------------------------------

function b64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
}

// ---------------------------------------------------------------------------
// Signature / vérification
// ---------------------------------------------------------------------------

/** Signe le corps de carte en JWS(EdDSA/Ed25519), renvoie la carte complète avec signatures. */
export function signAgentCard(body: AgentCardBody, privateKeyPem: string, keyId: string): SignedAgentCard {
  const protectedHeader = b64urlJson({ alg: 'EdDSA', typ: 'JWT', kid: keyId })
  const payload = b64urlJson(body)
  const signingInput = `${protectedHeader}.${payload}`
  const signature = signEd25519(privateKeyPem, signingInput)
  return { ...body, signatures: [{ protected: protectedHeader, signature, keyId }] }
}

/** Vérification : vérifier la signature avant de faire confiance (plan de collaboration §5.2). Renvoie false pour toute forme invalide (sans lever ; l'appelant traite comme un échec de vérification). */
export function verifyAgentCard(card: SignedAgentCard, publicKeyBase64: string): boolean {
  try {
    const sig = card.signatures?.[0]
    if (!sig?.protected || !sig.signature) return false
    const header = JSON.parse(Buffer.from(sig.protected, 'base64url').toString('utf8')) as { alg?: string }
    if (header.alg !== 'EdDSA') return false
    const { signatures: _signatures, ...body } = card
    const signingInput = `${sig.protected}.${b64urlJson(body)}`
    return verifyEd25519(publicKeyBase64, signingInput, sig.signature)
  } catch {
    return false
  }
}
