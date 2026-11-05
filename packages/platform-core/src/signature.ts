/**
 * Infrastructure de signature Ed25519 (fondation plateforme M2, extraite de plugin-market) :
 *   - vérification des signatures des cinq facettes de manifest du marketplace de plugins tiers (plugin-market.submit)
 *   - vérification des manifest de publication de l'auto-mise à jour plateforme (plugin-update, clôture de l'exposition chaîne d'approvisionnement T5)
 * Les deux partagent la même sémantique de clés/signature : clé publique SPKI DER base64 + clé privée PKCS8 PEM, Ed25519 sur les octets de l'empreinte.
 * La clé privée reste uniquement chez le détenteur (développeur / pipeline de publication) ; la plateforme ne stocke que des clés publiques, dans toutes ses collections.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto'

/** Vérification Ed25519 : l'empreinte doit être signée par la clé publique enregistrée. Toute entrée invalide → false (sans lever ; l'appelant traite comme un échec de vérification). */
export function verifyEd25519(publicKeyBase64: string, fingerprint: string, signatureBase64: string): boolean {
  try {
    const publicKey = createPublicKey({ key: Buffer.from(publicKeyBase64, 'base64'), format: 'der', type: 'spki' })
    return edVerify(null, Buffer.from(fingerprint), publicKey, Buffer.from(signatureBase64, 'base64'))
  } catch {
    return false
  }
}

/** Génération de paire de clés Ed25519 (auto-service échafaudage/pipeline de publication ; la clé privée reste chez l'appelant). */
export function generateEd25519KeyPair(): { publicKeyBase64: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return {
    publicKeyBase64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  }
}

/** Signature Ed25519 (clé privée PEM → signature des octets de l'empreinte, base64). Lève si la clé privée est invalide (le côté publication doit échouer bruyamment). */
export function signEd25519(privateKeyPem: string, fingerprint: string): string {
  const privateKey = createPrivateKey(privateKeyPem)
  return edSign(null, Buffer.from(fingerprint), privateKey).toString('base64')
}

/** Validation du format d'enregistrement de clé publique : doit être un SPKI DER base64 analysable (garde-fou du point d'écriture settings). */
export function isValidEd25519PublicKeyBase64(value: string): boolean {
  try {
    createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' })
    return true
  } catch {
    return false
  }
}
