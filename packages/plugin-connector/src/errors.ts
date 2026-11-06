/**
 * Modèle d'erreurs côté open-connector : enveloppe unifiée { success:false, errorCode } → unique lieu de mise en correspondance vers les erreurs de la plateforme.
 * client.ts est la seule couche d'adaptation du dépôt conscient du contrat open-connector v1.4.0 (verrouillage de version isolé), le reste du code ne voit que la sémantique du présent fichier.
 */

/** Code d'erreur → statut HTTP et libellé de message plateforme (sous-ensemble des codes documentés v1.4.0 + points non documentés en amont traités par défaut). */
import { t } from '../../platform-i18n/src/index.ts'

const OC_ERROR_STATUS: Record<string, number> = {
  connection_not_allowed: 403,
  rate_limited: 429,
  oauth_token_expired: 409,
  oauth_client_config_required: 400,
  unknown_action: 404,
  unauthorized: 401,
}

export class OcError extends Error {
  readonly code: string
  /** Code de statut HTTP conseillé (transmis à l'appelant par la couche de routage console). */
  readonly status: number
  /** Guide de correction destiné à l'assistant de connexion (ex. lien d'enregistrement OAuth d'une App apportée par le client). */
  readonly guidance?: string

  constructor(code: string, message?: string, guidance?: string, status?: number) {
    super(message ?? t('open-connector 错误：{code}', { code }))
    this.name = 'OcError'
    this.code = code
    this.status = status ?? OC_ERROR_STATUS[code] ?? 502
    this.guidance = guidance
  }
}

/** Sidecar injoignable / réponse hors forme contractuelle — entrée du jugement fail-closed. */
export class OcUnavailableError extends OcError {
  constructor(message: string) {
    super('gateway_unreachable', message)
    this.name = 'OcUnavailableError'
  }
}
