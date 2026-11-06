/**
 * plugin-workforce — entrée d'assemblage du domaine de l'employé numérique.
 *
 * Triple répartition des responsabilités (chemin d'implémentation §3.1, pas de triplication de trois systèmes d'identité) :
 *   - cette extension : dossier de l'employé, version de nomination, liaison d'exécution, inventaire de capacités, permit, registre des appels contrôlés, acceptation de la livraison ;
 *   - exec-hub : objectifs/projets/tâches/run et bail d'exécution (consommés via le port d'intégration ExecHubWorkIntegration) ;
 *   - les passerelles de ressources : appels de ressources réels et chaîne d'autorisation d'origine (réutilisées via les adapters, pas réécrites).
 *
 * Anti-assemblage circulaire (§10.2) : cette extension est assemblée après les services de base existants ; sa seule face transversale externe est
 * le port étroit de platform-core (ctx.workforcePolicy, présent dès apply) — une fois cette extension ready,
 * register() enregistre l'implémentation ; exec-hub et les passerelles de ressources ne dépendent que du type du port, sans dépendance inverse vers cette extension.
 */
import type { Context } from '@deepseek-ai/cordis'
import { WorkforceStoreService } from './repositories.ts'
import { EmployeeService } from './employee-service.ts'
import { AppointmentService } from './appointment-service.ts'
import { IdentityResolverService } from './identity-resolver.ts'
import { AdmissionService } from './admission-service.ts'
import { PermitService } from './permit-service.ts'
import { CapabilityManifestService } from './capability-manifest.ts'
import { InvocationService } from './invocation-service.ts'
import { ArtifactService } from './artifact-service.ts'
import { DeliveryService } from './acceptance-service.ts'
import { MaintenanceService } from './maintenance-service.ts'
import { AdapterRegistryService } from './adapters/index.ts'
import { createWorkforcePolicyPort } from './port.ts'
import { registerWorkforceTools } from './tools.ts'
import { registerWorkforceRoutes } from './routes.ts'
import type { WorkforceGrayConfig } from './contract.ts'

export * from './contract.ts'

export interface WorkforceConfig extends WorkforceGrayConfig {
  /** Répertoire de données (staging des artefacts et SQLite sur la même base) ; défaut <cwd>/data. */
  dataDir?: string
  /** Validité par défaut du permit (millisecondes), 30 minutes par défaut. */
  permitTtlMs?: number
  /** Validité par défaut du bail (millisecondes), 15 minutes par défaut. */
  leaseTtlMs?: number
}

export const name = 'workforce'

// Les fournisseurs sont tous assemblés avant cette extension (même ordre dans boot-all.ts / cordis.yml) : couche de base→passerelles→agent→exec-hub→workforce
export const inject = [
  'httpServer', 'opsStorage', 'platformBus', 'iam', 'authn', 'audit', 'txnStore', 'usage',
  'resourceCore', 'agentRegistry', 'mcpRegistry', 'connectorHub', 'modelGateway', 'skillHub', 'nasRegistry',
  'execHub', 'tools', 'workforcePolicy',
]

export async function apply(ctx: Context, config: WorkforceConfig = {}) {
  // Construction directe des services (même forme que plugin-mcp/plugin-connector) : new Service(ctx) enregistre le provide dans
  // la fiber de cette extension — les ports/outils/routes dans apply peuvent ainsi lire synchrone­ment les clés de services de la même extension (ctx.plugin(Classe) crée
  // une sous-fiber indépendante, les clés de la même extension sont invisibles sans déclaration inject, et le montage await ne garantit pas l'ordre des sous-apply).
  // L'ordre de construction est l'ordre des dépendances : les adapters lisent la face de sondage workforceArtifacts dès leur construction, donc artifacts avant adapters.
  // 1. Migration du stockage de référence (création de tables idempotente : WORKFORCE_TABLES)
  new WorkforceStoreService(ctx, config)
  // 2. Services du domaine employé (dépendances entre services résolues paresseusement via ctx — les getters de chaque service lisent à la requête, aucun couplage d'ordre de construction)
  new EmployeeService(ctx)
  new AppointmentService(ctx)
  new IdentityResolverService(ctx)
  new PermitService(ctx)
  new CapabilityManifestService(ctx)
  new ArtifactService(ctx, config)
  new AdapterRegistryService(ctx)
  new InvocationService(ctx)
  new DeliveryService(ctx)
  // Commutateur de déploiement progressif (contrat W7 D-②) : la construction de l'admission reçoit la configuration de progressivité, les entrées de réclamation/prolongation refusent par organisation
  new AdmissionService(ctx, config)
  // Maintenance du registre (face opérationnelle W5 D-③) : comptabilisation des permits expirés + inventaire des runs à état terminal (archivage sans suppression de ligne) ;
  // inspection périodique dès la construction (désactivable par env), déclenchement manuel via REST /api/workforce/admin/maintenance/run
  new MaintenanceService(ctx)
  // 3. Enregistrement de l'implémentation du port étroit (registre de platform-core) : la fiber de cette extension détient déjà tous ses services, enregistrement synchrone
  //    (la configuration de progressivité entre dans authorizeWorkAction via le port : organisation désactivée = refus explicite à l'entrée d'autorisation au niveau travail)
  ctx.workforcePolicy.register(createWorkforcePolicyPort(ctx, config))
  // 4. Outils fins d'exécution (workforce_claim/invoke/renew/submit ; identité tirée d'exec.principal, transmission par args interdite)
  registerWorkforceTools(ctx)
  // 5. Face de travail REST (/api/workforce/*, les routes guarded dépendent de la priorité du middleware console)
  registerWorkforceRoutes(ctx)
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    workforceStore: WorkforceStoreService
    workforceEmployees: EmployeeService
    workforceAppointments: AppointmentService
    workforceIdentity: IdentityResolverService
    workforceAdmission: AdmissionService
    workforcePermits: PermitService
    workforceCapabilities: CapabilityManifestService
    workforceInvocations: InvocationService
    workforceArtifacts: ArtifactService
    workforceDelivery: DeliveryService
    workforceAdapters: AdapterRegistryService
    workforceMaintenance: MaintenanceService
  }
}
