/**
 * Registre des adaptateurs de ressources (contrat AdapterRegistry ; les six adaptateurs intégrés de adapters/* sont assemblés ici).
 *
 * Responsabilité des adaptateurs : mapper l'appel contrôlé vers les passerelles existantes (mcpRegistry/connectorHub/modelGateway/
 * skillHub/nasRegistry), sans retirer un seul maillon de la chaîne d'autorisation d'origine des passerelles (intersection des deux couches d'autorisation, §9.5) ;
 * une capacité absente renvoie non pris en charge, sans faire passer une implémentation vide pour un succès.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import type {
  AdapterRegistry,
  ResourceAdapter,
  ResourceGrantSpec,
} from '../contract.ts'
import { createMcpAdapter } from './mcp.ts'
import { createConnectorAdapter } from './connector.ts'
import { createModelAdapter } from './model.ts'
import { createSkillAdapter } from './skill.ts'
import { createNasAdapter } from './nas.ts'
import { createAppAdapter } from './app.ts'

export class AdapterRegistryService extends Service implements AdapterRegistry {
  static readonly provide = 'workforceAdapters'

  private readonly adapters = new Map<ResourceGrantSpec['kind'], ResourceAdapter>()

  constructor(ctx: Context) {
    super(ctx, 'workforceAdapters')
    // Les six adaptateurs intégrés (ctx passé sous forme d'une face de sondage structurée, les adaptateurs ne dépendent pas des classes de service concrètes ;
    // la forme de la face de sondage est l'interface Probe de chaque fichier d'adaptateur — les extensions additives des passerelles seront livrées par les groupes 4/5)
    const probeCtx = ctx as unknown as {
      mcpRegistry?: Parameters<typeof createMcpAdapter>[0]['mcpRegistry']
      connectorHub?: Parameters<typeof createConnectorAdapter>[0]['connectorHub']
      modelGateway?: Parameters<typeof createModelAdapter>[0]['modelGateway']
      skillHub?: Parameters<typeof createSkillAdapter>[0]['skillHub']
      nasRegistry?: Parameters<typeof createNasAdapter>[0]['nasRegistry']
      workforceArtifacts?: Parameters<typeof createNasAdapter>[0]['workforceArtifacts']
    }
    for (const adapter of [
      createMcpAdapter({ mcpRegistry: probeCtx.mcpRegistry }),
      createConnectorAdapter({ connectorHub: probeCtx.connectorHub }),
      createModelAdapter({ modelGateway: probeCtx.modelGateway }),
      createSkillAdapter({ skillHub: probeCtx.skillHub }),
      createNasAdapter({ nasRegistry: probeCtx.nasRegistry, workforceArtifacts: probeCtx.workforceArtifacts }),
      createAppAdapter(ctx),
    ]) {
      this.register(adapter)
    }
  }

  get(kind: ResourceGrantSpec['kind']): ResourceAdapter | undefined {
    return this.adapters.get(kind)
  }

  register(adapter: ResourceAdapter): void {
    this.adapters.set(adapter.kind, adapter)
  }
}
