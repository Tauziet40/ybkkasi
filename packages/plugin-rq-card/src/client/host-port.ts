/**
 * Adaptateur du port hôte de la moitié navigateur (EXEC-CHECKLIST W5 : resserrement de la face de couplage dsh).
 *
 * [Convergence en un point] les dépendances de types des trois paquets dsh-client-runtime (runtime / ui-conversation / locale)
 * ne peuvent apparaître que dans ce fichier ; le corps de l'extension (index.ts) ne dépend que du port étroit
 * HostClientPort déclaré par platform-core (import type-only, effacé à la compilation, sans toucher la barrière
 * de pureté bundle du build.mjs — platform-core n'entre pas dans l'artefact navigateur).
 * En cas de dérive d'API à une montée de version de dsh, ne modifier que ce fichier + relancer les tests de contrat
 * (section plugin-rq-card de npm run test:contracts).
 * @module @dsh-ops/plugin-rq-card/client/host-port
 */
import type { ClientContext, SessionId } from '@deepseek-ai/dsh-client-runtime/client'
// Type-only : introduit la fusion SlotMap d'ui-conversation (forme d'entrée assistant-actions).
import type {} from '@deepseek-ai/dsh-client-ui-conversation/client'
// Type-only : introduit la fusion Context du plugin locale (face ctx.locale).
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type { HostClientPort } from '../../../platform-core/src/host-bridge.ts'

/** index.ts / le corps de l'extension passe par ici (les types dsh n'entrent pas directement dans le corps). */
export type { ClientContext, SessionId }

/** Vue minimale structurée de ctx.slots (les différences de forme à l'exécution convergent dans ce fichier, ne sortent pas du port). */
interface SlotsView {
  specDynamic?: (name: string) => unknown
  inject: (slot: string, factory: () => unknown) => unknown
  register: (spec: unknown, component: unknown) => () => void
}

/** Vue minimale structurée de ctx.locale. */
interface LocaleView {
  register: (namespace: string, dictionaries: unknown) => unknown
}

/**
 * Adaptateur : resserre le context racine du client dsh en HostClientPort.
 *   - slots.specDynamic resserré selon l'existence + sonde sûre (absent/jette/non-objet = replié en
 *     undefined, l'appelant dégrade en « slot indisponible » — la sémantique existante du spike §5 avancée à la frontière du port,
 *     un vieil hôte sans cette API n'a pas besoin de monter de version pour fonctionner) ;
 *   - les autres faces de capacité (inject/register/locale.register/effect) sont transmises telles quels.
 */
export function createClientHostPort(ctx: ClientContext): HostClientPort {
  const slots = ctx.slots as SlotsView
  const locale = ctx.locale as LocaleView
  const root = ctx as unknown as { effect: (action: () => void, name?: string) => unknown }
  const port: HostClientPort = {
    slots: {
      inject: (slot, factory) => slots.inject(slot, factory),
      register: (spec, component) => slots.register(spec, component),
    },
    locale: {
      register: (namespace, dictionaries) => locale.register(namespace, dictionaries),
    },
    effect: (action, name) => root.effect(action, name),
  }
  if (typeof slots.specDynamic === 'function') {
    const specDynamic = slots.specDynamic.bind(ctx.slots)
    port.slots.specDynamic = (name: string) => {
      try {
        const spec = specDynamic(name)
        return typeof spec === 'object' && spec !== null ? (spec as { kind?: string }) : undefined
      } catch {
        return undefined
      }
    }
  }
  return port
}
