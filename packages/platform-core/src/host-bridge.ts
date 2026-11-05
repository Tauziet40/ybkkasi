/**
 * Port étroit du pont hôte (EXEC-CHECKLIST W5 : réduction de la surface de couplage dsh, P2).
 *
 * [Intention de conception] Seuls deux endroits de ce dépôt touchent réellement l'API hôte dsh : plugin-dsh-bridge
 * (moitié serveur ctx.webServer : montage + identité) et la moitié navigateur de plugin-rq-card
 * (ctx.slots / ctx.locale : enregistrement de slots + dictionnaire). La méthode de réduction est du même type que workforce-port.ts :
 * l'interface de port ne déclare que la surface minimale de capacités réellement consommée par les deux plugins ; les types spécifiques à dsh
 * n'entrent jamais dans les signatures de port (interfaces minimales structurelles, les différences de forme à l'exécution sont réduites par l'adapter de chaque côté).
 * Ainsi, la dérive d'API d'une mise à jour dsh n'exige que : ajuster les adapters de chaque côté + relancer les tests de contrat
 * (npm run test:contracts), sans toucher au code métier ni aux signatures de port.
 *
 * [Classement des surfaces de capacités · côté dsh-bridge] (inventaire de tous les points d'appel de src/index.ts : 5
 * register + 1 tapIndex optionnel)
 *   Requis : register(route) — enregistrement de routes exact/prefix, le handler détient le req/res natif ;
 *         absent = l'hôte n'est pas de forme web, apply de dsh-bridge échoue directement (comportement existant).
 *   Optionnel : tapIndex(transform) — réécriture HTML de l'UI web dsh (injection de script sans login) ;
 *         absent (hôte ancien, webServer falsifié du selftest sans cette capacité) = repli sur le seul canal
 *         query /auth/entry?entry_ticket=, warn journalisé sans lever d'erreur (comportement existant).
 *         L'adapter réduit selon la présence : l'hôte n'est jamais forcé de fournir une capacité optionnelle à cause du port.
 *
 * [Classement des surfaces de capacités · côté client rq-card]
 *   Requis : slots.inject / slots.register / locale.register / effect —
 *         le plugin client déclare ['slots','locale'] via inject, l'hôte le fournit nécessairement.
 *   Optionnel : slots.specDynamic — sondage d'existence/forme d'un slot ; absent ou erreur d'exécution, tout est replié en
 *         undefined, l'appelant dégrade en « slot indisponible » (sémantique existante du spike §5 avancée jusqu'à la frontière du port).
 *
 * [Pourquoi le type du port client est aussi ici, l'adapter restant côté client] le bundle navigateur a
 * un contrôle de pureté (purityGate de plugin-rq-card/build.mjs) : platform-core ne peut pas entrer
 * dans le bundle navigateur — le client ne fait donc qu'un import type-only de ce fichier (effacé à la compilation, impact
 * volume nul) ; l'implémentation d'emballage (adapter) est concentrée en un point unique :
 * packages/plugin-rq-card/src/client/host-port.ts.
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'

// ---------------------------------------------------------------------------
// Facette serveur : port étroit du webServer dsh (consommé par plugin-dsh-bridge)
// ---------------------------------------------------------------------------

/** Surface structurelle d'enregistrement de routes (alignée sur le contrat WebRoute du webserver dsh : kind/path/handler). */
export interface HostWebRoute {
  kind: 'exact' | 'prefix'
  path: string
  handler: (req: IncomingMessage, res: ServerResponse) => void
}

/** Surface structurelle minimale du webServer dsh (n'importe pas le package dsh, ne consomme que les contrats register/tapIndex). */
export interface HostWebServerLike {
  register(route: HostWebRoute): unknown
  tapIndex?: (transform: (html: string) => string) => unknown
}

/** Port étroit web de l'hôte : le code métier de dsh-bridge ne dépend que de cette interface, sans connaître l'implémentation hôte concrète. */
export interface HostWebPort {
  /** Enregistre une route (capacité requise ; l'adapter garantit la transmission de l'appel et de la valeur de retour). */
  register(route: HostWebRoute): unknown
  /** Réécriture HTML de l'UI web dsh (capacité optionnelle : la propriété entière est absente si l'hôte ne la fournit pas). */
  tapIndex?(transform: (html: string) => string): unknown
}

/** Adapter : réduit la structure du webServer hôte en HostWebPort (capacités optionnelles réduites selon leur présence). */
export function createHostWebPort(webServer: HostWebServerLike): HostWebPort {
  const port: HostWebPort = {
    register: (route) => webServer.register(route),
  }
  if (typeof webServer.tapIndex === 'function') {
    const tapIndex = webServer.tapIndex.bind(webServer)
    port.tapIndex = (transform) => tapIndex(transform)
  }
  return port
}

// ---------------------------------------------------------------------------
// Facette client : port étroit de la moitié navigateur (consommé par plugin-rq-card ; ce fichier ne déclare que le contrat,
// l'implémentation adapter se trouve dans packages/plugin-rq-card/src/client/host-port.ts)
// ---------------------------------------------------------------------------

/** Surface structurelle minimale d'enregistrement d'une entrée de slot (champs issus de tous les points d'appel register de rq-card). */
export interface HostClientSlotSpec {
  name: string
  id: string
  /** Spécifique aux slots keyed : nom de la clé (rq-card enregistre tool.call.toolview pour chaque outil). */
  key?: string
  /** Spécifique aux slots list : tri (rq-feedback=20, placé après le feedback=10 fourni par dsh). */
  order?: number
  /** Nom du siège de dictionnaire (les props.t des entrées sont pilotées par le dictionnaire de ce siège). */
  locale?: string
  /** Callback d'injection paresseuse : appelé seulement au rendu effectif de l'entrée, produit l'objet d'injection. */
  inject?: (arg: unknown) => unknown
}

export interface HostClientSlotsPort {
  /**
   * Sondage de slot (capacité optionnelle) : renvoie { kind } ('keyed' | 'list'…).
   * Hôte ne fournissant pas, erreur d'exécution, retour non objet — toujours undefined (signal de repli).
   */
  specDynamic?(name: string): { kind?: string } | undefined
  /** Injection paresseuse : l'usine n'est jamais exécutée si le slot cible n'est pas déclaré (un renommage amont du slot = carte silencieusement absente, l'hôte ne crashe pas). */
  inject(slot: string, factory: () => unknown): unknown
  /** Enregistre une entrée de slot ; renvoie la fonction de désinscription. */
  register(spec: HostClientSlotSpec, component: unknown): () => void
}

export interface HostClientLocalePort {
  /** Enregistre un espace de noms de dictionnaire (rq-card utilise le siège 'rq-card' + les trois langues zh/en/ja). */
  register(namespace: string, dictionaries: unknown): unknown
}

/** Port hôte de la moitié navigateur : l'unique surface de dépendance hôte du corps du plugin rq-card. */
export interface HostClientPort {
  slots: HostClientSlotsPort
  locale: HostClientLocalePort
  /** Enregistrement d'effets au context racine (dictionnaires etc. libérés avec le cycle de vie du context hôte). */
  effect(action: () => void, name: string): unknown
}

// ---------------------------------------------------------------------------
// Enregistreurs
// ---------------------------------------------------------------------------

/**
 * Enregistreur du pont hôte (détenu par platform-core ; câblage aligné sur WorkforcePolicyRegistry).
 * À l'assemblage, plugin-dsh-bridge enregistre le port emballé ; les autres services/tests y accèdent via port().
 * Hôte autonome (sans webServer dsh) : le port reste vacant = null, les consommateurs se replient d'eux-mêmes.
 *
 * Note de frontière W5 : apply de platform-core n'assemble pas cet enregistreur (surface d'assemblage existante inchangée),
 * l'amorçage « détection ou montage direct » se fait côté plugin-dsh-bridge (aligné sur la méthode d'évitement
 * d'auto-fourniture de son IdentityBindingService) — sur l'arbre cordis réel, monté dans ctx.hostBridge ; dans le ctx léger
 * (vue services du selftest), l'enregistrement est silencieusement ignoré, le port est utilisé localement, comportement externe inchangé.
 */
export class HostBridgeRegistry extends Service {
  static readonly provide = 'hostBridge'

  private web: HostWebPort | null = null

  constructor(ctx: Context) {
    super(ctx, 'hostBridge')
  }

  registerWebPort(port: HostWebPort): void {
    this.web = port
    try {
      this.ctx.platformBus?.emit('hostBridge.port.ready', { at: new Date().toISOString() })
    } catch {
      // Si platformBus n'est pas injecté dans le fiber courant, on saute la notification (accès strict aux services cordis)
    }
  }

  /** Non enregistré → renvoie null : les consommateurs s'en servent pour se replier (sémantique alignée sur workforce port()). */
  port(): HostWebPort | null {
    return this.web
  }

  isReady(): boolean {
    return this.web !== null
  }
}

// Compléments de type Cordis Context : hostBridge est fourni par auto-montage de plugin-dsh-bridge
// (provide='hostBridge') ; la forme absente (hôte autonome/ctx léger) est légale, d'où la déclaration optionnelle —
// les consommateurs doivent y accéder par lecture défensive, sans présumer sa présence.
declare module '@deepseek-ai/cordis' {
  interface Context {
    hostBridge?: HostBridgeRegistry
  }
}
