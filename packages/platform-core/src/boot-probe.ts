/**
 * Sonde de robustesse du démarrage (EXEC-CHECKLIST W2).
 *
 * Cause racine : cordis stocke les clés d'implémentation de services dans ctx.root[symbols.isolate][name] (reflect.ts),
 * la résolution d'inject ne reconnaît qu'un seul root — quand enregistrement et consommation se font dans deux instances Context distinctes,
 * fiber._checkImpl ne trouve pas l'implémentation et la supprime silencieusement : fiber en PENDING permanent, zéro erreur.
 * Ce module fournit deux lignes de défense : assertion de double instance (fail-fast avant assemblage) et diagnostic de l'arbre de plugins (refus de démarrage défectueux après assemblage).
 *
 * API internes vérifiées contre le code source de @deepseek-ai/cordis 4.0.4 :
 *   - ctx.reflect._getImpl(name, strict) : en strict, exige que le fiber fournisseur soit ACTIVE (reflect.ts)
 *   - ctx.registry.values() → runtime.fibers (DisposableList, itérable) → fiber.state/inject/name
 *   - FiberState est un const enum : inliné à la compilation, non importable à l'exécution, noms d'états reconstitués selon l'ordre d'énumération de fiber.ts
 */
import type { Context, Fiber } from '@deepseek-ai/cordis'

/** Clé d'enregistrement du root sur globalThis : un même processus ne doit enregistrer qu'un seul root. */
const ROOT_KEY = Symbol.for('ybkk.cordis.root')

/** Noms des états du cycle de vie des fiber (ordre du const enum de cordis 4.0.4 fiber.ts, reconstitué par valeur à l'exécution). */
const FIBER_STATE: Record<number, string> = {
  0: 'PENDING',
  1: 'LOADING',
  2: 'ACTIVE',
  3: 'FAILED',
  4: 'DISPOSED',
  5: 'UNLOADING',
}

const STATE_ACTIVE = 2
const STATE_FAILED = 3

/** Affirme que le processus courant ne contient qu'un seul Context root ; lève immédiatement à la découverte d'un second (réaffirmer le même arbre est idempotent, sans effet de bord). */
export function assertSingleRoot(ctx: Context): void {
  const holder = globalThis as Record<symbol, unknown>
  const existing = holder[ROOT_KEY]
  if (existing && existing !== ctx.root) {
    throw new Error(
      '检测到双实例：进程内出现了第二个 root Context，服务注册与 inject 解析将分属两棵'
      + '隔离树，fiber 会静默卡死在 PENDING。修复方式：复用 vendor/cordis 单实例'
      + '（全部模块经同一 specifier 解析到同一份 cordis），或改用独立宿主进程形态，'
      + '禁止在同一进程创建第二个根上下文。',
    )
  }
  holder[ROOT_KEY] ??= ctx.root
}

/** Instantané de diagnostic d'un seul fiber non ACTIVE. */
export interface StuckFiber {
  /** Nom du plugin (fiber.name : ancêtre nommé le plus proche, défaut 'root'). */
  plugin: string
  /** Nom de l'état du cycle de vie (reconstitué par valeur). */
  state: string
  /** Clés de services déclarés en inject dont l'implémentation ACTIVE est introuvable dans la portée courante. */
  waiting: string[]
  /** true = bloque le démarrage (câblage non prêt ou vraie panne) ; false = fiber perdant bénin, journalisé sans blocage. */
  blocking: boolean
}

/** Résultat du diagnostic de l'arbre de plugins. */
export interface TreeHealth {
  ok: boolean
  /** Services requis inaccessibles (aucune implémentation ACTIVE dans la portée courante). */
  unreachable: string[]
  /** Instantanés de tous les fiber dans un état non ACTIVE (perdants bénins inclus, vue de diagnostic complète). */
  stuck: StuckFiber[]
}

/**
 * Exemption bénigne des fiber FAILED : quand chaque nom de service déclaré en provide par ce plugin a été
 * repris par un autre fiber ACTIVE, c'est le husk perdant de l'idiome de double enregistrement, plus aucun blocage du démarrage.
 * Contexte : sous la double inscription « classe enregistrée via ctx.plugin + new synchrone » de panel-core/flow-core, le new synchrone
 * enregistre l'implémentation d'abord ; le chargement asynchrone du fiber de classe échoue alors sur le provide et laisse un husk FAILED (le service est fourni par le gagnant,
 * la fonctionnalité est intacte ; cette erreur était auparavant avalée par l'exporter à pur tampon du logger par défaut, jamais visible).
 * Inversement, un service déclaré repris par personne = vraie panne, il faut bloquer.
 */
function failedButCovered(ctx: Context, fiber: Fiber): boolean {
  const declared = (fiber.runtime?.callback as { provide?: string | string[] } | undefined)?.provide
  const names = typeof declared === 'string' ? [declared] : Array.isArray(declared) ? declared : []
  if (names.length === 0) return false
  return names.every((name) => {
    const impl = ctx.reflect._getImpl(name, true)
    return !!impl && impl.fiber !== fiber
  })
}

/**
 * Diagnostic après assemblage : tous les services requis accessibles, et aucun fiber bloqué interdisant le démarrage.
 * Doit être appelé après tous les await ctx.plugin — à cet instant, tous les fiber devraient être ACTIVE.
 */
export function probeTree(ctx: Context, required: string[]): TreeHealth {
  const unreachable = required.filter((name) => !ctx.reflect._getImpl(name, true))
  const stuck: StuckFiber[] = []
  for (const runtime of ctx.registry.values()) {
    for (const fiber of runtime.fibers) {
      if (fiber.state === STATE_ACTIVE) continue
      const waiting = Object.keys(fiber.inject)
        .filter((name) => !fiber.ctx.reflect._getImpl(name, true))
      stuck.push({
        plugin: fiber.name,
        state: FIBER_STATE[fiber.state] ?? `UNKNOWN(${fiber.state})`,
        waiting,
        blocking: fiber.state === STATE_FAILED ? !failedButCovered(ctx, fiber) : true,
      })
    }
  }
  return { ok: unreachable.length === 0 && !stuck.some((item) => item.blocking), unreachable, stuck }
}

/** Formate le résultat du diagnostic en texte multiligne directement levable. */
export function formatTreeHealth(h: TreeHealth): string {
  const lines = ['插件树未健康，拒绝启动']
  if (h.unreachable.length > 0) {
    lines.push(`不可达服务（${h.unreachable.length}）：${h.unreachable.join('、')}`)
  }
  for (const item of h.stuck) {
    const waiting = item.waiting.length > 0 ? item.waiting.join('、') : '（无未满足的 inject，查插件自身启动错误）'
    const benign = item.blocking ? '' : '（良性败者：声明服务已由其他 fiber 接管，不拦启动）'
    lines.push(`卡死插件 ${item.plugin} · 状态 ${item.state}${benign} · 等待 inject：${waiting}`)
  }
  return lines.join('\n')
}
