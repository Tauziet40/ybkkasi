/** Dictionnaire de l'espace de noms `rq-card` (tous les libellés de la carte d'exécution + barre de feedback + coin de repli). */

/** Dictionnaire chinois simplifié (source d'autorité du jeu de clés). */
export const zh = {
  // ── carte d'exécution : badges d'état ──
  'card.state.calling': '调用中',
  'card.state.executing': '执行中',
  'card.state.done': '已完成',
  'card.state.blocked': '已受阻',
  'card.state.idle': '等待中',

  // ── carte d'exécution : génériques ──
  'card.args.summary': '调用参数',
  'card.result.title': '执行结果',
  'card.result.truncated': '（内容过长，已截断）',
  'card.console.link': '到控制台查看',

  // ── carte d'exécution : en appel (squelette + placeholder annulable) ──
  'card.cancel.button': '取消',
  'card.cancel.hint': '取消通道待宿主半接线后启用',

  // ── carte d'exécution : en exécution (pulsation de progression) ──
  'card.degraded.hint': '有点慢，已转后台处理',

  // ── carte d'exécution : bloqué anomalie (libellé métier, code de motif = clé de C3 js/errors.js) ──
  'card.blocked.nas-authz-deny': '没有访问权限，请先申请授权',
  'card.blocked.quota-exhausted': '钱包额度已耗尽，请申请追加',
  'card.blocked.pdp-unreachable': '策略决策点暂不可达，已保护性暂停',
  'card.blocked.breaker-open': '熔断保护生效中，待服务恢复后重试',
  'card.blocked.down': '服务暂不可用，恢复后即可重试',
  'card.blocked.binding-invalid': '身份绑定已失效，请重新绑定',
  'card.blocked.invoke-error': '执行出错，详见结果信息',

  // ── carte d'exécution : bouton d'action de blocage (saut vers la page correspondante de la console /rq, same-origin avec état de connexion) ──
  'card.action.nas-authz-deny': '申请访问',
  'card.action.quota-exhausted': '申请额度',
  'card.action.pdp-unreachable': '查看平台状态',
  'card.action.breaker-open': '查看服务状态',
  'card.action.down': '查看服务状态',
  'card.action.binding-invalid': '重新绑定',
  'card.action.invoke-error': '查看平台状态',

  // ── barre de feedback ──
  'fb.like': '有帮助',
  'fb.dislike': '没帮助',
  'fb.done': '已记录，感谢反馈',

  // ── coin de repli (shell.overlay) ──
  'badge.degraded': '元冰可卡片未生效（纯文本模式）',
} satisfies Record<string, string>

/** Union des clés de l'espace de noms `rq-card`. */
export type RqCardKey = keyof typeof zh

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Libellés de la carte d'exécution et de la barre de feedback de method. */
    'rq-card': RqCardKey
  }
}

/** Dictionnaire anglais, vérifié clé à clé avec le jeu zh. */
export const en = {
  'card.state.calling': 'Calling',
  'card.state.executing': 'Running',
  'card.state.done': 'Done',
  'card.state.blocked': 'Blocked',
  'card.state.idle': 'Waiting',

  'card.args.summary': 'Arguments',
  'card.result.title': 'Result',
  'card.result.truncated': '(truncated)',
  'card.console.link': 'Open in console',

  'card.cancel.button': 'Cancel',
  'card.cancel.hint': 'Cancellation becomes available once the host channel is wired',

  'card.degraded.hint': 'Slow — moved to background',

  'card.blocked.nas-authz-deny': 'No access permission — request authorization first',
  'card.blocked.quota-exhausted': 'Wallet quota exhausted — request a top-up',
  'card.blocked.pdp-unreachable': 'Policy decision point unreachable — paused protectively',
  'card.blocked.breaker-open': 'Circuit breaker is open — retry after recovery',
  'card.blocked.down': 'Service is down — retry once it recovers',
  'card.blocked.binding-invalid': 'Identity binding expired — please re-bind',
  'card.blocked.invoke-error': 'Execution failed — see result details',

  'card.action.nas-authz-deny': 'Request access',
  'card.action.quota-exhausted': 'Request quota',
  'card.action.pdp-unreachable': 'Platform status',
  'card.action.breaker-open': 'Service status',
  'card.action.down': 'Service status',
  'card.action.binding-invalid': 'Re-bind',
  'card.action.invoke-error': 'Platform status',

  'fb.like': 'Helpful',
  'fb.dislike': 'Not helpful',
  'fb.done': 'Recorded — thanks for the feedback',

  'badge.degraded': 'RongQi cards inactive (plain-text mode)',
} satisfies Record<RqCardKey, string>

/** Dictionnaire japonais, vérifié clé à clé avec les jeux zh/en (style です・ます). */
export const ja = {
  'card.state.calling': '呼び出し中',
  'card.state.executing': '実行中',
  'card.state.done': '完了',
  'card.state.blocked': 'ブロック中',
  'card.state.idle': '待機中',

  'card.args.summary': '呼び出し引数',
  'card.result.title': '実行結果',
  'card.result.truncated': '（内容が長いため切り捨てました）',
  'card.console.link': 'コンソールで開く',

  'card.cancel.button': 'キャンセル',
  'card.cancel.hint': 'キャンセルはホスト側の接続後に有効になります',

  'card.degraded.hint': '時間がかかっています。バックグラウンドで処理中です',

  'card.blocked.nas-authz-deny': 'アクセス権がありません。先に権限を申請してください',
  'card.blocked.quota-exhausted': 'ウォレット残高を使い切りました。追加を申請してください',
  'card.blocked.pdp-unreachable': 'ポリシー判定ポイント（PDP）に到達できないため、保護的に一時停止中です',
  'card.blocked.breaker-open': 'サーキットブレーカーが作動中です。復旧後に再試行してください',
  'card.blocked.down': 'サービスは現在利用できません。復旧後に再試行してください',
  'card.blocked.binding-invalid': 'ID バインディングの有効期限が切れています。再バインドしてください',
  'card.blocked.invoke-error': '実行エラーが発生しました。詳細は結果情報を確認してください',

  'card.action.nas-authz-deny': 'アクセス申請',
  'card.action.quota-exhausted': '残高を申請',
  'card.action.pdp-unreachable': 'プラットフォーム状態を確認',
  'card.action.breaker-open': 'サービス状態を確認',
  'card.action.down': 'サービス状態を確認',
  'card.action.binding-invalid': '再バインド',
  'card.action.invoke-error': 'プラットフォーム状態を確認',

  'fb.like': '役に立った',
  'fb.dislike': '役に立たなかった',
  'fb.done': '記録しました。フィードバックありがとうございます',

  'badge.degraded': 'RongQi カードが無効です（テキストモード）',
} satisfies Record<RqCardKey, string>
