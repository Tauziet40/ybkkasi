/**
 * Tests unitaires de l'hébergement d'identifiants externes d'application (issue #19, direction A, boucle minimale).
 *
 * Exécution (chargement direct par Node, construction dans le processus, sur le modèle bus factice+StorageService de capabilities.test.mjs) :
 *
 *     node packages/plugin-app/src/credentials.test.mjs
 *
 * Couverture :
 *   - enregistrement → écho masqué (réponse et métadonnées de masque jamais en clair) ; gardes de nom/valeur (nom illégal, valeur vide, valeur trop longue) ;
 *   - chiffrement au repos : le contenu du fichier de clés ne contient pas de clair (AES-256-GCM), clé maîtresse dans un fichier distinct généré au premier usage (0600/répertoire 0700) ;
 *   - aller-retour de déchiffrement ; sémantique 404 pour clé non enregistrée (AppCredentialMissingError + code CREDENTIAL_NOT_FOUND) ;
 *   - détection de falsification : chiffré ou tag modifié → échec de déchiffrement fail-closed explicite (jamais de valeur poubelle) ;
 *   - rotation : un second put sur la même clé = rotation (rotatedAt/rotatedBy mis à jour, createdAt inchangé, ancienne valeur invalidée immédiatement) ;
 *   - suppression : à l'unité idempotente ; purge supprime le fichier entier (cascade de suppression d'application) ;
 *   - traçabilité : chaque resolve émet app.secret.access (payload en métadonnées seules, jamais de valeur).
 */
import assert from 'node:assert/strict'
import { test, afterEach } from 'node:test'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { StorageService } from '../../platform-core/src/storage.ts'
import { AppCredentialService, AppCredentialMissingError } from './credentials.ts'

// -- Construction de l'hôte dans le processus (bus factice + vrai StorageService + répertoire de données temporaire) ----------------------------

const cleanup = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()()
})

function makeHarness(existingDataDir) {
  const dataDir = existingDataDir ?? mkdtempSync(join(tmpdir(), 'app-credentials-'))
  cleanup.push(() => rmSync(dataDir, { recursive: true, force: true }))
  const ctx = new Context()
  const events = []
  // Bus factice : enregistre les emit pour les assertions de traçabilité (on renvoie une fonction de désinscription vide)
  ctx.platformBus = {
    on: () => () => {},
    emit: (name, payload) => events.push({ name, payload }),
  }
  new StorageService(ctx, { dataDir })
  const vault = new AppCredentialService(ctx)
  return { ctx, vault, events, dataDir }
}

// -- A. Enregistrement et masque ---------------------------------------------------------------------------

test('登记：掩码回显绝不含明文；键名/值护栏（非法键名/空值/超长值）', () => {
  const { vault } = makeHarness()
  const meta = vault.put('app_1', { key: 'kizuna-admin-token', value: 'tk_live_9f8e7d6c5b4a', rotatedBy: '管理员', description: 'Kizuna 产品服务管理令牌' })
  assert.equal(meta.key, 'kizuna-admin-token')
  assert.equal(meta.masked, '••••••••5b4a', '长值保留末 4 位掩码')
  assert.ok(!JSON.stringify(meta).includes('tk_live'), '掩码元数据不含明文')
  assert.equal(meta.rotatedBy, '管理员')
  assert.equal(meta.description, 'Kizuna 产品服务管理令牌')

  // Valeur courte entièrement masquée (pas d'ancre sur les derniers caractères pour la force brute)
  const short = vault.put('app_1', { key: 'short-key', value: 'abc', rotatedBy: 'x' })
  assert.equal(short.masked, '••••••••')

  // Gardes : nom de clé illégal / valeur vide / valeur trop longue
  assert.throws(() => vault.put('app_1', { key: '../escape', value: 'v', rotatedBy: 'x' }), /键名非法/)
  assert.throws(() => vault.put('app_1', { key: '-lead', value: 'v', rotatedBy: 'x' }), /键名非法/)
  assert.throws(() => vault.put('app_1', { key: 'ok', value: '', rotatedBy: 'x' }), /凭证值必填/)
  assert.throws(() => vault.put('app_1', { key: 'ok', value: 'x'.repeat(8193), rotatedBy: 'x' }), /过长/)
})

// -- B. Chiffrement au repos et aller-retour de déchiffrement -------------------------------------------------------------------

test('静态加密：密钥文件不含明文；主密钥独立文件 0600 / 目录 0700；解密往返一致', () => {
  const { vault, dataDir } = makeHarness()
  const SECRET = 'tk_live_zz_top_secret_value'
  vault.put('app_1', { key: 'token', value: SECRET, rotatedBy: 'x' })

  const file = vault.fileOf('app_1')
  const raw = readFileSync(file, 'utf8')
  assert.ok(!raw.includes(SECRET), '密钥文件不含明文（AES-256-GCM 密文落盘）')
  assert.ok(!raw.includes('maskedPreview": "••••••••_value'), '掩码字段只存掩码')

  // Fichier distinct de la clé maîtresse + bits de permission
  const keyFile = join(dataDir, 'secrets', 'app', '.master.key')
  assert.ok(existsSync(keyFile), '主密钥首用生成')
  assert.equal((statSync(keyFile).mode & 0o777), 0o600, '主密钥文件 0600')
  assert.equal((statSync(join(dataDir, 'secrets', 'app')).mode & 0o777), 0o700, '密钥目录 0700')
  assert.ok(!readFileSync(keyFile, 'utf8').includes(SECRET))

  // Aller-retour de déchiffrement (sémantique de redémarrage avec la même clé maîtresse : un nouveau Context/nouvelle instance pointant le même répertoire de données déchiffre encore)
  const restarted = makeHarness(dataDir)
  assert.equal(restarted.vault.resolve('app_1', 'token'), SECRET)
})

test('取值：未登记键 404 语义；篡改检测 fail-closed（密文被改显式报错，绝不返回垃圾值）', () => {
  const { vault, events } = makeHarness()
  assert.throws(() => vault.resolve('app_1', 'ghost'), AppCredentialMissingError)
  assert.equal(events.at(-1).name, 'app.secret.access', '未命中也留痕（missing）')
  assert.equal(events.at(-1).payload.result, 'missing')

  vault.put('app_1', { key: 'token', value: 'tk_live_value_01', rotatedBy: 'x' })
  // Falsification du chiffré (simule une altération hors ligne après vol de la base) : la vérification GCM échoue → fail-closed
  const file = vault.fileOf('app_1')
  const stored = JSON.parse(readFileSync(file, 'utf8'))
  stored.entries.token.data = Buffer.from('tampered').toString('base64')
  writeFileSync(file, JSON.stringify(stored), 'utf8')
  assert.throws(() => vault.resolve('app_1', 'token'), /解密失败/)
  assert.equal(events.at(-1).payload.result, 'error', '解密失败留痕（error）')
})

// -- C. Rotation / suppression / effacement -------------------------------------------------------------------

test('轮换：同键再 put 即轮换（rotatedAt/rotatedBy 更新、createdAt 不变、旧值立即失效）', async () => {
  const { vault } = makeHarness()
  const first = vault.put('app_1', { key: 'token', value: 'tk_live_old_value_1', rotatedBy: '旧操作者' })
  await new Promise((resolve) => setTimeout(resolve, 5)) // garantit des timestamps rotatedAt distinguables
  const second = vault.put('app_1', { key: 'token', value: 'tk_live_new_value_2', rotatedBy: '新操作者' })
  assert.equal(second.createdAt, first.createdAt, 'createdAt 保持首次登记时间')
  assert.notEqual(second.rotatedAt, first.rotatedAt, 'rotatedAt 更新为轮换时间')
  assert.equal(second.rotatedBy, '新操作者')
  assert.equal(vault.resolve('app_1', 'token'), 'tk_live_new_value_2', '旧值立即失效，取到新值')
  assert.equal(vault.list('app_1').length, 1, '同键轮换不新增条目')
})

test('删除：单条幂等；purge 整文件删除（应用删除联动清库）', () => {
  const { vault } = makeHarness()
  vault.put('app_1', { key: 'a', value: 'va_1234567890', rotatedBy: 'x' })
  vault.put('app_1', { key: 'b', value: 'vb_1234567890', rotatedBy: 'x' })
  assert.equal(vault.remove('app_1', 'a'), true)
  assert.equal(vault.remove('app_1', 'a'), false, '重复删除幂等')
  assert.deepEqual(vault.list('app_1').map((item) => item.key), ['b'])
  assert.equal(vault.purge('app_2'), false, '无文件 purge 幂等')
  assert.equal(vault.purge('app_1'), true)
  assert.ok(!existsSync(vault.fileOf('app_1')), 'purge 整文件删除')
  assert.deepEqual(vault.list('app_1'), [])
})

// -- D. Traçabilité des accès -----------------------------------------------------------------------------

test('留痕：每次 resolve emit app.secret.access，payload 仅元数据绝无值；caller 透传审计主体', () => {
  const { vault, events } = makeHarness()
  vault.put('app_1', { key: 'token', value: 'tk_live_audit_check', rotatedBy: 'x' })
  vault.resolve('app_1', 'token', { actor: 'u1', actorName: '数字员工' })
  const hit = events.at(-1)
  assert.equal(hit.name, 'app.secret.access')
  assert.equal(hit.payload.result, 'ok')
  assert.equal(hit.payload.key, 'token')
  assert.equal(hit.payload.actor, 'u1')
  assert.equal(hit.payload.actorName, '数字员工')
  assert.equal(hit.payload.type, 'app')
  assert.equal(hit.payload.id, 'app_1')
  assert.ok(!JSON.stringify(hit.payload).includes('tk_live_audit_check'), '事件 payload 绝不带值')
})
