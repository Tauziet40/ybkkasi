/**
 * Outil de signature du manifeste de publication (clôture de la dette technique T5 de M2 — volet publication de la validation de chaîne d'approvisionnement de l'auto-mise à jour plateforme).
 *
 * Génère release-manifest.json (publié à la racine du dépôt ; plugin-update tire et vérifie la signature selon le commit cible à la mise à niveau) :
 *   node scripts/release-manifest.mjs --generate-key --key-file release-key.pem   # première fois : génère la paire de clés de publication
 *   node scripts/release-manifest.mjs --key-file release-key.pem                  # à la publication : génère le manifeste signé
 *   node scripts/release-manifest.mjs --check --out release-manifest.json --pubkey <base64>  # validation côté administrateur
 *
 * La clé privée reste chez l'éditeur (--key-file ou env RELEASE_SIGNING_KEY), jamais en base ni sur la plateforme ;
 * la clé publique est enregistrée par l'administrateur dans les paramètres de mise à jour de la plateforme (POST /api/update/settings.releasePublicKey).
 * Objet signé = SHA pleine longueur du commit cible (le verrouillage de version a résolu cette valeur ; vérifier « le commit a été signé par la clé de publication » revient à la validation de chaîne d'approvisionnement).
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateEd25519KeyPair, signEd25519, verifyEd25519 } from '../packages/platform-core/src/index.ts'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function argOf(flag) {
  const index = process.argv.indexOf(flag)
  return index >= 0 ? process.argv[index + 1] : undefined
}
const fail = (message) => { console.error(`✘ ${message}`); process.exit(1) }

const keyFile = argOf('--key-file')
const out = argOf('--out') ?? 'release-manifest.json'

// --check n'a besoin que de la clé publique (contre-vérification du produit côté administrateur ; la clé privée n'a pas besoin d'être présente)
if (process.argv.includes('--check')) {
  const publicKey = process.env.RELEASE_SIGNING_PUBKEY ?? argOf('--pubkey')
  if (!publicKey) fail('--check 需要 --pubkey <base64> 或 env RELEASE_SIGNING_PUBKEY（登记进平台的那个公钥）')
  const path = resolve(root, out)
  if (!existsSync(path)) fail(`清单不存在：${out}`)
  const existing = JSON.parse(readFileSync(path, 'utf8'))
  const commit = (argOf('--commit') ?? execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' })).trim()
  const ok = existing.commit === commit && verifyEd25519(String(publicKey), String(existing.commit), existing.signature)
  if (!ok) fail('清单校验未通过（commit 不一致或签名无效）')
  console.log(`✔ 清单校验通过：version=${existing.version} commit=${String(existing.commit).slice(0, 12)}…`)
  process.exit(0)
}

if (process.argv.includes('--generate-key')) {
  if (!keyFile) fail('--generate-key 需要 --key-file 指定私钥保存路径')
  if (existsSync(keyFile)) fail(`私钥文件已存在，拒绝覆盖：${keyFile}`)
  const keys = generateEd25519KeyPair()
  writeFileSync(keyFile, keys.privateKeyPem, { mode: 0o600 })
  console.log(`✔ 发布密钥对已生成：私钥 ${keyFile}（0600，绝不入库/上传）`)
  console.log('  公钥（登记到平台：POST /api/update/settings {"releasePublicKey": "..."}）：')
  console.log(`  ${keys.publicKeyBase64}`)
  process.exit(0)
}

const privateKeyPem = keyFile
  ? (existsSync(keyFile) ? readFileSync(keyFile, 'utf8') : fail(`私钥文件不存在：${keyFile}`))
  : (process.env.RELEASE_SIGNING_KEY ?? fail('缺少私钥：--key-file <path> 或 env RELEASE_SIGNING_KEY（首次用 --generate-key 生成）'))

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const version = argOf('--version') ?? pkg.version
const commit = (argOf('--commit') ?? execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' })).trim()
if (!/^[0-9a-f]{40}$/.test(commit)) fail(`commit 非全长 SHA：${commit}`)

const manifest = {
  algorithm: 'ed25519',
  version,
  commit,
  signedAt: new Date().toISOString(),
  signature: signEd25519(privateKeyPem, commit),
}

writeFileSync(resolve(root, out), `${JSON.stringify(manifest, null, 2)}\n`)
console.log(`✔ 发布清单已生成：${out}`)
console.log(`  version=${version} commit=${commit.slice(0, 12)}…`)
console.log('  提交该文件到仓库根随版本发布；管理员侧登记公钥并在升级设置开启 requireSignedManifests。')
