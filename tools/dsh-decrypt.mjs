#!/usr/bin/env node
// dsh-decrypt.mjs — 把 dsh-backup 的加密备份解成普通备份，好让面板 / 命令直接恢复。
// 用法：node dsh-decrypt.mjs "<备份文件路径>.tar.gz"
// 只用 Node 自带模块，口令在终端里输入（不显示、不保存）。
// 算法与 dsh-backup lib/encrypt.js 一致：scrypt 派生密钥 + AES-256-GCM，参数读自 .encrypted.json 边车。

import { createDecipheriv, createHash, scrypt as scryptCb } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync } from 'node:fs';
import { readFile, writeFile, rm, copyFile } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';
import path from 'node:path';

const scrypt = promisify(scryptCb);

function askHidden(prompt) {
  return new Promise((resolve) => {
    const { stdin, stdout } = process;
    stdout.write(prompt);
    if (!stdin.isTTY) { // 非终端（管道）时直接读一行
      let buf = '';
      stdin.setEncoding('utf8');
      stdin.on('data', (d) => { buf += d; });
      stdin.on('end', () => resolve(buf.replace(/\r?\n$/, '')));
      return;
    }
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let pw = '';
    const onData = (ch) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') {
          stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData);
          stdout.write('\n'); resolve(pw); return;
        } else if (c === '\u0003') { stdout.write('\n'); process.exit(130); }
        else if (c === '\u007f' || c === '\b') { pw = pw.slice(0, -1); }
        else { pw += c; }
      }
    };
    stdin.on('data', onData);
  });
}

async function sha256(file) {
  const h = createHash('sha256');
  await pipeline(createReadStream(file), h);
  return h.digest('hex');
}

async function main() {
  const input = process.argv[2];
  if (!input) {
    console.log('用法：node dsh-decrypt.mjs "<加密备份>.tar.gz"');
    process.exit(1);
  }
  const archive = path.resolve(input);
  const sidecarPath = `${archive}.encrypted.json`;
  if (!existsSync(archive)) throw new Error(`找不到备份文件：${archive}`);
  if (!existsSync(sidecarPath)) throw new Error(`找不到同名的 .encrypted.json（加密参数文件），请把它和备份放在同一个文件夹：${sidecarPath}`);

  const sidecar = JSON.parse(await readFile(sidecarPath, 'utf8'));
  if (Number(sidecar.version) !== 1 || sidecar.cipher !== 'aes-256-gcm') {
    throw new Error(`不认识的加密格式（version=${sidecar.version}, cipher=${sidecar.cipher}）`);
  }

  const password = process.env.DSH_BACKUP_PASSWORD || await askHidden('请输入备份时设置的口令（输入时不显示）：');
  if (!password) throw new Error('口令不能为空');

  const p = sidecar.kdfParams || {};
  const N = Number(p.N) || 16384, r = Number(p.r) || 8, pp = Number(p.p) || 1, keyLen = Number(p.keyLen) || 32;
  const salt = Buffer.from(sidecar.salt, 'base64');
  const key = await scrypt(password, salt, keyLen, { N, r, p: pp, maxmem: 128 * N * r * 2 + 1024 * 1024 });
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sidecar.nonce, 'base64'));
  decipher.setAuthTag(Buffer.from(sidecar.authTag, 'base64'));

  const dir = path.dirname(archive);
  const base = path.basename(archive).replace(/\.tar\.gz$/, '');
  const outName = `${base}-plain.tar.gz`;
  const out = path.join(dir, outName);

  try {
    await pipeline(createReadStream(archive), decipher, createWriteStream(out, { mode: 0o600 }));
  } catch (err) {
    await rm(out, { force: true }).catch(() => {});
    if (/authenticate/i.test(String(err?.message))) throw new Error('口令不对（或者备份文件损坏了），请再试一次');
    throw err;
  }

  // 配套文件：校验文件 + 元信息（标记为未加密）+ 脱敏清单，让插件把它当普通备份
  await writeFile(`${out}.sha256`, `${await sha256(out)}  ${out}\n`);
  const metaPath = `${archive}.meta.json`;
  if (existsSync(metaPath)) {
    try {
      const meta = JSON.parse(await readFile(metaPath, 'utf8'));
      meta.encrypted = false;
      await writeFile(`${out}.meta.json`, JSON.stringify(meta, null, 2));
    } catch { /* 元信息读不了就跳过，不影响恢复 */ }
  }
  if (existsSync(`${archive}.redacted.json`)) await copyFile(`${archive}.redacted.json`, `${out}.redacted.json`);

  console.log(`\n✅ 解密成功：${outName}`);
  console.log('现在回到 DSH 的 设置 → 插件 → 备份 → 恢复，选这份带 -plain 的备份恢复即可。');
  console.log(`或在 DSH 里输入：/backup restore ${outName}`);
  console.log('恢复完成后建议删掉这份 -plain 文件（它是没加密的）。');
}

main().catch((e) => { console.error(`\n❌ ${e.message}`); process.exit(1); });
