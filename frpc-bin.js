import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { STATE_DIR } from './state.js';

/**
 * Locates or fetches the frpc binary the relay runs.
 *
 * Order: a copy this plugin downloaded before, then `frpc` on PATH (or the
 * usual Homebrew locations), then a download of the pinned frp release. The
 * archive is checked against the SHA-256 recorded here before anything is
 * extracted, so the GitHub mirrors tried after GitHub itself cannot swap it.
 */

export const FRP_VERSION = '0.71.1';
export const BIN_DIR = join(STATE_DIR, 'bin');
const EXE = process.platform === 'win32' ? 'frpc.exe' : 'frpc';

// From the v0.71.1 release on github.com/fatedier/frp.
const ASSETS = {
  'darwin-arm64': ['darwin_arm64.tar.gz', 'd15d0324b99e14619c9aa46e37f6db588c06a09be4bc6f7948890b6b61077842'],
  'darwin-x64': ['darwin_amd64.tar.gz', '8acb59b6fb998cc8d209d1373d90bf70fa5ec3efeb4dfbc7bda6ce3abd78cb45'],
  'linux-x64': ['linux_amd64.tar.gz', '1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803'],
  'linux-arm64': ['linux_arm64.tar.gz', '8edf590b0c396fa42f9c147121a76af83cfc2002b08f5aef0ea1008c43482019'],
  'win32-x64': ['windows_amd64.zip', 'b90074b2b6a1d792a7a40f085ac6d276bcab2d1bc60201f8a86ca53ce65ce821'],
  'win32-arm64': ['windows_arm64.zip', '6c25afb4058f7708937db7064836fec593e941de0e6c2c255982335a9b16d370'],
};
const MIRRORS = ['', 'https://ghfast.top/', 'https://gh-proxy.com/'];
const DOWNLOAD_TIMEOUT_MS = 180_000;

const isFile = (path) => {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
};

function onPath() {
  const dirs = String(process.env.PATH ?? '').split(delimiter);
  if (process.platform !== 'win32') dirs.push('/opt/homebrew/bin', '/usr/local/bin');
  for (const dir of dirs) {
    if (dir && isFile(join(dir, EXE))) return join(dir, EXE);
  }
  return undefined;
}

function run(file, args) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout: 60_000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(`${file} ${args[0]}: ${String(stderr || error.message).trim()}`));
      else resolve(stdout);
    });
  });
}

async function fetchVerified(url, sha256) {
  const response = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = Buffer.from(await response.arrayBuffer());
  const actual = createHash('sha256').update(data).digest('hex');
  if (actual !== sha256) throw new Error(`checksum mismatch (${actual.slice(0, 12)}…)`);
  return data;
}

/**
 * Path of a usable frpc, downloading it on first use.
 * @param onDownload - called once before a download starts.
 */
export async function ensureFrpc({ onDownload } = {}) {
  const cached = join(BIN_DIR, EXE);
  if (isFile(cached)) return cached;
  const system = onPath();
  if (system !== undefined) return system;

  const asset = ASSETS[`${process.platform}-${process.arch}`];
  if (asset === undefined) throw new Error(`no frpc download for ${process.platform}-${process.arch}; install frpc on PATH`);
  const [suffix, sha256] = asset;
  const base = `frp_${FRP_VERSION}_${suffix.replace(/\.(tar\.gz|zip)$/, '')}`;
  const github = `https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_${suffix}`;
  onDownload?.();

  const failures = [];
  let data;
  for (const mirror of MIRRORS) {
    try {
      data = await fetchVerified(mirror + github, sha256);
      break;
    } catch (error) {
      failures.push(`${mirror ? new URL(mirror).host : 'github.com'}: ${error.message}`);
    }
  }
  if (data === undefined) throw new Error(`cannot download frpc ${FRP_VERSION} (${failures.join('; ')}); put ${EXE} in ${BIN_DIR} or on PATH`);

  const work = mkdtempSync(join(tmpdir(), 'peer-link-frp-'));
  try {
    const archive = join(work, `frp.${suffix.endsWith('.zip') ? 'zip' : 'tar.gz'}`);
    writeFileSync(archive, data);
    // bsdtar ships with Windows 10 and later and reads zip archives too.
    const tar = process.platform === 'win32' && process.env.SystemRoot ? join(process.env.SystemRoot, 'System32', 'tar.exe') : 'tar';
    await run(tar, ['-xf', archive, '-C', work, `${base}/${EXE}`]);
    mkdirSync(BIN_DIR, { recursive: true });
    copyFileSync(join(work, base, EXE), cached);
    if (process.platform !== 'win32') chmodSync(cached, 0o755);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  return cached;
}
