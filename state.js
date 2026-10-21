import { chmodSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { homedir, hostname, platform } from 'node:os';
import { join } from 'node:path';
import { lanInterfaces, newSecret, parseHint, PeerError } from './protocol.js';

/**
 * Plugin-owned pairing state, kept outside the Cordis profile so secrets never
 * enter `cordis.patch.yml` or the chat:
 *
 *   ~/.dsh/peer-link/state.json         { secret, peers: [{ name, secret, addr?, hints, platform, addedAt }] }
 *   ~/.dsh/peer-link/pairing-code.txt   this machine's pairing code (contains the secret)
 *
 * A peer's `addr` (`host:port`) is only a cache: the HTTP port is random, so
 * discovery refreshes it whenever the peer restarts or changes networks.
 * `hints` are the peer's LAN IPs from its pairing code, used for unicast
 * discovery where broadcasts do not pass.
 *
 * Both files are written with mode 0600. The state is re-read whenever its
 * mtime changes, so hand edits and the other plugin instance's writes apply live.
 */

export const STATE_DIR = join(homedir(), '.dsh', 'peer-link');
const STATE_FILE = join(STATE_DIR, 'state.json');
export const PAIRING_FILE = join(STATE_DIR, 'pairing-code.txt');
const CODE_PREFIX = 'dshpeer1.';
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/;

export function writePrivate(path, text) {
  mkdirSync(STATE_DIR, { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  renameSync(tmp, path);
  try {
    chmodSync(path, 0o600);
  } catch {
    // Windows ignores POSIX modes.
  }
}

export function normalizeName(raw) {
  const name = String(raw ?? '')
    .trim()
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^[-_.]+/, '')
    .slice(0, 32);
  if (!NAME_RE.test(name)) throw new PeerError('BAD_INPUT', `invalid peer name "${raw}"`);
  return name;
}

/** Hints are bare IPs or `ip:port`; anything else is dropped. */
function cleanHints(list) {
  return [...new Set((Array.isArray(list) ? list : []).map(String).filter((hint) => parseHint(hint) !== undefined))].slice(0, 8);
}

/** Old pairing codes and state carried full URLs. */
function hintsFromUrls(urls) {
  return (Array.isArray(urls) ? urls : []).flatMap((url) => {
    try {
      const parsed = new URL(url);
      return [`${parsed.hostname}:${parsed.port || 80}`];
    } catch {
      return [];
    }
  });
}

export function encodeCode({ name, hints, secret }) {
  const json = JSON.stringify({ n: name, h: hints, k: secret, p: platform() });
  return CODE_PREFIX + Buffer.from(json, 'utf8').toString('base64url');
}

export function decodeCode(code) {
  const text = String(code ?? '').trim();
  if (!text.startsWith(CODE_PREFIX)) throw new PeerError('BAD_INPUT', 'not a peer-link pairing code (expected dshpeer1.…)');
  let data;
  try {
    data = JSON.parse(Buffer.from(text.slice(CODE_PREFIX.length), 'base64url').toString('utf8'));
  } catch {
    throw new PeerError('BAD_INPUT', 'corrupt pairing code');
  }
  if (typeof data?.k !== 'string' || data.k.length < 32) throw new PeerError('BAD_INPUT', 'incomplete pairing code');
  return {
    name: normalizeName(data.n),
    hints: cleanHints([...(data.h ?? []), ...hintsFromUrls(data.u)]),
    secret: data.k,
    platform: typeof data.p === 'string' ? data.p : undefined,
  };
}

/** Public view of a peer: everything except its secret. */
export function publicPeer(peer) {
  return { name: peer.name, addr: peer.addr, hints: peer.hints, platform: peer.platform, addedAt: peer.addedAt, seenAt: peer.seenAt };
}

function cleanPeer(raw) {
  if (!raw || typeof raw.name !== 'string' || typeof raw.secret !== 'string') return undefined;
  const hints = cleanHints([...(raw.hints ?? []), ...hintsFromUrls(raw.urls)]);
  const addr = parseHint(raw.addr)?.port !== undefined ? raw.addr : undefined;
  return { name: raw.name, secret: raw.secret, addr, hints, platform: raw.platform, addedAt: raw.addedAt, seenAt: raw.seenAt };
}

export class PeerState {
  constructor() {
    this.mtime = -1;
    this.data = { secret: '', peers: [] };
  }

  /** Re-read the file when it changed; creates the secret on first use. */
  load() {
    let mtime = 0;
    try {
      mtime = statSync(STATE_FILE).mtimeMs;
    } catch {
      mtime = 0;
    }
    if (mtime === this.mtime) return this.data;
    let data = { secret: '', peers: [] };
    if (mtime !== 0) {
      try {
        const parsed = JSON.parse(readFileSync(STATE_FILE, 'utf8'));
        data = {
          secret: typeof parsed.secret === 'string' ? parsed.secret : '',
          lastPort: parsed.lastPort,
          ...(typeof parsed.accessDecision === 'string' ? { accessDecision: parsed.accessDecision } : {}),
          peers: Array.isArray(parsed.peers) ? parsed.peers.map(cleanPeer).filter(Boolean) : [],
        };
      } catch {
        // Keep the previous good state when the file is mid-edit or corrupt.
        return this.data;
      }
    }
    this.data = data;
    if (!this.data.secret) {
      this.data.secret = newSecret();
      this.save();
      return this.data;
    }
    this.mtime = mtime;
    return this.data;
  }

  save() {
    writePrivate(STATE_FILE, `${JSON.stringify(this.data, null, 2)}\n`);
    this.mtime = statSync(STATE_FILE).mtimeMs;
  }

  get secret() {
    return this.load().secret;
  }

  /** The HTTP port used last time, tried first so peers' cached addresses survive restarts. */
  get lastPort() {
    const port = Number(this.load().lastPort);
    return Number.isInteger(port) && port > 0 && port < 65536 ? port : undefined;
  }

  set lastPort(port) {
    this.load();
    if (this.data.lastPort === port) return;
    this.data.lastPort = port;
    this.save();
  }

  /**
   * The user's answer to the full-access prompt shown after installation:
   * `granted`, `declined`, or undefined while unanswered.
   */
  get accessDecision() {
    return this.load().accessDecision;
  }

  set accessDecision(decision) {
    this.load();
    if (this.data.accessDecision === decision) return;
    this.data.accessDecision = decision;
    this.save();
  }

  peers() {
    return this.load().peers;
  }

  peer(name) {
    const peers = this.peers();
    if (name === undefined || name === '') {
      if (peers.length === 1) return peers[0];
      throw new PeerError('BAD_INPUT', peers.length === 0 ? 'no peers paired yet' : `specify a peer: ${peers.map((p) => p.name).join(', ')}`);
    }
    const found = peers.find((p) => p.name.toLowerCase() === String(name).toLowerCase());
    if (!found) throw new PeerError('NOT_FOUND', `unknown peer "${name}"; paired: ${peers.map((p) => p.name).join(', ') || '(none)'}`);
    return found;
  }

  /** Add or replace a peer; a peer holding the same secret under another name is replaced too. */
  upsertPeer({ name, hints, secret, platform: peerPlatform, addr }) {
    this.load();
    const entry = cleanPeer({ name: normalizeName(name), hints, secret, platform: peerPlatform, addr, addedAt: Date.now() });
    const others = this.data.peers.filter((p) => p.name.toLowerCase() !== entry.name.toLowerCase() && p.secret !== secret);
    this.data.peers = [...others, entry];
    this.save();
    return entry;
  }

  /** Cache the address a peer was last verified at. */
  rememberAddr(name, addr) {
    this.load();
    const peer = this.data.peers.find((p) => p.name === name);
    if (!peer) return;
    const host = parseHint(addr)?.host;
    const changed = peer.addr !== addr;
    peer.addr = addr;
    peer.seenAt = Date.now();
    if (host && !peer.hints.some((hint) => parseHint(hint)?.host === host)) peer.hints = [host, ...peer.hints].slice(0, 8);
    // Avoid rewriting the file on every call when nothing but seenAt moved.
    if (changed) this.save();
  }

  removePeer(name) {
    this.load();
    const before = this.data.peers.length;
    this.data.peers = this.data.peers.filter((p) => p.name.toLowerCase() !== String(name).toLowerCase());
    if (this.data.peers.length === before) return false;
    this.save();
    return true;
  }

  /** Write this machine's pairing code for the given listener port and return it. */
  writePairingCode(name, port) {
    const hints = lanInterfaces().map((iface) => `${iface.address}:${port}`);
    const code = encodeCode({ name, hints, secret: this.secret });
    writePrivate(PAIRING_FILE, `${code}\n`);
    return { code, hints };
  }
}

export function defaultDisplayName() {
  try {
    return normalizeName(hostname().split('.')[0]);
  } catch {
    return 'dsh';
  }
}
