import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import net from 'node:net';
import { networkInterfaces } from 'node:os';

/**
 * Wire protocol shared by the peer-link server, client, and discovery.
 *
 * Every request is `POST /peer/v1/<op>` with a JSON body and three headers:
 *   x-peer-ts     milliseconds since epoch
 *   x-peer-nonce  random, single use within the replay window
 *   x-peer-sig    hex HMAC-SHA256(secret, `${ts}\n${nonce}\n${path}\n${sha256(body)}`)
 * Every response carries
 *   x-peer-resp-sig  hex HMAC-SHA256(secret, `response\n${nonce}\n${status}\n${sha256(body)}`)
 * so a client only trusts an address that proves it holds the same secret.
 * The secret itself never travels on the network.
 */

export const API_PREFIX = '/peer/v1/';
export const MAX_SKEW_MS = 5 * 60 * 1000;
export const BODY_LIMIT = 4 * 1024 * 1024;

export class PeerError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function newSecret() {
  return randomBytes(32).toString('base64url');
}

export function newNonce() {
  return randomBytes(16).toString('hex');
}

function bodyDigest(body) {
  return createHash('sha256').update(body).digest('hex');
}

export function hmac(secret, parts) {
  return createHmac('sha256', secret).update(parts.join('\n')).digest('hex');
}

export function sign(secret, ts, nonce, path, body) {
  return hmac(secret, [ts, nonce, path, bodyDigest(body)]);
}

export function signedHeaders(secret, path, body) {
  const ts = String(Date.now());
  const nonce = newNonce();
  return {
    'content-type': 'application/json',
    'x-peer-ts': ts,
    'x-peer-nonce': nonce,
    'x-peer-sig': sign(secret, ts, nonce, path, body),
  };
}

export function signResponse(secret, nonce, status, body) {
  return hmac(secret, ['response', nonce, String(status), bodyDigest(body)]);
}

export function verifyResponse(secret, nonce, status, body, sig) {
  return typeof sig === 'string' && safeEqualHex(sig, signResponse(secret, nonce, status, body));
}

export function safeEqualHex(a, b) {
  const left = Buffer.from(String(a), 'utf8');
  const right = Buffer.from(String(b), 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

/** Remembers nonces for the replay window so a captured request cannot be resent. */
export class NonceCache {
  constructor(windowMs = MAX_SKEW_MS * 2) {
    this.windowMs = windowMs;
    this.seen = new Map();
  }

  /** @returns false when the nonce was already used. */
  admit(nonce, now = Date.now()) {
    if (this.seen.size > 5000) {
      for (const [key, at] of this.seen) if (now - at > this.windowMs) this.seen.delete(key);
    }
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, now);
    return true;
  }
}

export function freshTimestamp(ts) {
  const skew = Math.abs(Date.now() - Number(ts));
  return Number.isFinite(skew) && skew <= MAX_SKEW_MS;
}

/** Verify a request's signature headers; throws PeerError on failure. */
export function verify(secret, headers, path, body, nonces) {
  const ts = headers['x-peer-ts'];
  const nonce = headers['x-peer-nonce'];
  const sig = headers['x-peer-sig'];
  if (typeof ts !== 'string' || typeof nonce !== 'string' || typeof sig !== 'string') {
    throw new PeerError('AUTH', 'missing signature headers', 401);
  }
  if (!freshTimestamp(ts)) {
    const skew = Math.abs(Date.now() - Number(ts));
    throw new PeerError('CLOCK', `clock skew too large (${Math.round(skew / 1000)}s); sync both machines' clocks`, 401);
  }
  if (!/^[0-9a-f]{16,64}$/.test(nonce)) throw new PeerError('AUTH', 'bad nonce', 401);
  if (!safeEqualHex(sig, sign(secret, ts, nonce, path, body))) {
    throw new PeerError('AUTH', 'bad signature (secret mismatch?)', 401);
  }
  if (!nonces.admit(nonce)) throw new PeerError('REPLAY', 'nonce reused', 401);
}

// ---- Network helpers -------------------------------------------------------

export function normalizeIp(raw) {
  const ip = String(raw ?? '');
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

export function buildAllowList(cidrs) {
  const list = new net.BlockList();
  for (const raw of String(cidrs ?? '').split(/[\s,]+/)) {
    if (!raw) continue;
    const [addr, bits] = raw.split('/');
    const type = net.isIPv6(addr) ? 'ipv6' : 'ipv4';
    try {
      if (bits === undefined) list.addAddress(addr, type);
      else list.addSubnet(addr, Number(bits), type);
    } catch {
      // Ignore malformed entries; the settings page shows the raw value.
    }
  }
  return {
    check(ip) {
      const address = normalizeIp(ip);
      return list.check(address, net.isIPv6(address) ? 'ipv6' : 'ipv4');
    },
  };
}

const SKIP_IFACE = /^(bridge|vmnet|vboxnet|utun|awdl|llw|docker|veth|vEthernet)|VMware|VirtualBox|Hyper-V|Loopback|Bluetooth/i;
const toInt = (ip) => ip.split('.').reduce((acc, part) => ((acc << 8) | Number(part)) >>> 0, 0);
const toIp = (n) => [24, 16, 8, 0].map((shift) => (n >>> shift) & 255).join('.');

/** Usable LAN IPv4 interfaces, best candidates first. */
export function lanInterfaces() {
  const rank = (ip) =>
    ip.startsWith('192.168.') ? 0 : ip.startsWith('10.') ? 1 : /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ? 2 : 3;
  const found = [];
  for (const [name, list] of Object.entries(networkInterfaces())) {
    if (SKIP_IFACE.test(name)) continue;
    for (const item of list ?? []) {
      if (item.family !== 'IPv4' || item.internal || item.address.startsWith('169.254.')) continue;
      const broadcast = toIp((toInt(item.address) | (~toInt(item.netmask) >>> 0)) >>> 0);
      found.push({ name, address: item.address, broadcast });
    }
  }
  return found.sort((a, b) => rank(a.address) - rank(b.address));
}

/** Split `host:port` / `host` hints. */
export function parseHint(hint) {
  const match = /^([0-9.]+)(?::(\d{1,5}))?$/.exec(String(hint ?? '').trim());
  if (!match) return undefined;
  return { host: match[1], port: match[2] === undefined ? undefined : Number(match[2]) };
}
