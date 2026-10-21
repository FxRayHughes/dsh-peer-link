import dgram from 'node:dgram';
import {
  buildAllowList,
  freshTimestamp,
  hmac,
  lanInterfaces,
  newNonce,
  NonceCache,
  normalizeIp,
  parseHint,
  safeEqualHex,
} from './protocol.js';

/**
 * LAN discovery, so the HTTP listener can use any free port.
 *
 * Datagrams are JSON `{ app: 'dsh-peer-link', v: 1, t, ... }` sent to the
 * multicast group, every interface's broadcast address, and the last known
 * address of each peer, all on one well-known UDP port. That port is bound
 * shared (SO_REUSEADDR), so it never blocks another program.
 *
 *   q  query    { k, n, ts, s=HMAC(target, query k n ts) }       "who holds key k?"
 *   r  reply    { n, port, ts, s=HMAC(own, reply n port ts) }     unicast to the asker
 *   a  announce { k, n, port, ts, s=HMAC(own, announce k port ts n) }  periodic / on change
 *
 * `k` is a short id derived from the target's pairing secret; only holders of
 * that secret can build a valid query or verify a reply, so an outsider can
 * neither learn the port nor redirect a peer elsewhere.
 */

export const DISCOVERY_GROUP = '239.255.77.88';
export const DISCOVERY_PORT = 47788;
const ANNOUNCE_EVERY_MS = 60_000;
const RESEND_AT_MS = [0, 500, 1300];

export function keyIdOf(secret) {
  return hmac(secret, ['peer-link-key-id']).slice(0, 16);
}

function encode(message) {
  return Buffer.from(JSON.stringify({ app: 'dsh-peer-link', v: 1, ...message }));
}

function decode(buffer) {
  try {
    const message = JSON.parse(buffer.toString('utf8'));
    return message?.app === 'dsh-peer-link' && message.v === 1 ? message : undefined;
  } catch {
    return undefined;
  }
}

function bindSocket(socket, port) {
  return new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(port, () => {
      socket.off('error', reject);
      resolve();
    });
  });
}

function sendTo(socket, buffer, port, host) {
  return new Promise((resolve) => {
    try {
      socket.send(buffer, port, host, () => resolve());
    } catch {
      resolve();
    }
  });
}

export class Discovery {
  constructor({ state, logger, port = DISCOVERY_PORT, allowCidrs }) {
    this.state = state;
    this.logger = logger;
    this.port = port;
    this.allow = buildAllowList(allowCidrs);
    this.httpPort = undefined;
    this.pending = new Map();
    this.announces = new NonceCache();
    this.shared = undefined;
    this.sender = undefined;
  }

  get bound() {
    return this.shared !== undefined;
  }

  async start() {
    const sender = dgram.createSocket({ type: 'udp4' });
    sender.on('message', (buffer, rinfo) => this.onReply(buffer, rinfo));
    sender.on('error', (error) => this.logger.warn(`peer-link: discovery sender: ${error.message}`));
    await bindSocket(sender, 0);
    sender.setBroadcast(true);
    sender.setMulticastTTL(1);
    this.sender = sender;

    const shared = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    shared.on('message', (buffer, rinfo) => this.onShared(buffer, rinfo));
    shared.on('error', (error) => this.logger.warn(`peer-link: discovery: ${error.message}`));
    try {
      await bindSocket(shared, this.port);
      if (this.port === 0) this.port = shared.address().port;
      shared.setBroadcast(true);
      shared.setMulticastTTL(1);
      for (const iface of lanInterfaces()) {
        try {
          shared.addMembership(DISCOVERY_GROUP, iface.address);
        } catch {
          // Interfaces without multicast still receive broadcasts and unicast.
        }
      }
      this.shared = shared;
    } catch (error) {
      shared.close();
      this.logger.warn(`peer-link: discovery port ${this.port}/udp unavailable (${error.message}); peers can still reach this machine at its last known address`);
    }

    this.timer = setInterval(() => this.announce(), ANNOUNCE_EVERY_MS);
    this.timer.unref?.();
  }

  close() {
    clearInterval(this.timer);
    for (const pending of this.pending.values()) pending.finish();
    for (const socket of [this.shared, this.sender]) {
      try {
        socket?.close();
      } catch {
        // Already closed.
      }
    }
    this.shared = undefined;
    this.sender = undefined;
  }

  /** The HTTP port this machine answers queries with; undefined while not listening. */
  setHttpPort(port) {
    this.httpPort = port;
  }

  /** Datagram fan-out: multicast and broadcast on every LAN interface, plus direct unicast hosts. */
  async fanOut(buffer, unicast = []) {
    if (this.sender === undefined) return;
    for (const iface of lanInterfaces()) {
      try {
        this.sender.setMulticastInterface(iface.address);
        await sendTo(this.sender, buffer, this.port, DISCOVERY_GROUP);
      } catch {
        // Fall through to broadcast.
      }
      await sendTo(this.sender, buffer, this.port, iface.broadcast);
    }
    await sendTo(this.sender, buffer, this.port, '255.255.255.255');
    const seen = new Set();
    for (const target of unicast) {
      const key = `${target.host}:${target.port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      await sendTo(this.sender, buffer, target.port, target.host);
    }
  }

  /** Tell paired peers where this machine's HTTP listener is now. */
  async announce() {
    if (this.httpPort === undefined || this.sender === undefined) return;
    const secret = this.state.secret;
    const k = keyIdOf(secret);
    const n = newNonce();
    const ts = String(Date.now());
    const port = String(this.httpPort);
    const buffer = encode({ t: 'a', k, n, ts, port: this.httpPort, s: hmac(secret, ['announce', k, port, ts, n]) });
    await this.fanOut(buffer, this.knownHosts(this.state.peers()));
  }

  knownHosts(peers) {
    const hosts = [];
    for (const peer of peers) {
      for (const hint of [peer.addr, ...(peer.hints ?? [])]) {
        const parsed = parseHint(hint);
        if (parsed) hosts.push({ host: parsed.host, port: peer.discoveryPort ?? this.port });
      }
    }
    return hosts;
  }

  /**
   * Ask the LAN where `peer` listens.
   * @returns verified `host:port` addresses (empty when nobody answered in time).
   */
  find(peer, { timeoutMs = 2500, signal } = {}) {
    if (this.sender === undefined) return Promise.resolve([]);
    const k = keyIdOf(peer.secret);
    const n = newNonce();
    const ts = String(Date.now());
    const buffer = encode({ t: 'q', k, n, ts, s: hmac(peer.secret, ['query', k, n, ts]) });
    const unicast = this.knownHosts([peer]);
    return new Promise((resolve) => {
      const timers = [];
      const found = [];
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        for (const timer of timers) clearTimeout(timer);
        signal?.removeEventListener('abort', finish);
        this.pending.delete(n);
        resolve(found);
      };
      this.pending.set(n, {
        secret: peer.secret,
        finish,
        accept: (address) => {
          if (!found.includes(address)) found.push(address);
          // Let simultaneous answers from other interfaces arrive, then stop.
          timers.push(setTimeout(finish, 150));
        },
      });
      signal?.addEventListener('abort', finish, { once: true });
      for (const at of RESEND_AT_MS) timers.push(setTimeout(() => !done && this.fanOut(buffer, unicast), at));
      timers.push(setTimeout(finish, timeoutMs));
    });
  }

  onReply(buffer, rinfo) {
    const message = decode(buffer);
    if (message?.t !== 'r') return;
    const pending = this.pending.get(message.n);
    if (pending === undefined || !freshTimestamp(message.ts)) return;
    const port = Number(message.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return;
    const expected = hmac(pending.secret, ['reply', message.n, String(port), String(message.ts)]);
    if (!safeEqualHex(String(message.s ?? ''), expected)) return;
    pending.accept(`${normalizeIp(rinfo.address)}:${port}`);
  }

  onShared(buffer, rinfo) {
    if (!this.allow.check(rinfo.address)) return;
    const message = decode(buffer);
    if (message === undefined || !freshTimestamp(message.ts)) return;
    if (message.t === 'q') this.answer(message, rinfo);
    else if (message.t === 'a') this.learn(message, rinfo);
  }

  answer(message, rinfo) {
    if (this.httpPort === undefined || this.shared === undefined) return;
    const secret = this.state.secret;
    if (message.k !== keyIdOf(secret)) return;
    if (!safeEqualHex(String(message.s ?? ''), hmac(secret, ['query', message.k, String(message.n), String(message.ts)]))) return;
    const ts = String(Date.now());
    const port = String(this.httpPort);
    const reply = encode({ t: 'r', n: message.n, ts, port: this.httpPort, s: hmac(secret, ['reply', String(message.n), port, ts]) });
    this.shared.send(reply, rinfo.port, rinfo.address, () => undefined);
  }

  learn(message, rinfo) {
    const port = Number(message.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return;
    for (const peer of this.state.peers()) {
      if (keyIdOf(peer.secret) !== message.k) continue;
      const expected = hmac(peer.secret, ['announce', message.k, String(port), String(message.ts), String(message.n)]);
      if (!safeEqualHex(String(message.s ?? ''), expected)) continue;
      if (!this.announces.admit(`${peer.name}:${message.n}`)) return;
      this.state.rememberAddr(peer.name, `${normalizeIp(rinfo.address)}:${port}`);
    }
  }
}
