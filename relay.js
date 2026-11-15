import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { join } from 'node:path';
import { keyIdOf } from './discovery.js';
import { ensureFrpc } from './frpc-bin.js';
import { hmac } from './protocol.js';
import { STATE_DIR, writePrivate } from './state.js';

/**
 * Reaches paired peers that are not on this LAN through an frps server both
 * machines log in to (the "relay", set on one machine and carried to the
 * other in the pairing code).
 *
 * One frpc child per machine:
 *  - publishes this machine's peer-link listener as an xtcp proxy (P2P hole
 *    punching) and an stcp proxy (relayed by frps). Both are named from this
 *    machine's key id and keyed by a secret derived from its peer secret, so
 *    only paired machines can visit them;
 *  - for every paired peer, an xtcp visitor on a loopback port that hands a
 *    connection to an stcp visitor when no hole opens within FALLBACK_MS.
 *    frpc keeps retrying the hole in the background.
 * PeerClient tries that loopback port after the LAN addresses. The signed
 * protocol on top is unchanged, so frps can neither forge nor replay calls.
 *
 * Peer changes go through frpc's admin API reload, which keeps the running
 * proxies and their connections, including the request that caused the change.
 */

const CONF_FILE = join(STATE_DIR, 'frpc.toml');
const RUN_FILE = join(STATE_DIR, 'relay-run.json');
const FALLBACK_MS = 1500;
const READY_TIMEOUT_MS = 20_000;
const MAX_RESTARTS = 5;
const RESTART_DELAY_MS = 5_000;

export const proxyName = (secret) => `plk-${keyIdOf(secret)}`;
const visitorName = (secret) => `plk-v-${keyIdOf(secret)}`;
const tunnelKey = (secret) => hmac(secret, ['peer-link-relay']).slice(0, 32);
const q = (value) => JSON.stringify(String(value));

function splitServer(server) {
  const index = server.lastIndexOf(':');
  return [server.slice(0, index).replace(/^\[|\]$/g, ''), Number(server.slice(index + 1))];
}

/** frpc TOML for this machine's proxies and one visitor pair per peer. */
export function buildToml({ relay, admin, ownSecret, localPort, visitors }) {
  const [host, port] = splitServer(relay.server);
  const lines = [
    `serverAddr = ${q(host)}`,
    `serverPort = ${port}`,
    'loginFailExit = false',
    `transport.tls.enable = ${relay.tls ? 'true' : 'false'}`,
    'log.to = "console"',
    'log.level = "info"',
    'log.disablePrintColor = true',
    'webServer.addr = "127.0.0.1"',
    `webServer.port = ${admin.port}`,
    `webServer.user = ${q(admin.user)}`,
    `webServer.password = ${q(admin.password)}`,
  ];
  if (relay.user) lines.push(`user = ${q(relay.user)}`);
  if (relay.token) lines.push('auth.method = "token"', `auth.token = ${q(relay.token)}`);
  if (localPort !== undefined) {
    const name = proxyName(ownSecret);
    const key = tunnelKey(ownSecret);
    for (const [type, suffix] of [['xtcp', ''], ['stcp', '-s']]) {
      lines.push('', '[[proxies]]', `name = ${q(name + suffix)}`, `type = "${type}"`, `secretKey = ${q(key)}`);
      lines.push('localIP = "127.0.0.1"', `localPort = ${localPort}`, 'transport.useEncryption = true');
    }
  }
  for (const { secret, port: bindPort } of visitors) {
    const name = visitorName(secret);
    const server = proxyName(secret);
    const key = tunnelKey(secret);
    lines.push('', '[[visitors]]', `name = ${q(name)}`, 'type = "xtcp"', `serverName = ${q(server)}`, `secretKey = ${q(key)}`);
    lines.push('bindAddr = "127.0.0.1"', `bindPort = ${bindPort}`, 'keepTunnelOpen = true');
    lines.push(`fallbackTo = ${q(`${name}-s`)}`, `fallbackTimeoutMs = ${FALLBACK_MS}`, 'transport.useEncryption = true');
    lines.push('', '[[visitors]]', `name = ${q(`${name}-s`)}`, 'type = "stcp"', `serverName = ${q(`${server}-s`)}`, `secretKey = ${q(key)}`);
    lines.push('bindPort = -1', 'transport.useEncryption = true');
  }
  return `${lines.join('\n')}\n`;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function connects(port, timeoutMs = 500) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const done = (ok) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

function adminCall(admin, method, path) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port: admin.port,
        method,
        path,
        auth: `${admin.user}:${admin.password}`,
        timeout: 5_000,
      },
      (response) => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => (text += chunk));
        response.on('end', () => (response.statusCode === 200 ? resolve(text) : reject(new Error(`frpc ${path}: HTTP ${response.statusCode} ${text.trim()}`))));
      },
    );
    request.on('timeout', () => request.destroy(new Error(`frpc ${path}: no answer`)));
    request.on('error', reject);
    request.end();
  });
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class Relay {
  /**
   * @param options.state - PeerState; supplies the relay settings, this
   *   machine's secret, and the peers.
   * @param options.localPort - the peer-link listener port, or undefined when
   *   this machine does not listen (then only visitors are configured).
   * @param options.enabled - the `relay` config switch.
   */
  constructor({ state, logger, localPort, enabled }) {
    this.state = state;
    this.logger = logger;
    this.localPort = localPort;
    this.enabled = enabled;
    this.child = undefined;
    this.admin = undefined;
    this.serverKey = '';
    this.visitorKey = '';
    this.ports = new Map();
    this.listening = new Set();
    this.phase = 'off';
    this.error = undefined;
    this.p2p = new Map();
    this.viaRelayAt = new Map();
    this.restarts = 0;
    this.lastServerKey = '';
    this.lastWarning = undefined;
    this.timer = undefined;
    this.waiters = new Set();
    this.queue = Promise.resolve();
    this.closed = false;
  }

  /** Settings that need a fresh frpc when they change. */
  serverConfig() {
    const relay = this.enabled() ? this.state.relay : undefined;
    if (relay === undefined) return undefined;
    return { relay, ownSecret: this.state.secret, localPort: this.localPort() };
  }

  /** Re-apply settings and peers; serialized, safe to call often. */
  sync() {
    this.queue = this.queue
      .then(() => this.apply())
      .catch((error) => {
        this.phase = 'error';
        this.error = error.message;
        this.logger.warn(`peer-link: relay: ${error.message}`);
        this.notify();
      });
    return this.queue;
  }

  async apply() {
    if (this.closed) return;
    const server = this.serverConfig();
    const serverKey = server === undefined ? '' : JSON.stringify(server);
    if (serverKey === '') {
      if (this.child !== undefined) this.logger.info('peer-link: relay stopped');
      this.stop();
      this.serverKey = '';
      this.phase = 'off';
      this.error = undefined;
      this.notify();
      return;
    }
    const peers = this.state.peers();
    for (const peer of peers) {
      const id = keyIdOf(peer.secret);
      if (!this.ports.has(id)) this.ports.set(id, await freePort());
    }
    const visitors = peers.map((peer) => ({ secret: peer.secret, port: this.ports.get(keyIdOf(peer.secret)) }));
    const visitorKey = JSON.stringify(visitors);
    if (serverKey === this.serverKey && this.child !== undefined) {
      if (visitorKey === this.visitorKey) return;
      this.writeConfig(server, visitors);
      await adminCall(this.admin, 'GET', '/api/reload');
      this.visitorKey = visitorKey;
      this.logger.info(`peer-link: relay reloaded (${visitors.length} peer${visitors.length === 1 ? '' : 's'})`);
      return;
    }
    this.stop();
    // A restart after a crash keeps counting; new settings get a fresh budget.
    if (serverKey !== this.lastServerKey) this.restarts = 0;
    this.lastServerKey = serverKey;
    this.serverKey = serverKey;
    this.visitorKey = visitorKey;
    this.phase = 'starting';
    this.error = undefined;
    this.notify();
    const binary = await ensureFrpc({ onDownload: () => this.logger.info('peer-link: relay: downloading frpc…') });
    if (this.closed || this.serverKey !== serverKey) return;
    await this.stopOrphan();
    this.admin = { port: await freePort(), user: 'peer-link', password: randomBytes(18).toString('base64url') };
    this.writeConfig(server, visitors);
    writePrivate(RUN_FILE, `${JSON.stringify({ admin: this.admin })}\n`);
    this.spawn(binary);
  }

  writeConfig(server, visitors) {
    writePrivate(CONF_FILE, buildToml({ ...server, admin: this.admin, visitors }));
  }

  /** An frpc left behind by a crashed DSH still holds the proxy names on frps. */
  async stopOrphan() {
    let previous;
    try {
      previous = JSON.parse(readFileSync(RUN_FILE, 'utf8')).admin;
    } catch {
      return;
    }
    if (!previous?.port) return;
    try {
      await adminCall(previous, 'POST', '/api/stop');
      await wait(800);
    } catch {
      // Nothing listening there any more.
    }
  }

  spawn(binary) {
    const child = spawn(binary, ['-c', CONF_FILE], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    this.child = child;
    const token = this.state.relay?.token;
    const pump = (stream) => {
      let pending = '';
      stream.setEncoding('utf8');
      stream.on('data', (chunk) => {
        pending += chunk;
        const lines = pending.split('\n');
        pending = lines.pop() ?? '';
        for (const line of lines) if (line.trim()) this.onLog(token ? line.split(token).join('***') : line);
      });
    };
    pump(child.stdout);
    pump(child.stderr);
    child.on('error', (error) => {
      this.phase = 'error';
      this.error = `cannot start frpc: ${error.message}`;
      this.notify();
    });
    child.on('exit', (code, signal) => {
      if (this.child !== child) return;
      this.child = undefined;
      this.phase = 'error';
      this.error = this.error ?? `frpc exited (${code ?? signal})`;
      this.notify();
      if (this.closed) return;
      if (this.restarts >= MAX_RESTARTS) {
        this.logger.warn(`peer-link: relay: frpc keeps exiting (${this.error}); change the relay settings to retry`);
        return;
      }
      this.restarts += 1;
      this.timer = setTimeout(() => {
        this.timer = undefined;
        this.serverKey = '';
        this.sync();
      }, RESTART_DELAY_MS);
      this.timer.unref?.();
    });
  }

  onLog(line) {
    const text = line.replace(/^\S+ \S+ \[\w\] \[[^\]]+\] /, '');
    if (/login to server success/.test(line)) {
      if (this.phase !== 'online') this.logger.info(`peer-link: relay online (${this.state.relay?.server})`);
      this.phase = 'online';
      this.error = undefined;
      this.restarts = 0;
      this.notify();
      return;
    }
    const hole = /\[(plk-v-[0-9a-f]+)\] establishing nat hole connection successful/.exec(line);
    if (hole) {
      this.p2p.set(hole[1], true);
      return;
    }
    const dropped = /\[(plk-v-[0-9a-f]+)\] (open tunnel error|keepTunnelOpenWorker get tunnel connection error)/.exec(line);
    if (dropped) {
      this.p2p.set(dropped[1], false);
      return;
    }
    // Failed punches and offline peers are routine; only frpc's own trouble is worth a warning.
    if (!/\[[EW]\]/.test(line) || /\[plk-v-/.test(line)) return;
    if (/login|connect to server|authoriz/i.test(text)) {
      this.phase = 'error';
      this.error = text;
      this.notify();
    }
    // frpc retries a lost server every few seconds; say it once.
    if (text === this.lastWarning) return;
    this.lastWarning = text;
    this.logger.warn(`peer-link: frpc: ${text}`);
  }

  notify() {
    for (const waiter of this.waiters) waiter();
  }

  /** Resolves once frpc is logged in (or right away when the relay is off or broken). */
  whenReady(timeoutMs = READY_TIMEOUT_MS, signal) {
    if (this.phase !== 'starting') return this.queue.then(() => undefined);
    return new Promise((resolve) => {
      const done = () => {
        if (this.phase === 'starting' && !signal?.aborted) return;
        clearTimeout(timer);
        this.waiters.delete(done);
        signal?.removeEventListener('abort', done);
        resolve();
      };
      const timer = setTimeout(() => {
        this.waiters.delete(done);
        resolve();
      }, timeoutMs);
      this.waiters.add(done);
      signal?.addEventListener('abort', done, { once: true });
    });
  }

  /** Apply pending peer changes, then wait until the peer's visitor listens. */
  async prepare(peer, signal) {
    // A first start may be downloading frpc; do not hold a call for that long.
    await Promise.race([this.sync(), wait(READY_TIMEOUT_MS)]);
    await this.whenReady(READY_TIMEOUT_MS, signal);
    const port = this.ports.get(keyIdOf(peer.secret));
    if (this.phase !== 'online' || port === undefined || this.listening.has(port)) return;
    // A visitor added by a reload starts listening a moment later.
    for (let i = 0; i < 50 && !signal?.aborted; i++) {
      if (await connects(port)) {
        this.listening.add(port);
        return;
      }
      await wait(100);
    }
  }

  /** Loopback address of the visitor for a peer, when the relay is up. */
  addrOf(peer) {
    if (this.phase !== 'online') return undefined;
    const port = this.ports.get(keyIdOf(peer.secret));
    return port === undefined ? undefined : `127.0.0.1:${port}`;
  }

  /** Whether `addr` is this relay's visitor address. */
  owns(addr) {
    return [...this.ports.values()].some((port) => addr === `127.0.0.1:${port}`);
  }

  /** The last call reached the peer through the relay; try it first next time. */
  noteRelay(peer) {
    this.viaRelayAt.set(peer.name, Date.now());
  }

  noteLan(peer) {
    this.viaRelayAt.delete(peer.name);
  }

  /** Relay first while it worked more recently than the peer was last seen on the LAN. */
  preferred(peer) {
    const at = this.viaRelayAt.get(peer.name);
    return at !== undefined && at > (peer.seenAt ?? 0);
  }

  /** `p2p` when a hole is open to the peer, else `relay`. */
  routeOf(peer) {
    return this.p2p.get(visitorName(peer.secret)) === true ? 'p2p' : 'relay';
  }

  status() {
    const relay = this.state.relay;
    return {
      configured: relay !== undefined,
      enabled: this.enabled(),
      server: relay?.server ?? null,
      tls: relay?.tls ?? true,
      user: relay?.user ?? '',
      hasToken: Boolean(relay?.token),
      phase: this.phase,
      error: this.error ?? null,
    };
  }

  stop() {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    const child = this.child;
    this.child = undefined;
    this.p2p.clear();
    this.listening.clear();
    if (child !== undefined) {
      child.removeAllListeners('exit');
      child.kill();
    }
  }

  close() {
    this.closed = true;
    this.stop();
    this.phase = 'off';
    this.notify();
  }
}
