import net from 'node:net';
import { API_PREFIX, parseHint, PeerError, signedHeaders, verifyResponse } from './protocol.js';

/**
 * Signed HTTP client for one paired peer.
 *
 * The peer's port is random, so the cached address can go stale. A call tries
 * the cached address, then asks discovery, then the pairing hints that carry a
 * port, and finally the relay (relay.js), which reaches peers off this LAN by
 * P2P or through frps. A peer last reached only through the relay gets the
 * relay first. Only a response signed with the peer's secret counts as
 * reaching it, so a different program that took over an old port is skipped.
 */

const PROBE_TIMEOUT_MS = 4_000;
const CONNECT_TIMEOUT_MS = 2_000;
// The relay's xtcp visitor waits for a hole, then falls back to frps.
const RELAY_PROBE_TIMEOUT_MS = 12_000;

function tcpReachable(addr, timeoutMs) {
  const target = parseHint(addr);
  if (target?.port === undefined) return Promise.resolve(false);
  return new Promise((resolve) => {
    const socket = net.connect({ host: target.host, port: target.port });
    const done = (ok) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

export class PeerClient {
  constructor(state, peer, logger, discovery, relay) {
    this.state = state;
    this.peer = peer;
    this.logger = logger;
    this.discovery = discovery;
    this.relay = relay;
    /** How the last successful call got there: `lan`, `p2p`, or `relay`. */
    this.route = undefined;
  }

  /** One request to one address; resolves `{ reached, value | error }`. */
  async attempt(addr, op, args, { signal, timeoutMs }) {
    const path = `${API_PREFIX}${op}`;
    const body = JSON.stringify(args);
    const headers = signedHeaders(this.peer.secret, path, body);
    const controller = new AbortController();
    const onAbort = () => controller.abort(signal.reason);
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => controller.abort(new Error('timeout')), timeoutMs);
    try {
      let response;
      let text;
      try {
        response = await fetch(`http://${addr}${path}`, { method: 'POST', headers, body, signal: controller.signal });
        text = await response.text();
      } catch (error) {
        if (signal?.aborted) throw signal.reason ?? error;
        return { reached: false, error: `${addr}: ${error?.cause?.code ?? error?.message ?? error}` };
      }
      if (!verifyResponse(this.peer.secret, headers['x-peer-nonce'], response.status, text, response.headers.get('x-peer-resp-sig'))) {
        return { reached: false, error: `${addr}: not ${this.peer.name} (unsigned or wrong-key response, HTTP ${response.status})` };
      }
      const payload = JSON.parse(text);
      if (payload?.ok === true) return { reached: true, value: payload.value };
      const err = payload?.error ?? {};
      return { reached: true, error: new PeerError(err.code ?? `HTTP_${response.status}`, `${this.peer.name}: ${err.message ?? response.statusText}`, response.status) };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  /** Candidate addresses in order, discovering lazily after the cache fails. */
  async *candidates(signal) {
    const tried = new Set();
    const fresh = (addr) => addr !== undefined && !tried.has(addr) && (tried.add(addr), true);
    const relayed = async () => {
      if (this.relay === undefined) return undefined;
      await this.relay.prepare(this.peer, signal);
      return this.relay.addrOf(this.peer);
    };
    if (this.relay?.preferred(this.peer)) {
      const addr = await relayed();
      if (fresh(addr)) yield addr;
    }
    if (fresh(this.peer.addr)) yield this.peer.addr;
    if (this.discovery !== undefined) {
      for (const addr of await this.discovery.find(this.peer, { signal })) if (fresh(addr)) yield addr;
    }
    for (const hint of this.peer.hints ?? []) {
      if (parseHint(hint)?.port !== undefined && fresh(hint)) yield hint;
    }
    const addr = await relayed();
    if (fresh(addr)) yield addr;
  }

  async call(op, args = {}, { signal, timeoutMs = 40_000 } = {}) {
    const failures = [];
    for await (const addr of this.candidates(signal)) {
      const viaRelay = this.relay?.owns(addr) === true;
      // A host that went away can leave a TCP connect hanging for the whole
      // request timeout; fail fast so discovery gets its turn. The relay's
      // visitor always accepts, so it is judged by the request itself.
      if (!viaRelay && !(await tcpReachable(addr, CONNECT_TIMEOUT_MS))) {
        failures.push(`${addr}: no TCP answer`);
        continue;
      }
      const result = await this.attempt(addr, op, args, { signal, timeoutMs: viaRelay ? Math.max(timeoutMs, RELAY_PROBE_TIMEOUT_MS) : timeoutMs });
      if (!result.reached) {
        failures.push(viaRelay ? `relay ${this.state.relay?.server ?? ''}: ${result.error.replace(`${addr}: `, '')}` : result.error);
        continue;
      }
      if (viaRelay) {
        this.relay.noteRelay(this.peer);
        this.route = this.relay.routeOf(this.peer);
      } else {
        this.relay?.noteLan(this.peer);
        this.route = 'lan';
        if (addr !== this.peer.addr) {
          this.state.rememberAddr(this.peer.name, addr);
          this.peer.addr = addr;
        }
      }
      if (result.error) throw result.error;
      return result.value;
    }
    const detail = failures.length ? failures.join('; ') : 'no address known and discovery got no answer';
    const hint = this.relay?.status().configured
      ? 'Check that its DSH is running with peer-link enabled and logged in to the same relay.'
      : 'Check that its DSH is running with peer-link enabled, both machines share a LAN (or set up a relay in the peer-link settings), and its firewall allows DSH.';
    throw new PeerError('UNREACHABLE', `${this.peer.name} unreachable (${detail}). ${hint}`, 502);
  }

  /** Quick reachability probe used by `peers` listings. */
  async probe() {
    try {
      const info = await this.call('info', {}, { timeoutMs: PROBE_TIMEOUT_MS });
      return { online: true, info, route: this.route };
    } catch (error) {
      return { online: false, error: error.message };
    }
  }
}
