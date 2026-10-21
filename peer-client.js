import net from 'node:net';
import { API_PREFIX, parseHint, PeerError, signedHeaders, verifyResponse } from './protocol.js';

/**
 * Signed HTTP client for one paired peer.
 *
 * The peer's port is random, so the cached address can go stale. A call tries
 * the cached address, then asks discovery, then the pairing hints that carry a
 * port. Only a response signed with the peer's secret counts as reaching it,
 * so a different program that took over an old port is skipped.
 */

const PROBE_TIMEOUT_MS = 4_000;
const CONNECT_TIMEOUT_MS = 2_000;

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
  constructor(state, peer, logger, discovery) {
    this.state = state;
    this.peer = peer;
    this.logger = logger;
    this.discovery = discovery;
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
    if (fresh(this.peer.addr)) yield this.peer.addr;
    if (this.discovery !== undefined) {
      for (const addr of await this.discovery.find(this.peer, { signal })) if (fresh(addr)) yield addr;
    }
    for (const hint of this.peer.hints ?? []) {
      if (parseHint(hint)?.port !== undefined && fresh(hint)) yield hint;
    }
  }

  async call(op, args = {}, { signal, timeoutMs = 40_000 } = {}) {
    const failures = [];
    for await (const addr of this.candidates(signal)) {
      // A host that went away can leave a TCP connect hanging for the whole
      // request timeout; fail fast so discovery gets its turn.
      if (!(await tcpReachable(addr, CONNECT_TIMEOUT_MS))) {
        failures.push(`${addr}: no TCP answer`);
        continue;
      }
      const result = await this.attempt(addr, op, args, { signal, timeoutMs });
      if (!result.reached) {
        failures.push(result.error);
        continue;
      }
      if (addr !== this.peer.addr) {
        this.state.rememberAddr(this.peer.name, addr);
        this.peer.addr = addr;
      }
      if (result.error) throw result.error;
      return result.value;
    }
    const detail = failures.length ? failures.join('; ') : 'no address known and discovery got no answer';
    throw new PeerError(
      'UNREACHABLE',
      `${this.peer.name} unreachable (${detail}). Check that its DSH is running with peer-link enabled, both machines share a LAN, and its firewall allows DSH.`,
      502,
    );
  }

  /** Quick reachability probe used by `peers` listings. */
  async probe() {
    try {
      const info = await this.call('info', {}, { timeoutMs: PROBE_TIMEOUT_MS });
      return { online: true, info };
    } catch (error) {
      return { online: false, error: error.message };
    }
  }
}
