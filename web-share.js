import http from 'node:http';
import net from 'node:net';
import { createHmac, randomBytes } from 'node:crypto';
import { normalizeIp, PeerError, safeEqualHex } from './protocol.js';

/**
 * Lets a paired peer's user open this machine's DSH Web page from the LAN.
 *
 * The peer-link listener answers `/peer/*` itself and hands every other path
 * here. This relay forwards to the local DSH listener with `Host`, `Origin`,
 * and `Referer` rewritten to the loopback authority, so DSH's trust fence and
 * its authority-bound login cookie keep working without widening
 * `trustedHosts`.
 *
 * Access takes two keys:
 *   1. A one-time ticket, which a paired peer obtains over the signed protocol
 *      (`webTicket`) and puts in the link it opens. Tickets expire in a minute.
 *   2. The gate cookie set when the ticket is redeemed: an HMAC of its expiry
 *      and the browser's address under a key derived from this machine's peer
 *      secret, so a copy sniffed on the LAN is useless from another address.
 *      Without it every request is refused before DSH sees it.
 * DSH's own launch token is exchanged here on the server, so it never reaches
 * the browser or its history.
 *
 * Redirect chains that start on another site do not carry SameSite=Strict
 * cookies, so the entry answers with a small page that continues with a
 * same-origin navigation instead of a 30x.
 */

export const ENTER_PATH = '/__peer-link/enter';
export const SESSION_HASH = 'peer-link-session';
const GATE_COOKIE = 'peer_link_gate';
const TICKET_TTL_MS = 60_000;
const GATE_TTL_S = 12 * 3600;
const RECOVER_WINDOW_MS = 10_000;
// Served by DSH without a login, and fetched by browsers without cookies.
const PUBLIC_PATHS = new Set(['/manifest.webmanifest']);

const escapeHtml = (text) =>
  String(text).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function readCookie(header, name) {
  if (typeof header !== 'string') return undefined;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index >= 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

function wantsHtml(req) {
  return req.method === 'GET' && String(req.headers.accept ?? '').includes('text/html');
}

/** Same-origin hop so the cookies just set travel with the next request. */
function continuePage(location, cookies = []) {
  const target = JSON.stringify(location).replace(/</g, '\\u003c');
  return {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      ...(cookies.length ? { 'set-cookie': cookies } : {}),
    },
    body: `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>正在打开 DSH…</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:-apple-system,system-ui,sans-serif;color:#8a91a0}</style>
</head><body>正在打开 DSH…<script>location.replace(${target});</script>
<noscript><a href="${escapeHtml(location)}">继续</a></noscript></body></html>`,
  };
}

function messagePage(status, text) {
  return {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    body: `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DSH 互联</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box;font-family:-apple-system,system-ui,sans-serif;color:#555;text-align:center;line-height:1.6}</style>
</head><body><p>${escapeHtml(text)}</p></body></html>`,
  };
}

function send(res, page) {
  res.writeHead(page.status ?? 200, page.headers);
  res.end(page.body);
}

/** Request headers as the local DSH listener should see them. */
function rewriteHeaders(headers, upstream) {
  const out = { ...headers, host: upstream.host };
  if (out.origin) out.origin = upstream.origin;
  if (out.referer) {
    try {
      const ref = new URL(out.referer);
      out.referer = upstream.origin + ref.pathname + ref.search;
    } catch {
      delete out.referer;
    }
  }
  if (typeof out.cookie === 'string') {
    const kept = out.cookie
      .split(';')
      .filter((part) => part.split('=')[0].trim() !== GATE_COOKIE)
      .join(';')
      .trim();
    if (kept) out.cookie = kept;
    else delete out.cookie;
  }
  return out;
}

export class WebShare {
  /**
   * @param options.enabled - whether sharing is switched on right now.
   * @param options.upstream - `{ origin, tokenPath }` of the local DSH Web
   *   listener (`tokenPath` is `/?token=…`), or undefined while it is not up.
   * @param options.secret - this machine's peer secret, read on use so a
   *   re-generated secret invalidates old gate cookies.
   */
  constructor({ enabled, upstream, secret, logger }) {
    this.enabled = enabled;
    this.upstream = upstream;
    this.secret = secret;
    this.logger = logger;
    this.tickets = new Map();
    this.recovered = new Map();
    this.sockets = new Set();
  }

  gateKey() {
    return createHmac('sha256', this.secret()).update('peer-link web gate').digest();
  }

  gateValue(expiresAt, address) {
    return `${expiresAt}.${createHmac('sha256', this.gateKey()).update(`${expiresAt}\n${address}`).digest('hex')}`;
  }

  gateOk(req) {
    const value = readCookie(req.headers.cookie, GATE_COOKIE);
    if (value === undefined) return false;
    const expiresAt = Number(value.split('.')[0]);
    if (!Number.isSafeInteger(expiresAt) || expiresAt < Date.now()) return false;
    return safeEqualHex(value, this.gateValue(expiresAt, normalizeIp(req.socket.remoteAddress)));
  }

  /** Whether a paired peer can open this machine's Web page right now. */
  available() {
    return this.enabled() && this.upstream() !== undefined;
  }

  /** Called through the signed protocol only, so the caller is a paired peer. */
  issue(sessionId) {
    if (!this.enabled()) throw new PeerError('FORBIDDEN', `this machine does not share its web page (turn on "share web page" in its peer-link settings)`, 403);
    if (this.upstream() === undefined) throw new PeerError('UNAVAILABLE', 'the DSH web page is not running on this machine', 503);
    const now = Date.now();
    for (const [key, ticket] of this.tickets) if (ticket.expiresAt < now) this.tickets.delete(key);
    const ticket = randomBytes(24).toString('base64url');
    const session = typeof sessionId === 'string' && /^[\w.:-]{1,200}$/.test(sessionId) ? sessionId : undefined;
    this.tickets.set(ticket, { expiresAt: now + TICKET_TTL_MS, session });
    return { ticket, path: `${ENTER_PATH}?ticket=${ticket}`, expiresIn: TICKET_TTL_MS / 1000 };
  }

  /** Exchange DSH's launch token on the server; resolves the cookies it mints. */
  exchange(upstream) {
    return new Promise((resolve, reject) => {
      const target = new URL(upstream.origin);
      const request = http.request(
        {
          host: target.hostname,
          port: Number(target.port || 80),
          method: 'GET',
          path: upstream.tokenPath,
          headers: { host: target.host, accept: 'text/html' },
          timeout: 8_000,
        },
        (response) => {
          response.resume();
          const cookies = response.headers['set-cookie'] ?? [];
          if (response.statusCode === 303 && cookies.length > 0) resolve(cookies);
          else reject(new Error(`DSH refused the launch token (HTTP ${response.statusCode})`));
        },
      );
      request.on('timeout', () => request.destroy(new Error('DSH did not answer')));
      request.on('error', reject);
      request.end();
    });
  }

  gateCookie(req) {
    const expiresAt = Date.now() + GATE_TTL_S * 1000;
    const value = this.gateValue(expiresAt, normalizeIp(req.socket.remoteAddress));
    return `${GATE_COOKIE}=${value}; Path=/; Max-Age=${GATE_TTL_S}; HttpOnly; SameSite=Strict`;
  }

  async enter(req, res, url) {
    const key = url.searchParams.get('ticket') ?? '';
    const ticket = this.tickets.get(key);
    this.tickets.delete(key);
    if (ticket === undefined || ticket.expiresAt < Date.now()) {
      send(res, messagePage(403, '链接已失效。请回到原来的 DSH 再点一次「打开网页」，每个链接只能用一次，并在一分钟内有效。'));
      return;
    }
    const upstream = this.upstream();
    if (upstream === undefined) {
      send(res, messagePage(503, '这台电脑上的 DSH 网页界面没有运行。'));
      return;
    }
    let cookies;
    try {
      cookies = await this.exchange(upstream);
    } catch (error) {
      this.logger.warn(`peer-link: web entry failed: ${error.message}`);
      send(res, messagePage(502, `无法登录这台电脑上的 DSH：${error.message}`));
      return;
    }
    const target = ticket.session ? `/#${SESSION_HASH}=${encodeURIComponent(ticket.session)}` : '/';
    send(res, continuePage(target, [this.gateCookie(req), ...cookies]));
  }

  /** Browser requests from other sites are refused before any rewriting. */
  crossSite(req) {
    if (req.headers['sec-fetch-site'] === 'cross-site') return true;
    const origin = req.headers.origin;
    if (typeof origin !== 'string' || origin === 'null') return origin === 'null';
    try {
      return new URL(origin).host !== req.headers.host;
    } catch {
      return true;
    }
  }

  /** Handle one non-protocol request on the peer-link listener. */
  async handle(req, res, url) {
    if (!this.enabled()) {
      send(res, messagePage(404, '这台电脑没有开启「共享网页界面」。'));
      return;
    }
    if (url.pathname === ENTER_PATH) {
      if (req.method !== 'GET') {
        res.writeHead(405, { allow: 'GET' });
        res.end();
        return;
      }
      await this.enter(req, res, url);
      return;
    }
    if (PUBLIC_PATHS.has(url.pathname) && req.method === 'GET') {
      const upstream = this.upstream();
      if (upstream !== undefined) this.proxy(req, res, upstream);
      else send(res, messagePage(503, '这台电脑上的 DSH 网页界面没有运行。'));
      return;
    }
    if (!this.gateOk(req)) {
      if (wantsHtml(req)) send(res, messagePage(401, '请从已配对的 DSH 打开：设置 → 插件 → DSH 互联，或侧边栏底部的「对端设备」。'));
      else {
        res.writeHead(401, { 'cache-control': 'no-store' });
        res.end();
      }
      return;
    }
    if (this.crossSite(req) && req.headers['sec-fetch-mode'] !== 'navigate') {
      res.writeHead(403);
      res.end();
      return;
    }
    const upstream = this.upstream();
    if (upstream === undefined) {
      send(res, messagePage(503, '这台电脑上的 DSH 网页界面没有运行。'));
      return;
    }
    this.proxy(req, res, upstream);
  }

  proxy(req, res, upstream) {
    const target = new URL(upstream.origin);
    const client = String(req.socket.remoteAddress ?? '');
    const proxyReq = http.request(
      {
        host: target.hostname,
        port: Number(target.port || 80),
        method: req.method,
        path: req.url,
        headers: rewriteHeaders(req.headers, target),
      },
      (proxyRes) => {
        // After a DSH restart the old login cookie stops working; log in again
        // once, then reload the same page.
        const last = this.recovered.get(client) ?? 0;
        if (proxyRes.statusCode === 401 && wantsHtml(req) && Date.now() - last > RECOVER_WINDOW_MS) {
          proxyRes.resume();
          this.recovered.set(client, Date.now());
          this.exchange(upstream)
            .then((cookies) => send(res, continuePage(req.url ?? '/', cookies)))
            .catch((error) => send(res, messagePage(502, `无法登录这台电脑上的 DSH：${error.message}`)));
          return;
        }
        res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(res);
      },
    );
    proxyReq.on('error', (error) => {
      this.logger.warn(`peer-link: web relay: ${error.message}`);
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.on('aborted', () => proxyReq.destroy());
    res.on('close', () => proxyReq.destroy());
    req.pipe(proxyReq);
  }

  /** WebSocket upgrades: same gate, then splice to the local listener. */
  upgrade(req, socket, head) {
    const upstream = this.enabled() ? this.upstream() : undefined;
    if (upstream === undefined || !this.gateOk(req) || this.crossSite(req)) {
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }
    const target = new URL(upstream.origin);
    const upstreamSocket = net.connect(Number(target.port || 80), target.hostname, () => {
      let raw = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
      for (const [key, value] of Object.entries(rewriteHeaders(req.headers, target))) {
        for (const v of Array.isArray(value) ? value : [value]) raw += `${key}: ${v}\r\n`;
      }
      upstreamSocket.write(`${raw}\r\n`);
      if (head?.length) upstreamSocket.write(head);
      upstreamSocket.pipe(socket);
      socket.pipe(upstreamSocket);
    });
    const destroyBoth = () => {
      socket.destroy();
      upstreamSocket.destroy();
    };
    for (const side of [socket, upstreamSocket]) {
      side.on('error', destroyBoth);
      side.on('close', destroyBoth);
      this.sockets.add(side);
      side.on('close', () => this.sockets.delete(side));
    }
    socket.on('end', () => upstreamSocket.end());
    upstreamSocket.on('end', () => socket.end());
  }

  closeSockets() {
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
  }
}
