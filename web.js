import { PeerError } from './protocol.js';

/**
 * Browser entry point for the settings page: `POST /peer-link/rpc` with
 * `{ method, args }`, answered as `{ ok, value }` or `{ ok: false, error }`.
 * It sits behind the Web connection's Host/Origin fence and browser
 * authentication, and only dispatches to the operations `api` names, which are
 * the same ones the `peer_dsh` tool runs.
 */

export const RPC_PATH = '/peer-link/rpc';
const BODY_LIMIT = 256 * 1024;

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        reject(new PeerError('TOO_LARGE', 'request body too large', 413));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/** @param api - method name → `(args, signal) => value`. */
export function webRoute(connection, api) {
  return {
    kind: 'exact',
    path: RPC_PATH,
    handler: async (req, res) => {
      const rejection = connection.requestRejection(req);
      if (rejection !== undefined) {
        res.statusCode = rejection;
        res.end();
        return;
      }
      if (req.method !== 'POST') {
        res.setHeader('allow', 'POST');
        sendJson(res, 405, { ok: false, error: { code: 'METHOD', message: 'POST only' } });
        return;
      }
      const type = String(req.headers['content-type'] ?? '').split(';', 1)[0].trim().toLowerCase();
      if (type !== 'application/json') {
        sendJson(res, 415, { ok: false, error: { code: 'MEDIA', message: 'application/json required' } });
        return;
      }
      const abort = new AbortController();
      res.on('close', () => abort.abort());
      try {
        const body = JSON.parse(await readBody(req));
        const method = String(body?.method ?? '');
        if (!Object.hasOwn(api, method)) throw new PeerError('BAD_INPUT', `unknown method ${method}`);
        const value = await api[method](body?.args ?? {}, abort.signal);
        sendJson(res, 200, { ok: true, value });
      } catch (error) {
        const known = error instanceof PeerError;
        sendJson(res, known ? (error.status >= 500 ? error.status : 400) : 500, {
          ok: false,
          error: { code: known ? error.code : 'INTERNAL', message: error instanceof Error ? error.message : String(error) },
        });
      }
    },
  };
}
