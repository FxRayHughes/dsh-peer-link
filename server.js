import http from 'node:http';
import { existsSync, statSync } from 'node:fs';
import { hostname, platform, release } from 'node:os';
import { isAbsolute } from 'node:path';
import { randomUUID } from 'node:crypto';
import { API_PREFIX, BODY_LIMIT, buildAllowList, NonceCache, normalizeIp, parseHint, PeerError, signResponse, verify } from './protocol.js';
import { decodeCode } from './state.js';

/**
 * LAN endpoint of the peer-link plugin. It accepts signed requests from paired
 * DSH instances and drives this DSH's Sessions in-process through
 * `ctx.sessionController`, so it never needs the per-launch Web token and
 * never widens the Web listener's trust fence.
 */

const WAIT_CAP_MS = 25_000;
const READ_CAP_CHARS = 60_000;

const sleep = (ms, signal) =>
  new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
  });

function textOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .filter((block) => block && block.type === 'text' && typeof block.text === 'string')
    .map((block) => block.text)
    .join('\n')
    .trim();
}

function clip(text, max) {
  if (text.length <= max) return { text, truncated: false };
  return { text: `${text.slice(0, max)}\n…[truncated ${text.length - max} chars]`, truncated: true };
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

/** Send JSON; with `proof`, sign it so the caller knows it reached the right peer. */
function sendJson(res, status, body, proof) {
  const text = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  if (proof !== undefined) res.setHeader('x-peer-resp-sig', signResponse(proof.secret, proof.nonce, status, text));
  res.end(text);
}

/** Session operations exposed to peers. */
export class SessionOps {
  constructor(ctx, getConfig, state) {
    this.ctx = ctx;
    this.getConfig = getConfig;
    this.state = state;
  }

  get controller() {
    const controller = this.ctx.get('sessionController');
    if (controller === undefined) throw new PeerError('UNAVAILABLE', 'session controller is not mounted on this DSH', 503);
    return controller;
  }

  info() {
    const config = this.getConfig();
    return {
      name: config.displayName,
      hostname: hostname(),
      platform: platform(),
      release: release(),
      node: process.version,
      pid: process.pid,
      time: Date.now(),
    };
  }

  /** Pairing handshake: the caller already proved it knows our secret and hands us its own code. */
  hello(args) {
    if (typeof args?.code !== 'string') return { paired: false, name: this.getConfig().displayName };
    const peer = decodeCode(args.code);
    // The caller's port comes from its code; its host is the address we actually saw.
    const port = peer.hints.map((hint) => parseHint(hint)?.port).find((p) => p !== undefined);
    const addr = args.remoteIp && port !== undefined ? `${args.remoteIp}:${port}` : undefined;
    this.state.upsertPeer({ ...peer, addr });
    this.ctx.logger.info(`peer-link: paired with "${peer.name}" (${addr ?? peer.hints.join(', ')})`);
    return { paired: true, name: this.getConfig().displayName };
  }

  /** First usable directory among lenient candidates (missing or forbidden ones are skipped). */
  pickCwd(candidates) {
    for (const candidate of Array.isArray(candidates) ? candidates : []) {
      try {
        const cwd = this.checkCwd(candidate);
        if (cwd !== undefined) return cwd;
      } catch {
        // Try the next candidate.
      }
    }
    return undefined;
  }

  checkCwd(cwd) {
    if (cwd === undefined || cwd === null || cwd === '') return undefined;
    const value = String(cwd);
    if (!isAbsolute(value)) throw new PeerError('BAD_INPUT', `cwd must be an absolute path on ${hostname()} (${platform()})`);
    if (!existsSync(value) || !statSync(value).isDirectory()) throw new PeerError('BAD_INPUT', `directory not found on ${hostname()}: ${value}`);
    const roots = String(this.getConfig().allowedRoots ?? '')
      .split(/[\n;]+/)
      .map((root) => root.trim())
      .filter(Boolean);
    if (roots.length > 0) {
      const norm = (p) => (platform() === 'win32' ? p.toLowerCase().replace(/\//g, '\\') : p);
      const target = norm(value);
      if (!roots.some((root) => target === norm(root) || target.startsWith(norm(root).replace(/[\\/]+$/, '') + (platform() === 'win32' ? '\\' : '/')))) {
        throw new PeerError('FORBIDDEN', `cwd is outside the allowed roots on this machine`, 403);
      }
    }
    return value;
  }

  async resolveAgent(sessionId) {
    const found = await this.controller.resolveAgent(sessionId);
    if (found && 'error' in found) throw new PeerError('NOT_FOUND', `session ${sessionId}: ${found.error?.message ?? 'unavailable'}`, 404);
    return found.agent;
  }

  /** Start a new remote Session or queue a prompt into an existing one. */
  async run(args, signal) {
    const prompt = String(args?.prompt ?? '').trim();
    if (!prompt) throw new PeerError('BAD_INPUT', 'prompt is empty');
    const from = typeof args?.from === 'string' ? args.from.slice(0, 32) : 'peer';
    let sessionId = typeof args?.sessionId === 'string' && args.sessionId ? args.sessionId : undefined;
    let created = false;
    if (sessionId === undefined) {
      const cwd = args?.cwd ? this.checkCwd(args.cwd) : this.pickCwd(args?.cwdCandidates);
      const result = await this.controller.create(cwd === undefined ? {} : { cwd });
      sessionId = result.sessionId;
      created = true;
      const preset = this.getConfig().permissionPreset;
      if (preset) {
        const presets = this.ctx.get('permissionPresets');
        const fresh = await this.resolveAgent(sessionId);
        try {
          presets?.set(fresh.session, preset);
        } catch (error) {
          this.ctx.logger.warn(`peer-link: cannot apply permission preset "${preset}": ${error.message}`);
        }
      }
      const label = String(args?.label ?? '').trim().slice(0, 60);
      try {
        await this.controller.rename({ sessionId, title: `[${from}] ${label || prompt.slice(0, 40)}` });
      } catch {
        // Titles are cosmetic.
      }
    }
    const agent = await this.resolveAgent(sessionId);
    const startSeq = Number(agent.session.seq);
    if (!created && args?.answerQuestions === true) {
      const answered = this.answerContinued(agent, prompt);
      if (answered > 0) {
        this.ctx.logger.info(`peer-link: ${from} answered ${answered} question(s) in session ${sessionId}`);
        return { sessionId, startSeq, created, answered, cwd: agent.session.header?.cwd };
      }
    }
    const requestId = randomUUID();
    // Steering joins a turn that is still running; an idle Session takes a new turn either way.
    const mode = args?.mode === 'steer' && agent.status === 'running' ? 'steer' : 'queue';
    const preface = this.getConfig().delegationNote
      ? `[Delegated from peer DSH "${from}" via peer-link. No human is watching this session: do not wait for answers, make reasonable decisions yourself, and end with a concise report of what you did and the results.]\n\n`
      : `[Delegated from peer DSH "${from}"]\n\n`;
    await this.controller.prompt(
      {
        requestId,
        sessionId,
        mode,
        content: [{ type: 'text', text: (created || args?.preface ? preface : `[From peer DSH "${from}"]\n\n`) + prompt }],
      },
      signal ?? new AbortController().signal,
    );
    this.ctx.logger.info(`peer-link: ${from} ${created ? 'started' : mode === 'steer' ? 'steered' : 'prompted'} session ${sessionId}`);
    return { sessionId, startSeq, requestId, created, mode, cwd: agent.session.header?.cwd };
  }

  /**
   * Answer every question the remote agent left pending (its ask_user_question
   * returned without an answer) with the caller's text. The reply is steered
   * into the agent by the user-questions service, which wakes an idle Session.
   * @returns how many question calls were answered.
   */
  answerContinued(agent, text) {
    const service = this.ctx.get('userQuestions');
    const view = this.ctx.get('sessionProjections')?.stateOf(agent.session, 'userQuestions');
    const continued = (view?.questions?.active ?? []).filter((item) => item.state === 'continued');
    if (service === undefined || continued.length === 0) return 0;
    let answered = 0;
    for (const item of continued) {
      try {
        const answers = item.questions.map((question) => ({ id: question.id, selected: [], custom: text }));
        if (service.answer(agent, item.callId, { answers })) answered += 1;
      } catch (error) {
        this.ctx.logger.warn(`peer-link: cannot answer question ${item.callId}: ${error.message}`);
      }
    }
    return answered;
  }

  events(sessionId) {
    const attached = this.ctx.get('sessions')?.get(sessionId);
    if (attached !== undefined && typeof attached.snapshotEvents === 'function') return attached.snapshotEvents();
    return undefined;
  }

  /**
   * Progress of one prompt. With `requestId`, only the turn that admitted that
   * prompt counts: a turn already running when it was queued cannot end the
   * run early, and a later turn woken by something else (a permission change
   * notice, a local prompt) cannot replace its reply. `startSeq` alone covers
   * prompts sent by older peers.
   */
  async status(args) {
    const sessionId = String(args?.sessionId ?? '');
    const startSeq = Number(args?.startSeq ?? 0);
    const requestId = typeof args?.requestId === 'string' ? args.requestId : undefined;
    const agent = this.ctx.get('agents')?.get(sessionId);
    let events = this.events(sessionId);
    if (events === undefined) {
      const inspected = await this.controller.inspect(sessionId);
      events = inspected.events;
    }
    let turnEnd;
    let finalText = '';
    let lastActivity;
    let errorText;
    let admitted = requestId === undefined;
    for (const event of events) {
      if (event.seq < startSeq) continue;
      if (!admitted) {
        if (event.type === 'user/message' && event.data?.source?.rpcId === requestId) admitted = true;
        continue;
      }
      if (event.type === 'assistant/message') {
        const text = textOf(event.data?.message?.content);
        if (text) finalText = text;
        lastActivity = event.time;
      } else if (event.type === 'turn/end') {
        turnEnd = event.data?.reason;
        if (turnEnd?.kind === 'error') errorText = turnEnd.error?.message ?? 'turn failed';
        if (requestId !== undefined) break;
      } else if (event.type === 'tool/call') {
        lastActivity = event.time;
      }
    }
    const pending = agent === undefined ? 0 : (agent.inbox?.nextTurn?.length ?? 0) + (agent.inbox?.nextStep?.length ?? 0);
    const running = agent !== undefined && (agent.status === 'running' || pending > 0);
    // The admitting turn's end settles a tracked request even if the Session went on to another turn.
    const done = turnEnd !== undefined && (requestId !== undefined || !running);
    const session = agent?.session ?? this.ctx.get('sessions')?.get(sessionId);
    const questionView = session === undefined ? undefined : this.ctx.get('sessionProjections')?.stateOf(session, 'userQuestions');
    const questions = (questionView?.questions?.active ?? []).map((item) => ({
      callId: item.callId,
      state: item.state,
      questions: item.questions,
    }));
    return {
      sessionId,
      running,
      done,
      stopReason: done ? turnEnd.kind : undefined,
      error: errorText,
      finalText: done ? clip(finalText, READ_CAP_CHARS).text : undefined,
      questions,
      seq: events.length,
      lastActivity,
    };
  }

  /** Long-poll until the run settles or the window closes. */
  async wait(args, signal) {
    const deadline = Date.now() + Math.min(Math.max(Number(args?.timeoutMs) || WAIT_CAP_MS, 1000), WAIT_CAP_MS);
    for (;;) {
      const status = await this.status(args);
      if (status.done || Date.now() >= deadline || signal?.aborted) return status;
      await sleep(700, signal);
    }
  }

  async cancel(args) {
    const sessionId = String(args?.sessionId ?? '');
    if (this.ctx.get('agents')?.get(sessionId) === undefined) return { accepted: false, reason: 'not running' };
    return this.controller.cancel({ sessionId });
  }

  async sessions(args, signal) {
    const { items } = await this.controller.list({}, signal ?? new AbortController().signal);
    const limit = Math.min(Math.max(Number(args?.limit) || 15, 1), 50);
    return {
      items: items.slice(0, limit).map((item) => ({
        sessionId: item.sessionId,
        title: item.projections?.values?.title ?? '',
        running: item.running === true,
        updatedAt: item.updatedAt,
        cwd: item.cwd,
      })),
      total: items.length,
    };
  }

  /** Last `limit` user/assistant messages as plain text. */
  async read(args) {
    const sessionId = String(args?.sessionId ?? '');
    let events = this.events(sessionId);
    if (events === undefined) events = (await this.controller.inspect(sessionId)).events;
    const limit = Math.min(Math.max(Number(args?.limit) || 10, 1), 50);
    const messages = [];
    for (const event of events) {
      if (event.type === 'assistant/message') {
        const text = textOf(event.data?.message?.content);
        if (text) messages.push({ seq: event.seq, role: 'assistant', text });
      } else if (event.type === 'user/message' && event.data?.source?.kind === 'user') {
        const text = textOf(event.data?.content);
        if (text) messages.push({ seq: event.seq, role: 'user', text });
      }
    }
    const tail = messages.slice(-limit);
    let budget = READ_CAP_CHARS;
    for (let i = tail.length - 1; i >= 0; i--) {
      const { text } = clip(tail[i].text, Math.max(budget, 500));
      tail[i].text = text;
      budget -= text.length;
    }
    return { sessionId, messages: tail, omitted: messages.length - tail.length };
  }
}

const OPS = new Set(['info', 'hello', 'run', 'status', 'wait', 'cancel', 'sessions', 'read']);

/** Start the LAN listener; resolves to `{ close, address }`. */
export async function startServer({ ctx, ops, state, host, port, allowCidrs }) {
  const allow = buildAllowList(allowCidrs);
  const nonces = new NonceCache();
  const failures = new Map();

  const server = http.createServer(async (req, res) => {
    const ip = normalizeIp(req.socket.remoteAddress);
    if (!allow.check(ip)) {
      sendJson(res, 403, { ok: false, error: { code: 'FORBIDDEN', message: `address ${ip} is not allowed` } });
      return;
    }
    const url = new URL(req.url ?? '/', 'http://peer');
    if (req.method === 'GET' && url.pathname === '/peer/ping') {
      sendJson(res, 200, { ok: true, service: 'dsh-peer-link', v: 1 });
      return;
    }
    if (req.method !== 'POST' || !url.pathname.startsWith(API_PREFIX)) {
      sendJson(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'not found' } });
      return;
    }
    const recent = failures.get(ip);
    if (recent && recent.count >= 10 && Date.now() - recent.at < 60_000) {
      sendJson(res, 429, { ok: false, error: { code: 'RATE', message: 'too many failed attempts; retry later' } });
      return;
    }
    const op = url.pathname.slice(API_PREFIX.length);
    const abort = new AbortController();
    res.on('close', () => abort.abort());
    // Set once the request is authenticated; failures before that stay unsigned.
    let proof;
    try {
      const body = await readBody(req);
      const secret = state.secret;
      verify(secret, req.headers, url.pathname, body, nonces);
      proof = { secret, nonce: req.headers['x-peer-nonce'] };
      failures.delete(ip);
      if (!OPS.has(op)) throw new PeerError('NOT_FOUND', `unknown op ${op}`, 404);
      const args = body ? JSON.parse(body) : {};
      if (op === 'hello') args.remoteIp = ip;
      const value = await ops[op](args, abort.signal);
      sendJson(res, 200, { ok: true, value }, proof);
    } catch (error) {
      const status = error instanceof PeerError ? error.status : 500;
      if (status === 401) {
        const entry = failures.get(ip) ?? { count: 0, at: 0 };
        failures.set(ip, { count: Date.now() - entry.at > 60_000 ? 1 : entry.count + 1, at: Date.now() });
        ctx.logger.warn(`peer-link: rejected ${ip} ${op}: ${error.message}`);
      }
      const code = error instanceof PeerError ? error.code : error?.code ?? 'INTERNAL';
      sendJson(res, status, { ok: false, error: { code: String(code), message: error instanceof Error ? error.message : String(error) } }, proof);
    }
  });
  server.keepAliveTimeout = 5_000;
  server.requestTimeout = 60_000;

  const listen = (target) =>
    new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(target, host, () => {
        server.off('error', reject);
        resolve();
      });
    });
  // Reuse the previous port when free so peers' cached addresses stay valid;
  // otherwise take any free port and let discovery spread the new one.
  try {
    await listen(port ?? 0);
  } catch (error) {
    if (!port || error?.code !== 'EADDRINUSE') throw error;
    await listen(0);
  }

  return {
    address: `${host}:${server.address().port}`,
    port: server.address().port,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
