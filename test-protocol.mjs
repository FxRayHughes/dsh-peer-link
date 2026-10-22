// Offline checks: signing, replay rejection, pairing codes, discovery, the
// peer-link model route against a fake sessionController, and the shared Web
// page against a fake DSH listener, over real loopback sockets.
// Run with: node test-protocol.mjs   (uses a temporary HOME)
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.HOME = mkdtempSync(join(tmpdir(), 'peer-link-test-'));
process.env.USERPROFILE = process.env.HOME;

const { NonceCache, newSecret, signedHeaders, verify, PeerError } = await import('./protocol.js');
const { decodeCode, encodeCode, PeerState } = await import('./state.js');
const { SessionOps, startServer } = await import('./server.js');
const { followRun } = await import('./provider.js');
const { PeerModelAdapter } = await import('./peer-model.js');
const { LinkStore } = await import('./links.js');
const { WebShare, ENTER_PATH } = await import('./web-share.js');
const { PeerClient } = await import('./peer-client.js');
const { Discovery, keyIdOf } = await import('./discovery.js');
const http = await import('node:http');
const net = await import('node:net');

// --- signing --------------------------------------------------------------
const secret = newSecret();
const body = JSON.stringify({ hello: 'world' });
const headers = signedHeaders(secret, '/peer/v1/info', body);
const nonces = new NonceCache();
verify(secret, headers, '/peer/v1/info', body, nonces);
assert.throws(() => verify(secret, headers, '/peer/v1/info', body, nonces), (e) => e.code === 'REPLAY');
const h2 = signedHeaders(secret, '/peer/v1/info', body);
assert.throws(() => verify(newSecret(), h2, '/peer/v1/info', body, new NonceCache()), (e) => e.code === 'AUTH');
assert.throws(() => verify(secret, h2, '/peer/v1/run', body, new NonceCache()), (e) => e.code === 'AUTH');
assert.throws(() => verify(secret, h2, '/peer/v1/info', '{}', new NonceCache()), (e) => e.code === 'AUTH');
const old = { ...signedHeaders(secret, '/x', ''), 'x-peer-ts': String(Date.now() - 10 * 60 * 1000) };
assert.throws(() => verify(secret, old, '/x', '', new NonceCache()), (e) => e instanceof PeerError && e.code === 'CLOCK');

// --- pairing codes --------------------------------------------------------
const code = encodeCode({ name: 'WIN-PC', hints: ['192.168.1.2:51234', 'bogus'], secret });
const decoded = decodeCode(code);
assert.equal(decoded.name, 'WIN-PC');
assert.equal(decoded.secret, secret);
assert.deepEqual(decoded.hints, ['192.168.1.2:51234']);
// Codes from the first version carried URLs.
const legacy = 'dshpeer1.' + Buffer.from(JSON.stringify({ n: 'old', u: ['http://10.0.0.5:7788'], k: secret })).toString('base64url');
assert.deepEqual(decodeCode(legacy).hints, ['10.0.0.5:7788']);
assert.throws(() => decodeCode('nope'), (e) => e.code === 'BAD_INPUT');

// --- loopback end to end --------------------------------------------------
const listeners = new Map();
let seq = 0;
const events = [];
const agent = {
  id: 's1',
  status: 'idle',
  inbox: { nextTurn: [], nextStep: [] },
  session: { get seq() { return events.length; }, header: { cwd: '/tmp' }, snapshotEvents: () => events },
};
const push = (type, data) => events.push({ type, seq: seq++, time: Date.now(), data });
const fakeController = {
  async create() { return { sessionId: 's1' }; },
  async rename() { return {}; },
  async resolveAgent() { return { agent }; },
  async prompt(request) {
    agent.status = 'running';
    setTimeout(() => {
      push('user/message', { source: { kind: 'user', rpcId: request.requestId }, content: request.content });
      push('assistant/message', { message: { content: [{ type: 'text', text: 'pong from fake' }] } });
      push('turn/end', { reason: { kind: 'completed' } });
      agent.status = 'idle';
    }, 300);
    return { accepted: true };
  },
  async inspect() { return { events }; },
  cancel() { return { accepted: true }; },
  async list() { return { items: [] }; },
};
const services = { sessionController: fakeController, agents: { get: (id) => (id === 's1' ? agent : undefined) }, sessions: { get: () => agent.session } };
const logger = { info() {}, warn: (m) => console.error('warn', m) };
const ctx = { get: (key) => services[key], logger };

const serverState = new PeerState();
const getConfig = () => ({ displayName: 'server', allowedRoots: '', delegationNote: true, permissionPreset: '' });
const listener = await startServer({ ctx, ops: new SessionOps(ctx, getConfig, serverState), state: serverState, host: '127.0.0.1', port: undefined, allowCidrs: '127.0.0.0/8' });
assert.ok(listener.port > 1024, 'random port');

// Discovery on an ephemeral UDP port; peers are found by unicast to their hint.
const discovery = new Discovery({ state: serverState, logger, port: 0, allowCidrs: '127.0.0.0/8' });
await discovery.start();
assert.ok(discovery.bound);
discovery.setHttpPort(listener.port);

// The client side shares the same state file in this test, so pair to itself.
// The peer starts with only a bare-IP hint: discovery must supply the port.
const clientState = new PeerState();
clientState.upsertPeer({ name: 'loop', hints: ['127.0.0.1'], secret: serverState.secret });
const found = await discovery.find(clientState.peer('loop'), { timeoutMs: 1500 });
assert.deepEqual(found, [`127.0.0.1:${listener.port}`]);
// A query signed with another key gets no answer.
assert.deepEqual(await discovery.find({ name: 'x', hints: ['127.0.0.1'], secret: newSecret() }, { timeoutMs: 600 }), []);
assert.notEqual(keyIdOf(secret), keyIdOf(newSecret()));

const clientFor = (name) => new PeerClient(clientState, clientState.peer(name), logger, discovery);
const started = await clientFor('loop').call('run', { prompt: 'ping', from: 'client', preface: true });
const result = await followRun(clientFor('loop'), started, new AbortController().signal);
assert.equal(result.stopReason, 'completed');
assert.match(result.output[0].text, /pong from fake/);
assert.match(result.output[0].text, /remote session s1/);
assert.equal(clientState.peer('loop').addr, `127.0.0.1:${listener.port}`, 'discovered address is cached');

// A stale cached address now held by an unrelated program is skipped.
const impostor = http.createServer((_req, res) => res.end(JSON.stringify({ ok: true, value: { name: 'impostor' } })));
await new Promise((resolve) => impostor.listen(0, '127.0.0.1', resolve));
clientState.rememberAddr('loop', `127.0.0.1:${impostor.address().port}`);
const info = await clientFor('loop').call('info', {}, { timeoutMs: 5000 });
assert.equal(info.name, 'server');
assert.equal(clientState.peer('loop').addr, `127.0.0.1:${listener.port}`, 're-discovered after the port changed');
impostor.close();

// A turn that was already running when the prompt was queued must not settle it.
const ops = new SessionOps(ctx, getConfig, serverState);
events.length = 0;
seq = 0;
push('turn/start', {});
const queued = await ops.run({ prompt: 'second', sessionId: 's1', from: 'client' });
push('assistant/message', { message: { content: [{ type: 'text', text: 'earlier turn' }] } });
push('turn/end', { reason: { kind: 'completed' } });
agent.status = 'idle';
const early = await ops.status({ sessionId: 's1', startSeq: queued.startSeq, requestId: queued.requestId });
assert.equal(early.done, false, 'an earlier turn must not settle a queued prompt');
await new Promise((resolve) => setTimeout(resolve, 400));
const late = await ops.status({ sessionId: 's1', startSeq: queued.startSeq, requestId: queued.requestId });
assert.equal(late.done, true);
assert.equal(late.finalText, 'pong from fake');

// --- peer-link model route -------------------------------------------------
// A scripted remote: each prompt runs one turn that replies `reply:<text>`
// after `turnMs`, unless `hold` keeps it running until released.
let msgId = 0;
const userMsg = (text, kind = 'user') => ({ id: `m${++msgId}`, role: 'user', content: [{ type: 'text', text }], source: { kind } });
const assistantMsg = (text) => ({ id: `m${++msgId}`, role: 'assistant', content: [{ type: 'text', text }], source: { kind: 'model' } });
const remote = { prompts: [], hold: false, turnMs: 150, current: undefined, cancels: 0 };
const finishTurn = () => {
  const turn = remote.current;
  if (turn === undefined) return;
  remote.current = undefined;
  push('assistant/message', { message: { content: [{ type: 'text', text: `reply:${turn.texts.join('+')}` }] } });
  push('turn/end', { reason: { kind: turn.cancelled ? 'aborted' : 'completed' } });
  agent.status = 'idle';
};
fakeController.prompt = async (request) => {
  const text = request.content[0].text.replace(/^\[[^\]]*\]\n\n/, '');
  remote.prompts.push({ text, mode: request.mode });
  if (request.mode === 'steer' && remote.current !== undefined) {
    remote.current.texts.push(text);
    push('user/message', { source: { kind: 'user', rpcId: request.requestId }, content: request.content });
    return { accepted: true };
  }
  agent.status = 'running';
  remote.current = { texts: [text] };
  push('user/message', { source: { kind: 'user', rpcId: request.requestId }, content: request.content });
  if (!remote.hold) setTimeout(finishTurn, remote.turnMs);
  return { accepted: true };
};
fakeController.cancel = () => {
  remote.cancels += 1;
  if (remote.current) remote.current.cancelled = true;
  finishTurn();
  return { accepted: true };
};
events.length = 0;
seq = 0;

const links = new LinkStore(join(process.env.HOME, 'links.json'));
const childAgents = new Map();
const routeCtx = { get: (key) => (key === 'agents' ? { get: (id) => childAgents.get(id) } : undefined), logger };
const adapter = new PeerModelAdapter({
  getConfig: () => ({ displayName: 'client', remoteCwd: '', subagentPeer: '' }),
  clientFor,
  listPeerNames: () => ['loop'],
  links,
  ctx: routeCtx,
});
const child = { id: 'child-1', inbox: { nextStep: [] }, session: { header: { cwd: '/tmp' }, snapshotEvents: () => [{ type: 'subagent/descriptor', data: { label: 'probe' } }] } };
childAgents.set(child.id, child);

async function collect(messages, signal = new AbortController().signal) {
  const chunks = [];
  for await (const chunk of adapter.stream({ provider: 'peer-link', model: 'auto', sessionId: child.id, messages, signal })) chunks.push(chunk);
  const text = (type) => chunks.filter((c) => c.type === 'block-end' && c.block.type === type).map((c) => c.block.text).join('\n');
  return { chunks, text: text('text'), reasoning: text('reasoning'), finish: chunks.at(-1) };
}

assert.equal((await adapter.listModels('peer-link')).map((m) => m.id).join(), 'auto,loop');
assert.equal((await adapter.resolveModel('peer-link', 'auto')).context.contextWindow > 0, true);

// First turn: the task (minus the return guidance) opens a remote Session.
const history = [
  { id: 'rc', role: 'user', content: [{ type: 'text', text: 'runtime context' }], source: { kind: 'runtime-context' } },
  { ...userMsg('task one'), content: [{ type: 'text', text: 'task one' }, { type: 'text', text: 'Your parent agent id is "p". Before you finish, send...' }] },
];
let turn = await collect(history);
assert.equal(remote.prompts.length, 1);
assert.equal(remote.prompts[0].text, 'task one', 'only the task is forwarded');
assert.equal(turn.text.split('\n\n')[0], 'reply:task one');
assert.match(turn.text, /remote session s1 on loop/);
assert.equal(turn.finish.reason.kind, 'stop');
assert.equal(links.get(child.id).remote, 's1');
history.push(assistantMsg(turn.text));

// A later send_message continues the same remote Session.
history.push({ ...userMsg('', 'agent-message'), content: [{ type: 'text', text: 'Agent p sent a message: ' }, { type: 'text', text: 'follow up' }] });
turn = await collect(history);
assert.equal(remote.prompts.at(-1).text, 'follow up', 'the relay prefix is stripped');
assert.equal(remote.prompts.at(-1).mode, 'queue');
assert.equal(turn.text.split('\n\n')[0], 'reply:follow up');
history.push(assistantMsg(turn.text));

// Nothing new to send: the route answers without contacting the peer.
const before = remote.prompts.length;
turn = await collect(history.concat([{ id: 'rc2', role: 'user', content: [{ type: 'text', text: 'ctx' }], source: { kind: 'runtime-context' } }]));
assert.equal(remote.prompts.length, before);

// A message steered in mid-turn is relayed into the running remote turn at once,
// and its reply is held for the step that admits that message.
remote.hold = true;
history.push(userMsg('long task'));
const pendingTurn = collect(history);
await new Promise((resolve) => setTimeout(resolve, 400));
const steer = userMsg('', 'agent-message');
steer.content = [{ type: 'text', text: 'Agent p sent a message: ' }, { type: 'text', text: 'also this' }];
child.inbox.nextStep = [steer];
adapter.onInboxInserted(child, steer);
await new Promise((resolve) => setTimeout(resolve, 400));
assert.equal(remote.prompts.at(-1).text, 'also this');
assert.equal(remote.prompts.at(-1).mode, 'steer');
finishTurn();
turn = await pendingTurn;
assert.equal(turn.text, '', 'the reply waits for the relayed message');
assert.match(turn.reasoning, /steered the running turn/);
history.push(assistantMsg(''));
history.push(steer);
child.inbox.nextStep = [];
const promptsBefore = remote.prompts.length;
turn = await collect(history);
assert.equal(remote.prompts.length, promptsBefore, 'a relayed message is not sent twice');
assert.equal(turn.text.split('\n\n')[0], 'reply:long task+also this');
history.push(assistantMsg(turn.text));
remote.hold = false;

// Stopping the child cancels the remote turn; a disposed child leaves it running.
remote.hold = true;
history.push(userMsg('stop me'));
const stopper = new AbortController();
const stopped = collect(history, stopper.signal);
await new Promise((resolve) => setTimeout(resolve, 300));
stopper.abort({ kind: 'user' });
await assert.rejects(stopped);
await new Promise((resolve) => setTimeout(resolve, 200));
assert.equal(remote.cancels, 1, 'remote cancel is sent exactly once');
assert.equal(links.get(child.id).pending, null);
history.pop();
remote.hold = false;

// Pending remote questions are answered by the next forwarded message.
const answered = [];
services.userQuestions = { answer: (_agent, callId, answer) => (answered.push({ callId, answer }), true) };
services.sessionProjections = { stateOf: () => ({ questions: { active: [{ callId: 'q1', state: 'continued', questions: [{ id: 'a', question: 'Which?' }] }] } }) };
const answerRun = await ops.run({ prompt: 'option B', sessionId: 's1', from: 'client', answerQuestions: true });
assert.equal(answerRun.answered, 1);
assert.deepEqual(answered[0], { callId: 'q1', answer: { answers: [{ id: 'a', selected: [], custom: 'option B' }] } });
delete services.userQuestions;
delete services.sessionProjections;

// A later turn woken by something else does not replace a tracked request's reply.
const tracked = await ops.run({ prompt: 'tracked', sessionId: 's1', from: 'client' });
await new Promise((resolve) => setTimeout(resolve, 300));
agent.status = 'running';
push('user/message', { source: { kind: 'permission-notice' }, content: [{ type: 'text', text: 'policy changed' }] });
push('assistant/message', { message: { content: [{ type: 'text', text: 'noted the policy change' }] } });
const trackedStatus = await ops.status({ sessionId: 's1', startSeq: tracked.startSeq, requestId: tracked.requestId });
assert.equal(trackedStatus.done, true, 'the admitting turn settles the request while a later turn runs');
assert.equal(trackedStatus.finalText, 'reply:tracked');
agent.status = 'idle';

// The mapping survives a restart.
assert.equal(new LinkStore(join(process.env.HOME, 'links.json')).get(child.id).remote, 's1');

discovery.close();
await listener.close();

// ---- Shared Web page ----------------------------------------------------
{
// A fake DSH listener: the launch token mints a Host-bound cookie, and the
// Host/Origin fence refuses anything but its own loopback authority.
const TOKEN = 'launch-token-xyz';
let upstreamPort;
const seen = [];
const dsh = http.createServer((req, res) => {
  seen.push({ url: req.url, host: req.headers.host, origin: req.headers.origin, cookie: req.headers.cookie });
  const host = req.headers.host;
  if (host !== `127.0.0.1:${upstreamPort}`) { res.writeHead(403); return res.end('fence'); }
  if (req.headers.origin && req.headers.origin !== `http://${host}`) { res.writeHead(403); return res.end('origin'); }
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/' && url.searchParams.get('token') === TOKEN) {
    res.writeHead(303, { location: './', 'set-cookie': [`dsh-auth-abc=ok-${host}; Path=/; HttpOnly; SameSite=Strict`] });
    return res.end();
  }
  const authed = String(req.headers.cookie ?? '').includes(`dsh-auth-abc=ok-${host}`);
  if (!authed) { res.writeHead(401); return res.end('unauth'); }
  if (req.headers['peer_link_gate'] || String(req.headers.cookie).includes('peer_link_gate')) { res.writeHead(500); return res.end('gate leaked'); }
  if (url.pathname === '/api/echo') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ ok: true })); }
  res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>DSH APP</html>');
});
dsh.on('upgrade', (req, socket) => {
  const authed = String(req.headers.cookie ?? '').includes('dsh-auth-abc=ok-');
  if (!authed || req.headers.host !== `127.0.0.1:${upstreamPort}`) return socket.end('HTTP/1.1 401 x\r\n\r\n');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
  socket.on('data', (d) => socket.write(d)); // echo
});
await new Promise((r) => dsh.listen(0, '127.0.0.1', r));
upstreamPort = dsh.address().port;

let enabled = true;
const logger = { info() {}, warn() {} };
const secret = 'S'.repeat(43);
const state = { secret };
const web = new WebShare({
  enabled: () => enabled,
  upstream: () => ({ origin: `http://127.0.0.1:${upstreamPort}`, tokenPath: `/?token=${TOKEN}` }),
  secret: () => secret,
  logger,
});
const ops = new SessionOps({ logger, get: () => undefined }, () => ({ displayName: 'B' }), state);
ops.web = web;
const server = await startServer({ ctx: { logger }, ops, state, host: '127.0.0.1', port: 0, allowCidrs: '127.0.0.0/8', web });
const base = `http://127.0.0.1:${server.port}`;

const peer = { name: 'B', secret, addr: `127.0.0.1:${server.port}`, hints: [] };
const client = new PeerClient({ rememberAddr() {} }, peer, logger, undefined);
const info = await client.call('info');
assert.equal(info.web, true, 'info advertises web');

const get = (path, headers = {}) => fetch(base + path, { headers, redirect: 'manual' });
const cookiesOf = (res) => res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');

// 1. no gate → refused, upstream untouched
let before = seen.length;
let r = await get('/', { accept: 'text/html' });
assert.equal(r.status, 401); assert.equal(seen.length, before, 'ungated request never reaches DSH');
r = await get('/api/echo');
assert.equal(r.status, 401);

// 2. ticket via signed protocol, then enter
const t1 = await client.call('webTicket', { sessionId: 'sess-123' });
assert.ok(t1.path.startsWith(ENTER_PATH));
r = await get(t1.path, { accept: 'text/html' });
assert.equal(r.status, 200);
const html = await r.text();
assert.match(html, /location\.replace\("\/#peer-link-session=sess-123"\)/);
assert.doesNotMatch(html, new RegExp(TOKEN), 'launch token never reaches the browser');
const jar = cookiesOf(r);
assert.match(jar, /peer_link_gate=/); assert.match(jar, /dsh-auth-abc=/);

// 3. ticket is single-use
r = await get(t1.path, { accept: 'text/html' });
assert.equal(r.status, 403);

// 4. gated + DSH cookie → page and API through relay with rewritten Host
r = await get('/', { accept: 'text/html', cookie: jar });
assert.equal(r.status, 200); assert.equal(await r.text(), '<html>DSH APP</html>');
r = await fetch(base + '/api/echo', { method: 'POST', headers: { cookie: jar, origin: base, 'content-type': 'application/json' }, body: '{}' });
assert.equal(r.status, 200, 'same-origin API call passes the DSH fence');
const last = seen.at(-1);
assert.equal(last.host, `127.0.0.1:${upstreamPort}`); assert.equal(last.origin, `http://127.0.0.1:${upstreamPort}`);
assert.doesNotMatch(last.cookie, /peer_link_gate/, 'gate cookie stripped before DSH');

// 5. cross-site API request refused
r = await fetch(base + '/api/echo', { method: 'POST', headers: { cookie: jar, origin: 'http://evil.example', 'content-type': 'application/json' }, body: '{}' });
assert.equal(r.status, 403);

// 6. forged / tampered gate refused
const forged = jar.replace(/peer_link_gate=(\d+)\.[0-9a-f]+/, (_, e) => `peer_link_gate=${e}.${'0'.repeat(64)}`);
r = await get('/api/echo', { cookie: forged });
assert.equal(r.status, 401);

// 7. stale DSH cookie (DSH restarted) → re-login page once
const stale = jar.replace(/dsh-auth-abc=[^;]+/, 'dsh-auth-abc=old');
r = await get('/some/page', { accept: 'text/html', cookie: stale });
assert.equal(r.status, 200);
assert.match(await r.text(), /location\.replace\("\/some\/page"\)/);
assert.match(cookiesOf(r), /dsh-auth-abc=ok-/);

// 8. WebSocket upgrade through relay (gated)
const ws = await new Promise((resolve, reject) => {
  const sock = net.connect(server.port, '127.0.0.1', () => {
    sock.write(`GET /api/ws HTTP/1.1\r\nHost: 127.0.0.1:${server.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: ${base}\r\nCookie: ${jar}\r\n\r\n`);
  });
  let buf = '';
  sock.on('data', (d) => {
    buf += d;
    if (buf.includes('\r\n\r\n') && !buf.includes('PING')) { sock.write('PING'); }
    if (buf.includes('PING')) { sock.destroy(); resolve(buf); }
  });
  sock.on('error', reject);
  setTimeout(() => reject(new Error('ws timeout: ' + buf)), 3000);
});
assert.match(ws, /101 Switching/); assert.match(ws, /PING/);
const wsDenied = await new Promise((resolve) => {
  const sock = net.connect(server.port, '127.0.0.1', () => sock.write(`GET /api/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n`));
  let buf = ''; sock.on('data', (d) => (buf += d)); sock.on('close', () => resolve(buf));
});
assert.match(wsDenied, /403/);

// 9. protocol still works, unsigned protocol still refused
r = await fetch(base + '/peer/v1/info', { method: 'POST', body: '{}' });
assert.equal(r.status, 401);

// 10. sharing switched off
enabled = false;
await assert.rejects(client.call('webTicket', {}), /does not share its web page/);
r = await get('/', { accept: 'text/html', cookie: jar });
assert.equal(r.status, 404);
assert.equal((await client.call('info')).web, false);


// 11. the gate is bound to the browser's address: the same cookie from another address is refused
const lan = Object.values((await import('node:os')).networkInterfaces()).flat().find((i) => i?.family === 'IPv4' && !i.internal)?.address;
if (lan) {
  enabled = true;
  const wide = await startServer({ ctx: { logger }, ops, state, host: '0.0.0.0', port: 0, allowCidrs: `127.0.0.0/8, ${lan}/32`, web });
  const t2 = await client.call('webTicket', {});
  const loop = await fetch(`http://127.0.0.1:${wide.port}${t2.path}`, { redirect: 'manual' });
  const loopJar = loop.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  assert.equal((await fetch(`http://127.0.0.1:${wide.port}/api/echo`, { headers: { cookie: loopJar } })).status, 200);
  assert.equal((await fetch(`http://${lan}:${wide.port}/api/echo`, { headers: { cookie: loopJar } })).status, 401, 'cookie replayed from another address');
  await wide.close();
}
await server.close();
dsh.close();
}
console.log('peer-link protocol tests passed');
