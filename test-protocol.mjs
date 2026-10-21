// Offline checks: signing, replay rejection, pairing codes, discovery, and
// provider runs against a fake sessionController over real loopback sockets.
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
const { PeerSubagentProvider } = await import('./provider.js');
const { PeerClient } = await import('./peer-client.js');
const { Discovery, keyIdOf } = await import('./discovery.js');
const http = await import('node:http');

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
const provider = new PeerSubagentProvider({ name: 'peer', getConfig: () => ({ displayName: 'client', remoteCwd: '', subagentPeer: '' }), clientFor, logger });
const run = await provider.start({ prompt: [{ type: 'text', text: 'ping' }], label: 'test', cwd: '/tmp', signal: new AbortController().signal });
const result = await run.result;
await run.dispose();
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

// Aborting the parent cancels the remote turn and settles as aborted.
let cancelled = 0;
fakeController.cancel = () => {
  cancelled += 1;
  return { accepted: true };
};
fakeController.prompt = async () => {
  agent.status = 'running';
  return { accepted: true };
};
const abort = new AbortController();
const hung = await provider.start({ prompt: [{ type: 'text', text: 'hang' }], label: 'abort', cwd: '/tmp', signal: abort.signal });
abort.abort();
const aborted = await hung.result;
await hung.dispose();
await new Promise((resolve) => setTimeout(resolve, 200));
assert.equal(aborted.stopReason, 'aborted');
assert.equal(cancelled, 1, 'remote cancel is sent exactly once');

discovery.close();
await listener.close();
console.log('peer-link protocol tests passed');
