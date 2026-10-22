import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import z from '@deepseek-ai/schemastery';
import { Discovery, DISCOVERY_PORT } from './discovery.js';
import { PeerClient } from './peer-client.js';
import { PeerError } from './protocol.js';
import { LinkStore } from './links.js';
import { PeerModelAdapter, PROVIDER } from './peer-model.js';
import { followRun, PeerSubagentProvider } from './provider.js';
import { SessionOps, startServer } from './server.js';
import { decodeCode, defaultDisplayName, PAIRING_FILE, PeerState, publicPeer } from './state.js';
import { RPC_PATH, webRoute } from './web.js';
import { WebShare } from './web-share.js';

/**
 * Peer-link Host plugin: connects this DSH with other DSH instances on the LAN.
 *
 *  - A signed HTTP endpoint on a random free port lets paired peers start and
 *    follow Sessions here; signed UDP discovery tells them where it is.
 *  - A `peer` subagent provider makes a remote DSH a delegation backend; the
 *    patch mounts `dsh-tool-subagent` over it as the `subagent_peer` tool.
 *    Its children are continuable local Agents on the `peer-link` model
 *    route, which runs each of their turns in one remote Session.
 *  - The `peer_dsh` tool pairs peers and continues, reads, or cancels remote Sessions.
 *  - With `shareWeb`, the same listener also serves this DSH's Web page to
 *    paired peers' users through one-time links (see web-share.js), so the
 *    other machine's page and conversations open with one click.
 *
 * Secrets live in ~/.dsh/peer-link/state.json (mode 0600), never in the profile.
 */

export const name = 'peer-link';
export const inject = ['subagents', 'llm'];

export const Config = z.object({
  displayName: z.string().default('').description('本机在对端显示的名称；留空用主机名').volatile(),
  listen: z.boolean().default(true).description('接收对端请求（关闭后本机只能调用别人）').volatile(),
  host: z.string().default('0.0.0.0').description('监听地址；0.0.0.0 表示所有网卡').volatile(),
  port: z
    .natural()
    .max(65535)
    .default(0)
    .description('HTTP 端口；0 表示随机空闲端口（优先沿用上次的），对端通过局域网发现自动找到')
    .volatile(),
  discoveryPort: z
    .natural()
    .min(1)
    .max(65535)
    .default(DISCOVERY_PORT)
    .description('局域网发现用的 UDP 端口（共享绑定，不独占）；两侧必须一致')
    .volatile(),
  allowCidrs: z
    .string()
    .default('127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, ::1/128')
    .description('允许连入的地址段，逗号分隔')
    .volatile(),
  allowedRoots: z.string().default('').description('对端可用的工作目录根，分号或换行分隔；留空不限制').volatile(),
  remoteCwd: z.string().default('').description('委派给对端时的默认工作目录（对端机器上的绝对路径）；留空用对端默认目录').volatile(),
  subagentPeer: z.string().default('').description('subagent_peer 默认使用的对端名称；只配对一台时可留空').volatile(),
  permissionPreset: z
    .string()
    .default('')
    .description('对端发来的新会话使用的权限预设（如 danger-full-access）；留空沿用本机默认。无人值守时审批会卡住任务')
    .volatile(),
  delegationNote: z.boolean().default(true).description('在委派任务前附加"无人值守、请自行决策并汇报"的说明').volatile(),
  shareWeb: z
    .boolean()
    .default(true)
    .description('允许已配对的设备在局域网内打开本机的 DSH 网页界面（一次性链接进入，查看和操作本机的会话）')
    .volatile(),
});

const KEYS = Object.keys(Config.dict);
const unwrap = (value) =>
  value !== null && typeof value === 'object' && typeof value.get === 'function' ? value.get() : value;

function snapshot(config) {
  const plain = {};
  for (const key of KEYS) plain[key] = unwrap(config?.[key]);
  if (!plain.displayName) plain.displayName = defaultDisplayName();
  return plain;
}

const RUN_WAIT_DEFAULT_S = 600;
const FULL_ACCESS_PRESET = 'danger-full-access';

export function apply(ctx, config) {
  const state = new PeerState();
  state.load();
  const getConfig = () => snapshot(config);
  const ops = new SessionOps(ctx, getConfig, state);

  // ---- Web page sharing -----------------------------------------------------
  // The local DSH Web listener and its launch token, read on use: the
  // listener may come up after this plugin, and the token changes per launch.
  const webUpstream = () => {
    const webServer = ctx.get('webServer');
    const connection = ctx.get('connection');
    if (webServer === undefined || connection?.authenticatedUrl === undefined) return undefined;
    try {
      const origin = new URL(webServer.getOrigin()).origin;
      const authed = new URL(connection.authenticatedUrl(`${origin}/`));
      return { origin, tokenPath: authed.pathname + authed.search };
    } catch {
      return undefined;
    }
  };
  ops.web = new WebShare({
    enabled: () => getConfig().shareWeb !== false,
    upstream: webUpstream,
    secret: () => state.secret,
    logger: ctx.logger,
  });

  // ---- LAN listener and discovery ------------------------------------------
  let listener;
  let discovery;
  let appliedKey = '';
  let disposed = false;
  let queue = Promise.resolve();
  const sync = () => {
    queue = queue
      .then(async () => {
        const cfg = getConfig();
        const key = disposed ? 'disposed' : JSON.stringify([cfg.listen, cfg.host, cfg.port, cfg.discoveryPort, cfg.allowCidrs]);
        if (key === appliedKey) {
          // Only the display name may have changed.
          if (listener) state.writePairingCode(cfg.displayName, listener.port);
          return;
        }
        if (listener) await listener.close();
        discovery?.close();
        listener = undefined;
        discovery = undefined;
        appliedKey = key;
        if (disposed) return;

        discovery = new Discovery({ state, logger: ctx.logger, port: cfg.discoveryPort, allowCidrs: cfg.allowCidrs });
        await discovery.start();
        if (!cfg.listen) return;
        try {
          listener = await startServer({ ctx, ops, state, host: cfg.host, port: cfg.port || state.lastPort, allowCidrs: cfg.allowCidrs, web: ops.web });
        } catch (error) {
          appliedKey = '';
          ctx.logger.warn(`peer-link: cannot listen on ${cfg.host}:${cfg.port}: ${error.message}`);
          return;
        }
        state.lastPort = listener.port;
        discovery.setHttpPort(listener.port);
        const { hints } = state.writePairingCode(cfg.displayName, listener.port);
        ctx.logger.info(
          `peer-link: listening on ${listener.address}, discovery ${discovery.bound ? `udp/${discovery.port}` : 'unavailable'}; pairing code in ${PAIRING_FILE} (${hints.join(', ')})`,
        );
        await discovery.announce();
      })
      .catch((error) => ctx.logger.warn(`peer-link: ${error.message}`));
    return queue;
  };
  ctx.on('loader/volatile-update', () => {
    sync();
  });
  ctx.effect(() => {
    sync();
    return () => {
      disposed = true;
      return sync();
    };
  }, 'peer-link: LAN listener');

  // ---- Peer clients ---------------------------------------------------------
  const clientFor = (peerName) => new PeerClient(state, state.peer(peerName), ctx.logger, discovery);

  // ---- Subagent provider and its model route ------------------------------
  const adapter = new PeerModelAdapter({
    getConfig,
    clientFor,
    listPeerNames: () => state.peers().map((peer) => peer.name),
    links: new LinkStore(),
    ctx,
  });
  ctx.effect(() => ctx.llm.registerAdapter([PROVIDER], adapter), 'peer-link: model route');
  // Steering that reaches a child mid-turn is relayed to its running remote turn at once.
  ctx.on('agent/inbox/inserted', ({ agent, message }) => adapter.onInboxInserted(agent, message), { global: true });
  ctx.effect(() => ctx.subagents.registerProvider(new PeerSubagentProvider({ name: 'peer' })), 'peer-link: subagent provider');

  // ---- Operations shared by the tool and the settings page -----------------
  const selfInfo = () => ({
    name: getConfig().displayName,
    listening: listener?.address ?? null,
    discovery: discovery?.bound ? `udp/${discovery.port}` : null,
    pairingCodeFile: PAIRING_FILE,
  });

  async function probePeer(peer, signal) {
    const probe = await new PeerClient(state, peer, ctx.logger, discovery).probe();
    if (signal?.aborted) throw signal.reason;
    return { ...publicPeer(peer), online: probe.online, ...(probe.online ? { remote: probe.info } : { error: probe.error }) };
  }

  async function listPeers(signal) {
    const peers = await Promise.all(state.peers().map((peer) => probePeer(peer, signal)));
    return { self: selfInfo(), peers };
  }

  /** Pair from a code, or from the absolute path of a file holding one. */
  async function pair(input, signal, alias) {
    let code = String(input ?? '').trim();
    if (!code) throw new PeerError('BAD_INPUT', 'code is required');
    // A file path keeps the secret out of the conversation.
    if (!code.startsWith('dshpeer1.') && isAbsolute(code)) {
      if (!existsSync(code)) throw new PeerError('BAD_INPUT', `file not found: ${code}`);
      code = readFileSync(code, 'utf8').trim();
    }
    const peer = decodeCode(code);
    if (alias) peer.name = alias;
    if (peer.secret === state.secret) throw new PeerError('BAD_INPUT', 'this is the pairing code of this machine itself; use the other machine\'s code');
    if (listener === undefined) throw new PeerError('UNAVAILABLE', 'enable listening first so the peer can call back');
    const saved = state.upsertPeer(peer);
    const client = new PeerClient(state, saved, ctx.logger, discovery);
    const own = state.writePairingCode(getConfig().displayName, listener.port);
    const reply = await client.call('hello', { code: own.code }, { signal, timeoutMs: 8_000 });
    const probe = await client.probe();
    return { paired: saved.name, addr: client.peer.addr, reciprocal: reply.paired === true, remote: probe.info ?? probe.error };
  }

  /**
   * A one-time link to a peer's Web page. The browser connects to the
   * address this machine just reached the peer on, which is on the same LAN.
   * @param sessionId - the peer Session to open, when known.
   */
  async function openWeb(peerName, sessionId, signal) {
    const client = clientFor(peerName);
    const value = await client.call('webTicket', sessionId ? { sessionId } : {}, { signal, timeoutMs: 8_000 });
    return { peer: client.peer.name, url: `http://${client.peer.addr}${value.path}`, expiresIn: value.expiresIn };
  }

  /** The peer and remote Session behind a `subagent_peer` child, if it is one. */
  function remoteOf(childId) {
    const link = adapter.links.get(String(childId ?? ''));
    return link?.peer && link?.remote ? { peer: link.peer, session: link.remote } : null;
  }

  function unpair(name) {
    if (!name) throw new PeerError('BAD_INPUT', 'peer is required');
    return { removed: state.removePeer(name) };
  }

  // ---- Full-access prompt ---------------------------------------------------
  // Remote sessions run unattended, and on Windows the default sandbox cannot
  // even start PowerShell, so after installation the Client asks once whether
  // sessions peers start here get full access. Granting sets
  // `permissionPreset`, which the settings page can change later.
  const accessState = () => {
    const preset = getConfig().permissionPreset;
    return {
      decision: state.accessDecision ?? null,
      preset: preset || null,
      full: preset === FULL_ACCESS_PRESET,
      available: ctx.get('permissionPresets')?.catalog().options.some((option) => option.value === FULL_ACCESS_PRESET) ?? false,
    };
  };

  async function decideAccess(grant) {
    if (grant) {
      const settings = ctx.get('settings');
      if (settings === undefined) throw new PeerError('UNAVAILABLE', 'the settings service is not mounted; set permissionPreset on the settings page');
      await settings.mutate(ctx.fiber?.entry?.options?.id ?? 'peer-link', [{ op: 'set', path: ['permissionPreset'], value: FULL_ACCESS_PRESET }]);
    }
    state.accessDecision = grant ? 'granted' : 'declined';
    ctx.logger.info(`peer-link: full access for peer sessions ${grant ? 'granted' : 'declined'}`);
    return accessState();
  }

  // ---- Settings page --------------------------------------------------------
  // The page only reads this machine's own pairing code; it never pairs
  // without the user pasting the other side's code.
  const pageApi = {
    status: () => selfInfo(),
    peers: (_args, signal) => listPeers(signal),
    pairingCode: () => {
      if (listener === undefined) throw new PeerError('UNAVAILABLE', 'not listening; turn on "accept peer requests" first');
      return { code: state.writePairingCode(getConfig().displayName, listener.port).code, file: PAIRING_FILE };
    },
    pair: (args, signal) => pair(args.code, signal, typeof args.alias === 'string' ? args.alias.trim() : undefined),
    unpair: (args) => unpair(args.peer),
    presets: () => {
      const presets = ctx.get('permissionPresets');
      if (presets === undefined) return { options: [] };
      return { options: presets.catalog().options.map((option) => ({ value: option.value, name: option.name })) };
    },
    access: () => accessState(),
    decideAccess: (args) => decideAccess(args.grant === true),
    paired: () => ({ peers: state.peers().map(publicPeer) }),
    probe: (args, signal) => probePeer(clientFor(args.peer).peer, signal),
    openWeb: (args, signal) => openWeb(args.peer, typeof args.session === 'string' ? args.session : undefined, signal),
    remoteOf: (args) => remoteOf(args.session),
  };
  ctx.inject(['webServer', 'connection'], (web) => {
    web.effect(() => web.webServer.register(webRoute(web.connection, pageApi)), `peer-link: POST ${RPC_PATH}`);
  });

  // ---- Model-facing tool --------------------------------------------------
  const handlers = {
    peers: (_args, exec) => listPeers(exec.signal),
    pair: (args, exec) => pair(args.code, exec.signal, args.peer),
    unpair: (args) => unpair(args.peer),
    async sessions(args, exec) {
      return clientFor(args.peer).call('sessions', { limit: args.limit }, { signal: exec.signal });
    },
    async read(args, exec) {
      if (!args.session_id) throw new PeerError('BAD_INPUT', 'session_id is required');
      return clientFor(args.peer).call('read', { sessionId: args.session_id, limit: args.limit }, { signal: exec.signal });
    },
    async cancel(args, exec) {
      if (!args.session_id) throw new PeerError('BAD_INPUT', 'session_id is required');
      return clientFor(args.peer).call('cancel', { sessionId: args.session_id }, { signal: exec.signal });
    },
    async run(args, exec) {
      if (!args.prompt) throw new PeerError('BAD_INPUT', 'prompt is required');
      const client = clientFor(args.peer);
      const cfg = getConfig();
      const started = await client.call(
        'run',
        {
          prompt: args.prompt,
          sessionId: args.session_id,
          cwd: args.cwd ?? (args.session_id ? undefined : cfg.remoteCwd || undefined),
          cwdCandidates: [exec.agent?.session?.header?.cwd],
          from: cfg.displayName,
          preface: !args.session_id,
          answerQuestions: Boolean(args.session_id),
        },
        { signal: exec.signal, timeoutMs: 60_000 },
      );
      const waitSeconds = Math.min(Math.max(Number(args.wait_seconds ?? RUN_WAIT_DEFAULT_S), 0), 3600);
      if (waitSeconds === 0) return { peer: client.peer.name, session_id: started.sessionId, status: started.answered ? 'answered' : 'started' };
      const window = new AbortController();
      const timer = setTimeout(() => window.abort(), waitSeconds * 1000);
      const onAbort = () => window.abort();
      exec.signal.addEventListener('abort', onAbort, { once: true });
      let last;
      try {
        const result = await followRun(client, started, window.signal, (status) => {
          last = status;
        });
        if (window.signal.aborted && !exec.signal.aborted) {
          return {
            peer: client.peer.name,
            session_id: started.sessionId,
            status: 'still-running',
            note: `not finished after ${waitSeconds}s; check later with action=read`,
            questions: last?.questions,
          };
        }
        if (exec.signal.aborted) {
          await client.call('cancel', { sessionId: started.sessionId }, { timeoutMs: 8_000 }).catch(() => undefined);
          throw exec.signal.reason ?? new Error('aborted');
        }
        return {
          peer: client.peer.name,
          session_id: started.sessionId,
          status: result.stopReason,
          ...(result.diagnostic ? { error: result.diagnostic } : {}),
          reply: result.output.map((block) => block.text).join('\n'),
        };
      } finally {
        clearTimeout(timer);
        exec.signal.removeEventListener('abort', onAbort);
      }
    },
  };

  ctx.inject(['tools'], (child) => {
    child.tools.register({
      name: 'peer_dsh',
      description:
        'Work with paired DeepSeek Harness instances on other machines (e.g. a Windows PC). Each remote Session is a full agent with that machine\'s shell, files, and tools. ' +
        'action=peers lists paired peers with online status; pair adds a peer from its pairing code; unpair removes one; ' +
        'run sends a prompt to a new remote Session (or continues session_id) and waits for the reply; ' +
        'sessions lists recent remote Sessions; read returns a Session\'s latest messages; cancel stops its running turn. ' +
        'For delegation prefer the subagent_peer tool, whose children you continue with send_message; use run for remote Sessions started elsewhere. ' +
        'When a remote Session waits on a question, run on its session_id passes the prompt on as the answer.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['peers', 'pair', 'unpair', 'run', 'sessions', 'read', 'cancel'] },
          peer: { type: 'string', description: 'Peer name; optional when exactly one peer is paired. pair: optional local alias.' },
          prompt: { type: 'string', description: 'run: the complete task or reply. The remote agent does not see this conversation.' },
          session_id: { type: 'string', description: 'run: continue this remote Session instead of starting one; read/cancel: target Session.' },
          cwd: { type: 'string', description: 'run (new Session only): absolute working directory on the peer machine.' },
          wait_seconds: { type: 'number', description: 'run: seconds to wait for the turn to finish (default 600, 0 returns immediately).' },
          limit: { type: 'number', description: 'sessions/read: number of items (default 15 / 10).' },
          code: { type: 'string', description: 'pair: the peer\'s pairing code (dshpeer1.…) or the absolute path of a file containing it.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object' },
        render: (_args, value) => [{ type: 'text', text: typeof value?.reply === 'string' ? `${value.reply}\n\n${JSON.stringify({ ...value, reply: undefined }, null, 2)}` : JSON.stringify(value, null, 2) }],
      },
      isConcurrencySafe: () => true,
      async execute(args, exec) {
        const handler = handlers[args.action];
        if (handler === undefined) throw new PeerError('BAD_INPUT', `unknown action ${args.action}`);
        return handler(args, exec);
      },
    });
  });
}
