import { questionsNote, openQuestions, waitRemote } from './provider.js';

/**
 * `peer-link` LLM route: the "model" of a `subagent_peer` child is a Session
 * in the paired peer's DSH.
 *
 * Each agent-loop request forwards the child's user-role messages that the
 * remote side has not seen yet (the task, later `send_message` follow-ups,
 * human prompts typed into the child) to one remote Session per child, waits
 * for that remote turn, and answers with the remote agent's final text. The
 * child therefore continues like any local subagent: `send_message` steers or
 * wakes it, stop cancels the remote turn, and the mapping in links.json
 * survives restarts.
 *
 * Messages steered into the child while a remote turn runs are relayed at
 * once (steering the remote turn), so the parent never waits for one turn
 * before the next instruction arrives. When the remote agent left a question
 * unanswered, the next forwarded message answers it.
 *
 * Model ids: `auto` (the configured default peer, or the only one) or a peer name.
 */

export const PROVIDER = 'peer-link';
const AUTO = 'auto';
/** Generous on purpose: the local transcript only mirrors short relay text. */
const CONTEXT_WINDOW = 1_000_000;
/** User-role message sources that belong to the conversation: the task, human prompts, and `send_message`. */
const RELAY_SOURCES = new Set(['user', 'agent-message']);
const GUIDANCE_PREFIX = 'Your parent agent id is ';
const RELAY_PREFIX = /^Agent \S+ sent a message: ?$/;

class PeerRouteError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
    // The LLM runtime keeps `failure` when its code matches, so the code survives normalization.
    this.failure = { message, code };
  }
}

function textOfMessage(message) {
  const parts = [];
  for (const block of message.content ?? []) {
    if (block?.type === 'text' && typeof block.text === 'string') {
      if (block.text.startsWith(GUIDANCE_PREFIX) || RELAY_PREFIX.test(block.text)) continue;
      parts.push(block.text);
    } else if (block?.type === 'image' || block?.type === 'file') {
      parts.push(`[${block.type} attachment not forwarded]`);
    }
  }
  return parts.join('\n').trim();
}

/** Whether a message is conversation for the remote side rather than this machine's context. */
const isRelayable = (message) => message?.role === 'user' && RELAY_SOURCES.has(message.source?.kind);

/** User-role messages after the last assistant message that the remote has not received. */
function unsentMessages(messages, forwarded) {
  const sent = new Set(forwarded ?? []);
  const fresh = [];
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    if (message.role === 'assistant') break;
    if (!isRelayable(message) || sent.has(message.id)) continue;
    fresh.unshift(message);
  }
  return fresh;
}


/** The subagent's display label, from its descriptor event. */
function labelOf(child) {
  try {
    return child?.session?.snapshotEvents?.().find((event) => event.type === 'subagent/descriptor')?.data?.label;
  } catch {
    return undefined;
  }
}

function describeSend(peer, started) {
  if (started.created) return `→ ${peer}: new remote session ${started.sessionId}`;
  if (started.answered) return `→ ${peer}: answered its pending question`;
  return started.mode === 'steer' ? `→ ${peer}: steered the running turn` : `→ ${peer}: sent to session ${started.sessionId}`;
}

function* textBlock(index, type, text) {
  yield { type: 'block-start', index, blockType: type };
  yield { type: type === 'text' ? 'text-delta' : 'reasoning-delta', index, text };
  yield { type: 'block-end', index, block: { type, text } };
}

export class PeerModelAdapter {
  /**
   * @param getConfig - live plugin config snapshot.
   * @param clientFor - peer name (or undefined for the only peer) → PeerClient.
   * @param listPeerNames - paired peer names for the model list.
   * @param links - LinkStore.
   * @param ctx - plugin context: the agents registry and logger.
   */
  constructor({ getConfig, clientFor, listPeerNames, links, ctx }) {
    this.getConfig = getConfig;
    this.clientFor = clientFor;
    this.listPeerNames = listPeerNames;
    this.links = links;
    this.ctx = ctx;
    /** Child id → the remote turn its current request is waiting on. */
    this.live = new Map();
  }

  providerInfo(provider) {
    return { id: provider, name: 'DSH 互联（对端执行）' };
  }

  providerRetryPolicy() {
    return undefined;
  }

  imageRequestPricing() {
    return undefined;
  }

  imageRequestTarget(_provider, _model, image) {
    return { width: image.width, height: image.height, maxBytes: image.bytes };
  }

  modelInfo(provider, id) {
    return {
      provider,
      id,
      name: id === AUTO ? 'Default peer' : `Peer ${id}`,
      description: 'Runs each turn as a complete agent in the paired peer DSH.',
      context: { contextWindow: CONTEXT_WINDOW },
      inputModalities: ['text'],
    };
  }

  listModels(provider) {
    return Promise.resolve([AUTO, ...this.listPeerNames()].map((id) => this.modelInfo(provider, id)));
  }

  resolveModel(provider, model) {
    if (typeof model !== 'string' || model === '') throw new PeerRouteError('peer-link model must name a peer or "auto"', 'UNKNOWN_MODEL');
    return Promise.resolve(this.modelInfo(provider, model));
  }

  async prepareCall(provider, model, signal) {
    return { model: await this.resolveModel(provider, model, signal), stream: (options) => this.stream(options) };
  }

  stream(options) {
    if (options.purpose !== undefined) return this.auxiliary(options);
    return this.relay(options);
  }

  /** Compaction, titles, and other side requests stay local: the conversation lives remotely. */
  async *auxiliary(options) {
    const link = options.sessionId === undefined ? undefined : this.links.get(options.sessionId);
    const text =
      options.purpose === 'compaction'
        ? `This conversation is relayed to remote session ${link?.remote ?? '(not started)'} on peer ${link?.peer ?? '(unknown)'}; the remote session keeps the full history.`
        : (labelOf(this.ctx.get('agents')?.get(options.sessionId)) ?? 'Peer task');
    yield* textBlock(0, 'text', text);
    yield { type: 'finish', reason: { kind: 'stop' } };
  }

  async *relay(options) {
    const { signal } = options;
    const childId = options.sessionId;
    if (!childId) throw new PeerRouteError('peer-link requests need a session id', 'BAD_REQUEST');
    const child = this.ctx.get('agents')?.get(childId);
    const config = this.getConfig();

    let link = this.links.get(childId);
    const peerName = link?.peer ?? (options.model === AUTO ? config.subagentPeer || undefined : options.model);
    let client;
    try {
      client = this.clientFor(peerName);
    } catch (error) {
      throw new PeerRouteError(error.message, 'NO_PEER');
    }
    const peer = client.peer.name;
    let index = 0;
    // A reply held back for the step that admits a live-relayed message (see below).
    const carried = link?.carry;

    // ---- Forward what the remote side has not seen -------------------------
    const fresh = unsentMessages(options.messages ?? [], link?.forwarded);
    const prompt = fresh.map(textOfMessage).filter(Boolean).join('\n\n');
    if (prompt) {
      let started;
      try {
        started = await this.send(client, link, prompt, { signal, child, steer: link?.pending != null });
      } catch (error) {
        if (error.code !== 'REMOTE_SESSION_GONE' || !link?.remote) throw error;
        // The remote Session was deleted: start a new one rather than failing every later turn.
        link = this.links.update(childId, { remote: undefined, pending: null });
        started = await this.send(client, link, prompt, { signal, child, steer: false });
      }
      link = this.links.update(childId, {
        peer,
        remote: started.sessionId,
        forwarded: [...(link?.forwarded ?? []), ...fresh.map((message) => message.id)],
        pending: { startSeq: started.startSeq, requestId: started.requestId },
      });
      yield* textBlock(index++, 'reasoning', describeSend(peer, started));
    } else if (link?.pending == null) {
      // Every new message was relayed live: answer with the reply held back for this step.
      this.links.update(childId, { carry: undefined });
      yield* textBlock(index++, 'text', carried ?? `[peer-link] nothing new to send to ${peer}.`);
      yield { type: 'finish', reason: { kind: 'stop' } };
      return;
    }

    // ---- Relay live steering, then wait for the remote turn ----------------
    const target = { sessionId: link.remote, ...link.pending };
    const live = { client, target, queue: [], relaying: Promise.resolve(), notes: [], relayed: 0, signal };
    this.live.set(childId, live);
    const replies = [];
    let status;
    try {
      for (;;) {
        status = await waitRemote(client, target, signal);
        // Let relays started while waiting finish, including ones queued meanwhile.
        for (let settled; settled !== live.relaying; ) {
          settled = live.relaying;
          await settled;
        }
        if (status.aborted || status.lost || status.target.requestId === target.requestId) break;
        // A message was relayed just as that turn settled: also wait for the turn that saw it.
        if (status.finalText) replies.push(status.finalText);
      }
    } finally {
      this.live.delete(childId);
    }
    for (const note of live.notes) yield* textBlock(index++, 'reasoning', note);

    if (status.aborted) {
      // A disposed child (shutdown, reload) leaves the remote turn running and waits for it on resume.
      if (signal.reason?.kind !== 'disposed') {
        this.links.update(childId, { pending: null });
        client.call('cancel', { sessionId: target.sessionId }, { timeoutMs: 8_000 }).catch((error) => {
          this.ctx.logger.warn(`peer-link: cancel ${target.sessionId} on ${peer} failed: ${error.message}`);
        });
      }
      throw new PeerRouteError(`stopped; remote session ${target.sessionId} on ${peer}`, 'ABORTED');
    }
    if (status.lost) {
      // `pending` stays, so a retried request resumes waiting for the same remote turn.
      throw new PeerRouteError(`lost contact with ${peer} (${status.lost.message}); remote session ${target.sessionId} may still be running`, 'TRANSPORT');
    }
    this.links.update(childId, { pending: null });
    if (status.finalText) replies.push(status.finalText);
    const lines = [...(carried ? [carried] : []), ...replies];
    if (status.stopReason !== 'completed') lines.push(`[peer-link] the remote turn ended: ${status.stopReason}${status.error ? ` — ${status.error}` : ''}`);
    const note = questionsNote(openQuestions(status), 'Answer with send_message to this subagent; the reply is passed on as the answer.');
    if (note) lines.push(note);
    lines.push(`[peer-link] remote session ${target.sessionId} on ${peer}`);
    const reply = lines.join('\n\n');
    if (live.relayed > 0) {
      // The relayed message is admitted only after this step; the step that follows it
      // answers with this reply, so the transcript (and the parent's notice) stays in order.
      this.links.update(childId, { pending: null, carry: reply });
      yield* textBlock(index++, 'reasoning', 'The reply follows the relayed message.');
    } else {
      this.links.update(childId, { pending: null, carry: undefined });
      yield* textBlock(index++, 'text', reply);
    }
    yield { type: 'finish', reason: { kind: 'stop' } };
  }

  /**
   * `agent/inbox/inserted` from any Agent: a message steered into a child whose
   * remote turn is running goes to that turn now. Queued next-turn messages
   * wait for the child's next request.
   */
  onInboxInserted(agent, message) {
    const live = this.live.get(agent?.id);
    if (live === undefined || !isRelayable(message)) return;
    if (!agent.inbox?.nextStep?.some((item) => item.id === message.id)) return;
    if ((this.links.get(agent.id)?.forwarded ?? []).includes(message.id)) return;
    live.queue.push(message);
    live.relaying = live.relaying.then(() => this.relayLive(agent.id, live));
  }

  /** Start the child's remote Session, or continue it (answering pending questions first). */
  async send(client, link, prompt, { signal, child, steer }) {
    const config = this.getConfig();
    try {
      return await client.call(
        'run',
        link?.remote
          ? { prompt, sessionId: link.remote, from: config.displayName, mode: steer ? 'steer' : 'queue', answerQuestions: true }
          : {
              prompt,
              label: labelOf(child) ?? prompt.slice(0, 40),
              cwd: config.remoteCwd || undefined,
              cwdCandidates: [child?.session?.header?.cwd],
              from: config.displayName,
              preface: true,
            },
        { signal, timeoutMs: 60_000 },
      );
    } catch (error) {
      if (signal.aborted) throw new PeerRouteError('stopped before the peer accepted the message', 'ABORTED');
      if (error?.code === 'UNREACHABLE') throw new PeerRouteError(error.message, 'TRANSPORT');
      throw new PeerRouteError(error.message, error?.code === 'NOT_FOUND' ? 'REMOTE_SESSION_GONE' : 'PEER_ERROR');
    }
  }

  /** Steer messages that arrived mid-turn into the remote turn and follow the newest request. */
  async relayLive(childId, live) {
    const batch = live.queue.splice(0);
    if (batch.length === 0 || live.signal.aborted) return;
    const prompt = batch.map(textOfMessage).filter(Boolean).join('\n\n');
    if (!prompt) return;
    try {
      const link = this.links.get(childId);
      const started = await this.send(live.client, link, prompt, { signal: live.signal, steer: true });
      this.links.update(childId, {
        forwarded: [...(link?.forwarded ?? []), ...batch.map((message) => message.id)],
        pending: { startSeq: started.startSeq, requestId: started.requestId },
      });
      // Moving the target makes the wait settle on the turn that saw this message.
      live.target.startSeq = started.startSeq;
      live.target.requestId = started.requestId;
      live.relayed += 1;
      live.notes.push(describeSend(live.client.peer.name, started));
    } catch (error) {
      // Left unforwarded: the child's next request sends it.
      this.ctx.logger.warn(`peer-link: live relay to ${live.client.peer.name} failed: ${error.message}`);
    }
  }
}
