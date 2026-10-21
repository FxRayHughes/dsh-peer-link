import { randomUUID } from 'node:crypto';
import { PeerError } from './protocol.js';

/**
 * External subagent backend: each child is a complete agent in the paired
 * peer's DSH. `start()` opens a Session there, and the run settles when the
 * remote turn ends. The child keeps its remote Session, so the `peer_dsh`
 * tool's `run` can continue it later by session id.
 */

const NO_CAPABILITIES = Object.freeze({ agentOptions: false, agentPreset: false, outputSchema: false, depthLimit: false });
/** Consecutive unreachable polls tolerated before the run is reported as failed. */
const MAX_POLL_FAILURES = 20;

const STOP_REASONS = new Set(['completed', 'aborted', 'error', 'max-tokens', 'refusal']);

function diagnosticOf(text) {
  const value = String(text ?? '');
  return Buffer.byteLength(value) > 4000 ? `${value.slice(0, 1300)}…` : value;
}

function questionsNote(questions) {
  if (!questions?.length) return undefined;
  const lines = questions.flatMap((item) =>
    (item.questions ?? []).map((q) => `- ${q.question ?? q.header ?? q.id}${q.options?.length ? ` (options: ${q.options.map((o) => o.label).join(' / ')})` : ''}`),
  );
  return `The remote agent is waiting for an answer:\n${lines.join('\n')}\nReply with peer_dsh action=run on the same session_id.`;
}

/**
 * Poll the remote run to settlement.
 * @returns a SubagentResult-compatible object.
 */
export async function followRun(client, started, signal, onProgress) {
  let failures = 0;
  for (;;) {
    if (signal.aborted) {
      return { output: [], stopReason: 'aborted', diagnostic: `cancelled; remote session ${started.sessionId} on ${client.peer.name}` };
    }
    let status;
    try {
      status = await client.call(
        'wait',
        { sessionId: started.sessionId, startSeq: started.startSeq, requestId: started.requestId, timeoutMs: 25_000 },
        { signal, timeoutMs: 40_000 },
      );
      failures = 0;
    } catch (error) {
      if (signal.aborted) continue;
      failures += 1;
      if (failures >= MAX_POLL_FAILURES) {
        return {
          output: [],
          stopReason: 'error',
          diagnostic: diagnosticOf(`lost contact with ${client.peer.name} (${error.message}); remote session ${started.sessionId} may still be running`),
        };
      }
      await new Promise((resolve) => setTimeout(resolve, Math.min(1000 * failures, 10_000)));
      continue;
    }
    onProgress?.(status);
    const note = questionsNote(status.questions?.filter((q) => q.state === 'continued' || q.state === 'open'));
    if (status.done) {
      const stopReason = STOP_REASONS.has(status.stopReason) ? status.stopReason : status.stopReason === 'blocked' ? 'refusal' : 'error';
      const text = status.finalText ?? '';
      const footer = `\n\n[peer-link] remote session ${started.sessionId} on ${client.peer.name}${note ? `\n${note}` : ''}`;
      return {
        output: [{ type: 'text', text: `${text}${footer}` }],
        stopReason,
        ...(status.error ? { diagnostic: diagnosticOf(status.error) } : {}),
      };
    }
  }
}

export class PeerSubagentProvider {
  /** @param clientFor - resolves a peer name (or the only peer) to a PeerClient. */
  constructor({ name, getConfig, clientFor, logger }) {
    this.name = name;
    this.getConfig = getConfig;
    this.clientFor = clientFor;
    this.logger = logger;
    this.capabilities = NO_CAPABILITIES;
    this.inheritsParentContext = false;
  }

  /** @param {import('@deepseek-ai/dsh-subagent').ResolvedSubagentStartRequest} request */
  async start(request) {
    const config = this.getConfig();
    const client = this.clientFor(config.subagentPeer || undefined);
    const peer = client.peer;
    const prompt = request.prompt
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n')
      .trim();
    if (!prompt) throw new PeerError('BAD_INPUT', 'remote subagents accept text prompts only');
    // The parent's cwd is a path on this machine. The peer uses it only when
    // that directory also exists there; otherwise it falls back to its default.
    const started = await client.call(
      'run',
      {
        prompt,
        label: request.label,
        cwd: config.remoteCwd || undefined,
        cwdCandidates: [request.cwd],
        from: config.displayName,
        preface: true,
      },
      { signal: request.signal, timeoutMs: 60_000 },
    );

    const controller = new AbortController();
    const cancelRemote = () => {
      controller.abort();
      client.call('cancel', { sessionId: started.sessionId }, { timeoutMs: 8_000 }).catch((error) => {
        this.logger.warn(`peer-link: cancel ${started.sessionId} on ${peer.name} failed: ${error.message}`);
      });
    };
    const onAbort = () => cancelRemote();
    request.signal.addEventListener('abort', onAbort, { once: true });

    const result = followRun(client, started, controller.signal).finally(() => {
      request.signal.removeEventListener('abort', onAbort);
    });
    let disposal;
    let settled = false;
    result.then(() => {
      settled = true;
    }, () => {
      settled = true;
    });
    return {
      // Distinct from the remote Session id so it can never collide with a
      // Session that this DSH also knows (e.g. when a peer points at itself).
      id: `peer-${peer.name}-${randomUUID()}`,
      result,
      dispose() {
        if (disposal !== undefined) return disposal;
        if (!settled) cancelRemote();
        disposal = result.then(() => undefined, () => undefined);
        return disposal;
      },
    };
  }
}
