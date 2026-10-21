/**
 * `peer` subagent backend. Each child is an ordinary continuable local Agent
 * whose model route is `peer-link` (see peer-model.js): its turns run in the
 * paired peer's DSH, while `send_message`, steering, stop, and cold resume
 * work exactly as for any local subagent.
 *
 * Also the shared poll loop for remote runs, used by that route and by the
 * `peer_dsh` tool's `run`.
 */

const CAPABILITIES = Object.freeze({ agentOptions: true, agentPreset: false, outputSchema: false, depthLimit: false });
/** Consecutive unreachable polls tolerated before the run is reported as lost. */
const MAX_POLL_FAILURES = 20;

const STOP_REASONS = new Set(['completed', 'aborted', 'error', 'max-tokens', 'refusal']);

function diagnosticOf(text) {
  const value = String(text ?? '');
  return Buffer.byteLength(value) > 4000 ? `${value.slice(0, 1300)}…` : value;
}

/** Questions the remote agent is waiting on, with how to answer them. */
export function questionsNote(questions, howToReply) {
  if (!questions?.length) return undefined;
  const lines = questions.flatMap((item) =>
    (item.questions ?? []).map((q) => `- ${q.question ?? q.header ?? q.id}${q.options?.length ? ` (options: ${q.options.map((o) => o.label).join(' / ')})` : ''}`),
  );
  return `The remote agent is waiting for an answer:\n${lines.join('\n')}\n${howToReply}`;
}

export const openQuestions = (status) => status?.questions?.filter((q) => q.state === 'continued' || q.state === 'open') ?? [];

/**
 * Poll the remote run until it settles. `target` ({ sessionId, startSeq,
 * requestId? }) is read on every poll, so a caller may move it to a newer
 * request while waiting; a settlement only counts for the request it was asked about.
 * @returns the final status with `target` set to the request it settled,
 *   `{ aborted: true }`, or `{ lost: error }` after too many failed polls.
 */
export async function waitRemote(client, target, signal, onProgress) {
  let failures = 0;
  for (;;) {
    if (signal.aborted) return { aborted: true };
    const asked = { ...target };
    let status;
    try {
      status = await client.call(
        'wait',
        { sessionId: asked.sessionId, startSeq: asked.startSeq, requestId: asked.requestId, timeoutMs: 25_000 },
        { signal, timeoutMs: 40_000 },
      );
      failures = 0;
    } catch (error) {
      if (signal.aborted) continue;
      failures += 1;
      if (failures >= MAX_POLL_FAILURES) return { lost: error };
      await new Promise((resolve) => setTimeout(resolve, Math.min(1000 * failures, 10_000)));
      continue;
    }
    onProgress?.(status);
    if (status.done && target.requestId === asked.requestId) return { ...status, target: asked };
  }
}

/**
 * Poll the remote run to settlement for the `peer_dsh` tool.
 * @returns a SubagentResult-compatible object.
 */
export async function followRun(client, started, signal, onProgress) {
  const status = await waitRemote(client, { sessionId: started.sessionId, startSeq: started.startSeq, requestId: started.requestId }, signal, onProgress);
  if (status.aborted) {
    return { output: [], stopReason: 'aborted', diagnostic: `cancelled; remote session ${started.sessionId} on ${client.peer.name}` };
  }
  if (status.lost) {
    return {
      output: [],
      stopReason: 'error',
      diagnostic: diagnosticOf(`lost contact with ${client.peer.name} (${status.lost.message}); remote session ${started.sessionId} may still be running`),
    };
  }
  const note = questionsNote(openQuestions(status), 'Reply with peer_dsh action=run on the same session_id; the reply is passed on as the answer.');
  const stopReason = STOP_REASONS.has(status.stopReason) ? status.stopReason : status.stopReason === 'blocked' ? 'refusal' : 'error';
  const footer = `\n\n[peer-link] remote session ${started.sessionId} on ${client.peer.name}${note ? `\n${note}` : ''}`;
  return {
    output: [{ type: 'text', text: `${status.finalText ?? ''}${footer}` }],
    stopReason,
    ...(status.error ? { diagnostic: diagnosticOf(status.error) } : {}),
  };
}

export class PeerSubagentProvider {
  constructor({ name }) {
    this.name = name;
    this.capabilities = CAPABILITIES;
    this.inheritsParentContext = false;
  }

  /** A fresh child with no inherited history; the patch routes it to `peer-link`. */
  prepareContinuable() {
    return Promise.resolve({});
  }
}
