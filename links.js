import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { STATE_DIR, writePrivate } from './state.js';

/**
 * Which remote Session continues each `subagent_peer` child, kept in
 * ~/.dsh/peer-link/links.json so a child still reaches the same remote Session
 * after an interrupted turn or a restart:
 *
 *   { links: { <child session id>: { peer, remote, forwarded: [message ids], pending, updatedAt } } }
 *
 * `forwarded` lists the child messages already relayed, so a retry or the
 * step that admits a live-relayed message does not send it twice. `pending`
 * is the remote request still awaited (`{ startSeq, requestId? }`) or null.
 */

const LINKS_FILE = join(STATE_DIR, 'links.json');
const MAX_LINKS = 500;
const MAX_FORWARDED = 200;

export class LinkStore {
  constructor(file = LINKS_FILE) {
    this.file = file;
    this.links = undefined;
  }

  load() {
    if (this.links !== undefined) return this.links;
    try {
      const parsed = JSON.parse(readFileSync(this.file, 'utf8'));
      this.links = new Map(Object.entries(parsed?.links ?? {}));
    } catch {
      this.links = new Map();
    }
    return this.links;
  }

  get(childId) {
    return this.load().get(childId);
  }

  /** Merge `patch` into a child's link, keeping the most recently used links. */
  update(childId, patch) {
    const links = this.load();
    const next = { ...links.get(childId), ...patch, updatedAt: Date.now() };
    if (next.forwarded?.length > MAX_FORWARDED) next.forwarded = next.forwarded.slice(-MAX_FORWARDED);
    links.delete(childId);
    links.set(childId, next);
    while (links.size > MAX_LINKS) links.delete(links.keys().next().value);
    writePrivate(this.file, `${JSON.stringify({ links: Object.fromEntries(links) }, null, 2)}\n`);
    return next;
  }
}
