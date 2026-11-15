import { createReadStream } from 'node:fs';
import { mkdir, readdir, realpath, stat } from 'node:fs/promises';
import { homedir, hostname, platform } from 'node:os';
import { basename, dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';
import { PeerError } from './protocol.js';

/**
 * File operations for a browser that is not sitting at this machine.
 *
 * DSH's own "open folder", "open with", and directory picker act on the Host
 * desktop. Through peer-link's web share or the FRP tunnel that desktop is the
 * other machine's, so a click there launches an app nobody is looking at. The
 * relays mark such requests with `x-dsh-remote-viewer`, and the Client offers
 * these instead: an in-page directory browser, and downloads of a file or a
 * whole folder (as zip) to the device the browser runs on.
 *
 * The same functions back the signed `files.*` peer ops, so a `subagent_peer`
 * child's files on the peer can be previewed and downloaded here.
 *
 * Everything is read-only except `mkdir`, which creates one child directory
 * (the directory picker's "New folder").
 */

export const VIEWER_HEADER = 'x-dsh-remote-viewer';
export const FILE_PATH = '/peer-link/file';
export const ZIP_PATH = '/peer-link/zip';

const MAX_ENTRIES = 1000;
const MAX_PREVIEW_BYTES = 24 * 1024 * 1024;
const ZIP_MAX_FILES = 20_000;
const ZIP_MAX_BYTES = 4 * 1024 * 1024 * 1024 - 1; // stored zip without zip64
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', '__pycache__', '.venv', '.gradle', '.idea', '.next', 'dist-electron']);

const MIME = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml', bmp: 'image/bmp', ico: 'image/x-icon', avif: 'image/avif',
  pdf: 'application/pdf', json: 'application/json', zip: 'application/zip', mp4: 'video/mp4', mp3: 'audio/mpeg', wav: 'audio/wav', webm: 'video/webm',
  txt: 'text/plain', md: 'text/markdown', html: 'text/html', htm: 'text/html', css: 'text/css', js: 'text/javascript', csv: 'text/csv', xml: 'application/xml',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

export function mimeOf(path) {
  const ext = parse(path).ext.slice(1).toLowerCase();
  return MIME[ext] ?? 'application/octet-stream';
}

/** Absolute, normalized path; relative ones resolve against `base`. */
function absolute(path, base) {
  const value = String(path ?? '').trim();
  if (!value) throw new PeerError('BAD_INPUT', 'path is required');
  if (value.includes('\0')) throw new PeerError('BAD_INPUT', 'invalid path');
  if (isAbsolute(value)) return resolve(value);
  if (!base) throw new PeerError('BAD_INPUT', `path must be absolute on ${hostname()}`);
  return resolve(base, value);
}

function hiddenName(name) {
  return name.startsWith('.');
}

/** Roots the browser starts from: home, and on Windows every present drive. */
async function roots() {
  const list = [{ name: homedir(), path: homedir() }];
  if (platform() === 'win32') {
    for (const letter of 'CDEFGHIJKLMNOPQRSTUVWXYZ') {
      const drive = `${letter}:\\`;
      try {
        await stat(drive);
        list.push({ name: drive, path: drive });
      } catch {
        // Not present.
      }
    }
  } else {
    list.push({ name: '/', path: '/' });
  }
  return list;
}

function crumbsOf(path) {
  const { root } = parse(path);
  const crumbs = [{ name: root, path: root }];
  let current = root;
  for (const part of path.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, part);
    crumbs.push({ name: part, path: current });
  }
  return crumbs;
}

/**
 * One directory level: folders first, then files, name-sorted.
 * @param args.path - absolute directory; absent lists the home directory.
 * @param args.dirsOnly - leave files out (directory picking).
 */
export async function listDir(args = {}) {
  const path = args.path ? absolute(args.path, args.base) : homedir();
  let info;
  try {
    info = await stat(path);
  } catch (error) {
    throw new PeerError('NOT_FOUND', `${path}: ${error.code === 'ENOENT' ? 'not found' : error.message}`, 404);
  }
  if (!info.isDirectory()) throw new PeerError('BAD_INPUT', `${path} is not a directory`);
  let dirents;
  try {
    dirents = await readdir(path, { withFileTypes: true });
  } catch (error) {
    throw new PeerError('FORBIDDEN', `${path}: ${error.code === 'EACCES' || error.code === 'EPERM' ? 'permission denied' : error.message}`, 403);
  }
  const entries = [];
  for (const dirent of dirents) {
    const full = join(path, dirent.name);
    let dir = dirent.isDirectory();
    let size;
    let mtime;
    if (dirent.isSymbolicLink() || !dir || args.details) {
      try {
        const target = await stat(full);
        dir = target.isDirectory();
        if (!dir && !target.isFile()) continue;
        size = dir ? undefined : target.size;
        mtime = target.mtimeMs;
      } catch {
        continue; // broken link or unreadable
      }
    }
    if (args.dirsOnly && !dir) continue;
    entries.push({ name: dirent.name, path: full, dir, hidden: hiddenName(dirent.name), ...(size === undefined ? {} : { size }), ...(mtime === undefined ? {} : { mtime }) });
  }
  entries.sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }) : a.dir ? -1 : 1));
  const truncated = entries.length > MAX_ENTRIES;
  return {
    host: hostname(),
    platform: platform(),
    sep,
    path,
    parent: dirname(path) === path ? null : dirname(path),
    home: homedir(),
    crumbs: crumbsOf(path),
    roots: await roots(),
    entries: truncated ? entries.slice(0, MAX_ENTRIES) : entries,
    truncated,
  };
}

/** Create one child directory; `name` is a single path segment. */
export async function makeDir(args = {}) {
  const parent = absolute(args.path);
  const name = String(args.name ?? '').trim();
  if (!name || name === '.' || name === '..' || /[/\\\0]/.test(name)) throw new PeerError('BAD_INPUT', 'folder name must be a single path segment');
  const target = join(parent, name);
  try {
    await mkdir(target);
  } catch (error) {
    if (error.code === 'EEXIST') throw new PeerError('EXISTS', `${target} already exists`, 409);
    throw new PeerError('FAILED', `${target}: ${error.message}`);
  }
  return { path: target };
}

/** Metadata of one path. */
export async function statPath(args = {}) {
  const path = absolute(args.path, args.base);
  let info;
  try {
    info = await stat(path);
  } catch (error) {
    throw new PeerError('NOT_FOUND', `${path}: ${error.code === 'ENOENT' ? 'not found' : error.message}`, 404);
  }
  return { path, name: basename(path) || path, dir: info.isDirectory(), size: info.isFile() ? info.size : undefined, mtime: info.mtimeMs, mime: info.isFile() ? mimeOf(path) : undefined, host: hostname() };
}

/**
 * Bytes of one file for a peer's preview, as base64 inside the signed reply.
 * Bounded so a reply stays one JSON message; larger files are downloaded.
 */
export async function readFileBytes(args = {}) {
  const meta = await statPath(args);
  if (meta.dir) throw new PeerError('BAD_INPUT', `${meta.path} is a directory`);
  const limit = Math.min(Number(args.limit) || MAX_PREVIEW_BYTES, MAX_PREVIEW_BYTES);
  if (meta.size > limit) throw new PeerError('TOO_LARGE', `${meta.name} is ${(meta.size / 1048576).toFixed(1)} MB; download it instead`, 413);
  const chunks = [];
  for await (const chunk of createReadStream(meta.path)) chunks.push(chunk);
  return { ...meta, data: Buffer.concat(chunks).toString('base64') };
}

// ---- zip (stored, streaming) --------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(crc, chunk) {
  let c = crc ^ 0xffffffff;
  for (let i = 0; i < chunk.length; i++) c = CRC_TABLE[(c ^ chunk[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dosTime(ms) {
  const d = new Date(ms);
  const year = Math.max(d.getFullYear(), 1980);
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2),
    date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

/** Files under `root`, skipping build and VCS folders, hidden ones optional. */
async function collect(root, { hidden }, signal) {
  const files = [];
  let total = 0;
  const walk = async (dir, rel) => {
    if (signal?.aborted) throw new PeerError('CANCELLED', 'cancelled');
    let dirents;
    try {
      dirents = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const dirent of dirents) {
      if (!hidden && hiddenName(dirent.name)) continue;
      const full = join(dir, dirent.name);
      const name = rel ? `${rel}/${dirent.name}` : dirent.name;
      if (dirent.isDirectory()) {
        if (SKIP_DIRS.has(dirent.name)) continue;
        await walk(full, name);
      } else if (dirent.isFile()) {
        let info;
        try {
          info = await stat(full);
        } catch {
          continue;
        }
        files.push({ full, name, size: info.size, mtime: info.mtimeMs });
        total += info.size;
        if (files.length > ZIP_MAX_FILES) throw new PeerError('TOO_LARGE', `more than ${ZIP_MAX_FILES} files; pick a smaller folder`, 413);
        if (total > ZIP_MAX_BYTES) throw new PeerError('TOO_LARGE', 'folder is larger than 4 GB; pick a smaller folder', 413);
      }
    }
  };
  await walk(root, '');
  return files;
}

/**
 * Stream `dir` as a stored (uncompressed) zip into `out`. Sizes are known up
 * front, so no data descriptors and no buffering of whole files.
 */
export async function writeZip(dir, out, { hidden = false, signal } = {}) {
  const files = await collect(dir, { hidden }, signal);
  const central = [];
  let offset = 0;
  const write = (buffer) =>
    new Promise((resolveWrite, reject) => {
      if (out.destroyed) return reject(new PeerError('CANCELLED', 'client went away'));
      offset += buffer.length;
      if (out.write(buffer)) resolveWrite();
      else out.once('drain', resolveWrite);
    });
  for (const file of files) {
    if (signal?.aborted) throw new PeerError('CANCELLED', 'cancelled');
    // CRC first (one read), then header + data (second read): keeps memory flat.
    let crc = 0;
    let size = 0;
    try {
      for await (const chunk of createReadStream(file.full)) {
        crc = crc32(crc, chunk);
        size += chunk.length;
      }
    } catch {
      continue; // unreadable now; leave it out
    }
    const name = Buffer.from(file.name, 'utf8');
    const { time, date } = dosTime(file.mtime);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(10, 4);
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(size, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    const at = offset;
    await write(local);
    await write(name);
    let written = 0;
    for await (const chunk of createReadStream(file.full, { end: size > 0 ? size - 1 : 0 })) {
      if (size === 0) break;
      written += chunk.length;
      await write(chunk);
    }
    if (written !== size) throw new PeerError('FAILED', `${file.name} changed while zipping`);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(0x031e, 4);
    entry.writeUInt16LE(10, 6);
    entry.writeUInt16LE(0x0800, 8);
    entry.writeUInt16LE(0, 10);
    entry.writeUInt16LE(time, 12);
    entry.writeUInt16LE(date, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(size, 20);
    entry.writeUInt32LE(size, 24);
    entry.writeUInt16LE(name.length, 28);
    entry.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    entry.writeUInt32LE(at, 42);
    central.push(entry, name);
  }
  const start = offset;
  for (const part of central) await write(part);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(central.length / 2, 8);
  end.writeUInt16LE(central.length / 2, 10);
  end.writeUInt32LE(offset - start, 12);
  end.writeUInt32LE(start, 16);
  await write(end);
  return { files: central.length / 2, bytes: offset };
}

/** RFC 6266 attachment header with an ASCII fallback and the UTF-8 name. */
export function attachment(name, inline = false) {
  const ascii = name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `${inline ? 'inline' : 'attachment'}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

/**
 * Resolve the real path, so a link inside the folder cannot widen a later
 * check; also what a zip is named after.
 */
export async function realDir(path) {
  const real = await realpath(absolute(path));
  const info = await stat(real);
  if (!info.isDirectory()) throw new PeerError('BAD_INPUT', `${real} is not a directory`);
  return real;
}
