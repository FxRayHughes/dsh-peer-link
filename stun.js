import dgram from 'node:dgram';
import { lookup } from 'node:dns/promises';
import { randomBytes } from 'node:crypto';

/**
 * Pick a STUN server that frp's hole punching can actually use.
 *
 * Before punching, frpc asks a STUN server for this machine's public address,
 * then asks the server's OTHER-ADDRESS (a second IP and port) to classify the
 * NAT. Any timeout there aborts the attempt, and the connection silently
 * falls back to the frps relay. frp's default, stun.easyvoip.com, resolves to
 * four addresses of which two have stopped answering, so roughly every other
 * attempt failed.
 *
 * So the relay probes candidates the same way frp uses them and hands frpc a
 * literal `ip:port` that answered both requests; frpc then cannot resolve the
 * name to a dead address on its own.
 */

export const STUN_CANDIDATES = ['stun.miwifi.com:3478', 'stun.easyvoip.com:3478', 'stun.nextcloud.com:443'];
const TIMEOUT_MS = 2500;
const MAGIC = Buffer.from([0x21, 0x12, 0xa4, 0x42]);

function parseAddress(value) {
  // family 0x01 = IPv4: [0, family, port(2), ip(4)]
  if (value.length < 8 || value[1] !== 0x01) return undefined;
  return `${value[4]}.${value[5]}.${value[6]}.${value[7]}:${value.readUInt16BE(2)}`;
}

/** Attributes of a Binding response: the mapped address and the server's alternate one. */
export function parseBinding(buffer) {
  const out = {};
  for (let i = 20; i + 4 <= buffer.length; ) {
    const type = buffer.readUInt16BE(i);
    const length = buffer.readUInt16BE(i + 2);
    const value = buffer.subarray(i + 4, i + 4 + length);
    if (type === 0x0001) out.mapped = parseAddress(value);
    if (type === 0x0020 && value.length >= 8 && value[1] === 0x01) {
      const port = value.readUInt16BE(2) ^ 0x2112;
      out.mapped = `${[0, 1, 2, 3].map((k) => value[4 + k] ^ MAGIC[k]).join('.')}:${port}`;
    }
    // OTHER-ADDRESS (RFC 5780), or CHANGED-ADDRESS from RFC 3489 servers.
    if (type === 0x802c || type === 0x0005) out.other = parseAddress(value);
    i += 4 + length + ((4 - (length % 4)) % 4);
  }
  return out;
}

function request(socket, host, port) {
  return new Promise((resolve) => {
    const id = randomBytes(12);
    const timer = setTimeout(() => {
      socket.off('message', onMessage);
      resolve(undefined);
    }, TIMEOUT_MS);
    const onMessage = (buffer) => {
      if (buffer.length < 20 || !buffer.subarray(8, 20).equals(id)) return;
      clearTimeout(timer);
      socket.off('message', onMessage);
      resolve(parseBinding(buffer));
    };
    socket.on('message', onMessage);
    socket.send(Buffer.concat([Buffer.from([0x00, 0x01, 0x00, 0x00]), MAGIC, id]), port, host, (error) => {
      if (error) {
        clearTimeout(timer);
        socket.off('message', onMessage);
        resolve(undefined);
      }
    });
  });
}

/** Whether `ip:port` answers a Binding request and, if it names one, its alternate address too. */
export async function probeStun(ip, port) {
  const socket = dgram.createSocket('udp4');
  try {
    await new Promise((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(0, resolve);
    });
    const first = await request(socket, ip, port);
    if (first?.mapped === undefined) return false;
    if (first.other === undefined) return true;
    const [otherIp, otherPort] = first.other.split(':');
    const second = await request(socket, otherIp, Number(otherPort));
    return second?.mapped !== undefined;
  } catch {
    return false;
  } finally {
    socket.close();
  }
}

/**
 * First candidate address that passes {@link probeStun}, as `ip:port`, or
 * undefined when none does (frpc then keeps its built-in default).
 */
export async function pickStunServer(candidates = STUN_CANDIDATES) {
  for (const candidate of candidates) {
    const index = candidate.lastIndexOf(':');
    const host = candidate.slice(0, index);
    const port = Number(candidate.slice(index + 1));
    let addresses;
    try {
      addresses = (await lookup(host, { all: true, family: 4 })).map((entry) => entry.address);
    } catch {
      continue;
    }
    for (const ip of addresses) {
      if (await probeStun(ip, port)) return `${ip}:${port}`;
    }
  }
  return undefined;
}
