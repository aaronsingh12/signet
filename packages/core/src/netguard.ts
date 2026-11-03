import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import { isIP } from 'node:net';

// Outbound destination checks for tool calls (SSRF, OWASP A10). Agents never choose a URL: the gateway
// forwards only to registered tool addresses. Still, a registered name can resolve somewhere it should
// not (cloud metadata, DNS rebinding), so every connection is checked on the address actually dialled.

export type AddressClass = 'public' | 'loopback' | 'private' | 'link_local' | 'unspecified' | 'multicast' | 'reserved';

function v4(ip: string): number[] {
  return ip.split('.').map(Number);
}

export function classifyAddress(ip: string): AddressClass {
  let a = ip.toLowerCase();
  const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) a = mapped[1]!;
  if (isIP(a) === 4) {
    const [o1, o2] = v4(a) as [number, number];
    if (o1 === 0) return 'unspecified';
    if (o1 === 127) return 'loopback';
    if (o1 === 10 || (o1 === 172 && o2 >= 16 && o2 <= 31) || (o1 === 192 && o2 === 168) || (o1 === 100 && o2 >= 64 && o2 <= 127)) return 'private';
    if (o1 === 169 && o2 === 254) return 'link_local'; // includes 169.254.169.254, the cloud metadata service
    if (o1 >= 224 && o1 <= 239) return 'multicast';
    if (o1 >= 240) return 'reserved';
    return 'public';
  }
  if (isIP(a) === 6) {
    if (a === '::') return 'unspecified';
    if (a === '::1') return 'loopback';
    if (/^f[cd]/.test(a)) return 'private';
    if (/^fe[89ab]/.test(a)) return 'link_local';
    if (/^ff/.test(a)) return 'multicast';
    return 'public';
  }
  return 'reserved';
}

export interface DestinationPolicy {
  // Loopback and private networks (a tool on the same host, VPC or VPN). Off unless set.
  allowPrivate: boolean;
}

// Link-local (metadata), unspecified, multicast and reserved addresses are never reachable.
export function addressAllowed(ip: string, policy: DestinationPolicy): { ok: boolean; cls: AddressClass } {
  const cls = classifyAddress(ip);
  if (cls === 'public') return { ok: true, cls };
  if ((cls === 'loopback' || cls === 'private') && policy.allowPrivate) return { ok: true, cls };
  return { ok: false, cls };
}

export class DestinationBlocked extends Error {}

export function destinationPolicyFromEnv(): DestinationPolicy {
  return { allowPrivate: (process.env.SIGNET_TOOL_PRIVATE_DESTINATIONS ?? 'deny').toLowerCase() === 'allow' };
}

// A dns.lookup replacement for node:http that refuses to connect to a disallowed address.
export function guardedLookup(policy: DestinationPolicy) {
  return (hostname: string, options: object, callback: (err: Error | null, address: string | LookupAddress[], family?: number) => void) => {
    dnsLookup(hostname, { ...(options as object), all: true }, (err, addresses) => {
      if (err) return callback(err, '', 4);
      const list = addresses as LookupAddress[];
      const bad = list.find((x) => !addressAllowed(x.address, policy).ok);
      if (bad) return callback(new DestinationBlocked(`${hostname} resolves to ${bad.address} (${classifyAddress(bad.address)}), which tools may not reach`), '', 4);
      if ((options as { all?: boolean }).all) return callback(null, list);
      callback(null, list[0]!.address, list[0]!.family);
    });
  };
}

// For registration-time checks: resolve and classify without connecting.
export async function checkDestination(url: string | URL, policy: DestinationPolicy): Promise<{ addresses: string[] }> {
  const u = typeof url === 'string' ? new URL(url) : url;
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new DestinationBlocked('only http and https destinations are allowed');
  if (u.username || u.password) throw new DestinationBlocked('credentials in the URL are not allowed; store them in the Secrets Broker');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host)) {
    const r = addressAllowed(host, policy);
    if (!r.ok) throw new DestinationBlocked(`${host} is a ${r.cls.replace('_', '-')} address, which tools may not reach${r.cls === 'loopback' || r.cls === 'private' ? ' (set SIGNET_TOOL_PRIVATE_DESTINATIONS=allow for tools on your own network)' : ''}`);
    return { addresses: [host] };
  }
  const addresses = await new Promise<LookupAddress[]>((resolve, reject) => dnsLookup(host, { all: true }, (e, a) => (e ? reject(new DestinationBlocked(`cannot resolve ${host}: ${e.message}`)) : resolve(a))));
  for (const a of addresses) {
    const r = addressAllowed(a.address, policy);
    if (!r.ok) throw new DestinationBlocked(`${host} resolves to ${a.address}, a ${r.cls.replace('_', '-')} address, which tools may not reach${r.cls === 'loopback' || r.cls === 'private' ? ' (set SIGNET_TOOL_PRIVATE_DESTINATIONS=allow for tools on your own network)' : ''}`);
  }
  return { addresses: addresses.map((a) => a.address) };
}
