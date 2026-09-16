import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export type ResolvedAddress = { address: string; family: 4 | 6 };
export type AddressResolver = (hostname: string) => Promise<ResolvedAddress[]>;

export class NetworkPolicyError extends Error {
 constructor(public code: 'DNS_FAILED' | 'NO_ADDRESSES' | 'NON_PUBLIC_ADDRESS', message: string) {
  super(message);
  this.name = 'NetworkPolicyError';
 }
}

function ipv4Number(address: string): number | null {
 const parts = address.split('.');
 if (parts.length !== 4) return null;
 let value = 0;
 for (const part of parts) {
  if (!/^\d{1,3}$/.test(part)) return null;
  const octet = Number(part);
  if (octet < 0 || octet > 255) return null;
  value = value * 256 + octet;
 }
 return value >>> 0;
}

function ipv4InCidr(value: number, base: string, bits: number): boolean {
 const baseValue = ipv4Number(base);
 if (baseValue === null) return false;
 if (bits === 0) return true;
 const mask = (0xffffffff << (32 - bits)) >>> 0;
 return (value & mask) === (baseValue & mask);
}

function parseIpv6(address: string): number[] | null {
 let input = address.toLowerCase().split('%')[0];
 if (input.includes('.')) {
  const lastColon = input.lastIndexOf(':');
  if (lastColon < 0) return null;
  const v4 = ipv4Number(input.slice(lastColon + 1));
  if (v4 === null) return null;
  input = `${input.slice(0, lastColon)}:${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
 }
 const halves = input.split('::');
 if (halves.length > 2) return null;
 const left = halves[0] ? halves[0].split(':') : [];
 const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
 if (halves.length === 1 && left.length !== 8) return null;
 const missing = 8 - left.length - right.length;
 if (missing < 0 || (halves.length === 2 && missing < 1)) return null;
 const groups = [...left, ...Array.from({ length: missing }, () => '0'), ...right];
 if (groups.length !== 8) return null;
 const values: number[] = [];
 for (const group of groups) {
  if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
  values.push(parseInt(group, 16));
 }
 return values;
}

function ipv6InCidr(value: number[], base: string, bits: number): boolean {
 const baseValue = parseIpv6(base);
 if (!baseValue) return false;
 let remaining = bits;
 for (let index = 0; index < 8 && remaining > 0; index += 1) {
  const take = Math.min(16, remaining);
  const mask = take === 16 ? 0xffff : (0xffff << (16 - take)) & 0xffff;
  if ((value[index] & mask) !== (baseValue[index] & mask)) return false;
  remaining -= take;
 }
 return true;
}

export function isPublicIpAddress(address: string): boolean {
 const family = isIP(address);
 if (family === 4) {
  const value = ipv4Number(address);
  if (value === null) return false;
  const blocked: Array<[string, number]> = [
   ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
   ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
   ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
   ['224.0.0.0', 4], ['240.0.0.0', 4],
  ];
  return !blocked.some(([base, bits]) => ipv4InCidr(value, base, bits));
 }
 if (family === 6) {
  const value = parseIpv6(address);
  if (value === null) return false;
  if (!ipv6InCidr(value, '2000::', 3)) return false;
  if (ipv6InCidr(value, '2001:db8::', 32)) return false;
  return true;
 }
 return false;
}

const systemResolver: AddressResolver = async (hostname) => {
 const rows = await lookup(hostname, { all: true, verbatim: true });
 return rows.map(({ address, family }) => ({ address, family: family as 4 | 6 }));
};

export async function resolvePublicAddresses(hostname: string, resolver: AddressResolver = systemResolver): Promise<ResolvedAddress[]> {
 let rows: ResolvedAddress[];
 try {
  rows = await resolver(hostname);
 } catch {
  throw new NetworkPolicyError('DNS_FAILED', 'Target DNS lookup failed.');
 }
 if (!rows.length) throw new NetworkPolicyError('NO_ADDRESSES', 'Target DNS returned no addresses.');
 if (rows.some(({ address }) => !isPublicIpAddress(address))) {
  throw new NetworkPolicyError('NON_PUBLIC_ADDRESS', 'Target DNS resolved to a non-public address.');
 }
 return rows;
}
