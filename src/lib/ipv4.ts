const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIPv4(value: unknown): value is string {
  return typeof value === 'string' && IPV4.test(value);
}

export function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
}

export interface Cidr {
  network: number;
  mask: number;
  text: string;
}

export function parseCidr(text: string): Cidr {
  const [ip, bitsText] = text.split('/');
  const bits = Number(bitsText);
  if (!ip || !isIPv4(ip) || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    throw new Error(`CIDR inválido: ${text}`);
  }
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { network: (ipv4ToInt(ip) & mask) >>> 0, mask, text };
}

export function cidrContains(cidr: Cidr, ip: string): boolean {
  return isIPv4(ip) && ((ipv4ToInt(ip) & cidr.mask) >>> 0) === cidr.network;
}
