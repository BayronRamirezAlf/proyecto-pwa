import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Codec RADIUS mínimo (RFC 2865 autenticación, RFC 2866 accounting, RFC 3579 Message-Authenticator).
 * Solo lo que necesita el hotspot de RouterOS: PAP, atributos estándar y VSA de MikroTik.
 */

export const RadiusCode = {
  AccessRequest: 1,
  AccessAccept: 2,
  AccessReject: 3,
  AccountingRequest: 4,
  AccountingResponse: 5,
} as const;

export const Attr = {
  UserName: 1,
  UserPassword: 2,
  ChapPassword: 3,
  NasIpAddress: 4,
  NasPort: 5,
  ServiceType: 6,
  FramedIpAddress: 8,
  ReplyMessage: 18,
  Class: 25,
  VendorSpecific: 26,
  SessionTimeout: 27,
  IdleTimeout: 28,
  CalledStationId: 30,
  CallingStationId: 31,
  NasIdentifier: 32,
  AcctStatusType: 40,
  AcctDelayTime: 41,
  AcctInputOctets: 42,
  AcctOutputOctets: 43,
  AcctSessionId: 44,
  AcctSessionTime: 46,
  AcctTerminateCause: 49,
  AcctInputGigawords: 52,
  AcctOutputGigawords: 53,
  EventTimestamp: 55,
  NasPortType: 61,
  MessageAuthenticator: 80,
  AcctInterimInterval: 85,
} as const;

export const AcctStatusType = {
  Start: 1,
  Stop: 2,
  InterimUpdate: 3,
  AccountingOn: 7,
  AccountingOff: 8,
} as const;

/** Diccionario MikroTik (vendor 14988), ver /radius en la documentación de RouterOS. */
export const VENDOR_MIKROTIK = 14988;
export const MikrotikAttr = {
  RecvLimit: 1,
  XmitLimit: 2,
  Group: 3,
  RateLimit: 8,
  AddressList: 19,
} as const;

export interface Attribute {
  type: number;
  value: Buffer;
}

export interface Packet {
  code: number;
  identifier: number;
  authenticator: Buffer;
  attributes: Attribute[];
}

export class RadiusPacketError extends Error {}

const HEADER = 20;
const MAX_PACKET = 4096;

export function decodePacket(buf: Buffer): Packet {
  if (buf.length < HEADER) throw new RadiusPacketError('paquete demasiado corto');
  const length = buf.readUInt16BE(2);
  if (length < HEADER || length > MAX_PACKET || length > buf.length) {
    throw new RadiusPacketError(`longitud inválida (${length})`);
  }
  const attributes: Attribute[] = [];
  let off = HEADER;
  while (off < length) {
    if (off + 2 > length) throw new RadiusPacketError('atributo truncado');
    const type = buf[off]!;
    const len = buf[off + 1]!;
    if (len < 2 || off + len > length) throw new RadiusPacketError(`atributo ${type} con longitud inválida`);
    attributes.push({ type, value: Buffer.from(buf.subarray(off + 2, off + len)) });
    off += len;
  }
  return {
    code: buf[0]!,
    identifier: buf[1]!,
    authenticator: Buffer.from(buf.subarray(4, HEADER)),
    attributes,
  };
}

function encodeAttributes(attributes: Attribute[]): Buffer {
  const parts: Buffer[] = [];
  for (const a of attributes) {
    if (a.value.length > 253) throw new RadiusPacketError(`atributo ${a.type} excede 253 bytes`);
    parts.push(Buffer.from([a.type, a.value.length + 2]), a.value);
  }
  return Buffer.concat(parts);
}

function assemble(code: number, identifier: number, authenticator: Buffer, attributes: Attribute[]): Buffer {
  const body = encodeAttributes(attributes);
  const buf = Buffer.alloc(HEADER + body.length);
  buf[0] = code;
  buf[1] = identifier;
  buf.writeUInt16BE(buf.length, 2);
  authenticator.copy(buf, 4);
  body.copy(buf, HEADER);
  if (buf.length > MAX_PACKET) throw new RadiusPacketError('paquete excede 4096 bytes');
  return buf;
}

// ---------- Constructores y lectores de atributos ----------

export const attr = {
  string(type: number, value: string): Attribute {
    return { type, value: Buffer.from(value, 'utf8') };
  },
  uint32(type: number, value: number): Attribute {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(value >>> 0);
    return { type, value: b };
  },
  ipv4(type: number, ip: string): Attribute {
    return { type, value: Buffer.from(ip.split('.').map(Number)) };
  },
  vendor(vendorId: number, vendorType: number, value: Buffer | string): Attribute {
    const v = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
    const b = Buffer.alloc(6 + v.length);
    b.writeUInt32BE(vendorId, 0);
    b[4] = vendorType;
    b[5] = v.length + 2;
    v.copy(b, 6);
    return { type: Attr.VendorSpecific, value: b };
  },
};

export function getAttr(p: Packet, type: number): Buffer | undefined {
  return p.attributes.find((a) => a.type === type)?.value;
}

export function getString(p: Packet, type: number): string | undefined {
  return getAttr(p, type)?.toString('utf8');
}

export function getUint32(p: Packet, type: number): number | undefined {
  const v = getAttr(p, type);
  return v && v.length === 4 ? v.readUInt32BE(0) : undefined;
}

export function getIPv4(p: Packet, type: number): string | undefined {
  const v = getAttr(p, type);
  return v && v.length === 4 ? [...v].join('.') : undefined;
}

/** Sub-atributos de los VSA de un vendor (un atributo 26 puede traer varios). */
export function getVendorAttrs(p: Packet, vendorId: number): Attribute[] {
  const out: Attribute[] = [];
  for (const a of p.attributes) {
    if (a.type !== Attr.VendorSpecific || a.value.length < 6 || a.value.readUInt32BE(0) !== vendorId) continue;
    let off = 4;
    while (off + 2 <= a.value.length) {
      const type = a.value[off]!;
      const len = a.value[off + 1]!;
      if (len < 2 || off + len > a.value.length) break;
      out.push({ type, value: Buffer.from(a.value.subarray(off + 2, off + len)) });
      off += len;
    }
  }
  return out;
}

// ---------- Criptografía ----------

const md5 = (...parts: Buffer[]) => createHash('md5').update(Buffer.concat(parts)).digest();
const hmacMd5 = (secret: string, data: Buffer) => createHmac('md5', secret).update(data).digest();

function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** User-Password PAP (RFC 2865 §5.2). */
export function decryptPap(encrypted: Buffer, secret: string, authenticator: Buffer): string {
  if (encrypted.length === 0 || encrypted.length % 16 !== 0 || encrypted.length > 128) {
    throw new RadiusPacketError('User-Password con longitud inválida');
  }
  const s = Buffer.from(secret, 'utf8');
  const out = Buffer.alloc(encrypted.length);
  let prev = authenticator;
  for (let i = 0; i < encrypted.length; i += 16) {
    const b = md5(s, prev);
    for (let j = 0; j < 16; j++) out[i + j] = encrypted[i + j]! ^ b[j]!;
    prev = encrypted.subarray(i, i + 16);
  }
  let end = out.length;
  while (end > 0 && out[end - 1] === 0) end--;
  return out.subarray(0, end).toString('utf8');
}

export function encryptPap(password: string, secret: string, authenticator: Buffer): Buffer {
  const p = Buffer.from(password, 'utf8');
  if (p.length > 128) throw new RadiusPacketError('contraseña demasiado larga');
  const padded = Buffer.alloc(Math.max(16, Math.ceil(p.length / 16) * 16));
  p.copy(padded);
  const s = Buffer.from(secret, 'utf8');
  const out = Buffer.alloc(padded.length);
  let prev = authenticator;
  for (let i = 0; i < padded.length; i += 16) {
    const b = md5(s, prev);
    for (let j = 0; j < 16; j++) out[i + j] = padded[i + j]! ^ b[j]!;
    prev = out.subarray(i, i + 16);
  }
  return out;
}

function findMessageAuthenticatorOffset(buf: Buffer): number {
  const length = buf.readUInt16BE(2);
  let off = HEADER;
  while (off + 2 <= length) {
    const type = buf[off]!;
    const len = buf[off + 1]!;
    if (len < 2) return -1;
    if (type === Attr.MessageAuthenticator) return len === 18 ? off + 2 : -1;
    off += len;
  }
  return -1;
}

/**
 * Verifica Message-Authenticator (HMAC-MD5 sobre el paquete con el atributo en ceros).
 * Para verificar una respuesta, `requestAuthenticator` es el autenticador de la solicitud.
 * Devuelve null si el paquete no trae el atributo.
 */
export function verifyMessageAuthenticator(
  buf: Buffer,
  secret: string,
  requestAuthenticator?: Buffer,
): boolean | null {
  const off = findMessageAuthenticatorOffset(buf);
  if (off < 0) return null;
  const copy = Buffer.from(buf.subarray(0, buf.readUInt16BE(2)));
  const received = Buffer.from(copy.subarray(off, off + 16));
  copy.fill(0, off, off + 16);
  if (requestAuthenticator) requestAuthenticator.copy(copy, 4);
  return safeEqual(hmacMd5(secret, copy), received);
}

/** Accounting-Request: MD5(Code+Id+Length+16 ceros+Atributos+Secreto) (RFC 2866 §3). */
export function verifyAccountingRequest(buf: Buffer, secret: string): boolean {
  const length = buf.readUInt16BE(2);
  const copy = Buffer.from(buf.subarray(0, length));
  copy.fill(0, 4, HEADER);
  return safeEqual(md5(copy, Buffer.from(secret, 'utf8')), buf.subarray(4, HEADER));
}

/** Verifica el Response Authenticator de una respuesta (lado cliente/NAS). */
export function verifyResponse(buf: Buffer, requestAuthenticator: Buffer, secret: string): boolean {
  const length = buf.readUInt16BE(2);
  const copy = Buffer.from(buf.subarray(0, length));
  requestAuthenticator.copy(copy, 4);
  return safeEqual(md5(copy, Buffer.from(secret, 'utf8')), buf.subarray(4, HEADER));
}

// ---------- Construcción de paquetes ----------

/**
 * Respuesta a un Access-Request o Accounting-Request.
 * Con `messageAuthenticator`, el atributo va primero (mitigación BlastRADIUS, CVE-2024-3596).
 */
export function buildResponse(params: {
  code: number;
  request: Packet;
  attributes?: Attribute[];
  secret: string;
  messageAuthenticator?: boolean;
}): Buffer {
  const attributes = params.attributes ?? [];
  const withMa = params.messageAuthenticator
    ? [{ type: Attr.MessageAuthenticator, value: Buffer.alloc(16) }, ...attributes]
    : attributes;
  const buf = assemble(params.code, params.request.identifier, params.request.authenticator, withMa);
  if (params.messageAuthenticator) hmacMd5(params.secret, buf).copy(buf, HEADER + 2);
  md5(buf, Buffer.from(params.secret, 'utf8')).copy(buf, 4);
  return buf;
}

/** Access-Request PAP con Message-Authenticator (lo usan el simulador de router y las pruebas). */
export function buildAccessRequest(params: {
  identifier: number;
  username: string;
  password: string;
  secret: string;
  attributes?: Attribute[];
  messageAuthenticator?: boolean;
  authenticator?: Buffer;
}): { buf: Buffer; authenticator: Buffer } {
  const authenticator = params.authenticator ?? randomBytes(16);
  const attributes: Attribute[] = [
    ...(params.messageAuthenticator !== false
      ? [{ type: Attr.MessageAuthenticator, value: Buffer.alloc(16) }]
      : []),
    attr.string(Attr.UserName, params.username),
    { type: Attr.UserPassword, value: encryptPap(params.password, params.secret, authenticator) },
    ...(params.attributes ?? []),
  ];
  const buf = assemble(RadiusCode.AccessRequest, params.identifier, authenticator, attributes);
  if (params.messageAuthenticator !== false) hmacMd5(params.secret, buf).copy(buf, HEADER + 2);
  return { buf, authenticator };
}

export function buildAccountingRequest(params: {
  identifier: number;
  secret: string;
  attributes: Attribute[];
}): Buffer {
  const buf = assemble(RadiusCode.AccountingRequest, params.identifier, Buffer.alloc(16), params.attributes);
  md5(buf, Buffer.from(params.secret, 'utf8')).copy(buf, 4);
  return buf;
}
