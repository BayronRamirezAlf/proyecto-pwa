import dgram from 'node:dgram';
import { timingSafeEqual } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import { hashMac, isRandomizedMac, normalizeMac } from '../lib/mac.ts';
import type { GrantStore } from '../hotspot/grant-store.ts';
import { sha256 } from '../hotspot/hotspot-service.ts';
import { TERMINATE_CAUSES, type AccountingSink, type AccountingStatus } from './accounting.ts';
import {
  AcctStatusType,
  Attr,
  MikrotikAttr,
  RadiusCode,
  VENDOR_MIKROTIK,
  attr,
  buildResponse,
  decodePacket,
  decryptPap,
  getAttr,
  getIPv4,
  getString,
  getUint32,
  verifyAccountingRequest,
  verifyMessageAuthenticator,
  type Attribute,
  type Packet,
} from './packet.ts';

export interface RadiusServerOptions {
  host: string;
  authPort: number;
  acctPort: number;
  /** IP del NAS -> secreto compartido. Paquetes de otras IPs se descartan. */
  clients: Map<string, string>;
  requireMessageAuthenticator: boolean;
  interimIntervalSec: number;
  /** Perfil de usuario hotspot de RouterOS (Mikrotik-Group): aplica idle/keepalive-timeout. */
  userProfile: string;
  macHashSecret: string;
  store: GrantStore;
  accounting: AccountingSink;
  log: FastifyBaseLogger;
}

interface Decision {
  accept: boolean;
  reason: string;
  attributes: Attribute[];
}

const ACCT_STATUS: Record<number, AccountingStatus> = {
  [AcctStatusType.Start]: 'start',
  [AcctStatusType.InterimUpdate]: 'interim',
  [AcctStatusType.Stop]: 'stop',
};

/**
 * Servidor RADIUS interno (UDP 1812/1813) para el hotspot de RouterOS.
 * - Access-Request: valida la credencial de un solo uso creada por HotspotService y devuelve
 *   Session-Timeout + Mikrotik-Rate-Limit (RF-1.3).
 * - Accounting-Request: registra inicio/actualización/fin de sesión (RF-4.1).
 */
export class RadiusServer {
  readonly stats = { accepted: 0, rejected: 0, dropped: 0, accounting: 0 };
  private readonly opts: RadiusServerOptions;
  private authSocket: dgram.Socket | null = null;
  private acctSocket: dgram.Socket | null = null;

  constructor(opts: RadiusServerOptions) {
    this.opts = opts;
  }

  async start(): Promise<{ authPort: number; acctPort: number }> {
    this.authSocket = await this.bind(this.opts.authPort, (msg, rinfo) => this.onAuth(msg, rinfo));
    this.acctSocket = await this.bind(this.opts.acctPort, (msg, rinfo) => this.onAccounting(msg, rinfo));
    const ports = { authPort: this.authSocket.address().port, acctPort: this.acctSocket.address().port };
    this.opts.log.info({ host: this.opts.host, ...ports, nas: [...this.opts.clients.keys()] }, 'RADIUS escuchando');
    return ports;
  }

  async stop(): Promise<void> {
    await Promise.all(
      [this.authSocket, this.acctSocket].map(
        (s) => new Promise<void>((resolve) => (s ? s.close(() => resolve()) : resolve())),
      ),
    );
    this.authSocket = this.acctSocket = null;
  }

  private bind(
    port: number,
    handler: (msg: Buffer, rinfo: dgram.RemoteInfo) => Promise<void>,
  ): Promise<dgram.Socket> {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      socket.on('message', (msg, rinfo) => {
        handler(msg, rinfo).catch((e) => {
          this.stats.dropped++;
          this.opts.log.error({ err: e, nas: rinfo.address }, 'RADIUS: error procesando paquete');
        });
      });
      socket.once('error', reject);
      socket.bind(port, this.opts.host, () => {
        socket.off('error', reject);
        socket.on('error', (e) => this.opts.log.error({ err: e }, 'RADIUS: error de socket'));
        resolve(socket);
      });
    });
  }

  private drop(reason: string, nas: string): void {
    this.stats.dropped++;
    this.opts.log.warn({ nas, reason }, 'RADIUS: paquete descartado');
  }

  // ---------------- Autenticación ----------------

  private async onAuth(msg: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
    const secret = this.opts.clients.get(rinfo.address);
    if (!secret) return this.drop('NAS no registrado en RADIUS_CLIENTS', rinfo.address);

    let pkt: Packet;
    try {
      pkt = decodePacket(msg);
    } catch (e) {
      return this.drop(`paquete malformado: ${(e as Error).message}`, rinfo.address);
    }
    if (pkt.code !== RadiusCode.AccessRequest) return this.drop(`código ${pkt.code} inesperado`, rinfo.address);

    const ma = verifyMessageAuthenticator(msg, secret);
    if (ma === false) return this.drop('Message-Authenticator inválido (¿secreto incorrecto?)', rinfo.address);
    if (ma === null && this.opts.requireMessageAuthenticator) {
      return this.drop('Access-Request sin Message-Authenticator (RouterOS < 7.15?)', rinfo.address);
    }

    const decision = await this.decide(pkt, secret);
    const reply = buildResponse({
      code: decision.accept ? RadiusCode.AccessAccept : RadiusCode.AccessReject,
      request: pkt,
      attributes: decision.accept
        ? decision.attributes
        : [attr.string(Attr.ReplyMessage, decision.reason)],
      secret,
      messageAuthenticator: true,
    });
    await this.send(this.authSocket!, reply, rinfo);

    if (decision.accept) this.stats.accepted++;
    else this.stats.rejected++;
    this.opts.log.info(
      {
        nas: rinfo.address,
        user: getString(pkt, Attr.UserName),
        mac: getString(pkt, Attr.CallingStationId),
        result: decision.accept ? 'accept' : 'reject',
        reason: decision.reason,
      },
      'RADIUS: Access-Request',
    );
  }

  private async decide(pkt: Packet, secret: string): Promise<Decision> {
    const reject = (reason: string): Decision => ({ accept: false, reason, attributes: [] });

    const username = getString(pkt, Attr.UserName);
    if (!username) return reject('falta User-Name');
    const encrypted = getAttr(pkt, Attr.UserPassword);
    if (!encrypted) return reject('solo se admite PAP (falta User-Password)');

    const grant = await this.opts.store.getGrant(username);
    if (!grant) return reject('credencial inexistente o expirada');
    await this.opts.store.markGrantSeen(username);

    let password: string;
    try {
      password = decryptPap(encrypted, secret, pkt.authenticator);
    } catch {
      return reject('User-Password ilegible');
    }
    const expected = Buffer.from(grant.passwordHash, 'hex');
    const actual = Buffer.from(sha256(password), 'hex');
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return reject('contraseña incorrecta');
    }

    // La credencial está ligada al dispositivo para el que se emitió.
    const callingMac = normalizeMac(getString(pkt, Attr.CallingStationId));
    if (callingMac && callingMac !== grant.mac) return reject('la MAC no coincide con la autorización');
    const framedIp = getIPv4(pkt, Attr.FramedIpAddress);
    if (framedIp && framedIp !== grant.ip) return reject('la IP no coincide con la autorización');

    await this.opts.store.putSessionLink(
      { username, macHash: hashMac(grant.mac, this.opts.macHashSecret), userId: grant.userId },
      grant.sessionTimeoutSec + 3600,
    );

    return {
      accept: true,
      reason: 'ok',
      attributes: [
        attr.uint32(Attr.SessionTimeout, grant.sessionTimeoutSec),
        attr.uint32(Attr.AcctInterimInterval, this.opts.interimIntervalSec),
        attr.vendor(VENDOR_MIKROTIK, MikrotikAttr.RateLimit, grant.rateLimit),
        attr.vendor(VENDOR_MIKROTIK, MikrotikAttr.Group, this.opts.userProfile),
      ],
    };
  }

  // ---------------- Accounting ----------------

  private async onAccounting(msg: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
    const secret = this.opts.clients.get(rinfo.address);
    if (!secret) return this.drop('NAS no registrado en RADIUS_CLIENTS', rinfo.address);

    let pkt: Packet;
    try {
      pkt = decodePacket(msg);
    } catch (e) {
      return this.drop(`paquete malformado: ${(e as Error).message}`, rinfo.address);
    }
    if (pkt.code !== RadiusCode.AccountingRequest) return this.drop(`código ${pkt.code} inesperado`, rinfo.address);
    if (!verifyAccountingRequest(msg, secret)) {
      return this.drop('Request Authenticator inválido (¿secreto incorrecto?)', rinfo.address);
    }

    const nasId = getString(pkt, Attr.NasIdentifier) ?? rinfo.address;
    const statusType = getUint32(pkt, Attr.AcctStatusType);
    const eventAt = this.eventTime(pkt);

    if (statusType === AcctStatusType.AccountingOn || statusType === AcctStatusType.AccountingOff) {
      const closed = await this.opts.accounting.closeOpenSessions(nasId, eventAt, 'NAS-Reboot');
      this.opts.log.warn({ nasId, closed }, 'RADIUS: Accounting-On/Off, sesiones abiertas cerradas');
      return this.ack(pkt, secret, rinfo);
    }

    const status = statusType === undefined ? undefined : ACCT_STATUS[statusType];
    if (!status) return this.ack(pkt, secret, rinfo); // tipos que no usamos: se confirman y se ignoran

    const sessionId = getString(pkt, Attr.AcctSessionId);
    if (!sessionId) return this.drop('Accounting sin Acct-Session-Id', rinfo.address);

    const username = getString(pkt, Attr.UserName) ?? null;
    const link = username ? await this.opts.store.getSessionLink(username) : null;
    const mac = normalizeMac(getString(pkt, Attr.CallingStationId));
    const macHash = link?.macHash ?? (mac ? hashMac(mac, this.opts.macHashSecret) : null);
    if (!macHash) return this.drop('Accounting sin Calling-Station-Id', rinfo.address);

    const octets = (low: number, high: number) =>
      (getUint32(pkt, high) ?? 0) * 2 ** 32 + (getUint32(pkt, low) ?? 0);
    const causeCode = getUint32(pkt, Attr.AcctTerminateCause);

    // Si no se puede guardar, no se responde: RouterOS reintentará el envío.
    await this.opts.accounting.record({
      status,
      nasId,
      sessionId,
      username,
      macHash,
      macRandomized: mac ? isRandomizedMac(mac) : false,
      framedIp: getIPv4(pkt, Attr.FramedIpAddress) ?? null,
      userId: link?.userId ?? null,
      sessionTimeSec: getUint32(pkt, Attr.AcctSessionTime) ?? 0,
      inputOctets: octets(Attr.AcctInputOctets, Attr.AcctInputGigawords),
      outputOctets: octets(Attr.AcctOutputOctets, Attr.AcctOutputGigawords),
      terminateCause: causeCode === undefined ? null : (TERMINATE_CAUSES[causeCode] ?? `Code-${causeCode}`),
      at: eventAt,
    });
    this.stats.accounting++;
    await this.ack(pkt, secret, rinfo);
  }

  private eventTime(pkt: Packet): Date {
    const ts = getUint32(pkt, Attr.EventTimestamp);
    if (ts) return new Date(ts * 1000);
    const delay = getUint32(pkt, Attr.AcctDelayTime) ?? 0;
    return new Date(Date.now() - delay * 1000);
  }

  private async ack(pkt: Packet, secret: string, rinfo: dgram.RemoteInfo): Promise<void> {
    await this.send(
      this.acctSocket!,
      buildResponse({ code: RadiusCode.AccountingResponse, request: pkt, secret }),
      rinfo,
    );
  }

  private send(socket: dgram.Socket, buf: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
    return new Promise((resolve, reject) =>
      socket.send(buf, rinfo.port, rinfo.address, (e) => (e ? reject(e) : resolve())),
    );
  }
}
