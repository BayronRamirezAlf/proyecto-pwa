import { createHash, randomBytes } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import type { Config } from '../config.ts';
import { cidrContains, isIPv4 } from '../lib/ipv4.ts';
import { normalizeMac } from '../lib/mac.ts';
import { RouterOsError, type HotspotActive, type RouterOsClient } from '../mikrotik/routeros-client.ts';
import type { GrantStore } from './grant-store.ts';

export type HotspotErrorCode =
  | 'INVALID_MAC'
  | 'INVALID_IP'
  | 'OUT_OF_SUBNET'
  | 'ROUTER_REJECTED'
  | 'ROUTER_UNREACHABLE'
  | 'NOT_FOUND';

const HTTP_STATUS: Record<HotspotErrorCode, number> = {
  INVALID_MAC: 400,
  INVALID_IP: 400,
  OUT_OF_SUBNET: 400,
  ROUTER_REJECTED: 409,
  ROUTER_UNREACHABLE: 503,
  NOT_FOUND: 404,
};

export class HotspotError extends Error {
  readonly code: HotspotErrorCode;
  readonly httpStatus: number;

  constructor(code: HotspotErrorCode, message: string) {
    super(message);
    this.name = 'HotspotError';
    this.code = code;
    this.httpStatus = HTTP_STATUS[code];
  }
}

export interface AuthorizeInput {
  mac: string;
  ip: string;
  /** Por defecto SESSION_TIMEOUT_MIN. Permite p. ej. una pre-autorización corta para OAuth. */
  sessionTimeoutSec?: number;
  /** wifi_users.id cuando ya existe el lead (Sprint 2). */
  userId?: string | null;
}

export type AuthMethod = 'radius' | 'local' | 'local-fallback';

export interface AuthorizeResult {
  status: 'authorized' | 'already_active';
  method: AuthMethod | null;
  mac: string;
  ip: string;
  sessionTimeoutSec: number;
  rateLimit: string;
  session: HotspotActive | null;
  durationMs: number;
}

export interface HotspotServiceDeps {
  config: Config;
  router: RouterOsClient;
  store: GrantStore;
  log: FastifyBaseLogger;
}

export class HotspotService {
  private readonly config: Config;
  private readonly router: RouterOsClient;
  private readonly store: GrantStore;
  private readonly log: FastifyBaseLogger;

  constructor(deps: HotspotServiceDeps) {
    this.config = deps.config;
    this.router = deps.router;
    this.store = deps.store;
    this.log = deps.log;
  }

  /** RF-1.3: abre el acceso del cliente en RouterOS con límite de tiempo y de ancho de banda. */
  async authorize(input: AuthorizeInput): Promise<AuthorizeResult> {
    const started = performance.now();
    const mac = normalizeMac(input.mac);
    if (!mac) throw new HotspotError('INVALID_MAC', `MAC inválida: ${input.mac}`);
    if (!isIPv4(input.ip)) throw new HotspotError('INVALID_IP', `IP inválida: ${input.ip}`);
    if (!cidrContains(this.config.hotspot.guestSubnet, input.ip)) {
      throw new HotspotError(
        'OUT_OF_SUBNET',
        `La IP ${input.ip} no pertenece a la red de invitados ${this.config.hotspot.guestSubnet.text}`,
      );
    }
    const ip = input.ip;
    const sessionTimeoutSec = input.sessionTimeoutSec ?? this.config.hotspot.sessionTimeoutSec;
    const rateLimit = this.config.hotspot.rateLimit;

    const existing = await this.findSession(mac, ip);
    if (existing) {
      return {
        status: 'already_active',
        method: null,
        mac,
        ip,
        sessionTimeoutSec,
        rateLimit,
        session: existing,
        durationMs: Math.round(performance.now() - started),
      };
    }

    let method: AuthMethod;
    if (this.config.hotspot.authMode === 'radius') {
      method = await this.loginViaRadius({ mac, ip, sessionTimeoutSec, rateLimit, userId: input.userId ?? null });
    } else {
      await this.loginLocal(mac, ip);
      method = 'local';
    }

    const session = await this.findSession(mac, ip);
    const durationMs = Math.round(performance.now() - started);
    this.log.info({ mac, ip, method, durationMs, sessionId: session?.id }, 'hotspot: cliente autorizado');
    return { status: 'authorized', method, mac, ip, sessionTimeoutSec, rateLimit, session, durationMs };
  }

  async listSessions(): Promise<HotspotActive[]> {
    try {
      return await this.router.listActive();
    } catch (e) {
      throw this.mapRouterError(e);
    }
  }

  /** Cierra todas las sesiones activas de una MAC. Devuelve cuántas cerró. */
  async disconnect(macInput: string): Promise<number> {
    const mac = normalizeMac(macInput);
    if (!mac) throw new HotspotError('INVALID_MAC', `MAC inválida: ${macInput}`);
    try {
      const sessions = await this.router.listActive({ mac });
      if (sessions.length === 0) throw new HotspotError('NOT_FOUND', `No hay sesión activa para ${mac}`);
      for (const s of sessions) await this.router.removeActive(s.id);
      this.log.info({ mac, count: sessions.length }, 'hotspot: sesión cerrada');
      return sessions.length;
    } catch (e) {
      throw this.mapRouterError(e);
    }
  }

  private async loginViaRadius(params: {
    mac: string;
    ip: string;
    sessionTimeoutSec: number;
    rateLimit: string;
    userId: string | null;
  }): Promise<AuthMethod> {
    const username = `wf${randomBytes(8).toString('hex')}`;
    const password = randomBytes(18).toString('base64url');
    await this.store.putGrant(
      {
        username,
        passwordHash: sha256(password),
        mac: params.mac,
        ip: params.ip,
        sessionTimeoutSec: params.sessionTimeoutSec,
        rateLimit: params.rateLimit,
        userId: params.userId,
        createdAt: new Date().toISOString(),
      },
      this.config.hotspot.grantTtlSec,
    );

    try {
      await this.router.hotspotLogin({ user: username, password, mac: params.mac, ip: params.ip });
      return 'radius';
    } catch (e) {
      const grant = await this.store.getGrant(username);
      await this.store.deleteGrant(username);
      // Si nuestro RADIUS nunca recibió el Access-Request, el problema es la ruta router->RADIUS
      // (servidor caído, túnel, firewall, secreto). Se abre la sesión con el usuario local de respaldo
      // para no dejar al visitante sin internet (RNF-4); se pierde el accounting de esa sesión.
      const radiusUnreachable = e instanceof RouterOsError && !e.unreachable && !grant?.seenAt;
      if (radiusUnreachable && this.config.hotspot.fallbackToLocal) {
        this.log.warn(
          { mac: params.mac, ip: params.ip, detail: (e as RouterOsError).detail },
          'hotspot: el RADIUS no recibió la solicitud del router; reintentando con usuario local de respaldo',
        );
        await this.loginLocal(params.mac, params.ip);
        return 'local-fallback';
      }
      throw this.mapRouterError(e);
    }
  }

  private async loginLocal(mac: string, ip: string): Promise<void> {
    const { localUser, localPassword } = this.config.hotspot;
    try {
      await this.router.hotspotLogin({ user: localUser!, password: localPassword!, mac, ip });
    } catch (e) {
      throw this.mapRouterError(e);
    }
  }

  private async findSession(mac: string, ip: string): Promise<HotspotActive | null> {
    try {
      const sessions = await this.router.listActive({ mac });
      return sessions.find((s) => s.address === ip) ?? sessions[0] ?? null;
    } catch (e) {
      throw this.mapRouterError(e);
    }
  }

  private mapRouterError(e: unknown): Error {
    if (e instanceof HotspotError) return e;
    if (e instanceof RouterOsError) {
      if (e.unreachable) return new HotspotError('ROUTER_UNREACHABLE', e.message);
      if (e.status === 401) {
        return new HotspotError('ROUTER_UNREACHABLE', 'Credenciales de la REST API rechazadas por el router');
      }
      return new HotspotError('ROUTER_REJECTED', e.detail || e.message);
    }
    return e instanceof Error ? e : new Error(String(e));
  }
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
