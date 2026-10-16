import http from 'node:http';
import https from 'node:https';
import { readFileSync } from 'node:fs';

/**
 * Cliente mínimo de la REST API de RouterOS v7 (https://<router>/rest).
 * Mapeo: GET=print, PUT=add, PATCH=set, DELETE=remove, POST=<cualquier comando>.
 * RouterOS devuelve todos los valores como strings y los errores como
 * {"error":400,"message":"Bad Request","detail":"..."}.
 */

export class RouterOsError extends Error {
  /** Código HTTP; 0 = no hubo respuesta (red, TLS, timeout). */
  readonly status: number;
  readonly detail: string;

  constructor(status: number, message: string, detail = '') {
    super(detail ? `${message}: ${detail}` : message);
    this.name = 'RouterOsError';
    this.status = status;
    this.detail = detail;
  }

  get unreachable(): boolean {
    return this.status === 0;
  }
}

export interface HotspotActive {
  id: string;
  server: string;
  user: string;
  address: string;
  macAddress: string;
  loginBy: string;
  uptime: string;
  sessionTimeLeft: string | null;
  idleTime: string | null;
}

export interface SystemResource {
  version: string;
  uptime: string;
  cpuLoad: number;
  boardName: string;
  freeMemory: number;
  totalMemory: number;
}

export interface RouterOsClientOptions {
  baseUrl: string;
  username: string;
  password: string;
  caCertPath?: string | null;
  tlsInsecure?: boolean;
  timeoutMs?: number;
}

type Json = Record<string, string>;

export class RouterOsClient {
  private readonly base: URL;
  private readonly authHeader: string;
  private readonly timeoutMs: number;
  private readonly agent: http.Agent;
  private readonly transport: typeof http | typeof https;

  constructor(options: RouterOsClientOptions) {
    this.base = new URL(options.baseUrl);
    this.authHeader =
      'Basic ' + Buffer.from(`${options.username}:${options.password}`).toString('base64');
    this.timeoutMs = options.timeoutMs ?? 8000;
    if (this.base.protocol === 'https:') {
      this.transport = https;
      this.agent = new https.Agent({
        keepAlive: true,
        maxSockets: 16,
        ca: options.caCertPath ? readFileSync(options.caCertPath) : undefined,
        rejectUnauthorized: !options.tlsInsecure,
      });
    } else {
      this.transport = http;
      this.agent = new http.Agent({ keepAlive: true, maxSockets: 16 });
    }
  }

  /** /ip/hotspot/active/login: crea la sesión del cliente sin que el navegador toque el router. */
  async hotspotLogin(params: { user: string; password: string; mac: string; ip: string }): Promise<void> {
    await this.request('POST', '/ip/hotspot/active/login', {
      user: params.user,
      password: params.password,
      'mac-address': params.mac,
      ip: params.ip,
    });
  }

  async listActive(filter: { mac?: string; address?: string } = {}): Promise<HotspotActive[]> {
    const query = new URLSearchParams();
    if (filter.mac) query.set('mac-address', filter.mac);
    if (filter.address) query.set('address', filter.address);
    const qs = query.size ? `?${query}` : '';
    const rows = await this.request('GET', `/ip/hotspot/active${qs}`);
    return (Array.isArray(rows) ? rows : []).map(toHotspotActive);
  }

  async removeActive(id: string): Promise<void> {
    await this.request('DELETE', `/ip/hotspot/active/${encodeURIComponent(id)}`);
  }

  async systemResource(): Promise<SystemResource> {
    const r = (await this.request('GET', '/system/resource')) as Json;
    return {
      version: r.version ?? '',
      uptime: r.uptime ?? '',
      cpuLoad: Number(r['cpu-load'] ?? 0),
      boardName: r['board-name'] ?? '',
      freeMemory: Number(r['free-memory'] ?? 0),
      totalMemory: Number(r['total-memory'] ?? 0),
    };
  }

  close(): void {
    this.agent.destroy();
  }

  async request(method: string, path: string, body?: unknown): Promise<unknown> {
    const url = new URL(`/rest${path}`, this.base);
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));

    return new Promise((resolve, reject) => {
      const req = this.transport.request(
        url,
        {
          method,
          agent: this.agent,
          headers: {
            authorization: this.authHeader,
            accept: 'application/json',
            ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}),
          },
          timeout: this.timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            const status = res.statusCode ?? 0;
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed: unknown = null;
            if (text) {
              try {
                parsed = JSON.parse(text);
              } catch {
                parsed = text;
              }
            }
            if (status >= 200 && status < 300) return resolve(parsed);
            const err = (parsed && typeof parsed === 'object' ? parsed : {}) as Json;
            reject(new RouterOsError(status, err.message ?? `HTTP ${status}`, err.detail ?? ''));
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error(`timeout de ${this.timeoutMs} ms`)));
      req.on('error', (e) => reject(new RouterOsError(0, 'Router inalcanzable', e.message)));
      if (payload) req.write(payload);
      req.end();
    });
  }
}

function toHotspotActive(row: Json): HotspotActive {
  return {
    id: row['.id'] ?? '',
    server: row.server ?? '',
    user: row.user ?? '',
    address: row.address ?? '',
    macAddress: row['mac-address'] ?? '',
    loginBy: row['login-by'] ?? '',
    uptime: row.uptime ?? '',
    sessionTimeLeft: row['session-time-left'] ?? null,
    idleTime: row['idle-time'] ?? null,
  };
}
