import { Redis } from 'ioredis';

/**
 * "Grant": credencial de un solo uso que el backend crea antes de pedirle a RouterOS el login.
 * RouterOS la presenta al servidor RADIUS (Access-Request) y éste responde con los límites
 * de la sesión. Vive pocos segundos (HOTSPOT_GRANT_TTL_SEC).
 */
export interface Grant {
  username: string;
  /** SHA-256 hex de la contraseña de un solo uso; la contraseña en claro nunca se guarda. */
  passwordHash: string;
  mac: string;
  ip: string;
  sessionTimeoutSec: number;
  rateLimit: string;
  userId: string | null;
  createdAt: string;
  /** Lo marca el servidor RADIUS al recibir el Access-Request (sirve para diagnosticar fallas). */
  seenAt?: string;
}

/** Vínculo usuario RADIUS -> datos de analítica, para enriquecer el accounting. */
export interface SessionLink {
  username: string;
  macHash: string;
  userId: string | null;
}

export interface GrantStore {
  putGrant(grant: Grant, ttlSec: number): Promise<void>;
  getGrant(username: string): Promise<Grant | null>;
  markGrantSeen(username: string): Promise<void>;
  deleteGrant(username: string): Promise<void>;
  putSessionLink(link: SessionLink, ttlSec: number): Promise<void>;
  getSessionLink(username: string): Promise<SessionLink | null>;
  ping(): Promise<boolean>;
  close(): Promise<void>;
}

const GRANT = (u: string) => `hs:grant:${u}`;
const LINK = (u: string) => `hs:link:${u}`;

export class RedisGrantStore implements GrantStore {
  private readonly redis: Redis;

  constructor(url: string) {
    this.redis = new Redis(url, { maxRetriesPerRequest: 2, enableAutoPipelining: true });
  }

  async putGrant(grant: Grant, ttlSec: number): Promise<void> {
    await this.redis.set(GRANT(grant.username), JSON.stringify(grant), 'EX', ttlSec);
  }

  async getGrant(username: string): Promise<Grant | null> {
    const raw = await this.redis.get(GRANT(username));
    return raw ? (JSON.parse(raw) as Grant) : null;
  }

  async markGrantSeen(username: string): Promise<void> {
    const grant = await this.getGrant(username);
    if (!grant) return;
    // KEEPTTL conserva la expiración original del grant.
    await this.redis.set(
      GRANT(username),
      JSON.stringify({ ...grant, seenAt: new Date().toISOString() }),
      'KEEPTTL',
    );
  }

  async deleteGrant(username: string): Promise<void> {
    await this.redis.del(GRANT(username));
  }

  async putSessionLink(link: SessionLink, ttlSec: number): Promise<void> {
    await this.redis.set(LINK(link.username), JSON.stringify(link), 'EX', ttlSec);
  }

  async getSessionLink(username: string): Promise<SessionLink | null> {
    const raw = await this.redis.get(LINK(username));
    return raw ? (JSON.parse(raw) as SessionLink) : null;
  }

  async ping(): Promise<boolean> {
    try {
      return (await this.redis.ping()) === 'PONG';
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }
}

/** Implementación en memoria para desarrollo y pruebas (un solo proceso). */
export class MemoryGrantStore implements GrantStore {
  private readonly items = new Map<string, { value: string; expiresAt: number }>();

  private set(key: string, value: unknown, ttlSec: number): void {
    this.items.set(key, { value: JSON.stringify(value), expiresAt: Date.now() + ttlSec * 1000 });
  }

  private get<T>(key: string): T | null {
    const item = this.items.get(key);
    if (!item) return null;
    if (item.expiresAt <= Date.now()) {
      this.items.delete(key);
      return null;
    }
    return JSON.parse(item.value) as T;
  }

  async putGrant(grant: Grant, ttlSec: number): Promise<void> {
    this.set(GRANT(grant.username), grant, ttlSec);
  }

  async getGrant(username: string): Promise<Grant | null> {
    return this.get<Grant>(GRANT(username));
  }

  async markGrantSeen(username: string): Promise<void> {
    const item = this.items.get(GRANT(username));
    const grant = this.get<Grant>(GRANT(username));
    if (!item || !grant) return;
    item.value = JSON.stringify({ ...grant, seenAt: new Date().toISOString() });
  }

  async deleteGrant(username: string): Promise<void> {
    this.items.delete(GRANT(username));
  }

  async putSessionLink(link: SessionLink, ttlSec: number): Promise<void> {
    this.set(LINK(link.username), link, ttlSec);
  }

  async getSessionLink(username: string): Promise<SessionLink | null> {
    return this.get<SessionLink>(LINK(username));
  }

  async ping(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    this.items.clear();
  }
}
