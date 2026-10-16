import { parseCidr, type Cidr, isIPv4 } from './lib/ipv4.ts';

export type AuthMode = 'radius' | 'local';

export interface Config {
  env: 'development' | 'test' | 'production';
  logLevel: string;
  http: { host: string; port: number };
  internalApiToken: string;
  macHashSecret: string;
  redisUrl: string | null;
  databaseUrl: string | null;
  mikrotik: {
    url: string;
    user: string;
    password: string;
    caCertPath: string | null;
    tlsInsecure: boolean;
    timeoutMs: number;
  };
  hotspot: {
    authMode: AuthMode;
    server: string;
    userProfile: string;
    localUser: string | null;
    localPassword: string | null;
    fallbackToLocal: boolean;
    guestSubnet: Cidr;
    sessionTimeoutSec: number;
    /** Formato RouterOS rx/tx visto desde el router = subida/bajada del cliente, p. ej. "3M/10M". */
    rateLimit: string;
    grantTtlSec: number;
  };
  radius: {
    enabled: boolean;
    host: string;
    authPort: number;
    acctPort: number;
    /** IP del NAS (router) -> secreto compartido. */
    clients: Map<string, string>;
    requireMessageAuthenticator: boolean;
    interimIntervalSec: number;
  };
  testPortal: boolean;
}

type Env = Record<string, string | undefined>;

class ConfigError extends Error {}

function str(env: Env, key: string, fallback?: string): string {
  const value = env[key]?.trim();
  if (value) return value;
  if (fallback !== undefined) return fallback;
  throw new ConfigError(`Falta la variable de entorno ${key}`);
}

function optional(env: Env, key: string): string | null {
  const value = env[key]?.trim();
  return value ? value : null;
}

function int(env: Env, key: string, fallback: number, min: number, max: number): number {
  const raw = env[key]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ConfigError(`${key} debe ser un entero entre ${min} y ${max} (recibido: ${raw})`);
  }
  return value;
}

function bool(env: Env, key: string, fallback: boolean): boolean {
  const raw = env[key]?.trim().toLowerCase();
  if (!raw) return fallback;
  if (['true', '1', 'yes', 'si', 'sí'].includes(raw)) return true;
  if (['false', '0', 'no'].includes(raw)) return false;
  throw new ConfigError(`${key} debe ser true/false (recibido: ${raw})`);
}

const RATE = /^\d+(\.\d+)?[kKMG]?$/;

function parseRadiusClients(raw: string): Map<string, string> {
  const clients = new Map<string, string>();
  for (const entry of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    const idx = entry.indexOf('=');
    const ip = entry.slice(0, idx).trim();
    const secret = entry.slice(idx + 1).trim();
    if (idx <= 0 || !isIPv4(ip) || secret.length < 16) {
      throw new ConfigError(
        `RADIUS_CLIENTS: entrada inválida "${entry}". Formato: ip=secreto (secreto de 16+ caracteres)`,
      );
    }
    clients.set(ip, secret);
  }
  return clients;
}

export function loadConfig(env: Env = process.env): Config {
  const nodeEnv = str(env, 'NODE_ENV', 'development');
  if (nodeEnv !== 'development' && nodeEnv !== 'test' && nodeEnv !== 'production') {
    throw new ConfigError(`NODE_ENV inválido: ${nodeEnv}`);
  }

  const authMode = str(env, 'HOTSPOT_AUTH_MODE', 'radius');
  if (authMode !== 'radius' && authMode !== 'local') {
    throw new ConfigError('HOTSPOT_AUTH_MODE debe ser "radius" o "local"');
  }

  const rateDown = str(env, 'RATE_LIMIT_DOWN', '10M');
  const rateUp = str(env, 'RATE_LIMIT_UP', '3M');
  if (!RATE.test(rateDown) || !RATE.test(rateUp)) {
    throw new ConfigError('RATE_LIMIT_DOWN / RATE_LIMIT_UP deben tener formato RouterOS, p. ej. 10M, 512k');
  }

  const config: Config = {
    env: nodeEnv,
    logLevel: str(env, 'LOG_LEVEL', 'info'),
    http: {
      host: str(env, 'HTTP_HOST', '0.0.0.0'),
      port: int(env, 'HTTP_PORT', 3000, 1, 65535),
    },
    internalApiToken: str(env, 'INTERNAL_API_TOKEN'),
    macHashSecret: str(env, 'MAC_HASH_SECRET'),
    redisUrl: optional(env, 'REDIS_URL'),
    databaseUrl: optional(env, 'DATABASE_URL'),
    mikrotik: {
      url: str(env, 'MIKROTIK_URL').replace(/\/+$/, ''),
      user: str(env, 'MIKROTIK_USER'),
      password: str(env, 'MIKROTIK_PASSWORD'),
      caCertPath: optional(env, 'MIKROTIK_CA_CERT'),
      tlsInsecure: bool(env, 'MIKROTIK_TLS_INSECURE', false),
      timeoutMs: int(env, 'MIKROTIK_TIMEOUT_MS', 8000, 500, 60000),
    },
    hotspot: {
      authMode,
      server: str(env, 'HOTSPOT_SERVER', 'hs-invitados'),
      userProfile: str(env, 'HOTSPOT_USER_PROFILE', 'portal-60m'),
      localUser: optional(env, 'HOTSPOT_LOCAL_USER'),
      localPassword: optional(env, 'HOTSPOT_LOCAL_PASSWORD'),
      fallbackToLocal: bool(env, 'HOTSPOT_FALLBACK_LOCAL', true),
      guestSubnet: parseCidr(str(env, 'GUEST_SUBNET', '10.20.0.0/20')),
      sessionTimeoutSec: int(env, 'SESSION_TIMEOUT_MIN', 60, 1, 1440) * 60,
      rateLimit: `${rateUp}/${rateDown}`,
      grantTtlSec: int(env, 'HOTSPOT_GRANT_TTL_SEC', 120, 10, 900),
    },
    radius: {
      enabled: bool(env, 'RADIUS_ENABLED', authMode === 'radius'),
      host: str(env, 'RADIUS_HOST', '0.0.0.0'),
      authPort: int(env, 'RADIUS_AUTH_PORT', 1812, 0, 65535),
      acctPort: int(env, 'RADIUS_ACCT_PORT', 1813, 0, 65535),
      clients: parseRadiusClients(env.RADIUS_CLIENTS ?? ''),
      requireMessageAuthenticator: bool(env, 'RADIUS_REQUIRE_MESSAGE_AUTH', true),
      interimIntervalSec: int(env, 'RADIUS_INTERIM_SEC', 300, 60, 3600),
    },
    testPortal: bool(env, 'ENABLE_TEST_PORTAL', false),
  };

  validate(config);
  return config;
}

function validate(config: Config): void {
  if (config.internalApiToken.length < 32) {
    throw new ConfigError('INTERNAL_API_TOKEN debe tener al menos 32 caracteres');
  }
  if (config.macHashSecret.length < 32) {
    throw new ConfigError('MAC_HASH_SECRET debe tener al menos 32 caracteres');
  }
  const needsLocalUser = config.hotspot.authMode === 'local' || config.hotspot.fallbackToLocal;
  if (needsLocalUser && (!config.hotspot.localUser || !config.hotspot.localPassword)) {
    throw new ConfigError(
      'HOTSPOT_LOCAL_USER y HOTSPOT_LOCAL_PASSWORD son obligatorios en modo local o con HOTSPOT_FALLBACK_LOCAL=true',
    );
  }
  if (config.hotspot.authMode === 'radius' && !config.radius.enabled) {
    throw new ConfigError('HOTSPOT_AUTH_MODE=radius requiere RADIUS_ENABLED=true');
  }
  if (config.radius.enabled && config.radius.clients.size === 0) {
    throw new ConfigError('RADIUS_CLIENTS es obligatorio cuando RADIUS está habilitado');
  }
  if (config.env === 'production') {
    if (!config.redisUrl) throw new ConfigError('En producción REDIS_URL es obligatorio');
    if (!config.databaseUrl) throw new ConfigError('En producción DATABASE_URL es obligatorio');
    if (config.mikrotik.tlsInsecure) {
      throw new ConfigError('En producción MIKROTIK_TLS_INSECURE no está permitido; usa MIKROTIK_CA_CERT');
    }
    if (config.testPortal) throw new ConfigError('ENABLE_TEST_PORTAL no está permitido en producción');
  }
}
