import type { Db } from '../db/db.ts';

export type AccountingStatus = 'start' | 'interim' | 'stop';

export interface AccountingEvent {
  status: AccountingStatus;
  nasId: string;
  sessionId: string;
  username: string | null;
  macHash: string;
  macRandomized: boolean;
  framedIp: string | null;
  userId: string | null;
  sessionTimeSec: number;
  inputOctets: number;
  outputOctets: number;
  terminateCause: string | null;
  /** Momento del evento en el NAS (ya descontado Acct-Delay-Time). */
  at: Date;
}

export interface AccountingSink {
  record(event: AccountingEvent): Promise<void>;
  /** Accounting-On/Off: el NAS reinició; cierra sus sesiones abiertas. */
  closeOpenSessions(nasId: string, at: Date, cause: string): Promise<number>;
}

/** RFC 2866 §5.10 */
export const TERMINATE_CAUSES: Record<number, string> = {
  1: 'User-Request',
  2: 'Lost-Carrier',
  3: 'Lost-Service',
  4: 'Idle-Timeout',
  5: 'Session-Timeout',
  6: 'Admin-Reset',
  7: 'Admin-Reboot',
  8: 'Port-Error',
  9: 'NAS-Error',
  10: 'NAS-Request',
  11: 'NAS-Reboot',
  12: 'Port-Unneeded',
  13: 'Port-Preempted',
  14: 'Port-Suspended',
  15: 'Service-Unavailable',
  16: 'Callback',
  17: 'User-Error',
  18: 'Host-Request',
};

export class PostgresAccountingSink implements AccountingSink {
  private readonly db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  async record(e: AccountingEvent): Promise<void> {
    // Idempotente: RouterOS reintenta si no recibe Accounting-Response, y un Interim/Stop
    // puede llegar sin su Start (paquete perdido); started_at se reconstruye con session_time.
    await this.db.query(
      `INSERT INTO wifi_sessions (
         nas_identifier, acct_session_id, radius_username, mac_address_hash, mac_randomized,
         framed_ip, user_id, started_at, last_update_at, stopped_at,
         session_time_sec, input_octets, output_octets, terminate_cause)
       VALUES ($1, $2, $3, $4, $5, $6::inet, $7::uuid,
               $8::timestamptz - make_interval(secs => $9::int), $8::timestamptz,
               CASE WHEN $10::boolean THEN $8::timestamptz END,
               $9::int, $11::bigint, $12::bigint, $13)
       ON CONFLICT (nas_identifier, acct_session_id) DO UPDATE SET
         last_update_at   = GREATEST(wifi_sessions.last_update_at, EXCLUDED.last_update_at),
         stopped_at       = COALESCE(wifi_sessions.stopped_at, EXCLUDED.stopped_at),
         session_time_sec = GREATEST(wifi_sessions.session_time_sec, EXCLUDED.session_time_sec),
         input_octets     = GREATEST(wifi_sessions.input_octets, EXCLUDED.input_octets),
         output_octets    = GREATEST(wifi_sessions.output_octets, EXCLUDED.output_octets),
         terminate_cause  = COALESCE(EXCLUDED.terminate_cause, wifi_sessions.terminate_cause),
         user_id          = COALESCE(wifi_sessions.user_id, EXCLUDED.user_id),
         framed_ip        = COALESCE(wifi_sessions.framed_ip, EXCLUDED.framed_ip)`,
      [
        e.nasId,
        e.sessionId,
        e.username,
        e.macHash,
        e.macRandomized,
        e.framedIp,
        e.userId,
        e.at.toISOString(),
        e.sessionTimeSec,
        e.status === 'stop',
        e.inputOctets,
        e.outputOctets,
        e.terminateCause,
      ],
    );
  }

  async closeOpenSessions(nasId: string, at: Date, cause: string): Promise<number> {
    const { rows } = await this.db.query<{ id: string }>(
      `UPDATE wifi_sessions SET stopped_at = $2, terminate_cause = $3
        WHERE nas_identifier = $1 AND stopped_at IS NULL
        RETURNING id`,
      [nasId, at.toISOString(), cause],
    );
    return rows.length;
  }
}

/** Para desarrollo sin base de datos y para pruebas. */
export class MemoryAccountingSink implements AccountingSink {
  readonly sessions = new Map<string, AccountingEvent & { startedAt: Date; stoppedAt: Date | null }>();

  async record(e: AccountingEvent): Promise<void> {
    const key = `${e.nasId}|${e.sessionId}`;
    const prev = this.sessions.get(key);
    const startedAt = prev?.startedAt ?? new Date(e.at.getTime() - e.sessionTimeSec * 1000);
    this.sessions.set(key, {
      ...e,
      userId: prev?.userId ?? e.userId,
      sessionTimeSec: Math.max(prev?.sessionTimeSec ?? 0, e.sessionTimeSec),
      inputOctets: Math.max(prev?.inputOctets ?? 0, e.inputOctets),
      outputOctets: Math.max(prev?.outputOctets ?? 0, e.outputOctets),
      terminateCause: e.terminateCause ?? prev?.terminateCause ?? null,
      startedAt,
      stoppedAt: prev?.stoppedAt ?? (e.status === 'stop' ? e.at : null),
    });
  }

  async closeOpenSessions(nasId: string, at: Date, cause: string): Promise<number> {
    let count = 0;
    for (const s of this.sessions.values()) {
      if (s.nasId === nasId && !s.stoppedAt) {
        s.stoppedAt = at;
        s.terminateCause = cause;
        count++;
      }
    }
    return count;
  }
}
