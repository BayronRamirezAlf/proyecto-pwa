-- =====================================================================
-- 002 · Sesiones WiFi desde RADIUS Accounting (Start / Interim-Update / Stop)
-- Base para RF-4.1: dispositivos concurrentes, permanencia promedio y horas pico.
-- =====================================================================
CREATE TABLE wifi_sessions (
    id BIGSERIAL PRIMARY KEY,
    nas_identifier VARCHAR(64) NOT NULL,          -- identidad del router (NAS-Identifier)
    acct_session_id VARCHAR(64) NOT NULL,         -- Acct-Session-Id asignado por RouterOS
    radius_username VARCHAR(64),
    mac_address_hash VARCHAR(64) NOT NULL,        -- HMAC-SHA256 (RNF-3); nunca la MAC en claro
    mac_randomized BOOLEAN NOT NULL DEFAULT FALSE,-- MAC privada/aleatoria (iOS/Android/Windows)
    framed_ip INET,
    user_id UUID REFERENCES wifi_users(id) ON DELETE SET NULL,
    started_at TIMESTAMPTZ NOT NULL,
    last_update_at TIMESTAMPTZ NOT NULL,
    stopped_at TIMESTAMPTZ,
    session_time_sec INTEGER NOT NULL DEFAULT 0,
    input_octets BIGINT NOT NULL DEFAULT 0,       -- subida del cliente
    output_octets BIGINT NOT NULL DEFAULT 0,      -- bajada del cliente
    terminate_cause VARCHAR(40),
    UNIQUE (nas_identifier, acct_session_id)
);

CREATE INDEX idx_wifi_sessions_started_at ON wifi_sessions (started_at);
CREATE INDEX idx_wifi_sessions_mac_hash ON wifi_sessions (mac_address_hash);
CREATE INDEX idx_wifi_sessions_open ON wifi_sessions (nas_identifier) WHERE stopped_at IS NULL;
