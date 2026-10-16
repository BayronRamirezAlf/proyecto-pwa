-- =====================================================================
-- 001 · Esquema inicial (sección 5 del SRS), PostgreSQL 13+
-- (gen_random_uuid() es nativo desde PG 13; no requiere pgcrypto).
--
-- Desviaciones respecto al SRS, documentadas en docs/sprint-1/decisiones-y-riesgos.md:
--   D-01  wifi_users.mac_address_hash: el SRS lo declara con "INDEX" en línea, que no es SQL
--         válido en PostgreSQL; se crea con CREATE INDEX aparte.
--   D-02  issued_coupons.mac_address (MAC en claro) se sustituye por mac_address_hash
--         para cumplir RNF-3 (hashing de direcciones MAC).
-- =====================================================================

-- 1. Locales y comercios participantes
CREATE TABLE merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(150) NOT NULL,
    category VARCHAR(60) NOT NULL,
    local_number VARCHAR(30) NOT NULL,
    pin_hash VARCHAR(255) NOT NULL,
    tier VARCHAR(20) DEFAULT 'BASE',
    monthly_fee_mxn NUMERIC(10,2) DEFAULT 0.00,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Registro de leads y sesiones WiFi (First-Party Data)
CREATE TABLE wifi_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mac_address_hash VARCHAR(64) NOT NULL,
    email VARCHAR(180),
    auth_provider VARCHAR(30) NOT NULL,
    accepted_privacy_policy BOOLEAN NOT NULL,
    marketing_consent BOOLEAN DEFAULT FALSE,
    first_connected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_connected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    device_info JSONB
);
CREATE INDEX idx_wifi_users_mac_hash ON wifi_users (mac_address_hash);

-- 3. Catálogo de promociones
CREATE TABLE promotions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES merchants(id) ON DELETE CASCADE,
    title VARCHAR(150) NOT NULL,
    description TEXT,
    discount_type VARCHAR(20) NOT NULL,
    discount_value NUMERIC(10,2) NOT NULL,
    valid_days INT[] DEFAULT '{1,2,3,4}',
    valid_hour_start INT DEFAULT 12,
    valid_hour_end INT DEFAULT 17,
    is_ev_exclusive BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE
);

-- 4. Cupones emitidos (Tokens OTP dinámicos)
CREATE TABLE issued_coupons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    coupon_code VARCHAR(12) UNIQUE NOT NULL,
    promotion_id UUID REFERENCES promotions(id),
    user_id UUID REFERENCES wifi_users(id),
    mac_address_hash VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE'
);

-- 5. Canjes en punto de venta (Audit Log)
CREATE TABLE redemptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    coupon_id UUID REFERENCES issued_coupons(id) UNIQUE,
    merchant_id UUID REFERENCES merchants(id),
    redeemed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    cashier_user VARCHAR(50),
    ticket_subtotal_mxn NUMERIC(10,2),
    discount_applied_mxn NUMERIC(10,2)
);
