import { createHmac } from 'node:crypto';

const HEX12 = /^[0-9a-f]{12}$/;

/**
 * Normaliza una MAC a "AA:BB:CC:DD:EE:FF".
 * Acepta separadores ":" "-" "." o ninguno (formato que manda RouterOS, Cisco, Windows, etc.).
 * Devuelve null si no es una MAC unicast válida.
 */
export function normalizeMac(input: string | null | undefined): string | null {
  if (typeof input !== 'string') return null;
  const hex = input.trim().toLowerCase().replace(/[:.\-]/g, '');
  if (!HEX12.test(hex)) return null;
  // El bit menos significativo del primer octeto = multicast/broadcast: nunca es un cliente.
  if (parseInt(hex.slice(0, 2), 16) & 0x01) return null;
  return hex.toUpperCase().match(/.{2}/g)!.join(':');
}

/**
 * MAC "localmente administrada" (bit 2 del primer octeto). iOS 14+, Android 10+ y Windows 11
 * usan MACs aleatorias por SSID con este bit encendido; sirve para medir la calidad de la
 * analítica de recurrencia, que depende de que la MAC sea estable.
 */
export function isRandomizedMac(mac: string): boolean {
  const first = parseInt(mac.slice(0, 2), 16);
  return (first & 0x02) === 0x02;
}

/**
 * Hash de la MAC para auditorías de recurrencia (RNF-3).
 * HMAC-SHA256 con un secreto del servidor: un SHA-256 simple sería reversible por fuerza bruta
 * (el espacio de MACs es pequeño y los OUI son públicos). Salida: 64 caracteres hex.
 */
export function hashMac(mac: string, secret: string): string {
  const normalized = normalizeMac(mac);
  if (!normalized) throw new Error(`MAC inválida: ${mac}`);
  return createHmac('sha256', secret).update(normalized).digest('hex');
}
