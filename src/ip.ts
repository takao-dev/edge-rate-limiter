/**
 * IP utility functions for edge-rate-limiter.
 * Zero Runtime Dependencies.
 */

/**
 * Check whether an IP string is a private, loopback, or link-local address.
 */
export function isPrivateOrLoopbackIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;

  const trimmed = ip.trim();

  // IPv4 check
  if (trimmed.includes('.')) {
    const parts = trimmed.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return false;
    }

    const [b0, b1] = parts;

    // 127.0.0.0/8 (Loopback)
    if (b0 === 127) return true;
    // 10.0.0.0/8 (Private)
    if (b0 === 10) return true;
    // 172.16.0.0/12 (Private)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (b0 === 192 && b1 === 168) return true;
    // 169.254.0.0/16 (Link-local)
    if (b0 === 169 && b1 === 254) return true;
    // 0.0.0.0/8
    if (b0 === 0) return true;

    return false;
  }

  // IPv6 check
  const lower = trimmed.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) return true;

  return false;
}
