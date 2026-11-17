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
  if (trimmed.includes('.') && !trimmed.includes(':')) {
    const octets = trimmed.split('.');
    if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || (part.length > 1 && part.startsWith('0')))) return false;
    const parts = octets.map(Number);
    if (parts.some((n) => n < 0 || n > 255)) {
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

  const groups = parseIPv6(trimmed);
  if (!groups) return false;
  if (groups.every((part) => part === 0) || groups.slice(0, 7).every((part) => part === 0) && groups[7] === 1) return true;
  if ((groups[0] & 0xfe00) === 0xfc00) return true; // fc00::/7
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10
  if (groups.slice(0, 5).every((part) => part === 0) && groups[5] === 0xffff) {
    const mapped = `${groups[6] >>> 8}.${groups[6] & 255}.${groups[7] >>> 8}.${groups[7] & 255}`;
    return isPrivateOrLoopbackIp(mapped);
  }
  return false;
}

function parseIPv6(value: string): number[] | null {
  if (value.includes('%')) return null;
  let address = value.toLowerCase();
  const ipv4Match = address.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (ipv4Match) {
    const parts = ipv4Match[1].split('.');
    if (parts.some((part) => !/^\d{1,3}$/.test(part) || (part.length > 1 && part.startsWith('0')) || Number(part) > 255)) return null;
    const [a, b, c, d] = parts.map(Number);
    address = address.slice(0, -ipv4Match[1].length) + `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  if (!/^[0-9a-f:]+$/.test(address) || address.includes(':::')) return null;
  const compressed = address.includes('::');
  if (compressed && address.indexOf('::') !== address.lastIndexOf('::')) return null;
  const halves = compressed ? address.split('::') : [address];
  const left = halves[0] ? halves[0].split(':') : [];
  const right = compressed && halves[1] ? halves[1].split(':') : [];
  const values = [...left, ...right];
  if (values.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  if (compressed ? values.length >= 8 : values.length !== 8) return null;
  const groups = [...left.map((part) => parseInt(part, 16))];
  if (compressed) groups.push(...new Array(8 - values.length).fill(0));
  groups.push(...right.map((part) => parseInt(part, 16)));
  return groups.length === 8 ? groups : null;
}
