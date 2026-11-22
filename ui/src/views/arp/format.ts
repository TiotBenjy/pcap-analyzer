// Pure helpers of the ARP view.

/**
 * Sort key of an address: IPv4 first, octets zero-padded (`4:192.168.001.010`) so that text order
 * is numeric, then the other addresses as written.
 */
export function ipSortKey(ip: string): string {
  const parts = ip.split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p))) return `6:${ip}`;
  return `4:${parts.map((p) => p.padStart(3, '0')).join('.')}`;
}
