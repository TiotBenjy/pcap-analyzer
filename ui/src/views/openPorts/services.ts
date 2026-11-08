import type { OpenPortInfo } from '../../api/types/OpenPortInfo';
import type { PortCount } from '../../api/types/PortCount';

// Port labels and the "detected service differs from IANA" rule of the Open Ports view.

/**
 * IANA names compatible with a service detected by content. A detected service matches when it
 * equals the IANA name or appears here (TLS covers the `*s` secure variants of every protocol).
 */
const COMPATIBLE: Readonly<Record<string, (iana: string) => boolean>> = {
  http: (n) => n.startsWith('http') || n === 'www' || n === 'www-http' || n === 'webcache',
  tls: (n) => n === 'https' || n === 'ssl' || (n.length > 3 && n.endsWith('s')) || n.startsWith('https'),
  smb: (n) => n === 'microsoft-ds' || n === 'netbios-ssn' || n === 'cifs',
  smtp: (n) => n === 'smtp' || n === 'submission' || n === 'submissions' || n === 'urd',
  ftp: (n) => n === 'ftp' || n === 'ftps',
  pop3: (n) => n === 'pop3' || n === 'pop3s',
  imap: (n) => n === 'imap' || n === 'imaps' || n === 'imap3',
  vnc: (n) => n === 'rfb' || n.startsWith('vnc'),
  ssh: (n) => n === 'ssh',
  rtsp: (n) => n === 'rtsp',
};

/** True when both names are known and do not describe the same service. */
export function serviceMismatch(detected: string | null, iana: string | null): boolean {
  if (detected === null || iana === null) return false;
  const d = detected.toLowerCase();
  const n = iana.toLowerCase();
  if (d === n) return false;
  const rule = COMPATIBLE[d];
  return rule === undefined ? true : !rule(n);
}

/** Name shown next to the port: the detected service when it differs, else the IANA name. */
export function serviceName(p: Pick<OpenPortInfo, 'service' | 'detected'>): string | null {
  return serviceMismatch(p.detected, p.service) ? p.detected : (p.service ?? p.detected);
}

/** Port and transport, transport only for UDP (`443`, `53/udp`). */
export function portLabel(p: Pick<OpenPortInfo, 'port' | 'transport'>): string {
  return p.transport === 'udp' ? `${p.port}/udp` : String(p.port);
}

/** Bar label of the chart: `443 https`, `53/udp domain`, `61863` when unknown. */
export function barLabel(p: PortCount): string {
  const name = serviceName(p);
  return name === null ? portLabel(p) : `${portLabel(p)} ${name}`;
}
