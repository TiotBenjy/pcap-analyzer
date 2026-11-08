import type { DnsServer } from '../../api/types/DnsServer';
import { countryName } from '../../lib/countries';
import { escapeHtml } from './dnsCharts';

// Data of the DNS server map (ServerMap.tsx): servers grouped by country, tooltip per country.

/** Addresses listed in the tooltip of a country. */
const TOOLTIP_SERVERS = 5;

export interface CountryServers {
  code: string;
  messages: number;
  /** Most queried first. */
  servers: { ip: string; messages: number }[];
}

/** Servers grouped by country (servers without a country are left out). */
export function groupByCountry(servers: readonly DnsServer[]): CountryServers[] {
  const byCode = new Map<string, CountryServers>();
  for (const s of servers) {
    const code = s.host.country;
    if (code === null) continue;
    const entry = byCode.get(code) ?? { code, messages: 0, servers: [] };
    entry.messages += s.messages;
    entry.servers.push({ ip: s.host.ip, messages: s.messages });
    byCode.set(code, entry);
  }
  const list = [...byCode.values()];
  for (const c of list) c.servers.sort((a, b) => b.messages - a.messages || a.ip.localeCompare(b.ip));
  return list.sort((a, b) => b.messages - a.messages || a.code.localeCompare(b.code));
}

export interface MapText {
  lang: string;
  queries: (n: number) => string;
}

/** Tooltip HTML of a country: name, queries, its most queried servers. */
export function countryTooltip(countries: readonly CountryServers[], text: MapText): (code: string) => string {
  const byCode = new Map(countries.map((c) => [c.code, c]));
  return (code) => {
    const c = byCode.get(code);
    const name = escapeHtml(countryName(code, text.lang));
    if (c === undefined) return name;
    const lines = c.servers
      .slice(0, TOOLTIP_SERVERS)
      .map((s) => `${escapeHtml(s.ip)}: ${escapeHtml(text.queries(s.messages))}`);
    if (c.servers.length > TOOLTIP_SERVERS) lines.push('…');
    return [`<b>${name}</b>: ${escapeHtml(text.queries(c.messages))}`, ...lines].join('<br/>');
  };
}
