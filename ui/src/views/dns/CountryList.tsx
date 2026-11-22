import { MapPinOff } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { DnsStats } from '../../api/types/DnsStats';
import { NEUTRAL } from '../../charts/palette';
import { type BarItem, BarList } from '../../components/BarList';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { Flag } from '../../components/Flag';
import { countryName } from '../../lib/countries';
import { Skeleton } from '../../components/Skeleton';
import { formatCount, labelled } from '../../lib/format';

interface CountryListProps {
  stats: DnsStats | null;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}

/**
 * Countries of the queried servers, as a ranked list with bars (flags are SVG, which chart
 * labels cannot hold). Servers without a country (private, group addresses) are summed on a
 * last, neutral line.
 */
export function CountryList({ stats, loading, error, onRetry }: CountryListProps) {
  const { t, i18n } = useTranslation();
  if (loading) return <Skeleton height={240} />;
  if (error !== null) return <ErrorState message={error} onRetry={onRetry} />;
  if (stats === null) return null;
  const queries = (n: number) => t('views.dns.map.queries', { count: n, formatted: formatCount(n) });
  const rows = stats.countries.flatMap((c) =>
    c.country === null
      ? []
      : [{ key: c.country, code: c.country, label: countryName(c.country, i18n.language), value: c.messages, servers: c.servers }],
  );
  const unknown = stats.country_unknown;
  if (rows.length === 0) {
    return (
      <div className="flex items-center justify-center">
        <EmptyState
          icon={MapPinOff}
          title={t('views.dns.charts.noCountry')}
          {...(unknown.servers > 0
            ? { description: t('views.dns.charts.localServers', { count: unknown.servers }) }
            : {})}
        />
      </div>
    );
  }
  const title = (label: string, servers: number, messages: number) =>
    labelled(label, t('views.dns.charts.serverQueries', { count: servers, queries: queries(messages) }), i18n.language);
  const items: BarItem[] = rows.map((r) => ({
    key: r.key,
    label: r.label,
    title: title(r.label, r.servers, r.value),
    lead: <Flag country={r.code} />,
    value: r.value,
    valueText: formatCount(r.value),
    color: NEUTRAL,
  }));
  if (unknown.messages > 0) {
    const label = t('views.dns.charts.countryUnknown');
    items.push({
      key: '__unknown',
      label,
      title: title(label, unknown.servers, unknown.messages),
      lead: <span aria-hidden className="inline-block w-4 shrink-0" />,
      value: unknown.messages,
      valueText: formatCount(unknown.messages),
      color: NEUTRAL,
      muted: true,
    });
  }
  return <BarList ariaLabel={t('views.dns.charts.countriesLabel')} items={items} />;
}
