import { MapPinOff } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { DnsStats } from '../../api/types/DnsStats';
import { NEUTRAL } from '../../charts/palette';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { Flag } from '../../components/Flag';
import { countryName } from '../../lib/countries';
import { Skeleton } from '../../components/Skeleton';
import { formatCount } from '../../lib/format';

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
  const max = Math.max(...rows.map((r) => r.value), unknown.messages, 1);
  return (
    <ol aria-label={t('views.dns.charts.countriesLabel')} className="flex flex-col gap-1.5">
      {rows.map((r) => (
        <Row
          key={r.key}
          flag={<Flag country={r.code} />}
          label={r.label}
          title={`${r.label}: ${t('views.dns.charts.serverQueries', { count: r.servers, queries: formatCount(r.value) })}`}
          value={r.value}
          max={max}
        />
      ))}
      {unknown.messages > 0 && (
        <Row
          flag={<span aria-hidden className="inline-block w-[1.333em] shrink-0" />}
          label={t('views.dns.charts.countryUnknown')}
          title={`${t('views.dns.charts.countryUnknown')}: ${t('views.dns.charts.serverQueries', {
            count: unknown.servers,
            queries: formatCount(unknown.messages),
          })}`}
          value={unknown.messages}
          max={max}
          muted
        />
      )}
    </ol>
  );
}

interface RowProps {
  flag: ReactNode;
  label: string;
  title: string;
  value: number;
  max: number;
  muted?: boolean;
}

function Row({ flag, label, title, value, max, muted = false }: RowProps) {
  return (
    <li className="grid grid-cols-[minmax(0,9rem)_minmax(0,1fr)_auto] items-center gap-2 text-table">
      <span className="flex min-w-0 items-center gap-1.5">
        {flag}
        <span data-testid="truncatable" title={title} className="min-w-0 truncate">
          {label}
        </span>
      </span>
      <span aria-hidden className="h-2 min-w-0 rounded-sm bg-subtle">
        <span
          className="block h-full rounded-sm"
          style={{ width: `${Math.max(2, (100 * value) / max)}%`, backgroundColor: NEUTRAL, opacity: muted ? 0.5 : 1 }}
        />
      </span>
      <span className="num text-right text-muted">{formatCount(value)}</span>
    </li>
  );
}
