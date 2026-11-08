import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useDnsServers } from '../../api/dnsQueries';
import { Card } from '../../components/Card';
import { ErrorState } from '../../components/ErrorState';
import { WorldMap } from '../../components/WorldMap';
import { formatCount } from '../../lib/format';
import { countryTooltip, groupByCountry } from './serverMap';

/** Map of the queried DNS servers: light choropleth and points proportional to the queries. */
export function ServerMap({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const { t, i18n } = useTranslation();
  const servers = useDnsServers(sessionId, enabled);
  const countries = useMemo(() => groupByCountry(servers.data?.items ?? []), [servers.data]);
  const values = useMemo(() => new Map(countries.map((c) => [c.code, c.messages])), [countries]);
  const tooltip = useMemo(
    () =>
      countryTooltip(countries, {
        lang: i18n.language,
        queries: (n) => t('views.dns.map.queries', { count: n, formatted: formatCount(n) }),
      }),
    [countries, i18n.language, t],
  );

  if (servers.isError) {
    return (
      <Card title={t('views.dns.map.title')}>
        <ErrorState
          message={t('views.dns.loadError')}
          onRetry={() => {
            void servers.refetch();
          }}
        />
      </Card>
    );
  }
  // Nothing to place (or not known yet): the country list of the charts row already says so.
  if (countries.length === 0) return null;
  return (
    <Card title={t('views.dns.map.title')}>
      <WorldMap values={values} points tooltip={tooltip} ariaLabel={t('views.dns.map.label')} errorText={t('views.dns.loadError')} />
    </Card>
  );
}
