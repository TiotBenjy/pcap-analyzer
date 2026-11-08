import { getRouteApi } from '@tanstack/react-router';
import { Download, HardDrive, Image, Server } from 'lucide-react';
import { useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePictures, usePictureStats } from '../../api/objectQueries';
import type { PictureFilters } from '../../api/objects';
import { useSession } from '../../api/sessionQueries';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import { formatBytes, formatCount } from '../../lib/format';
import { isViewable } from '../connections/session';
import { SessionGate } from '../connections/SessionGate';
import { useDebounced } from '../connections/useDebounced';
import { typeLabel } from './format';
import { PictureGrid } from './PictureGrid';
import { PictureViewer } from './PictureViewer';

const route = getRouteApi('/sessions/$sessionId');
const SELECT_CLASS = 'h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body sm:w-auto sm:max-w-64';

/** Pictures view: images extracted from plain HTTP responses, as a grid of thumbnails. */
export default function PicturesView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const viewable = isViewable(session.data);
  const stats = usePictureStats(sessionId, viewable);

  const [search, setSearch] = useState('');
  const [type, setType] = useState('');
  const [host, setHost] = useState('');
  const [sort, setSort] = useState<'time' | 'size'>('time');
  const q = useDebounced(search.trim(), 250);
  const filters = useMemo<PictureFilters>(
    () => ({ q: q === '' ? undefined : q, type: type || undefined, host: host || undefined, sort }),
    [q, type, host, sort],
  );
  const pictures = usePictures(sessionId, filters, viewable);
  const [open, setOpen] = useState<number | null>(null);
  const typeId = useId();
  const hostId = useId();
  const sortId = useId();

  const filtered = search !== '' || type !== '' || host !== '';
  const items = pictures.data?.items ?? [];
  const st = stats.data;

  let body;
  if (pictures.isError || stats.isError) {
    body = (
      <ErrorState
        message={t('views.pictures.loadError')}
        onRetry={() => {
          void stats.refetch();
          void pictures.refetch();
        }}
      />
    );
  } else if (pictures.data === undefined) {
    body = <Skeleton height={320} />;
  } else if (items.length === 0) {
    body = filtered ? (
      <EmptyState icon={Image} title={t('views.pictures.noMatch')} />
    ) : (
      <EmptyState icon={Image} title={t('views.pictures.empty')} description={t('views.pictures.emptyText')} />
    );
  } else {
    body = (
      <div className="flex min-w-0 flex-col gap-3">
        {pictures.data.truncated && (
          <p role="status" className="text-meta text-muted">
            {t('views.pictures.truncated', { count: items.length })}
          </p>
        )}
        <PictureGrid sessionId={sessionId} items={items} onOpen={setOpen} />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.pictures')}
        subtitle={session.data?.name ?? t('views.pictures.subtitle')}
        {...(st === undefined ? {} : { count: <Badge>{formatCount(st.count)}</Badge> })}
      />
      <SessionGate session={session}>
        <div data-testid="pictures-summary" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatCard icon={Image} label={t('views.pictures.stat.images')} value={st === undefined ? null : formatCount(st.count)} />
          <StatCard icon={HardDrive} label={t('views.pictures.stat.size')} value={st === undefined ? null : formatBytes(st.bytes)} />
          <StatCard
            icon={Download}
            label={t('views.pictures.stat.downloads')}
            value={st === undefined ? null : formatCount(st.occurrences)}
          />
          <StatCard icon={Server} label={t('views.pictures.stat.hosts')} value={st === undefined ? null : formatCount(st.hosts.length)} />
        </div>
        <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
              <div className="min-w-0 flex-1 basis-48">
                <FilterBar filters={[]} onToggle={() => undefined} search={search} onSearch={setSearch} searchPlaceholder={t('views.pictures.filters.search')} />
              </div>
              <label htmlFor={typeId} className="sr-only">
                {t('views.pictures.filters.type')}
              </label>
              <select
                id={typeId}
                value={type}
                onChange={(e) => {
                  setType(e.target.value);
                }}
                className={SELECT_CLASS}
              >
                <option value="">{t('views.pictures.filters.anyType')}</option>
                {(st?.types ?? []).map((ty) => (
                  <option key={ty.mime} value={ty.mime}>
                    {`${typeLabel(ty.mime)} (${formatCount(ty.count)})`}
                  </option>
                ))}
              </select>
              <label htmlFor={hostId} className="sr-only">
                {t('views.pictures.filters.host')}
              </label>
              <select
                id={hostId}
                value={host}
                onChange={(e) => {
                  setHost(e.target.value);
                }}
                className={SELECT_CLASS}
              >
                <option value="">{t('views.pictures.filters.anyHost')}</option>
                {(st?.hosts ?? []).map((h) => (
                  <option key={h.host} value={h.host}>
                    {`${h.host} (${formatCount(h.count)})`}
                  </option>
                ))}
              </select>
              <label htmlFor={sortId} className="sr-only">
                {t('views.pictures.filters.sort')}
              </label>
              <select
                id={sortId}
                value={sort}
                onChange={(e) => {
                  setSort(e.target.value === 'size' ? 'size' : 'time');
                }}
                className={SELECT_CLASS}
              >
                <option value="time">{t('views.pictures.filters.sortTime')}</option>
                <option value="size">{t('views.pictures.filters.sortSize')}</option>
              </select>
              {filtered && (
                <Button
                  variant="ghost"
                  onClick={() => {
                    setSearch('');
                    setType('');
                    setHost('');
                  }}
                >
                  {t('views.pictures.filters.clear')}
                </Button>
              )}
        </div>
        <Card>{body}</Card>
        {open !== null && (
          <PictureViewer
            sessionId={sessionId}
            items={items}
            index={open}
            onIndex={setOpen}
            onClose={() => {
              setOpen(null);
            }}
          />
        )}
      </SessionGate>
    </div>
  );
}
