import { Link } from '@tanstack/react-router';
import { ArrowRight, Download, FileText } from 'lucide-react';
import { type ReactNode, useCallback, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { FTP_DIRECTIONS, type FtpTransferParams } from '../../api/ftp';
import { useFtpTransfers } from '../../api/ftpQueries';
import { useRendition } from '../../api/objectQueries';
import { downloadObject } from '../../api/objects';
import type { FtpDirection } from '../../api/types/FtpDirection';
import type { FtpTransferInfo } from '../../api/types/FtpTransferInfo';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { CopyButton } from '../../components/CopyButton';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorNote } from '../../components/ErrorNote';
import { ErrorState } from '../../components/ErrorState';
import { ExpandableList } from '../../components/ExpandableList';
import { SearchInput } from '../../components/SearchInput';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Timestamp } from '../../components/Timestamp';
import { cn } from '../../lib/cn';
import { formatByteCount, formatBytes, formatCount, formatTimestamp } from '../../lib/format';
import { useDebounced } from '../../lib/useDebounced';
import { baseName, transferStatus } from './format';
import { Field, ListLoading } from './parts';

/** Column layout of the transfer rows (wide screens). */
const TRANSFER_GRID =
  'md:grid md:grid-cols-[80px_104px_minmax(0,1fr)_88px_minmax(7rem,0.5fr)] md:items-center md:gap-3 ' +
  'xl:grid-cols-[80px_112px_minmax(0,1.4fr)_96px_minmax(8rem,0.5fr)_minmax(0,1.2fr)]';
/** Same layout without the client and server column (transfers of one session). */
const COMPACT_GRID =
  'md:grid md:grid-cols-[80px_104px_minmax(0,1fr)_88px_minmax(7rem,0.5fr)] md:items-center md:gap-3';
const SELECT_CLASS = 'h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body';

type DirectionFilter = FtpDirection | 'all';

interface TransfersCardProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
}

/** Every transfer of the session (or of the time range), newest last. */
export function TransfersCard({ sessionId, enabled, oneDay }: TransfersCardProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [direction, setDirection] = useState<DirectionFilter>('all');
  const params = useMemo<FtpTransferParams>(() => {
    const p: FtpTransferParams = {};
    if (q !== '') p.q = q;
    if (direction !== 'all') p.direction = direction;
    return p;
  }, [q, direction]);
  const query = useFtpTransfers(sessionId, params, enabled);
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total_estimate ?? null;
  const loadMore = useCallback(() => {
    void query.fetchNextPage();
  }, [query]);

  let body: ReactNode;
  if (query.isPending) body = <ListLoading />;
  else if (query.isError)
    body = (
      <ErrorState
        message={t('views.ftp.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  else if (items.length === 0)
    body =
      q === '' && direction === 'all' ? (
        <EmptyState icon={FileText} title={t('views.ftp.transfers.empty')} />
      ) : (
        <EmptyState title={t('views.ftp.transfers.noMatch')} />
      );
  else
    body = (
      <TransferList
        sessionId={sessionId}
        items={items}
        oneDay={oneDay}
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    );

  return (
    <Card
      title={t('views.ftp.transfers.title')}
      flush
      {...(total === null ? {} : { actions: <span className="num text-meta text-muted">{formatCount(total)}</span> })}
      filters={
        <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={t('views.ftp.transfers.search')} />
          <DirectionControl value={direction} onChange={setDirection} />
        </div>
      }
    >
      {body}
    </Card>
  );
}

/** Direction filter: a segmented control from `sm`, a list below. */
function DirectionControl({ value, onChange }: { value: DirectionFilter; onChange: (v: DirectionFilter) => void }) {
  const { t } = useTranslation();
  const id = useId();
  const options = (['all', ...FTP_DIRECTIONS] as const).map((k) => ({ value: k, label: t(`views.ftp.transfers.direction.${k}`) }));
  return (
    <>
      <div className="hidden sm:block">
        <SegmentedControl hideLabel label={t('views.ftp.transfers.direction.label')} value={value} options={options} onChange={onChange} />
      </div>
      <div className="w-full sm:hidden">
        <label htmlFor={id} className="sr-only">
          {t('views.ftp.transfers.direction.label')}
        </label>
        <select
          id={id}
          value={value}
          onChange={(e) => {
            onChange(e.target.value as DirectionFilter);
          }}
          className={SELECT_CLASS}
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
    </>
  );
}

interface TransferListProps {
  sessionId: string;
  items: readonly FtpTransferInfo[];
  oneDay: boolean;
  /** Transfers of one session: no client and server column, no paging. */
  compact?: boolean;
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
}

/** No more pages: the transfers of one session come in one answer. */
const noop = () => undefined;

export function TransferList({ sessionId, items, oneDay, compact = false, hasMore = false, loadingMore = false, onLoadMore = noop }: TransferListProps) {
  const { t } = useTranslation();
  return (
    <ExpandableList
      items={items}
      getKey={(x) => `${x.flow_id}:${x.seq}`}
      ariaLabel={t(compact ? 'views.ftp.detail.transfers' : 'views.ftp.transfers.label')}
      header={<TransferHeader compact={compact} />}
      renderRow={(x) => <TransferRow transfer={x} oneDay={oneDay} compact={compact} />}
      renderDetail={(x) => <TransferDetail sessionId={sessionId} transfer={x} />}
      rowLabel={(x) =>
        t('views.ftp.transfers.rowLabel', {
          command: x.command,
          path: x.path ?? t('views.ftp.transfers.noPath'),
        }) + `, ${formatTimestamp(x.ts_us, !oneDay)}`
      }
      hasMore={hasMore}
      loadingMore={loadingMore}
      onLoadMore={onLoadMore}
    />
  );
}

function TransferHeader({ compact }: { compact: boolean }) {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={compact ? COMPACT_GRID : TRANSFER_GRID}>
        <span>{t('views.ftp.transfers.col.time')}</span>
        <span>{t('views.ftp.transfers.col.direction')}</span>
        <span>{t('views.ftp.transfers.col.path')}</span>
        <span className="text-right">{t('views.ftp.transfers.col.size')}</span>
        <span>{t('views.ftp.transfers.col.status')}</span>
        {!compact && <span className="hidden xl:block">{t('views.ftp.transfers.col.session')}</span>}
      </div>
    </div>
  );
}

function DirectionBadge({ transfer: x }: { transfer: FtpTransferInfo }) {
  const { t } = useTranslation();
  return (
    <Badge tone={x.direction === 'upload' ? 'accent' : 'neutral'} className="max-w-full min-w-0 overflow-hidden">
      <span className="truncate">{t(`views.ftp.transfers.badge.${x.direction}`)}</span>
    </Badge>
  );
}

function StatusBadges({ transfer: x }: { transfer: FtpTransferInfo }) {
  const { t } = useTranslation();
  const status = transferStatus(x);
  const tone = status === 'complete' ? 'success' : status === 'noReply' ? 'neutral' : status === 'interrupted' ? 'warning' : 'danger';
  const label = t(`views.ftp.transfers.status.${status}`);
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-1">
      <Badge tone={tone} {...(x.status_text === null ? {} : { title: x.status_text })}>
        {x.status === null ? label : `${x.status} ${label}`}
      </Badge>
      {x.truncated && <Badge tone="warning">{t('views.ftp.transfers.truncated')}</Badge>}
    </span>
  );
}

function TransferRow({ transfer: x, oneDay, compact }: { transfer: FtpTransferInfo; oneDay: boolean; compact: boolean }) {
  const { t } = useTranslation();
  const path = x.path ?? t('views.ftp.transfers.noPath');
  return (
    <span className={cn('flex min-w-0 flex-col gap-1', compact ? COMPACT_GRID : TRANSFER_GRID)}>
      <span className="flex min-w-0 items-center justify-between gap-2 md:contents">
        <Timestamp us={x.ts_us} withDate={!oneDay} className="order-2 shrink-0 text-meta text-muted md:order-none" />
        <span className="order-1 min-w-0 md:order-none">
          <DirectionBadge transfer={x} />
        </span>
      </span>
      <span data-testid="truncatable" title={path} className={cn('block min-w-0 truncate font-mono text-meta', x.path === null && 'text-muted')}>
        {path}
      </span>
      {/* Narrow screens: size and status share a line. */}
      <span className="flex min-w-0 items-center justify-between gap-2 md:contents">
        <span className="num order-2 shrink-0 text-meta md:order-none md:text-right">{x.data_flow_id === null ? '-' : formatBytes(x.bytes)}</span>
        <span className="order-1 min-w-0 md:order-none">
          <StatusBadges transfer={x} />
        </span>
      </span>
      {!compact && (
        <span className="hidden min-w-0 items-center gap-1.5 text-meta xl:flex">
          <span className="min-w-0 shrink">
            <Endpoint endpoint={x.client} show="address" className="text-meta" />
          </span>
          <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint" />
          <span className="min-w-0 shrink">
            <Endpoint endpoint={x.server} port={x.server_port} show="address" className="text-meta" />
          </span>
        </span>
      )}
    </span>
  );
}

function TransferDetail({ sessionId, transfer: x }: { sessionId: string; transfer: FtpTransferInfo }) {
  const { t } = useTranslation();
  const image = x.sha256 !== null && x.mime?.startsWith('image/') === true && x.mime !== 'image/svg+xml';
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <dl className="flex min-w-0 flex-col gap-2">
        <Field label={t('views.ftp.transfers.command')}>
          <span className="block font-mono text-meta [overflow-wrap:anywhere]">
            <span className="font-semibold">{x.command}</span>
            {x.path !== null && <span className="text-accent">{` ${x.path}`}</span>}
          </span>
        </Field>
        <Field label={t('views.ftp.transfers.reply')}>
          {x.status === null ? (
            <span className="text-meta text-muted">{t('views.ftp.transfers.status.noReply')}</span>
          ) : (
            <span className="block font-mono text-meta [overflow-wrap:anywhere]">{`${x.status} ${x.status_text ?? ''}`}</span>
          )}
        </Field>
        <Field label={t('views.ftp.transfers.mode')}>
          <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-meta">
            {x.mode !== null && (
              <span>
                {t(x.mode === 'active' ? 'views.ftp.transfers.modes.active' : 'views.ftp.transfers.modes.passive', {
                  command: x.mode_command ?? (x.mode === 'active' ? 'PORT' : 'PASV'),
                })}
              </span>
            )}
            {x.data_flow_id === null ? (
              <span className="text-muted">{t('views.ftp.transfers.noData')}</span>
            ) : (
              <span className="num text-muted">{formatByteCount(x.bytes)}</span>
            )}
          </span>
        </Field>
        {x.restart_offset !== null && (
          <Field label={t('views.ftp.transfers.restart')}>
            <span className="num text-meta">{formatCount(x.restart_offset)}</span>
          </Field>
        )}
        {x.sha256 !== null && (
          <>
            <Field label={t('views.ftp.transfers.type')}>
              <span className="font-mono text-meta">{x.mime ?? '-'}</span>
            </Field>
            <Field label={t('views.ftp.transfers.sha256')}>
              <span className="flex min-w-0 items-center gap-1">
                <span data-testid="truncatable" title={x.sha256} className="min-w-0 truncate font-mono text-meta">
                  {x.sha256}
                </span>
                <CopyButton value={x.sha256} name={t('views.ftp.transfers.sha256')} />
              </span>
            </Field>
          </>
        )}
      </dl>
      {x.sha256 !== null ? (
        <StoredFile sessionId={sessionId} sha256={x.sha256} name={baseName(x.path)} image={image} />
      ) : (
        x.direction !== 'listing' && <p className="text-meta text-muted">{t('views.ftp.transfers.notStored')}</p>
      )}
      {x.listing !== null && (
        <div className="flex min-w-0 flex-col gap-1">
          <span className="text-meta text-muted">{t('views.ftp.transfers.listingNote')}</span>
          {/* Text only: React escapes it, nothing from the capture is ever interpreted as markup. */}
          <pre
            data-testid="ftp-listing"
            className="max-h-64 max-w-full min-w-0 overflow-auto rounded-md border border-line bg-subtle p-3 font-mono text-meta whitespace-pre"
          >
            {x.listing}
          </pre>
        </div>
      )}
    </div>
  );
}

/** A stored file: its PNG thumbnail generated by the backend for an image, download, link to Pictures. */
function StoredFile({ sessionId, sha256, name, image }: { sessionId: string; sha256: string; name: string; image: boolean }) {
  const { t } = useTranslation();
  const thumb = useRendition(sessionId, sha256, 'thumb', image);
  const [error, setError] = useState<unknown>(null);
  return (
    <div className="flex min-w-0 flex-col gap-2">
      {image && thumb.data !== undefined && (
        <img
          src={thumb.data}
          alt={t('views.ftp.transfers.thumbnail', { name })}
          className="max-h-40 max-w-full self-start rounded-md border border-line object-contain"
        />
      )}
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Button
          onClick={() => {
            setError(null);
            downloadObject(sessionId, { sha256, file_name: name }).catch((e: unknown) => {
              setError(e);
            });
          }}
        >
          <Download aria-hidden size={16} strokeWidth={1.75} />
          {t('views.ftp.transfers.download')}
        </Button>
        {image && (
          <Link to="/sessions/$sessionId/pictures" params={{ sessionId }} className="text-meta font-medium text-accent hover:underline">
            {t('views.ftp.transfers.pictures')}
          </Link>
        )}
      </div>
      {error !== null && <ErrorNote error={error} format={(message) => t('views.ftp.transfers.downloadError', { message })} />}
    </div>
  );
}
