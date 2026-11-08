import { ChevronDown, ChevronRight, Globe, SearchX } from 'lucide-react';
import { Fragment, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { DnsFilter } from '../../api/dns';
import { useDnsPairs } from '../../api/dnsQueries';
import type { Endpoint as EndpointInfo } from '../../api/types/Endpoint';
import type { DnsPair } from '../../api/types/DnsPair';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Endpoint } from '../../components/Endpoint';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { Skeleton } from '../../components/Skeleton';
import { cn } from '../../lib/cn';
import { formatCount } from '../../lib/format';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { protocolLabel } from './dnsFormat';
import { MessagesPanel } from './MessagesPanel';
import { useElementWidth } from '../../lib/useElementWidth';

/** Below 768 px the layout is always the cards one (docs/UI_GUIDELINES.md). */
const MD_QUERY = '(min-width: 768px)';
/** Container width from which the columns of the tables fit; cards below. */
const TABLE_MIN_WIDTH = 860;

interface PairsListProps {
  sessionId: string;
  filter: DnsFilter;
  enabled: boolean;
  /** Whether the session has DNS traffic at all (`null` while unknown): picks the empty state. */
  hasTraffic: boolean | null;
}

/** Clients and servers, grouped; a row expands into its detailed transactions. */
export function PairsList(props: PairsListProps) {
  const md = useMediaQuery(MD_QUERY);
  const [ref, width] = useElementWidth();
  // Without layout information (first render, tests), the viewport decides.
  const wide = md && (width === 0 || width >= TABLE_MIN_WIDTH);
  return (
    <div ref={ref} className="min-w-0">
      <PairsContent {...props} wide={wide} />
    </div>
  );
}

function PairsContent({ sessionId, filter, enabled, hasTraffic, wide }: PairsListProps & { wide: boolean }) {
  const { t } = useTranslation();
  const pairs = useDnsPairs(sessionId, filter, enabled);
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const toggle = (id: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (pairs.isPending) {
    return (
      <div className="flex flex-col gap-2 p-3 sm:p-4">
        <Skeleton height={32} />
        <Skeleton height={32} />
        <Skeleton height={32} />
      </div>
    );
  }
  if (pairs.isError) {
    return (
      <ErrorState
        message={t('views.dns.loadError')}
        onRetry={() => {
          void pairs.refetch();
        }}
      />
    );
  }
  const items = pairs.data.pages.flatMap((p) => p.items);
  const total = pairs.data.pages[0]?.total_estimate ?? items.length;
  if (items.length === 0) {
    return hasTraffic === false ? (
      <EmptyState icon={Globe} title={t('views.dns.table.empty')} />
    ) : (
      <EmptyState icon={SearchX} title={t('views.dns.table.noMatch')} />
    );
  }

  const footer = (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-3 py-2 sm:px-4">
      <span className="num text-meta text-muted">
        {t('views.dns.table.shown', { shown: formatCount(items.length), total: formatCount(total) })}
      </span>
      {pairs.hasNextPage && (
        <Button
          variant="secondary"
          disabled={pairs.isFetchingNextPage}
          onClick={() => {
            void pairs.fetchNextPage();
          }}
        >
          {t('views.dns.table.loadMore')}
        </Button>
      )}
    </div>
  );

  if (!wide) {
    return (
      <>
        <ul aria-label={t('views.dns.table.label')} className="divide-y divide-line">
          {items.map((p) => (
            <PairCard
              key={p.id}
              pair={p}
              open={open.has(p.id)}
              onToggle={() => {
                toggle(p.id);
              }}
              sessionId={sessionId}
              filter={filter}
            />
          ))}
        </ul>
        {footer}
      </>
    );
  }

  return (
    <>
      <div className="w-full min-w-0 overflow-x-auto">
        <table aria-label={t('views.dns.table.label')} className="w-full table-fixed border-collapse text-table">
          <colgroup>
            <col className="w-10" />
            <col className="w-[22%]" />
            <col className="w-[24%]" />
            <col className="w-24" />
            <col />
            <col className="w-24" />
            <col className="w-20" />
          </colgroup>
          <thead>
            <tr className="border-b border-line text-left text-meta text-muted">
              <th scope="col" className="h-8 px-2 font-medium">
                <span className="sr-only">{t('views.dns.table.details')}</span>
              </th>
              <th scope="col" className="px-3 font-medium">
                {t('views.dns.table.client')}
              </th>
              <th scope="col" className="px-3 font-medium">
                {t('views.dns.table.server')}
              </th>
              <th scope="col" className="px-3 font-medium">
                {t('views.dns.table.protocol')}
              </th>
              <th scope="col" className="px-3 font-medium">
                {t('views.dns.table.names')}
              </th>
              <th scope="col" className="px-3 text-right font-medium">
                {t('views.dns.table.queries')}
              </th>
              <th scope="col" className="px-3 text-right font-medium">
                {t('views.dns.table.errors')}
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((p) => {
              const isOpen = open.has(p.id);
              return (
                <Fragment key={p.id}>
                  <tr className={cn('border-b border-line align-top', isOpen && 'bg-subtle/50')}>
                    <td className="px-2 py-1.5">
                      <ExpandButton
                        open={isOpen}
                        pair={p}
                        onToggle={() => {
                          toggle(p.id);
                        }}
                      />
                    </td>
                    <td className="px-3 py-2">
                      <HostCell host={p.client} />
                    </td>
                    <td className="px-3 py-2">
                      <HostCell host={p.server} />
                    </td>
                    <td className="px-3 py-2">
                      <Badge>{protocolLabel(t, p.protocol)}</Badge>
                    </td>
                    <td className="px-3 py-2">
                      <Names
                        pair={p}
                        open={isOpen}
                        onMore={() => {
                          toggle(p.id);
                        }}
                      />
                    </td>
                    <td className="num px-3 py-2 text-right">{formatCount(p.messages)}</td>
                    <td className={cn('num px-3 py-2 text-right', p.errors > 0 ? 'text-danger' : 'text-muted')}>
                      {formatCount(p.errors)}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="border-b border-line">
                      <td colSpan={7} className="bg-subtle/50 px-3 pt-1 pb-3">
                        <MessagesPanel sessionId={sessionId} pair={p} filter={filter} wide />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      {footer}
    </>
  );
}

function HostCell({ host }: { host: EndpointInfo }) {
  return <Endpoint endpoint={host} />;
}

function ExpandButton({ open, pair, onToggle }: { open: boolean; pair: DnsPair; onToggle: () => void }) {
  const { t } = useTranslation();
  const Icon = open ? ChevronDown : ChevronRight;
  return (
    <button
      type="button"
      aria-expanded={open}
      aria-label={open ? t('views.dns.table.collapse') : t('views.dns.table.expand', { client: pair.client.ip, server: pair.server.ip })}
      onClick={onToggle}
      className="inline-flex size-8 items-center justify-center rounded-md text-muted hover:bg-subtle hover:text-fg"
    >
      <Icon aria-hidden size={16} strokeWidth={1.75} />
    </button>
  );
}

/** The most frequent names, then "n more" (expands the row, whose detail lists every query). */
function Names({ pair, open, onMore }: { pair: DnsPair; open: boolean; onMore: () => void }) {
  const { t } = useTranslation();
  const more = pair.name_count - pair.top_names.length;
  return (
    <div className="flex min-w-0 flex-col">
      {pair.top_names.map((n) => (
        <span key={n} data-testid="truncatable" title={n} className="truncate font-mono">
          {n}
        </span>
      ))}
      {more > 0 && !open && (
        <button type="button" onClick={onMore} className="self-start text-meta text-accent hover:underline">
          {t('views.dns.table.more', { count: more })}
        </button>
      )}
    </div>
  );
}

interface PairCardProps {
  pair: DnsPair;
  open: boolean;
  onToggle: () => void;
  sessionId: string;
  filter: DnsFilter;
}

/** Narrow layout: one card per pair. */
function PairCard({ pair, open, onToggle, sessionId, filter }: PairCardProps) {
  const { t } = useTranslation();
  return (
    <li className={cn('min-w-0 px-3 py-2.5', open && 'bg-subtle/50')}>
      <div className="flex min-w-0 items-start gap-2">
        <ExpandButton open={open} pair={pair} onToggle={onToggle} />
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <Badge>{protocolLabel(t, pair.protocol)}</Badge>
            <span className="num text-meta text-muted">
              {t('views.dns.table.cardCounts', { queries: formatCount(pair.messages), errors: formatCount(pair.errors) })}
            </span>
          </div>
          <dl className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] gap-x-2 gap-y-0.5">
            <dt className="text-meta text-muted">{t('views.dns.table.client')}</dt>
            <dd className="min-w-0">
              <HostCell host={pair.client} />
            </dd>
            <dt className="text-meta text-muted">{t('views.dns.table.server')}</dt>
            <dd className="min-w-0">
              <HostCell host={pair.server} />
            </dd>
          </dl>
          <Names pair={pair} open={open} onMore={onToggle} />
        </div>
      </div>
      {open && (
        <div className="mt-2 min-w-0">
          <MessagesPanel sessionId={sessionId} pair={pair} filter={filter} wide={false} />
        </div>
      )}
    </li>
  );
}
