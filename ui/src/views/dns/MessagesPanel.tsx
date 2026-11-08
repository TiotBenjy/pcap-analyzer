import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { DnsFilter } from '../../api/dns';
import { useDnsMessages } from '../../api/dnsQueries';
import type { DnsMessage } from '../../api/types/DnsMessage';
import type { DnsPair } from '../../api/types/DnsPair';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { Skeleton } from '../../components/Skeleton';
import { formatCount, formatTimestamp } from '../../lib/format';
import { answerText, formatLatency, rcodeLabel, rcodeTone, suffixLabel } from './dnsFormat';

/** Answers listed per transaction before "n more". */
const ANSWERS_SHOWN = 3;

interface MessagesPanelProps {
  sessionId: string;
  pair: DnsPair;
  filter: DnsFilter;
  /** Table layout (the pairs table is shown), else stacked entries. */
  wide: boolean;
}

/** True while rows of the scrolling list are hidden below its visible part. */
function useHiddenBelow(el: HTMLElement | null, pages: number): boolean {
  const [hidden, setHidden] = useState(false);
  useEffect(() => {
    if (el === null) return;
    const check = () => {
      setHidden(el.scrollTop + el.clientHeight < el.scrollHeight - 1);
    };
    check();
    el.addEventListener('scroll', check, { passive: true });
    const ro = new ResizeObserver(check);
    ro.observe(el);
    return () => {
      el.removeEventListener('scroll', check);
      ro.disconnect();
    };
  }, [el, pages]);
  return hidden;
}

/** Transactions of one pair, in time order, with the filters of the view. */
export function MessagesPanel({ sessionId, pair, filter, wide }: MessagesPanelProps) {
  const { t } = useTranslation();
  const messages = useDnsMessages(sessionId, pair.id, filter, true);
  const label = t('views.dns.messages.label', { client: pair.client.ip, server: pair.server.ip });
  const [scroller, setScroller] = useState<HTMLElement | null>(null);
  const hidden = useHiddenBelow(scroller, messages.data?.pages.length ?? 0);

  if (messages.isPending) return <Skeleton height={64} />;
  if (messages.isError) {
    return (
      <ErrorState
        message={t('views.dns.loadError')}
        onRetry={() => {
          void messages.refetch();
        }}
      />
    );
  }
  const items = messages.data.pages.flatMap((p) => p.items);
  const total = messages.data.pages[0]?.total_estimate ?? items.length;
  if (items.length === 0) return <EmptyState title={t('views.dns.messages.empty')} />;

  const more = (
    <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
      <span className="num text-meta text-muted">
        {t('views.dns.table.shown', { shown: formatCount(items.length), total: formatCount(total) })}
        {hidden && <span className="ml-2">{t('views.dns.messages.scrollHint')}</span>}
      </span>
      {messages.hasNextPage && (
        <Button
          variant="secondary"
          disabled={messages.isFetchingNextPage}
          onClick={() => {
            void messages.fetchNextPage();
          }}
        >
          {t('views.dns.table.loadMore')}
        </Button>
      )}
    </div>
  );

  if (!wide) {
    return (
      <div className="min-w-0">
        <ul
          ref={setScroller}
          aria-label={label}
          className="flex max-h-[28rem] flex-col divide-y divide-line overflow-y-auto rounded-md border border-line bg-surface"
        >
          {items.map((m) => (
            <li key={m.id} className="flex min-w-0 flex-col gap-1 px-2.5 py-2">
              <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
                <Result message={m} />
                <span className="num text-meta text-muted">{formatTimestamp(m.ts_us)}</span>
                {m.latency_us !== null && <span className="num text-meta text-muted">{formatLatency(m.latency_us)}</span>}
              </div>
              <QueryName message={m} />
              <Answers message={m} />
            </li>
          ))}
        </ul>
        {more}
      </div>
    );
  }

  return (
    <div className="min-w-0">
      <div
        ref={setScroller}
        className="max-h-[28rem] w-full min-w-0 overflow-auto rounded-md border border-line bg-surface"
      >
        <table aria-label={label} className="w-full table-fixed border-collapse text-table">
          <colgroup>
            <col className="w-44" />
            <col />
            <col className="w-20" />
            <col className="w-32" />
            <col className="w-[30%]" />
            <col className="w-20" />
          </colgroup>
          <thead className="sticky top-0 z-10 bg-surface">
            <tr className="border-b border-line text-left text-meta text-muted">
              <th scope="col" className="h-8 px-2.5 font-medium">
                {t('views.dns.messages.time')}
              </th>
              <th scope="col" className="px-2.5 font-medium">
                {t('views.dns.messages.name')}
              </th>
              <th scope="col" className="px-2.5 font-medium">
                {t('views.dns.messages.type')}
              </th>
              <th scope="col" className="px-2.5 font-medium">
                {t('views.dns.messages.result')}
              </th>
              <th scope="col" className="px-2.5 font-medium">
                {t('views.dns.messages.answers')}
              </th>
              <th scope="col" className="px-2.5 text-right font-medium">
                {t('views.dns.messages.latency')}
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((m) => (
              <tr key={m.id} className="border-b border-line align-top last:border-b-0">
                <td className="num truncate px-2.5 py-1.5 text-muted">{formatTimestamp(m.ts_us)}</td>
                <td className="px-2.5 py-1.5">
                  <QueryName message={m} />
                </td>
                <td className="truncate px-2.5 py-1.5 font-mono">{m.qtype}</td>
                <td className="px-2.5 py-1.5">
                  <Result message={m} />
                </td>
                <td className="px-2.5 py-1.5">
                  <Answers message={m} />
                </td>
                <td className="num truncate px-2.5 py-1.5 text-right text-muted">
                  {m.latency_us === null ? '' : formatLatency(m.latency_us)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {more}
    </div>
  );
}

function QueryName({ message: m }: { message: DnsMessage }) {
  const { t } = useTranslation();
  const name = m.qname === '' ? t('views.dns.messages.noName') : m.qname;
  const suffix = m.nb_suffix === null ? null : suffixLabel(t, m.nb_suffix);
  const opcode = m.opcode === 'QUERY' ? null : m.opcode;
  const full = [name, suffix, opcode].filter((s) => s !== null).join(' ');
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <span data-testid="truncatable" title={full} className="min-w-0 truncate font-mono">
        {name}
      </span>
      {suffix !== null && (
        <span data-testid="truncatable" title={suffix} className="max-w-[45%] shrink-0 truncate text-meta text-muted">
          {suffix}
        </span>
      )}
      {opcode !== null && <Badge>{opcode}</Badge>}
    </span>
  );
}

function Result({ message: m }: { message: DnsMessage }) {
  const { t } = useTranslation();
  const label = rcodeLabel(t, m.rcode);
  const responder = m.responder_ip === null ? null : t('views.dns.messages.responder', { ip: m.responder_ip });
  return (
    <span className="flex min-w-0 flex-col items-start">
      <Badge tone={rcodeTone(m.rcode)} title={label}>
        {label}
      </Badge>
      {responder !== null && (
        <span data-testid="truncatable" title={responder} className="max-w-full truncate text-meta text-muted">
          {responder}
        </span>
      )}
    </span>
  );
}

function Answers({ message: m }: { message: DnsMessage }) {
  const { t } = useTranslation();
  if (m.answers.length === 0) return null;
  const shown = m.answers.slice(0, ANSWERS_SHOWN);
  const rest = m.answers.length - shown.length;
  const all = m.answers.map(answerText).join('\n');
  return (
    <span className="flex min-w-0 flex-col">
      {shown.map((a, i) => {
        const text = answerText(a);
        return (
          <span key={`${i}-${text}`} data-testid="truncatable" title={text} className="truncate font-mono">
            {text}
          </span>
        );
      })}
      {rest > 0 && (
        <span data-testid="truncatable" title={all} className="truncate text-meta text-muted">
          {t('views.dns.messages.moreAnswers', { count: rest })}
        </span>
      )}
    </span>
  );
}
