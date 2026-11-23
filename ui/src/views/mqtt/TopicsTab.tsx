import type { ColumnDef } from '@tanstack/react-table';
import { ChevronRight } from 'lucide-react';
import { type ReactNode, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMqttTopic, useMqttTopics } from '../../api/mqttQueries';
import type { MqttTopicNode } from '../../api/types/MqttTopicNode';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { CopyButton } from '../../components/CopyButton';
import { DataTable } from '../../components/DataTable';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { MiddleTruncate } from '../../components/MiddleTruncate';
import { SearchInput } from '../../components/SearchInput';
import { Skeleton } from '../../components/Skeleton';
import { Timestamp } from '../../components/Timestamp';
import { WholeSessionLine } from '../../components/WholeSession';
import { wholeSessionHeader } from '../../components/wholeSessionHeader';
import { formatByteCount, formatCount } from '../../lib/format';
import { useDebounced } from '../../lib/useDebounced';
import { LoadMore } from '../connections/LoadMore';
import { ClientId } from './ConnectionsTab';
import { Field, PayloadView } from './parts';

interface TopicsTabProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
  ranged: boolean;
  /** Messages of a topic (`exact`) or of a subtree. */
  onShowMessages: (path: string, exact: boolean) => void;
}

/** Levels of a path (`/` separated, empty levels kept). */
function levelsOf(path: string): string[] {
  return path.split('/');
}

/** Topic tree browsed level by level, and the detail of the selected node. */
export function TopicsTab({ sessionId, enabled, oneDay, ranged, onShowMessages }: TopicsTabProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [parent, setParent] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const query = useMqttTopics(sessionId, q === '' ? parent : null, q, enabled);
  const columns = useTopicColumns(oneDay, ranged, q !== '');
  const open = (node: MqttTopicNode) => {
    setSelected(node.path);
    if (q === '' && node.children > 0) setParent(node.path);
  };

  let list: ReactNode;
  if (query.isError)
    list = (
      <ErrorState
        message={t('views.mqtt.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  else if (query.data === undefined)
    list = (
      <div className="p-3 sm:p-4">
        <Skeleton height={160} />
      </div>
    );
  else {
    const items = query.data.pages.flatMap((p) => p.items);
    list = (
      <>
        {q !== '' && (
          <p className="border-b border-line px-3 py-2 text-meta text-muted sm:px-4">{t('views.mqtt.topics.results', { count: items.length })}</p>
        )}
        <DataTable
          columns={columns}
          data={items}
          getRowId={(n) => n.path}
          ariaLabel={t('views.mqtt.topics.label')}
          cards
          maxHeight={520}
          emptyText={t('views.mqtt.topics.noMatch')}
          onRowClick={open}
        />
        <LoadMore
          shown={items.length}
          total={null}
          hasMore={query.hasNextPage}
          loading={query.isFetchingNextPage}
          onMore={() => {
            void query.fetchNextPage();
          }}
        />
      </>
    );
  }

  return (
    <div className="grid min-w-0 items-start gap-4 xl:grid-cols-[minmax(0,1fr)_400px]">
      <Card
        title={t('views.mqtt.topics.title')}
        flush
        filters={
          <>
            <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
              <SearchInput value={search} onChange={setSearch} placeholder={t('views.mqtt.topics.search')} />
            </div>
            {q === '' && (
              <Breadcrumb
                path={parent}
                onGo={(p) => {
                  setParent(p);
                  setSelected(p);
                }}
              />
            )}
          </>
        }
      >
        {list}
      </Card>
      <TopicDetail sessionId={sessionId} path={selected} enabled={enabled} oneDay={oneDay} ranged={ranged} onShowMessages={onShowMessages} />
    </div>
  );
}

/** Root / level / level: each level opens its node; the full path in the tooltip. */
function Breadcrumb({ path, onGo }: { path: string | null; onGo: (p: string | null) => void }) {
  const { t } = useTranslation();
  const levels = path === null ? [] : levelsOf(path);
  // Narrow screens keep the last two levels, the others behind an ellipsis.
  const hidden = Math.max(0, levels.length - 2);
  return (
    <nav aria-label={t('views.mqtt.topics.breadcrumb')} className="min-w-0">
      <ol className="flex min-w-0 flex-wrap items-center gap-x-1 gap-y-0.5 text-meta">
        <li>
          <button
            type="button"
            className={path === null ? 'font-medium' : 'text-accent hover:underline'}
            onClick={() => {
              onGo(null);
            }}
          >
            {t('views.mqtt.topics.root')}
          </button>
        </li>
        {hidden > 0 && (
          <li className="flex items-center gap-1 sm:hidden" title={path ?? ''}>
            <ChevronRight aria-hidden size={12} strokeWidth={1.75} className="text-faint" />
            <span className="text-muted">…</span>
          </li>
        )}
        {levels.map((name, i) => {
          const p = levels.slice(0, i + 1).join('/');
          const last = i === levels.length - 1;
          return (
            <li key={p} className={`min-w-0 items-center gap-1 ${i < hidden ? 'hidden sm:flex' : 'flex'}`}>
              <ChevronRight aria-hidden size={12} strokeWidth={1.75} className="shrink-0 text-faint" />
              <button
                type="button"
                title={p}
                aria-current={last ? 'page' : undefined}
                className={`min-w-0 truncate font-mono ${last ? 'font-medium' : 'text-accent hover:underline'}`}
                onClick={() => {
                  onGo(p);
                }}
              >
                {name === '' ? t('views.mqtt.topics.emptyName') : name}
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

function useTopicColumns(oneDay: boolean, ranged: boolean, search: boolean) {
  const { t } = useTranslation();
  return useMemo<ColumnDef<MqttTopicNode>[]>(() => {
    const counter = (label: string) => wholeSessionHeader(label, ranged);
    return [
      {
        id: 'name',
        meta: { card: 'title' },
        accessorFn: (n) => (search ? n.path : n.name),
        header: t('views.mqtt.topics.col.name'),
        size: 260,
        cell: ({ row }) => {
          const n = row.original;
          const text = search ? n.path : n.name === '' ? t('views.mqtt.topics.emptyName') : n.name;
          return (
            <span className="flex min-w-0 items-center gap-1.5">
              <MiddleTruncate text={text} title={n.path} className={`min-w-0 font-mono ${n.name === '' && !search ? 'text-muted italic' : ''}`} />
              {!search && n.is_topic && n.children > 0 && <span className="shrink-0 text-meta text-muted">{t('views.mqtt.topics.asTopic')}</span>}
              {!search && n.children > 0 && <ChevronRight aria-label={t('views.mqtt.topics.open', { name: text })} size={14} strokeWidth={1.75} className="shrink-0 text-faint" />}
            </span>
          );
        },
      },
      {
        id: 'topics',
        meta: { align: 'right' },
        accessorFn: (n) => n.topics,
        header: t('views.mqtt.topics.col.topics'),
        size: 90,
        cell: ({ row }) => <span className="num">{formatCount(row.original.topics)}</span>,
      },
      {
        id: 'published',
        meta: { align: 'right' },
        accessorFn: (n) => n.messages_pub,
        header: counter(t('views.mqtt.topics.col.published')),
        size: 110,
        cell: ({ row }) => <span className="num">{formatCount(row.original.messages_pub)}</span>,
      },
      {
        id: 'delivered',
        meta: { align: 'right' },
        accessorFn: (n) => n.messages_del,
        header: counter(t('views.mqtt.topics.col.delivered')),
        size: 110,
        cell: ({ row }) => <span className="num">{formatCount(row.original.messages_del)}</span>,
      },
      {
        id: 'bytes',
        meta: { align: 'right' },
        accessorFn: (n) => n.payload_bytes,
        header: counter(t('views.mqtt.topics.col.bytes')),
        size: 120,
        cell: ({ row }) => <span className="num">{formatByteCount(row.original.payload_bytes)}</span>,
      },
      {
        id: 'last',
        accessorFn: (n) => n.last_ts_us,
        header: counter(t('views.mqtt.topics.col.lastSeen')),
        size: oneDay ? 130 : 170,
        cell: ({ row }) => <Timestamp us={row.original.last_ts_us} withDate={!oneDay} />,
      },
    ];
  }, [t, oneDay, ranged, search]);
}

function TopicDetail({
  sessionId,
  path,
  enabled,
  oneDay,
  ranged,
  onShowMessages,
}: {
  sessionId: string;
  path: string | null;
  enabled: boolean;
  oneDay: boolean;
  ranged: boolean;
  onShowMessages: (path: string, exact: boolean) => void;
}) {
  const { t } = useTranslation();
  const detail = useMqttTopic(sessionId, path, enabled);
  let body: ReactNode;
  if (path === null) body = <EmptyState title={t('views.mqtt.topics.detail.hint')} />;
  else if (detail.isPending) body = <Skeleton height={200} />;
  else if (detail.isError)
    body = (
      <ErrorState
        message={t('views.mqtt.topics.detail.loadError')}
        onRetry={() => {
          void detail.refetch();
        }}
      />
    );
  else {
    const d = detail.data;
    const n = d.node;
    const exact = n.is_topic && n.topics === 1;
    body = (
      <div className="flex min-w-0 flex-col gap-4" data-testid="mqtt-topic-detail">
        <dl className="grid min-w-0 gap-3">
          <Field label={t('views.mqtt.topics.detail.path')}>
            <span className="flex min-w-0 items-start gap-1">
              <span className="min-w-0 font-mono break-all">{n.path === '' ? t('views.mqtt.topics.emptyName') : n.path}</span>
              <CopyButton value={n.path} name={t('views.mqtt.topics.detail.path')} />
            </span>
          </Field>
          <Field label={t('views.mqtt.topics.detail.messages')}>
            <span className="num">
              {t('views.mqtt.topics.detail.messagesValue', { published: formatCount(n.messages_pub), delivered: formatCount(n.messages_del) })}
            </span>
            {ranged && <WholeSessionLine />}
          </Field>
          <Field label={t('views.mqtt.topics.detail.qos')}>
            <span className="num">
              {t('views.mqtt.topics.detail.qosValue', {
                q0: formatCount(d.qos[0] ?? 0),
                q1: formatCount(d.qos[1] ?? 0),
                q2: formatCount(d.qos[2] ?? 0),
              })}
            </span>
          </Field>
          <Field label={t('views.mqtt.topics.detail.retained')}>
            <span className="num">{formatCount(n.retained)}</span>
          </Field>
          {n.topics > 1 && (
            <Field label={t('views.mqtt.topics.detail.topics')}>
              <span className="num">{formatCount(n.topics)}</span>
            </Field>
          )}
        </dl>
        <div className="flex min-w-0 flex-col gap-1.5">
          <span className="text-meta font-medium">{t('views.mqtt.topics.detail.publishers')}</span>
          {d.publishers.length === 0 ? (
            <p className="text-meta text-muted">{t('views.mqtt.topics.detail.noPublisher')}</p>
          ) : (
            <ul className="flex min-w-0 flex-col gap-1 text-meta">
              {d.publishers.map((p, i) => (
                <li key={i} className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
                  <ClientId id={p.client_id} />
                  <Endpoint endpoint={p.client} show="address" className="text-meta" />
                  <span className="num text-muted">{formatCount(p.messages)}</span>
                </li>
              ))}
            </ul>
          )}
          {d.publisher_count > d.publishers.length && (
            <span className="text-meta text-muted">{t('views.mqtt.topics.detail.publishersMore', { count: d.publisher_count })}</span>
          )}
        </div>
        <div className="flex min-w-0 flex-col gap-1.5">
          <span className="text-meta font-medium">{t('views.mqtt.topics.detail.subscribers')}</span>
          {d.subscribers.length === 0 ? (
            <p className="text-meta text-muted">{t('views.mqtt.topics.detail.noSubscriber')}</p>
          ) : (
            <ul className="flex min-w-0 flex-col gap-1 text-meta">
              {d.subscribers.map((s, i) => (
                <li key={i} className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
                  <span className="font-mono break-all">{s.filter}</span>
                  <ClientId id={s.client_id} />
                  <Endpoint endpoint={s.client} show="address" className="text-meta" />
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="flex min-w-0 flex-col gap-2">
          <span className="text-meta font-medium">{t('views.mqtt.topics.detail.recent')}</span>
          {d.recent.length === 0 ? (
            <p className="text-meta text-muted">{t('views.mqtt.topics.detail.noRecent')}</p>
          ) : (
            d.recent.map((m) => (
              <div key={m.id} className="flex min-w-0 flex-col gap-1">
                <span className="flex min-w-0 flex-wrap items-center gap-x-2 text-meta text-muted">
                  <Timestamp us={m.ts_us} withDate={!oneDay} />
                  {!exact && m.topic !== null && <span className="min-w-0 font-mono break-all text-accent">{m.topic}</span>}
                  <ClientId id={m.client_id} />
                </span>
                {m.payload !== null && <PayloadView payload={m.payload} contentType={m.content_type} format={m.payload_format} />}
              </div>
            ))
          )}
        </div>
        <div>
          <Button
            variant="secondary"
            onClick={() => {
              onShowMessages(n.path, exact);
            }}
          >
            {t('views.mqtt.topics.detail.showMessages')}
          </Button>
        </div>
      </div>
    );
  }
  return <Card title={t('views.mqtt.topics.detail.title')}>{body}</Card>;
}
