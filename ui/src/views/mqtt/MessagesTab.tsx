import { ArrowRight } from 'lucide-react';
import { type ReactNode, useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { MqttMessageParams } from '../../api/mqtt';
import { useMqttMessages } from '../../api/mqttQueries';
import type { MqttDir } from '../../api/types/MqttDir';
import type { MqttPacketInfo } from '../../api/types/MqttPacketInfo';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { ExpandableList } from '../../components/ExpandableList';
import { MiddleTruncate } from '../../components/MiddleTruncate';
import { SearchInput } from '../../components/SearchInput';
import { Timestamp } from '../../components/Timestamp';
import { Toggle } from '../../components/Toggle';
import { formatByteCount, formatCount, formatLatency, formatTimestamp } from '../../lib/format';
import { useDebounced } from '../../lib/useDebounced';
import { ClientId, ListLoading } from './ConnectionsTab';
import { FilterChips } from './filters';
import type { MessageFilters } from './filterState';
import { reasonLabel } from './labels';
import { Choice, PayloadView, Properties, Select } from './parts';

/** Column layout of the message rows (wide screens). */
// Fixed widths for the figures: every row gets the same columns, whatever its badges.
const ROW_GRID =
  'md:grid md:grid-cols-[4.5rem_minmax(0,0.8fr)_minmax(0,1.6fr)_12rem] md:items-center md:gap-3 ' +
  'xl:grid-cols-[8.5rem_minmax(0,0.7fr)_minmax(0,1.8fr)_14rem_6.5rem]';

type DirChoice = MqttDir | 'all';
type QosChoice = '0' | '1' | '2' | 'all';

interface MessagesTabProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
  filters: MessageFilters;
  onFilters: (f: MessageFilters) => void;
  onShowConnection: (m: MqttPacketInfo) => void;
}

/** Stored PUBLISH packets, with their payload excerpt. */
export function MessagesTab({ sessionId, enabled, oneDay, filters, onFilters, onShowConnection }: MessagesTabProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [dir, setDir] = useState<DirChoice>('all');
  const [qos, setQos] = useState<QosChoice>('all');
  const [retained, setRetained] = useState(false);
  const params = useMemo<MqttMessageParams>(() => {
    const p: MqttMessageParams = {};
    if (q !== '') p.q = q;
    if (dir !== 'all') p.dir = dir;
    if (qos !== 'all') p.qos = Number(qos);
    if (retained) p.retain = true;
    if (filters.topic !== null) p.topic = filters.topic;
    if (filters.prefix !== null) p.prefix = filters.prefix;
    if (filters.client !== null) p.client = filters.client.key;
    return p;
  }, [q, dir, qos, retained, filters]);
  const query = useMqttMessages(sessionId, params, enabled);
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
        message={t('views.mqtt.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  else if (items.length === 0) body = <EmptyState title={t('views.mqtt.messages.noMatch')} />;
  else
    body = (
      <ExpandableList
        items={items}
        getKey={(m) => m.id}
        ariaLabel={t('views.mqtt.messages.label')}
        header={<RowHeader />}
        renderRow={(m) => <MessageRow message={m} oneDay={oneDay} />}
        renderDetail={(m) => <MessageDetail message={m} onShowConnection={onShowConnection} />}
        rowLabel={(m) =>
          t('views.mqtt.messages.rowLabel', {
            topic: m.topic ?? t('views.mqtt.messages.unknownTopic'),
            time: formatTimestamp(m.ts_us, !oneDay),
          })
        }
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    );

  return (
    <Card
      title={t('views.mqtt.messages.title')}
      flush
      {...(total === null ? {} : { actions: <span className="num text-meta text-muted">{formatCount(total)}</span> })}
      filters={
        <>
          <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
            <SearchInput value={search} onChange={setSearch} placeholder={t('views.mqtt.messages.search')} />
            <Choice
              label={t('views.mqtt.messages.dirLabel')}
              value={dir}
              options={(['all', 'client', 'broker'] as const).map((v) => ({ value: v, label: t(`views.mqtt.messages.dirs.${v}`) }))}
              onChange={setDir}
            />
            <Select
              label={t('views.mqtt.messages.qosLabel')}
              value={qos}
              options={(['all', '0', '1', '2'] as const).map((v) => ({ value: v, label: t(`views.mqtt.messages.qos.${v}`) }))}
              onChange={setQos}
            />
            <Toggle label={t('views.mqtt.messages.retained')} checked={retained} onChange={setRetained} />
          </div>
          <FilterChips message={filters} onMessage={onFilters} />
        </>
      }
    >
      {body}
    </Card>
  );
}

function RowHeader() {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={ROW_GRID}>
        <span>{t('views.mqtt.messages.col.time')}</span>
        <span>{t('views.mqtt.messages.col.client')}</span>
        <span>{t('views.mqtt.messages.col.topic')}</span>
        <span className="text-right">{t('views.mqtt.messages.col.sizeQos')}</span>
        <span className="hidden xl:block">{t('views.mqtt.messages.col.dir')}</span>
      </div>
    </div>
  );
}

function Flags({ message: m }: { message: MqttPacketInfo }) {
  const { t } = useTranslation();
  return (
    <>
      {m.qos !== null && <Badge className="font-mono">{t('views.mqtt.packet.qos', { qos: m.qos })}</Badge>}
      {m.retain && <Badge>{t('views.mqtt.packet.retain')}</Badge>}
      {m.dup && <Badge>{t('views.mqtt.packet.dup')}</Badge>}
      {m.ack?.state === 'missing' && <Badge tone="warning">{t('views.mqtt.packet.noAck')}</Badge>}
      {m.ack?.state === 'error' && m.ack.reason !== null && (
        <Badge tone="danger">{t('views.mqtt.packet.ackError', { reason: reasonLabel(t, m.ack.reason, '5.0') })}</Badge>
      )}
    </>
  );
}

function MessageRow({ message: m, oneDay }: { message: MqttPacketInfo; oneDay: boolean }) {
  const { t } = useTranslation();
  const topic = m.topic ?? t('views.mqtt.messages.unknownTopic');
  const size = m.payload === null ? '' : formatByteCount(m.payload.len);
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${ROW_GRID}`}>
      <Timestamp us={m.ts_us} withDate={!oneDay} className="hidden text-meta text-muted md:block" />
      <span className="hidden min-w-0 md:flex">
        <ClientId id={m.client_id} className="text-meta" />
      </span>
      <span className="flex min-w-0 items-center gap-1.5">
        <MiddleTruncate text={topic} className={`min-w-0 font-mono ${m.topic === null ? 'text-muted italic' : ''}`} />
      </span>
      {/* Narrow screens: time, client, size and flags. */}
      <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-meta text-muted md:hidden">
        <Timestamp us={m.ts_us} withDate={!oneDay} />
        <ClientId id={m.client_id} />
        <span className="num">{size}</span>
        <Flags message={m} />
      </span>
      <span className="hidden min-w-0 flex-wrap items-center justify-end gap-1 md:flex">
        <span className="num text-meta">{size}</span>
        <Flags message={m} />
      </span>
      <span className="hidden text-meta text-muted xl:block">{t(`views.mqtt.packet.${m.dir}`)}</span>
    </span>
  );
}

function MessageDetail({ message: m, onShowConnection }: { message: MqttPacketInfo; onShowConnection: (m: MqttPacketInfo) => void }) {
  const { t } = useTranslation();
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-meta">
        <span className="text-muted">{t(`views.mqtt.messages.dirs.${m.dir}`)}</span>
        {m.client !== null && (
          <span className="min-w-0 max-w-full">
            <Endpoint endpoint={m.client} show="address" className="text-meta" />
          </span>
        )}
        {/* The arrow stays with the broker: never an arrow at a line end. */}
        {m.broker !== null && (
          <span className="flex min-w-0 max-w-full items-center gap-1.5">
            {m.client !== null && <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint" />}
            <span className="min-w-0 max-w-full">
              <Endpoint endpoint={m.broker} port={m.broker_port} show="address" className="text-meta" />
            </span>
          </span>
        )}
        {m.topic_alias !== null && (
          <span className="text-muted">
            {m.topic_source === 'unresolved'
              ? t('views.mqtt.packet.unresolved', { alias: m.topic_alias })
              : t('views.mqtt.packet.alias', { alias: m.topic_alias })}
          </span>
        )}
        {m.ack !== null && m.ack.state === 'acked' && m.ack.delay_us !== null && (
          <span className="text-muted">
            {t('views.mqtt.packet.ack', { ack: m.qos === 2 ? 'PUBCOMP' : 'PUBACK', delay: formatLatency(m.ack.delay_us) })}
          </span>
        )}
      </div>
      {m.payload !== null && <PayloadView payload={m.payload} contentType={m.content_type} format={m.payload_format} />}
      <Properties props={m.props} />
      <div>
        <Button
          variant="secondary"
          onClick={() => {
            onShowConnection(m);
          }}
        >
          {t('views.mqtt.messages.showConnection')}
        </Button>
      </div>
    </div>
  );
}
