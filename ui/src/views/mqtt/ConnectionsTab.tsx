import { Link } from '@tanstack/react-router';
import type { TFunction } from 'i18next';
import { ArrowRight, ChevronRight } from 'lucide-react';
import { type ReactNode, useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  MQTT_AUTHS,
  MQTT_LOGINS,
  MQTT_VERSIONS,
  type MqttConnectionParams,
  type MqttLoginFilter,
  type MqttVersionFilter,
} from '../../api/mqtt';
import { useMqttConnection, useMqttConnections, useMqttPackets } from '../../api/mqttQueries';
import type { MqttAuth } from '../../api/types/MqttAuth';
import type { MqttConnectionDetail } from '../../api/types/MqttConnectionDetail';
import type { MqttConnectionInfo } from '../../api/types/MqttConnectionInfo';
import type { MqttPacketInfo } from '../../api/types/MqttPacketInfo';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { CopyButton } from '../../components/CopyButton';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { ExpandableList } from '../../components/ExpandableList';
import { SearchInput } from '../../components/SearchInput';
import { SecretValue } from '../../components/SecretValue';
import { Skeleton } from '../../components/Skeleton';
import { Timestamp } from '../../components/Timestamp';
import { WholeSessionHeader } from '../../components/WholeSession';
import { formatByteCount, formatBytes, formatCount, formatFixedDuration, formatLatency, formatNumber, formatTimestamp } from '../../lib/format';
import { useDebounced } from '../../lib/useDebounced';
import { hexCode, reasonLabel } from './labels';
import { Field, PayloadView, Properties, Select } from './parts';
import { FilterChips } from './filters';
import type { ConnectionFilters } from './filterState';

/** Column layout of the connection rows (wide screens), shared by the header and the rows. */
// Fixed widths for the figures: every row gets the same columns, whatever its content.
const ROW_GRID =
  'md:grid md:grid-cols-[4.5rem_minmax(0,1.1fr)_minmax(0,1fr)_9rem] md:items-start md:gap-3 ' +
  'xl:grid-cols-[8.5rem_minmax(15rem,24rem)_minmax(0,1fr)_10rem_6.5rem]';

type All<V> = V | 'all';

/** Height of the connection list: room for a connection unfolded on its CONNECT and CONNACK. */
const LIST_HEIGHT = 760;
/** Topics and packets of a connection shown before « show all ». */
const FIRST_TOPICS = 5;
const FIRST_PACKETS = 12;

interface ConnectionsTabProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
  ranged: boolean;
  filters: ConnectionFilters;
  onFilters: (f: ConnectionFilters) => void;
}

/** Connections: filters, list, and the detail of each connection with its transcript. */
export function ConnectionsTab({ sessionId, enabled, oneDay, ranged, filters, onFilters }: ConnectionsTabProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [login, setLogin] = useState<All<MqttLoginFilter>>('all');
  const [auth, setAuth] = useState<All<MqttAuth>>('all');
  const [version, setVersion] = useState<All<MqttVersionFilter>>('all');
  const params = useMemo<MqttConnectionParams>(() => {
    const p: MqttConnectionParams = {};
    if (q !== '') p.q = q;
    if (login !== 'all') p.login = login;
    if (auth !== 'all') p.auth = auth;
    if (version !== 'all') p.version = version;
    if (filters.client !== null) p.client = filters.client.key;
    if (filters.broker !== null) p.broker = { ip: filters.broker.ip, port: filters.broker.port };
    if (filters.signal !== null) p.signal = filters.signal;
    if (filters.flow !== null) p.flow = filters.flow.id;
    return p;
  }, [q, login, auth, version, filters]);
  const query = useMqttConnections(sessionId, params, enabled);
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
  else if (items.length === 0) body = <EmptyState title={t('views.mqtt.connections.noMatch')} />;
  else
    body = (
      <ExpandableList
        items={items}
        getKey={(c) => c.flow_id}
        ariaLabel={t('views.mqtt.connections.label')}
        header={<RowHeader ranged={ranged} />}
        renderRow={(c) => <ConnectionRow connection={c} oneDay={oneDay} ranged={ranged} />}
        renderDetail={(c) => <ConnectionDetail sessionId={sessionId} connection={c} oneDay={oneDay} ranged={ranged} />}
        rowLabel={(c) =>
          t('views.mqtt.connections.rowLabel', {
            client: c.client.ip,
            broker: c.broker.ip,
            time: formatTimestamp(c.first_ts_us, !oneDay),
          })
        }
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
        maxHeight={LIST_HEIGHT}
      />
    );

  return (
    <Card
      title={t('views.mqtt.connections.title')}
      flush
      {...(total === null ? {} : { actions: <span className="num text-meta text-muted">{formatCount(total)}</span> })}
      filters={
        <>
          <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
            <SearchInput value={search} onChange={setSearch} placeholder={t('views.mqtt.connections.search')} />
            <Select
              label={t('views.mqtt.connections.loginLabel')}
              value={login}
              options={(['all', ...MQTT_LOGINS] as const).map((v) => ({ value: v, label: t(`views.mqtt.connections.logins.${v}`) }))}
              onChange={setLogin}
            />
            <Select
              label={t('views.mqtt.connections.authLabel')}
              value={auth}
              options={(['all', ...MQTT_AUTHS] as const).map((v) => ({ value: v, label: t(`views.mqtt.connections.auths.${v}`) }))}
              onChange={setAuth}
            />
            <Select
              label={t('views.mqtt.connections.versionLabel')}
              value={version}
              options={(['all', ...MQTT_VERSIONS] as const).map((v) => ({ value: v, label: t(`views.mqtt.connections.versions.${v}`) }))}
              onChange={setVersion}
            />
          </div>
          <FilterChips connection={filters} onConnection={onFilters} />
        </>
      }
    >
      {body}
    </Card>
  );
}

export function ListLoading() {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-2 p-3 sm:p-4" aria-busy="true">
      <span className="sr-only">{t('common.loading')}</span>
      {[0, 1, 2, 3].map((i) => (
        <Skeleton key={i} height={32} />
      ))}
    </div>
  );
}

function RowHeader({ ranged }: { ranged: boolean }) {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={ROW_GRID}>
        <span>{t('views.mqtt.connections.col.start')}</span>
        <span>{t('views.mqtt.connections.col.endpoints')}</span>
        <span>{t('views.mqtt.connections.col.client')}</span>
        <span className="text-right xl:hidden">
          <WholeSessionHeader label={t('views.mqtt.connections.col.messagesDuration')} ranged={ranged} />
        </span>
        <span className="hidden text-right xl:block">
          <WholeSessionHeader label={t('views.mqtt.connections.col.messages')} ranged={ranged} />
        </span>
        <span className="hidden text-right xl:block">
          <WholeSessionHeader label={t('views.mqtt.connections.col.duration')} ranged={ranged} />
        </span>
      </div>
    </div>
  );
}

/** Name of the client of a connection (identifier, else a muted mention). */
export function ClientId({ id, className }: { id: string | null; className?: string }) {
  const { t } = useTranslation();
  const text = id === null ? t('views.mqtt.connections.unknownId') : id === '' ? t('views.mqtt.connections.emptyId') : id;
  return (
    <span
      data-testid="truncatable"
      title={text}
      className={`min-w-0 truncate ${id === null || id === '' ? 'text-muted italic' : 'font-mono'} ${className ?? ''}`}
    >
      {text}
    </span>
  );
}

function StatusBadges({ connection: c }: { connection: MqttConnectionInfo }) {
  const { t } = useTranslation();
  return (
    <>
      {c.auth === 'none' && <Badge tone="warning">{t('views.mqtt.connections.badge.anonymous')}</Badge>}
      {c.auth === 'password' && <Badge>{t('views.mqtt.connections.badge.credentials')}</Badge>}
      {c.auth === 'enhanced' && <Badge>{t('views.mqtt.connections.badge.enhanced')}</Badge>}
      {c.login === 'accepted' && <Badge tone="success">{t('views.mqtt.connections.badge.accepted')}</Badge>}
      {c.login === 'rejected' && <Badge tone="warning">{t('views.mqtt.connections.badge.rejected')}</Badge>}
      {c.login === 'rejected' && c.connack_code !== null && (
        <span className="min-w-0 text-meta break-words text-warning">{reasonLabel(t, c.connack_code, c.version)}</span>
      )}
      {c.partial && <Badge>{t('views.mqtt.connections.badge.partial')}</Badge>}
      {c.packets_truncated && <Badge>{t('views.mqtt.connections.badge.truncated')}</Badge>}
    </>
  );
}

function ConnectionRow({ connection: c, oneDay, ranged }: { connection: MqttConnectionInfo; oneDay: boolean; ranged: boolean }) {
  const { t } = useTranslation();
  const messages = t('views.mqtt.connections.messagesValue', { sent: formatCount(c.publish_c2s), received: formatCount(c.publish_s2c) });
  const messagesTitle = t('views.mqtt.connections.messagesTitle', { sent: formatCount(c.publish_c2s), received: formatCount(c.publish_s2c) });
  const duration = formatFixedDuration(Math.max(0, c.last_ts_us - c.first_ts_us) / 1e6);
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${ROW_GRID}`}>
      <Timestamp us={c.first_ts_us} withDate={!oneDay} className="hidden text-meta text-muted md:block" />
      <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 text-meta">
        <span className="min-w-0 max-w-full">
          <Endpoint endpoint={c.client} show="address" className="text-meta" />
        </span>
        <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint" />
        <span className="min-w-0 max-w-full">
          <Endpoint endpoint={c.broker} port={c.broker_port} show="address" className="text-meta" />
        </span>
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-1.5">
        <ClientId id={c.client_id} />
        {c.version !== null && <Badge className="font-mono">{c.version}</Badge>}
        <StatusBadges connection={c} />
      </span>
      {/* Narrow screens: start, then messages and duration (whole connection under a range). */}
      <span className="flex min-w-0 flex-wrap items-center gap-x-2 text-meta text-muted md:hidden">
        <Timestamp us={c.first_ts_us} withDate={!oneDay} />
        <span className="num" title={messagesTitle}>
          {ranged ? t('timeRange.wholeSessionColumn', { label: `${messages}, ${duration}` }) : `${messages}, ${duration}`}
        </span>
      </span>
      <span className="hidden min-w-0 flex-col items-end text-meta md:flex" title={messagesTitle}>
        <span className="num text-right">{messages}</span>
        <span className="num text-right text-muted xl:hidden">{duration}</span>
      </span>
      <span className="num hidden text-right text-meta text-muted xl:block">{duration}</span>
    </span>
  );
}

function ConnectionDetail({
  sessionId,
  connection: c,
  oneDay,
  ranged,
}: {
  sessionId: string;
  connection: MqttConnectionInfo;
  oneDay: boolean;
  ranged: boolean;
}) {
  const { t } = useTranslation();
  const detail = useMqttConnection(sessionId, c.flow_id, true);
  if (detail.isPending) return <Skeleton height={160} />;
  if (detail.isError)
    return (
      <ErrorState
        message={t('views.mqtt.detail.loadError')}
        onRetry={() => {
          void detail.refetch();
        }}
      />
    );
  const d = detail.data;
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        <ConnectSection sessionId={sessionId} detail={d} />
        <div className="flex min-w-0 flex-col gap-4">
          <ConnackSection detail={d} oneDay={oneDay} />
          <EndSection detail={d} oneDay={oneDay} />
        </div>
      </div>
      <Subscriptions detail={d} oneDay={oneDay} />
      <Topics detail={d} />
      <Transcript sessionId={sessionId} connection={c} detail={d} oneDay={oneDay} ranged={ranged} />
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex min-w-0 flex-col gap-2">
      <h4 className="text-meta font-medium">{title}</h4>
      {children}
    </section>
  );
}

const DL = 'grid min-w-0 gap-3 [grid-template-columns:repeat(auto-fill,minmax(min(100%,11rem),1fr))]';

function ConnectSection({ sessionId, detail: d }: { sessionId: string; detail: MqttConnectionDetail }) {
  const { t } = useTranslation();
  const c = d.connection;
  if (c.partial) {
    return (
      <Section title={t('views.mqtt.detail.connect')}>
        <p className="text-meta text-muted">{t('views.mqtt.detail.noConnect')}</p>
      </Section>
    );
  }
  const yesNo = (v: boolean | null) => (v === null ? null : v ? t('views.mqtt.detail.yes') : t('views.mqtt.detail.no'));
  return (
    <Section title={t('views.mqtt.detail.connect')}>
      <dl className={DL}>
        <Field label={t('views.mqtt.detail.version')}>
          <span className="font-mono">{c.version ?? ''}</span>
          {d.protocol_name !== null && (
            <span className="text-muted">{` (${t('views.mqtt.detail.protocol', { name: d.protocol_name })}${c.bridge ? `, ${t('views.mqtt.detail.bridge')}` : ''})`}</span>
          )}
        </Field>
        <Field label={t('views.mqtt.detail.clientId')}>
          <span className="flex min-w-0 items-center gap-1">
            <ClientId id={c.client_id} />
            {c.client_id !== null && c.client_id !== '' && <CopyButton value={c.client_id} name={t('views.mqtt.detail.clientId')} />}
          </span>
        </Field>
        {d.clean_start !== null && <Field label={t('views.mqtt.detail.cleanStart')}>{yesNo(d.clean_start)}</Field>}
        {d.keep_alive !== null && (
          <Field label={t('views.mqtt.detail.keepAlive')}>
            <span className="num">{t('views.mqtt.detail.seconds', { count: d.keep_alive })}</span>
          </Field>
        )}
        {d.session_expiry !== null && (
          <Field label={t('views.mqtt.detail.sessionExpiry')}>
            <span className="num">{t('views.mqtt.detail.seconds', { count: d.session_expiry })}</span>
          </Field>
        )}
        {c.username !== null && (
          <Field label={t('views.mqtt.detail.username')}>
            <span className="font-mono break-all">{c.username}</span>
          </Field>
        )}
        {d.password !== null && (
          <Field label={t('views.mqtt.detail.password')} wide>
            <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
              <SecretValue value={d.password} label={t('views.mqtt.detail.password')} />
              {d.password_len !== null && (
                <span className="num text-muted">{t('views.mqtt.detail.passwordLength', { count: d.password_len })}</span>
              )}
              <Link to="/sessions/$sessionId/credentials" params={{ sessionId }} className="text-accent hover:underline">
                {t('views.mqtt.detail.openCredentials')}
              </Link>
            </span>
          </Field>
        )}
        {d.auth_method !== null && (
          <Field label={t('views.mqtt.detail.authMethod')}>
            <span className="font-mono break-all">{d.auth_method}</span>
          </Field>
        )}
      </dl>
      {d.will !== null && (
        <div className="flex min-w-0 flex-col gap-1.5">
          <span className="text-meta text-muted">{t('views.mqtt.detail.will')}</span>
          <span className="text-meta break-all">
            <span className="font-mono">{t('views.mqtt.detail.willValue', { topic: d.will.topic, qos: d.will.qos })}</span>
            {d.will.retain && <span className="text-muted">{`, ${t('views.mqtt.detail.willRetain')}`}</span>}
          </span>
          <PayloadView payload={d.will.payload} />
        </div>
      )}
      {d.connect_props.length > 0 && (
        <div className="flex min-w-0 flex-col gap-1.5">
          <span className="text-meta text-muted">{t('views.mqtt.detail.props')}</span>
          <Properties props={d.connect_props} />
        </div>
      )}
    </Section>
  );
}

function ConnackSection({ detail: d, oneDay }: { detail: MqttConnectionDetail; oneDay: boolean }) {
  const { t } = useTranslation();
  const c = d.connection;
  if (d.connack_ts_us === null || c.connack_code === null) {
    return (
      <Section title={t('views.mqtt.detail.connack')}>
        <p className="text-meta text-muted">{t('views.mqtt.detail.noConnack')}</p>
      </Section>
    );
  }
  return (
    <Section title={t('views.mqtt.detail.connack')}>
      <dl className={DL}>
        <Field label={t('views.mqtt.detail.code')}>
          <span className={c.login === 'rejected' ? 'text-danger' : undefined}>{reasonLabel(t, c.connack_code, c.version)}</span>
          <span className="num text-muted">{` (${hexCode(c.connack_code)})`}</span>
        </Field>
        <Field label={t('views.mqtt.messages.col.time')}>
          <Timestamp us={d.connack_ts_us} withDate={!oneDay} />
        </Field>
        {d.session_present !== null && (
          <Field label={t('views.mqtt.detail.sessionPresent')}>{d.session_present ? t('views.mqtt.detail.yes') : t('views.mqtt.detail.no')}</Field>
        )}
        {c.assigned_client_id !== null && (
          <Field label={t('views.mqtt.detail.assignedId')}>
            <span className="font-mono break-all">{c.assigned_client_id}</span>
          </Field>
        )}
        {d.server_keep_alive !== null && (
          <Field label={t('views.mqtt.detail.serverKeepAlive')}>
            <span className="num">{t('views.mqtt.detail.seconds', { count: d.server_keep_alive })}</span>
          </Field>
        )}
      </dl>
      {d.connack_props.length > 0 && <Properties props={d.connack_props} />}
    </Section>
  );
}

function EndSection({ detail: d, oneDay }: { detail: MqttConnectionDetail; oneDay: boolean }) {
  const { t } = useTranslation();
  const c = d.connection;
  const end =
    c.end === 'disconnect' && d.disconnect_by !== null
      ? t('views.mqtt.detail.disconnectBy', { who: t(`views.mqtt.detail.who.${d.disconnect_by}`) })
      : t(`views.mqtt.detail.endKind.${c.end}`);
  return (
    <Section title={t('views.mqtt.detail.end')}>
      <dl className={DL}>
        <Field label={t('views.mqtt.detail.end')}>
          {end}
          {d.disconnect_ts_us !== null && (
            <span className="text-muted">
              {' '}
              <Timestamp us={d.disconnect_ts_us} withDate={!oneDay} />
            </span>
          )}
        </Field>
        {d.disconnect_reason !== null && (
          <Field label={t('views.mqtt.detail.reason')}>
            {reasonLabel(t, d.disconnect_reason, '5.0')}
            <span className="num text-muted">{` (${hexCode(d.disconnect_reason)})`}</span>
          </Field>
        )}
        {d.broker_software !== null && (
          <Field label={t('views.mqtt.detail.software')}>
            <span className="break-all" title={t('views.mqtt.detail.softwareNote')}>
              {d.broker_software}
            </span>
          </Field>
        )}
        {d.pings > 0 && d.last_ping_ts_us !== null && (
          <Field label={t('views.mqtt.detail.pings')}>
            <span className="num">{t('views.mqtt.detail.pingsValue', { count: d.pings, time: formatTimestamp(d.last_ping_ts_us, !oneDay) })}</span>
          </Field>
        )}
        <Field label={t('views.mqtt.detail.traffic')}>
          <span className="num">{t('views.mqtt.detail.trafficValue', { client: formatBytes(d.bytes_c2s), broker: formatBytes(d.bytes_s2c) })}</span>
        </Field>
      </dl>
    </Section>
  );
}

function grantedText(t: TFunction, granted: number | null, version: MqttConnectionInfo['version']): string {
  if (granted === null) return t('views.mqtt.detail.noAnswer');
  if (granted >= 0x80) return t('views.mqtt.detail.refused', { reason: reasonLabel(t, granted, version === '5.0' ? '5.0' : null) });
  return t('views.mqtt.detail.granted', { qos: granted });
}

function Subscriptions({ detail: d, oneDay }: { detail: MqttConnectionDetail; oneDay: boolean }) {
  const { t } = useTranslation();
  if (d.subscriptions.length === 0) return null;
  return (
    <Section title={t('views.mqtt.detail.subscriptions')}>
      <ul className="flex min-w-0 flex-col gap-1 text-meta">
        {d.subscriptions.map((s, i) => (
          <li key={i} className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span className="min-w-0 font-mono break-all">{s.filter}</span>
            <span className="text-muted">{t('views.mqtt.packet.qos', { qos: s.qos })}</span>
            <span className={s.granted !== null && s.granted >= 0x80 ? 'text-danger' : 'text-muted'}>
              {grantedText(t, s.granted, d.connection.version)}
            </span>
            {s.shared_group !== null && <span className="text-muted">{t('views.mqtt.detail.shared', { group: s.shared_group })}</span>}
            {s.wildcard && <Badge tone="warning">{t('views.mqtt.signals.kind.wildcard')}</Badge>}
            {s.unsubscribed_ts_us !== null && (
              <span className="text-muted">{t('views.mqtt.detail.unsubscribed', { time: formatTimestamp(s.unsubscribed_ts_us, !oneDay) })}</span>
            )}
          </li>
        ))}
      </ul>
    </Section>
  );
}

/** « Show all n » under a list cut to its first rows. */
function ShowAll({ total, onShow }: { total: number; onShow: () => void }) {
  const { t } = useTranslation();
  return (
    <div>
      <Button variant="secondary" onClick={onShow}>
        {t('views.mqtt.detail.showAll', { count: total })}
      </Button>
    </div>
  );
}

function Topics({ detail: d }: { detail: MqttConnectionDetail }) {
  const { t } = useTranslation();
  const [all, setAll] = useState(false);
  if (d.topics.length === 0) return null;
  const shown = all ? d.topics : d.topics.slice(0, FIRST_TOPICS);
  return (
    <Section title={t('views.mqtt.detail.topics')}>
      <ul className="flex min-w-0 flex-col gap-1 text-meta">
        {shown.map((topic, i) => (
          <li key={i} className="flex min-w-0 flex-wrap items-baseline gap-x-2">
            <span className={topic.topic === null ? 'text-muted italic' : 'min-w-0 font-mono break-all'}>
              {topic.topic ?? t('views.mqtt.detail.otherTopics')}
            </span>
            <span className="num text-muted">
              {`${formatCount(topic.messages)} ${topic.dir === 'client' ? t('views.mqtt.detail.published') : t('views.mqtt.detail.delivered')}, ${formatByteCount(topic.payload_bytes)}`}
            </span>
          </li>
        ))}
      </ul>
      {shown.length < d.topics.length && (
        <ShowAll
          total={d.topics.length}
          onShow={() => {
            setAll(true);
          }}
        />
      )}
    </Section>
  );
}

/** Offset of a packet from the start of the connection (`+12.345 s`). */
function offset(t: TFunction, packet: MqttPacketInfo, start: number): string {
  return t('views.mqtt.packet.offset', { seconds: formatNumber(Math.max(0, packet.ts_us - start) / 1e6, 3) });
}

function PacketLine({ packet: p, start, version }: { packet: MqttPacketInfo; start: number; version: MqttConnectionInfo['version'] }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const parts: ReactNode[] = [];
  if (p.packet_id !== null) parts.push(t('views.mqtt.packet.id', { id: p.packet_id }));
  if (p.qos !== null) parts.push(t('views.mqtt.packet.qos', { qos: p.qos }));
  if (p.retain) parts.push(t('views.mqtt.packet.retain'));
  if (p.dup) parts.push(t('views.mqtt.packet.dup'));
  if (p.topic_alias !== null)
    parts.push(
      p.topic_source === 'unresolved'
        ? t('views.mqtt.packet.unresolved', { alias: p.topic_alias })
        : t('views.mqtt.packet.alias', { alias: p.topic_alias }),
    );
  if (p.filters.length > 0) parts.push(t('views.mqtt.packet.filters', { count: p.filters.length }));
  if (p.payload !== null) parts.push(formatByteCount(p.payload.len));
  const ack = p.ack;
  let ackNode: ReactNode = null;
  if (p.type === 'PUBLISH' && ack !== null && ack.state !== 'none') {
    if (ack.state === 'acked')
      ackNode = (
        <span className="text-muted">
          {t('views.mqtt.packet.ack', {
            ack: p.qos === 2 ? 'PUBCOMP' : 'PUBACK',
            delay: ack.delay_us === null ? '' : formatLatency(ack.delay_us),
          })}
        </span>
      );
    else if (ack.state === 'missing') ackNode = <span className="text-warning">{t('views.mqtt.packet.noAck')}</span>;
    else if (ack.state === 'received') ackNode = <span className="text-warning">{t('views.mqtt.packet.received')}</span>;
    else if (ack.reason !== null)
      ackNode = <span className="text-danger">{t('views.mqtt.packet.ackError', { reason: reasonLabel(t, ack.reason, '5.0') })}</span>;
  }
  const reason = p.reason_code === null ? null : reasonLabel(t, p.reason_code, version);
  const expandable = p.payload !== null || p.props.length > 0 || p.filters.length > 0;
  const line = (
    <>
      <span className="text-faint" title={formatTimestamp(p.ts_us)}>{offset(t, p, start)}</span> <span className="text-muted">{t(`views.mqtt.packet.${p.dir}`)}</span>{' '}
      <span className={p.malformed ? 'font-semibold text-danger' : 'font-semibold'}>{p.type}</span>
      {p.topic !== null && (
        <>
          {' '}
          <span className="text-accent">{p.topic}</span>
        </>
      )}
      {parts.length > 0 && <span className="text-muted">{` ${parts.join(', ')}`}</span>}
      {reason !== null && <span className={p.reason_code !== null && p.reason_code >= 0x80 ? 'text-danger' : 'text-muted'}>{` ${reason}`}</span>}
      {ackNode !== null && <> {ackNode}</>}
    </>
  );
  if (!expandable) return <div className="min-w-0 py-0.5 pl-5">{line}</div>;
  return (
    <div className="min-w-0 py-0.5">
      <button
        type="button"
        aria-expanded={open}
        aria-label={t('views.mqtt.packet.expand', { seq: p.seq })}
        onClick={() => {
          setOpen(!open);
        }}
        className="flex w-full min-w-0 items-start gap-1 text-left hover:bg-subtle"
      >
        <ChevronRight aria-hidden size={14} strokeWidth={1.75} className={`mt-0.5 shrink-0 text-faint ${open ? 'rotate-90' : ''}`} />
        <span className="min-w-0">{line}</span>
      </button>
      {open && (
        <div className="flex min-w-0 flex-col gap-2 py-2 pl-5 font-sans">
          {p.filters.length > 0 && (
            <ul className="flex min-w-0 flex-col gap-0.5 text-meta">
              {p.filters.map((f, i) => (
                <li key={i} className="flex min-w-0 flex-wrap gap-x-2">
                  <span className="font-mono break-all">{f.filter}</span>
                  {p.type === 'SUBSCRIBE' && <span className="text-muted">{t('views.mqtt.packet.qos', { qos: f.options & 3 })}</span>}
                  <span className="text-muted">{grantedText(t, f.granted, version)}</span>
                </li>
              ))}
            </ul>
          )}
          {p.payload !== null && <PayloadView payload={p.payload} contentType={p.content_type} format={p.payload_format} />}
          <Properties props={p.props} />
        </div>
      )}
    </div>
  );
}

function Transcript({
  sessionId,
  connection: c,
  detail: d,
  ranged,
}: {
  sessionId: string;
  connection: MqttConnectionInfo;
  detail: MqttConnectionDetail;
  oneDay: boolean;
  ranged: boolean;
}) {
  const { t } = useTranslation();
  const packets = useMqttPackets(sessionId, c.flow_id, true);
  const [all, setAll] = useState(false);
  const loaded = packets.data?.pages.flatMap((p) => p.items) ?? [];
  const items = all ? loaded : loaded.slice(0, FIRST_PACKETS);
  return (
    <Section title={t('views.mqtt.detail.transcript')}>
      <span className="text-meta text-faint">{ranged ? t('views.mqtt.detail.rangeNote') : t('views.mqtt.detail.transcriptNote')}</span>
      {packets.isPending ? (
        <Skeleton height={120} />
      ) : packets.isError ? (
        <ErrorState
          message={t('views.mqtt.detail.loadError')}
          onRetry={() => {
            void packets.refetch();
          }}
        />
      ) : items.length === 0 ? (
        <p className="text-meta text-muted">{t('views.mqtt.detail.noPacket')}</p>
      ) : (
        <div
          role="log"
          aria-label={t('views.mqtt.detail.transcriptLabel')}
          data-testid="mqtt-transcript"
          className="min-w-0 rounded-md border border-line bg-surface p-2 font-mono text-meta leading-5 break-words [overflow-wrap:anywhere]"
        >
          {items.map((p) => (
            <PacketLine key={p.id} packet={p} start={c.first_ts_us} version={c.version} />
          ))}
        </div>
      )}
      {items.length < loaded.length && (
        <ShowAll
          total={packets.data?.pages[0]?.total_estimate ?? loaded.length}
          onShow={() => {
            setAll(true);
          }}
        />
      )}
      {all && packets.hasNextPage && (
        <div>
          <Button
            variant="secondary"
            disabled={packets.isFetchingNextPage}
            onClick={() => {
              void packets.fetchNextPage();
            }}
          >
            {t('views.mqtt.detail.loadMore')}
          </Button>
        </div>
      )}
      {d.connection.packets_truncated && <p className="text-meta text-warning">{t('views.mqtt.detail.storedNote')}</p>}
      {d.connection.malformed > 0 && <p className="text-meta text-danger">{t('views.mqtt.detail.malformed')}</p>}
      {d.gaps > 0 && <p className="text-meta text-warning">{t('views.mqtt.detail.gaps', { count: d.gaps })}</p>}
      {d.state_dropped > 0 && <p className="text-meta text-warning">{t('views.mqtt.detail.stateDropped', { count: d.state_dropped })}</p>}
    </Section>
  );
}
