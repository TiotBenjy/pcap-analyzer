import { getRouteApi } from '@tanstack/react-router';
import type { TFunction } from 'i18next';
import { ArrowRight, Megaphone, MonitorSmartphone, Radar, Reply, Search, Send } from 'lucide-react';
import { type ReactNode, useCallback, useId, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { SSDP_KINDS, type SsdpMessageParams } from '../../api/ssdp';
import { useSsdpDevices, useSsdpMessages, useSsdpStats } from '../../api/ssdpQueries';
import type { SsdpDeviceInfo } from '../../api/types/SsdpDeviceInfo';
import type { SsdpKind } from '../../api/types/SsdpKind';
import type { SsdpMessageInfo } from '../../api/types/SsdpMessageInfo';
import type { SsdpStats } from '../../api/types/SsdpStats';
import { useViewRange } from '../../app/timeRange';
import { CATEGORICAL } from '../../charts/palette';
import { Badge } from '../../components/Badge';
import { type BarItem, BarList } from '../../components/BarList';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { CopyButton } from '../../components/CopyButton';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { endpointHost, endpointTitle } from '../../components/endpointText';
import { ErrorState } from '../../components/ErrorState';
import { Flag } from '../../components/Flag';
import { PageHeader } from '../../components/PageHeader';
import { SearchInput } from '../../components/SearchInput';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import { Timestamp } from '../../components/Timestamp';
import { formatCount, formatTimestamp } from '../../lib/format';
import { SessionGate } from '../connections/SessionGate';
import { ExpandableList } from '../http/ExpandableList';
import { FilterChip } from '../http/shared';
import { useDebounced, useViewableSession } from '../http/state';
import { deviceKey, shortType } from './format';

const route = getRouteApi('/sessions/$sessionId');

/** Column layout of the device rows (wide screens), shared by the header and the rows. */
const DEVICE_GRID =
  'md:grid md:grid-cols-[minmax(0,1.3fr)_minmax(9rem,1fr)_minmax(0,1.4fr)_88px] md:items-center md:gap-3 ' +
  'xl:grid-cols-[minmax(0,1.3fr)_minmax(10rem,1fr)_minmax(0,1.6fr)_96px_minmax(9rem,0.8fr)]';
/** Column layout of the message rows (wide screens). */
const MESSAGE_GRID =
  'md:grid md:grid-cols-[72px_128px_minmax(8rem,1fr)_minmax(0,1.5fr)] md:items-center md:gap-3 ' +
  'xl:grid-cols-[80px_136px_minmax(10rem,1fr)_minmax(10rem,1fr)_minmax(0,1.6fr)]';
const SELECT_CLASS = 'h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body';

type KindFilter = SsdpKind | 'all';

/** Device of the message filter: its UUID and announcing address. */
interface DeviceFilter {
  uuid: string;
  ip: string;
  label: string;
}

/** SSDP view (docs/specs/ssdp.md): figures, rankings, UPnP devices and messages with raw text. */
export default function SsdpView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const { session, viewable, oneDay } = useViewableSession(sessionId);
  const stats = useSsdpStats(sessionId, viewable);

  const [kind, setKind] = useState<KindFilter>('all');
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [device, setDevice] = useState<DeviceFilter | null>(null);
  const [sender, setSender] = useState<string | null>(null);
  const [target, setTarget] = useState<string | null>(null);
  const messagesRef = useRef<HTMLDivElement>(null);

  const params = useMemo<SsdpMessageParams>(() => {
    const p: SsdpMessageParams = {};
    if (kind !== 'all') p.kind = kind;
    if (q !== '') p.q = q;
    if (device !== null) {
      p.uuid = device.uuid;
      p.src = device.ip;
    } else if (sender !== null) p.src = sender;
    if (target !== null) p.target = target;
    return p;
  }, [kind, q, device, sender, target]);

  const showDevice = useCallback((d: SsdpDeviceInfo) => {
    setSender(null);
    setDevice({ uuid: d.uuid, ip: d.address.ip, label: d.device_type === '' ? d.uuid : shortType(d.device_type) });
    messagesRef.current?.scrollIntoView?.({ block: 'start' });
  }, []);

  const s = stats.data;
  let content: ReactNode;
  if (stats.isError)
    content = (
      <Card>
        <ErrorState
          message={t('views.ssdp.loadError')}
          onRetry={() => {
            void stats.refetch();
          }}
        />
      </Card>
    );
  else if (s !== undefined && s.messages === 0)
    content = (
      <Card>
        <EmptyState icon={Radar} title={t('views.ssdp.empty')} />
      </Card>
    );
  else
    content = (
      <>
        <StatBand stats={s} />
        <Rankings
          stats={s}
          onTarget={(v) => {
            setTarget(v);
            messagesRef.current?.scrollIntoView?.({ block: 'start' });
          }}
          onSender={(ip) => {
            setDevice(null);
            setSender(ip);
            messagesRef.current?.scrollIntoView?.({ block: 'start' });
          }}
        />
        <DevicesCard sessionId={sessionId} enabled={viewable} oneDay={oneDay} onShowMessages={showDevice} />
        <div ref={messagesRef} className="scroll-mt-4">
          <Card
            title={t('views.ssdp.messages.title')}
            flush
            filters={
              <>
                <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
                  <SearchInput value={search} onChange={setSearch} placeholder={t('views.ssdp.messages.search')} />
                  <KindControl value={kind} onChange={setKind} />
                </div>
                {(device !== null || sender !== null || target !== null) && (
                  <div className="flex min-w-0 flex-wrap gap-2">
                    {device !== null && (
                      <Chip
                        label={t('views.ssdp.messages.deviceChip', { device: `${device.label}, ${device.ip}` })}
                        onRemove={() => {
                          setDevice(null);
                        }}
                      />
                    )}
                    {sender !== null && (
                      <Chip
                        label={t('views.ssdp.messages.senderChip', { address: sender })}
                        onRemove={() => {
                          setSender(null);
                        }}
                      />
                    )}
                    {target !== null && (
                      <Chip
                        label={t('views.ssdp.messages.targetChip', { target })}
                        onRemove={() => {
                          setTarget(null);
                        }}
                      />
                    )}
                  </div>
                )}
              </>
            }
          >
            <MessageList sessionId={sessionId} params={params} enabled={viewable} oneDay={oneDay} />
          </Card>
        </div>
      </>
    );

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.ssdp')}
        subtitle={session.data?.name ?? t('views.ssdp.subtitle')}
        {...(s === undefined ? {} : { count: <Badge>{formatCount(s.messages)}</Badge> })}
      />
      <SessionGate session={session}>{content}</SessionGate>
    </div>
  );
}

function Chip({ label, onRemove }: { label: string; onRemove: () => void }) {
  const { t } = useTranslation();
  return <FilterChip label={label} removeLabel={t('views.ssdp.messages.removeFilter', { label })} onRemove={onRemove} />;
}

/** Message type: a segmented control from `sm`, a list below (five choices do not fit 375 px). */
function KindControl({ value, onChange }: { value: KindFilter; onChange: (v: KindFilter) => void }) {
  const { t } = useTranslation();
  const id = useId();
  const options = (['all', ...SSDP_KINDS] as const).map((k) => ({ value: k, label: t(`views.ssdp.messages.kinds.${k}`) }));
  return (
    <>
      <div className="hidden sm:block">
        <SegmentedControl hideLabel label={t('views.ssdp.messages.kindLabel')} value={value} options={options} onChange={onChange} />
      </div>
      <div className="w-full sm:hidden">
        <label htmlFor={id} className="sr-only">
          {t('views.ssdp.messages.kindLabel')}
        </label>
        <select
          id={id}
          value={value}
          onChange={(e) => {
            onChange(e.target.value as KindFilter);
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

function StatBand({ stats }: { stats: SsdpStats | undefined }) {
  const { t } = useTranslation();
  const v = (n: number | undefined) => (n === undefined ? null : formatCount(n));
  return (
    <section
      aria-label={t('views.ssdp.stat.label')}
      data-testid="ssdp-summary"
      className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6"
    >
      <StatCard icon={Radar} label={t('views.ssdp.stat.messages')} value={v(stats?.messages)} />
      <StatCard
        icon={Megaphone}
        label={t('views.ssdp.stat.notify')}
        value={v(stats?.notify)}
        hint={stats === undefined ? ' ' : t('views.ssdp.stat.notifyHint', { alive: formatCount(stats.alive), byebye: formatCount(stats.byebye) })}
      />
      <StatCard icon={Search} label={t('views.ssdp.stat.search')} value={v(stats?.search)} hint=" " />
      <StatCard icon={Reply} label={t('views.ssdp.stat.response')} value={v(stats?.response)} hint=" " />
      <StatCard icon={MonitorSmartphone} label={t('views.ssdp.stat.devices')} value={v(stats?.devices)} hint=" " />
      <StatCard icon={Send} label={t('views.ssdp.stat.senders')} value={v(stats?.senders)} hint=" " />
    </section>
  );
}

interface RankingsProps {
  stats: SsdpStats | undefined;
  onTarget: (target: string) => void;
  onSender: (ip: string) => void;
}

function Rankings({ stats, onTarget, onSender }: RankingsProps) {
  const { t } = useTranslation();
  const loading = stats === undefined;
  const named = (items: SsdpStats['targets'] | undefined, color: string, mono: boolean): BarItem[] =>
    (items ?? []).map((x) => ({
      key: x.name,
      label: x.name,
      value: x.count,
      valueText: formatCount(x.count),
      color,
      mono,
      truncate: mono ? 'middle' : 'end',
    }));
  const senders: BarItem[] = (stats?.top_senders ?? []).map((x) => ({
    key: x.address.ip,
    label: endpointHost(x.address),
    title: endpointTitle(x.address),
    lead: x.address.country === null ? undefined : <Flag country={x.address.country} />,
    value: x.count,
    valueText: formatCount(x.count),
    color: CATEGORICAL[2],
    mono: true,
  }));
  return (
    <div className="grid items-start gap-4 [grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))]">
      <Card title={t('views.ssdp.rank.targets')}>
        <BarList
          ariaLabel={t('views.ssdp.rank.targetsLabel')}
          items={named(stats?.targets, CATEGORICAL[0], true)}
          loading={loading}
          emptyText={t('views.ssdp.rank.empty')}
          onSelect={onTarget}
          selectLabel={(item) => t('views.ssdp.rank.filterTarget', { target: item.label })}
        />
      </Card>
      <Card title={t('views.ssdp.rank.software')}>
        <BarList
          ariaLabel={t('views.ssdp.rank.softwareLabel')}
          items={named(stats?.software, CATEGORICAL[1], false)}
          loading={loading}
          emptyText={t('views.ssdp.rank.empty')}
        />
      </Card>
      <Card title={t('views.ssdp.rank.senders')}>
        <BarList
          ariaLabel={t('views.ssdp.rank.sendersLabel')}
          items={senders}
          loading={loading}
          emptyText={t('views.ssdp.rank.empty')}
          onSelect={onSender}
          selectLabel={(item) => t('views.ssdp.rank.filterSender', { address: item.label })}
        />
      </Card>
    </div>
  );
}

function ListLoading() {
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

// ---- devices ------------------------------------------------------------------------------------

interface DevicesCardProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
  onShowMessages: (d: SsdpDeviceInfo) => void;
}

function DevicesCard({ sessionId, enabled, oneDay, onShowMessages }: DevicesCardProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const params = useMemo(() => (q === '' ? {} : { q }), [q]);
  const query = useSsdpDevices(sessionId, params, enabled);
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total_estimate ?? null;
  const loadMore = useCallback(() => {
    void query.fetchNextPage();
  }, [query]);
  // Devices are folded over the session: under a range their counters stay those of the session.
  const ranged = useViewRange() !== null;

  let body: ReactNode;
  if (query.isPending) body = <ListLoading />;
  else if (query.isError)
    body = (
      <ErrorState
        message={t('views.ssdp.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  else if (items.length === 0)
    body = q === '' ? <EmptyState icon={MonitorSmartphone} title={t('views.ssdp.devices.empty')} /> : <EmptyState title={t('views.ssdp.devices.noMatch')} />;
  else
    body = (
      <ExpandableList
        items={items}
        getKey={deviceKey}
        ariaLabel={t('views.ssdp.devices.label')}
        header={<DeviceHeader ranged={ranged} />}
        renderRow={(d) => <DeviceRow device={d} oneDay={oneDay} ranged={ranged} />}
        renderDetail={(d) => <DeviceDetail device={d} oneDay={oneDay} onShowMessages={onShowMessages} />}
        rowLabel={(d) => t('views.ssdp.devices.rowLabel', { device: deviceName(d, t('views.ssdp.devices.unknownType')), address: d.address.ip })}
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    );

  return (
    <Card
      title={t('views.ssdp.devices.title')}
      flush
      {...(total === null ? {} : { actions: <span className="num text-meta text-muted">{formatCount(total)}</span> })}
      filters={
        <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={t('views.ssdp.devices.search')} />
        </div>
      }
    >
      {body}
    </Card>
  );
}

function deviceName(d: SsdpDeviceInfo, unknown: string): string {
  return d.device_type === '' ? unknown : shortType(d.device_type);
}

function DeviceHeader({ ranged }: { ranged: boolean }) {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={DEVICE_GRID}>
        <span>{t('views.ssdp.devices.col.device')}</span>
        <span>{t('views.ssdp.devices.col.address')}</span>
        <span>{t('views.ssdp.devices.col.software')}</span>
        <span className="text-right">
          {t('views.ssdp.devices.col.messages')}
          {ranged && <span className="block leading-tight font-normal text-faint">{t('timeRange.wholeSession')}</span>}
        </span>
        <span className="hidden xl:block">{t('views.ssdp.devices.col.lastSeen')}</span>
      </div>
    </div>
  );
}

function DeviceRow({ device: d, oneDay, ranged }: { device: SsdpDeviceInfo; oneDay: boolean; ranged: boolean }) {
  const { t } = useTranslation();
  const name = deviceName(d, t('views.ssdp.devices.unknownType'));
  const count = t('views.ssdp.devices.messages', { count: d.message_count });
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${DEVICE_GRID}`}>
      <span className="flex min-w-0 items-center justify-between gap-2 md:block">
        <span data-testid="truncatable" title={d.device_type === '' ? d.uuid : d.device_type} className="block min-w-0 truncate font-medium">
          {name}
        </span>
        <span className="num shrink-0 text-meta text-muted md:hidden">
          {ranged ? t('timeRange.wholeSessionColumn', { label: count }) : count}
        </span>
      </span>
      <span className="min-w-0">
        <Endpoint endpoint={d.address} show="address" className="text-meta" />
      </span>
      <span data-testid="truncatable" title={d.server} className="block min-w-0 truncate text-meta text-muted">
        {d.server === '' ? '-' : d.server}
      </span>
      <span className="num hidden text-right md:block">{formatCount(d.message_count)}</span>
      <Timestamp us={d.last_ts_us} withDate={!oneDay} className="hidden text-meta text-muted xl:block" />
    </span>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5 sm:flex-row sm:gap-3">
      <dt className="shrink-0 text-meta text-muted sm:w-36">{label}</dt>
      <dd className="min-w-0 flex-1">{children}</dd>
    </div>
  );
}

function DeviceDetail({
  device: d,
  oneDay,
  onShowMessages,
}: {
  device: SsdpDeviceInfo;
  oneDay: boolean;
  onShowMessages: (d: SsdpDeviceInfo) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <dl className="flex min-w-0 flex-col gap-2">
        <Field label={t('views.ssdp.devices.uuid')}>
          <span className="flex min-w-0 items-center gap-1">
            <span data-testid="truncatable" title={d.uuid} className="min-w-0 truncate font-mono text-meta">
              {d.uuid}
            </span>
            <CopyButton value={d.uuid} name={t('views.ssdp.devices.uuid')} />
          </span>
        </Field>
        {d.device_type !== '' && (
          <Field label={t('views.ssdp.devices.type')}>
            <span className="block font-mono text-meta break-all">{d.device_type}</span>
          </Field>
        )}
        <Field label={t('views.ssdp.devices.col.address')}>
          <Endpoint endpoint={d.address} show="both" copy />
        </Field>
        {d.location !== '' && (
          <Field label={t('views.ssdp.devices.location')}>
            <Location value={d.location} />
          </Field>
        )}
        {d.server !== '' && (
          <Field label={t('views.ssdp.devices.software')}>
            <span className="block text-meta break-words">{d.server}</span>
          </Field>
        )}
        <Field label={t('views.ssdp.devices.firstSeen')}>
          <Timestamp us={d.first_ts_us} withDate={!oneDay} className="text-meta" />
        </Field>
        <Field label={t('views.ssdp.devices.lastSeen')}>
          <Timestamp us={d.last_ts_us} withDate={!oneDay} className="text-meta" />
        </Field>
        <Field label={t('views.ssdp.devices.countsLabel')}>
          <span className="num text-meta">
            {t('views.ssdp.devices.counts', {
              alive: formatCount(d.alive_count),
              byebye: formatCount(d.byebye_count),
              responses: formatCount(d.response_count),
            })}
          </span>
        </Field>
        {d.targets.length > 0 && (
          <Field label={t('views.ssdp.devices.targets')}>
            <ul className="flex min-w-0 flex-wrap gap-1">
              {d.targets.map((x) => (
                <li key={x} className="max-w-full min-w-0">
                  <Badge title={x} className="max-w-full min-w-0 overflow-hidden font-mono">
                    <span className="truncate">{x}</span>
                  </Badge>
                </li>
              ))}
            </ul>
          </Field>
        )}
      </dl>
      <div>
        <Button
          onClick={() => {
            onShowMessages(d);
          }}
        >
          {t('views.ssdp.devices.showMessages')}
        </Button>
      </div>
    </div>
  );
}

/** An announced description URL: text and copy, never a link (the application never fetches it). */
function Location({ value }: { value: string }) {
  const { t } = useTranslation();
  return (
    <span className="flex min-w-0 flex-col gap-0.5">
      <span className="flex min-w-0 items-center gap-1">
        <span data-testid="truncatable" title={value} className="min-w-0 truncate font-mono text-meta">
          {value}
        </span>
        <CopyButton value={value} name={t('views.ssdp.devices.location')} />
      </span>
      <span className="text-meta text-faint">{t('views.ssdp.devices.locationNote')}</span>
    </span>
  );
}

// ---- messages -----------------------------------------------------------------------------------

interface MessageListProps {
  sessionId: string;
  params: SsdpMessageParams;
  enabled: boolean;
  oneDay: boolean;
}

function MessageList({ sessionId, params, enabled, oneDay }: MessageListProps) {
  const { t } = useTranslation();
  const query = useSsdpMessages(sessionId, params, enabled);
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total_estimate ?? null;
  const loadMore = useCallback(() => {
    void query.fetchNextPage();
  }, [query]);
  if (query.isPending) return <ListLoading />;
  if (query.isError)
    return (
      <ErrorState
        message={t('views.ssdp.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  if (items.length === 0) return <EmptyState title={t('views.ssdp.messages.empty')} />;
  return (
    <>
      {total !== null && (
        <p className="border-b border-line px-3 py-1.5 text-meta text-muted sm:px-4" data-testid="ssdp-row-count">
          {t('common.rows', { count: total })}
        </p>
      )}
      <ExpandableList
        items={items}
        getKey={(m) => m.id}
        ariaLabel={t('views.ssdp.messages.label')}
        header={<MessageHeader />}
        renderRow={(m) => <MessageRow message={m} oneDay={oneDay} />}
        renderDetail={(m) => <MessageDetail message={m} />}
        rowLabel={(m) =>
          t('views.ssdp.messages.rowLabel', {
            kind: kindLabel(t, m),
            source: m.source.ip,
            time: formatTimestamp(m.ts_us, !oneDay),
          })
        }
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    </>
  );
}

function kindLabel(t: TFunction, m: SsdpMessageInfo): string {
  // The notification sub-type is a protocol value (`alive`, `byebye`...), shown as sent.
  if (m.kind === 'notify' && m.nts !== null) return `${t('views.ssdp.messages.badge.notify')} ${m.nts}`;
  if (m.kind === 'response') return t('views.ssdp.messages.badge.response', { status: m.status ?? '-' });
  return t(`views.ssdp.messages.badge.${m.kind}`);
}

function KindBadge({ message: m }: { message: SsdpMessageInfo }) {
  const { t } = useTranslation();
  const tone = m.kind === 'invalid' ? 'warning' : m.nts === 'byebye' ? 'neutral' : 'accent';
  return (
    <Badge tone={tone} className="max-w-full min-w-0 overflow-hidden">
      <span className="truncate">{kindLabel(t, m)}</span>
    </Badge>
  );
}

function MessageHeader() {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={MESSAGE_GRID}>
        <span>{t('views.ssdp.messages.col.time')}</span>
        <span>{t('views.ssdp.messages.col.type')}</span>
        <span>{t('views.ssdp.messages.col.source')}</span>
        <span className="hidden xl:block">{t('views.ssdp.messages.col.destination')}</span>
        <span>{t('views.ssdp.messages.col.target')}</span>
      </div>
    </div>
  );
}

function MessageRow({ message: m, oneDay }: { message: SsdpMessageInfo; oneDay: boolean }) {
  const target = m.target ?? '-';
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${MESSAGE_GRID}`}>
      <span className="flex min-w-0 items-center justify-between gap-2 md:contents">
        <Timestamp us={m.ts_us} withDate={!oneDay} className="order-2 shrink-0 text-meta text-muted md:order-none" />
        <span className="order-1 min-w-0 md:order-none">
          <KindBadge message={m} />
        </span>
      </span>
      <span className="flex min-w-0 items-center gap-1.5 text-meta md:block">
        <Endpoint endpoint={m.source} port={m.src_port} show="address" className="text-meta" />
        <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint md:hidden" />
        <span className="min-w-0 md:hidden">
          <Endpoint endpoint={m.destination} port={m.dst_port} show="address" className="text-meta" />
        </span>
      </span>
      <span className="hidden min-w-0 xl:block">
        <Endpoint endpoint={m.destination} port={m.dst_port} show="address" className="text-meta" />
      </span>
      <span data-testid="truncatable" title={target} className="block min-w-0 truncate font-mono text-meta">
        {target}
      </span>
    </span>
  );
}

function MessageDetail({ message: m }: { message: SsdpMessageInfo }) {
  const { t } = useTranslation();
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <span className="min-w-0 text-meta text-muted">
          {t('views.ssdp.messages.raw')}
          {', '}
          {m.raw_truncated
            ? t('views.ssdp.messages.truncated', { shown: formatCount(2048), size: formatCount(m.size) })
            : t('views.ssdp.messages.size', { size: formatCount(m.size) })}
        </span>
        <CopyButton value={m.raw} name={t('views.ssdp.messages.rawName')} />
      </div>
      {/* Text only: React escapes it, nothing in a capture is ever interpreted as markup. */}
      <pre
        data-testid="ssdp-raw"
        className="max-h-80 max-w-full min-w-0 overflow-auto rounded-md border border-line bg-surface p-3 font-mono text-meta whitespace-pre"
      >
        {m.raw}
      </pre>
      {m.location !== null && (
        <dl>
          <Field label={t('views.ssdp.messages.location')}>
            <Location value={m.location} />
          </Field>
        </dl>
      )}
    </div>
  );
}
