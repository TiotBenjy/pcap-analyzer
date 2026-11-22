import { getRouteApi } from '@tanstack/react-router';
import type { ColumnDef } from '@tanstack/react-table';
import { Building2, Cable, Layers, Network, Router, Shuffle } from 'lucide-react';
import { type ReactNode, useId, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useViewRange } from '../../app/timeRange';
import {
  MAC_SORTS,
  type MacClass,
  type MacFilters,
  type MacSort,
  PAIR_SORTS,
  type PairFilters,
  type PairSort,
} from '../../api/ethernet';
import { useEthernetStats, useMacPairs, useMacs } from '../../api/ethernetQueries';
import { useSession } from '../../api/sessionQueries';
import type { EthernetStats } from '../../api/types/EthernetStats';
import type { EtherTypeRef } from '../../api/types/EtherTypeRef';
import type { MacInfo } from '../../api/types/MacInfo';
import type { MacPairInfo } from '../../api/types/MacPairInfo';
import type { Page } from '../../api/types/Page';
import type { VlanInfo } from '../../api/types/VlanInfo';
import { CATEGORICAL, OTHER_COLOR } from '../../charts/palette';
import { Badge } from '../../components/Badge';
import { type BarItem, BarList } from '../../components/BarList';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { DataTable } from '../../components/DataTable';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { PageHeader } from '../../components/PageHeader';
import { SearchInput } from '../../components/SearchInput';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import { Timestamp } from '../../components/Timestamp';
import { formatBytes, formatCount, formatShare, sameLocalDay } from '../../lib/format';
import { LoadMore } from '../connections/LoadMore';
import { isViewable } from '../connections/session';
import { SessionGate } from '../connections/SessionGate';
import { useDebounced } from '../connections/useDebounced';
import { FilterChip } from '../http/shared';
import { MacAddress, VendorName } from './MacAddress';

const route = getRouteApi('/sessions/$sessionId');

/** Value of the "all classes" segment. */
const ALL = 'all';
type ClassChoice = MacClass | typeof ALL;

/** Ethernet view (docs/specs/ethernet.md): vendors, EtherTypes, VLANs, addresses and pairs. */
export default function EthernetView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const viewable = isViewable(session.data);
  const stats = useEthernetStats(sessionId, viewable);
  const ranged = useViewRange() !== null;
  const oneDay =
    session.data?.first_ts_us != null && session.data.last_ts_us != null && sameLocalDay(session.data.first_ts_us, session.data.last_ts_us);

  // Filters shared by the blocks: a vendor bar filters the addresses, an EtherType the pairs, a
  // VLAN both, an address row the pairs.
  const [vendor, setVendor] = useState<{ key: string; label: string } | null>(null);
  const [vlan, setVlan] = useState<string | null>(null);
  const [ethertype, setEthertype] = useState<{ value: number; label: string } | null>(null);
  const [pairMac, setPairMac] = useState<string | null>(null);
  const pairsRef = useRef<HTMLDivElement>(null);

  let content: ReactNode;
  if (stats.isError) {
    content = (
      <Card>
        <ErrorState
          message={t('views.ethernet.loadError')}
          onRetry={() => {
            void stats.refetch();
          }}
        />
      </Card>
    );
  } else if (stats.data === undefined) {
    content = (
      <div className="flex flex-col gap-4" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        <Skeleton height={88} />
        <Skeleton height={240} />
      </div>
    );
  } else if (stats.data.mac_count === 0) {
    content = (
      <Card>
        <EmptyState icon={Router} title={t('views.ethernet.empty')} {...(ranged ? {} : { description: t('views.ethernet.emptyText') })} />
      </Card>
    );
  } else {
    const s = stats.data;
    content = (
      <>
        <StatBand stats={s} />
        <div className="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))]">
          <VendorsCard
            stats={s}
            active={vendor?.key ?? null}
            onSelect={(v) => {
              setVendor((cur) => (cur?.key === v.key ? null : v));
            }}
          />
          <EtherTypesCard
            stats={s}
            ranged={ranged}
            active={ethertype?.value ?? null}
            onSelect={(e) => {
              setEthertype((cur) => (cur?.value === e.value ? null : e));
              pairsRef.current?.scrollIntoView?.({ block: 'start', behavior: 'smooth' });
            }}
          />
        </div>
        {s.vlans.length > 0 && (
          <VlanCard
            vlans={s.vlans}
            ranged={ranged}
            oneDay={oneDay}
            onSelect={(v) => {
              setVlan((cur) => (cur === v ? null : v));
            }}
          />
        )}
        <MacsCard
          sessionId={sessionId}
          enabled={viewable}
          ranged={ranged}
          oneDay={oneDay}
          vendor={vendor}
          onClearVendor={() => {
            setVendor(null);
          }}
          vlan={vlan}
          onClearVlan={() => {
            setVlan(null);
          }}
          onSelect={(mac) => {
            setPairMac(mac);
            pairsRef.current?.scrollIntoView?.({ block: 'start', behavior: 'smooth' });
          }}
        />
        <div ref={pairsRef} className="scroll-mt-4">
          <PairsCard
            sessionId={sessionId}
            enabled={viewable}
            ranged={ranged}
            oneDay={oneDay}
            mac={pairMac}
            onClearMac={() => {
              setPairMac(null);
            }}
            vlan={vlan}
            onClearVlan={() => {
              setVlan(null);
            }}
            ethertype={ethertype}
            onClearEthertype={() => {
              setEthertype(null);
            }}
          />
        </div>
      </>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.ethernet')}
        subtitle={session.data?.name ?? t('views.ethernet.subtitle')}
        {...(stats.data === undefined ? {} : { count: <Badge>{formatCount(stats.data.mac_count)}</Badge> })}
      />
      <SessionGate session={session}>{content}</SessionGate>
    </div>
  );
}

function StatBand({ stats }: { stats: EthernetStats }) {
  const { t } = useTranslation();
  return (
    <section aria-label={t('views.ethernet.stat.label')} className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
      <StatCard
        icon={Cable}
        label={t('views.ethernet.stat.macs')}
        value={formatCount(stats.mac_count)}
        hint={t('views.ethernet.stat.macsHint', { count: stats.unicast_count })}
      />
      <StatCard icon={Building2} label={t('views.ethernet.stat.vendors')} value={formatCount(stats.vendor_count)} />
      <StatCard
        icon={Shuffle}
        label={t('views.ethernet.stat.local')}
        value={formatCount(stats.local_count)}
        hint={t('views.ethernet.stat.localHint')}
      />
      <StatCard icon={Network} label={t('views.ethernet.stat.pairs')} value={formatCount(stats.pair_count)} />
      <StatCard
        icon={Layers}
        label={t('views.ethernet.stat.vlans')}
        value={formatCount(stats.vlan_count)}
        hint={t('views.ethernet.stat.vlansHint', { share: formatShare(stats.tagged_frames, stats.frames) })}
      />
    </section>
  );
}

function VendorsCard({
  stats,
  active,
  onSelect,
}: {
  stats: EthernetStats;
  active: string | null;
  onSelect: (v: { key: string; label: string }) => void;
}) {
  const { t } = useTranslation();
  const items = useMemo<BarItem[]>(
    () =>
      stats.vendors.map((v) => {
        const label =
          v.kind === 'named' ? (v.name ?? v.key) : v.kind === 'local' ? t('views.ethernet.vendors.local') : t('views.ethernet.vendors.unknown');
        return {
          key: v.key,
          label,
          title: `${label}\n${t('views.ethernet.vendors.addresses', { count: v.count })}`,
          value: v.count,
          valueText: formatCount(v.count),
          color: v.kind === 'named' ? CATEGORICAL[0] : OTHER_COLOR,
          muted: v.kind !== 'named',
          active: v.key === active,
        };
      }),
    [stats.vendors, active, t],
  );
  return (
    <Card title={t('views.ethernet.vendors.title')}>
      <div className="flex flex-col gap-2">
        <BarList
          items={items}
          ariaLabel={t('views.ethernet.vendors.label')}
          emptyText={t('views.ethernet.vendors.empty')}
          onSelect={(key) => {
            const item = items.find((i) => i.key === key);
            if (item !== undefined) onSelect({ key, label: item.label });
          }}
          selectLabel={(item) => t('views.ethernet.vendors.filter', { name: item.label })}
        />
        {stats.vendors_other > 0 && <p className="text-meta text-muted">{t('views.ethernet.vendors.others', { count: stats.vendors_other })}</p>}
      </div>
    </Card>
  );
}

/** Display name of an EtherType: its protocol name, else its code (LLC SAP, truncated header). */
function useEtherLabel(): (e: EtherTypeRef) => string {
  const { t } = useTranslation();
  return (e) => {
    if (e.kind === 'unknown') return t('views.ethernet.ethertypes.unknown');
    if (e.name !== null) return e.name;
    return e.kind === 'llc' ? t('views.ethernet.ethertypes.llc', { code: e.code }) : e.code;
  };
}

function EtherTypesCard({
  stats,
  ranged,
  active,
  onSelect,
}: {
  stats: EthernetStats;
  ranged: boolean;
  active: number | null;
  onSelect: (e: { value: number; label: string }) => void;
}) {
  const { t } = useTranslation();
  const label = useEtherLabel();
  const items = useMemo<BarItem[]>(
    () =>
      stats.ethertypes.map((e) => {
        const name = label(e.ethertype);
        const code = e.ethertype.kind === 'llc' ? t('views.ethernet.ethertypes.llc', { code: e.ethertype.code }) : e.ethertype.code;
        return {
          key: String(e.ethertype.value),
          label: name,
          title: [name, code, t('views.ethernet.ethertypes.frames', { count: e.frames }), formatBytes(e.bytes)].filter((x) => x !== '').join('\n'),
          value: e.frames,
          valueText: formatCount(e.frames),
          ...(code !== '' && code !== name ? { detail: code } : {}),
          color: CATEGORICAL[1],
          muted: e.ethertype.kind === 'unknown',
          active: e.ethertype.value === active,
        };
      }),
    [stats.ethertypes, active, label, t],
  );
  const title = t('views.ethernet.ethertypes.title');
  return (
    <Card title={ranged ? t('timeRange.wholeSessionColumn', { label: title }) : title}>
      <BarList
        items={items}
        ariaLabel={t('views.ethernet.ethertypes.label')}
        emptyText={t('views.ethernet.ethertypes.empty')}
        onSelect={(key) => {
          const item = items.find((i) => i.key === key);
          if (item !== undefined) onSelect({ value: Number(key), label: item.label });
        }}
        selectLabel={(item) => t('views.ethernet.ethertypes.filter', { name: item.label })}
      />
    </Card>
  );
}

/** Header of a counter column: under a range, it says that the value is that of the session. */
function useCounterHeader(ranged: boolean): (label: string) => string {
  const { t } = useTranslation();
  return (label) => (ranged ? t('timeRange.wholeSessionColumn', { label }) : label);
}

function tpidKey(tpid: number): 'dot1q' | 'dot1ad' | 'qinqOld' {
  if (tpid === 0x88a8) return 'dot1ad';
  if (tpid === 0x9100) return 'qinqOld';
  return 'dot1q';
}

function VlanCard({ vlans, ranged, oneDay, onSelect }: { vlans: VlanInfo[]; ranged: boolean; oneDay: boolean; onSelect: (stack: string) => void }) {
  const { t } = useTranslation();
  const counter = useCounterHeader(ranged);
  const columns = useMemo<ColumnDef<VlanInfo, unknown>[]>(
    () => [
      {
        id: 'stack',
        meta: { card: 'title' },
        accessorFn: (v) => v.stack,
        header: t('views.ethernet.vlans.stack'),
        size: 120,
        cell: ({ row }) => {
          const v = row.original;
          const title = v.depth > 1 ? t('views.ethernet.vlans.stackTitle', { outer: v.outer_id, inner: v.inner_id }) : v.stack;
          return (
            <span data-testid="truncatable" title={title} className="block truncate font-mono">
              {v.stack}
            </span>
          );
        },
      },
      {
        id: 'tag',
        meta: { card: 'action' },
        accessorFn: (v) => v.outer_tpid,
        header: t('views.ethernet.vlans.tag'),
        size: 150,
        cell: ({ row }) => <Badge>{t(`views.ethernet.vlans.${tpidKey(row.original.outer_tpid)}`)}</Badge>,
      },
      {
        id: 'frames',
        meta: { align: 'right' },
        accessorFn: (v) => v.frames,
        header: counter(t('views.ethernet.vlans.frames')),
        size: 130,
        cell: ({ row }) => <span className="num">{formatCount(row.original.frames)}</span>,
      },
      {
        id: 'bytes',
        meta: { align: 'right' },
        accessorFn: (v) => v.bytes,
        header: counter(t('views.ethernet.vlans.bytes')),
        size: 130,
        cell: ({ row }) => <span className="num">{formatBytes(row.original.bytes)}</span>,
      },
      {
        id: 'first',
        accessorFn: (v) => v.first_ts_us,
        header: t('views.ethernet.vlans.firstSeen'),
        size: oneDay ? 110 : 170,
        cell: ({ row }) => <Timestamp us={row.original.first_ts_us} withDate={!oneDay} />,
      },
      {
        id: 'last',
        accessorFn: (v) => v.last_ts_us,
        header: t('views.ethernet.vlans.lastSeen'),
        size: oneDay ? 110 : 170,
        cell: ({ row }) => <Timestamp us={row.original.last_ts_us} withDate={!oneDay} />,
      },
    ],
    [t, counter, oneDay],
  );
  return (
    <Card title={t('views.ethernet.vlans.title')} flush>
      <DataTable
        columns={columns}
        data={vlans}
        getRowId={(v) => v.stack}
        ariaLabel={t('views.ethernet.vlans.label')}
        cards
        maxHeight={320}
        onRowClick={(v) => {
          onSelect(v.stack);
        }}
      />
    </Card>
  );
}

interface ListQuery<T> {
  data: { pages: Page<T>[] } | undefined;
  isPending: boolean;
  isError: boolean;
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => Promise<unknown>;
  refetch: () => Promise<unknown>;
}

/** Table body of a keyset list: loading, error, rows and the "load more" footer. */
function PagedTable<T>({ query, children }: { query: ListQuery<T>; children: (items: T[]) => ReactNode }) {
  const { t } = useTranslation();
  if (query.isError)
    return (
      <ErrorState
        message={t('views.ethernet.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  if (query.data === undefined)
    return (
      <div className="p-3 sm:p-4">
        <Skeleton height={160} />
      </div>
    );
  const items = query.data.pages.flatMap((p) => p.items);
  return (
    <>
      {children(items)}
      <LoadMore
        shown={items.length}
        total={query.data.pages[0]?.total_estimate ?? null}
        hasMore={query.hasNextPage}
        loading={query.isFetchingNextPage}
        onMore={() => {
          void query.fetchNextPage();
        }}
      />
    </>
  );
}

function SortSelect<S extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: S;
  options: readonly { value: S; label: string }[];
  onChange: (v: S) => void;
}) {
  const id = useId();
  return (
    <>
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(e) => {
          const next = options.find((o) => o.value === e.target.value);
          if (next !== undefined) onChange(next.value);
        }}
        className="h-8 min-w-0 rounded-md border border-line bg-surface px-2 text-body"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </>
  );
}

function VlanBadges({ vlans }: { vlans: readonly string[] }) {
  if (vlans.length === 0) return <span className="text-faint">-</span>;
  return (
    <span className="flex min-w-0 flex-wrap gap-1">
      {vlans.map((v) => (
        <Badge key={v} className="font-mono">
          {v}
        </Badge>
      ))}
    </span>
  );
}

interface MacsCardProps {
  sessionId: string;
  enabled: boolean;
  ranged: boolean;
  oneDay: boolean;
  vendor: { key: string; label: string } | null;
  onClearVendor: () => void;
  vlan: string | null;
  onClearVlan: () => void;
  onSelect: (mac: string) => void;
}

function MacsCard({ sessionId, enabled, ranged, oneDay, vendor, onClearVendor, vlan, onClearVlan, onSelect }: MacsCardProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search);
  const [choice, setChoice] = useState<ClassChoice>(ALL);
  const [sort, setSort] = useState<MacSort>('frames');
  const filters = useMemo<MacFilters>(
    () => ({
      sort,
      ...(q.trim() === '' ? {} : { q: q.trim() }),
      ...(choice === ALL ? {} : { class: choice }),
      ...(vendor === null ? {} : { vendor: vendor.key }),
      ...(vlan === null ? {} : { vlan }),
    }),
    [sort, q, choice, vendor, vlan],
  );
  const list = useMacs(sessionId, filters, enabled);
  const counter = useCounterHeader(ranged);
  const filtered = search.trim() !== '' || choice !== ALL || vendor !== null || vlan !== null;

  const columns = useMemo<ColumnDef<MacInfo, unknown>[]>(
    () => [
      {
        id: 'address',
        meta: { card: 'title' },
        accessorFn: (m) => m.address.mac,
        header: t('views.ethernet.macs.col.address'),
        size: 270,
        cell: ({ row }) => <MacAddress address={row.original.address} copy />,
      },
      {
        id: 'vendor',
        accessorFn: (m) => m.address.vendor ?? '',
        header: t('views.ethernet.macs.col.vendor'),
        size: 220,
        cell: ({ row }) => <VendorName address={row.original.address} registry={row.original.registry} />,
      },
      {
        id: 'sent',
        meta: { align: 'right' },
        accessorFn: (m) => m.frames_sent,
        header: counter(t('views.ethernet.macs.col.sent')),
        size: 130,
        cell: ({ row }) => <span className="num">{formatCount(row.original.frames_sent)}</span>,
      },
      {
        id: 'received',
        meta: { align: 'right' },
        accessorFn: (m) => m.frames_received,
        header: counter(t('views.ethernet.macs.col.received')),
        size: 130,
        cell: ({ row }) => <span className="num">{formatCount(row.original.frames_received)}</span>,
      },
      {
        id: 'bytes',
        meta: { align: 'right' },
        accessorFn: (m) => m.bytes_sent + m.bytes_received,
        header: counter(t('views.ethernet.macs.col.bytes')),
        size: 120,
        cell: ({ row }) => <span className="num">{formatBytes(row.original.bytes_sent + row.original.bytes_received)}</span>,
      },
      {
        id: 'vlans',
        accessorFn: (m) => m.vlans.join(','),
        header: t('views.ethernet.macs.col.vlans'),
        size: 110,
        cell: ({ row }) => <VlanBadges vlans={row.original.vlans} />,
      },
      {
        id: 'last',
        accessorFn: (m) => m.last_ts_us,
        header: t('views.ethernet.macs.col.lastSeen'),
        size: oneDay ? 110 : 170,
        cell: ({ row }) => <Timestamp us={row.original.last_ts_us} withDate={!oneDay} />,
      },
    ],
    [t, counter, oneDay],
  );

  return (
    <Card
      title={t('views.ethernet.macs.title')}
      actions={
        <SortSelect
          label={t('views.ethernet.macs.sortLabel')}
          value={sort}
          options={MAC_SORTS.map((s) => ({ value: s, label: t(`views.ethernet.macs.sort.${s}`) }))}
          onChange={setSort}
        />
      }
      filters={
        <>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <SearchInput value={search} onChange={setSearch} placeholder={t('views.ethernet.macs.search')} />
            <div className="relative min-w-0 max-w-full overflow-x-auto">
              <SegmentedControl
                hideLabel
                label={t('views.ethernet.macs.classLabel')}
                value={choice}
                options={(['all', 'unicast', 'local', 'group'] as const).map((c) => ({ value: c, label: t(`views.ethernet.macs.class.${c}`) }))}
                onChange={setChoice}
              />
            </div>
          </div>
          {(vendor !== null || vlan !== null) && (
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              {vendor !== null && (
                <FilterChip
                  label={t('views.ethernet.macs.vendorChip', { name: vendor.label })}
                  removeLabel={t('views.ethernet.macs.removeFilter', { name: vendor.label })}
                  onRemove={onClearVendor}
                />
              )}
              {vlan !== null && (
                <FilterChip
                  label={t('views.ethernet.macs.vlanChip', { vlan })}
                  removeLabel={t('views.ethernet.macs.removeFilter', { name: vlan })}
                  onRemove={onClearVlan}
                />
              )}
              <Button
                variant="ghost"
                onClick={() => {
                  setSearch('');
                  setChoice(ALL);
                  onClearVendor();
                  onClearVlan();
                }}
              >
                {t('views.ethernet.macs.clear')}
              </Button>
            </div>
          )}
        </>
      }
      flush
    >
      <PagedTable query={list}>
        {(items) => (
          <DataTable
            columns={columns}
            data={items}
            getRowId={(m) => m.address.mac}
            ariaLabel={t('views.ethernet.macs.label')}
            cards
            emptyText={filtered ? t('views.ethernet.macs.noMatch') : t('views.ethernet.macs.empty')}
            onRowClick={(m) => {
              onSelect(m.address.mac);
            }}
          />
        )}
      </PagedTable>
    </Card>
  );
}

interface PairsCardProps {
  sessionId: string;
  enabled: boolean;
  ranged: boolean;
  oneDay: boolean;
  mac: string | null;
  onClearMac: () => void;
  vlan: string | null;
  onClearVlan: () => void;
  ethertype: { value: number; label: string } | null;
  onClearEthertype: () => void;
}

function EtherTypeBadges({ types }: { types: readonly EtherTypeRef[] }) {
  const label = useEtherLabel();
  return (
    <span className="flex min-w-0 flex-wrap gap-1">
      {types.map((e) => {
        const name = label(e);
        return (
          <Badge key={e.value} title={e.code === '' || e.code === name ? name : `${name} (${e.code})`} className="max-w-full min-w-0 overflow-hidden">
            <span className="truncate">{name}</span>
          </Badge>
        );
      })}
    </span>
  );
}

function PairsCard({
  sessionId,
  enabled,
  ranged,
  oneDay,
  mac,
  onClearMac,
  vlan,
  onClearVlan,
  ethertype,
  onClearEthertype,
}: PairsCardProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search);
  const [sort, setSort] = useState<PairSort>('frames');
  const filters = useMemo<PairFilters>(
    () => ({
      sort,
      ...(q.trim() === '' ? {} : { q: q.trim() }),
      ...(mac === null ? {} : { mac }),
      ...(vlan === null ? {} : { vlan }),
      ...(ethertype === null ? {} : { ethertype: ethertype.value }),
    }),
    [sort, q, mac, vlan, ethertype],
  );
  const list = useMacPairs(sessionId, filters, enabled);
  const counter = useCounterHeader(ranged);
  const filtered = search.trim() !== '' || mac !== null || vlan !== null || ethertype !== null;

  const columns = useMemo<ColumnDef<MacPairInfo, unknown>[]>(
    () => [
      {
        id: 'source',
        meta: { card: 'title' },
        accessorFn: (p) => p.src.mac,
        header: t('views.ethernet.pairs.col.source'),
        size: 240,
        cell: ({ row }) => <MacAddress address={row.original.src} withVendor />,
      },
      {
        id: 'destination',
        accessorFn: (p) => p.dst.mac,
        header: t('views.ethernet.pairs.col.destination'),
        size: 240,
        cell: ({ row }) => <MacAddress address={row.original.dst} withVendor />,
      },
      {
        id: 'frames',
        meta: { align: 'right' },
        accessorFn: (p) => p.frames,
        header: counter(t('views.ethernet.pairs.col.frames')),
        size: 110,
        cell: ({ row }) => <span className="num">{formatCount(row.original.frames)}</span>,
      },
      {
        id: 'bytes',
        meta: { align: 'right' },
        accessorFn: (p) => p.bytes,
        header: counter(t('views.ethernet.pairs.col.bytes')),
        size: 110,
        cell: ({ row }) => <span className="num">{formatBytes(row.original.bytes)}</span>,
      },
      {
        id: 'ethertypes',
        accessorFn: (p) => p.ethertypes.map((e) => e.value).join(','),
        header: t('views.ethernet.pairs.col.ethertypes'),
        size: 170,
        cell: ({ row }) => <EtherTypeBadges types={row.original.ethertypes} />,
      },
      {
        id: 'vlans',
        accessorFn: (p) => p.vlans.join(','),
        header: t('views.ethernet.pairs.col.vlans'),
        size: 100,
        cell: ({ row }) => <VlanBadges vlans={row.original.vlans} />,
      },
      {
        id: 'last',
        accessorFn: (p) => p.last_ts_us,
        header: t('views.ethernet.pairs.col.lastSeen'),
        size: oneDay ? 110 : 170,
        cell: ({ row }) => <Timestamp us={row.original.last_ts_us} withDate={!oneDay} />,
      },
    ],
    [t, counter, oneDay],
  );

  return (
    <Card
      title={t('views.ethernet.pairs.title')}
      actions={
        <SortSelect
          label={t('views.ethernet.pairs.sortLabel')}
          value={sort}
          options={PAIR_SORTS.map((s) => ({ value: s, label: t(`views.ethernet.pairs.sort.${s}`) }))}
          onChange={setSort}
        />
      }
      filters={
        <>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <SearchInput value={search} onChange={setSearch} placeholder={t('views.ethernet.pairs.search')} />
          </div>
          {(mac !== null || vlan !== null || ethertype !== null) && (
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              {mac !== null && (
                <FilterChip
                  label={t('views.ethernet.pairs.macChip', { mac })}
                  removeLabel={t('views.ethernet.macs.removeFilter', { name: mac })}
                  onRemove={onClearMac}
                />
              )}
              {ethertype !== null && (
                <FilterChip
                  label={t('views.ethernet.pairs.ethertypeChip', { name: ethertype.label })}
                  removeLabel={t('views.ethernet.macs.removeFilter', { name: ethertype.label })}
                  onRemove={onClearEthertype}
                />
              )}
              {vlan !== null && (
                <FilterChip
                  label={t('views.ethernet.pairs.vlanChip', { vlan })}
                  removeLabel={t('views.ethernet.macs.removeFilter', { name: vlan })}
                  onRemove={onClearVlan}
                />
              )}
            </div>
          )}
        </>
      }
      flush
    >
      <PagedTable query={list}>
        {(items) => (
          <DataTable
            columns={columns}
            data={items}
            getRowId={(p) => p.id}
            ariaLabel={t('views.ethernet.pairs.label')}
            cards
            emptyText={filtered ? t('views.ethernet.pairs.noMatch') : t('views.ethernet.pairs.empty')}
          />
        )}
      </PagedTable>
    </Card>
  );
}
