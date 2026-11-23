import { getRouteApi } from '@tanstack/react-router';
import type { TFunction } from 'i18next';
import { ArrowRight, Clock, MessageSquare, Phone, PhoneCall, ShieldAlert, UserCheck, Users } from 'lucide-react';
import { type ReactNode, useCallback, useId, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { SIP_DIALOG_TYPES, SIP_MESSAGE_KINDS, type SipDialogParams, type SipMessageParams } from '../../api/sip';
import { useSipDialogs, useSipMessages, useSipScanners, useSipStats } from '../../api/sipQueries';
import type { SipDialogInfo } from '../../api/types/SipDialogInfo';
import type { SipDialogState } from '../../api/types/SipDialogState';
import type { SipDialogType } from '../../api/types/SipDialogType';
import type { SipMediaInfo } from '../../api/types/SipMediaInfo';
import type { SipMessageInfo } from '../../api/types/SipMessageInfo';
import type { SipMessageKind } from '../../api/types/SipMessageKind';
import type { SipScannerInfo } from '../../api/types/SipScannerInfo';
import type { SipStats } from '../../api/types/SipStats';
import { useViewRange } from '../../app/timeRange';
import { CATEGORICAL } from '../../charts/palette';
import { Badge, type BadgeTone } from '../../components/Badge';
import { type BarItem, BarList } from '../../components/BarList';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { CopyButton } from '../../components/CopyButton';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { ExpandableList } from '../../components/ExpandableList';
import { FilterChip } from '../../components/FilterChip';
import { PageHeader } from '../../components/PageHeader';
import { SearchInput } from '../../components/SearchInput';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import { Timestamp } from '../../components/Timestamp';
import { WholeSessionHeader, WholeSessionLine } from '../../components/WholeSession';
import { formatByteCount, formatCount, formatDuration, formatTimestamp } from '../../lib/format';
import { useDebounced } from '../../lib/useDebounced';
import { SessionGate } from '../connections/SessionGate';
import { useViewableSession } from '../http/state';

const route = getRouteApi('/sessions/$sessionId');

/** Column layout of the dialog rows (wide screens), shared by the header and the rows. */
const DIALOG_GRID =
  'md:grid md:grid-cols-[80px_minmax(0,1fr)_112px_96px] md:items-center md:gap-3 ' +
  'xl:grid-cols-[136px_minmax(0,1fr)_112px_minmax(7rem,0.5fr)_96px_112px]';
/** Column layout of the message rows (wide screens). */
const MESSAGE_GRID =
  'md:grid md:grid-cols-[72px_200px_minmax(0,1.6fr)_minmax(0,1fr)] md:items-center md:gap-3 ' +
  'xl:grid-cols-[80px_200px_minmax(10rem,1fr)_minmax(10rem,1fr)_minmax(0,1.2fr)]';
const SELECT_CLASS = 'h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body';

type KindFilter = SipMessageKind | 'all';

/** Filters of the message list set from the other blocks (rankings, scanners, dialogs). */
interface MessageFilters {
  method: string | null;
  callId: string | null;
  sender: string | null;
  agent: string | null;
  scanner: boolean;
}

const NO_FILTERS: MessageFilters = { method: null, callId: null, sender: null, agent: null, scanner: false };

/** SIP view (docs/specs/sip.md): figures, rankings, scanners, calls and dialogs, messages. */
export default function SipView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const { session, viewable, oneDay } = useViewableSession(sessionId);
  const stats = useSipStats(sessionId, viewable);

  const [kind, setKind] = useState<KindFilter>('all');
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [filters, setFilters] = useState<MessageFilters>(NO_FILTERS);
  const messagesRef = useRef<HTMLDivElement>(null);

  const params = useMemo<SipMessageParams>(() => {
    const p: SipMessageParams = {};
    if (kind !== 'all') p.kind = kind;
    if (q !== '') p.q = q;
    if (filters.method !== null) p.method = filters.method;
    if (filters.callId !== null) p.call_id = filters.callId;
    if (filters.sender !== null) p.src = filters.sender;
    if (filters.agent !== null) p.agent = filters.agent;
    if (filters.scanner) p.scanner = true;
    return p;
  }, [kind, q, filters]);

  const showMessages = useCallback((next: Partial<MessageFilters>) => {
    setFilters({ ...NO_FILTERS, ...next });
    messagesRef.current?.scrollIntoView?.({ block: 'start' });
  }, []);

  const s = stats.data;
  let content: ReactNode;
  if (stats.isError)
    content = (
      <Card>
        <ErrorState
          message={t('views.sip.loadError')}
          onRetry={() => {
            void stats.refetch();
          }}
        />
      </Card>
    );
  else if (s !== undefined && s.messages === 0 && s.dialogs === 0)
    content = (
      <Card>
        <EmptyState icon={Phone} title={t('views.sip.empty')} />
      </Card>
    );
  else
    content = (
      <>
        <StatBand stats={s} />
        <Rankings
          stats={s}
          onMethod={(method) => {
            showMessages({ method });
          }}
          onAgent={(agent) => {
            showMessages({ agent });
          }}
        />
        <ScannersCard
          sessionId={sessionId}
          enabled={viewable}
          oneDay={oneDay}
          onShowMessages={(ip) => {
            showMessages({ sender: ip, scanner: true });
          }}
        />
        <DialogsCard
          sessionId={sessionId}
          enabled={viewable}
          oneDay={oneDay}
          onShowMessages={(callId) => {
            showMessages({ callId });
          }}
        />
        <div ref={messagesRef} className="scroll-mt-4">
          <Card
            title={t('views.sip.messages.title')}
            flush
            filters={
              <>
                <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
                  <SearchInput value={search} onChange={setSearch} placeholder={t('views.sip.messages.search')} />
                  <KindControl value={kind} onChange={setKind} />
                </div>
                <ActiveFilters filters={filters} onChange={setFilters} />
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
        title={t('nav.items.sip')}
        subtitle={session.data?.name ?? t('views.sip.subtitle')}
        {...(s === undefined ? {} : { count: <Badge>{formatCount(s.messages)}</Badge> })}
      />
      <SessionGate session={session}>{content}</SessionGate>
    </div>
  );
}

function ActiveFilters({ filters: f, onChange }: { filters: MessageFilters; onChange: (f: MessageFilters) => void }) {
  const { t } = useTranslation();
  const chips: { key: string; label: string; clear: Partial<MessageFilters> }[] = [];
  if (f.method !== null) chips.push({ key: 'method', label: t('views.sip.messages.methodChip', { method: f.method }), clear: { method: null } });
  if (f.callId !== null) chips.push({ key: 'call', label: t('views.sip.messages.callChip', { call: f.callId }), clear: { callId: null } });
  if (f.sender !== null) chips.push({ key: 'sender', label: t('views.sip.messages.senderChip', { address: f.sender }), clear: { sender: null } });
  if (f.agent !== null) chips.push({ key: 'agent', label: t('views.sip.messages.agentChip', { agent: f.agent }), clear: { agent: null } });
  if (f.scanner) chips.push({ key: 'scanner', label: t('views.sip.messages.scannerChip'), clear: { scanner: false } });
  if (chips.length === 0) return null;
  return (
    <div className="flex min-w-0 flex-wrap gap-2">
      {chips.map((c) => (
        <FilterChip
          key={c.key}
          label={c.label}
          removeLabel={t('views.sip.messages.removeFilter', { label: c.label })}
          onRemove={() => {
            onChange({ ...f, ...c.clear });
          }}
        />
      ))}
    </div>
  );
}

/** A segmented control from `sm`, a list below (long labels do not fit 375 px). */
function Choice<V extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: V;
  options: readonly { value: V; label: string }[];
  onChange: (v: V) => void;
}) {
  const id = useId();
  return (
    <>
      <div className="hidden sm:block">
        <SegmentedControl hideLabel label={label} value={value} options={options} onChange={onChange} />
      </div>
      <div className="w-full sm:hidden">
        <label htmlFor={id} className="sr-only">
          {label}
        </label>
        <select
          id={id}
          value={value}
          onChange={(e) => {
            onChange(e.target.value as V);
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

function KindControl({ value, onChange }: { value: KindFilter; onChange: (v: KindFilter) => void }) {
  const { t } = useTranslation();
  const options = (['all', ...SIP_MESSAGE_KINDS] as const).map((k) => ({ value: k, label: t(`views.sip.messages.kinds.${k}`) }));
  return <Choice label={t('views.sip.messages.kindLabel')} value={value} options={options} onChange={onChange} />;
}

function StatBand({ stats }: { stats: SipStats | undefined }) {
  const { t } = useTranslation();
  const v = (n: number | undefined) => (n === undefined ? null : formatCount(n));
  const answered = (stats?.call_states ?? [])
    .filter((x) => x.state === 'completed' || x.state === 'answered')
    .reduce((sum, x) => sum + x.count, 0);
  return (
    <section aria-label={t('views.sip.stat.label')} data-testid="sip-summary" className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
      <StatCard
        icon={MessageSquare}
        label={t('views.sip.stat.messages')}
        value={v(stats?.messages)}
        hint={
          stats === undefined
            ? ' '
            : t('views.sip.stat.messagesHint', { requests: formatCount(stats.requests), responses: formatCount(stats.responses) })
        }
      />
      <StatCard
        icon={PhoneCall}
        label={t('views.sip.stat.calls')}
        value={v(stats?.calls)}
        hint={
          stats === undefined
            ? ' '
            : t('views.sip.stat.callsHint', { answered: formatCount(answered), failed: formatCount(stats.calls - answered) })
        }
      />
      <StatCard
        icon={Clock}
        label={t('views.sip.stat.duration')}
        value={stats === undefined ? null : formatDuration(stats.call_duration_us / 1e6)}
        hint={t('views.sip.stat.durationHint')}
      />
      <StatCard icon={UserCheck} label={t('views.sip.stat.registrations')} value={v(stats?.registrations)} hint=" " />
      <StatCard icon={Users} label={t('views.sip.stat.agents')} value={v(stats?.user_agents)} hint=" " />
      <StatCard
        icon={ShieldAlert}
        label={t('views.sip.stat.scanners')}
        value={v(stats?.scanner_messages)}
        hint={t('views.sip.stat.scannersHint')}
        {...(stats !== undefined && stats.scanner_messages > 0 ? { tone: 'warning' as const } : {})}
      />
    </section>
  );
}

interface RankingsProps {
  stats: SipStats | undefined;
  onMethod: (method: string) => void;
  onAgent: (agent: string) => void;
}

function Rankings({ stats, onMethod, onAgent }: RankingsProps) {
  const { t } = useTranslation();
  const loading = stats === undefined;
  const methods: BarItem[] = (stats?.methods ?? []).map((x) => ({
    key: x.name,
    label: x.name,
    value: x.count,
    valueText: formatCount(x.count),
    color: CATEGORICAL[0],
    mono: true,
  }));
  const statuses: BarItem[] = (stats?.statuses ?? []).map((x) => {
    const label = x.reason === '' ? String(x.status) : `${x.status} ${x.reason}`;
    return { key: String(x.status), label, value: x.count, valueText: formatCount(x.count), color: CATEGORICAL[1] };
  });
  const agents: BarItem[] = (stats?.top_user_agents ?? []).map((x) => ({
    key: x.name,
    label: x.name,
    ...(x.scanner === null ? {} : { detail: t('views.sip.rank.scannerTag'), title: `${x.name} (${x.scanner})` }),
    value: x.count,
    valueText: formatCount(x.count),
    color: x.scanner === null ? CATEGORICAL[2] : CATEGORICAL[4],
  }));
  return (
    <div className="grid items-start gap-4 [grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))]">
      <Card title={t('views.sip.rank.methods')}>
        <BarList
          ariaLabel={t('views.sip.rank.methodsLabel')}
          items={methods}
          loading={loading}
          emptyText={t('views.sip.rank.empty')}
          onSelect={onMethod}
          selectLabel={(item) => t('views.sip.rank.filterMethod', { method: item.label })}
        />
      </Card>
      <Card title={t('views.sip.rank.statuses')}>
        <BarList ariaLabel={t('views.sip.rank.statusesLabel')} items={statuses} loading={loading} emptyText={t('views.sip.rank.empty')} />
      </Card>
      <Card title={t('views.sip.rank.agents')}>
        <BarList
          ariaLabel={t('views.sip.rank.agentsLabel')}
          items={agents}
          loading={loading}
          emptyText={t('views.sip.rank.empty')}
          onSelect={onAgent}
          selectLabel={(item) => t('views.sip.rank.filterAgent', { agent: item.label })}
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

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5 sm:flex-row sm:items-baseline sm:gap-3">
      <dt className="shrink-0 text-meta text-muted sm:w-40">{label}</dt>
      <dd className="min-w-0 flex-1">{children}</dd>
    </div>
  );
}

/** Text that may be long (URI, Call-ID, user agent): one line, truncated, full text on hover. */
function Clip({ value, mono = false, className = '' }: { value: string; mono?: boolean; className?: string }) {
  return (
    <span data-testid="truncatable" title={value} className={`block min-w-0 truncate ${mono ? 'font-mono' : ''} ${className}`}>
      {value}
    </span>
  );
}

// ---- scanners -----------------------------------------------------------------------------------

interface ScannersCardProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
  onShowMessages: (ip: string) => void;
}

/** Senders announcing a SIP scanner (absent when there is none). */
function ScannersCard({ sessionId, enabled, oneDay, onShowMessages }: ScannersCardProps) {
  const { t } = useTranslation();
  const query = useSipScanners(sessionId, enabled);
  const items = query.data ?? [];
  if (query.isPending || items.length === 0) return null;
  return (
    <Card title={t('views.sip.scanners.title')} flush>
      <p className="border-b border-line px-3 py-2 text-meta text-muted sm:px-4">{t('views.sip.scanners.explain')}</p>
      <ul aria-label={t('views.sip.scanners.label')} className="divide-y divide-line">
        {items.map((s) => (
          <ScannerRow key={`${s.tool}-${s.address.ip}`} scanner={s} oneDay={oneDay} onShowMessages={onShowMessages} />
        ))}
      </ul>
    </Card>
  );
}

function ScannerRow({ scanner: s, oneDay, onShowMessages }: { scanner: SipScannerInfo; oneDay: boolean; onShowMessages: (ip: string) => void }) {
  const { t } = useTranslation();
  return (
    <li className="flex min-w-0 flex-col gap-2 px-3 py-2 sm:px-4 md:flex-row md:items-center md:gap-4">
      <span className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1">
        <Badge tone="warning">{s.tool}</Badge>
        <Endpoint endpoint={s.address} show="both" className="text-meta" />
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-meta text-muted">
        <span className="num">{t('views.sip.scanners.messages', { count: s.messages })}</span>
        <span className="font-mono">{s.methods.join(', ')}</span>
        <span className="num">{t('views.sip.scanners.targets', { count: s.targets })}</span>
        <span className="flex items-center gap-1.5">
          <span>{t('views.sip.scanners.col.lastSeen')}</span>
          <Timestamp us={s.last_ts_us} withDate={!oneDay} className="text-fg" />
        </span>
      </span>
      <span className="shrink-0">
        <Button
          aria-label={t('views.sip.scanners.rowLabel', { tool: s.tool, address: s.address.ip })}
          onClick={() => {
            onShowMessages(s.address.ip);
          }}
        >
          {t('views.sip.dialogs.showMessages')}
        </Button>
      </span>
    </li>
  );
}

// ---- dialogs ------------------------------------------------------------------------------------

interface DialogsCardProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
  onShowMessages: (callId: string) => void;
}

function DialogsCard({ sessionId, enabled, oneDay, onShowMessages }: DialogsCardProps) {
  const { t } = useTranslation();
  const [type, setType] = useState<SipDialogType>('call');
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const params = useMemo<SipDialogParams>(() => (q === '' ? { type } : { type, q }), [type, q]);
  const query = useSipDialogs(sessionId, params, enabled);
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total_estimate ?? null;
  const loadMore = useCallback(() => {
    void query.fetchNextPage();
  }, [query]);
  // Dialogs are folded over the session: under a range their counters stay those of the session.
  const ranged = useViewRange() !== null;
  const options = SIP_DIALOG_TYPES.map((v) => ({ value: v, label: t(`views.sip.dialogs.types.${v}`) }));

  let body: ReactNode;
  if (query.isPending) body = <ListLoading />;
  else if (query.isError)
    body = (
      <ErrorState
        message={t('views.sip.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  else if (items.length === 0)
    body = q === '' ? <EmptyState icon={PhoneCall} title={t('views.sip.dialogs.empty')} /> : <EmptyState title={t('views.sip.dialogs.noMatch')} />;
  else
    body = (
      <ExpandableList
        items={items}
        getKey={(d) => d.id}
        ariaLabel={t('views.sip.dialogs.label')}
        header={<DialogHeader ranged={ranged} />}
        renderRow={(d) => <DialogRow dialog={d} oneDay={oneDay} ranged={ranged} />}
        renderDetail={(d) => <DialogDetail dialog={d} oneDay={oneDay} onShowMessages={onShowMessages} />}
        rowLabel={(d) =>
          t('views.sip.dialogs.rowLabel', {
            method: d.method,
            from: party(d.from_name, d.from_uri, d.client.ip),
            to: party(d.to_name, d.to_uri, d.server.ip),
            time: formatTimestamp(d.first_ts_us, !oneDay),
          })
        }
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    );

  return (
    <Card
      title={t('views.sip.dialogs.title')}
      flush
      {...(total === null ? {} : { actions: <span className="num text-meta text-muted">{formatCount(total)}</span> })}
      filters={
        <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={t('views.sip.dialogs.search')} />
          <Choice label={t('views.sip.dialogs.typeLabel')} value={type} options={options} onChange={setType} />
        </div>
      }
    >
      {body}
    </Card>
  );
}

/** Display name, else URI, else address of a party. */
function party(name: string | null, uri: string | null, ip: string): string {
  return name ?? uri ?? ip;
}

const STATE_TONES: Record<SipDialogState, BadgeTone> = {
  completed: 'success',
  answered: 'success',
  ok: 'success',
  cancelled: 'neutral',
  rejected: 'danger',
  'no-answer': 'warning',
};

function StateBadge({ state }: { state: SipDialogState }) {
  const { t } = useTranslation();
  return (
    <Badge tone={STATE_TONES[state]} className="max-w-full min-w-0 overflow-hidden">
      <span className="truncate">{t(`views.sip.dialogs.states.${state}`)}</span>
    </Badge>
  );
}

function durationText(t: TFunction, d: SipDialogInfo): string {
  if (d.duration_us === null) return '-';
  const text = formatDuration(d.duration_us / 1e6);
  return d.state === 'answered' ? `${text} (${t('views.sip.dialogs.openEnded')})` : text;
}

function statusText(d: SipDialogInfo): string {
  if (d.final_status === null) return '-';
  return d.final_reason === null ? String(d.final_status) : `${d.final_status} ${d.final_reason}`;
}

function DialogHeader({ ranged }: { ranged: boolean }) {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={DIALOG_GRID}>
        <span>{t('views.sip.dialogs.col.start')}</span>
        <span>{t('views.sip.dialogs.col.parties')}</span>
        <span>{t('views.sip.dialogs.col.state')}</span>
        <span className="hidden xl:block">{t('views.sip.dialogs.col.status')}</span>
        <span className="text-right">{t('views.sip.dialogs.col.duration')}</span>
        <span className="hidden text-right xl:block">
          <WholeSessionHeader label={t('views.sip.dialogs.col.messages')} ranged={ranged} />
        </span>
      </div>
    </div>
  );
}

function DialogRow({ dialog: d, oneDay, ranged }: { dialog: SipDialogInfo; oneDay: boolean; ranged: boolean }) {
  const { t } = useTranslation();
  const from = party(d.from_name, d.from_uri, d.client.ip);
  const to = party(d.to_name, d.to_uri, d.server.ip);
  const count = t('views.sip.dialogs.messages', { count: d.requests + d.responses });
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${DIALOG_GRID}`}>
      <span className="flex min-w-0 items-center justify-between gap-2 md:contents">
        <Timestamp us={d.first_ts_us} withDate={!oneDay} className="order-2 shrink-0 text-meta text-muted md:order-none" />
        <span className="order-1 flex min-w-0 items-center gap-1.5 md:order-none">
          <Clip value={from} className="font-medium" />
          <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint" />
          <Clip value={to} className="font-medium" />
        </span>
      </span>
      <span className="flex min-w-0 items-center gap-2 md:contents">
        <span className="min-w-0">
          <StateBadge state={d.state} />
        </span>
        <span className="hidden min-w-0 xl:block">
          <Clip value={statusText(d)} className="text-meta text-muted" />
        </span>
        <span className="num text-meta text-muted md:text-right md:text-table md:text-fg">{durationText(t, d)}</span>
      </span>
      {/* Below xl: the message count on its own line, with the "whole session" mention under a range. */}
      <span className="num flex flex-wrap gap-x-1.5 text-meta text-muted md:col-span-4 xl:hidden">
        <span>{count}</span>
        {ranged && <WholeSessionLine inline />}
      </span>
      <span className="num hidden text-right xl:block">{formatCount(d.requests + d.responses)}</span>
    </span>
  );
}

function DialogDetail({ dialog: d, oneDay, onShowMessages }: { dialog: SipDialogInfo; oneDay: boolean; onShowMessages: (callId: string) => void }) {
  const { t } = useTranslation();
  const steps: { key: string; label: string; us: number }[] = [];
  if (d.invite_ts_us !== null) steps.push({ key: 'invite', label: t('views.sip.dialogs.step.invite'), us: d.invite_ts_us });
  if (d.ringing_ts_us !== null) steps.push({ key: 'ringing', label: t('views.sip.dialogs.step.ringing'), us: d.ringing_ts_us });
  if (d.answer_ts_us !== null) steps.push({ key: 'answer', label: t('views.sip.dialogs.step.answer'), us: d.answer_ts_us });
  if (d.bye_ts_us !== null) steps.push({ key: 'bye', label: t('views.sip.dialogs.step.bye'), us: d.bye_ts_us });
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <dl className="flex min-w-0 flex-col gap-2">
        <Field label={t('views.sip.dialogs.callId')}>
          <span className="flex min-w-0 items-center gap-1">
            <Clip value={d.call_id} mono className="text-meta" />
            <CopyButton value={d.call_id} name={t('views.sip.dialogs.callId')} />
          </span>
        </Field>
        <Field label={t('views.sip.dialogs.client')}>
          <Endpoint endpoint={d.client} port={d.client_port} show="both" copy />
        </Field>
        <Field label={t('views.sip.dialogs.server')}>
          <Endpoint endpoint={d.server} port={d.server_port} show="both" copy />
        </Field>
        {d.from_uri !== null && (
          <Field label={t('views.sip.dialogs.from')}>
            <Clip value={d.from_name === null ? d.from_uri : `${d.from_name} <${d.from_uri}>`} mono className="text-meta" />
          </Field>
        )}
        {d.to_uri !== null && (
          <Field label={t('views.sip.dialogs.to')}>
            <Clip value={d.to_name === null ? d.to_uri : `${d.to_name} <${d.to_uri}>`} mono className="text-meta" />
          </Field>
        )}
        {d.contact !== null && (
          <Field label={t('views.sip.dialogs.contact')}>
            <Clip value={d.contact} mono className="text-meta" />
          </Field>
        )}
        <Field label={t('views.sip.dialogs.col.status')}>
          <span className="flex min-w-0 flex-wrap items-center gap-2 text-meta">
            <StateBadge state={d.state} />
            <span>{statusText(d)}</span>
            {d.duration_us !== null && <span className="num text-muted">{durationText(t, d)}</span>}
          </span>
        </Field>
        {(steps.length > 0 || d.cancelled) && (
          <Field label={t('views.sip.dialogs.steps')}>
            <ol className="flex min-w-0 flex-wrap gap-x-4 gap-y-1 text-meta">
              {steps.map((s) => (
                <li key={s.key} className="flex items-center gap-1.5">
                  <span className="text-muted">{s.label}</span>
                  <Timestamp us={s.us} withDate={!oneDay} />
                </li>
              ))}
              {d.cancelled && <li className="text-muted">{t('views.sip.dialogs.step.cancel')}</li>}
            </ol>
          </Field>
        )}
        {d.user_agent !== null && (
          <Field label={t('views.sip.dialogs.userAgent')}>
            <Clip value={d.user_agent} className="text-meta" />
          </Field>
        )}
        {d.server_agent !== null && (
          <Field label={t('views.sip.dialogs.serverAgent')}>
            <Clip value={d.server_agent} className="text-meta" />
          </Field>
        )}
        {d.auth_user !== null && (
          <Field label={t('views.sip.dialogs.authUser')}>
            <span className="font-mono text-meta break-all">{d.auth_user}</span>
          </Field>
        )}
        {d.challenged && d.auth_user === null && (
          <Field label={t('views.sip.dialogs.authUser')}>
            <span className="text-meta text-muted">{t('views.sip.dialogs.challenged')}</span>
          </Field>
        )}
        <Field label={t('views.sip.dialogs.transport')}>
          <span className="text-meta uppercase">{d.transport}</span>
        </Field>
        <Field label={t('views.sip.dialogs.col.messages')}>
          <span className="num text-meta">
            {t('views.sip.dialogs.counts', { requests: formatCount(d.requests), responses: formatCount(d.responses) })}
          </span>
        </Field>
      </dl>
      {d.dialog_type === 'call' && <MediaList media={d.media} />}
      <div>
        <Button
          onClick={() => {
            onShowMessages(d.call_id);
          }}
        >
          {t('views.sip.dialogs.showMessages')}
        </Button>
      </div>
    </div>
  );
}

/** RTP streams announced in the SDP of a call, with the flows observed for each. */
function MediaList({ media }: { media: readonly SipMediaInfo[] }) {
  const { t } = useTranslation();
  return (
    <section className="flex min-w-0 flex-col gap-1.5">
      <h4 className="text-meta font-medium">{t('views.sip.dialogs.media')}</h4>
      {media.length === 0 ? (
        <p className="text-meta text-muted">{t('views.sip.dialogs.mediaNone')}</p>
      ) : (
        <ul aria-label={t('views.sip.dialogs.mediaLabel')} data-testid="sip-media" className="flex min-w-0 flex-col gap-1.5">
          {media.map((m) => (
            <li
              key={`${m.media}-${m.address.ip}-${m.port}`}
              className="flex min-w-0 flex-col gap-1 rounded-md border border-line px-3 py-2 lg:flex-row lg:items-center lg:gap-4"
            >
              <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
                <Badge>{m.media}</Badge>
                <Endpoint endpoint={m.address} port={m.port} show="address" className="text-meta" />
                <span className="font-mono text-meta text-muted">{m.codecs.join(', ')}</span>
              </span>
              <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-meta text-muted lg:ml-auto">
                {m.direction !== null && <span>{m.direction}</span>}
                {m.port === 0 ? (
                  <span>{t('views.sip.dialogs.refused')}</span>
                ) : m.flow_count === 0 ? (
                  <span>{t('views.sip.dialogs.noFlow')}</span>
                ) : (
                  <>
                    <span className="num">{t('views.sip.dialogs.flows', { count: m.flow_count })}</span>
                    <span className="num">{t('views.sip.dialogs.packets', { count: m.packets })}</span>
                    <span className="num">{formatByteCount(m.bytes)}</span>
                  </>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// ---- messages -----------------------------------------------------------------------------------

interface MessageListProps {
  sessionId: string;
  params: SipMessageParams;
  enabled: boolean;
  oneDay: boolean;
}

function MessageList({ sessionId, params, enabled, oneDay }: MessageListProps) {
  const { t } = useTranslation();
  const query = useSipMessages(sessionId, params, enabled);
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total_estimate ?? null;
  const loadMore = useCallback(() => {
    void query.fetchNextPage();
  }, [query]);
  if (query.isPending) return <ListLoading />;
  if (query.isError)
    return (
      <ErrorState
        message={t('views.sip.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  if (items.length === 0) return <EmptyState title={t('views.sip.messages.empty')} />;
  return (
    <>
      {total !== null && (
        <p className="border-b border-line px-3 py-1.5 text-meta text-muted sm:px-4" data-testid="sip-row-count">
          {t('common.rows', { count: total })}
        </p>
      )}
      <ExpandableList
        items={items}
        getKey={(m) => m.id}
        ariaLabel={t('views.sip.messages.label')}
        header={<MessageHeader />}
        renderRow={(m) => <MessageRow message={m} oneDay={oneDay} />}
        renderDetail={(m) => <MessageDetail message={m} />}
        rowLabel={(m) =>
          t('views.sip.messages.rowLabel', { kind: messageLabel(m), source: m.source.ip, time: formatTimestamp(m.ts_us, !oneDay) })
        }
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    </>
  );
}

/** `INVITE`, or `180 Ringing (INVITE)`: protocol values, shown as sent. */
function messageLabel(m: SipMessageInfo): string {
  if (m.kind === 'request') return m.method ?? '-';
  const head = m.reason === null ? String(m.status ?? '-') : `${m.status ?? '-'} ${m.reason}`;
  return m.method === null ? head : `${head} (${m.method})`;
}

function MessageBadge({ message: m }: { message: SipMessageInfo }) {
  let tone: BadgeTone = 'accent';
  if (m.scanner !== null) tone = 'warning';
  else if (m.kind === 'response') tone = (m.status ?? 0) >= 400 ? 'danger' : 'neutral';
  return (
    <Badge tone={tone} title={messageLabel(m)} className="max-w-full min-w-0 overflow-hidden">
      <span className="truncate">{messageLabel(m)}</span>
    </Badge>
  );
}

function MessageHeader() {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={MESSAGE_GRID}>
        <span>{t('views.sip.messages.col.time')}</span>
        <span>{t('views.sip.messages.col.type')}</span>
        <span>
          <span className="xl:hidden">{t('views.sip.messages.col.sourceDestination')}</span>
          <span className="hidden xl:inline">{t('views.sip.messages.col.source')}</span>
        </span>
        <span className="hidden xl:block">{t('views.sip.messages.col.destination')}</span>
        <span>{t('views.sip.messages.col.callId')}</span>
      </div>
    </div>
  );
}

function MessageRow({ message: m, oneDay }: { message: SipMessageInfo; oneDay: boolean }) {
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${MESSAGE_GRID}`}>
      <span className="flex min-w-0 items-center justify-between gap-2 md:contents">
        <Timestamp us={m.ts_us} withDate={!oneDay} className="order-2 shrink-0 text-meta text-muted md:order-none" />
        <span className="order-1 min-w-0 md:order-none">
          <MessageBadge message={m} />
        </span>
      </span>
      {/* Source and destination together up to xl, in two columns from xl. */}
      <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 text-meta xl:block">
        <Endpoint endpoint={m.source} port={m.src_port} show="address" className="text-meta" />
        <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint xl:hidden" />
        <span className="min-w-0 xl:hidden">
          <Endpoint endpoint={m.destination} port={m.dst_port} show="address" className="text-meta" />
        </span>
      </span>
      <span className="hidden min-w-0 text-meta xl:block">
        <Endpoint endpoint={m.destination} port={m.dst_port} show="address" className="text-meta" />
      </span>
      <Clip value={m.call_id ?? '-'} mono className="text-meta text-muted" />
    </span>
  );
}

function MessageDetail({ message: m }: { message: SipMessageInfo }) {
  const { t } = useTranslation();
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <span className="min-w-0 text-meta text-muted">
          {t('views.sip.messages.raw')}
          {', '}
          {m.transport.toUpperCase()}
          {', '}
          {m.raw_truncated
            ? t('views.sip.messages.truncated', { shown: formatCount(4096), size: formatCount(m.size) })
            : t('views.sip.messages.size', { size: formatCount(m.size) })}
        </span>
        <CopyButton value={m.raw} name={t('views.sip.messages.rawName')} />
      </div>
      {/* Text only: React escapes it, nothing in a capture is ever interpreted as markup. */}
      {/* Bounded to 4 KiB: no height limit, long lines wrap (no scrolling inside the list). */}
      <pre
        data-testid="sip-raw"
        className="max-w-full min-w-0 rounded-md border border-line bg-surface p-3 font-mono text-meta whitespace-pre-wrap [overflow-wrap:anywhere]"
      >
        {m.raw.replace(/\n+$/, '')}
      </pre>
    </div>
  );
}
