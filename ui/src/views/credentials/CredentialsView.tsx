import { getRouteApi } from '@tanstack/react-router';
import { ArrowRight, ChevronDown, Download, KeyRound, ShieldAlert, X } from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useViewRange } from '../../app/timeRange';
import { useCredential, useCredentialPaths, useCredentialStats, useCredentials } from '../../api/credentialQueries';
import { type CredentialExport, MAX_EXPORT, type SecretState, downloadCredentials } from '../../api/credentials';
import { useSession } from '../../api/sessionQueries';
import type { CredentialEndpoint } from '../../api/types/CredentialEndpoint';
import type { CredentialInfo } from '../../api/types/CredentialInfo';
import type { CredentialPaths } from '../../api/types/CredentialPaths';
import type { CredentialStats } from '../../api/types/CredentialStats';
import { Badge, type BadgeTone } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Dialog } from '../../components/Dialog';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorNote } from '../../components/ErrorNote';
import { ErrorState } from '../../components/ErrorState';
import { PageHeader } from '../../components/PageHeader';
import { SecretValue } from '../../components/SecretValue';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import type { en } from '../../i18n/en';
import { cn } from '../../lib/cn';
import { formatCount } from '../../lib/format';
import { MD_QUERY, useMediaQuery } from '../../lib/useMediaQuery';
import { isViewable } from '../connections/session';
import { SessionGate } from '../connections/SessionGate';
import { Timestamp } from '../../components/Timestamp';

const route = getRouteApi('/sessions/$sessionId');

type Creds = (typeof en)['views']['credentials'];
type Group = 'state' | 'kind' | 'detailKey' | 'result';
type TokenKey<G extends Group> = `views.credentials.${G}.${keyof Creds[G] & string}`;

/** Key of a stable backend token (state, kind, detail key, result) under `views.credentials`. */
function tokenKey<G extends Group>(group: G, value: string): TokenKey<G> {
  return `views.credentials.${group}.${value}` as TokenKey<G>;
}

const SELECT_CLASS = 'h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body sm:w-auto sm:max-w-64';

/** Protocol names as written in the protocols' specifications (not translated). */
const PROTOCOL_LABELS: Record<string, string> = {
  ftp: 'FTP',
  http: 'HTTP',
  imap: 'IMAP',
  ldap: 'LDAP',
  pop3: 'POP3',
  smb: 'SMB',
  smtp: 'SMTP',
  snmp: 'SNMP',
};

/** Material named by each hashcat mode emitted by the analyzers. */
const HASHCAT_NAMES: Record<number, string> = {
  5500: 'NetNTLMv1',
  5600: 'NetNTLMv2',
  16400: 'CRAM-MD5',
};

function protocolLabel(p: string): string {
  return PROTOCOL_LABELS[p] ?? p.toUpperCase();
}

function modeLabel(mode: number): string {
  const name = HASHCAT_NAMES[mode];
  return name === undefined ? String(mode) : `${mode} (${name})`;
}

/** Badge tones of the secret states: clear text in amber, recoverable neutral, metadata grey. */
const STATE_TONES: Record<string, { tone: BadgeTone; className?: string }> = {
  plaintext: { tone: 'warning' },
  recoverable: { tone: 'neutral', className: 'text-fg' },
  'metadata-only': { tone: 'neutral' },
};

type StateFilter = 'all' | SecretState;

/** An export waiting for the user's confirmation. */
interface PendingExport {
  request: CredentialExport;
  count: number;
}

/** Credentials view: aggregated paths, key figures and the list of captured credentials. */
export default function CredentialsView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const viewable = isViewable(session.data);
  const stats = useCredentialStats(sessionId, viewable);
  const analyzed = stats.data?.analyzed !== false;
  const paths = useCredentialPaths(sessionId, viewable && analyzed);

  const [stateFilter, setStateFilter] = useState<StateFilter>('all');
  const [protocol, setProtocol] = useState('');
  const filters = { state: stateFilter === 'all' ? null : stateFilter, protocol: protocol === '' ? null : protocol };
  const list = useCredentials(sessionId, filters, viewable && stats.data !== undefined && analyzed);
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];
  const filteredTotal = list.data?.pages[0]?.total_estimate ?? null;

  const [pending, setPending] = useState<PendingExport | null>(null);
  const [exported, setExported] = useState<string | null>(null);

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.credentials')}
        subtitle={session.data?.name ?? t('views.credentials.subtitle')}
        {...(stats.data === undefined ? {} : { count: <Badge>{formatCount(stats.data.total)}</Badge> })}
      />
      <SessionGate session={session}>
        {exported !== null && (
          <SensitiveBanner
            name={exported}
            onDismiss={() => {
              setExported(null);
            }}
          />
        )}
        {stats.isError ? (
          <Card>
            <ErrorState message={t('views.credentials.loadError')} onRetry={() => void stats.refetch()} />
          </Card>
        ) : !analyzed ? (
          <Card>
            <EmptyState
              icon={KeyRound}
              title={t('views.credentials.notAnalyzedTitle')}
              description={t('views.credentials.notAnalyzedText')}
            />
          </Card>
        ) : (
          <>
            <Card title={t('views.credentials.paths.title')}>
              <PathsBlock query={paths} />
            </Card>
            <StatsBand stats={stats.data} shown={list.data === undefined ? null : items.length} total={filteredTotal} />
            <Card
              title={t('views.credentials.list.title')}
              actions={
                <ExportActions
                  stats={stats.data}
                  count={filteredTotal ?? 0}
                  onExport={(request, count) => {
                    setPending({ request: { ...request, ...filters }, count });
                  }}
                  onExportMode={(mode, count) => {
                    setPending({ request: { format: 'hashcat', mode }, count });
                  }}
                />
              }
              filters={
                <Filters
                  stats={stats.data}
                  state={stateFilter}
                  onState={setStateFilter}
                  protocol={protocol}
                  onProtocol={setProtocol}
                />
              }
            >
              <CredentialList
                sessionId={sessionId}
                query={list}
                items={items}
                filtered={stateFilter !== 'all' || protocol !== ''}
                onExport={(request) => {
                  setPending({ request, count: 1 });
                }}
              />
            </Card>
          </>
        )}
        <ExportDialog
          sessionId={sessionId}
          pending={pending}
          onClose={() => {
            setPending(null);
          }}
          onDone={(name) => {
            setPending(null);
            setExported(name);
          }}
        />
      </SessionGate>
    </div>
  );
}

/** Persistent notice after an export: the file holds secrets. */
function SensitiveBanner({ name, onDismiss }: { name: string; onDismiss: () => void }) {
  const { t } = useTranslation();
  return (
    <div role="status" className="flex min-w-0 items-start gap-2 rounded-lg border border-line bg-surface px-3 py-2 text-meta sm:px-4">
      <ShieldAlert aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-warning" />
      <p className="min-w-0 flex-1 [overflow-wrap:anywhere]">{t('views.credentials.export.banner', { name })}</p>
      <button
        type="button"
        onClick={onDismiss}
        aria-label={t('views.credentials.export.dismiss')}
        title={t('views.credentials.export.dismiss')}
        className="inline-flex size-8 shrink-0 items-center justify-center rounded-md text-muted hover:bg-subtle hover:text-fg"
      >
        <X aria-hidden size={16} strokeWidth={1.75} />
      </button>
    </div>
  );
}

interface Query<T> {
  isPending: boolean;
  isError: boolean;
  data: T | undefined;
  refetch: () => Promise<unknown>;
}

function Loading() {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-2" aria-busy="true">
      <span className="sr-only">{t('common.loading')}</span>
      <Skeleton height={32} />
      <Skeleton height={32} />
    </div>
  );
}

/** Address and port (mono), then the first resolved name in grey, as in the other views. */
function End({ end }: { end: CredentialEndpoint | null }) {
  if (end === null) return <span className="text-muted">-</span>;
  return <Endpoint endpoint={end.endpoint} port={end.port} show="both" />;
}

/** Aggregated client -> protocol -> server paths (readable list instead of a node graph). */
function PathsBlock({ query }: { query: Query<CredentialPaths> }) {
  const { t } = useTranslation();
  const wide = useMediaQuery(MD_QUERY);
  if (query.isPending) return <Loading />;
  if (query.isError || query.data === undefined)
    return <ErrorState message={t('views.credentials.loadError')} onRetry={() => void query.refetch()} />;
  const { paths, others } = query.data;
  if (paths.length === 0) return <EmptyState icon={KeyRound} title={t('views.credentials.paths.empty')} />;
  const othersNote =
    others > 0 ? <p className="text-meta text-muted">{t('views.credentials.paths.others', { count: others })}</p> : null;
  if (!wide)
    return (
      <div className="flex flex-col gap-2">
        <ul aria-label={t('views.credentials.paths.label')} className="divide-y divide-line">
          {paths.map((p, i) => (
            <li key={i} className="flex min-w-0 flex-col gap-1 py-2 first:pt-0">
              <div className="flex min-w-0 items-center gap-1.5">
                <End end={p.client} />
                <ArrowRight aria-hidden size={16} strokeWidth={1.75} className="shrink-0 text-faint" />
                <Badge>{protocolLabel(p.protocol)}</Badge>
              </div>
              <div className="flex min-w-0 items-center justify-between gap-2">
                <End end={p.server} />
                <span className="flex shrink-0 flex-col items-end text-meta">
                  <span className="num text-muted">{t('views.credentials.paths.entries', { count: p.entries })}</span>
                  {p.plaintext > 0 && <span className="num text-warning">{t('views.credentials.paths.clear', { count: p.plaintext })}</span>}
                </span>
              </div>
            </li>
          ))}
        </ul>
        {othersNote}
      </div>
    );
  return (
    <div className="flex flex-col gap-2">
      <table aria-label={t('views.credentials.paths.label')} className="w-full table-fixed border-collapse text-table">
        <thead>
          <tr className="border-b border-line text-left text-meta text-muted">
            <th scope="col" className="py-1.5 pr-3 font-medium">{t('views.credentials.paths.client')}</th>
            <th scope="col" className="w-8" aria-hidden />
            <th scope="col" className="w-24 py-1.5 pr-3 font-medium">{t('views.credentials.paths.protocol')}</th>
            <th scope="col" className="w-8" aria-hidden />
            <th scope="col" className="py-1.5 pr-3 font-medium">{t('views.credentials.paths.server')}</th>
            <th scope="col" className="w-40 py-1.5 text-right font-medium">{t('views.credentials.paths.entriesHeader')}</th>
          </tr>
        </thead>
        <tbody>
          {paths.map((p, i) => (
            <tr key={i} className="border-b border-line last:border-b-0">
              <td className="py-1.5 pr-3"><End end={p.client} /></td>
              <td className="text-faint"><ArrowRight aria-hidden size={16} strokeWidth={1.75} /></td>
              <td className="py-1.5 pr-3"><Badge>{protocolLabel(p.protocol)}</Badge></td>
              <td className="text-faint"><ArrowRight aria-hidden size={16} strokeWidth={1.75} /></td>
              <td className="py-1.5 pr-3"><End end={p.server} /></td>
              <td className="num py-1.5 text-right">
                {formatCount(p.entries)}
                {p.plaintext > 0 && (
                  <span className="ml-2 text-meta text-warning">{t('views.credentials.paths.clear', { count: p.plaintext })}</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {othersNote}
    </div>
  );
}

function StatsBand({ stats, shown, total }: { stats: CredentialStats | undefined; shown: number | null; total: number | null }) {
  const { t } = useTranslation();
  const value = (n: number | undefined) => (n === undefined ? null : formatCount(n));
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        label={t('views.credentials.stats.plaintext')}
        value={value(stats?.plaintext)}
        hint={t('views.credentials.stats.plaintextHint')}
        tone={(stats?.plaintext ?? 0) > 0 ? 'warning' : 'neutral'}
      />
      <StatCard
        label={t('views.credentials.stats.recoverable')}
        value={value(stats?.recoverable)}
        hint={t('views.credentials.stats.recoverableHint')}
      />
      <StatCard
        label={t('views.credentials.stats.handshakes')}
        value={value(stats?.handshakes)}
        hint={t('views.credentials.stats.handshakesHint')}
      />
      <StatCard
        label={t('views.credentials.stats.shown')}
        value={shown === null || total === null ? null : t('common.shownOf', { shown: formatCount(shown), total: formatCount(total) })}
        hint={t('views.credentials.stats.shownHint')}
      />
    </div>
  );
}

function Filters({
  stats,
  state,
  onState,
  protocol,
  onProtocol,
}: {
  stats: CredentialStats | undefined;
  state: StateFilter;
  onState: (s: StateFilter) => void;
  protocol: string;
  onProtocol: (p: string) => void;
}) {
  const { t } = useTranslation();
  const wide = useMediaQuery(MD_QUERY);
  const protocolId = useId();
  const stateId = useId();
  const options: { value: StateFilter; label: string }[] = [
    { value: 'all', label: t('views.credentials.filters.all') },
    { value: 'plaintext', label: t('views.credentials.state.plaintext') },
    { value: 'recoverable', label: t('views.credentials.state.recoverable') },
    { value: 'metadata-only', label: t('views.credentials.state.metadata-only') },
  ];
  const protocolSelect = (
    <select
      id={protocolId}
      value={protocol}
      onChange={(e) => {
        onProtocol(e.target.value);
      }}
      className={SELECT_CLASS}
    >
      <option value="">{t('views.credentials.filters.anyProtocol')}</option>
      {(stats?.protocols ?? []).map((p) => (
        <option key={p.protocol} value={p.protocol}>
          {`${protocolLabel(p.protocol)} (${formatCount(p.count)})`}
        </option>
      ))}
    </select>
  );
  if (wide)
    return (
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <div className="max-w-full min-w-0">
          <SegmentedControl hideLabel label={t('views.credentials.filters.state')} value={state} options={options} onChange={onState} />
        </div>
        <label htmlFor={protocolId} className="sr-only">
          {t('views.credentials.filters.protocol')}
        </label>
        {protocolSelect}
      </div>
    );
  // Below 768 px the filters move into a "Filters" disclosure menu, as in the HTTP view.
  const active = Number(state !== 'all') + Number(protocol !== '');
  return (
    <details className="group relative" data-testid="credentials-filters-menu">
      <summary className="inline-flex h-8 cursor-pointer list-none items-center gap-1.5 rounded-md border border-line bg-surface px-3 text-body [&::-webkit-details-marker]:hidden">
        {t('common.filters')}
        <span className="num text-meta text-muted">{active}/2</span>
        <ChevronDown aria-hidden size={16} strokeWidth={1.75} className="group-open:rotate-180" />
      </summary>
      <div className="absolute top-full left-0 z-20 mt-1 flex w-72 max-w-[calc(100vw-3rem)] flex-col gap-3 rounded-lg border border-line bg-surface p-3 shadow-xs">
        <div className="flex flex-col gap-1">
          <label htmlFor={stateId} className="text-meta text-muted">
            {t('views.credentials.filters.state')}
          </label>
          <select
            id={stateId}
            value={state}
            onChange={(e) => {
              onState(e.target.value as StateFilter);
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
        <div className="flex flex-col gap-1">
          <label htmlFor={protocolId} className="text-meta text-muted">
            {t('views.credentials.filters.protocol')}
          </label>
          {protocolSelect}
        </div>
      </div>
    </details>
  );
}

function ExportActions({
  stats,
  count,
  onExport,
  onExportMode,
}: {
  stats: CredentialStats | undefined;
  count: number;
  onExport: (request: CredentialExport, count: number) => void;
  onExportMode: (mode: number, count: number) => void;
}) {
  const { t } = useTranslation();
  return (
    <>
      <Button
        disabled={count === 0}
        onClick={() => {
          onExport({ format: 'csv' }, count);
        }}
      >
        <Download aria-hidden size={16} strokeWidth={1.75} />
        {t('views.credentials.export.csv')}
      </Button>
      {(stats?.hashcat_modes ?? []).map((m) => (
        <Button
          key={m.mode}
          title={modeLabel(m.mode)}
          onClick={() => {
            onExportMode(m.mode, m.count);
          }}
        >
          <Download aria-hidden size={16} strokeWidth={1.75} />
          {t('views.credentials.export.hashcat', { mode: m.mode })}
        </Button>
      ))}
    </>
  );
}

interface ListQuery {
  isPending: boolean;
  isError: boolean;
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => Promise<unknown>;
  refetch: () => Promise<unknown>;
}

function CredentialList({
  sessionId,
  query,
  items,
  filtered,
  onExport,
}: {
  sessionId: string;
  query: ListQuery;
  items: CredentialInfo[];
  filtered: boolean;
  onExport: (request: CredentialExport) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  if (query.isPending) return <Loading />;
  if (query.isError) return <ErrorState message={t('views.credentials.loadError')} onRetry={() => void query.refetch()} />;
  if (items.length === 0)
    return filtered ? (
      <EmptyState icon={KeyRound} title={t('views.credentials.list.noMatch')} />
    ) : (
      <EmptyState icon={KeyRound} title={t('views.credentials.list.empty')} description={t('views.credentials.list.emptyText')} />
    );
  const toggle = (id: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  return (
    <div className="flex flex-col gap-3">
      <ul aria-label={t('views.credentials.list.label')} className="flex flex-col gap-2">
        {items.map((c) => (
          <CredentialCard
            key={c.id}
            sessionId={sessionId}
            credential={c}
            expanded={open.has(c.id)}
            onToggle={() => {
              toggle(c.id);
            }}
            onExport={onExport}
          />
        ))}
      </ul>
      {query.hasNextPage && (
        <div className="flex justify-center">
          <Button disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>
            {t('common.loadMore')}
          </Button>
        </div>
      )}
    </div>
  );
}

function StateBadge({ state }: { state: string }) {
  const { t } = useTranslation();
  const style = STATE_TONES[state] ?? { tone: 'neutral' as const };
  return (
    <Badge tone={style.tone} {...(style.className === undefined ? {} : { className: style.className })}>
      {t(tokenKey('state', state), { defaultValue: state })}
    </Badge>
  );
}

function CredentialCard({
  sessionId,
  credential: c,
  expanded,
  onToggle,
  onExport,
}: {
  sessionId: string;
  credential: CredentialInfo;
  expanded: boolean;
  onToggle: () => void;
  onExport: (request: CredentialExport) => void;
}) {
  const { t } = useTranslation();
  const panelId = useId();
  // Identical observations are folded: under a range the count stays that of the session.
  const ranged = useViewRange() !== null;
  const kind = t(tokenKey('kind', c.kind), { defaultValue: c.kind });
  const label = `${protocolLabel(c.protocol)} ${kind}`;
  const login = [c.domain, c.username].filter((v) => v !== null && v !== '').join('\\');
  return (
    <li className="min-w-0 rounded-lg border border-line">
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={panelId}
        aria-label={t(expanded ? 'views.credentials.card.collapse' : 'views.credentials.card.expand', { label })}
        onClick={onToggle}
        className="flex w-full min-w-0 flex-col gap-2 rounded-lg px-3 py-2.5 text-left hover:bg-subtle sm:px-4"
      >
        <span className="flex w-full min-w-0 items-center gap-2">
          <Badge>{protocolLabel(c.protocol)}</Badge>
          <span className="min-w-0 flex-1 truncate text-meta text-muted" data-testid="truncatable" title={kind}>
            {kind}
          </span>
          <StateBadge state={c.secret_state} />
          <ChevronDown
            aria-hidden
            size={16}
            strokeWidth={1.75}
            className={cn('shrink-0 text-muted transition-transform', expanded && 'rotate-180')}
          />
        </span>
        <span className="flex w-full min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <span className="sr-only">{t('views.credentials.card.from')}</span>
          <End end={c.client} />
          <ArrowRight aria-hidden size={16} strokeWidth={1.75} className="shrink-0 text-faint" />
          <span className="sr-only">{t('views.credentials.card.to')}</span>
          <End end={c.server} />
        </span>
        <span className="flex w-full min-w-0 flex-wrap items-center justify-between gap-x-3 gap-y-1 text-meta">
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="shrink-0 text-muted">{t('views.credentials.card.login')}</span>
            {login === '' ? (
              <span className="text-muted italic">{t('views.credentials.card.unavailable')}</span>
            ) : (
              <span className="truncate font-mono" data-testid="truncatable" title={login}>
                {login}
              </span>
            )}
          </span>
          <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-muted">
            <span className="num">
              {ranged
                ? t('timeRange.wholeSessionColumn', { label: t('views.credentials.card.seen', { count: c.seen_count }) })
                : t('views.credentials.card.seen', { count: c.seen_count })}
            </span>
            <Timestamp us={c.first_ts_us} />
          </span>
        </span>
      </button>
      {expanded && (
        <div id={panelId} className="border-t border-line px-3 py-3 sm:px-4">
          <CredentialDetailPanel sessionId={sessionId} credential={c} onExport={onExport} />
        </div>
      )}
    </li>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5 sm:flex-row sm:gap-4">
      <dt className="shrink-0 text-meta text-muted sm:w-44">{label}</dt>
      <dd className="min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

function CredentialDetailPanel({
  sessionId,
  credential: c,
  onExport,
}: {
  sessionId: string;
  credential: CredentialInfo;
  onExport: (request: CredentialExport) => void;
}) {
  const { t } = useTranslation();
  const detail = useCredential(sessionId, c.id, true);
  const ranged = useViewRange() !== null;
  return (
    <div className="flex flex-col gap-3">
      <dl className="flex flex-col gap-1.5">
        <Row label={t('views.credentials.detail.protocol')}>{protocolLabel(c.protocol)}</Row>
        <Row label={t('views.credentials.detail.kind')}>{t(tokenKey('kind', c.kind), { defaultValue: c.kind })}</Row>
        <Row label={t('views.credentials.detail.client')}>
          <End end={c.client} />
        </Row>
        <Row label={t('views.credentials.detail.server')}>
          <End end={c.server} />
        </Row>
        {c.username !== null && (
          <Row label={t('views.credentials.detail.username')}>
            <span className="font-mono">{c.username}</span>
          </Row>
        )}
        {c.domain !== null && (
          <Row label={t('views.credentials.detail.domain')}>
            <span className="font-mono">{c.domain}</span>
          </Row>
        )}
        {c.workstation !== null && (
          <Row label={t('views.credentials.detail.workstation')}>
            <span className="font-mono">{c.workstation}</span>
          </Row>
        )}
        {c.details.map((d) => (
          <Row key={d.key} label={t(tokenKey('detailKey', d.key), { defaultValue: d.key })}>
            <span className={cn(d.key === 'server_challenge' && 'font-mono')}>{d.key === 'result' ? t(tokenKey('result', d.value), { defaultValue: d.value }) : d.value}</span>
          </Row>
        ))}
        <Row label={t('views.credentials.detail.firstSeen')}>
          <Timestamp us={c.first_ts_us} />
        </Row>
        {c.seen_count > 1 && (
          <Row label={t('views.credentials.detail.lastSeen')}>
            <Timestamp us={c.last_ts_us} />
          </Row>
        )}
        <Row
          label={
            ranged
              ? t('timeRange.wholeSessionColumn', { label: t('views.credentials.detail.seen') })
              : t('views.credentials.detail.seen')
          }
        >
          <span className="num">{formatCount(c.seen_count)}</span>
        </Row>
        {c.hashcat_mode !== null && (
          <Row label={t('views.credentials.detail.mode')}>
            <span className="num">{modeLabel(c.hashcat_mode)}</span>
          </Row>
        )}
        {detail.isPending ? (
          <Skeleton height={20} />
        ) : detail.isError || detail.data === undefined ? (
          <ErrorNote error={detail.error} format={() => t('views.credentials.detail.loadError')} />
        ) : (
          <>
            {detail.data.secret !== null && (
              <Row label={t('views.credentials.detail.secret')}>
                <SecretValue value={detail.data.secret} label={t('views.credentials.detail.secretLabel')}>
                  <span className="font-mono">{detail.data.secret}</span>
                </SecretValue>
              </Row>
            )}
            {detail.data.hashcat_line !== null && (
              <Row label={t('views.credentials.detail.hashcat')}>
                <SecretValue value={detail.data.hashcat_line} label={t('views.credentials.detail.hashcatLabel')}>
                  <span className="font-mono text-meta">{detail.data.hashcat_line}</span>
                </SecretValue>
              </Row>
            )}
            {detail.data.secret === null && detail.data.hashcat_line === null && (
              <p className="text-meta text-muted">{t('views.credentials.detail.noSecret')}</p>
            )}
          </>
        )}
      </dl>
      {c.has_secret && (
        <div className="flex flex-wrap gap-2">
          <Button
            onClick={() => {
              onExport({ format: 'csv', ids: [c.id] });
            }}
          >
            <Download aria-hidden size={16} strokeWidth={1.75} />
            {t('views.credentials.export.entryCsv')}
          </Button>
          {c.hashcat_mode !== null && (
            <Button
              onClick={() => {
                onExport({ format: 'hashcat', mode: c.hashcat_mode, ids: [c.id] });
              }}
            >
              <Download aria-hidden size={16} strokeWidth={1.75} />
              {t('views.credentials.export.entryHashcat')}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

function ExportDialog({
  sessionId,
  pending,
  onClose,
  onDone,
}: {
  sessionId: string;
  pending: PendingExport | null;
  onClose: () => void;
  onDone: (name: string) => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  // An export of the filtered list follows the time range of the list (a selection does not).
  const range = useViewRange();
  const close = () => {
    setError(null);
    onClose();
  };
  // An export is never truncated: above the server bound it is refused, so it is not offered.
  const tooMany = pending !== null && pending.count > MAX_EXPORT;
  const confirm = () => {
    if (pending === null || tooMany) return;
    setBusy(true);
    setError(null);
    downloadCredentials(sessionId, { ...pending.request, range })
      .then((name) => {
        onDone(name);
      })
      .catch((e: unknown) => {
        setError(e);
      })
      .finally(() => {
        setBusy(false);
      });
  };
  return (
    <Dialog
      open={pending !== null}
      onClose={close}
      title={t('views.credentials.export.title')}
      footer={
        <>
          <Button data-autofocus onClick={close}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" disabled={busy || tooMany} onClick={confirm}>
            <Download aria-hidden size={16} strokeWidth={1.75} />
            {t('views.credentials.export.confirm')}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <p className="flex items-start gap-2">
          <ShieldAlert aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-warning" />
          <span>
            {tooMany
              ? t('views.credentials.export.tooMany', {
                  count: pending?.count ?? 0,
                  n: formatCount(pending?.count ?? 0),
                  max: formatCount(MAX_EXPORT),
                })
              : t('views.credentials.export.body', { count: pending?.count ?? 0, n: formatCount(pending?.count ?? 0) })}
          </span>
        </p>
        {error !== null && <ErrorNote error={error} format={(message) => t('views.credentials.export.error', { message })} />}
      </div>
    </Dialog>
  );
}
