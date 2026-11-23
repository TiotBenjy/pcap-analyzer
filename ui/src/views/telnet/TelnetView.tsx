import { getRouteApi } from '@tanstack/react-router';
import { ArrowRight, KeyRound, Monitor, Scissors, Server, SquareTerminal } from 'lucide-react';
import { type ReactNode, useCallback, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { TELNET_LOGINS, type TelnetLoginFilter, type TelnetSessionParams } from '../../api/telnet';
import { useTelnetSession, useTelnetSessions, useTelnetStats } from '../../api/telnetQueries';
import type { TelnetRun } from '../../api/types/TelnetRun';
import type { TelnetSessionInfo } from '../../api/types/TelnetSessionInfo';
import type { TelnetStats } from '../../api/types/TelnetStats';
import { useViewRange } from '../../app/timeRange';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { ExpandableList } from '../../components/ExpandableList';
import { PageHeader } from '../../components/PageHeader';
import { SearchInput } from '../../components/SearchInput';
import { SecretValue } from '../../components/SecretValue';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import { Timestamp } from '../../components/Timestamp';
import { WholeSessionHeader } from '../../components/WholeSession';
import { formatBytes, formatCount, formatSpan, formatTimestamp } from '../../lib/format';
import { useDebounced } from '../../lib/useDebounced';
import { SessionGate } from '../connections/SessionGate';
import { useViewableSession } from '../http/state';

const route = getRouteApi('/sessions/$sessionId');

/** Column layout of the session rows (wide screens), shared by the header and the rows. */
// Top-aligned: the expand chevron stays on the first line when the badges wrap.
const SESSION_GRID =
  'md:grid md:grid-cols-[minmax(15.5rem,1fr)_minmax(0,1fr)_minmax(8.5rem,auto)_6.5rem] md:items-start md:gap-3 ' +
  'xl:grid-cols-[minmax(16rem,24rem)_minmax(0,1fr)_minmax(9rem,auto)_6rem_6.5rem]';
const SELECT_CLASS = 'h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body sm:w-auto sm:max-w-56';

type LoginChoice = TelnetLoginFilter | 'all';

/** Telnet view (docs/specs/telnet.md): figures, sessions and their transcripts. */
export default function TelnetView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const { session, viewable, oneDay } = useViewableSession(sessionId);
  const stats = useTelnetStats(sessionId, viewable);
  const ranged = useViewRange() !== null;

  const s = stats.data;
  let content: ReactNode;
  if (stats.isError)
    content = (
      <Card>
        <ErrorState
          message={t('views.telnet.loadError')}
          onRetry={() => {
            void stats.refetch();
          }}
        />
      </Card>
    );
  else if (s === undefined)
    content = (
      <div className="flex flex-col gap-4" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        <Skeleton height={88} />
        <Skeleton height={240} />
      </div>
    );
  else if (s.sessions === 0)
    content = (
      <Card>
        <EmptyState icon={SquareTerminal} title={ranged ? t('timeRange.emptyTitle') : t('views.telnet.empty')} />
      </Card>
    );
  else
    content = (
      <>
        <StatBand stats={s} />
        <SessionsCard sessionId={sessionId} enabled={viewable} oneDay={oneDay} ranged={ranged} />
      </>
    );

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.telnet')}
        subtitle={session.data?.name ?? t('views.telnet.subtitle')}
        {...(s === undefined ? {} : { count: <Badge>{formatCount(s.sessions)}</Badge> })}
      />
      <SessionGate session={session}>{content}</SessionGate>
    </div>
  );
}

function StatBand({ stats }: { stats: TelnetStats }) {
  const { t } = useTranslation();
  return (
    <section
      aria-label={t('views.telnet.stat.label')}
      data-testid="telnet-summary"
      className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5"
    >
      <StatCard icon={SquareTerminal} label={t('views.telnet.stat.sessions')} value={formatCount(stats.sessions)} hint=" " />
      <StatCard icon={Monitor} label={t('views.telnet.stat.clients')} value={formatCount(stats.clients)} hint=" " />
      <StatCard icon={Server} label={t('views.telnet.stat.servers')} value={formatCount(stats.servers)} hint=" " />
      <StatCard
        icon={KeyRound}
        label={t('views.telnet.stat.logins')}
        value={formatCount(stats.logins)}
        hint={`${t('views.telnet.stat.accepted', { count: stats.accepted })}, ${t('views.telnet.stat.rejected', { count: stats.rejected })}`}
      />
      <StatCard
        icon={Scissors}
        label={t('views.telnet.stat.truncated')}
        value={formatCount(stats.truncated)}
        hint={stats.truncated > 0 ? t('views.telnet.stat.truncatedHint') : ' '}
      />
    </section>
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

interface SessionsCardProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
  ranged: boolean;
}

function SessionsCard({ sessionId, enabled, oneDay, ranged }: SessionsCardProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [login, setLogin] = useState<LoginChoice>('all');
  const params = useMemo<TelnetSessionParams>(() => {
    const p: TelnetSessionParams = {};
    if (q !== '') p.q = q;
    if (login !== 'all') p.login = login;
    return p;
  }, [q, login]);
  const query = useTelnetSessions(sessionId, params, enabled);
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
        message={t('views.telnet.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  else if (items.length === 0) body = <EmptyState title={t('views.telnet.sessions.noMatch')} />;
  else
    body = (
      <ExpandableList
        items={items}
        getKey={(s) => s.flow_id}
        ariaLabel={t('views.telnet.sessions.label')}
        header={<SessionHeader ranged={ranged} />}
        renderRow={(s) => <SessionRow session={s} oneDay={oneDay} ranged={ranged} />}
        renderDetail={(s) => <SessionDetail sessionId={sessionId} session={s} />}
        rowLabel={(s) =>
          t('views.telnet.sessions.rowLabel', {
            client: s.client.ip,
            server: s.server.ip,
            time: formatTimestamp(s.first_ts_us, !oneDay),
          })
        }
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    );

  return (
    <Card
      title={t('views.telnet.sessions.title')}
      flush
      {...(total === null ? {} : { actions: <span className="num text-meta text-muted">{formatCount(total)}</span> })}
      filters={
        <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={t('views.telnet.sessions.search')} />
          <LoginSelect value={login} onChange={setLogin} />
        </div>
      }
    >
      {body}
    </Card>
  );
}

function LoginSelect({ value, onChange }: { value: LoginChoice; onChange: (v: LoginChoice) => void }) {
  const { t } = useTranslation();
  const id = useId();
  return (
    <>
      <label htmlFor={id} className="sr-only">
        {t('views.telnet.sessions.loginLabel')}
      </label>
      <select
        id={id}
        value={value}
        onChange={(e) => {
          onChange(e.target.value as LoginChoice);
        }}
        className={SELECT_CLASS}
      >
        {(['all', ...TELNET_LOGINS] as const).map((v) => (
          <option key={v} value={v}>
            {t(`views.telnet.sessions.logins.${v}`)}
          </option>
        ))}
      </select>
    </>
  );
}

function SessionHeader({ ranged }: { ranged: boolean }) {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={SESSION_GRID}>
        <span>{t('views.telnet.sessions.col.endpoints')}</span>
        <span>{t('views.telnet.sessions.col.user')}</span>
        <span>{t('views.telnet.sessions.col.start')}</span>
        <span className="hidden text-right xl:block">
          <WholeSessionHeader label={t('views.telnet.sessions.col.duration')} ranged={ranged} />
        </span>
        <span className="text-right">
          <WholeSessionHeader label={t('views.telnet.sessions.col.bytes')} ranged={ranged} />
        </span>
      </div>
    </div>
  );
}

function StatusBadges({ session: s }: { session: TelnetSessionInfo }) {
  const { t } = useTranslation();
  return (
    <>
      {s.login === 'rejected' && <Badge tone="warning">{t('views.telnet.sessions.badge.rejected')}</Badge>}
      {s.login === 'accepted' && <Badge tone="success">{t('views.telnet.sessions.badge.accepted')}</Badge>}
      {s.truncated && <Badge>{t('views.telnet.sessions.badge.truncated')}</Badge>}
    </>
  );
}

function SessionRow({ session: s, oneDay, ranged }: { session: TelnetSessionInfo; oneDay: boolean; ranged: boolean }) {
  const { t } = useTranslation();
  const bytes = formatBytes(s.client_bytes + s.server_bytes);
  const bytesTitle = t('views.telnet.sessions.bytesTitle', { client: formatBytes(s.client_bytes), server: formatBytes(s.server_bytes) });
  const duration = formatSpan(s.first_ts_us, s.last_ts_us);
  const user = s.username ?? t('views.telnet.sessions.unknownUser');
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${SESSION_GRID}`}>
      <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 text-meta">
        <span className="min-w-0 max-w-full">
          <Endpoint endpoint={s.client} show="address" className="text-meta" />
        </span>
        <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint" />
        <span className="min-w-0 max-w-full">
          <Endpoint endpoint={s.server} port={s.server_port} show="address" className="text-meta" />
        </span>
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-1.5">
        <span data-testid="truncatable" title={user} className={`min-w-0 truncate ${s.username === null ? 'text-muted italic' : 'font-medium'}`}>
          {user}
        </span>
        <StatusBadges session={s} />
      </span>
      {/* Narrow screens: start, then duration and bytes (folded: whole session under a range). */}
      <span className="flex min-w-0 flex-wrap items-center gap-x-2 text-meta text-muted md:hidden">
        <Timestamp us={s.first_ts_us} withDate={!oneDay} />
        <span className="num" title={bytesTitle}>
          {ranged ? t('timeRange.wholeSessionColumn', { label: `${duration}, ${bytes}` }) : `${duration}, ${bytes}`}
        </span>
      </span>
      <Timestamp us={s.first_ts_us} withDate={!oneDay} className="hidden text-meta text-muted md:block" />
      <span className="num hidden text-right text-meta text-muted xl:block">{duration}</span>
      <span className="num hidden text-right md:block" title={bytesTitle}>
        {bytes}
      </span>
    </span>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-meta text-muted">{label}</dt>
      <dd className="min-w-0 text-meta">{children}</dd>
    </div>
  );
}

function SessionDetail({ sessionId, session: s }: { sessionId: string; session: TelnetSessionInfo }) {
  const { t } = useTranslation();
  const detail = useTelnetSession(sessionId, s.flow_id, true);
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <dl className="grid min-w-0 gap-3 [grid-template-columns:repeat(auto-fill,minmax(min(100%,9rem),1fr))]">
        {s.terminal !== null && (
          <Field label={t('views.telnet.detail.terminal')}>
            <span className="block font-mono break-all">{s.terminal}</span>
          </Field>
        )}
        {s.window !== null && (
          <Field label={t('views.telnet.detail.window')}>
            <span className="num">{t('views.telnet.detail.windowSize', { cols: s.window.cols, rows: s.window.rows })}</span>
          </Field>
        )}
        {s.env_user !== null && (
          <Field label={t('views.telnet.detail.envUser')}>
            <span className="block break-all">{s.env_user}</span>
          </Field>
        )}
        <Field label={t('views.telnet.detail.traffic')}>
          <span className="num">
            {t('views.telnet.detail.trafficValue', { client: formatBytes(s.client_bytes), server: formatBytes(s.server_bytes) })}
          </span>
        </Field>
        {s.login_attempts > 0 && (
          <Field label={t('views.telnet.stat.logins')}>
            <span className="num">{t('views.telnet.sessions.attempts', { count: s.login_attempts })}</span>
          </Field>
        )}
        {s.options.length > 0 && (
          <div className="flex min-w-0 flex-col gap-0.5 [grid-column:1/-1]">
            <dt className="text-meta text-muted">{t('views.telnet.detail.options')}</dt>
            <dd className="flex min-w-0 flex-wrap gap-1">
              {s.options.map((o) => (
                <Badge key={o} className="font-mono">
                  {o}
                </Badge>
              ))}
            </dd>
          </div>
        )}
      </dl>
      <div className="flex min-w-0 flex-col gap-1.5">
        <div className="flex max-w-[100ch] min-w-0 flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
          <span className="text-meta font-medium">{t('views.telnet.detail.transcript')}</span>
          <span className="min-w-0 text-meta text-faint">{t('views.telnet.detail.transcriptNote')}</span>
        </div>
        {detail.isPending ? (
          <Skeleton height={160} />
        ) : detail.isError ? (
          <ErrorState
            message={t('views.telnet.detail.loadError')}
            onRetry={() => {
              void detail.refetch();
            }}
          />
        ) : (
          <Transcript runs={detail.data.runs} />
        )}
        {s.truncated && <p className="text-meta text-warning">{t('views.telnet.detail.truncated')}</p>}
      </div>
    </div>
  );
}

/** The runs without the empty lines that open most sessions (banner line ends). */
function withoutLeadingBlankLines(runs: readonly TelnetRun[]): TelnetRun[] {
  const out = [...runs];
  while (out.length > 0) {
    const first = out[0] as TelnetRun;
    if (first.speaker === 'secret') break;
    const text = first.text.replace(/^(?:[ \t]*\n)+/, '');
    if (text === '') {
      out.shift();
      continue;
    }
    out[0] = { ...first, text };
    break;
  }
  return out;
}

/**
 * The transcript as text: React escapes every run, nothing from the capture is interpreted.
 * Wraps long lines (never scrolls horizontally) and is not a scroll container of its own: the
 * session list already scrolls (two levels at most with the page).
 */
function Transcript({ runs: all }: { runs: readonly TelnetRun[] }) {
  const { t } = useTranslation();
  const runs = withoutLeadingBlankLines(all);
  if (runs.length === 0) return <p className="text-meta text-muted">{t('views.telnet.detail.empty')}</p>;
  return (
    <div
      role="log"
      aria-label={t('views.telnet.detail.transcriptLabel')}
      data-testid="telnet-transcript"
      className="max-w-[100ch] min-w-0 rounded-md border border-line bg-surface p-3 font-mono text-meta leading-5 whitespace-pre-wrap [overflow-wrap:anywhere]"
    >
      {runs.map((r, i) =>
        r.speaker === 'secret' ? (
          <SecretValue key={i} value={r.text} label={t('views.telnet.detail.password')} className="ml-1 align-middle font-sans" />
        ) : (
          <span key={i} className={r.speaker === 'client' ? 'text-accent' : undefined}>
            {r.text}
          </span>
        ),
      )}
    </div>
  );
}
