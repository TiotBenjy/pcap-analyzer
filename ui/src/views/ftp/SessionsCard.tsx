import { Link } from '@tanstack/react-router';
import { ArrowRight, Upload } from 'lucide-react';
import { type ReactNode, useCallback, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { FTP_LOGINS, type FtpSessionParams } from '../../api/ftp';
import { useFtpSession, useFtpSessions } from '../../api/ftpQueries';
import type { FtpLogin } from '../../api/types/FtpLogin';
import type { FtpSessionInfo } from '../../api/types/FtpSessionInfo';
import { useViewRange } from '../../app/timeRange';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { ExpandableList } from '../../components/ExpandableList';
import { SearchInput } from '../../components/SearchInput';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { Timestamp } from '../../components/Timestamp';
import { WholeSessionHeader } from '../../components/WholeSession';
import { formatCount, formatDuration } from '../../lib/format';
import { useDebounced } from '../../lib/useDebounced';
import { Field, ListLoading } from './parts';
import { Transcript } from './Transcript';
import { TransferList } from './TransfersCard';

/**
 * Column layout of the session rows (wide screens), shared by the header and the rows. Counter
 * columns keep room for the "Whole session" line under a time range (docs/UI_GUIDELINES.md).
 */
const SESSION_GRID =
  'md:grid md:grid-cols-[minmax(0,2fr)_minmax(0,1.2fr)_112px_112px] md:items-center md:gap-3 ' +
  'xl:grid-cols-[minmax(0,2fr)_minmax(0,1.2fr)_112px_112px_112px_minmax(9rem,0.9fr)]';
const SELECT_CLASS = 'h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body';

type LoginFilter = FtpLogin | 'all';

interface SessionsCardProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
}

/** Control sessions, each expanding on its transcript and transfers. */
export function SessionsCard({ sessionId, enabled, oneDay }: SessionsCardProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [login, setLogin] = useState<LoginFilter>('all');
  const params = useMemo<FtpSessionParams>(() => {
    const p: FtpSessionParams = {};
    if (q !== '') p.q = q;
    if (login !== 'all') p.login = login;
    return p;
  }, [q, login]);
  const query = useFtpSessions(sessionId, params, enabled);
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total_estimate ?? null;
  const loadMore = useCallback(() => {
    void query.fetchNextPage();
  }, [query]);
  // Sessions are folded rows: under a range, their counters stay those of the whole session.
  const ranged = useViewRange() !== null;

  let body: ReactNode;
  if (query.isPending) body = <ListLoading />;
  else if (query.isError)
    body = (
      <ErrorState
        message={t('views.ftp.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  else if (items.length === 0)
    body =
      q === '' && login === 'all' ? <EmptyState icon={Upload} title={t('views.ftp.empty')} /> : <EmptyState title={t('views.ftp.sessions.noMatch')} />;
  else
    body = (
      <ExpandableList
        items={items}
        getKey={(s) => s.flow_id}
        ariaLabel={t('views.ftp.sessions.label')}
        header={<SessionHeader ranged={ranged} />}
        renderRow={(s) => <SessionRow session={s} oneDay={oneDay} ranged={ranged} />}
        renderDetail={(s) => <SessionDetail sessionId={sessionId} session={s} oneDay={oneDay} />}
        rowLabel={(s) => t('views.ftp.sessions.rowLabel', { client: s.client.ip, server: s.server.ip })}
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    );

  return (
    <Card
      title={t('views.ftp.sessions.title')}
      flush
      {...(total === null ? {} : { actions: <span className="num text-meta text-muted">{formatCount(total)}</span> })}
      filters={
        <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={t('views.ftp.sessions.search')} />
          <LoginControl value={login} onChange={setLogin} />
        </div>
      }
    >
      {body}
    </Card>
  );
}

/** Login filter: a segmented control from `sm`, a list below (four choices do not fit 375 px). */
function LoginControl({ value, onChange }: { value: LoginFilter; onChange: (v: LoginFilter) => void }) {
  const { t } = useTranslation();
  const id = useId();
  const options = (['all', ...FTP_LOGINS] as const).map((k) => ({ value: k, label: t(`views.ftp.sessions.login.${k}`) }));
  return (
    <>
      <div className="hidden sm:block">
        <SegmentedControl hideLabel label={t('views.ftp.sessions.login.label')} value={value} options={options} onChange={onChange} />
      </div>
      <div className="w-full sm:hidden">
        <label htmlFor={id} className="sr-only">
          {t('views.ftp.sessions.login.label')}
        </label>
        <select
          id={id}
          value={value}
          onChange={(e) => {
            onChange(e.target.value as LoginFilter);
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

function SessionHeader({ ranged }: { ranged: boolean }) {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={SESSION_GRID}>
        <span>{t('views.ftp.sessions.col.session')}</span>
        <span>{t('views.ftp.sessions.col.user')}</span>
        <span className="text-right">
          <WholeSessionHeader label={t('views.ftp.sessions.col.commands')} ranged={ranged} />
        </span>
        <span className="text-right">
          <WholeSessionHeader label={t('views.ftp.sessions.col.files')} ranged={ranged} />
        </span>
        <span className="hidden text-right xl:block">
          <WholeSessionHeader label={t('views.ftp.sessions.col.duration')} ranged={ranged} />
        </span>
        <span className="hidden xl:block">{t('views.ftp.sessions.col.start')}</span>
      </div>
    </div>
  );
}

function LoginBadges({ session: s }: { session: FtpSessionInfo }) {
  const { t } = useTranslation();
  return (
    <>
      {s.login === 'accepted' && <Badge tone="success">{t('views.ftp.sessions.badge.accepted')}</Badge>}
      {s.login === 'rejected' && <Badge tone="danger">{t('views.ftp.sessions.badge.rejected')}</Badge>}
      {s.tls && <Badge tone="accent">{t('views.ftp.sessions.badge.tls')}</Badge>}
    </>
  );
}

function duration(s: FtpSessionInfo): number {
  return Math.max(0, s.last_ts_us - s.first_ts_us) / 1e6;
}

function SessionRow({ session: s, oneDay, ranged }: { session: FtpSessionInfo; oneDay: boolean; ranged: boolean }) {
  const { t } = useTranslation();
  const user = s.username ?? t('views.ftp.sessions.noUser');
  const counts = `${t('views.ftp.sessions.commands', { count: s.commands })}, ${t('views.ftp.sessions.files', { count: s.files })}`;
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${SESSION_GRID}`}>
      <span className="flex min-w-0 items-center gap-1.5 text-meta">
        <span className="min-w-0 shrink">
          <Endpoint endpoint={s.client} show="address" className="text-meta" />
        </span>
        <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint" />
        <span className="min-w-0 shrink">
          <Endpoint endpoint={s.server} port={s.server_port} show="address" className="text-meta" />
        </span>
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-1.5">
        <span data-testid="truncatable" title={user} className={`min-w-0 truncate ${s.username === null ? 'text-muted' : 'font-medium'}`}>
          {user}
        </span>
        <LoginBadges session={s} />
      </span>
      {/* Narrow screens: counters and start on their own line. */}
      <span className="flex min-w-0 flex-wrap items-center justify-between gap-x-3 gap-y-1 text-meta text-muted md:hidden">
        <span className="num">{ranged ? t('timeRange.wholeSessionColumn', { label: counts }) : counts}</span>
        <Timestamp us={s.first_ts_us} withDate={!oneDay} />
      </span>
      <span className="num hidden text-right md:block">{formatCount(s.commands)}</span>
      <span className="num hidden text-right md:block">{formatCount(s.files)}</span>
      <span className="num hidden text-right text-meta text-muted xl:block">{formatDuration(duration(s))}</span>
      <Timestamp us={s.first_ts_us} withDate={!oneDay} className="hidden text-meta text-muted xl:block" />
    </span>
  );
}

function SessionDetail({ sessionId, session: s, oneDay }: { sessionId: string; session: FtpSessionInfo; oneDay: boolean }) {
  const { t } = useTranslation();
  const detail = useFtpSession(sessionId, s.flow_id, true);
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <dl className="flex min-w-0 flex-col gap-2">
        <Field label={t('views.ftp.sessions.col.session')}>
          <span className="flex min-w-0 flex-wrap items-center gap-1.5">
            <Endpoint endpoint={s.client} port={s.client_port} show="both" copy />
            <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint" />
            <Endpoint endpoint={s.server} port={s.server_port} show="both" copy />
          </span>
        </Field>
        {s.banner !== null && (
          <Field label={t('views.ftp.detail.banner')}>
            <span className="block font-mono text-meta [overflow-wrap:anywhere]">{s.banner}</span>
          </Field>
        )}
        <Field label={t('views.ftp.detail.user')}>
          <span className="flex min-w-0 flex-wrap items-center gap-2">
            <span className={`min-w-0 [overflow-wrap:anywhere] ${s.username === null ? 'text-muted' : ''}`}>
              {s.username ?? t('views.ftp.sessions.noUser')}
            </span>
            <LoginBadges session={s} />
            {s.username !== null && (
              <Link to="/sessions/$sessionId/credentials" params={{ sessionId }} className="shrink-0 text-meta font-medium text-accent hover:underline">
                {t('views.ftp.detail.credentials')}
              </Link>
            )}
          </span>
        </Field>
        <Field label={t('views.ftp.sessions.col.start')}>
          <Timestamp us={s.first_ts_us} withDate={!oneDay} className="text-meta" />
          <span className="num text-meta text-muted">{`, ${formatDuration(duration(s))}`}</span>
        </Field>
      </dl>
      <h3 className="text-meta font-medium text-muted">{t('views.ftp.detail.transcript')}</h3>
      {detail.isPending && (
        <div aria-busy="true">
          <span className="sr-only">{t('views.ftp.detail.loading')}</span>
          <Skeleton height={96} />
        </div>
      )}
      {detail.isError && (
        <ErrorState
          message={t('views.ftp.detail.error')}
          onRetry={() => {
            void detail.refetch();
          }}
        />
      )}
      {detail.data !== undefined && (
        <>
          <Transcript lines={detail.data.lines} truncated={s.transcript_truncated} />
          {detail.data.transfers.length > 0 && (
            <>
              <h3 className="text-meta font-medium text-muted">{t('views.ftp.detail.transfers')}</h3>
              <div className="rounded-md border border-line">
                <TransferList sessionId={sessionId} items={detail.data.transfers} oneDay={oneDay} compact />
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
