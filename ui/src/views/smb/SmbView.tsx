import { getRouteApi, Link } from '@tanstack/react-router';
import type { EChartsCoreOption } from 'echarts/core';
import { FolderTree, KeyRound } from 'lucide-react';
import { type ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { NAV_ITEMS } from '../../app/nav';
import { useSession } from '../../api/sessionQueries';
import { useSmbAnnounces, useSmbAuth, useSmbStats } from '../../api/smbQueries';
import type { SmbAnnounceInfo } from '../../api/types/SmbAnnounceInfo';
import type { SmbAuthInfo } from '../../api/types/SmbAuthInfo';
import type { SmbStats } from '../../api/types/SmbStats';
import { CATEGORICAL } from '../../charts/palette';
import { CHART_HEIGHT } from '../../charts/sizes';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { Chart } from '../../components/Chart';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { PageHeader } from '../../components/PageHeader';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import type { en } from '../../i18n/en';
import { formatCount } from '../../lib/format';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { isViewable } from '../connections/session';
import { SessionGate } from '../connections/SessionGate';

const route = getRouteApi('/sessions/$sessionId');

type Tab = 'announces' | 'auth';
type Smb = (typeof en)['views']['smb'];
type TokenKey<G extends 'roles' | 'kind' | 'signingState' | 'phase'> = `views.smb.${G}.${keyof Smb[G] & string}`;

/** Key of a stable backend token (role, kind, signing, phase) under `views.smb`. */
function tokenKey<G extends 'roles' | 'kind' | 'signingState' | 'phase'>(group: G, value: string): TokenKey<G> {
  return `views.smb.${group}.${value}` as TokenKey<G>;
}

/** Reads the `tab` query parameter from the hash location (`#/.../smb?tab=auth`). */
function initialTab(): string | null {
  if (typeof window === 'undefined') return null;
  const query = window.location.hash.split('?')[1] ?? '';
  return new URLSearchParams(query).get('tab');
}

const MD_QUERY = '(min-width: 768px)';
/** Container width from which the OS legend sits beside the donut instead of below it. */
const LEGEND_SIDE_MIN_WIDTH = 1024;
/** The Credentials view is navigable only once implemented (task P3.7). */
const CREDENTIALS_ENABLED = NAV_ITEMS.some((i) => i.id === 'credentials' && i.enabled);

/** Width of an element followed with a ResizeObserver (0 before layout). */
function useElementWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (el === null) return;
    const ro = new ResizeObserver((entries) => setWidth(Math.round(entries[0]?.contentRect.width ?? 0)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

/** SMB view: announced-OS donut, host announcements and NTLM authentication sessions. */
export default function SmbView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const viewable = isViewable(session.data);

  const stats = useSmbStats(sessionId, viewable);
  const announces = useSmbAnnounces(sessionId, viewable);
  const auth = useSmbAuth(sessionId, viewable);
  // The active tab is addressable (`?tab=auth`) so it can be linked to and captured.
  const [tab, setTab] = useState<Tab>(() => (initialTab() === 'auth' ? 'auth' : 'announces'));

  const total = stats.data === undefined ? null : stats.data.announce_count + stats.data.session_count;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.smb')}
        subtitle={session.data?.name ?? t('views.smb.subtitle')}
        {...(total === null ? {} : { count: <Badge>{formatCount(total)}</Badge> })}
      />
      <SessionGate session={session}>
        <Card title={t('views.smb.osTitle')}>
          <OsChart query={stats} />
        </Card>
        <div className="flex flex-col gap-3">
          <div className="min-w-0 overflow-x-auto">
            <SegmentedControl
              hideLabel
              label={t('nav.items.smb')}
              value={tab}
              options={[
                { value: 'announces', label: `${t('views.smb.tabs.announces')} (${formatCount(stats.data?.announce_count ?? 0)})` },
                { value: 'auth', label: `${t('views.smb.tabs.auth')} (${formatCount(stats.data?.auth_count ?? 0)})` },
              ]}
              onChange={setTab}
            />
          </div>
          {tab === 'announces' ? (
            <Card flush>
              <AnnounceTable query={announces} />
            </Card>
          ) : (
            <AuthPanel query={auth} sessionId={sessionId} hasAuth={(stats.data?.auth_count ?? 0) > 0} />
          )}
        </div>
      </SessionGate>
    </div>
  );
}

interface Query<T> {
  isPending: boolean;
  isError: boolean;
  data: T | undefined;
  refetch: () => Promise<unknown>;
}
type ListQuery<T> = Query<{ items: T[]; truncated: boolean }>;

function OsChart({ query }: { query: Query<SmbStats> }) {
  const { t } = useTranslation();
  const data = query.data;
  const [boxRef, boxWidth] = useElementWidth<HTMLDivElement>();
  const side = boxWidth >= LEGEND_SIDE_MIN_WIDTH;

  const option = useMemo<EChartsCoreOption>(
    () => ({
      tooltip: { trigger: 'item' },
      series: [
        {
          type: 'pie',
          radius: ['45%', '72%'],
          center: ['50%', '50%'],
          avoidLabelOverlap: true,
          label: { show: false },
          data: (data?.os ?? []).map((o, i) => ({
            name: o.label,
            value: Number(o.count),
            itemStyle: { color: CATEGORICAL[i % CATEGORICAL.length] },
          })),
        },
      ],
    }),
    [data],
  );

  const empty = data !== undefined && data.os.length === 0;
  return (
    <div ref={boxRef} className={`flex min-w-0 flex-col gap-4 ${side ? 'sm:flex-row sm:items-center' : ''}`}>
      <div className={`min-w-0 ${side ? 'sm:w-1/2' : ''}`}>
        <Chart
          option={option}
          height={CHART_HEIGHT.donut}
          ariaLabel={t('views.smb.osTitle')}
          loading={query.isPending}
          error={query.isError ? t('views.smb.loadError') : null}
          onRetry={() => void query.refetch()}
          empty={empty}
          emptyText={t('views.smb.osEmpty')}
        />
      </div>
      {!empty && (
        <ul className={`flex min-w-0 flex-col gap-2 ${side ? 'sm:w-1/2' : ''}`} data-testid="os-legend">
          {(data?.os ?? []).map((o, i) => (
            <li key={o.label} className="flex min-w-0 items-center gap-2">
              <span aria-hidden className="size-3 shrink-0 rounded-sm" style={{ backgroundColor: CATEGORICAL[i % CATEGORICAL.length] }} />
              <span className="min-w-0 flex-1 truncate" title={o.label}>
                {o.label}
              </span>
              <span className="num shrink-0 text-muted">{t('views.smb.osServers', { count: Number(o.count) })}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Block<T>({ query, children }: { query: ListQuery<T>; children: (items: T[]) => ReactNode }) {
  const { t } = useTranslation();
  if (query.isPending)
    return (
      <div className="flex flex-col gap-2 p-3 sm:p-4" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        <Skeleton height={32} />
        <Skeleton height={32} />
      </div>
    );
  if (query.isError || query.data === undefined)
    return <ErrorState message={t('views.smb.loadError')} onRetry={() => void query.refetch()} />;
  return <>{children(query.data.items)}</>;
}

function Roles({ roles }: { roles: readonly string[] }) {
  const { t } = useTranslation();
  if (roles.length === 0) return <span className="text-muted">-</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {roles.map((r) => (
        <Badge key={r} tone="neutral">
          {t(tokenKey('roles', r), { defaultValue: r })}
        </Badge>
      ))}
    </span>
  );
}

function Name({ announce }: { announce: SmbAnnounceInfo }) {
  const { t } = useTranslation();
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <span className="truncate font-mono text-meta">{announce.server_name}</span>
      <Badge tone="neutral">{t(tokenKey('kind', announce.kind), { defaultValue: announce.kind })}</Badge>
    </span>
  );
}

function AnnounceTable({ query }: { query: ListQuery<SmbAnnounceInfo> }) {
  const { t } = useTranslation();
  const wide = useMediaQuery(MD_QUERY);
  return (
    <Block query={query}>
      {(items) => {
        if (items.length === 0) return <EmptyState icon={FolderTree} title={t('views.smb.announce.empty')} />;
        if (!wide)
          return (
            <ul aria-label={t('views.smb.announce.label')} className="divide-y divide-line">
              {items.map((a) => (
                <li key={`${a.source.ip}-${a.server_name}-${a.dst_name}`} className="flex min-w-0 flex-col gap-1.5 px-3 py-2.5">
                  <div className="flex min-w-0 items-center justify-between gap-2">
                    <Name announce={a} />
                    <span className="num shrink-0 text-meta text-muted">{t('views.smb.announce.times', { count: Number(a.announce_count) })}</span>
                  </div>
                  <div className="flex min-w-0 items-center gap-1.5 text-meta text-muted">
                    <Endpoint endpoint={a.source} />
                    <span aria-hidden>→</span>
                    <span className="truncate font-mono">{a.dst_name}</span>
                  </div>
                  <span className="truncate" title={`${a.os_label} (${a.os_version})`}>{a.os_label}</span>
                  <Roles roles={a.roles} />
                  {a.comment !== '' && <span className="truncate text-meta text-muted" title={a.comment}>{a.comment}</span>}
                </li>
              ))}
            </ul>
          );
        return (
          <div className="min-w-0 overflow-x-auto">
            <table aria-label={t('views.smb.announce.label')} className="w-full table-fixed border-collapse text-table">
              <thead>
                <tr className="border-b border-line text-left text-meta text-muted">
                  <th scope="col" className="w-[16%] px-3 py-2 font-medium sm:px-4">{t('views.smb.announce.server')}</th>
                  <th scope="col" className="w-[15%] px-3 py-2 font-medium">{t('views.smb.announce.source')}</th>
                  <th scope="col" className="w-[13%] px-3 py-2 font-medium">{t('views.smb.announce.destination')}</th>
                  <th scope="col" className="w-[16%] px-3 py-2 font-medium">{t('views.smb.announce.os')}</th>
                  <th scope="col" className="px-3 py-2 font-medium">{t('views.smb.announce.roles')}</th>
                  <th scope="col" className="w-[14%] px-3 py-2 font-medium">{t('views.smb.announce.comment')}</th>
                  <th scope="col" className="w-20 px-3 py-2 text-right font-medium sm:pr-4">{t('views.smb.announce.count')}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={`${a.source.ip}-${a.server_name}-${a.dst_name}`} className="border-b border-line align-top last:border-b-0">
                    <td className="px-3 py-2 sm:px-4"><Name announce={a} /></td>
                    <td className="px-3 py-2"><Endpoint endpoint={a.source} /></td>
                    <td className="truncate px-3 py-2 font-mono text-meta" title={a.dst_name}>{a.dst_name}</td>
                    <td className="px-3 py-2"><span className="block truncate" title={`${a.os_label} (${a.os_version})`}>{a.os_label}</span></td>
                    <td className="px-3 py-2"><Roles roles={a.roles} /></td>
                    <td className="truncate px-3 py-2 text-muted" title={a.comment}>{a.comment}</td>
                    <td className="num px-3 py-2 text-right sm:pr-4">{formatCount(a.announce_count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      }}
    </Block>
  );
}

function Signing({ value }: { value: string }) {
  const { t } = useTranslation();
  return (
    <Badge tone={value === 'required' ? 'success' : 'neutral'}>{t(tokenKey('signingState', value), { defaultValue: value })}</Badge>
  );
}

function Phase({ value }: { value: string | null }) {
  const { t } = useTranslation();
  if (value === null) return <span className="text-muted">-</span>;
  return <Badge tone="warning">{t(tokenKey('phase', value), { defaultValue: value })}</Badge>;
}

function AuthPanel({ query, sessionId, hasAuth }: { query: ListQuery<SmbAuthInfo>; sessionId: string; hasAuth: boolean }) {
  const { t } = useTranslation();
  const wide = useMediaQuery(MD_QUERY);
  return (
    <div className="flex flex-col gap-2">
      {hasAuth && (
        <div role="note" className="flex min-w-0 items-start gap-2 rounded-lg border border-line bg-surface px-3 py-2 text-meta sm:px-4">
          <KeyRound aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-muted" />
          <p className="min-w-0 flex-1 text-muted">{t('views.smb.auth.note')}</p>
          {CREDENTIALS_ENABLED && (
            <Link to="/sessions/$sessionId/credentials" params={{ sessionId }} className="shrink-0 font-medium text-accent hover:underline">
              {t('views.smb.auth.toCredentials')}
            </Link>
          )}
        </div>
      )}
      <Card flush>
        <Block query={query}>
          {(items) => {
            if (items.length === 0) return <EmptyState icon={KeyRound} title={t('views.smb.auth.empty')} />;
            if (!wide)
              return (
                <ul aria-label={t('views.smb.auth.label')} className="divide-y divide-line">
                  {items.map((s) => (
                    <li key={s.flow_id} className="flex min-w-0 flex-col gap-1.5 px-3 py-2.5">
                      <div className="flex min-w-0 items-center gap-1.5">
                        <Endpoint endpoint={s.client} port={s.client_port} />
                        <span aria-hidden>→</span>
                        <Endpoint endpoint={s.server} port={s.server_port} />
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 text-meta">
                        <span className="text-muted">{s.dialect ?? s.protocol.toUpperCase()}</span>
                        <Signing value={s.signing} />
                        <Phase value={s.ntlm_phase} />
                      </div>
                      <span className="font-mono text-meta">
                        {[s.domain, s.account].filter((v) => v !== null && v !== '').join(' / ') || '-'}
                      </span>
                    </li>
                  ))}
                </ul>
              );
            return (
              <div className="min-w-0 overflow-x-auto">
                <table aria-label={t('views.smb.auth.label')} className="w-full table-fixed border-collapse text-table">
                  <thead>
                    <tr className="border-b border-line text-left text-meta text-muted">
                      <th scope="col" className="w-[18%] px-3 py-2 font-medium sm:px-4">{t('views.smb.auth.client')}</th>
                      <th scope="col" className="w-[18%] px-3 py-2 font-medium">{t('views.smb.auth.server')}</th>
                      <th scope="col" className="w-[12%] px-3 py-2 font-medium">{t('views.smb.auth.protocol')}</th>
                      <th scope="col" className="px-3 py-2 font-medium">{t('views.smb.auth.domain')}</th>
                      <th scope="col" className="px-3 py-2 font-medium">{t('views.smb.auth.account')}</th>
                      <th scope="col" className="w-[12%] px-3 py-2 font-medium">{t('views.smb.auth.signing')}</th>
                      <th scope="col" className="w-[12%] px-3 py-2 font-medium sm:pr-4">{t('views.smb.auth.phase')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((s) => (
                      <tr key={s.flow_id} className="border-b border-line align-top last:border-b-0">
                        <td className="px-3 py-2 sm:px-4"><Endpoint endpoint={s.client} port={s.client_port} /></td>
                        <td className="px-3 py-2"><Endpoint endpoint={s.server} port={s.server_port} /></td>
                        <td className="truncate px-3 py-2 text-meta" title={s.dialect ?? s.protocol}>{s.dialect ?? s.protocol.toUpperCase()}</td>
                        <td className="truncate px-3 py-2 font-mono text-meta" title={s.domain ?? ''}>{s.domain ?? ''}</td>
                        <td className="truncate px-3 py-2 font-mono text-meta" title={s.account ?? ''}>{s.account ?? ''}</td>
                        <td className="px-3 py-2"><Signing value={s.signing} /></td>
                        <td className="px-3 py-2 sm:pr-4"><Phase value={s.ntlm_phase} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          }}
        </Block>
      </Card>
    </div>
  );
}
