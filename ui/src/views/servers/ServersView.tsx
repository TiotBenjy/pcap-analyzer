import { getRouteApi } from '@tanstack/react-router';
import type { LucideIcon } from 'lucide-react';
import { ArrowLeftRight, BookUser, ChevronRight, Clock, FolderTree, Globe, Router, Server, Ticket } from 'lucide-react';
import { Fragment, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useServers } from '../../api/serverQueries';
import { useSession } from '../../api/sessionQueries';
import type { AddressCategory } from '../../api/types/AddressCategory';
import type { RoleServer } from '../../api/types/RoleServer';
import type { RoleServers } from '../../api/types/RoleServers';
import type { ServerEvidence } from '../../api/types/ServerEvidence';
import type { ServerRole } from '../../api/types/ServerRole';
import { ADDRESS_CATEGORY_ORDER } from '../../charts/palette';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { MultiSelect } from '../../components/MultiSelect';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { cn } from '../../lib/cn';
import { formatCount, formatTimestamp } from '../../lib/format';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { isViewable } from '../connections/session';
import { SessionGate } from '../connections/SessionGate';
import { CopyButton } from '../tls/parts';

const route = getRouteApi('/sessions/$sessionId');

const MD_QUERY = '(min-width: 768px)';

const ROLE_ICONS: Record<ServerRole, LucideIcon> = {
  dns: Globe,
  dhcp: Router,
  ldap: BookUser,
  ntp: Clock,
  kerberos: Ticket,
  smb: FolderTree,
  http: ArrowLeftRight,
};

/** DOM id of the card of a role (the role badges scroll to it). */
const cardId = (role: ServerRole) => `servers-role-${role}`;

/** Roles played by each address, over every role of the response. */
function rolesByAddress(roles: readonly RoleServers[]): Map<string, ServerRole[]> {
  const out = new Map<string, ServerRole[]>();
  for (const r of roles)
    for (const s of r.servers) {
      const list = out.get(s.endpoint.ip) ?? [];
      list.push(r.role);
      out.set(s.endpoint.ip, list);
    }
  return out;
}

/** Servers view: hosts playing an infrastructure role, one card per role, with their evidence. */
export default function ServersView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const viewable = isViewable(session.data);
  const [categories, setCategories] = useState<ReadonlySet<AddressCategory>>(() => new Set(ADDRESS_CATEGORY_ORDER));
  const allCategories = categories.size === ADDRESS_CATEGORY_ORDER.length;
  const filters = useMemo(
    () => (allCategories ? {} : { categories: ADDRESS_CATEGORY_ORDER.filter((c) => categories.has(c)) }),
    [allCategories, categories],
  );
  const query = useServers(sessionId, filters, viewable);
  const data = query.data;
  const total = data === undefined ? null : data.roles.reduce((n, r) => n + r.total, 0);

  const categoryOptions = ADDRESS_CATEGORY_ORDER.map((c) => ({ value: c, label: t(`addressCategories.${c}`) }));
  const roleLabels = Object.fromEntries(
    (Object.keys(ROLE_ICONS) as ServerRole[]).map((r) => [r, t(`views.servers.roles.${r}`)]),
  ) as Record<ServerRole, string>;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.servers')}
        subtitle={session.data?.name ?? t('views.servers.subtitle')}
        {...(total === null || data?.analyzed !== true ? {} : { count: <Badge>{formatCount(total)}</Badge> })}
      />
      <SessionGate session={session}>
        <Card
          title={t('views.servers.rolesTitle')}
          actions={
            <MultiSelect
              label={t('views.servers.categories')}
              options={categoryOptions}
              selected={categories}
              onChange={setCategories}
              align="end"
            />
          }
        >
          {query.isPending ? (
            <div aria-busy="true" className="flex flex-wrap gap-2">
              <span className="sr-only">{t('common.loading')}</span>
              <Skeleton height={32} className="w-24" />
              <Skeleton height={32} className="w-24" />
              <Skeleton height={32} className="w-24" />
            </div>
          ) : query.isError || data === undefined ? (
            <ErrorState message={t('views.servers.loadError')} onRetry={() => void query.refetch()} />
          ) : !data.analyzed ? (
            <EmptyState icon={Server} title={t('views.servers.notRunTitle')} description={t('views.servers.notRunText')} />
          ) : (
            <RoleBadges roles={data.roles} labels={roleLabels} />
          )}
        </Card>
        {data?.analyzed === true && <RoleGrid roles={data.roles} labels={roleLabels} />}
      </SessionGate>
    </div>
  );
}

function RoleBadges({ roles, labels }: { roles: readonly RoleServers[]; labels: Record<ServerRole, string> }) {
  const { t } = useTranslation();
  return (
    <ul aria-label={t('views.servers.rolesLabel')} className="flex flex-wrap gap-2">
        {roles.map((r) => {
          const Icon = ROLE_ICONS[r.role];
          return (
            <li key={r.role}>
              <button
                type="button"
                onClick={() => document.getElementById(cardId(r.role))?.scrollIntoView({ block: 'start' })}
                className={cn(
                  'inline-flex h-8 items-center gap-1.5 rounded-md border border-line px-2.5 text-meta hover:bg-subtle',
                  r.total === 0 && 'text-faint',
                )}
              >
                <Icon aria-hidden size={16} strokeWidth={1.75} className="shrink-0" />
                <span className="font-medium">{labels[r.role]}</span>
                <span className="num text-muted">{formatCount(r.total)}</span>
              </button>
            </li>
          );
        })}
    </ul>
  );
}

/** Roles with servers first (full width), then the empty ones in a grid of small cards. */
function RoleGrid({ roles, labels }: { roles: readonly RoleServers[]; labels: Record<ServerRole, string> }) {
  const byAddress = useMemo(() => rolesByAddress(roles), [roles]);
  const ordered = [...roles.filter((r) => r.total > 0), ...roles.filter((r) => r.total === 0)];
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      {ordered.map((r) => (
        <RoleCard key={r.role} role={r} labels={labels} byAddress={byAddress} />
      ))}
    </div>
  );
}

function RoleCard({
  role,
  labels,
  byAddress,
}: {
  role: RoleServers;
  labels: Record<ServerRole, string>;
  byAddress: ReadonlyMap<string, ServerRole[]>;
}) {
  const { t } = useTranslation();
  const wide = useMediaQuery(MD_QUERY);
  const Icon = ROLE_ICONS[role.role];
  const label = labels[role.role];
  const empty = role.total === 0;
  const title = (
    <span className="flex min-w-0 items-center gap-2">
      <Icon aria-hidden size={16} strokeWidth={1.75} className="shrink-0 text-muted" />
      <span className="truncate">{label}</span>
    </span>
  );
  const counter = empty ? undefined : (
    <span className="flex flex-wrap items-center gap-2 text-meta text-muted">
      {role.servers.length < role.total && (
        <span>{t('views.servers.shown', { shown: formatCount(role.servers.length), total: formatCount(role.total) })}</span>
      )}
      <Badge>{t('views.servers.serverCount', { count: role.total })}</Badge>
    </span>
  );
  return (
    <div id={cardId(role.role)} className={cn('min-w-0 scroll-mt-4', !empty && 'col-span-full')}>
      <Card title={title} {...(counter === undefined ? {} : { actions: counter })} flush className="h-full">
        {empty ? (
          <EmptyState icon={Icon} title={t('views.servers.empty', { role: label })} />
        ) : wide ? (
          <ServerTable role={role} labels={labels} byAddress={byAddress} />
        ) : (
          <ServerCards role={role} labels={labels} byAddress={byAddress} />
        )}
      </Card>
    </div>
  );
}

interface ServerListProps {
  role: RoleServers;
  labels: Record<ServerRole, string>;
  byAddress: ReadonlyMap<string, ServerRole[]>;
}

function useExpanded() {
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const toggle = (ip: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  };
  return [open, toggle] as const;
}

/** Name or address of a server, for accessible labels. */
const serverName = (s: RoleServer) => s.endpoint.names[0] ?? s.endpoint.ip;

function ExpandButton({ server, expanded, controls, onToggle }: { server: RoleServer; expanded: boolean; controls: string; onToggle: () => void }) {
  const { t } = useTranslation();
  return (
    <button
      type="button"
      aria-expanded={expanded}
      aria-controls={expanded ? controls : undefined}
      aria-label={t('views.servers.showEvidence', { server: serverName(server) })}
      onClick={onToggle}
      className="-my-1 inline-flex size-8 shrink-0 items-center justify-center rounded-md text-faint hover:bg-subtle hover:text-fg"
    >
      <ChevronRight aria-hidden size={16} strokeWidth={1.75} className={cn('transition-transform', expanded && 'rotate-90')} />
    </button>
  );
}

/** Server cell: endpoint (name first), its address below when a name is shown, copy button. */
function ServerCell({ server }: { server: RoleServer }) {
  const { t } = useTranslation();
  const named = server.endpoint.names.length > 0;
  return (
    <span className="flex min-w-0 items-center gap-1">
      <span className="flex min-w-0 flex-col">
        <Endpoint endpoint={server.endpoint} />
        {named && (
          <span data-testid="truncatable" title={server.endpoint.ip} className="truncate font-mono text-meta text-muted">
            {server.endpoint.ip}
          </span>
        )}
      </span>
      <CopyButton value={server.endpoint.ip} name={t('views.servers.address')} />
    </span>
  );
}

function OtherRoles({
  server,
  role,
  labels,
  byAddress,
  hideEmpty = false,
}: { server: RoleServer; hideEmpty?: boolean } & ServerListProps) {
  const { t } = useTranslation();
  const others = (byAddress.get(server.endpoint.ip) ?? []).filter((r) => r !== role.role);
  if (others.length === 0) return hideEmpty ? null : <span className="text-faint">-</span>;
  return (
    <span className="flex flex-wrap gap-1" title={t('views.servers.otherRoles')}>
      {others.map((r) => (
        <Badge key={r}>{labels[r]}</Badge>
      ))}
    </span>
  );
}

function EvidenceKinds({ server }: { server: RoleServer }) {
  const { t } = useTranslation();
  return (
    <span className="flex flex-wrap gap-1">
      {server.evidence.map((e, i) => (
        <Badge key={`${e.kind}-${i}`}>
          {t(`views.servers.kinds.${e.kind}`)}
          {e.kind === 'open_port' && e.example !== null ? ` ${e.example}` : ''}
        </Badge>
      ))}
    </span>
  );
}

function ServerTable({ role, labels, byAddress }: ServerListProps) {
  const { t } = useTranslation();
  const [open, toggle] = useExpanded();
  const baseId = useId();
  const label = labels[role.role];
  return (
    <div className="min-w-0 overflow-x-auto">
      <table aria-label={t('views.servers.listLabel', { role: label })} className="w-full table-fixed border-collapse text-table">
        <thead>
          <tr className="border-b border-line text-left text-meta text-muted">
            <th scope="col" className="w-11 px-2 py-2 font-medium">
              <span className="sr-only">{t('views.servers.evidence')}</span>
            </th>
            <th scope="col" className="w-[30%] px-3 py-2 font-medium">{t('views.servers.server')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('views.servers.evidence')}</th>
            <th scope="col" className="w-28 px-3 py-2 text-right font-medium">{t('views.servers.occurrences')}</th>
            <th scope="col" className="w-44 px-3 py-2 font-medium sm:pr-4">{t('views.servers.lastSeen')}</th>
          </tr>
        </thead>
        <tbody>
          {role.servers.map((s) => {
            const expanded = open.has(s.endpoint.ip);
            const detailId = `${baseId}-${s.endpoint.ip}`;
            return (
              <Fragment key={s.endpoint.ip}>
                <tr className="border-b border-line align-top last:border-b-0">
                  <td className="px-2 py-2">
                    <ExpandButton server={s} expanded={expanded} controls={detailId} onToggle={() => toggle(s.endpoint.ip)} />
                  </td>
                  <td className="px-3 py-2">
                    <span className="flex min-w-0 flex-col gap-1">
                      <ServerCell server={s} />
                      <OtherRoles server={s} role={role} labels={labels} byAddress={byAddress} hideEmpty />
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <EvidenceKinds server={s} />
                  </td>
                  <td className="num px-3 py-2 text-right">{formatCount(s.count)}</td>
                  <td className="num px-3 py-2 text-meta sm:pr-4">{formatTimestamp(s.last_ts_us)}</td>
                </tr>
                {expanded && (
                  <tr id={detailId} className="border-b border-line last:border-b-0">
                    <td colSpan={5} className="bg-app/40 px-3 py-3 sm:px-4">
                      <EvidenceTable server={s} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Example({ evidence }: { evidence: ServerEvidence }) {
  if (evidence.example === null) return <span className="text-faint">-</span>;
  return (
    <span data-testid="truncatable" title={evidence.example} className="block truncate font-mono text-meta">
      {evidence.example}
    </span>
  );
}

function EvidenceTable({ server }: { server: RoleServer }) {
  const { t } = useTranslation();
  return (
    <table aria-label={t('views.servers.evidenceLabel', { server: serverName(server) })} className="w-full table-fixed border-collapse text-table">
      <thead>
        <tr className="text-left text-meta text-muted">
          <th scope="col" className="w-[30%] py-1 pr-3 font-medium">{t('views.servers.evidence')}</th>
          <th scope="col" className="w-20 py-1 pr-3 text-right font-medium">{t('views.servers.count')}</th>
          <th scope="col" className="w-20 py-1 pr-3 text-right font-medium">{t('views.servers.clients')}</th>
          <th scope="col" className="hidden w-44 py-1 pr-3 font-medium lg:table-cell">{t('views.servers.firstSeen')}</th>
          <th scope="col" className="w-44 py-1 pr-3 font-medium">{t('views.servers.lastSeen')}</th>
          <th scope="col" className="py-1 font-medium">{t('views.servers.example')}</th>
        </tr>
      </thead>
      <tbody>
        {server.evidence.map((e, i) => (
          <tr key={`${e.kind}-${i}`} className="align-top">
            <td className="truncate py-1 pr-3" title={t(`views.servers.kinds.${e.kind}`)}>
              {t(`views.servers.kinds.${e.kind}`)}
            </td>
            <td className="num py-1 pr-3 text-right">{formatCount(e.count)}</td>
            <td className="num py-1 pr-3 text-right">{e.clients === null ? '-' : formatCount(e.clients)}</td>
            <td className="num hidden py-1 pr-3 text-meta lg:table-cell">{formatTimestamp(e.first_ts_us)}</td>
            <td className="num py-1 pr-3 text-meta">{formatTimestamp(e.last_ts_us)}</td>
            <td className="min-w-0 py-1">
              <Example evidence={e} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ServerCards({ role, labels, byAddress }: ServerListProps) {
  const { t } = useTranslation();
  const [open, toggle] = useExpanded();
  const baseId = useId();
  return (
    <ul aria-label={t('views.servers.listLabel', { role: labels[role.role] })} className="divide-y divide-line">
      {role.servers.map((s) => {
        const expanded = open.has(s.endpoint.ip);
        const detailId = `${baseId}-${s.endpoint.ip}`;
        return (
          <li key={s.endpoint.ip} className="flex min-w-0 flex-col gap-1.5 px-3 py-2.5">
            <div className="flex min-w-0 items-start gap-1">
              <ExpandButton server={s} expanded={expanded} controls={detailId} onToggle={() => toggle(s.endpoint.ip)} />
              <span className="min-w-0 flex-1">
                <ServerCell server={s} />
              </span>
              <span className="num shrink-0 pt-1 text-meta text-muted">{formatCount(s.count)}</span>
            </div>
            <EvidenceKinds server={s} />
            <OtherRoles server={s} role={role} labels={labels} byAddress={byAddress} hideEmpty />
            {expanded && (
              <ul id={detailId} aria-label={t('views.servers.evidenceLabel', { server: serverName(s) })} className="flex flex-col gap-2 pt-1">
                {s.evidence.map((e, i) => (
                  <li key={`${e.kind}-${i}`} className="flex min-w-0 flex-col gap-0.5 rounded-md border border-line bg-app px-2.5 py-2 text-meta">
                    <span className="flex min-w-0 items-center justify-between gap-2">
                      <span className="truncate font-medium" title={t(`views.servers.kinds.${e.kind}`)}>
                        {t(`views.servers.kinds.${e.kind}`)}
                      </span>
                      <span className="num shrink-0">{formatCount(e.count)}</span>
                    </span>
                    {e.clients !== null && (
                      <span className="text-muted">
                        {t('views.servers.clients')} <span className="num">{formatCount(e.clients)}</span>
                      </span>
                    )}
                    <span className="text-muted">
                      {t('views.servers.firstSeen')} <span className="num">{formatTimestamp(e.first_ts_us)}</span>
                    </span>
                    <span className="text-muted">
                      {t('views.servers.lastSeen')} <span className="num">{formatTimestamp(e.last_ts_us)}</span>
                    </span>
                    {e.example !== null && <Example evidence={e} />}
                  </li>
                ))}
              </ul>
            )}
          </li>
        );
      })}
    </ul>
  );
}
