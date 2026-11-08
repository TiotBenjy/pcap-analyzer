import { useNavigate } from '@tanstack/react-router';
import type { ColumnDef } from '@tanstack/react-table';
import { Activity, ArrowRight, File, FolderOpen, Lock, Pencil, Trash2 } from 'lucide-react';
import { type ReactNode, useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useServerInfo } from '../../api/queries';
import { useSessions } from '../../api/sessionQueries';
import type { SessionSummary } from '../../api/types/SessionSummary';
import { isActive, openImportWizard, reopenImportProgress, trackImport, useImportState } from '../../app/importTracker';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { DataTable } from '../../components/DataTable';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { formatBytes, formatCount, formatPeriod, formatSpan, timeZoneLabel } from '../../lib/format';
import { LG_QUERY, useMediaQuery } from '../../lib/useMediaQuery';
import { DeleteDialog, RenameDialog } from './SessionDialogs';
import { SessionStateBadge } from './SessionStateBadge';

/** Below this width the table drops its Duration column (still in the period tooltip). */
const XXL_QUERY = '(min-width: 1536px)';

type PendingAction = { kind: 'rename' | 'delete'; session: SessionSummary } | null;

/** Sessions list and import entry points (docs/specs/captures.md). */
export default function CapturesView() {
  const { t } = useTranslation();
  const sessions = useSessions();
  const info = useServerInfo();
  const readOnly = info.data?.read_only === true;
  const [pending, setPending] = useState<PendingAction>(null);
  const onRename = useCallback((session: SessionSummary) => {
    setPending({ kind: 'rename', session });
  }, []);
  const onDelete = useCallback((session: SessionSummary) => {
    setPending({ kind: 'delete', session });
  }, []);

  const importButtons = (
    <>
      <Button
        variant="primary"
        disabled={readOnly}
        title={readOnly ? t('views.captures.readOnly') : undefined}
        onClick={() => {
          openImportWizard('folder');
        }}
      >
        <FolderOpen aria-hidden size={16} strokeWidth={1.75} />
        {t('views.captures.importFolder')}
      </Button>
      <Button
        disabled={readOnly}
        title={readOnly ? t('views.captures.readOnly') : undefined}
        onClick={() => {
          openImportWizard('file');
        }}
      >
        <File aria-hidden size={16} strokeWidth={1.75} />
        {t('views.captures.importFile')}
      </Button>
    </>
  );

  let body: ReactNode;
  if (sessions.isPending) {
    body = (
      <div className="flex flex-col gap-2 p-3 sm:p-4" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} height={32} />
        ))}
      </div>
    );
  } else if (sessions.isError) {
    body = (
      <ErrorState
        message={t('views.captures.loadError')}
        onRetry={() => {
          void sessions.refetch();
        }}
      />
    );
  } else if (sessions.data.length === 0) {
    body = (
      <EmptyState
        icon={FolderOpen}
        title={t('views.captures.emptyTitle')}
        description={t('views.captures.emptyText')}
        {...(readOnly ? {} : { action: <div className="flex flex-wrap justify-center gap-2">{importButtons}</div> })}
      />
    );
  } else {
    body = (
      <SessionList
        sessions={sessions.data}
        readOnly={readOnly}
        onRename={onRename}
        onDelete={onDelete}
      />
    );
  }

  const close = () => {
    setPending(null);
  };

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.captures')}
        subtitle={t('views.captures.subtitle')}
        {...(sessions.data === undefined ? {} : { count: <Badge>{formatCount(sessions.data.length)}</Badge> })}
        actions={importButtons}
      />
      {readOnly && (
        <p data-testid="read-only-note" className="-mt-2 flex min-w-0 items-start gap-1.5 text-meta text-muted">
          <Lock aria-hidden size={14} strokeWidth={1.75} className="mt-px shrink-0" />
          <span className="min-w-0">{t('views.captures.readOnly')}</span>
        </p>
      )}
      <Card
        flush
        title={t('views.captures.tableLabel')}
        actions={<span className="text-meta text-muted">{t('views.captures.timeZone', { tz: timeZoneLabel() })}</span>}
      >
        {body}
      </Card>
      {pending?.kind === 'rename' && <RenameDialog session={pending.session} onClose={close} />}
      {pending?.kind === 'delete' && <DeleteDialog session={pending.session} onClose={close} />}
    </div>
  );
}

interface ListProps {
  sessions: readonly SessionSummary[];
  /** Read-only server: mutating actions are disabled. */
  readOnly: boolean;
  onRename: (s: SessionSummary) => void;
  onDelete: (s: SessionSummary) => void;
}

function useOpenSession() {
  const navigate = useNavigate();
  return useCallback(
    (s: SessionSummary) => {
      void navigate({ to: '/sessions/$sessionId/overview', params: { sessionId: s.id } });
    },
    [navigate],
  );
}

/**
 * Table from 1024 px, stacked cards below (docs/specs/captures.md, "Responsive": cards under
 * 768 px at least; up to 1024 px the table would hide the anomalies and actions in a scroll).
 */
function SessionList(props: ListProps) {
  const wide = useMediaQuery(LG_QUERY);
  return wide ? <SessionTable {...props} /> : <SessionCards {...props} />;
}

function SessionTable({ sessions, readOnly, onRename, onDelete }: ListProps) {
  const { t } = useTranslation();
  const open = useOpenSession();
  // Keeps every column, actions included, visible at 1280 px with the sidebar open.
  const showDuration = useMediaQuery(XXL_QUERY);

  const columns = useMemo<ColumnDef<SessionSummary, unknown>[]>(
    () => [
      {
        id: 'name',
        accessorFn: (s) => s.name,
        header: t('views.captures.col.name'),
        size: 176,
        cell: ({ row }) => (
          <span data-testid="truncatable" title={row.original.name} className="block truncate font-medium">
            {row.original.name}
          </span>
        ),
      },
      {
        id: 'period',
        accessorFn: (s) => s.first_ts_us ?? Number.MAX_SAFE_INTEGER,
        header: t('views.captures.col.period'),
        size: 236,
        cell: ({ row }) => <Period session={row.original} />,
      },
      {
        id: 'duration',
        meta: { align: 'right' },
        accessorFn: (s) => (s.first_ts_us === null || s.last_ts_us === null ? -1 : s.last_ts_us - s.first_ts_us),
        header: t('views.captures.col.duration'),
        size: 96,
        cell: ({ row }) => <span className="num">{formatSpan(row.original.first_ts_us, row.original.last_ts_us)}</span>,
      },
      {
        id: 'size',
        meta: { align: 'right' },
        accessorFn: (s) => s.source_bytes,
        header: t('views.captures.col.size'),
        size: 84,
        cell: ({ row }) => <span className="num">{formatBytes(row.original.source_bytes)}</span>,
      },
      {
        id: 'packets',
        meta: { align: 'right' },
        accessorFn: (s) => s.packets,
        header: t('views.captures.col.packets'),
        size: 92,
        cell: ({ row }) => <span className="num">{formatCount(row.original.packets)}</span>,
      },
      {
        id: 'chunks',
        meta: { align: 'right' },
        accessorFn: (s) => s.chunk_count,
        header: t('views.captures.col.chunks'),
        size: 68,
        cell: ({ row }) => <span className="num">{formatCount(row.original.chunk_count)}</span>,
      },
      {
        id: 'state',
        accessorFn: (s) => s.state,
        header: t('views.captures.col.state'),
        size: 116,
        cell: ({ row }) => <SessionStateBadge state={row.original.state} detail={row.original.state_detail} />,
      },
      {
        id: 'anomalies',
        meta: { align: 'right' },
        accessorFn: (s) => s.anomaly_count,
        header: t('views.captures.col.anomalies'),
        size: 84,
        cell: ({ row }) => <AnomalyCount count={row.original.anomaly_count} />,
      },
      {
        id: 'actions',
        header: t('views.captures.col.actions'),
        enableSorting: false,
        size: 124,
        cell: ({ row }) => (
          <SessionActions
            session={row.original}
            readOnly={readOnly}
            onOpen={open}
            onRename={onRename}
            onDelete={onDelete}
          />
        ),
      },
    ],
    [t, open, readOnly, onRename, onDelete],
  );
  const visibleColumns = useMemo(
    () => (showDuration ? columns : columns.filter((c) => c.id !== 'duration')),
    [columns, showDuration],
  );

  return (
    <DataTable
      ariaLabel={t('views.captures.tableLabel')}
      columns={visibleColumns}
      data={sessions}
      getRowId={(s) => s.id}
      onRowClick={open}
    />
  );
}

function SessionCards({ sessions, readOnly, onRename, onDelete }: ListProps) {
  const { t } = useTranslation();
  const open = useOpenSession();
  return (
    <ul aria-label={t('views.captures.tableLabel')} className="divide-y divide-line">
      {sessions.map((s) => (
        <li key={s.id} className="flex min-w-0 flex-col gap-2 p-3">
          <div className="flex min-w-0 items-center gap-2">
            <button
              type="button"
              onClick={() => {
                open(s);
              }}
              data-testid="truncatable"
              title={s.name}
              className="min-w-0 flex-1 truncate text-left font-medium hover:text-accent"
            >
              {s.name}
            </button>
            <SessionStateBadge state={s.state} detail={s.state_detail} />
          </div>
          <Period session={s} />
          <dl className="grid grid-cols-[repeat(auto-fill,minmax(7.5rem,1fr))] gap-x-4 gap-y-1 text-table">
            <Field label={t('views.captures.col.duration')}>{formatSpan(s.first_ts_us, s.last_ts_us)}</Field>
            <Field label={t('views.captures.col.size')}>{formatBytes(s.source_bytes)}</Field>
            <Field label={t('views.captures.col.packets')}>{formatCount(s.packets)}</Field>
            <Field label={t('views.captures.col.chunks')}>{formatCount(s.chunk_count)}</Field>
            <Field label={t('views.captures.col.anomalies')}>
              <AnomalyCount count={s.anomaly_count} />
            </Field>
          </dl>
          <div className="flex justify-end">
            <SessionActions session={s} readOnly={readOnly} onOpen={open} onRename={onRename} onDelete={onDelete} />
          </div>
        </li>
      ))}
    </ul>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-meta text-muted">{label}</dt>
      <dd className="num truncate">{children}</dd>
    </div>
  );
}

function Period({ session }: { session: SessionSummary }) {
  const { t } = useTranslation();
  const text = formatPeriod(session.first_ts_us, session.last_ts_us);
  if (text === '') return <span className="text-muted">{t('views.captures.unknownPeriod')}</span>;
  const title = `${text} (${formatSpan(session.first_ts_us, session.last_ts_us)})`;
  return (
    <span data-testid="truncatable" title={title} className="num block truncate text-table">
      {text}
    </span>
  );
}

function AnomalyCount({ count }: { count: number }) {
  // `data-shot-visible`: the visual tests check that the counter is never clipped (768 px).
  return (
    <span data-shot-visible="anomaly-count" className="inline-flex">
      <Badge tone={count > 0 ? 'warning' : 'neutral'}>{formatCount(count)}</Badge>
    </span>
  );
}

interface ActionsProps {
  session: SessionSummary;
  readOnly: boolean;
  onOpen: (s: SessionSummary) => void;
  onRename: (s: SessionSummary) => void;
  onDelete: (s: SessionSummary) => void;
}

function SessionActions({ session, readOnly, onOpen, onRename, onDelete }: ActionsProps) {
  const { t } = useTranslation();
  const { current } = useImportState();
  const importing = session.state === 'importing';
  const name = session.name;
  const icon = { 'aria-hidden': true, size: 16, strokeWidth: 1.75 } as const;

  const showProgress = () => {
    // (Re)connect unless this import is already followed live (a lost stream reconnects).
    if (current?.sessionId !== session.id || !isActive(current)) trackImport(session.id, session.name);
    reopenImportProgress();
  };

  return (
    // Actions never trigger the row click (mouse or keyboard).
    <div
      className="flex items-center gap-0.5"
      onClick={(e) => {
        e.stopPropagation();
      }}
      onKeyDown={(e) => {
        e.stopPropagation();
      }}
    >
      {importing && (
        <Button
          variant="ghost"
          icon
          aria-label={t('views.captures.progress', { name })}
          title={t('views.captures.progress', { name })}
          onClick={showProgress}
        >
          <Activity {...icon} />
        </Button>
      )}
      <Button
        variant="ghost"
        icon
        aria-label={t('views.captures.open', { name })}
        title={t('views.captures.open', { name })}
        onClick={() => {
          onOpen(session);
        }}
      >
        <ArrowRight {...icon} />
      </Button>
      <Button
        variant="ghost"
        icon
        disabled={readOnly}
        aria-label={t('views.captures.rename', { name })}
        title={t('views.captures.rename', { name })}
        onClick={() => {
          onRename(session);
        }}
      >
        <Pencil {...icon} />
      </Button>
      {/* An import in progress cannot be deleted: its slot shows the progress action instead. */}
      {!importing && (
        <Button
          variant="ghost"
          icon
          disabled={readOnly}
          aria-label={t('views.captures.delete', { name })}
          title={t('views.captures.delete', { name })}
          onClick={() => {
            onDelete(session);
          }}
        >
          <Trash2 {...icon} />
        </Button>
      )}
    </div>
  );
}
