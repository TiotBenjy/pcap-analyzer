import { Download, Waypoints } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useConversationFlows, useSessionExports, useStartExport } from '../../api/exportQueries';
import { useServerInfo } from '../../api/queries';
import type { ConversationInfo } from '../../api/types/ConversationInfo';
import type { ExportJob } from '../../api/types/ExportJob';
import type { FlowInfo } from '../../api/types/FlowInfo';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Dialog } from '../../components/Dialog';
import { EmptyState } from '../../components/EmptyState';
import { ErrorNote } from '../../components/ErrorNote';
import { ErrorState } from '../../components/ErrorState';
import { Skeleton } from '../../components/Skeleton';
import { formatBytes, formatDuration, formatTimestamp } from '../../lib/format';
import { ExportStatus } from '../exports/ExportStatus';
import { Timestamp } from '../../components/Timestamp';

interface FlowsDialogProps {
  sessionId: string;
  /** Conversation whose flows are listed; `null` keeps the dialog closed. */
  conversation: ConversationInfo | null;
  onClose: () => void;
}

/** Named IP protocols; any other number is shown as such. */
const TRANSPORTS = {
  1: 'icmp',
  6: 'tcp',
  17: 'udp',
  58: 'icmpv6',
} as const satisfies Record<number, string>;

const endpointName = (c: ConversationInfo, side: 'src' | 'dst') => c[side].names[0] ?? c[side].ip;

/** Flows of one conversation, each with its Save PCAP action and the state of its export. */
export function FlowsDialog({ sessionId, conversation, onClose }: FlowsDialogProps) {
  const { t } = useTranslation();
  return (
    <Dialog
      open={conversation !== null}
      onClose={onClose}
      size="lg"
      title={t('views.exportPcap.flows.title')}
      {...(conversation === null
        ? {}
        : {
            description: (
              <span className="break-all">
                {t('views.exportPcap.flows.description', {
                  from: endpointName(conversation, 'src'),
                  to: endpointName(conversation, 'dst'),
                })}
              </span>
            ),
          })}
    >
      {conversation !== null && <FlowList sessionId={sessionId} conversationId={conversation.id} />}
    </Dialog>
  );
}

function FlowList({ sessionId, conversationId }: { sessionId: string; conversationId: string }) {
  const { t } = useTranslation();
  const flows = useConversationFlows(sessionId, conversationId, true);
  const jobs = useSessionExports(sessionId, true);
  const start = useStartExport(sessionId);
  const readOnly = useServerInfo().data?.read_only === true;
  const rows = flows.data?.pages.flatMap((p) => p.items) ?? [];

  if (flows.isError) {
    return (
      <ErrorState
        message={t('views.exportPcap.flows.loadError')}
        onRetry={() => {
          void flows.refetch();
        }}
      />
    );
  }
  if (flows.data === undefined) return <Skeleton height={160} />;
  if (rows.length === 0) return <EmptyState icon={Waypoints} title={t('views.exportPcap.flows.empty')} />;

  // Newest export of each flow (the list comes newest first).
  const latest = new Map<string, ExportJob>();
  for (const job of jobs.data ?? []) {
    if (job.flow_id !== null && !latest.has(job.flow_id)) latest.set(job.flow_id, job);
  }
  return (
    <div className="flex flex-col gap-3">
      {start.isError && <ErrorNote error={start.error} />}
      <ul aria-label={t('views.exportPcap.flows.listLabel')} className="flex flex-col divide-y divide-line">
        {rows.map((flow) => (
          <FlowRow
            key={flow.id}
            flow={flow}
            sessionId={sessionId}
            job={latest.get(flow.id)}
            disabled={readOnly || start.isPending}
            disabledReason={readOnly ? t('views.exportPcap.dialog.readOnly') : undefined}
            onSave={() => {
              start.mutate({ scope: 'flow', flow_id: flow.id });
            }}
          />
        ))}
      </ul>
      {flows.hasNextPage && (
        <div className="flex justify-center">
          <Button
            disabled={flows.isFetchingNextPage}
            onClick={() => {
              void flows.fetchNextPage();
            }}
          >
            {t('common.loadMore')}
          </Button>
        </div>
      )}
    </div>
  );
}

function FlowRow({
  flow,
  sessionId,
  job,
  disabled,
  disabledReason,
  onSave,
}: {
  flow: FlowInfo;
  sessionId: string;
  job: ExportJob | undefined;
  disabled: boolean;
  disabledReason: string | undefined;
  onSave: () => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const named = (TRANSPORTS as Record<number, (typeof TRANSPORTS)[keyof typeof TRANSPORTS] | undefined>)[flow.transport];
  const transport =
    named === undefined
      ? t('views.exportPcap.flows.transport.other', { proto: flow.transport })
      : t(`views.exportPcap.flows.transport.${named}`);
  const ports =
    flow.src_port === 0 && flow.dst_port === 0
      ? t('views.exportPcap.flows.noPorts')
      : t('views.exportPcap.flows.ports', { src: flow.src_port, dst: flow.dst_port });
  const summary = `${transport} ${ports} ${formatTimestamp(flow.first_ts_us)}`;
  return (
    <li className="flex min-w-0 flex-col gap-2 py-2.5 first:pt-0 last:pb-0">
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
        <div className="flex min-w-0 flex-1 basis-56 flex-col gap-0.5">
          <p className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-medium">{transport}</span>
            <span className="num font-mono text-meta">{ports}</span>
            {flow.app_proto !== null && <Badge>{flow.app_proto}</Badge>}
          </p>
          <p className="num flex min-w-0 flex-wrap gap-x-3 text-meta text-muted">
            <Timestamp us={flow.first_ts_us} />
            <span>{formatDuration(flow.duration_us / 1e6, lang)}</span>
            <span>{formatBytes(flow.bytes_fwd + flow.bytes_rev, lang)}</span>
            <span>{t('views.exportPcap.flows.packets', { count: flow.packets_total })}</span>
          </p>
        </div>
        <Button
          disabled={disabled || job?.state === 'running'}
          title={disabledReason}
          aria-label={t('views.exportPcap.flows.saveLabel', { flow: summary })}
          onClick={onSave}
        >
          <Download aria-hidden size={16} strokeWidth={1.75} />
          {t('views.exportPcap.flows.save')}
        </Button>
      </div>
      {job !== undefined && <ExportStatus job={job} sessionId={sessionId} />}
    </li>
  );
}
