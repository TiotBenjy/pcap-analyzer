import { Download, FolderOpen, X } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useCancelExport } from '../../api/exportQueries';
import { deliversByFolder, exportFileUrl, jobError, openExportFolder } from '../../api/exports';
import type { ExportJob } from '../../api/types/ExportJob';
import { Button } from '../../components/Button';
import { ErrorNote } from '../../components/ErrorNote';
import { formatBytes, formatPercent } from '../../lib/format';

/** Progress, result or error of one export, with its actions (cancel, open folder, download). */
export function ExportStatus({ job, sessionId }: { job: ExportJob; sessionId: string }) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const cancel = useCancelExport(sessionId);
  const [openFailed, setOpenFailed] = useState<unknown>(null);

  if (job.state === 'running') {
    const share = job.bytes_total > 0 ? Math.min(1, job.bytes_read / job.bytes_total) : 0;
    return (
      <div role="status" className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-meta">
        <div className="flex min-w-0 flex-1 basis-48 flex-col gap-1">
          <p>{t('views.exportPcap.status.running', { percent: formatPercent(share, 0, lang) })}</p>
          <div aria-hidden className="h-1.5 overflow-hidden rounded-full bg-subtle">
            <div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(1, share * 100)}%` }} />
          </div>
          <p className="num text-muted">
            {t('views.exportPcap.status.runningDetail', {
              read: formatBytes(job.bytes_read, lang),
              total: formatBytes(job.bytes_total, lang),
            })}
          </p>
        </div>
        <Button
          variant="ghost"
          disabled={cancel.isPending}
          onClick={() => {
            cancel.mutate(job.id);
          }}
        >
          <X aria-hidden size={16} strokeWidth={1.75} />
          {t('views.exportPcap.status.cancel')}
        </Button>
      </div>
    );
  }
  if (job.state === 'failed') {
    return <ErrorNote error={jobError(job)} format={(message) => t('views.exportPcap.status.failed', { message })} />;
  }
  if (job.state === 'cancelled') {
    return (
      <p role="status" className="text-meta text-muted">
        {t('views.exportPcap.status.cancelled')}
      </p>
    );
  }
  return (
    <div role="status" className="flex min-w-0 flex-col gap-2 text-meta">
      <p className="text-success">
        {t('views.exportPcap.status.done', { count: job.packets, size: formatBytes(job.bytes_written, lang) })}
      </p>
      {job.read_errors > 0 && <p className="text-warning">{t('views.exportPcap.status.readErrors', { count: job.read_errors })}</p>}
      <p className="flex min-w-0 items-center gap-1.5">
        <span className="shrink-0 text-muted">{t('views.exportPcap.status.file')}</span>
        <span data-testid="truncatable" title={job.file_name} className="min-w-0 truncate font-mono">
          {job.file_name}
        </span>
      </p>
      <div className="flex flex-wrap gap-2">
        {deliversByFolder() ? (
          <Button
            onClick={() => {
              setOpenFailed(null);
              openExportFolder(job.folder).catch((e: unknown) => {
                setOpenFailed(e);
              });
            }}
          >
            <FolderOpen aria-hidden size={16} strokeWidth={1.75} />
            {t('views.exportPcap.status.openFolder')}
          </Button>
        ) : (
          <a
            href={exportFileUrl(job.id)}
            download={job.file_name}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line bg-surface px-3 font-medium text-fg hover:bg-subtle"
          >
            <Download aria-hidden size={16} strokeWidth={1.75} />
            {t('views.exportPcap.status.download')}
          </a>
        )}
      </div>
      {openFailed !== null && (
        <ErrorNote error={openFailed} format={() => t('views.exportPcap.status.openError')} />
      )}
    </div>
  );
}
