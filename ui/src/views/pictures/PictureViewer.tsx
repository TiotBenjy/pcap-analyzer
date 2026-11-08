import { ChevronLeft, ChevronRight, Download, FileCode, ImageOff } from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useRendition } from '../../api/objectQueries';
import { downloadObject, hasRendition } from '../../api/objects';
import type { ObjectItem } from '../../api/types/ObjectItem';
import { Button } from '../../components/Button';
import { Dialog } from '../../components/Dialog';
import { formatBytes, formatCount, formatTimestamp } from '../../lib/format';
import { dimensions, displayName, typeLabel } from './format';

interface PictureViewerProps {
  sessionId: string;
  items: readonly ObjectItem[];
  index: number;
  onIndex: (index: number) => void;
  onClose: () => void;
}

/**
 * Viewer of one image: PNG preview re-encoded by the backend (never the original) on a neutral
 * background, metadata, download, previous / next (buttons and arrow keys).
 */
export function PictureViewer({ sessionId, items, index, onIndex, onClose }: PictureViewerProps) {
  const { t } = useTranslation();
  const item = items[index];
  const [downloadFailed, setDownloadFailed] = useState(false);
  const count = items.length;
  const hasPrev = index > 0;
  const hasNext = index < count - 1;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.key === 'ArrowLeft' && index > 0) onIndex(index - 1);
      else if (e.key === 'ArrowRight' && index < count - 1) onIndex(index + 1);
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
    };
  }, [index, count, onIndex]);

  if (item === undefined) return null;
  const name = displayName(item);

  return (
    <Dialog
      open
      size="lg"
      onClose={onClose}
      title={<span title={name}>{name}</span>}
      description={t('views.pictures.viewer.position', { index: formatCount(index + 1), total: formatCount(count) })}
      footer={
        <>
          {downloadFailed && (
            <span role="alert" className="mr-auto text-meta text-danger">
              {t('views.pictures.viewer.downloadError')}
            </span>
          )}
          <Button
            icon
            aria-label={t('views.pictures.viewer.previous')}
            title={t('views.pictures.viewer.previous')}
            disabled={!hasPrev}
            onClick={() => {
              onIndex(index - 1);
            }}
          >
            <ChevronLeft aria-hidden size={16} strokeWidth={1.75} />
          </Button>
          <Button
            icon
            aria-label={t('views.pictures.viewer.next')}
            title={t('views.pictures.viewer.next')}
            disabled={!hasNext}
            onClick={() => {
              onIndex(index + 1);
            }}
          >
            <ChevronRight aria-hidden size={16} strokeWidth={1.75} />
          </Button>
          <Button
            variant="primary"
            data-autofocus
            onClick={() => {
              setDownloadFailed(false);
              downloadObject(sessionId, item).catch(() => {
                setDownloadFailed(true);
              });
            }}
          >
            <span className="inline-flex items-center gap-1.5">
              <Download aria-hidden size={16} strokeWidth={1.75} />
              {t('views.pictures.viewer.download')}
            </span>
          </Button>
        </>
      }
    >
      <div className="flex min-w-0 flex-col gap-4">
        <Preview key={item.sha256} sessionId={sessionId} item={item} />
        <Metadata item={item} />
      </div>
    </Dialog>
  );
}

function Preview({ sessionId, item }: { sessionId: string; item: ObjectItem }) {
  const { t } = useTranslation();
  const renderable = hasRendition(item);
  const preview = useRendition(sessionId, item.sha256, 'preview', renderable);
  let content: ReactNode;
  if (!renderable || preview.isError) {
    const svg = item.mime === 'image/svg+xml';
    const Icon = svg ? FileCode : ImageOff;
    const note = svg
      ? t('views.pictures.viewer.svgNote')
      : renderable
        ? t('views.pictures.viewer.previewError')
        : t('views.pictures.viewer.failedNote');
    content = (
      <span className="flex max-w-sm flex-col items-center gap-2 px-4 text-center text-body text-muted">
        <Icon aria-hidden size={32} strokeWidth={1.5} />
        {note}
      </span>
    );
  } else if (preview.data === undefined) {
    content = <span aria-hidden className="size-full animate-pulse bg-subtle" />;
  } else {
    content = <img src={preview.data} alt={displayName(item)} className="max-h-full max-w-full object-contain" />;
  }
  return (
    <div className="flex h-[min(55vh,520px)] min-h-40 w-full items-center justify-center overflow-hidden rounded-md bg-subtle">
      {content}
    </div>
  );
}

function Metadata({ item }: { item: ObjectItem }) {
  const { t } = useTranslation();
  const unknown = t('views.pictures.viewer.unknown');
  const rows: [string, ReactNode][] = [
    [t('views.pictures.viewer.url'), item.url ?? item.uri ?? unknown],
    [t('views.pictures.viewer.host'), item.host ?? unknown],
    [t('views.pictures.viewer.server'), `${item.server_ip}:${item.server_port}`],
    [t('views.pictures.viewer.client'), item.client_ip],
    [t('views.pictures.viewer.type'), `${typeLabel(item.mime)} (${item.mime})`],
    [t('views.pictures.viewer.declared'), item.declared_type ?? unknown],
    [t('views.pictures.viewer.dimensions'), dimensions(item) ?? unknown],
    [t('views.pictures.viewer.size'), `${formatBytes(item.size)} (${formatCount(item.size)})`],
    [t('views.pictures.viewer.occurrences'), formatCount(item.occurrences)],
    [t('views.pictures.viewer.firstSeen'), formatTimestamp(item.first_ts_us)],
    [t('views.pictures.viewer.lastSeen'), formatTimestamp(item.last_ts_us)],
    [t('views.pictures.viewer.sha256'), item.sha256],
  ];
  return (
    <dl className="grid min-w-0 grid-cols-1 gap-x-4 gap-y-1.5 text-body sm:grid-cols-[minmax(8rem,auto)_minmax(0,1fr)]">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-meta text-muted sm:text-body">{label}</dt>
          <dd className="min-w-0 font-mono text-meta break-all">{value}</dd>
        </div>
      ))}
    </dl>
  );
}
