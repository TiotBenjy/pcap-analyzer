import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowUp, File, Folder } from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { ApiError } from '../../api/client';
import { downloadGeoip, getGeoipUpdate, importGeoip } from '../../api/geoip';
import { browse } from '../../api/sessions';
import type { BrowseResponse } from '../../api/types/BrowseResponse';
import type { GeoipInfo } from '../../api/types/GeoipInfo';
import type { GeoipUpdate } from '../../api/types/GeoipUpdate';
import type { ServerInfo } from '../../api/types/ServerInfo';
import { Button } from '../../components/Button';
import { Dialog } from '../../components/Dialog';
import { ErrorState } from '../../components/ErrorState';
import { cn } from '../../lib/cn';
import { describeError } from '../../lib/errors';
import { formatBytes } from '../../lib/format';
import { nativePicker, pickFile } from '../sessions/import/pickers';

// Country database: state, update by download (done by the backend, ADR-015) or from a file,
// and the CC BY 4.0 attribution. Plain text only: the application never opens external URLs.

type UpdateRequest = { kind: 'download' } | { kind: 'import'; path: string };

/** Problem types of the GeoIP routes (`netsift-api/src/error.rs`). */
const GEOIP_PROBLEMS = {
  'urn:netsift:problem:geoip-download-failed': 'views.settings.geoip.errors.downloadFailed',
  'urn:netsift:problem:geoip-invalid': 'views.settings.geoip.errors.invalid',
  'urn:netsift:problem:geoip-too-large': 'views.settings.geoip.errors.tooLarge',
  'urn:netsift:problem:geoip-update-running': 'views.settings.geoip.errors.running',
} as const;

function updateErrorMessage(t: TFunction, error: unknown): string {
  if (error instanceof ApiError && error.kind in GEOIP_PROBLEMS) {
    return t(GEOIP_PROBLEMS[error.kind as keyof typeof GEOIP_PROBLEMS]);
  }
  return describeError(t, error).message;
}

const dateFormat = (lang: string, utc: boolean) =>
  new Intl.DateTimeFormat(lang, utc ? { dateStyle: 'medium', timeZone: 'UTC' } : { dateStyle: 'medium' });

interface GeoipSectionProps {
  info: ServerInfo | undefined;
  /** `server-info` failed to load (and has no previous data). */
  infoError: boolean;
}

export function GeoipSection({ info, infoError }: GeoipSectionProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [browsing, setBrowsing] = useState(false);
  const [pickError, setPickError] = useState<string | null>(null);

  const update = useMutation({
    mutationFn: (req: UpdateRequest) => (req.kind === 'download' ? downloadGeoip() : importGeoip(req.path)),
    // The progress of a previous download must not show at the start of the next one.
    onMutate: () => {
      queryClient.removeQueries({ queryKey: ['geoip-update'] });
    },
    onSuccess: (geoip) => {
      queryClient.setQueryData<ServerInfo>(['server-info'], (old) => (old === undefined ? old : { ...old, geoip }));
    },
  });
  const downloading = update.isPending && update.variables.kind === 'download';
  const progress = useQuery({
    queryKey: ['geoip-update'],
    queryFn: ({ signal }) => getGeoipUpdate(signal),
    enabled: downloading,
    refetchInterval: 500,
    staleTime: 0,
  });

  const desktop = nativePicker() !== null;
  const readOnly = info?.read_only ?? true;
  const canImport = desktop || (info?.can_browse ?? false);
  const busy = update.isPending;

  const start = (req: UpdateRequest) => {
    setPickError(null);
    update.mutate(req);
  };
  const chooseFile = () => {
    setPickError(null);
    if (!desktop) {
      setBrowsing(true);
      return;
    }
    pickFile().then(
      (path) => {
        if (path !== null) start({ kind: 'import', path });
      },
      (e: unknown) => {
        setPickError(e instanceof Error ? e.message : String(e));
      },
    );
  };

  let disabledReason: string | undefined;
  if (readOnly) disabledReason = t('views.settings.geoip.readOnly');
  else if (busy) disabledReason = t('views.settings.geoip.errors.running');

  return (
    <div className="flex min-w-0 flex-col gap-3">
      {info === undefined &&
        (infoError ? (
          <p role="alert" className="break-words text-danger" data-testid="geoip-status" data-status="error">
            {t('views.settings.geoip.infoError')}
          </p>
        ) : (
          <p className="text-muted" data-testid="geoip-status" data-status="checking">
            {t('views.settings.checking')}
          </p>
        ))}
      {info !== undefined && (
        <div className="flex min-w-0 flex-col gap-0.5">
          <GeoipStatus geoip={info.geoip} />
          <GeoipDetails geoip={info.geoip} />
        </div>
      )}

      {info !== undefined && (
        <div className="flex min-w-0 flex-col gap-2" data-testid="geoip-update">
          <div className="flex min-w-0 flex-wrap gap-2">
            <Button
              variant="primary"
              disabled={readOnly || busy}
              title={disabledReason}
              onClick={() => {
                start({ kind: 'download' });
              }}
            >
              {t('views.settings.geoip.download')}
            </Button>
            <Button
              disabled={readOnly || busy || !canImport}
              title={disabledReason ?? (canImport ? undefined : t('views.settings.geoip.noBrowse'))}
              onClick={chooseFile}
            >
              {t('views.settings.geoip.importFile')}
            </Button>
          </div>
          <UpdateFeedback
            pending={busy}
            downloading={downloading}
            progress={progress.data}
            error={update.isError ? updateErrorMessage(t, update.error) : pickError}
            success={update.isSuccess}
          />
          {readOnly && <p className="break-words text-meta text-muted">{t('views.settings.geoip.readOnly')}</p>}
          {!readOnly && !canImport && (
            <p className="break-words text-meta text-muted">{t('views.settings.geoip.noBrowse')}</p>
          )}
          <p className="break-words text-meta text-muted">{t('views.settings.geoip.downloadNote')}</p>
          <p className="break-words text-meta text-muted">{t('views.settings.geoip.reimportNote')}</p>
        </div>
      )}

      <div className="flex min-w-0 flex-col gap-0.5" data-testid="geoip-attribution">
        <span className="break-words">{t('views.settings.geoip.attribution')}</span>
        <span className="break-all text-muted">{t('views.settings.geoip.source')}</span>
        <span className="break-words text-muted">{t('views.settings.geoip.license')}</span>
        <span className="break-all text-muted">{t('views.settings.geoip.licenseUrl')}</span>
      </div>

      {browsing && (
        <GeoipFileDialog
          onClose={() => {
            setBrowsing(false);
          }}
          onPick={(path) => {
            setBrowsing(false);
            start({ kind: 'import', path });
          }}
        />
      )}
    </div>
  );
}

function GeoipStatus({ geoip }: { geoip: GeoipInfo }) {
  const { t, i18n } = useTranslation();
  let text: string;
  let tone: string;
  if (geoip.status === 'available') {
    tone = 'text-success';
    text =
      geoip.built_at_us === null
        ? t('views.settings.geoip.availableUndated')
        : t('views.settings.geoip.available', {
            // Build date of the database in UTC: the publisher's calendar, not local time.
            date: dateFormat(i18n.language, true).format(new Date(geoip.built_at_us / 1000)),
          });
  } else if (geoip.status === 'invalid') {
    tone = 'text-danger';
    text = t('views.settings.geoip.invalid');
  } else {
    tone = 'text-warning';
    text = t('views.settings.geoip.missing');
  }
  // Wrapping text rather than a badge: the sentence must fit the narrowest card.
  return (
    <span className={cn('break-words font-medium', tone)} data-testid="geoip-status" data-status={geoip.status}>
      {text}
    </span>
  );
}

function GeoipDetails({ geoip }: { geoip: GeoipInfo }) {
  const { t, i18n } = useTranslation();
  if (geoip.source === null) return null;
  const size = geoip.size_bytes === null ? '' : formatBytes(geoip.size_bytes, i18n.language);
  const text =
    geoip.source === 'bundled'
      ? t('views.settings.geoip.sourceBundled', { size })
      : geoip.installed_at_us === null
        ? t('views.settings.geoip.sourceUserUndated', { size })
        : t('views.settings.geoip.sourceUser', {
            size,
            date: dateFormat(i18n.language, false).format(new Date(geoip.installed_at_us / 1000)),
          });
  return (
    <span className="break-words text-meta text-muted" data-testid="geoip-source" data-source={geoip.source}>
      {text}
    </span>
  );
}

interface UpdateFeedbackProps {
  pending: boolean;
  downloading: boolean;
  progress: GeoipUpdate | undefined;
  error: string | null;
  success: boolean;
}

function UpdateFeedback({ pending, downloading, progress, error, success }: UpdateFeedbackProps) {
  const { t, i18n } = useTranslation();
  if (pending) {
    // Only the phase is announced (role="status"); the byte counter changes twice a second and
    // stays out of the live region.
    const fetching = downloading && progress?.phase !== 'installing';
    const phase = fetching ? t('views.settings.geoip.downloading') : t('views.settings.geoip.installing');
    let counter: string | null = null;
    let ratio: number | null = null;
    if (fetching) {
      const received = progress?.received_bytes ?? 0;
      const total = progress?.total_bytes ?? null;
      if (total !== null && total > 0) {
        ratio = Math.min(1, received / total);
        counter = t('views.settings.geoip.progressOf', {
          received: formatBytes(received, i18n.language),
          total: formatBytes(total, i18n.language),
        });
      } else if (received > 0) {
        counter = t('views.settings.geoip.progressBytes', { received: formatBytes(received, i18n.language) });
      }
    }
    return (
      <div className="flex min-w-0 flex-col gap-1" data-testid="geoip-progress">
        <span role="status" className="break-words text-meta">
          {phase}
        </span>
        {counter !== null && (
          <span className="num break-words text-meta text-muted" data-testid="geoip-progress-bytes">
            {counter}
          </span>
        )}
        {ratio !== null && (
          <div className="h-1.5 w-full max-w-xs overflow-hidden rounded-full bg-subtle" aria-hidden>
            <div className="h-full bg-accent" style={{ width: `${Math.round(ratio * 100)}%` }} />
          </div>
        )}
      </div>
    );
  }
  if (error !== null) {
    return (
      <p role="alert" className="break-words text-meta text-danger">
        {error}
      </p>
    );
  }
  if (success) {
    return (
      <p role="status" className="break-words text-meta text-success">
        {t('views.settings.geoip.updated')}
      </p>
    );
  }
  return null;
}

const joinPath = (dir: string, name: string) => `${dir.replace(/[/\\]+$/, '')}/${name}`;

/** Dev web mode: file chosen in the allowed roots of the backend (`GET /fs/browse`). */
function GeoipFileDialog({ onClose, onPick }: { onClose: () => void; onPick: (path: string) => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [dir, setDir] = useState<string | undefined>(undefined);
  // Folder shown before the current one: its listing stays visible if the next one fails.
  const [prevDir, setPrevDir] = useState<string | undefined>(undefined);
  const [file, setFile] = useState<string | null>(null);
  const rootsId = useId();
  const listing = useQuery({
    queryKey: ['fs', 'browse', dir ?? null],
    queryFn: ({ signal }) => browse(dir, signal),
    placeholderData: keepPreviousData,
    retry: false,
    staleTime: 0,
  });
  const failed = listing.isError;
  const data =
    listing.data ?? (failed ? queryClient.getQueryData<BrowseResponse>(['fs', 'browse', prevDir ?? null]) : undefined);
  const go = (path: string) => {
    setFile(null);
    // Query key of the listing on screen (`undefined`: the first root), unchanged while a failed
    // folder is shown over it.
    if (listing.data !== undefined) setPrevDir(dir);
    setDir(path);
  };
  const retry = () => {
    void listing.refetch();
  };

  let body;
  if (failed && data === undefined) {
    // First listing failed: nothing to show yet, offer a retry.
    body = <ErrorState message={t('views.import.browseError')} onRetry={retry} />;
  } else if (data === undefined) {
    body = <p className="p-3 text-muted">{t('common.loading')}</p>;
  } else if (data.entries.length === 0) {
    body = <p className="p-3 text-muted">{t('views.import.browseEmpty')}</p>;
  } else {
    body = (
      <ul aria-label={t('views.import.browseLabel')} className="flex flex-col py-1">
        {data.entries.map((e) => {
          const path = joinPath(data.path, e.name);
          const Icon = e.is_dir ? Folder : File;
          const selected = !e.is_dir && file === path;
          return (
            <li key={e.name} className="px-1">
              <button
                type="button"
                aria-pressed={e.is_dir ? undefined : selected}
                onClick={() => {
                  if (e.is_dir) go(path);
                  else setFile(path);
                }}
                onDoubleClick={() => {
                  if (!e.is_dir) onPick(path);
                }}
                className={cn(
                  'flex h-8 w-full min-w-0 items-center gap-2 rounded-md px-2 text-left hover:bg-subtle',
                  selected && 'bg-accent-soft text-accent',
                )}
              >
                <Icon aria-hidden size={16} strokeWidth={1.75} className="shrink-0 text-faint" />
                <span data-testid="truncatable" title={e.name} className="min-w-0 flex-1 truncate font-mono text-meta">
                  {e.name}
                </span>
                {!e.is_dir && <span className="num shrink-0 text-meta text-muted">{formatBytes(e.size)}</span>}
              </button>
            </li>
          );
        })}
      </ul>
    );
  }

  return (
    <Dialog
      open
      size="lg"
      onClose={onClose}
      title={t('views.settings.geoip.chooseTitle')}
      description={t('views.settings.geoip.chooseHint')}
      footer={
        <>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            disabled={file === null}
            onClick={() => {
              if (file !== null) onPick(file);
            }}
          >
            {t('views.settings.geoip.install')}
          </Button>
        </>
      }
    >
      <div className="flex min-w-0 flex-col gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Button
            icon
            aria-label={t('views.import.browseUp')}
            title={t('views.import.browseUp')}
            disabled={data?.parent === null || data === undefined}
            onClick={() => {
              if (data?.parent !== null && data?.parent !== undefined) go(data.parent);
            }}
          >
            <ArrowUp aria-hidden size={16} strokeWidth={1.75} />
          </Button>
          {data !== undefined && data.roots.length > 1 && (
            <>
              <label htmlFor={rootsId} className="sr-only">
                {t('views.import.browseRoots')}
              </label>
              <select
                id={rootsId}
                value={data.roots.find((r) => data.path === r || data.path.startsWith(`${r}/`)) ?? ''}
                onChange={(e) => {
                  go(e.target.value);
                }}
                className="h-8 max-w-full min-w-0 rounded-md border border-line bg-surface px-2 font-mono text-meta"
              >
                {data.roots.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </>
          )}
          <span
            data-testid="truncatable"
            title={data?.path ?? ''}
            className="min-w-0 flex-1 truncate font-mono text-meta text-muted"
          >
            {data?.path ?? ''}
          </span>
        </div>
        <div className="h-72 min-w-0 overflow-y-auto rounded-md border border-line" aria-busy={listing.isFetching}>
          {body}
        </div>
        {failed && data !== undefined && (
          // A later folder failed to load: the previous listing stays, the error is said.
          <p role="alert" className="text-meta text-danger">
            {t('views.import.browseError')}
          </p>
        )}
      </div>
    </Dialog>
  );
}
