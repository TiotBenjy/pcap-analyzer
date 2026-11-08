import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { ArrowUp, File, Folder } from 'lucide-react';
import { type FormEvent, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { browse } from '../../../api/sessions';
import type { PickKind } from '../../../app/importTracker';
import { closeImportWizard } from '../../../app/importTracker';
import { Button } from '../../../components/Button';
import { ErrorState } from '../../../components/ErrorState';
import { Skeleton } from '../../../components/Skeleton';
import { cn } from '../../../lib/cn';
import { formatBytes } from '../../../lib/format';
import { nativePicker, pickFile, pickFolder } from './pickers';
import { WizardDialog } from './WizardDialog';

interface SelectStepProps {
  kind: PickKind;
  onPick: (path: string) => void;
}

/** Step 1: native dialog in the desktop app, in-app folder browser in web mode. */
export function SelectStep({ kind, onPick }: SelectStepProps) {
  return nativePicker() === null ? <BrowserSelect kind={kind} onPick={onPick} /> : <NativeSelect kind={kind} onPick={onPick} />;
}

function NativeSelect({ kind, onPick }: SelectStepProps) {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const choose = () => {
    setError(null);
    (kind === 'folder' ? pickFolder() : pickFile()).then(
      (path) => {
        if (path !== null) onPick(path);
      },
      (e: unknown) => {
        setError(e instanceof Error ? e.message : String(e));
      },
    );
  };
  return (
    <WizardDialog
      step={1}
      kind={kind}
      footer={<Button onClick={closeImportWizard}>{t('common.cancel')}</Button>}
    >
      <div className="flex flex-col items-start gap-3">
        <p className="text-muted">{t('views.import.nativeHint')}</p>
        <Button variant="primary" data-autofocus onClick={choose}>
          {kind === 'folder' ? t('views.import.chooseFolder') : t('views.import.chooseFile')}
        </Button>
        {error !== null && (
          <p role="alert" className="text-meta text-danger">
            {error}
          </p>
        )}
      </div>
    </WizardDialog>
  );
}

const joinPath = (dir: string, name: string) => `${dir.replace(/[/\\]+$/, '')}/${name}`;

function BrowserSelect({ kind, onPick }: SelectStepProps) {
  const { t } = useTranslation();
  const [dir, setDir] = useState<string | undefined>(undefined);
  const [file, setFile] = useState<string | null>(null);
  const listing = useQuery({
    queryKey: ['fs', 'browse', dir ?? null],
    queryFn: ({ signal }) => browse(dir, signal),
    placeholderData: keepPreviousData,
    retry: false,
    staleTime: 0,
  });
  const data = listing.data;
  const rootsId = useId();

  const go = (path: string) => {
    setFile(null);
    setDir(path);
  };

  let footer;
  if (kind === 'folder') {
    footer = (
      <Button
        variant="primary"
        // While another folder loads, the previous listing is still shown: do not pick it.
        disabled={data === undefined || listing.isPlaceholderData}
        onClick={() => {
          if (data !== undefined && !listing.isPlaceholderData) onPick(data.path);
        }}
      >
        {t('views.import.selectFolder')}
      </Button>
    );
  } else {
    footer = (
      <Button
        variant="primary"
        disabled={file === null}
        onClick={() => {
          if (file !== null) onPick(file);
        }}
      >
        {t('views.import.selectFile')}
      </Button>
    );
  }

  return (
    <WizardDialog
      step={1}
      kind={kind}
      footer={
        <>
          <Button onClick={closeImportWizard}>{t('common.cancel')}</Button>
          {footer}
        </>
      }
    >
      {listing.isError && data === undefined ? (
        <div className="flex flex-col gap-4">
          <ErrorState
            message={t('views.import.browseError')}
            onRetry={() => {
              void listing.refetch();
            }}
          />
          <ManualPath onPick={onPick} />
        </div>
      ) : (
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

          <div className="h-80 min-w-0 overflow-y-auto rounded-md border border-line" aria-busy={listing.isFetching}>
            {data === undefined ? (
              <div className="flex flex-col gap-2 p-2">
                <Skeleton height={28} />
                <Skeleton height={28} />
                <Skeleton height={28} />
              </div>
            ) : data.entries.length === 0 ? (
              <p className="p-3 text-muted">{t('views.import.browseEmpty')}</p>
            ) : (
              <ul aria-label={t('views.import.browseLabel')} className="flex flex-col py-1">
                {data.entries.map((e) => {
                  const path = joinPath(data.path, e.name);
                  const Icon = e.is_dir ? Folder : File;
                  const selectable = e.is_dir || kind === 'file';
                  const selected = !e.is_dir && file === path;
                  const content = (
                    <>
                      <Icon aria-hidden size={16} strokeWidth={1.75} className="shrink-0 text-faint" />
                      <span data-testid="truncatable" title={e.name} className="min-w-0 flex-1 truncate font-mono text-meta">
                        {e.name}
                      </span>
                      {!e.is_dir && <span className="num shrink-0 text-meta text-muted">{formatBytes(e.size)}</span>}
                    </>
                  );
                  return (
                    <li key={e.name} className="px-1">
                      {selectable ? (
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
                          {content}
                        </button>
                      ) : (
                        <div className="flex h-8 min-w-0 items-center gap-2 px-2 text-muted">{content}</div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
          {listing.isError && (
            <p role="alert" className="text-meta text-danger">
              {t('views.import.browseError')}
            </p>
          )}
        </div>
      )}
    </WizardDialog>
  );
}

/** Fallback when the browser is unavailable: an absolute path typed by the user. */
function ManualPath({ onPick }: { onPick: (path: string) => void }) {
  const { t } = useTranslation();
  const [value, setValue] = useState('');
  const id = useId();
  const hintId = useId();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (value.trim() !== '') onPick(value.trim());
  };
  return (
    <form onSubmit={submit} className="flex min-w-0 flex-col gap-1.5">
      <p className="text-muted">{t('views.import.browseUnavailable')}</p>
      <label htmlFor={id} className="text-meta font-medium text-muted">
        {t('views.import.manualPath')}
      </label>
      <div className="flex min-w-0 flex-wrap gap-2">
        <input
          id={id}
          aria-describedby={hintId}
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
          }}
          className="h-8 min-w-0 flex-1 rounded-md border border-line bg-surface px-2 font-mono text-meta"
        />
        <Button type="submit" disabled={value.trim() === ''}>
          {t('views.import.usePath')}
        </Button>
      </div>
      <p id={hintId} className="text-meta text-muted">
        {t('views.import.manualHint')}
      </p>
    </form>
  );
}
