import { type FormEvent, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useDeleteSession, useRenameSession } from '../../api/sessionQueries';
import type { SessionSummary } from '../../api/types/SessionSummary';
import { forgetSession } from '../../app/session';
import { Button } from '../../components/Button';
import { Dialog } from '../../components/Dialog';
import { ErrorNote } from '../../components/ErrorNote';

export function RenameDialog({ session, onClose }: { session: SessionSummary; onClose: () => void }) {
  const { t } = useTranslation();
  const rename = useRenameSession();
  const [name, setName] = useState(session.name);
  const inputId = useId();
  const formId = useId();
  const trimmed = name.trim();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (trimmed === '' || rename.isPending) return;
    rename.mutate(
      { id: session.id, name: trimmed },
      {
        onSuccess: onClose,
      },
    );
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={t('views.captures.renameTitle')}
      footer={
        <>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" type="submit" form={formId} disabled={trimmed === '' || rename.isPending}>
            {t('common.save')}
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={submit} className="flex flex-col gap-1.5">
        <label htmlFor={inputId} className="text-meta font-medium text-muted">
          {t('views.captures.nameLabel')}
        </label>
        <input
          id={inputId}
          data-autofocus
          value={name}
          maxLength={200}
          onChange={(e) => {
            setName(e.target.value);
          }}
          className="h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2"
        />
        {rename.isError && (
          <ErrorNote error={rename.error} format={(message) => t('views.captures.renameError', { message })} />
        )}
      </form>
    </Dialog>
  );
}

export function DeleteDialog({ session, onClose }: { session: SessionSummary; onClose: () => void }) {
  const { t } = useTranslation();
  const del = useDeleteSession();

  const confirm = () => {
    del.mutate(session.id, {
      onSuccess: () => {
        forgetSession(session.id);
        onClose();
      },
    });
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={t('views.captures.deleteTitle')}
      footer={
        <>
          {/* Safe default: focus starts on Cancel. */}
          <Button data-autofocus onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" onClick={confirm} disabled={del.isPending}>
            {t('common.delete')}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-2">
        <p className="[overflow-wrap:anywhere]">{t('views.captures.deleteText', { name: session.name })}</p>
        <p className="text-muted">{t('views.captures.deleteSafe')}</p>
        {del.isError && (
          <ErrorNote error={del.error} format={(message) => t('views.captures.deleteError', { message })} />
        )}
      </div>
    </Dialog>
  );
}
