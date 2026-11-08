import { useTranslation } from 'react-i18next';
import { describeError } from '../lib/errors';

interface ErrorNoteProps {
  error: unknown;
  /** Wraps the translated message, e.g. "Rename failed: {message}". */
  format?: (message: string) => string;
}

/** Inline error of a form or step: translated message, raw detail in small text below. */
export function ErrorNote({ error, format }: ErrorNoteProps) {
  const { t } = useTranslation();
  const { message, detail } = describeError(t, error);
  return (
    <div role="alert" className="flex min-w-0 flex-col gap-0.5 text-meta">
      <p className="text-danger">{format === undefined ? message : format(message)}</p>
      {detail !== null && <p className="text-muted [overflow-wrap:anywhere]">{detail}</p>}
    </div>
  );
}
