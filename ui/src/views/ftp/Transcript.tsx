import { useTranslation } from 'react-i18next';
import type { FtpLine } from '../../api/types/FtpLine';
import { SecretValue } from '../../components/SecretValue';
import { cn } from '../../lib/cn';
import { isErrorCode } from './format';

/**
 * Transcript of a control session: one line per command or reply, verbs in bold, arguments in the
 * accent color, error codes in red. Text only: React escapes it, nothing from the capture is ever
 * interpreted as markup. A password (`PASS`, `ACCT`) is masked by default.
 */
export function Transcript({ lines, truncated }: { lines: readonly FtpLine[]; truncated: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="relative max-h-96 max-w-full min-w-0 overflow-auto rounded-md border border-line bg-subtle p-3">
      <ol aria-label={t('views.ftp.detail.transcriptLabel')} data-testid="ftp-transcript" className="flex min-w-0 flex-col font-mono text-meta">
        {lines.map((l) => (
          // Hanging indent: a long line wraps under its text, not under its verb or code.
          <li key={l.seq} className="min-w-0 pl-4 -indent-4 whitespace-pre-wrap [overflow-wrap:anywhere]">
            <Line line={l} />
          </li>
        ))}
        {truncated && (
          <li className="font-sans text-muted italic">{t('views.ftp.detail.truncated', { count: lines.length })}</li>
        )}
      </ol>
    </div>
  );
}

function Line({ line: l }: { line: FtpLine }) {
  const { t } = useTranslation();
  if (l.kind === 'note') {
    const note = l.text === 'tls' || l.text === 'gap' ? t(`views.ftp.detail.note.${l.text}`) : l.text;
    return <span className="font-sans text-muted italic">{note}</span>;
  }
  const cut = l.truncated && <span className="font-sans text-faint italic"> ({t('views.ftp.detail.lineCut')})</span>;
  if (l.kind === 'command') {
    return (
      <span>
        {l.head !== null && <span className="font-semibold text-fg">{l.head}</span>}
        {l.head !== null && l.text !== '' && ' '}
        {l.secret ? (
          <SecretValue value={l.text} label={t('views.ftp.detail.password')} inline className="indent-0" />
        ) : (
          <span className={l.head === null ? 'text-fg' : 'text-accent'}>{l.text}</span>
        )}
        {cut}
      </span>
    );
  }
  return (
    <span>
      {l.head !== null && <span className={cn(isErrorCode(l.head) ? 'text-danger' : 'text-muted')}>{l.head}</span>}
      {l.head !== null && !l.head.endsWith('-') && l.text !== '' && ' '}
      <span className="text-fg">{l.text}</span>
      {cut}
    </span>
  );
}
