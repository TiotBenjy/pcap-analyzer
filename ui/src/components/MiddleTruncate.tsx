import { cn } from '../lib/cn';

/** Characters always kept visible at the end, besides the extension (sequence numbers, dates). */
const TAIL_CHARS = 8;
const EXTENSION = /(\.[A-Za-z0-9]{1,8}){1,2}$/;

/**
 * Truncates in the middle and keeps the end visible (extension such as `.pcapng` or `.pcap.gz`,
 * plus the last characters, often a sequence number), adapting to the available width.
 * The full text (or `title`, e.g. the full path of a file name) is in the tooltip.
 */
export function MiddleTruncate({ text, title, className }: { text: string; title?: string; className?: string }) {
  const ext = EXTENSION.exec(text)?.[0] ?? '';
  const tailLength = Math.min(text.length, ext.length + TAIL_CHARS);
  const head = text.slice(0, text.length - tailLength);
  const tail = text.slice(text.length - tailLength);
  return (
    <span data-testid="truncatable" title={title ?? text} className={cn('flex min-w-0', className)}>
      <span className="min-w-0 truncate">{head}</span>
      <span className="shrink-0 whitespace-pre">{tail}</span>
    </span>
  );
}
