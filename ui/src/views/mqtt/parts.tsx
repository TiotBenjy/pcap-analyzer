import { type ReactNode, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { MqttPayload } from '../../api/types/MqttPayload';
import type { MqttProperty } from '../../api/types/MqttProperty';
import { SegmentedControl } from '../../components/SegmentedControl';
import { formatByteCount } from '../../lib/format';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { propLabel } from './labels';

export const SELECT_CLASS = 'h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body sm:w-auto sm:max-w-60';

/** A segmented control from `sm`, a list below (long labels do not fit 375 px). */
export function Choice<V extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: V;
  options: readonly { value: V; label: string }[];
  onChange: (v: V) => void;
}) {
  const id = useId();
  return (
    <>
      <div className="hidden sm:block">
        <SegmentedControl hideLabel label={label} value={value} options={options} onChange={onChange} />
      </div>
      <div className="w-full sm:hidden">
        <label htmlFor={id} className="sr-only">
          {label}
        </label>
        <select
          id={id}
          value={value}
          onChange={(e) => {
            onChange(e.target.value as V);
          }}
          className={SELECT_CLASS}
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
    </>
  );
}

/** A labelled select of a filter band. */
export function Select<V extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: V;
  options: readonly { value: V; label: string }[];
  onChange: (v: V) => void;
}) {
  const id = useId();
  return (
    <>
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(e) => {
          onChange(e.target.value as V);
        }}
        className={SELECT_CLASS}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </>
  );
}

/** One labelled value of a detail list. */
export function Field({ label, children, wide = false }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <div className={wide ? 'flex min-w-0 flex-col gap-0.5 [grid-column:1/-1]' : 'flex min-w-0 flex-col gap-0.5'}>
      <dt className="text-meta text-muted">{label}</dt>
      <dd className="min-w-0 text-meta break-words">{children}</dd>
    </div>
  );
}

/** Property list of a packet or connection (names of the specifications, values as text). */
export function Properties({ props }: { props: readonly MqttProperty[] }) {
  const { t } = useTranslation();
  if (props.length === 0) return null;
  return (
    <dl className="grid min-w-0 gap-x-3 gap-y-1 text-meta sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)]">
      {props.map((p, i) => (
        <div key={i} className="contents">
          <dt className="min-w-0 text-muted">{propLabel(t, p.name)}</dt>
          <dd className="min-w-0 font-mono break-all">{p.value}</dd>
        </div>
      ))}
    </dl>
  );
}

const SM_QUERY = '(min-width: 640px)';

/** Hexadecimal dump: offset, bytes, printable characters (a dot otherwise). */
function hexDump(hex: string, perLine: number): string {
  const bytes: number[] = [];
  for (let i = 0; i + 1 < hex.length; i += 2) bytes.push(Number.parseInt(hex.slice(i, i + 2), 16));
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += perLine) {
    const chunk = bytes.slice(off, off + perLine);
    const hexPart = chunk
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ')
      .padEnd(perLine * 3 - 1, ' ');
    const ascii = chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${off.toString(16).padStart(4, '0')}  ${hexPart}  ${ascii}`);
  }
  return lines.join('\n');
}

type PayloadMode = 'text' | 'hex';

/**
 * A payload excerpt rendered by the server: escaped text or a hexadecimal dump, always as React
 * text (never interpreted). Wraps, never scrolls horizontally, no scroll of its own.
 */
export function PayloadView({
  payload,
  contentType,
  format,
}: {
  payload: MqttPayload;
  contentType?: string | null;
  format?: number | null;
}) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<PayloadMode>(payload.text === null ? 'hex' : 'text');
  const wide = useMediaQuery(SM_QUERY);
  const size =
    payload.truncated
      ? t('views.mqtt.payload.excerpt', { shown: formatByteCount(payload.excerpt_len), total: formatByteCount(payload.len) })
      : t('views.mqtt.payload.whole', { total: formatByteCount(payload.len) });
  if (payload.len === 0) return <p className="text-meta text-muted">{t('views.mqtt.payload.empty')}</p>;
  const shown = mode === 'text' && payload.text !== null ? payload.text : hexDump(payload.hex, wide ? 16 : 8);
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
        {payload.text !== null && (
          <SegmentedControl
            hideLabel
            label={t('views.mqtt.payload.label')}
            value={mode}
            options={[
              { value: 'text', label: t('views.mqtt.payload.text') },
              { value: 'hex', label: t('views.mqtt.payload.hex') },
            ]}
            onChange={setMode}
          />
        )}
        <span className="num text-meta text-muted">{size}</span>
        {contentType !== undefined && contentType !== null && (
          <span className="min-w-0 text-meta break-all text-muted">{`${t('views.mqtt.payload.contentType')} ${contentType}`}</span>
        )}
        {format !== undefined && format !== null && (
          <span className="text-meta text-muted">
            {`${t('views.mqtt.payload.format')} ${format === 1 ? t('views.mqtt.payload.formatUtf8') : t('views.mqtt.payload.formatBytes')}`}
          </span>
        )}
      </div>
      <pre
        data-testid="mqtt-payload"
        className="max-w-[100ch] min-w-0 rounded-md border border-line bg-surface p-2 font-mono text-meta leading-5 whitespace-pre-wrap [overflow-wrap:anywhere]"
      >
        {shown}
      </pre>
    </div>
  );
}
