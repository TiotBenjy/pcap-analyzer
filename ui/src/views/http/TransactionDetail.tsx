import { type KeyboardEvent, type ReactNode, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useHttpTransaction } from '../../api/httpQueries';
import type { HttpMessageInfo } from '../../api/types/HttpMessageInfo';
import type { HttpTransactionDetail } from '../../api/types/HttpTransactionDetail';
import { Badge, type BadgeTone } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { Skeleton } from '../../components/Skeleton';
import { cn } from '../../lib/cn';
import { formatBytes, formatCount, formatDuration, formatTimestamp } from '../../lib/format';
import { HeaderTable } from './HeaderTable';

const TABS = ['request', 'response', 'body', 'flow'] as const;
type Tab = (typeof TABS)[number];

const STATE_TONES: Record<string, BadgeTone> = {
  complete: 'success',
  none: 'neutral',
  incomplete: 'warning',
  truncated: 'warning',
  bomb: 'danger',
  decode_error: 'danger',
  not_decoded: 'neutral',
  malformed: 'danger',
};
const BODY_STATES = new Set([
  'none',
  'complete',
  'incomplete',
  'truncated',
  'bomb',
  'decode_error',
  'not_decoded',
  'malformed',
] as const);
type BodyState = typeof BODY_STATES extends Set<infer S> ? S : never;
const isBodyState = (s: string): s is BodyState => (BODY_STATES as Set<string>).has(s);

/** Accessible tabs (arrow keys move between tabs). */
function Tabs({ value, onChange, labels }: { value: Tab; onChange: (t: Tab) => void; labels: Record<Tab, string> }) {
  const refs = useRef<Partial<Record<Tab, HTMLButtonElement | null>>>({});
  const onKey = (e: KeyboardEvent) => {
    const i = TABS.indexOf(value);
    const delta = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (delta === 0) return;
    e.preventDefault();
    const next = TABS[(i + delta + TABS.length) % TABS.length] ?? value;
    onChange(next);
    refs.current[next]?.focus();
  };
  return (
    <div role="tablist" className="flex min-w-0 gap-0.5 overflow-x-auto border-b border-line sm:gap-1" onKeyDown={onKey}>
      {TABS.map((tab) => (
        <button
          key={tab}
          ref={(el) => {
            refs.current[tab] = el;
          }}
          type="button"
          role="tab"
          aria-selected={tab === value}
          tabIndex={tab === value ? 0 : -1}
          onClick={() => {
            onChange(tab);
          }}
          className={cn(
            '-mb-px h-8 shrink-0 border-b-2 px-2 text-body whitespace-nowrap sm:px-3',
            tab === value ? 'border-accent font-medium text-fg' : 'border-transparent text-muted hover:text-fg',
          )}
        >
          {labels[tab]}
        </button>
      ))}
    </div>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-meta text-muted">{label}</dt>
      <dd className="min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

function BodyFacts({ message, sensitive }: { message: HttpMessageInfo; sensitive: boolean }) {
  const { t, i18n } = useTranslation();
  const [revealed, setRevealed] = useState(!sensitive);
  const state = isBodyState(message.body_state) ? message.body_state : 'none';
  return (
    <div className="flex flex-col gap-3">
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <Fact label={t('views.http.detail.bodySize')}>
          <span className="num">{formatBytes(message.body_size, i18n.language)}</span>
        </Fact>
        <Fact label={t('views.http.detail.wireSize')}>
          <span className="num">{formatBytes(message.body_wire_size, i18n.language)}</span>
          {message.chunked && <span className="text-muted"> {t('views.http.detail.chunked')}</span>}
        </Fact>
        <Fact label={t('views.http.detail.state')}>
          <Badge tone={STATE_TONES[state] ?? 'neutral'}>{t(`views.http.bodyState.${state}`)}</Badge>
        </Fact>
        <Fact label={t('views.http.detail.encoding')}>{message.content_encoding ?? '-'}</Fact>
        <Fact label={t('views.http.detail.declaredType')}>{message.content_type ?? '-'}</Fact>
        <Fact label={t('views.http.detail.sniffedType')}>{message.mime_magic ?? '-'}</Fact>
      </dl>
      {message.sha256 !== null && (
        <Fact label={t('views.http.detail.sha256')}>
          <span data-testid="truncatable" title={message.sha256} className="block truncate font-mono text-meta">
            {message.sha256}
          </span>
        </Fact>
      )}
      {message.preview !== null &&
        (revealed ? (
          <pre className="max-h-64 overflow-auto rounded-md border border-line bg-surface p-2 font-mono text-meta whitespace-pre-wrap [overflow-wrap:anywhere]">
            {message.preview}
          </pre>
        ) : (
          <div className="flex flex-wrap items-center gap-2 text-muted">
            <span>{t('views.http.detail.previewHidden')}</span>
            <Button
              variant="secondary"
              onClick={() => {
                setRevealed(true);
              }}
            >
              {t('views.http.detail.showPreview')}
            </Button>
          </div>
        ))}
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex min-w-0 flex-col gap-2">
      <h4 className="text-meta font-medium text-muted uppercase">{title}</h4>
      {children}
    </section>
  );
}

function DetailBody({ d, tab }: { d: HttpTransactionDetail; tab: Tab }) {
  const { t, i18n } = useTranslation();
  const s = d.summary;
  const lang = i18n.language;
  if (tab === 'request') {
    if (d.request === null) return <p className="text-muted">{t('views.http.detail.noRequest')}</p>;
    return (
      <div className="flex flex-col gap-2">
        <p className="font-mono text-meta [overflow-wrap:anywhere]">
          {s.method} {s.uri} {s.version}
        </p>
        <HeaderTable headers={d.request.headers} label={t('views.http.detail.requestHeaders')} />
      </div>
    );
  }
  if (tab === 'response') {
    if (d.response === null) return <p className="text-muted">{t('views.http.detail.noResponse')}</p>;
    return (
      <div className="flex flex-col gap-2">
        <p className="font-mono text-meta [overflow-wrap:anywhere]">
          {s.version} {s.status} {s.reason}
        </p>
        <HeaderTable headers={d.response.headers} label={t('views.http.detail.responseHeaders')} />
      </div>
    );
  }
  if (tab === 'body') {
    return (
      <div className="flex flex-col gap-4">
        <Section title={t('views.http.detail.requestBody')}>
          {d.request === null ? (
            <p className="text-muted">{t('views.http.detail.noRequest')}</p>
          ) : (
            <BodyFacts message={d.request} sensitive />
          )}
        </Section>
        <Section title={t('views.http.detail.responseBody')}>
          {d.response === null ? (
            <p className="text-muted">{t('views.http.detail.noResponse')}</p>
          ) : (
            <BodyFacts message={d.response} sensitive={false} />
          )}
        </Section>
      </div>
    );
  }
  const flowDuration =
    d.flow_first_ts_us !== null && d.flow_last_ts_us !== null ? (d.flow_last_ts_us - d.flow_first_ts_us) / 1e6 : null;
  return (
    <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Fact label={t('views.http.detail.client')}>
        <Endpoint endpoint={s.client} port={s.client_port} showName={false} />
      </Fact>
      <Fact label={t('views.http.detail.server')}>
        <Endpoint endpoint={s.server} port={s.server_port} showName={false} />
      </Fact>
      <Fact label={t('views.http.detail.started')}>
        <span className="num">{formatTimestamp(s.ts_us)}</span>
      </Fact>
      <Fact label={t('views.http.detail.responseTime')}>
        <span className="num">{s.response_time_us === null ? '-' : formatDuration(s.response_time_us / 1e6, lang)}</span>
      </Fact>
      <Fact label={t('views.http.detail.duration')}>
        <span className="num">{formatDuration((s.end_ts_us - s.ts_us) / 1e6, lang)}</span>
      </Fact>
      <Fact label={t('views.http.detail.connection')}>
        <span className="num">{flowDuration === null ? '-' : formatDuration(flowDuration, lang)}</span>
      </Fact>
      <Fact label={t('views.http.detail.position')}>
        <span className="num">{formatCount(s.seq + 1)}</span>
      </Fact>
      <Fact label={t('views.http.detail.flow')}>
        <span className="font-mono text-meta">{s.flow_id}</span>
      </Fact>
    </dl>
  );
}

/** Expanded transaction: request, response, bodies and connection, fetched on demand. */
export function TransactionDetail({ sessionId, id }: { sessionId: string; id: number }) {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>('request');
  const query = useHttpTransaction(sessionId, id, true);
  const panelId = useId();
  const labels: Record<Tab, string> = {
    request: t('views.http.detail.request'),
    response: t('views.http.detail.response'),
    body: t('views.http.detail.body'),
    flow: t('views.http.detail.flowTab'),
  };
  let body: ReactNode;
  if (query.isPending) body = <Skeleton height={120} />;
  else if (query.isError)
    body = (
      <ErrorState
        message={t('views.http.detailError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  else body = <DetailBody d={query.data} tab={tab} />;
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <Tabs value={tab} onChange={setTab} labels={labels} />
      <div role="tabpanel" id={panelId} aria-label={labels[tab]} className="min-w-0">
        {body}
      </div>
    </div>
  );
}
