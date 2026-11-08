import { Download, X } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { downloadCertificate } from '../../api/tls';
import { useTlsSession } from '../../api/tlsQueries';
import type { TlsCertificateInfo } from '../../api/types/TlsCertificateInfo';
import type { TlsClientHelloInfo } from '../../api/types/TlsClientHelloInfo';
import type { TlsServerHelloInfo } from '../../api/types/TlsServerHelloInfo';
import type { TlsSessionItem } from '../../api/types/TlsSessionItem';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { ErrorState } from '../../components/ErrorState';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { formatBytes, formatTimestamp } from '../../lib/format';
import { CodeList, Field, Fields, IssueBadges, MonoValue, SuiteName } from './parts';
import { alertName, formatDate, hex4, versionLabel, versionTone } from './tlsFormat';

type Tab = 'overview' | 'client' | 'server' | 'certificates';

interface SessionDetailProps {
  sessionId: string;
  /** Row of the table (shown at once, the details load behind). */
  item: TlsSessionItem;
  onClose: () => void;
}

/** Details of one TLS session: overview, decoded hellos and certificate chain. */
export function SessionDetail({ sessionId, item, onClose }: SessionDetailProps) {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>('overview');
  const detail = useTlsSession(sessionId, item.id);
  const server = `${item.server_ip}:${item.server_port}`;

  let body;
  if (tab === 'overview') body = <Overview item={item} />;
  else if (detail.isPending) body = <Skeleton height={160} />;
  else if (detail.isError)
    body = (
      <ErrorState
        message={t('views.tls.detail.loadError')}
        onRetry={() => {
          void detail.refetch();
        }}
      />
    );
  else if (tab === 'client') body = <ClientHello hello={detail.data.client_hello} />;
  else if (tab === 'server') body = <ServerHello hello={detail.data.server_hello} />;
  else
    body = (
      <Certificates sessionId={sessionId} status={item.cert_status} certificates={detail.data.certificates} />
    );

  return (
    <Card
      title={`${t('views.tls.detail.title')}: ${item.sni ?? server}`}
      actions={
        <Button variant="ghost" icon aria-label={t('views.tls.detail.close')} title={t('views.tls.detail.close')} onClick={onClose}>
          <X aria-hidden size={16} strokeWidth={1.75} />
        </Button>
      }
    >
      <div className="flex flex-col gap-4" data-testid="tls-session-detail">
        <SegmentedControl
          hideLabel
          label={t('views.tls.detail.tabs.label')}
          value={tab}
          options={[
            { value: 'overview', label: t('views.tls.detail.tabs.overview') },
            { value: 'client', label: t('views.tls.detail.tabs.clientHello') },
            { value: 'server', label: t('views.tls.detail.tabs.serverHello') },
            { value: 'certificates', label: t('views.tls.detail.tabs.certificates', { count: item.cert_count }) },
          ]}
          onChange={setTab}
        />
        {body}
      </div>
    </Card>
  );
}

function Overview({ item }: { item: TlsSessionItem }) {
  const { t } = useTranslation();
  const none = <span className="text-muted">{t('views.tls.detail.none')}</span>;
  const version = versionLabel(item.version);
  return (
    <Fields>
      <Field label={t('views.tls.detail.field.time')}>
        <span className="num">{formatTimestamp(item.ts_us)}</span>
      </Field>
      <Field label={t('views.tls.detail.field.client')}>
        <span className="font-mono text-meta">{`${item.client_ip}:${item.client_port}`}</span>
      </Field>
      <Field label={t('views.tls.detail.field.server')}>
        <span className="font-mono text-meta">{`${item.server_ip}:${item.server_port}`}</span>
      </Field>
      <Field label={t('views.tls.detail.field.sni')}>{item.sni ?? none}</Field>
      <Field label={t('views.tls.detail.field.offered')}>{versionLabel(item.offered_version) ?? none}</Field>
      <Field label={t('views.tls.detail.field.version')}>
        {version === null ? none : <Badge tone={versionTone(item.version)}>{version}</Badge>}
      </Field>
      <Field label={t('views.tls.detail.field.suite')}>
        {item.cipher_suite === null ? (
          none
        ) : (
          <SuiteName name={item.cipher_name} id={item.cipher_suite} weak={item.cipher_weak} />
        )}
      </Field>
      <Field label={t('views.tls.detail.field.alpnOffered')}>
        {item.alpn_offered.length === 0 ? none : item.alpn_offered.join(', ')}
      </Field>
      <Field label={t('views.tls.detail.field.alpn')}>{item.alpn ?? none}</Field>
      <Field label={t('views.tls.detail.field.ja3')}>
        {item.ja3 === null ? none : <MonoValue value={item.ja3} name={t('views.tls.detail.field.ja3')} />}
      </Field>
      <Field label={t('views.tls.detail.field.ja3Hash')}>
        {item.ja3_hash === null ? none : <MonoValue value={item.ja3_hash} name={t('views.tls.detail.field.ja3Hash')} />}
      </Field>
      <Field label={t('views.tls.detail.field.ja4')}>
        {item.ja4 === null ? none : <MonoValue value={item.ja4} name={t('views.tls.detail.field.ja4')} />}
      </Field>
      <Field label={t('views.tls.detail.field.outcome')}>
        <Badge tone={item.outcome === 'complete' ? 'success' : 'warning'}>
          {item.outcome === 'complete' ? t('views.tls.detail.outcome.complete') : t('views.tls.detail.outcome.partial')}
        </Badge>
      </Field>
      <Field label={t('views.tls.detail.field.resumed')}>
        {item.resumed ? t('views.tls.detail.yes') : t('views.tls.detail.no')}
      </Field>
      <Field label={t('views.tls.detail.field.alert')}>
        {item.alert === null
          ? none
          : t('views.tls.detail.alertFrom', {
              name: alertName(item.alert.description),
              level: item.alert.level === 2 ? t('views.tls.detail.level.fatal') : t('views.tls.detail.level.warning'),
              from: item.alert.from === 'server' ? t('views.tls.detail.from.server') : t('views.tls.detail.from.client'),
            })}
      </Field>
      <Field label={t('views.tls.detail.field.certificates')}>
        <span className="flex flex-wrap items-center gap-1.5">
          <span>{certSummary(t, item)}</span>
          <IssueBadges issues={item.cert_issues} />
        </span>
      </Field>
    </Fields>
  );
}

type T = ReturnType<typeof useTranslation>['t'];

function certSummary(t: T, item: TlsSessionItem): string {
  if (item.cert_status === 'encrypted') return t('views.tls.cert.encrypted');
  if (item.cert_count === 0) return t('views.tls.cert.none');
  return item.leaf_subject_cn ?? String(item.cert_count);
}

function ClientHello({ hello }: { hello: TlsClientHelloInfo | null }) {
  const { t } = useTranslation();
  if (hello === null) return <p className="text-muted">{t('views.tls.detail.noClientHello')}</p>;
  const none = t('views.tls.detail.none');
  return (
    <Fields>
      <Field label={t('views.tls.detail.field.legacyVersion')}>
        {versionLabel(hello.legacy_version)} <span className="text-faint">{hex4(hello.legacy_version)}</span>
      </Field>
      <Field label={t('views.tls.detail.field.random')}>
        <MonoValue value={hello.random} name={t('views.tls.detail.field.random')} />
      </Field>
      <Field label={t('views.tls.detail.field.sessionId')}>
        {hello.session_id === '' ? none : <MonoValue value={hello.session_id} name={t('views.tls.detail.field.sessionId')} />}
      </Field>
      <Field label={t('views.tls.detail.field.sessionTicket')}>
        {hello.session_ticket ? t('views.tls.detail.yes') : t('views.tls.detail.no')}
      </Field>
      <Field label={t('views.tls.detail.field.supportedVersions')}>
        <CodeList values={hello.supported_versions} empty={none} />
      </Field>
      <Field label={t('views.tls.detail.field.suites')}>
        <CodeList values={hello.cipher_suites} empty={none} />
      </Field>
      <Field label={t('views.tls.detail.field.extensions')}>
        <CodeList values={hello.extensions} empty={none} />
      </Field>
      <Field label={t('views.tls.detail.field.groups')}>
        <CodeList values={hello.groups} empty={none} />
      </Field>
      <Field label={t('views.tls.detail.field.keyShares')}>
        <CodeList values={hello.key_share_groups} empty={none} />
      </Field>
      <Field label={t('views.tls.detail.field.sigAlgs')}>
        <CodeList values={hello.signature_algorithms} empty={none} />
      </Field>
      <Field label={t('views.tls.detail.field.pointFormats')}>
        <span className="font-mono text-meta">{hello.point_formats.length === 0 ? none : hello.point_formats.join(', ')}</span>
      </Field>
      <Field label={t('views.tls.detail.field.compressions')}>
        <span className="font-mono text-meta">{hello.compressions.join(', ')}</span>
      </Field>
    </Fields>
  );
}

function ServerHello({ hello }: { hello: TlsServerHelloInfo | null }) {
  const { t } = useTranslation();
  if (hello === null) return <p className="text-muted">{t('views.tls.detail.noServerHello')}</p>;
  const none = t('views.tls.detail.none');
  return (
    <Fields>
      <Field label={t('views.tls.detail.field.legacyVersion')}>
        {versionLabel(hello.legacy_version)} <span className="text-faint">{hex4(hello.legacy_version)}</span>
      </Field>
      <Field label={t('views.tls.detail.field.selectedVersion')}>
        {hello.selected_version === null ? none : versionLabel(hello.selected_version)}
      </Field>
      <Field label={t('views.tls.detail.field.random')}>
        <MonoValue value={hello.random} name={t('views.tls.detail.field.random')} />
      </Field>
      <Field label={t('views.tls.detail.field.sessionId')}>
        {hello.session_id === '' ? none : <MonoValue value={hello.session_id} name={t('views.tls.detail.field.sessionId')} />}
      </Field>
      <Field label={t('views.tls.detail.field.suite')}>
        <CodeList values={[hello.cipher_suite]} empty={none} />
      </Field>
      <Field label={t('views.tls.detail.field.compression')}>
        <span className="font-mono text-meta">{hello.compression}</span>
      </Field>
      <Field label={t('views.tls.detail.field.extensions')}>
        <CodeList values={hello.extensions} empty={none} />
      </Field>
    </Fields>
  );
}

function Certificates({
  sessionId,
  status,
  certificates,
}: {
  sessionId: string;
  status: string;
  certificates: readonly TlsCertificateInfo[];
}) {
  const { t } = useTranslation();
  if (status === 'encrypted') return <p className="text-muted">{t('views.tls.detail.certEncrypted')}</p>;
  if (certificates.length === 0) return <p className="text-muted">{t('views.tls.detail.noCertificate')}</p>;
  return (
    <ol className="flex flex-col gap-3" aria-label={t('views.tls.detail.field.certificates')}>
      {certificates.map((c, i) => (
        <li key={`${i}-${c.sha256}`} className="min-w-0 rounded-md border border-line p-3">
          <CertificateCard sessionId={sessionId} certificate={c} position={i} />
        </li>
      ))}
    </ol>
  );
}

/** Key fields of one certificate, with its download buttons. */
export function CertificateCard({
  sessionId,
  certificate: c,
  position,
}: {
  sessionId: string;
  certificate: TlsCertificateInfo;
  position?: number;
}) {
  const { t } = useTranslation();
  const none = t('views.tls.detail.none');
  const name = c.subject_cn ?? c.sha256.slice(0, 12);
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-1.5">
          {position !== undefined && (
            <Badge>{position === 0 ? t('views.tls.detail.leaf') : t('views.tls.detail.position', { position: position + 1 })}</Badge>
          )}
          <span data-testid="truncatable" title={c.subject ?? name} className="min-w-0 truncate font-medium">
            {name}
          </span>
          <CertificateBadges certificate={c} />
        </div>
        <DownloadButtons sessionId={sessionId} certificate={c} />
      </div>
      {!c.parsed && <p className="text-muted">{t('views.tls.detail.notParsed')}</p>}
      <Fields>
        {c.parsed && (
          <>
            <Field label={t('views.tls.detail.field.subject')}>{c.subject ?? none}</Field>
            <Field label={t('views.tls.detail.field.issuer')}>{c.issuer ?? none}</Field>
            <Field label={t('views.tls.detail.field.validity')}>
              <span className="num">
                {c.not_before_us === null || c.not_after_us === null
                  ? none
                  : t('views.tls.detail.validFromTo', { from: formatDate(c.not_before_us), to: formatDate(c.not_after_us) })}
              </span>
            </Field>
            <Field label={t('views.tls.detail.field.san')}>{c.san.length === 0 ? none : c.san.join(', ')}</Field>
            <Field label={t('views.tls.detail.field.key')}>
              {c.key_algorithm === null
                ? none
                : c.key_bits === null
                  ? c.key_algorithm
                  : t('views.tls.detail.bits', { algorithm: c.key_algorithm, bits: c.key_bits })}
            </Field>
            <Field label={t('views.tls.detail.field.signature')}>{c.signature_algorithm ?? none}</Field>
            <Field label={t('views.tls.detail.field.serial')}>
              <span className="font-mono text-meta">{c.serial ?? none}</span>
            </Field>
          </>
        )}
        <Field label={t('views.tls.detail.field.sha256')}>
          <MonoValue value={c.sha256} name={t('views.tls.detail.field.sha256')} />
        </Field>
        <Field label={t('views.tls.detail.field.sha1')}>
          <MonoValue value={c.sha1} name={t('views.tls.detail.field.sha1')} />
        </Field>
        <Field label={t('views.tls.detail.field.size')}>
          <span className="num">{formatBytes(c.size)}</span>
        </Field>
      </Fields>
    </div>
  );
}

/** Expired, not yet valid, self-signed and CA badges of a certificate. */
export function CertificateBadges({ certificate: c }: { certificate: TlsCertificateInfo }) {
  const { t } = useTranslation();
  return (
    <>
      {c.expired && <Badge tone="danger">{t('views.tls.cert.expired')}</Badge>}
      {c.not_yet_valid && <Badge tone="danger">{t('views.tls.cert.notYetValid')}</Badge>}
      {c.self_signed && !c.is_ca && <Badge tone="warning">{t('views.tls.cert.selfSigned')}</Badge>}
      {c.is_ca && <Badge>{t('views.tls.cert.ca')}</Badge>}
    </>
  );
}

/** DER and PEM downloads (files only, never shown in the webview). */
export function DownloadButtons({ sessionId, certificate: c }: { sessionId: string; certificate: TlsCertificateInfo }) {
  const { t } = useTranslation();
  const [failed, setFailed] = useState(false);
  const name = c.subject_cn ?? c.sha256.slice(0, 12);
  const download = (format: 'der' | 'pem') => {
    setFailed(false);
    downloadCertificate(sessionId, c.sha256, format).catch(() => {
      setFailed(true);
    });
  };
  const unavailable = c.downloadable ? undefined : t('views.tls.download.unavailable');
  return (
    <span className="flex shrink-0 items-center gap-1">
      {(['der', 'pem'] as const).map((format) => {
        const label = t(format === 'der' ? 'views.tls.download.derLabel' : 'views.tls.download.pemLabel', { name });
        return (
          <Button
            key={format}
            variant="secondary"
            disabled={!c.downloadable}
            aria-label={label}
            title={unavailable ?? label}
            onClick={(e) => {
              e.stopPropagation();
              download(format);
            }}
            className="h-7 px-2"
          >
            <Download aria-hidden size={14} strokeWidth={1.75} />
            {t(format === 'der' ? 'views.tls.download.der' : 'views.tls.download.pem')}
          </Button>
        );
      })}
      {failed && (
        <span role="alert" className="text-meta text-danger">
          {t('views.tls.download.error')}
        </span>
      )}
    </span>
  );
}
