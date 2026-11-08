import type { ColumnDef } from '@tanstack/react-table';
import { ShieldCheck } from 'lucide-react';
import { useDeferredValue, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useTlsCertificates } from '../../api/tlsQueries';
import type { TlsCertificateItem } from '../../api/types/TlsCertificateItem';
import { Card } from '../../components/Card';
import { DataTable } from '../../components/DataTable';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar } from '../../components/FilterBar';
import { Skeleton } from '../../components/Skeleton';
import { formatCount } from '../../lib/format';
import { MonoValue } from './parts';
import { CertificateBadges, CertificateCard, DownloadButtons } from './SessionDetail';
import { formatDate } from './tlsFormat';

/** Deduplicated certificates (by SHA-256) with the number of sessions using each. */
export function CertificatesPanel({ sessionId, enabled, total }: { sessionId: string; enabled: boolean; total: number }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [problems, setProblems] = useState(false);
  const q = useDeferredValue(search);
  const list = useTlsCertificates(sessionId, { q, problems }, enabled);
  const [selected, setSelected] = useState<string | null>(null);

  const columns = useMemo<ColumnDef<TlsCertificateItem, unknown>[]>(
    () => [
      {
        id: 'subject',
        accessorFn: (r) => r.certificate.subject_cn ?? '',
        header: t('views.tls.certificates.col.subject'),
        size: 220,
        cell: ({ row }) => {
          const c = row.original.certificate;
          const text = c.subject_cn ?? c.sha256.slice(0, 12);
          return (
            <span data-testid="truncatable" title={c.subject ?? text} className="block truncate">
              {text}
            </span>
          );
        },
      },
      {
        id: 'issuer',
        accessorFn: (r) => r.certificate.issuer_cn ?? '',
        header: t('views.tls.certificates.col.issuer'),
        size: 180,
        cell: ({ row }) => {
          const c = row.original.certificate;
          const text = c.issuer_cn ?? '';
          return (
            <span data-testid="truncatable" title={c.issuer ?? text} className="block truncate text-muted">
              {text}
            </span>
          );
        },
      },
      {
        id: 'validUntil',
        accessorFn: (r) => r.certificate.not_after_us ?? 0,
        header: t('views.tls.certificates.col.validUntil'),
        size: 112,
        cell: ({ row }) => {
          const until = row.original.certificate.not_after_us;
          return <span className="num">{until === null ? '' : formatDate(until)}</span>;
        },
      },
      {
        id: 'flags',
        accessorFn: (r) => Number(r.certificate.expired) * 2 + Number(r.certificate.self_signed),
        header: t('views.tls.certificates.col.flags'),
        size: 168,
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex min-w-0 items-center gap-1 overflow-hidden">
            <CertificateBadges certificate={row.original.certificate} />
          </span>
        ),
      },
      {
        id: 'key',
        accessorFn: (r) => `${r.certificate.key_algorithm ?? ''} ${r.certificate.key_bits ?? ''}`,
        header: t('views.tls.certificates.col.key'),
        size: 96,
        cell: ({ row }) => {
          const c = row.original.certificate;
          return (
            <span className="font-mono text-meta">
              {c.key_algorithm ?? ''} {c.key_bits ?? ''}
            </span>
          );
        },
      },
      {
        id: 'sessions',
        accessorFn: (r) => r.sessions,
        header: t('views.tls.certificates.col.sessions'),
        size: 88,
        meta: { align: 'right' },
        cell: ({ row }) => <span className="num">{formatCount(row.original.sessions)}</span>,
      },
      {
        id: 'sha256',
        accessorFn: (r) => r.certificate.sha256,
        header: t('views.tls.certificates.col.sha256'),
        size: 180,
        cell: ({ row }) => (
          <MonoValue value={row.original.certificate.sha256} name={t('views.tls.certificates.col.sha256')} />
        ),
      },
      {
        id: 'download',
        header: t('views.tls.certificates.col.download'),
        size: 152,
        enableSorting: false,
        cell: ({ row }) => <DownloadButtons sessionId={sessionId} certificate={row.original.certificate} />,
      },
    ],
    [t, sessionId],
  );

  let body;
  if (list.isPending) body = <Skeleton height={160} />;
  else if (list.isError)
    body = (
      <ErrorState
        message={t('views.tls.loadError')}
        onRetry={() => {
          void list.refetch();
        }}
      />
    );
  else if (total === 0) body = <EmptyState icon={ShieldCheck} title={t('views.tls.certificates.noCertificates')} />;
  else
    body = (
      <>
        <DataTable
          columns={columns}
          data={list.data.items}
          getRowId={(r) => r.certificate.sha256}
          ariaLabel={t('views.tls.certificates.label')}
          emptyText={t('views.tls.certificates.empty')}
          onRowClick={(r) => {
            setSelected((s) => (s === r.certificate.sha256 ? null : r.certificate.sha256));
          }}
        />
        {list.data.truncated && (
          <p className="border-t border-line px-3 py-2 text-meta text-muted sm:px-4">
            {t('views.tls.certificates.truncated', { count: list.data.items.length })}
          </p>
        )}
      </>
    );

  const current = list.data?.items.find((r) => r.certificate.sha256 === selected);

  return (
    <div className="flex flex-col gap-4">
      <FilterBar
        filters={[{ id: 'problems', label: t('views.tls.certificates.problems'), active: problems }]}
        onToggle={(_, active) => {
          setProblems(active);
        }}
        search={search}
        onSearch={setSearch}
        searchPlaceholder={t('views.tls.certificates.search')}
      />
      <Card flush>{body}</Card>
      {current !== undefined && (
        <Card>
          <CertificateCard sessionId={sessionId} certificate={current.certificate} />
        </Card>
      )}
    </div>
  );
}
