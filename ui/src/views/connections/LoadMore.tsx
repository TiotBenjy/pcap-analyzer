import { useTranslation } from 'react-i18next';
import { Button } from '../../components/Button';
import { formatCount } from '../../lib/format';

interface LoadMoreProps {
  shown: number;
  total: number | null;
  hasMore: boolean;
  loading: boolean;
  onMore: () => void;
}

/** Footer of a keyset-paginated list: rows shown out of the total, and the next page. */
export function LoadMore({ shown, total, hasMore, loading, onMore }: LoadMoreProps) {
  const { t } = useTranslation();
  if (!hasMore && (total === null || total <= shown)) return null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-3 py-2 sm:px-4">
      <span className="num text-meta text-muted">
        {total === null ? formatCount(shown) : t('common.shownOf', { shown: formatCount(shown), total: formatCount(total) })}
      </span>
      {hasMore && (
        <Button variant="secondary" disabled={loading} onClick={onMore}>
          {t('common.loadMore')}
        </Button>
      )}
    </div>
  );
}
