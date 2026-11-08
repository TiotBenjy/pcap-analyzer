import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type { ModuleCount } from '../../api/types/ModuleCount';
import { Badge } from '../../components/Badge';
import { Skeleton } from '../../components/Skeleton';
import { cn } from '../../lib/cn';
import { formatCount } from '../../lib/format';
import { MODULE_ITEMS, type ModuleId, moduleState, REASON_KEYS } from './modules';

interface ModuleGridProps {
  sessionId: string;
  /** `null` while the summary loads. */
  modules: readonly ModuleCount[] | null;
}

/** One card per analysis view: icon, title, one-line description, counter (1/2/3/4 columns). */
export function ModuleGrid({ sessionId, modules }: ModuleGridProps) {
  const { t } = useTranslation();
  const counts = new Map((modules ?? []).map((m) => [m.id, m.count]));
  return (
    <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      {MODULE_ITEMS.map((item) => {
        const state = moduleState(item, counts);
        const Icon = item.icon;
        const title = t(`nav.items.${item.id}`);
        const description = t(`views.overview.modules.${item.id as ModuleId}`);
        const body = (
          <>
            <div className="flex items-start justify-between gap-2">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-subtle text-muted">
                <Icon aria-hidden size={16} strokeWidth={1.75} />
              </span>
              {modules === null ? (
                <Skeleton className="h-5 w-10" />
              ) : (
                state.count !== null && <Badge>{formatCount(state.count)}</Badge>
              )}
            </div>
            <h3 className="mt-3 truncate text-card font-medium">{title}</h3>
            <p data-testid="truncatable" title={description} className="mt-0.5 line-clamp-2 min-h-10 text-muted">
              {description}
            </p>
          </>
        );
        const base = 'block h-full min-w-0 rounded-lg border border-line bg-surface p-3 sm:p-4';
        return (
          <li key={item.id} className="min-w-0">
            {state.active ? (
              <Link
                to={`/sessions/$sessionId${item.path}`}
                params={{ sessionId }}
                className={cn(base, 'hover:border-accent hover:bg-subtle')}
              >
                {body}
              </Link>
            ) : (
              <div
                aria-disabled="true"
                title={modules === null || state.reason === null ? undefined : t(REASON_KEYS[state.reason])}
                className={cn(base, 'opacity-60')}
              >
                {body}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
