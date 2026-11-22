import { ChevronDown } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from './Button';
import { SearchInput } from './SearchInput';
import { Toggle } from './Toggle';

export interface FilterOption {
  id: string;
  label: string;
  count?: number;
  active: boolean;
}

interface FilterBarProps {
  filters: readonly FilterOption[];
  onToggle: (id: string, active: boolean) => void;
  /** Enable (true) or disable (false) every filter. */
  onSetAll?: (active: boolean) => void;
  search?: string;
  onSearch?: (q: string) => void;
  searchPlaceholder?: string;
}

/**
 * Filter toggles with counters, search, and enable/disable all.
 * Wraps cleanly (flex-wrap); below 768 px the toggles move into a "Filters" disclosure menu.
 */
export function FilterBar({ filters, onToggle, onSetAll, search, onSearch, searchPlaceholder }: FilterBarProps) {
  const { t } = useTranslation();
  const activeCount = filters.filter((f) => f.active).length;

  const toggles = filters.map((f) => (
    <Toggle
      key={f.id}
      label={f.label}
      checked={f.active}
      {...(f.count === undefined ? {} : { count: f.count })}
      onChange={(v) => {
        onToggle(f.id, v);
      }}
    />
  ));

  const bulk = onSetAll !== undefined && (
    <div className="flex flex-wrap gap-2">
      <Button
        variant="ghost"
        onClick={() => {
          onSetAll(true);
        }}
      >
        {t('common.enableAll')}
      </Button>
      <Button
        variant="ghost"
        onClick={() => {
          onSetAll(false);
        }}
      >
        {t('common.disableAll')}
      </Button>
    </div>
  );

  return (
    <div className="relative flex min-w-0 flex-wrap items-center gap-2">
      {onSearch !== undefined && (
        <SearchInput value={search ?? ''} onChange={onSearch} placeholder={searchPlaceholder ?? t('common.search')} />
      )}

      {filters.length > 0 && (
        <>
          <div className="hidden min-w-0 flex-wrap items-center gap-2 md:flex" data-testid="filterbar-inline">
            {toggles}
            {bulk}
          </div>

          <details className="group md:hidden" data-testid="filterbar-menu">
            <summary className="inline-flex h-8 cursor-pointer list-none items-center gap-1.5 rounded-md border border-line bg-surface px-3 text-body [&::-webkit-details-marker]:hidden">
              {t('common.filters')}
              <span className="num text-meta text-muted">
                {activeCount}/{filters.length}
              </span>
              <ChevronDown aria-hidden size={16} strokeWidth={1.75} className="group-open:rotate-180" />
            </summary>
            <div className="absolute inset-x-0 top-full z-20 mt-1 flex flex-col gap-2 rounded-lg border border-line bg-surface p-3 shadow-xs">
              {toggles}
              {bulk}
            </div>
          </details>
        </>
      )}
    </div>
  );
}
