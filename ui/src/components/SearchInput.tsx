import { Search } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';

interface SearchInputProps {
  value: string;
  onChange: (value: string) => void;
  /** Placeholder and accessible name; "Search" by default. */
  placeholder?: string;
  /** Width rules of the field in its bar (it grows by default, up to 20 rem from `sm`). */
  className?: string;
  autoFocus?: boolean;
}

/** The only search field of the UI: magnifier icon, 32 px high, grows in a wrapping filter bar. */
export function SearchInput({ value, onChange, placeholder, className, autoFocus = false }: SearchInputProps) {
  const { t } = useTranslation();
  const label = placeholder ?? t('common.search');
  return (
    <label className={cn('relative flex h-8 min-w-0 items-center', className ?? 'flex-1 basis-48 sm:max-w-xs')}>
      <span className="sr-only">{label}</span>
      <Search aria-hidden size={16} strokeWidth={1.75} className="pointer-events-none absolute left-2.5 text-faint" />
      <input
        type="search"
        value={value}
        placeholder={label}
        {...(autoFocus ? { 'data-autofocus': true } : {})}
        onChange={(e) => {
          onChange(e.target.value);
        }}
        className="h-8 w-full min-w-0 rounded-md border border-line bg-surface pr-2 pl-8 text-body placeholder:text-faint"
      />
    </label>
  );
}
