import { Outlet, useRouterState } from '@tanstack/react-router';
import { Menu, Moon, Sun } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { findNavItem } from '../app/nav';
import { readPref, writePref } from '../lib/storage';
import { useTheme } from '../theme/theme';
import { Button } from './Button';
import { Sidebar } from './Sidebar';

const COLLAPSED_KEY = 'netsift.sidebar.collapsed';

/**
 * Application frame. >= 1024 px: fixed 240 px sidebar (collapsible to 56 px).
 * < 1024 px: sidebar becomes a modal drawer opened from the header menu button.
 *
 * The main column never hides horizontal overflow: a view that overflows is a bug that the
 * screenshot tests must see (docs/UI_GUIDELINES.md).
 */
export function AppShell() {
  const { t } = useTranslation();
  const { theme, setPref } = useTheme();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const current = findNavItem(pathname);
  const [collapsed, setCollapsed] = useState(() => readPref(COLLAPSED_KEY) === '1');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);
  const wasOpen = useRef(false);

  // Close the drawer on navigation.
  const [lastPath, setLastPath] = useState(pathname);
  if (lastPath !== pathname) {
    setLastPath(pathname);
    setDrawerOpen(false);
  }

  // Drawer focus management: focus inside on open, Escape closes, focus returns to the trigger.
  useEffect(() => {
    if (drawerOpen) {
      wasOpen.current = true;
      drawerRef.current?.querySelector<HTMLElement>('button, a[href]')?.focus();
      const onKey = (e: KeyboardEvent) => {
        if (e.key === 'Escape') setDrawerOpen(false);
      };
      window.addEventListener('keydown', onKey);
      return () => {
        window.removeEventListener('keydown', onKey);
      };
    }
    if (wasOpen.current) {
      wasOpen.current = false;
      menuButtonRef.current?.focus();
    }
    return undefined;
  }, [drawerOpen]);

  const toggleCollapsed = () => {
    const next = !collapsed;
    writePref(COLLAPSED_KEY, next ? '1' : null);
    setCollapsed(next);
  };

  return (
    <div className="flex h-full min-h-0">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2"
      >
        {t('app.skipToContent')}
      </a>

      {/* Desktop sidebar */}
      <div className="hidden shrink-0 lg:flex">
        <Sidebar collapsed={collapsed} onToggleCollapsed={toggleCollapsed} />
      </div>

      {/* Mobile / tablet drawer (modal: the rest of the page is inert while it is open) */}
      {drawerOpen && (
        <div
          ref={drawerRef}
          className="fixed inset-0 z-40 lg:hidden"
          role="dialog"
          aria-modal="true"
          aria-label={t('nav.drawer')}
        >
          <button
            type="button"
            tabIndex={-1}
            aria-hidden
            className="absolute inset-0 bg-zinc-950/40"
            onClick={() => {
              setDrawerOpen(false);
            }}
          />
          <div className="relative flex h-full w-60 max-w-[85vw]">
            <Sidebar
              collapsed={false}
              onClose={() => {
                setDrawerOpen(false);
              }}
            />
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col" inert={drawerOpen}>
        <header className="flex h-12 shrink-0 items-center gap-2 border-b border-line bg-surface px-3 sm:px-4">
          <Button
            ref={menuButtonRef}
            variant="ghost"
            icon
            className="lg:hidden"
            aria-label={t('nav.openMenu')}
            aria-expanded={drawerOpen}
            onClick={() => {
              setDrawerOpen(true);
            }}
          >
            <Menu aria-hidden size={20} strokeWidth={1.75} />
          </Button>
          <span className="min-w-0 truncate font-medium lg:hidden">
            {current === undefined ? t('app.name') : t(`nav.items.${current.id}`)}
          </span>
          <div className="ml-auto flex items-center gap-1">
            <Button
              variant="ghost"
              icon
              aria-label={t('theme.toggle')}
              title={t('theme.toggle')}
              onClick={() => {
                setPref(theme === 'dark' ? 'light' : 'dark');
              }}
            >
              {theme === 'dark' ? (
                <Sun aria-hidden size={16} strokeWidth={1.75} />
              ) : (
                <Moon aria-hidden size={16} strokeWidth={1.75} />
              )}
            </Button>
          </div>
        </header>

        <main id="main" className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1600px] p-3 sm:p-4 lg:p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
