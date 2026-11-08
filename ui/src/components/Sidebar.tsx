import { Link } from '@tanstack/react-router';
import { PanelLeftClose, PanelLeftOpen, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { NAV_GROUPS, NAV_ITEMS, type NavItem, navHref, SETTINGS_ITEM } from '../app/nav';
import { useActiveSessionId } from '../app/session';
import { cn } from '../lib/cn';
import { Badge } from './Badge';
import { Button } from './Button';

interface SidebarProps {
  collapsed: boolean;
  /** Desktop only: collapse/expand control. */
  onToggleCollapsed?: () => void;
  /** Drawer only: close control. */
  onClose?: () => void;
  /** Item counts per view for the current session (badges); views at 0 are dimmed. */
  counts?: Partial<Record<NavItem['id'], number>>;
}

export function Sidebar({ collapsed, onToggleCollapsed, onClose, counts }: SidebarProps) {
  const { t } = useTranslation();
  // Session views point to the session in the URL, else the last opened one.
  const sessionId = useActiveSessionId();

  return (
    <nav
      aria-label={t('app.name')}
      className={cn(
        'flex h-full flex-col border-r border-line bg-surface',
        collapsed ? 'w-14' : 'w-60',
      )}
    >
      <div className={cn('flex h-12 shrink-0 items-center border-b border-line', collapsed ? 'justify-center' : 'gap-2 px-4')}>
        <img src="./favicon.svg" alt="" width={20} height={20} className="shrink-0" />
        {!collapsed && <span className="truncate font-semibold">{t('app.name')}</span>}
        {onClose !== undefined && (
          <Button variant="ghost" icon className="ml-auto" aria-label={t('nav.closeMenu')} onClick={onClose}>
            <X aria-hidden size={20} strokeWidth={1.75} />
          </Button>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto py-2">
        {NAV_GROUPS.map((group) => (
          <div key={group} className="mb-2">
            {!collapsed && (
              <div className="px-4 pt-2 pb-1 text-meta font-medium tracking-wide text-faint uppercase">
                {t(`nav.groups.${group}`)}
              </div>
            )}
            <ul className="flex flex-col gap-0.5 px-2">
              {NAV_ITEMS.filter((i) => i.group === group).map((item) => (
                <li key={item.id}>
                  <SidebarEntry
                    item={item}
                    href={navHref(item, sessionId)}
                    collapsed={collapsed}
                    count={counts?.[item.id]}
                  />
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="flex shrink-0 flex-col gap-0.5 border-t border-line p-2">
        <SidebarEntry item={SETTINGS_ITEM} href={SETTINGS_ITEM.path} collapsed={collapsed} count={undefined} />
        {onToggleCollapsed !== undefined && (
          <button
            type="button"
            onClick={onToggleCollapsed}
            aria-label={collapsed ? t('nav.expand') : t('nav.collapse')}
            title={collapsed ? t('nav.expand') : t('nav.collapse')}
            className={cn(
              'flex h-8 items-center gap-3 rounded-md text-muted hover:bg-subtle hover:text-fg',
              collapsed ? 'justify-center' : 'px-2',
            )}
          >
            {collapsed ? (
              <PanelLeftOpen aria-hidden size={20} strokeWidth={1.75} />
            ) : (
              <PanelLeftClose aria-hidden size={20} strokeWidth={1.75} />
            )}
            {!collapsed && <span className="truncate">{t('nav.collapse')}</span>}
          </button>
        )}
      </div>
    </nav>
  );
}

interface SidebarEntryProps {
  item: NavItem;
  /** Resolved target; `null` when the view needs a session and none is open. */
  href: string | null;
  collapsed: boolean;
  count: number | undefined;
}

function SidebarEntry({ item, href, collapsed, count }: SidebarEntryProps) {
  const { t } = useTranslation();
  const label = t(`nav.items.${item.id}`);
  const Icon = item.icon;
  const base = cn('flex h-8 items-center gap-3 rounded-md', collapsed ? 'justify-center' : 'px-2');

  if (!item.enabled || href === null) {
    const title = item.enabled ? t('nav.needsSession', { label }) : t('nav.unavailableItem', { label });
    return (
      <span aria-disabled="true" title={title} className={cn(base, 'cursor-not-allowed text-faint opacity-60')}>
        <Icon aria-hidden size={20} strokeWidth={1.75} className="shrink-0" />
        {!collapsed && <span className="truncate">{label}</span>}
        {collapsed && <span className="sr-only">{title}</span>}
      </span>
    );
  }

  return (
    <Link
      to={href}
      title={collapsed ? label : undefined}
      className={cn(base, 'text-muted hover:bg-subtle hover:text-fg', count === 0 && 'opacity-60')}
      activeProps={{ className: 'bg-accent-soft !text-accent font-medium', 'aria-current': 'page' }}
    >
      <Icon aria-hidden size={20} strokeWidth={1.75} className="shrink-0" />
      {!collapsed && <span className="min-w-0 flex-1 truncate">{label}</span>}
      {!collapsed && count !== undefined && <Badge>{count}</Badge>}
      {collapsed && <span className="sr-only">{label}</span>}
    </Link>
  );
}
