import type { LucideIcon } from 'lucide-react';
import { Inbox } from 'lucide-react';
import type { ReactNode } from 'react';

interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: LucideIcon;
  action?: ReactNode;
}

/** Explicit empty state: neutral icon, one short sentence, optional action. Never a blank block. */
export function EmptyState({ title, description, icon: Icon = Inbox, action }: EmptyStateProps) {
  return (
    <div role="status" className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
      <Icon aria-hidden size={20} strokeWidth={1.75} className="text-faint" />
      <p className="font-medium">{title}</p>
      {description !== undefined && <p className="max-w-prose text-muted">{description}</p>}
      {action !== undefined && <div className="mt-2">{action}</div>}
    </div>
  );
}
