import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import '../i18n';
import { setupUser } from '../test/user';
import { ExpandableList } from './ExpandableList';

interface Item {
  id: string;
  name: string;
}

const ITEMS: Item[] = [
  { id: 'a', name: 'First' },
  { id: 'b', name: 'Second' },
];

function renderList(overrides: { hasMore?: boolean; onLoadMore?: () => void } = {}) {
  return render(
    <ExpandableList
      items={ITEMS}
      getKey={(i) => i.id}
      ariaLabel="Items"
      header={<div>Name</div>}
      renderRow={(i) => i.name}
      renderDetail={(i) => `Detail of ${i.name}`}
      rowLabel={(i) => `Show ${i.name}`}
      hasMore={overrides.hasMore ?? false}
      loadingMore={false}
      onLoadMore={overrides.onLoadMore ?? vi.fn()}
    />,
  );
}

describe('ExpandableList', () => {
  it('expands and folds a row in place', async () => {
    const user = setupUser();
    renderList();
    expect(screen.getByRole('list', { name: 'Items' })).toBeInTheDocument();
    expect(screen.getByText('Name')).toBeInTheDocument();
    const row = screen.getByRole('button', { name: 'Show First' });
    expect(row).toHaveAttribute('aria-expanded', 'false');
    await user.click(row);
    expect(row).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('Detail of First')).toBeInTheDocument();
    expect(screen.queryByText('Detail of Second')).not.toBeInTheDocument();
    await user.click(row);
    expect(screen.queryByText('Detail of First')).not.toBeInTheDocument();
  });

  it('loads the next page on request', async () => {
    const user = setupUser();
    const onLoadMore = vi.fn();
    renderList({ hasMore: true, onLoadMore });
    await user.click(screen.getByRole('button', { name: 'Load more' }));
    expect(onLoadMore).toHaveBeenCalled();
  });
});
