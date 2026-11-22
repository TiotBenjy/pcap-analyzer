import type { ColumnDef } from '@tanstack/react-table';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import '../i18n';
import { setViewportWide } from '../test/renderApp';
import { setupUser } from '../test/user';
import { DataTable } from './DataTable';

interface Row {
  id: string;
  host: string;
  bytes: number;
  secret: string;
}

const rows: Row[] = [
  { id: '1', host: 'a.test', bytes: 10, secret: 'x' },
  { id: '2', host: 'b.test', bytes: 20, secret: 'y' },
];

const columns: ColumnDef<Row, unknown>[] = [
  { id: 'host', header: 'Host', meta: { card: 'title' }, cell: ({ row }) => row.original.host },
  { id: 'bytes', header: 'Bytes', meta: { align: 'right' }, cell: ({ row }) => `${row.original.bytes} B` },
  { id: 'secret', header: 'Secret', meta: { card: 'hidden' }, cell: ({ row }) => row.original.secret },
  { id: 'open', header: 'Open', meta: { card: 'action' }, cell: () => <button type="button">Open</button> },
];

describe('DataTable', () => {
  afterEach(() => {
    setViewportWide(true);
  });

  it('stays a table from 768 px, even with cards', () => {
    setViewportWide(true);
    render(<DataTable columns={columns} data={rows} getRowId={(r) => r.id} ariaLabel="Flows" cards />);
    expect(screen.getByRole('table', { name: 'Flows' })).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Flows' })).toBeNull();
  });

  it('draws one card per row below 768 px: title, action, then labelled lines', async () => {
    setViewportWide(false);
    const onRowClick = vi.fn();
    render(<DataTable columns={columns} data={rows} getRowId={(r) => r.id} ariaLabel="Flows" cards onRowClick={onRowClick} />);
    expect(screen.queryByRole('table')).toBeNull();
    const cards = within(screen.getByRole('list', { name: 'Flows' })).getAllByRole('listitem');
    expect(cards).toHaveLength(2);
    const first = within(cards[0] as HTMLElement);
    expect(first.getByText('a.test')).toBeInTheDocument();
    expect(first.getByRole('button', { name: 'Open' })).toBeInTheDocument();
    expect(first.getByRole('term')).toHaveTextContent('Bytes');
    expect(first.getByRole('definition')).toHaveTextContent('10 B');
    expect(first.queryByText('x')).toBeNull();
    await setupUser().click(first.getByText('a.test'));
    expect(onRowClick).toHaveBeenCalledWith(rows[0]);
  });

  it('leaves Enter and Space on a nested button to that button, in rows and cards', () => {
    for (const wide of [true, false]) {
      setViewportWide(wide);
      const onRowClick = vi.fn();
      const { unmount } = render(
        <DataTable columns={columns} data={rows} getRowId={(r) => r.id} ariaLabel="Flows" cards onRowClick={onRowClick} />,
      );
      const button = screen.getAllByRole('button', { name: 'Open' })[0] as HTMLElement;
      fireEvent.keyDown(button, { key: 'Enter' });
      fireEvent.keyDown(button, { key: ' ' });
      expect(onRowClick).not.toHaveBeenCalled();
      // On the row (or card) itself, Enter still opens it.
      const row = button.closest('[tabindex="0"]') as HTMLElement;
      fireEvent.keyDown(row, { key: 'Enter' });
      expect(onRowClick).toHaveBeenCalledWith(rows[0]);
      unmount();
    }
  });

  it('keeps the table below 768 px without cards (scrolling inside its container)', () => {
    setViewportWide(false);
    render(<DataTable columns={columns} data={rows} getRowId={(r) => r.id} ariaLabel="Flows" />);
    expect(screen.getByRole('table', { name: 'Flows' })).toBeInTheDocument();
  });
});
