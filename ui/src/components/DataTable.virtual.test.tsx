import type * as ReactVirtual from '@tanstack/react-virtual';
import type { Virtualizer } from '@tanstack/react-virtual';
import type { ColumnDef } from '@tanstack/react-table';
import { render } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import '../i18n';
import { setViewportWide } from '../test/renderApp';
import { DataTable, VIRTUALIZE_THRESHOLD } from './DataTable';

// Counts the size resets of the table's virtualizer.
const measured = vi.fn();
vi.mock('@tanstack/react-virtual', async (importOriginal) => {
  const actual = await importOriginal<typeof ReactVirtual>();
  const wrapped = new WeakSet<object>();
  return {
    ...actual,
    useVirtualizer: (options: Parameters<typeof actual.useVirtualizer>[0]) => {
      const v: Virtualizer<Element, Element> = actual.useVirtualizer(options);
      if (!wrapped.has(v)) {
        wrapped.add(v);
        const measure = v.measure.bind(v);
        v.measure = () => {
          measured();
          measure();
        };
      }
      return v;
    },
  };
});

interface Row {
  id: string;
}
const rows: Row[] = Array.from({ length: VIRTUALIZE_THRESHOLD + 10 }, (_, i) => ({ id: String(i) }));
const columns: ColumnDef<Row, unknown>[] = [{ id: 'id', header: 'Id', meta: { card: 'title' }, cell: ({ row }) => row.original.id }];

describe('DataTable virtualization', () => {
  it('measures again when switching between rows and cards', () => {
    setViewportWide(true);
    const table = <DataTable columns={columns} data={rows} getRowId={(r) => r.id} ariaLabel="Flows" cards />;
    const { rerender } = render(table);
    const before = measured.mock.calls.length;
    setViewportWide(false);
    rerender(<DataTable columns={columns} data={rows} getRowId={(r) => r.id} ariaLabel="Flows" cards />);
    expect(measured.mock.calls.length).toBeGreaterThan(before);
    const cards = measured.mock.calls.length;
    rerender(<DataTable columns={columns} data={rows} getRowId={(r) => r.id} ariaLabel="Flows" cards />);
    // No reset while the mode stays the same.
    expect(measured.mock.calls.length).toBe(cards);
  });
});
