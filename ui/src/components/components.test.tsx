import '../i18n';
import type { ColumnDef } from '@tanstack/react-table';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { Badge } from './Badge';
import { Chart } from './Chart';
import { DataTable } from './DataTable';
import { EmptyState } from './EmptyState';
import { type FilterOption, FilterBar } from './FilterBar';
import { MultiSelect } from './MultiSelect';
import { StatCard } from './StatCard';
import { Toggle } from './Toggle';

describe('Toggle', () => {
  it('is an accessible switch that reports the new state', async () => {
    const onChange = vi.fn();
    render(<Toggle label="DNS" checked={false} onChange={onChange} count={1234} />);
    const sw = screen.getByRole('switch', { name: /DNS/ });
    expect(sw).toHaveAttribute('aria-checked', 'false');
    await userEvent.click(sw);
    expect(onChange).toHaveBeenCalledWith(true);
  });
});

describe('FilterBar', () => {
  function Harness() {
    const [filters, setFilters] = useState<FilterOption[]>([
      { id: 'a', label: 'Alpha', count: 3, active: true },
      { id: 'b', label: 'Beta', count: 0, active: false },
    ]);
    return (
      <FilterBar
        filters={filters}
        onToggle={(id, active) => {
          setFilters((fs) => fs.map((f) => (f.id === id ? { ...f, active } : f)));
        }}
        onSetAll={(active) => {
          setFilters((fs) => fs.map((f) => ({ ...f, active })));
        }}
      />
    );
  }

  it('toggles one filter and all filters', async () => {
    render(<Harness />);
    const inline = within(screen.getByTestId('filterbar-inline'));
    await userEvent.click(inline.getByRole('switch', { name: /Beta/ }));
    expect(inline.getByRole('switch', { name: /Beta/ })).toHaveAttribute('aria-checked', 'true');
    await userEvent.click(inline.getByRole('button', { name: 'Disable all' }));
    for (const sw of inline.getAllByRole('switch')) expect(sw).toHaveAttribute('aria-checked', 'false');
  });
});

describe('DataTable', () => {
  interface Row {
    ip: string;
    bytes: number;
  }
  const columns: ColumnDef<Row, unknown>[] = [
    { accessorKey: 'ip', header: 'IP' },
    { accessorKey: 'bytes', header: 'Bytes' },
  ];

  it('renders rows and sorts on header click (numbers: descending first)', async () => {
    const data: Row[] = [
      { ip: '10.0.0.2', bytes: 20 },
      { ip: '10.0.0.1', bytes: 10 },
    ];
    render(<DataTable ariaLabel="Hosts" columns={columns} data={data} getRowId={(r) => r.ip} />);
    const table = screen.getByRole('table', { name: 'Hosts' });
    expect(within(table).getAllByRole('row')).toHaveLength(3);
    const firstIp = () => within(table).getAllByRole('row')[1]?.querySelector('td');
    const sortBytes = within(table).getByRole('button', { name: 'Bytes' });
    await userEvent.click(sortBytes);
    expect(sortBytes.closest('th')).toHaveAttribute('aria-sort', 'descending');
    expect(firstIp()).toHaveTextContent('10.0.0.2');
    await userEvent.click(sortBytes);
    expect(sortBytes.closest('th')).toHaveAttribute('aria-sort', 'ascending');
    expect(firstIp()).toHaveTextContent('10.0.0.1');
  });

  it('shows an explicit empty state', () => {
    render(<DataTable ariaLabel="Hosts" columns={columns} data={[]} getRowId={(r) => r.ip} emptyText="Nothing" />);
    expect(screen.getByRole('status')).toHaveTextContent('Nothing');
  });
});

describe('Chart', () => {
  it('renders the empty state instead of a blank chart', () => {
    render(<Chart option={{}} height={240} ariaLabel="x" empty emptyText="No traffic" />);
    expect(screen.getByRole('status')).toHaveTextContent('No traffic');
  });
  it('renders the error state with retry', async () => {
    const onRetry = vi.fn();
    render(<Chart option={{}} height={240} ariaLabel="x" error="Failed" onRetry={onRetry} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Failed');
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalled();
  });
});

describe('EmptyState and Badge', () => {
  it('renders text content', () => {
    render(
      <>
        <EmptyState title="Empty" description="Nothing here" />
        <Badge>42</Badge>
      </>,
    );
    expect(screen.getByText('Nothing here')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
  });
});

describe('StatCard', () => {
  it('shows the value with its full title, or a placeholder while loading', () => {
    const { rerender } = render(<StatCard label="Packets" value={null} />);
    expect(screen.queryByTestId('truncatable')).toBeNull();
    rerender(<StatCard label="Packets" value="1.2 MiB" title="1,258,291 B" hint="Link: Ethernet" />);
    expect(screen.getByTestId('truncatable')).toHaveAttribute('title', '1,258,291 B');
    expect(screen.getByText('Link: Ethernet')).toBeInTheDocument();
  });
});

describe('MultiSelect', () => {
  it('reports the new selection and closes on Escape', async () => {
    const onChange = vi.fn();
    const options = [
      { value: 'dns', label: 'DNS', detail: '3' },
      { value: 'tls', label: 'TLS' },
    ] as const;
    render(<MultiSelect label="Protocols" options={options} selected={new Set(['dns'])} onChange={onChange} />);
    const button = screen.getByRole('button', { name: /Protocols/ });
    expect(button).toHaveTextContent('1/2');
    await userEvent.click(button);
    await userEvent.click(screen.getByRole('checkbox', { name: /TLS/ }));
    expect(onChange).toHaveBeenLastCalledWith(new Set(['dns', 'tls']));
    await userEvent.click(screen.getByRole('button', { name: 'None' }));
    expect(onChange).toHaveBeenLastCalledWith(new Set());
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('group', { name: 'Protocols' })).toBeNull();
    expect(button).toHaveFocus();
  });
});
