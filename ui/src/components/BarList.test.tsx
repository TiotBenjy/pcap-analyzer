import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import '../i18n';
import { setupUser } from '../test/user';
import { type BarItem, BarList } from './BarList';

const items: BarItem[] = [
  { key: 'a', label: 'very-long-host-name.example.test', title: 'very-long-host-name.example.test: 1,234', value: 1234, valueText: '1,234' },
  { key: 'b', label: 'b.test', value: 617, valueText: '617', detail: '2 hosts', lead: <span data-testid="lead" /> },
  { key: 'other', label: 'Other', value: 10, valueText: '10', muted: true, selectable: false },
];

const fills = (li: HTMLElement) => [...li.querySelectorAll<HTMLElement>('[aria-hidden] > span')].map((s) => s.style.width);

describe('BarList', () => {
  it('writes every value in full, the label truncated with its tooltip, bars relative to the largest', () => {
    render(<BarList ariaLabel="Top hosts" items={items} />);
    const list = screen.getByRole('list', { name: 'Top hosts' });
    const rows = within(list).getAllByRole('listitem');
    expect(rows).toHaveLength(3);
    expect(within(rows[0] as HTMLElement).getByText('1,234')).toHaveClass('num', 'shrink-0');
    const label = within(rows[0] as HTMLElement).getByTestId('truncatable');
    expect(label).toHaveClass('truncate');
    expect(label).toHaveAttribute('title', 'very-long-host-name.example.test: 1,234');
    expect(fills(rows[0] as HTMLElement)).toEqual(['100%']);
    expect(fills(rows[1] as HTMLElement)).toEqual(['50%']);
    expect(within(rows[1] as HTMLElement).getByText('2 hosts')).toHaveClass('text-muted');
    expect(within(rows[1] as HTMLElement).getByTestId('lead')).toBeInTheDocument();
    expect((rows[2] as HTMLElement).querySelector('[aria-hidden] > span')).toHaveClass('opacity-50');
  });

  it('stacks segments and honours a shared maximum', () => {
    render(
      <BarList
        ariaLabel="Pairs"
        max={200}
        items={[{ key: 'p', label: 'a / b', value: 100, valueText: '100 B', segments: [{ value: 75, color: 'red' }, { value: 25, color: 'blue' }] }]}
      />,
    );
    expect(fills(screen.getByRole('listitem'))).toEqual(['37.5%', '12.5%']);
  });

  it('turns rows into toggle buttons, except unselectable ones', async () => {
    const user = setupUser();
    const onSelect = vi.fn();
    render(
      <BarList
        ariaLabel="Suites"
        items={items.map((i) => ({ ...i, active: i.key === 'b' }))}
        onSelect={onSelect}
        selectLabel={(i) => `Filter ${i.label}`}
      />,
    );
    expect(screen.getAllByRole('button')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Filter b.test' })).toHaveAttribute('aria-pressed', 'true');
    await user.click(screen.getByRole('button', { name: 'Filter very-long-host-name.example.test' }));
    expect(onSelect).toHaveBeenCalledWith('a');
  });

  it('cuts long identifiers in the middle on request', () => {
    render(<BarList ariaLabel="Suites" items={[{ key: 's', label: 'ECDHE_RSA_WITH_AES_128_GCM_SHA256', value: 1, valueText: '1', truncate: 'middle' }]} />);
    expect(screen.getByTestId('truncatable')).toHaveAttribute('title', 'ECDHE_RSA_WITH_AES_128_GCM_SHA256');
    expect(screen.getByText('M_SHA256')).toHaveClass('shrink-0');
  });

  it('has loading, error and empty states', async () => {
    const user = setupUser();
    const onRetry = vi.fn();
    const { rerender } = render(<BarList ariaLabel="x" items={[]} loading />);
    expect(screen.getByText('Loading')).toBeInTheDocument();
    rerender(<BarList ariaLabel="x" items={[]} error="Failed" onRetry={onRetry} />);
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalled();
    rerender(<BarList ariaLabel="x" items={[]} emptyText="Nothing" />);
    expect(screen.getByRole('status')).toHaveTextContent('Nothing');
  });
});
