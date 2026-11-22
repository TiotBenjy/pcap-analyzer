import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { setupUser } from '../test/user';
import { FilterChip } from './FilterChip';

describe('FilterChip', () => {
  it('shows the filter, truncated with a tooltip, and removes it', async () => {
    const user = setupUser();
    const onRemove = vi.fn();
    render(<FilterChip label="Host example.org" removeLabel="Clear the host filter" onRemove={onRemove} />);
    expect(screen.getByText('Host example.org')).toHaveAttribute('title', 'Host example.org');
    expect(screen.getByText('Host example.org')).toHaveClass('truncate');
    await user.click(screen.getByRole('button', { name: 'Clear the host filter' }));
    expect(onRemove).toHaveBeenCalledTimes(1);
  });
});
