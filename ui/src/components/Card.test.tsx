import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import '../i18n';
import { setupUser } from '../test/user';
import { Card } from './Card';
import { SearchInput } from './SearchInput';

describe('Card filters', () => {
  it('puts the filters in a band of the header, under the title and actions', () => {
    render(
      <Card title="Transactions" actions={<button type="button">Sort</button>} filters={<input aria-label="Query" />}>
        <p>body</p>
      </Card>,
    );
    const header = screen.getByRole('banner');
    const band = within(header).getByRole('group', { name: 'Filters' });
    expect(within(band).getByRole('textbox', { name: 'Query' })).toBeInTheDocument();
    expect(band).toHaveClass('border-t');
    // Title row first, then the band.
    expect(header.firstElementChild).toContainElement(screen.getByRole('heading', { name: 'Transactions' }));
    expect(header.lastElementChild).toBe(band);
  });

  it('draws the band alone without a title, and no header without either', () => {
    const { rerender } = render(<Card filters={<span>f</span>}>x</Card>);
    expect(screen.getByRole('group', { name: 'Filters' })).not.toHaveClass('border-t');
    rerender(<Card>x</Card>);
    expect(screen.queryByRole('banner')).toBeNull();
  });
});

describe('SearchInput', () => {
  it('is named by its placeholder and reports every change', async () => {
    const user = setupUser();
    const onChange = vi.fn();
    render(<SearchInput value="" onChange={onChange} placeholder="Server name or address" />);
    await user.type(screen.getByRole('searchbox', { name: 'Server name or address' }), 'a');
    expect(onChange).toHaveBeenCalledWith('a');
  });

  it('defaults to "Search"', () => {
    render(<SearchInput value="" onChange={() => undefined} />);
    expect(screen.getByRole('searchbox', { name: 'Search' })).toHaveAttribute('placeholder', 'Search');
  });
});
