import { flexRender } from '@tanstack/react-table';
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import i18n from '../i18n';
import { WholeSessionHeader, WholeSessionLine } from './WholeSession';
import { wholeSessionHeader } from './wholeSessionHeader';

describe('WholeSession', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('shows the short line in faint text on a line of its own', () => {
    render(<WholeSessionLine className="text-meta" />);
    const line = screen.getByText('Whole session');
    expect(line).toHaveClass('block', 'text-faint', 'font-normal', 'text-meta');
  });

  it('adds the line under the label only under a range', () => {
    const { rerender } = render(<WholeSessionHeader label="Messages" ranged={false} />);
    expect(screen.getByText('Messages')).toBeInTheDocument();
    expect(screen.queryByText('Whole session')).not.toBeInTheDocument();
    rerender(
      <span data-testid="th">
        <WholeSessionHeader label="Messages" ranged className="xl:whitespace-nowrap" />
      </span>,
    );
    expect(screen.getByTestId('th')).toHaveTextContent('MessagesWhole session');
    expect(screen.getByText('Whole session')).toHaveClass('xl:whitespace-nowrap');
  });

  it('is translated', async () => {
    await i18n.changeLanguage('fr');
    render(<WholeSessionHeader label="Messages" ranged />);
    expect(screen.getByText('Session entière')).toBeInTheDocument();
  });

  it('gives a DataTable header: the label as is, a renderer under a range', () => {
    expect(wholeSessionHeader('Frames', false)).toBe('Frames');
    const header = wholeSessionHeader('Frames', true);
    expect(typeof header).toBe('function');
    render(<span data-testid="th">{flexRender(header, {})}</span>);
    expect(screen.getByTestId('th')).toHaveTextContent('FramesWhole session');
  });
});
