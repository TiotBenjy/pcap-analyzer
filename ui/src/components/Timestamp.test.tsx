import { act, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import i18n from '../i18n';
import { timeZoneLabel } from '../lib/format';
import { Timestamp } from './Timestamp';

describe('Timestamp', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  const us = new Date(2026, 10, 8, 14, 3, 12).getTime() * 1000 + 250;

  it('shows the local ISO time, the microseconds and the zone on hover', () => {
    render(<Timestamp us={us} className="text-muted" />);
    const time = screen.getByText('2026-11-08 14:03:12');
    expect(time.tagName).toBe('TIME');
    expect(time).toHaveClass('num', 'text-muted');
    expect(time).toHaveAttribute('title', `2026-11-08 14:03:12.000250 ${timeZoneLabel()}`);
    expect(time.getAttribute('datetime')).toMatch(/^2026-11-0[78]T\d{2}:03:12\.000Z$/);
  });

  it('drops the date on request and renders nothing without a time', () => {
    const { container, rerender } = render(<Timestamp us={us} withDate={false} />);
    expect(screen.getByText('14:03:12')).toBeInTheDocument();
    rerender(<Timestamp us={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('writes the same time in French', async () => {
    await act(async () => {
      await i18n.changeLanguage('fr');
    });
    render(<Timestamp us={us} />);
    expect(screen.getByText('2026-11-08 14:03:12')).toBeInTheDocument();
  });
});
