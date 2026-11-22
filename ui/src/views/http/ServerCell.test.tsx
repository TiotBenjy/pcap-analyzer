import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import '../../i18n';
import { tx } from '../../test/httpFixtures';
import { ServerCell } from './shared';

describe('HTTP server cell', () => {
  it('shows the host alone, the address and port in its tooltip', () => {
    render(<ServerCell tx={tx(1)} />);
    const cell = screen.getByTestId('truncatable');
    expect(cell).toHaveTextContent(/^portal.example.test$/);
    expect(cell).toHaveAttribute('title', 'portal.example.test 203.0.113.10:80 portal.example.test FR');
    // The address is never shown cut next to the host.
    expect(screen.queryByText(/203\.0\.113\.10/)).toBeNull();
  });

  it('shows the address and port without a host, or with the address as host', () => {
    const { rerender } = render(<ServerCell tx={tx(1, { host: null })} />);
    expect(screen.getByTestId('truncatable')).toHaveTextContent(/^203.0.113.10:80$/);
    rerender(<ServerCell tx={tx(1, { host: '203.0.113.10' })} />);
    expect(screen.getByTestId('truncatable')).toHaveTextContent(/^203.0.113.10:80$/);
  });
});
