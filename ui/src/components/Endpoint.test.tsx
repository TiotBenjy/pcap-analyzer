import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import '../i18n';
import { setupUser } from '../test/user';
import { Endpoint } from './Endpoint';
import { endpointAddress, endpointTitle, toEndpoint } from './endpointText';
import { HostLinkContext } from './hostLink';

const host = { ip: '2001:db8::1', names: ['web.example.test', 'alias.test'], category: 'public' as const, country: 'FR' };

describe('endpoint text', () => {
  it('brackets IPv6 before a port and describes the host', () => {
    expect(endpointAddress(host, 443)).toBe('[2001:db8::1]:443');
    expect(endpointAddress(host)).toBe('2001:db8::1');
    expect(endpointAddress(toEndpoint('10.0.0.1'), 80)).toBe('10.0.0.1:80');
    expect(endpointTitle(host, 443)).toBe('[2001:db8::1]:443 web.example.test alias.test FR');
    expect(endpointTitle(toEndpoint('10.0.0.1'), null)).toBe('10.0.0.1');
  });
});

describe('Endpoint', () => {
  it('shows the address in mono with the port in grey, names in the tooltip', () => {
    render(<Endpoint endpoint={host} port={8080} show="address" />);
    const text = screen.getByTestId('truncatable');
    expect(text).toHaveTextContent('[2001:db8::1]:8080');
    expect(text).toHaveClass('font-mono');
    expect(text).toHaveAttribute('title', '[2001:db8::1]:8080 web.example.test alias.test FR');
    // Muted, not faint: the port keeps a 4.5:1 contrast in both themes (WCAG AA).
    expect(screen.getByText(':8080')).toHaveClass('text-muted');
    // Flag (decorative image) before the address.
    expect(document.querySelector('img')).toHaveAttribute('aria-hidden', 'true');
  });

  it('shows the first name by default, the address otherwise', () => {
    const { rerender } = render(<Endpoint endpoint={host} port={80} />);
    expect(screen.getByTestId('truncatable')).toHaveTextContent(/^web.example.test$/);
    rerender(<Endpoint endpoint={{ ...host, names: [] }} />);
    expect(screen.getByTestId('truncatable')).toHaveTextContent(/^2001:db8::1$/);
  });

  it('accepts a bare address (no flag, no names) and a null port', () => {
    render(<Endpoint endpoint="192.0.2.7" port={null} />);
    expect(screen.getByTestId('truncatable')).toHaveTextContent(/^192.0.2.7$/);
    expect(document.querySelector('img')).toBeNull();
  });

  it('puts the name after the address (both) or under it (stacked)', () => {
    const { rerender } = render(<Endpoint endpoint={host} port={445} show="both" />);
    let parts = screen.getAllByTestId('truncatable');
    expect(parts.map((p) => p.textContent)).toEqual(['[2001:db8::1]:445', 'web.example.test']);
    rerender(<Endpoint endpoint={host} show="stacked" />);
    parts = screen.getAllByTestId('truncatable');
    expect(parts.map((p) => p.textContent)).toEqual(['web.example.test', '2001:db8::1']);
    // Without a name, stacked is the address alone.
    rerender(<Endpoint endpoint={{ ...host, names: [] }} show="stacked" />);
    expect(screen.getAllByTestId('truncatable')).toHaveLength(1);
  });

  it('copies ip:port on demand', () => {
    render(<Endpoint endpoint={host} port={53} copy />);
    expect(screen.getByRole('button', { name: 'Copy [2001:db8::1]:53' })).toBeInTheDocument();
  });

  it('links to the host page when a HostLinkContext is provided', async () => {
    const user = setupUser();
    const open = vi.fn();
    render(
      <HostLinkContext value={{ open, label: (ip) => `Open ${ip}` }}>
        <Endpoint endpoint={host} />
      </HostLinkContext>,
    );
    await user.click(screen.getByRole('button', { name: 'Open 2001:db8::1' }));
    expect(open).toHaveBeenCalledWith('2001:db8::1');
  });
});
