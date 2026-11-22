import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { MacAddress as MacAddressDto } from '../api/types/MacAddress';
import i18n from '../i18n';
import { MacAddress, MacText } from './MacAddress';

function address(overrides: Partial<MacAddressDto> = {}): MacAddressDto {
  return { mac: '00:1b:21:aa:bb:cc', kind: 'unicast', local: false, group: null, vendor: 'Intel', ...overrides };
}

describe('MacAddress', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('shows the address, its vendor and a copy button', () => {
    render(<MacAddress address={address()} withVendor copy />);
    expect(screen.getByText('00:1b:21:aa:bb:cc')).toHaveClass('font-mono');
    expect(screen.getByText('Intel')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy MAC address' })).toBeInTheDocument();
  });

  it('badges broadcast, well-known groups and local addresses', () => {
    const { rerender } = render(<MacAddress address={address({ mac: 'ff:ff:ff:ff:ff:ff', kind: 'broadcast', vendor: null })} />);
    expect(screen.getByText('Broadcast')).toBeInTheDocument();
    rerender(<MacAddress address={address({ mac: '01:00:5e:00:00:fb', kind: 'multicast', group: 'ipv4_multicast', vendor: null })} />);
    expect(screen.getByText('IPv4 multicast')).toBeInTheDocument();
    rerender(<MacAddress address={address({ mac: '02:00:5e:10:00:10', local: true, vendor: null })} withVendor />);
    expect(screen.getByText('Local')).toBeInTheDocument();
    expect(screen.getByText('Locally administered')).toBeInTheDocument();
  });
});

describe('MacText', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('shows a text address, truncated with a tooltip', () => {
    render(<MacText mac="00:00:00:00:00:00" muted />);
    const text = screen.getByText('00:00:00:00:00:00');
    expect(text).toHaveAttribute('title', '00:00:00:00:00:00');
    expect(text).toHaveClass('truncate', 'font-mono', 'text-faint');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('adds a translated copy button', async () => {
    await i18n.changeLanguage('fr');
    render(<MacText mac="00:1b:21:aa:bb:cc" copy className="text-table" />);
    expect(screen.getByRole('button', { name: 'Copier adresse MAC' })).toBeInTheDocument();
    expect(screen.getByText('00:1b:21:aa:bb:cc').parentElement).toHaveClass('text-table');
  });
});
