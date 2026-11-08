import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import '../i18n';
import { setupUser } from '../test/user';
import { Endpoint } from './Endpoint';
import { SecretValue } from './SecretValue';

describe('SecretValue', () => {
  it('masks the value, reveals and copies it', async () => {
    const user = setupUser();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
    render(<SecretValue value="Basic dXNlcjpwYXNz" label="Authorization" />);
    expect(screen.queryByText('Basic dXNlcjpwYXNz')).toBeNull();
    expect(screen.getByText('Hidden (18 characters)')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show Authorization' }));
    expect(screen.getByText('Basic dXNlcjpwYXNz')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Hide Authorization' })).toHaveAttribute('aria-pressed', 'true');
    await user.click(screen.getByRole('button', { name: 'Copy Authorization' }));
    expect(writeText).toHaveBeenCalledWith('Basic dXNlcjpwYXNz');
  });
});

describe('Endpoint', () => {
  const host = { ip: '2001:db8::1', names: ['web.example.test'], category: 'public' as const, country: null };

  it('shows the port in grey after the address, the full text in the tooltip', () => {
    const { rerender } = render(<Endpoint endpoint={host} port={8080} showName={false} />);
    const text = screen.getByTestId('truncatable');
    expect(text).toHaveTextContent('[2001:db8::1]:8080');
    expect(text).toHaveAttribute('title', '[2001:db8::1]:8080 web.example.test');
    expect(screen.getByText(':8080')).toHaveClass('text-faint');
    // Without port (Connections, Open ports): the address alone, or the name.
    rerender(<Endpoint endpoint={host} showName={false} />);
    expect(screen.getByTestId('truncatable')).toHaveTextContent(/^2001:db8::1$/);
    rerender(<Endpoint endpoint={host} port={80} />);
    expect(screen.getByTestId('truncatable')).toHaveTextContent(/^web.example.test$/);
  });
});
