import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import '../i18n';
import { setupUser } from '../test/user';
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
