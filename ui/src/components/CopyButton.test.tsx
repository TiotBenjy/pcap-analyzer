import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import { COPIED_MS, CopyButton } from './CopyButton';

/** jsdom has no Clipboard API: a stub that records the copied text. */
function stubClipboard() {
  const writeText = vi.fn<(text: string) => Promise<void>>().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
  return writeText;
}

describe('CopyButton', () => {
  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    await i18n.changeLanguage('en');
  });

  it('copies the value, shows "Copied", then comes back', async () => {
    vi.useFakeTimers();
    const writeText = stubClipboard();
    render(<CopyButton value="10.0.0.1" name="Address" />);
    const button = screen.getByRole('button', { name: 'Copy Address' });
    // 32 px target, 16 px icon (docs/UI_GUIDELINES.md).
    expect(button).toHaveClass('size-8');
    expect(button.querySelector('svg')).toHaveAttribute('width', '16');
    await act(async () => {
      fireEvent.click(button);
      await Promise.resolve();
    });
    expect(writeText).toHaveBeenCalledWith('10.0.0.1');
    expect(screen.getByRole('button', { name: 'Copied' })).toHaveClass('text-success');
    act(() => {
      vi.advanceTimersByTime(COPIED_MS);
    });
    expect(screen.getByRole('button', { name: 'Copy Address' })).toBeInTheDocument();
  });

  it('does not select the clickable row it sits in', () => {
    stubClipboard();
    const onRow = vi.fn();
    render(
      <div onClick={onRow}>
        <CopyButton value="x" name="Hash" />
      </div>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Copy Hash' }));
    expect(onRow).not.toHaveBeenCalled();
  });

  it('does not claim "Copied" when the copy fails', async () => {
    const writeText = vi.fn<(text: string) => Promise<void>>().mockRejectedValue(new Error('denied'));
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    // The selection fallback fails too.
    Object.defineProperty(document, 'execCommand', { value: () => false, configurable: true });
    render(<CopyButton value="secret" name="Token" />);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy Token' }));
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(writeText).toHaveBeenCalledWith('secret');
    expect(screen.queryByRole('button', { name: 'Copied' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Copy Token' })).not.toHaveClass('text-success');
  });

  it('is labelled in French', async () => {
    await act(async () => {
      await i18n.changeLanguage('fr');
    });
    render(<CopyButton value="x" name="SHA-256" />);
    expect(screen.getByRole('button', { name: 'Copier SHA-256' })).toBeInTheDocument();
  });
});
