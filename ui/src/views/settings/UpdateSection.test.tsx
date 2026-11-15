import '../../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../api/client';
import type { UpdateDownload } from '../../api/types/UpdateDownload';
import i18n from '../../i18n';
import { setupUser } from '../../test/user';
import { setNativeSavePicker } from '../../updates/savePicker';
import { APPIMAGE, available, DEB, IDLE, release, state, UP_TO_DATE } from '../../updates/testing';
import { ONLINE_EXTENSIONS } from './online/extensions';
import { UpdateSection } from './UpdateSection';

const api = vi.hoisted(() => ({
  getUpdates: vi.fn(),
  checkUpdates: vi.fn(),
  startUpdateDownload: vi.fn(),
  getUpdateDownload: vi.fn(),
}));
vi.mock('../../api/updates', () => api);

function renderSection(readOnly = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <UpdateSection readOnly={readOnly} />
    </QueryClientProvider>,
  );
}

const status = () => screen.getByTestId('update-status');

beforeEach(() => {
  api.getUpdates.mockResolvedValue(state(null));
  api.getUpdateDownload.mockResolvedValue(IDLE);
});

afterEach(async () => {
  setNativeSavePicker(undefined);
  vi.clearAllMocks();
  await i18n.changeLanguage('en');
});

describe('Settings > About > Updates', () => {
  it('checks on click and shows "up to date"', async () => {
    let resolve: (v: typeof UP_TO_DATE) => void = () => undefined;
    api.checkUpdates.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    renderSection();
    await waitFor(() => {
      expect(api.getUpdates).toHaveBeenCalled();
    });
    expect(screen.queryByTestId('update-status')).not.toBeInTheDocument();
    expect(screen.getByText(/Asks api\.github\.com/)).toBeInTheDocument();
    const button = screen.getByRole('button', { name: 'Check for updates' });
    await setupUser().click(button);
    expect(status()).toHaveAttribute('data-status', 'checking');
    expect(button).toBeDisabled();
    resolve(UP_TO_DATE);
    await waitFor(() => {
      expect(status()).toHaveAttribute('data-status', 'up-to-date');
    });
    expect(status()).toHaveTextContent('NetSift 0.1.0 is the latest version.');
    expect(button).toBeEnabled();
  });

  it('reports a failed check inline', async () => {
    api.checkUpdates.mockRejectedValue(new ApiError(502, 'urn:netsift:problem:update-check-failed', 'Update check failed'));
    renderSection();
    await setupUser().click(screen.getByRole('button', { name: 'Check for updates' }));
    await waitFor(() => {
      expect(status()).toHaveAttribute('data-status', 'failed');
    });
    expect(status()).toHaveTextContent('The check failed.');
  });

  it('shows the result of the startup check, and "checking" while it runs', async () => {
    api.getUpdates.mockResolvedValue(state(null, { checking: true }));
    const first = renderSection();
    await waitFor(() => {
      expect(status()).toHaveAttribute('data-status', 'checking');
    });
    first.unmount();
    setNativeSavePicker(null);
    api.getUpdates.mockResolvedValue(state(available(), { can_download: false }));
    renderSection();
    await waitFor(() => {
      expect(status()).toHaveAttribute('data-status', 'available');
    });
    expect(status()).toHaveTextContent('NetSift 0.2.0 is available.');
  });

  it('is disabled on a read-only server', async () => {
    renderSection(true);
    const button = screen.getByRole('button', { name: 'Check for updates' });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('title', 'Not available on a read-only server.');
  });

  it('web mode: the release page instead of a download', async () => {
    setNativeSavePicker(null);
    api.getUpdates.mockResolvedValue(state(available(), { can_download: false }));
    renderSection();
    const section = await screen.findByTestId('update-release');
    expect(within(section).queryByRole('button', { name: 'Download' })).not.toBeInTheDocument();
    expect(within(section).getByRole('link')).toHaveAttribute('href', release().html_url);
    expect(api.getUpdateDownload).not.toHaveBeenCalled();
  });

  it('desktop: downloads the chosen installer and shows the saved path', async () => {
    const picker = vi.fn<(name: string) => Promise<string | null>>().mockResolvedValue('/home/u/Downloads/x.deb');
    setNativeSavePicker(picker);
    api.getUpdates.mockResolvedValue(state(available()));
    const running: UpdateDownload = { ...IDLE, phase: 'downloading', asset: DEB, received_bytes: 0, total_bytes: 120_000_000 };
    api.startUpdateDownload.mockResolvedValue(running);
    api.getUpdateDownload
      .mockResolvedValueOnce(IDLE)
      .mockResolvedValueOnce({ ...running, received_bytes: 60_000_000 })
      .mockResolvedValue({ ...running, phase: 'done', received_bytes: 120_000_000, path: '/home/u/Downloads/x.deb' });
    renderSection();
    const section = await screen.findByTestId('update-release');
    // Installed format known: no choice offered.
    expect(within(section).queryByRole('combobox')).not.toBeInTheDocument();
    await setupUser().click(within(section).getByRole('button', { name: 'Download' }));
    expect(picker).toHaveBeenCalledWith(DEB);
    await waitFor(() => {
      expect(api.startUpdateDownload).toHaveBeenCalledWith(DEB, '/home/u/Downloads/x.deb');
    });
    expect(await within(section).findByTestId('update-download-progress')).toBeInTheDocument();
    const done = await within(section).findByTestId('update-download-done', undefined, { timeout: 3000 });
    expect(done).toHaveTextContent('Saved to /home/u/Downloads/x.deb');
    expect(done).toHaveTextContent('NetSift does not install updates');
    expect(within(section).getByRole('button', { name: 'Download' })).toBeEnabled();
  });

  it('desktop: lets the user choose the format when the installed one is unknown', async () => {
    const picker = vi.fn<(name: string) => Promise<string | null>>().mockResolvedValue(null);
    setNativeSavePicker(picker);
    api.getUpdates.mockResolvedValue(state(available(release({ format_known: false }))));
    renderSection();
    const section = await screen.findByTestId('update-release');
    const user = setupUser();
    await user.selectOptions(within(section).getByRole('combobox', { name: 'Format' }), 'AppImage (any distribution)');
    await user.click(within(section).getByRole('button', { name: 'Download' }));
    expect(picker).toHaveBeenCalledWith(APPIMAGE);
    expect(api.startUpdateDownload).not.toHaveBeenCalled();
  });

  it('desktop: explains failures', async () => {
    const picker = vi.fn<(name: string) => Promise<string | null>>().mockResolvedValue('/x/y.deb');
    setNativeSavePicker(picker);
    api.getUpdates.mockResolvedValue(state(available()));
    api.startUpdateDownload.mockRejectedValue(new ApiError(400, 'urn:netsift:problem:update-path-invalid', 'bad'));
    renderSection();
    const section = await screen.findByTestId('update-release');
    const user = setupUser();
    await user.click(within(section).getByRole('button', { name: 'Download' }));
    expect(await within(section).findByTestId('update-download-error')).toHaveTextContent('This location cannot be used.');

    // Failure reported by the server after the start.
    api.startUpdateDownload.mockResolvedValue({ ...IDLE, phase: 'failed', asset: DEB, error: 'checksum_mismatch' });
    await user.click(within(section).getByRole('button', { name: 'Download' }));
    await waitFor(() => {
      expect(within(section).getByTestId('update-download-error')).toHaveTextContent(
        'The file does not match its published checksum: it was deleted.',
      );
    });

    // The save dialog itself failed.
    picker.mockRejectedValue(new Error('no portal'));
    await user.click(within(section).getByRole('button', { name: 'Download' }));
    await waitFor(() => {
      expect(within(section).getByTestId('update-download-error')).toHaveTextContent('The save dialog could not open: no portal');
    });
  });

  it('names the download hosts under the startup setting of Settings > Online', () => {
    const ext = ONLINE_EXTENSIONS.find((e) => e.id === 'update');
    expect(ext?.setting).toBe('update_check');
    if (ext === undefined) return;
    render(<ext.Component enabled={false} readOnly={false} />);
    expect(screen.getByTestId('online-update-hosts')).toHaveTextContent(
      /github\.com.*release-assets\.githubusercontent\.com.*objects\.githubusercontent\.com/,
    );
  });

  it('speaks French', async () => {
    await i18n.changeLanguage('fr');
    api.checkUpdates.mockResolvedValue(UP_TO_DATE);
    renderSection();
    await setupUser().click(screen.getByRole('button', { name: 'Rechercher une mise à jour' }));
    await waitFor(() => {
      expect(status()).toHaveTextContent('NetSift 0.1.0 est la dernière version.');
    });
  });
});
