import '../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Settings } from '../api/types/Settings';
import i18n from '../i18n';
import { setupUser } from '../test/user';
import { setNativeSavePicker } from '../updates/savePicker';
import { available, DEB, IDLE, release, state, UP_TO_DATE } from '../updates/testing';
import { NoticeArea } from './NoticeArea';
import { NOTICE_PROVIDERS } from './providers';
import { UpdateNotice } from './UpdateNotice';

const updateNotice = { id: 'update', Component: UpdateNotice };

const settingsApi = vi.hoisted(() => ({ getSettings: vi.fn(), dismissNotice: vi.fn(), updateSettings: vi.fn() }));
vi.mock('../api/settings', () => settingsApi);
const api = vi.hoisted(() => ({
  getUpdates: vi.fn(),
  checkUpdates: vi.fn(),
  startUpdateDownload: vi.fn(),
  getUpdateDownload: vi.fn(),
}));
vi.mock('../api/updates', () => api);

const SETTINGS: Settings = { online: { geoip_check: false, update_check: true }, dismissed_notices: [] };

function renderBanner() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <NoticeArea providers={[updateNotice]} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  settingsApi.getSettings.mockResolvedValue(SETTINGS);
  settingsApi.dismissNotice.mockImplementation((id: string, key: string) =>
    Promise.resolve({ ...SETTINGS, dismissed_notices: [{ id, key }] }),
  );
  api.getUpdates.mockResolvedValue(state(available()));
  api.getUpdateDownload.mockResolvedValue(IDLE);
  api.startUpdateDownload.mockResolvedValue({ ...IDLE, phase: 'downloading', asset: DEB, total_bytes: 120_000_000 });
});

afterEach(async () => {
  setNativeSavePicker(undefined);
  vi.clearAllMocks();
  await i18n.changeLanguage('en');
});

describe('update notice', () => {
  it('is registered in production', () => {
    expect(NOTICE_PROVIDERS).toContainEqual(updateNotice);
  });

  it('shows the version and the notes as plain text', async () => {
    setNativeSavePicker(null);
    renderBanner();
    const banner = await screen.findByTestId('notice-update');
    expect(banner).toHaveTextContent('NetSift 0.2.0 is available.');
    const excerpt = within(banner).getByTestId('update-notes-excerpt');
    // Markup from the network stays text.
    expect(excerpt).toHaveTextContent('<b>Faster</b> import; Second line');
    expect(banner.querySelector('b')).toBeNull();

    await setupUser().click(within(banner).getByRole('button', { name: 'Release notes' }));
    const dialog = screen.getByRole('dialog', { name: 'NetSift 0.2.0' });
    expect(within(dialog).getByTestId('update-notes').querySelector('pre')?.textContent).toBe(
      '## Fixes\n\n- <b>Faster</b> import\n- Second line',
    );
    expect(dialog.querySelector('b')).toBeNull();
  });

  it('shows nothing when up to date, or before any check', async () => {
    api.getUpdates.mockResolvedValue(state(UP_TO_DATE));
    const first = renderBanner();
    await waitFor(() => {
      expect(api.getUpdates).toHaveBeenCalled();
    });
    expect(screen.queryByTestId('notice-update')).not.toBeInTheDocument();
    first.unmount();

    api.getUpdates.mockResolvedValue(state(null));
    renderBanner();
    await waitFor(() => {
      expect(api.getUpdates).toHaveBeenCalledTimes(2);
    });
    expect(screen.queryByTestId('notice-update')).not.toBeInTheDocument();
    expect(settingsApi.getSettings).not.toHaveBeenCalled();
  });

  it('is dismissed for this version only', async () => {
    setNativeSavePicker(null);
    renderBanner();
    const banner = await screen.findByTestId('notice-update');
    await setupUser().click(within(banner).getByRole('button', { name: 'Dismiss' }));
    expect(settingsApi.dismissNotice).toHaveBeenCalledWith('update', '0.2.0');
    expect(screen.queryByTestId('notice-update')).not.toBeInTheDocument();
  });

  it('desktop: downloads after the save dialog, nothing when it is cancelled', async () => {
    const picker = vi.fn<(name: string) => Promise<string | null>>().mockResolvedValue(null);
    setNativeSavePicker(picker);
    renderBanner();
    const banner = await screen.findByTestId('notice-update');
    const user = setupUser();
    // The installed format first, its name as the default file name.
    await user.click(within(banner).getByRole('button', { name: 'Download' }));
    expect(picker).toHaveBeenCalledWith(DEB);
    expect(api.startUpdateDownload).not.toHaveBeenCalled();

    picker.mockResolvedValue('/home/u/Downloads/NetSift.deb');
    await user.click(within(banner).getByRole('button', { name: 'Download' }));
    await waitFor(() => {
      expect(api.startUpdateDownload).toHaveBeenCalledWith(DEB, '/home/u/Downloads/NetSift.deb');
    });
    expect(await within(banner).findByTestId('update-download-progress')).toHaveTextContent(`Downloading ${DEB}`);
    expect(within(banner).getByRole('button', { name: 'Download' })).toBeDisabled();
    expect(within(banner).queryByTestId('update-release-page')).not.toBeInTheDocument();
  });

  it('web mode: a link to the release page, no download', async () => {
    setNativeSavePicker(null);
    api.getUpdates.mockResolvedValue(state(available(), { can_download: false }));
    renderBanner();
    const banner = await screen.findByTestId('notice-update');
    expect(within(banner).queryByRole('button', { name: 'Download' })).not.toBeInTheDocument();
    const link = within(within(banner).getByTestId('update-release-page')).getByRole('link');
    expect(link).toHaveAttribute('href', release().html_url);
    expect(link).toHaveAttribute('rel', 'noreferrer noopener');
    expect(api.getUpdateDownload).not.toHaveBeenCalled();
  });

  it('speaks French', async () => {
    await i18n.changeLanguage('fr');
    setNativeSavePicker(null);
    renderBanner();
    const banner = await screen.findByTestId('notice-update');
    expect(banner).toHaveTextContent('NetSift 0.2.0 est disponible.');
    expect(within(banner).getByRole('button', { name: 'Notes de version' })).toBeInTheDocument();
  });
});
