import '../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import type { GeoipFreshness } from '../api/types/GeoipFreshness';
import type { GeoipInfo } from '../api/types/GeoipInfo';
import type { Settings } from '../api/types/Settings';
import i18n from '../i18n';
import { setupUser } from '../test/user';
import { NoticeArea } from './NoticeArea';
import { NOTICE_PROVIDERS } from './providers';

let readOnly = false;
vi.mock('../api/queries', () => ({
  useServerInfo: () => ({ data: { version: '0.1.0', read_only: readOnly, can_browse: false } }),
}));
const api = vi.hoisted(() => ({
  getSettings: vi.fn(),
  dismissNotice: vi.fn(),
  updateSettings: vi.fn(),
  getGeoipStatus: vi.fn(),
  downloadGeoip: vi.fn(),
  importGeoip: vi.fn(),
  getGeoipUpdate: vi.fn(),
}));
vi.mock('../api/settings', () => ({
  getSettings: api.getSettings,
  dismissNotice: api.dismissNotice,
  updateSettings: api.updateSettings,
}));
vi.mock('../api/geoip', () => ({
  getGeoipStatus: api.getGeoipStatus,
  downloadGeoip: api.downloadGeoip,
  importGeoip: api.importGeoip,
  getGeoipUpdate: api.getGeoipUpdate,
}));

function settings(dismissed: Record<string, string> = {}): Settings {
  return {
    online: { geoip_check: false, update_check: false },
    dismissed_notices: Object.entries(dismissed).map(([id, key]) => ({ id, key })),
  };
}

function status(extra: Partial<GeoipFreshness> = {}): GeoipFreshness {
  return {
    state: 'outdated',
    built_month: '2026-10',
    current_month: '2026-11',
    online: 'off',
    published_month: null,
    offer: 'update',
    ...extra,
  };
}

const MISSING = status({ state: 'missing', built_month: null, offer: 'download' });
const CURRENT = status({ state: 'current', built_month: '2026-11', offer: null });
const INSTALLED: GeoipInfo = {
  status: 'available',
  source: 'user',
  built_at_us: 1_793_491_200_000_000,
  size_bytes: 8 * 1024 * 1024,
  installed_at_us: 1_793_491_200_000_000,
};

function renderArea() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <NoticeArea />
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  api.getSettings.mockResolvedValue(settings());
  api.dismissNotice.mockImplementation((id: string, key: string) => Promise.resolve(settings({ [id]: key })));
  api.getGeoipUpdate.mockResolvedValue({ phase: 'idle', received_bytes: 0, total_bytes: null });
});

afterEach(async () => {
  readOnly = false;
  vi.clearAllMocks();
  await i18n.changeLanguage('en');
});

describe('GeoIP notice', () => {
  it('is registered under the id of its dismissals', () => {
    expect(NOTICE_PROVIDERS.map((p) => p.id)).toContain('geoip');
  });

  it('offers a download when no database is usable', async () => {
    api.getGeoipStatus.mockResolvedValue(MISSING);
    renderArea();
    const banner = await screen.findByTestId('notice-geoip');
    expect(banner).toHaveTextContent('No GeoIP database: the countries of public addresses stay unknown.');
    expect(banner).toHaveTextContent('Downloaded by NetSift from download.db-ip.com.');
    expect(within(banner).getByRole('button', { name: 'Download' })).toBeEnabled();
  });

  it('offers an update with the month of the installed database', async () => {
    api.getGeoipStatus.mockResolvedValue(status());
    renderArea();
    const banner = await screen.findByTestId('notice-geoip');
    expect(banner).toHaveTextContent('GeoIP database built in October 2026. DB-IP publishes a new one each month.');
    expect(within(banner).getByRole('button', { name: 'Update' })).toBeInTheDocument();
  });

  it('names the month the online check found', async () => {
    api.getGeoipStatus.mockResolvedValue(status({ built_month: '2026-09', online: 'published', published_month: '2026-10' }));
    renderArea();
    expect(await screen.findByTestId('notice-geoip')).toHaveTextContent(
      'GeoIP database built in September 2026. A newer one is available (October 2026).',
    );
  });

  it.each([
    ['a current database', CURRENT],
    ['a running online check', status({ online: 'pending', offer: null })],
    ['nothing published', status({ online: 'not_published', offer: null })],
    ['another answer shape', { version: 'x' } as unknown as GeoipFreshness],
  ])('shows nothing for %s', async (_name, answer) => {
    api.getGeoipStatus.mockResolvedValue(answer);
    renderArea();
    await waitFor(() => {
      expect(api.getGeoipStatus).toHaveBeenCalled();
    });
    await Promise.resolve();
    expect(screen.queryByTestId('notice-geoip')).not.toBeInTheDocument();
    expect(api.getSettings).not.toHaveBeenCalled();
  });

  it('asks again while the online check runs', async () => {
    api.getGeoipStatus
      .mockResolvedValueOnce(status({ online: 'pending', offer: null }))
      .mockResolvedValue(status({ online: 'published', published_month: '2026-11' }));
    renderArea();
    const banner = await screen.findByTestId('notice-geoip', {}, { timeout: 4000 });
    expect(banner).toHaveTextContent('A newer one is available (November 2026).');
    expect(api.getGeoipStatus).toHaveBeenCalledTimes(2);
  });

  it('is dismissed for the current month', async () => {
    api.getGeoipStatus.mockResolvedValue(status());
    renderArea();
    const user = setupUser();
    await user.click(within(await screen.findByTestId('notice-geoip')).getByRole('button', { name: 'Dismiss' }));
    expect(api.dismissNotice).toHaveBeenCalledWith('geoip', '2026-11');
    expect(screen.queryByTestId('notice-geoip')).not.toBeInTheDocument();
  });

  it('is hidden when dismissed for this month, not for an earlier one', async () => {
    api.getSettings.mockResolvedValue(settings({ geoip: '2026-11' }));
    api.getGeoipStatus.mockResolvedValue(status());
    renderArea();
    await waitFor(() => {
      expect(api.getSettings).toHaveBeenCalled();
    });
    await Promise.resolve();
    expect(screen.queryByTestId('notice-geoip')).not.toBeInTheDocument();

    api.getSettings.mockResolvedValue(settings({ geoip: '2026-10' }));
    renderArea();
    expect(await screen.findByTestId('notice-geoip')).toBeInTheDocument();
  });

  it('downloads with progress, then disappears once the database is current', async () => {
    api.getGeoipStatus.mockResolvedValue(status());
    let finish: (info: GeoipInfo) => void = () => undefined;
    api.downloadGeoip.mockReturnValue(
      new Promise<GeoipInfo>((resolve) => {
        finish = resolve;
      }),
    );
    api.getGeoipUpdate.mockResolvedValue({ phase: 'downloading', received_bytes: 1024 * 1024, total_bytes: 4 * 1024 * 1024 });
    renderArea();
    const banner = await screen.findByTestId('notice-geoip');
    await setupUser().click(within(banner).getByRole('button', { name: 'Update' }));
    expect(api.downloadGeoip).toHaveBeenCalledOnce();
    await waitFor(() => {
      expect(within(banner).getByTestId('geoip-progress-bytes')).toHaveTextContent(/^1\.0\sMiB of 4\.0\sMiB$/);
    });
    expect(within(banner).getByRole('status')).toHaveTextContent('Downloading');
    expect(within(banner).getByRole('button', { name: 'Update' })).toBeDisabled();

    api.getGeoipStatus.mockResolvedValue(CURRENT);
    finish(INSTALLED);
    await waitFor(() => {
      expect(screen.queryByTestId('notice-geoip')).not.toBeInTheDocument();
    });
  });

  it('reports a failed download in the banner', async () => {
    api.getGeoipStatus.mockResolvedValue(MISSING);
    api.downloadGeoip.mockRejectedValue(new ApiError(502, 'urn:netsift:problem:geoip-download-failed', 'x'));
    renderArea();
    const banner = await screen.findByTestId('notice-geoip');
    await setupUser().click(within(banner).getByRole('button', { name: 'Download' }));
    expect(await within(banner).findByRole('alert')).toHaveTextContent('Download failed.');
    expect(within(banner).getByRole('button', { name: 'Download' })).toBeEnabled();
  });

  it('cannot download on a read-only server', async () => {
    readOnly = true;
    api.getGeoipStatus.mockResolvedValue(MISSING);
    renderArea();
    const button = within(await screen.findByTestId('notice-geoip')).getByRole('button', { name: 'Download' });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('title', 'Updates are disabled on a read-only server.');
  });

  it('speaks French', async () => {
    await i18n.changeLanguage('fr');
    api.getGeoipStatus.mockResolvedValue(status());
    renderArea();
    const banner = await screen.findByTestId('notice-geoip');
    expect(banner).toHaveTextContent('Base GeoIP générée en octobre 2026. DB-IP en publie une nouvelle chaque mois.');
    expect(within(banner).getByRole('button', { name: 'Mettre à jour' })).toBeInTheDocument();
    expect(banner).toHaveTextContent('Téléchargée par NetSift depuis download.db-ip.com.');
  });
});
