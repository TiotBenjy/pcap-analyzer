import '../../../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../../api/client';
import type { GeoipFreshness } from '../../../api/types/GeoipFreshness';
import type { Settings } from '../../../api/types/Settings';
import i18n from '../../../i18n';
import { setupUser } from '../../../test/user';
import { ONLINE_EXTENSIONS, type OnlineExtension } from './extensions';
import { OnlineCard } from './OnlineCard';

let readOnly = false;
vi.mock('../../../api/queries', () => ({
  useServerInfo: () => ({ data: { version: '0.1.0', read_only: readOnly, can_browse: false } }),
}));
const api = vi.hoisted(() => ({ getSettings: vi.fn(), updateSettings: vi.fn(), dismissNotice: vi.fn() }));
vi.mock('../../../api/settings', () => api);
const geoipApi = vi.hoisted(() => ({ getGeoipStatus: vi.fn(), downloadGeoip: vi.fn(), importGeoip: vi.fn(), getGeoipUpdate: vi.fn() }));
vi.mock('../../../api/geoip', () => geoipApi);

function freshness(extra: Partial<GeoipFreshness> = {}): GeoipFreshness {
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

const DEFAULTS: Settings = { online: { geoip_check: false, update_check: false }, dismissed_notices: [] };

function renderCard(extensions: readonly OnlineExtension[] = ONLINE_EXTENSIONS) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <OnlineCard extensions={extensions} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  geoipApi.getGeoipStatus.mockResolvedValue(freshness());
  api.getSettings.mockResolvedValue(DEFAULTS);
  api.updateSettings.mockImplementation((u: { online: Partial<Settings['online']> }) =>
    Promise.resolve({ ...DEFAULTS, online: { ...DEFAULTS.online, ...u.online } }),
  );
});

afterEach(async () => {
  readOnly = false;
  vi.clearAllMocks();
  await i18n.changeLanguage('en');
});

describe('OnlineCard', () => {
  it('has no example extension in production', () => {
    const ids = ONLINE_EXTENSIONS.map((e) => e.id);
    expect(ids).toEqual([...new Set(ids)].sort());
  });

  it('shows both checks, off by default, with the host each one contacts', async () => {
    renderCard();
    const geoip = await screen.findByRole('switch', { name: 'Check for a new GeoIP database at startup' });
    const update = screen.getByRole('switch', { name: 'Check for updates at startup' });
    await waitFor(() => {
      expect(geoip).toBeEnabled();
    });
    expect(geoip).toHaveAttribute('aria-checked', 'false');
    expect(update).toHaveAttribute('aria-checked', 'false');
    expect(geoip).toHaveAccessibleDescription(/download\.db-ip\.com/);
    expect(update).toHaveAccessibleDescription(/api\.github\.com/);
    expect(screen.getByTestId('online-settings')).toHaveTextContent('off by default');
  });

  it('saves a change on the server and says when it applies', async () => {
    renderCard();
    const update = await screen.findByRole('switch', { name: 'Check for updates at startup' });
    await waitFor(() => {
      expect(update).toBeEnabled();
    });
    await setupUser().click(update);
    expect(api.updateSettings).toHaveBeenCalledWith({ online: { update_check: true } });
    await waitFor(() => {
      expect(update).toHaveAttribute('aria-checked', 'true');
    });
    expect(screen.getByRole('switch', { name: 'Check for a new GeoIP database at startup' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
    expect(await screen.findByText('Applies from the next start.')).toBeInTheDocument();
  });

  it('reports a refused change and keeps the previous value', async () => {
    api.updateSettings.mockRejectedValue(new ApiError(500, 'urn:netsift:problem:internal', 'Internal error'));
    renderCard();
    const geoip = await screen.findByRole('switch', { name: 'Check for a new GeoIP database at startup' });
    await waitFor(() => {
      expect(geoip).toBeEnabled();
    });
    await setupUser().click(geoip);
    expect(await screen.findByRole('alert')).toHaveTextContent('The setting could not be saved');
    expect(geoip).toHaveAttribute('aria-checked', 'false');
  });

  it('disables the switches on a read-only server', async () => {
    readOnly = true;
    api.getSettings.mockResolvedValue({ ...DEFAULTS, online: { geoip_check: true, update_check: false } });
    renderCard();
    const geoip = await screen.findByRole('switch', { name: 'Check for a new GeoIP database at startup' });
    await waitFor(() => {
      expect(geoip).toHaveAttribute('aria-checked', 'true');
    });
    expect(geoip).toBeDisabled();
    expect(screen.getByRole('switch', { name: 'Check for updates at startup' })).toBeDisabled();
    expect(screen.getAllByText('These settings cannot be changed on a read-only server.').length).toBeGreaterThan(0);
  });

  it('says when the settings cannot be read', async () => {
    api.getSettings.mockRejectedValue(new ApiError(0, 'network', 'down'));
    renderCard();
    expect(await screen.findByRole('alert')).toHaveTextContent('Settings unavailable');
    expect(screen.getByRole('switch', { name: 'Check for updates at startup' })).toBeDisabled();
  });

  it('shows the content of each feature under its own switch', async () => {
    api.getSettings.mockResolvedValue({ ...DEFAULTS, online: { geoip_check: false, update_check: true } });
    const examples: OnlineExtension[] = [
      { id: 'geoip-example', setting: 'geoip_check', Component: ({ enabled }) => <p>{`geoip example ${String(enabled)}`}</p> },
      { id: 'update-example', setting: 'update_check', Component: ({ enabled }) => <p>{`update example ${String(enabled)}`}</p> },
    ];
    renderCard(examples);
    expect(await screen.findByText('update example true')).toBeInTheDocument();
    const items = screen.getAllByRole('listitem');
    expect(within(items[0] as HTMLElement).getByText('geoip example false')).toBeInTheDocument();
    expect(within(items[1] as HTMLElement).getByText('update example true')).toBeInTheDocument();
  });

  it('shows the installed database under the GeoIP switch, and the check only when on', async () => {
    renderCard();
    const status = await screen.findByTestId('geoip-check-status');
    expect(status).toHaveTextContent(/^Installed database: October 2026\.$/);
  });

  it.each([
    [freshness({ online: 'off' }), 'Not checked at this start. Applies from the next start.'],
    [freshness({ online: 'off', state: 'current', built_month: '2026-11', offer: null }), 'Not checked at this start: the database is current.'],
    [freshness({ online: 'pending', offer: null }), 'Checking download.db-ip.com.'],
    [freshness({ online: 'published', published_month: '2026-11' }), 'Last check: database of November 2026 published.'],
    [freshness({ online: 'not_published', offer: null }), 'Last check: no database published for this month or the previous one.'],
    [freshness({ online: 'failed' }), 'Last check: no answer from download.db-ip.com.'],
    [freshness({ state: 'missing', built_month: null, online: 'failed', offer: 'download' }), 'Installed database: none.'],
  ])('reports the GeoIP check when on (%#)', async (answer, text) => {
    api.getSettings.mockResolvedValue({ ...DEFAULTS, online: { geoip_check: true, update_check: false } });
    geoipApi.getGeoipStatus.mockResolvedValue(answer);
    renderCard();
    await waitFor(() => {
      expect(screen.getByTestId('geoip-check-status')).toHaveTextContent(text);
    });
  });

  it('is translated in French', async () => {
    await i18n.changeLanguage('fr');
    renderCard();
    expect(await screen.findByRole('heading', { name: 'En ligne' })).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Rechercher les mises à jour au démarrage' })).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Rechercher une nouvelle base GeoIP au démarrage' })).toBeInTheDocument();
    expect(await screen.findByTestId('geoip-check-status')).toHaveTextContent(/^Base installée\s: octobre 2026\.$/);
  });
});
