import '../../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../api/client';
import type { GeoipInfo } from '../../api/types/GeoipInfo';
import i18n from '../../i18n';
import { setupUser } from '../../test/user';
import { setNativePicker } from '../sessions/import/pickers';
import SettingsView from './SettingsView';

const MISSING: GeoipInfo = { status: 'missing', source: null, built_at_us: null, size_bytes: null, installed_at_us: null };
let geoip: GeoipInfo | undefined = MISSING;
let readOnly = true;
let canBrowse = false;

vi.mock('../../api/queries', () => ({
  useHealth: () => ({ isPending: false, isError: false, data: { version: '0.1.0' } }),
  useServerInfo: () => ({
    data: geoip === undefined ? undefined : { version: '0.1.0', read_only: readOnly, can_browse: canBrowse, geoip },
  }),
}));

const api = vi.hoisted(() => ({
  downloadGeoip: vi.fn(),
  importGeoip: vi.fn(),
  getGeoipUpdate: vi.fn(),
  browse: vi.fn(),
}));
vi.mock('../../api/geoip', () => ({
  downloadGeoip: api.downloadGeoip,
  importGeoip: api.importGeoip,
  getGeoipUpdate: api.getGeoipUpdate,
}));
vi.mock('../../api/sessions', () => ({ browse: api.browse }));

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <SettingsView />
    </QueryClientProvider>,
  );
}

const AVAILABLE: GeoipInfo = {
  status: 'available',
  source: 'user',
  built_at_us: Date.UTC(2026, 10, 1, 0, 30) * 1000,
  size_bytes: 8 * 1024 * 1024,
  installed_at_us: Date.UTC(2026, 10, 8, 12) * 1000,
};

describe('SettingsView', () => {
  afterEach(async () => {
    geoip = MISSING;
    readOnly = true;
    canBrowse = false;
    setNativePicker(undefined);
    vi.clearAllMocks();
    await i18n.changeLanguage('en');
  });

  it('shows the DB-IP attribution as plain text, without any link', async () => {
    await i18n.changeLanguage('en');
    renderView();
    const attribution = screen.getByTestId('geoip-attribution');
    expect(attribution).toHaveTextContent('IP geolocation by DB-IP');
    expect(attribution).toHaveTextContent('https://db-ip.com');
    expect(attribution).toHaveTextContent('CC BY 4.0');
    expect(attribution).toHaveTextContent('https://creativecommons.org/licenses/by/4.0/');
    expect(document.querySelector('a')).toBeNull();
  });

  it('is translated in French', async () => {
    await i18n.changeLanguage('fr');
    renderView();
    expect(screen.getByTestId('geoip-attribution')).toHaveTextContent('Géolocalisation IP par DB-IP');
    expect(screen.getByTestId('geoip-status')).toHaveTextContent('Aucune base, pays inconnus');
    expect(screen.getByRole('button', { name: 'Télécharger la dernière version' })).toBeDisabled();
    expect(screen.getByTestId('geoip-update')).toHaveTextContent('Réimportez-les');
  });

  it('says when the GeoIP database is missing', async () => {
    await i18n.changeLanguage('en');
    renderView();
    const status = screen.getByTestId('geoip-status');
    expect(status).toHaveAttribute('data-status', 'missing');
    expect(status).toHaveTextContent('No database, countries unknown');
    expect(screen.queryByTestId('geoip-source')).toBeNull();
  });

  it('shows the build date in UTC, the origin and the size of the database', async () => {
    // 2026-11-01T00:30Z: still November 1st in UTC whatever the local time zone.
    geoip = AVAILABLE;
    await i18n.changeLanguage('en');
    const { unmount } = renderView();
    expect(screen.getByTestId('geoip-status')).toHaveTextContent('Database installed, built Nov 1, 2026');
    const source = screen.getByTestId('geoip-source');
    expect(source).toHaveAttribute('data-source', 'user');
    expect(source).toHaveTextContent(/^Updated copy, 8\.0\sMiB, installed Nov \d+, 2026$/);
    unmount();

    geoip = { ...AVAILABLE, source: 'bundled' };
    await i18n.changeLanguage('fr');
    renderView();
    expect(screen.getByTestId('geoip-status')).toHaveTextContent('Base installée, générée le 1 nov. 2026');
    expect(screen.getByTestId('geoip-source')).toHaveTextContent(/^Copie fournie avec NetSift, 8,0\sMio$/);
  });

  it('handles an undated or unreadable database', () => {
    geoip = { ...MISSING, status: 'available', source: 'user', size_bytes: 1024 };
    const { unmount } = renderView();
    expect(screen.getByTestId('geoip-status')).toHaveTextContent(/^Database installed$/);
    expect(screen.getByTestId('geoip-source')).toHaveTextContent(/^Updated copy, 1\.0\sKiB$/);
    unmount();

    geoip = { ...MISSING, status: 'invalid' };
    renderView();
    const status = screen.getByTestId('geoip-status');
    expect(status).toHaveAttribute('data-status', 'invalid');
    expect(status).toHaveTextContent('Unreadable database, countries unknown');
  });

  it('shows no status nor update buttons before the server info arrives', () => {
    geoip = undefined;
    renderView();
    expect(screen.queryByTestId('geoip-status')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Download latest version' })).toBeNull();
    expect(screen.getByTestId('geoip-attribution')).toHaveTextContent('DB-IP');
  });

  it('disables the updates on a read-only server', () => {
    renderView();
    expect(screen.getByRole('button', { name: 'Download latest version' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Import a file' })).toBeDisabled();
    expect(screen.getByTestId('geoip-update')).toHaveTextContent('Updates are disabled on a read-only server.');
  });

  it('downloads on click only, says which host it contacts, and reports success', async () => {
    readOnly = false;
    let finish: (info: GeoipInfo) => void = () => undefined;
    api.downloadGeoip.mockReturnValue(
      new Promise<GeoipInfo>((resolve) => {
        finish = resolve;
      }),
    );
    api.getGeoipUpdate.mockResolvedValue({ phase: 'downloading', received_bytes: 1024 * 1024, total_bytes: 4 * 1024 * 1024 });
    const user = setupUser();
    renderView();
    expect(screen.getByTestId('geoip-update')).toHaveTextContent('Downloading contacts download.db-ip.com.');
    expect(api.downloadGeoip).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Download latest version' }));
    expect(api.downloadGeoip).toHaveBeenCalledTimes(1);
    await waitFor(() => {
      expect(screen.getByTestId('geoip-progress')).toHaveTextContent(/^Downloading, 1\.0\sMiB of 4\.0\sMiB$/);
    });
    // One update at a time.
    expect(screen.getByRole('button', { name: 'Download latest version' })).toBeDisabled();

    finish(AVAILABLE);
    expect(await screen.findByText('Database updated. New imports use it.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download latest version' })).toBeEnabled();
  });

  it('translates the update errors', async () => {
    readOnly = false;
    canBrowse = true;
    api.downloadGeoip.mockRejectedValue(new ApiError(502, 'urn:netsift:problem:geoip-download-failed', 'x'));
    const user = setupUser();
    renderView();
    await user.click(screen.getByRole('button', { name: 'Download latest version' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/^Download failed\. .*The current database is unchanged\.$/);

    api.downloadGeoip.mockRejectedValue(new ApiError(422, 'urn:netsift:problem:geoip-invalid', 'x'));
    await user.click(screen.getByRole('button', { name: 'Download latest version' }));
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('This file is not a usable country database.');
    });
  });

  it('imports a file chosen with the native dialog in the desktop app', async () => {
    readOnly = false;
    const picker = vi.fn().mockResolvedValue('/home/u/dbip-country-lite.mmdb.gz');
    setNativePicker(picker);
    api.importGeoip.mockResolvedValue(AVAILABLE);
    const user = setupUser();
    renderView();
    await user.click(screen.getByRole('button', { name: 'Import a file' }));
    expect(picker).toHaveBeenCalledWith('file');
    await waitFor(() => {
      expect(api.importGeoip).toHaveBeenCalledWith('/home/u/dbip-country-lite.mmdb.gz');
    });
    expect(await screen.findByText('Database updated. New imports use it.')).toBeInTheDocument();
  });

  it('imports a file chosen in the allowed roots in web mode', async () => {
    readOnly = false;
    canBrowse = true;
    api.browse.mockResolvedValue({
      path: '/captures',
      parent: null,
      roots: ['/captures'],
      entries: [
        { name: 'old', is_dir: true, size: 0 },
        { name: 'country.mmdb', is_dir: false, size: 2048 },
      ],
    });
    api.importGeoip.mockResolvedValue(AVAILABLE);
    const user = setupUser();
    renderView();
    await user.click(screen.getByRole('button', { name: 'Import a file' }));
    const dialog = await screen.findByRole('dialog', { name: 'Import a GeoIP database' });
    const install = screen.getByRole('button', { name: 'Install' });
    expect(install).toBeDisabled();
    await user.click(await screen.findByRole('button', { name: /country\.mmdb/ }));
    await user.click(install);
    expect(api.importGeoip).toHaveBeenCalledWith('/captures/country.mmdb');
    await waitFor(() => {
      expect(dialog).not.toBeInTheDocument();
    });
  });

  it('cannot import in web mode without allowed roots', () => {
    readOnly = false;
    renderView();
    const button = screen.getByRole('button', { name: 'Import a file' });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('title', 'No folder is available to choose a file from.');
    expect(screen.getByRole('button', { name: 'Download latest version' })).toBeEnabled();
  });
});
