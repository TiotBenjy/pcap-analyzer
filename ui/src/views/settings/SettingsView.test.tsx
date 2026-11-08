import '../../i18n';
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { GeoipInfo } from '../../api/types/GeoipInfo';
import i18n from '../../i18n';
import SettingsView from './SettingsView';

const MISSING: GeoipInfo = { status: 'missing', built_at_us: null };
let geoip: GeoipInfo | undefined = MISSING;

vi.mock('../../api/queries', () => ({
  useHealth: () => ({ isPending: false, isError: false, data: { version: '0.1.0' } }),
  useServerInfo: () => ({
    data: geoip === undefined ? undefined : { version: '0.1.0', read_only: true, can_browse: false, geoip },
  }),
}));

describe('SettingsView', () => {
  afterEach(async () => {
    geoip = MISSING;
    await i18n.changeLanguage('en');
  });

  it('shows the DB-IP attribution as plain text, without any link', async () => {
    await i18n.changeLanguage('en');
    render(<SettingsView />);
    const attribution = screen.getByTestId('geoip-attribution');
    expect(attribution).toHaveTextContent('IP geolocation by DB-IP');
    expect(attribution).toHaveTextContent('https://db-ip.com');
    expect(attribution).toHaveTextContent('CC BY 4.0');
    expect(attribution).toHaveTextContent('https://creativecommons.org/licenses/by/4.0/');
    expect(attribution.querySelector('a')).toBeNull();
  });

  it('is translated in French', async () => {
    await i18n.changeLanguage('fr');
    render(<SettingsView />);
    expect(screen.getByTestId('geoip-attribution')).toHaveTextContent('Géolocalisation IP par DB-IP');
    expect(screen.getByTestId('geoip-status')).toHaveTextContent('Aucune base, pays inconnus');
  });

  it('says when the GeoIP database is missing', async () => {
    await i18n.changeLanguage('en');
    render(<SettingsView />);
    const status = screen.getByTestId('geoip-status');
    expect(status).toHaveAttribute('data-status', 'missing');
    expect(status).toHaveTextContent('No database, countries unknown');
  });

  it('shows the build date of an installed database, in UTC', async () => {
    // 2026-11-01T00:30Z: still November 1st in UTC whatever the local time zone.
    geoip = { status: 'available', built_at_us: Date.UTC(2026, 10, 1, 0, 30) * 1000 };
    await i18n.changeLanguage('en');
    const { unmount } = render(<SettingsView />);
    expect(screen.getByTestId('geoip-status')).toHaveTextContent('Database installed, built Nov 1, 2026');
    unmount();

    await i18n.changeLanguage('fr');
    render(<SettingsView />);
    expect(screen.getByTestId('geoip-status')).toHaveTextContent('Base installée, générée le 1 nov. 2026');
  });

  it('handles an undated or unreadable database', async () => {
    geoip = { status: 'available', built_at_us: null };
    const { unmount } = render(<SettingsView />);
    expect(screen.getByTestId('geoip-status')).toHaveTextContent(/^Database installed$/);
    unmount();

    geoip = { status: 'invalid', built_at_us: null };
    render(<SettingsView />);
    const status = screen.getByTestId('geoip-status');
    expect(status).toHaveAttribute('data-status', 'invalid');
    expect(status).toHaveTextContent('Unreadable database, countries unknown');
  });

  it('shows no status before the server info arrives', () => {
    geoip = undefined;
    render(<SettingsView />);
    expect(screen.queryByTestId('geoip-status')).toBeNull();
    expect(screen.getByTestId('geoip-attribution')).toHaveTextContent('DB-IP');
  });
});
