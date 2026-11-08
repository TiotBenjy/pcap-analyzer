import '../../i18n';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import SettingsView from './SettingsView';

vi.mock('../../api/queries', () => ({
  useHealth: () => ({ isPending: false, isError: false, data: { version: '0.1.0' } }),
  useServerInfo: () => ({ data: { read_only: true } }),
}));

describe('SettingsView', () => {
  it('shows the DB-IP attribution as plain text, without any link', async () => {
    await i18n.changeLanguage('en');
    render(<SettingsView />);
    const geoip = screen.getByTestId('geoip-attribution');
    expect(geoip).toHaveTextContent('IP geolocation by DB-IP');
    expect(geoip).toHaveTextContent('https://db-ip.com');
    expect(geoip).toHaveTextContent('CC BY 4.0');
    expect(geoip).toHaveTextContent('https://creativecommons.org/licenses/by/4.0/');
    expect(geoip.querySelector('a')).toBeNull();
  });

  it('is translated in French', async () => {
    await i18n.changeLanguage('fr');
    render(<SettingsView />);
    expect(screen.getByTestId('geoip-attribution')).toHaveTextContent('Géolocalisation IP par DB-IP');
    await i18n.changeLanguage('en');
  });
});
