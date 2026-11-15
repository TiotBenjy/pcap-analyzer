import '../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import type { Settings } from '../api/types/Settings';
import i18n from '../i18n';
import { setupUser } from '../test/user';
import { NoticeArea } from './NoticeArea';
import { NoticeSlot } from './NoticeSlot';
import { MAX_NOTICES, NOTICE_PROVIDERS } from './providers';
import type { Notice, NoticeProvider } from './types';

const api = vi.hoisted(() => ({ getSettings: vi.fn(), dismissNotice: vi.fn(), updateSettings: vi.fn() }));
vi.mock('../api/settings', () => api);

function settings(dismissed: Record<string, string> = {}): Settings {
  return { online: { geoip_check: false, update_check: false }, dismissed_notices: dismissed };
}

/** Example provider (tests only): shows whatever `current[id]` holds. */
const current: Record<string, Notice | null> = {};
function example(id: string): NoticeProvider {
  return {
    id,
    Component: (slot) => <NoticeSlot slot={slot} notice={current[id] ?? null} />,
  };
}

function notice(message: string, dismissKey = '1', extra: Partial<Notice> = {}): Notice {
  return { message, dismissKey, ...extra };
}

function renderArea(providers: readonly NoticeProvider[], max = MAX_NOTICES) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const utils = render(
    <QueryClientProvider client={client}>
      <NoticeArea providers={providers} max={max} />
    </QueryClientProvider>,
  );
  return {
    ...utils,
    rerenderArea: () => {
      utils.rerender(
        <QueryClientProvider client={client}>
          <NoticeArea providers={providers} max={max} />
        </QueryClientProvider>,
      );
    },
  };
}

beforeEach(() => {
  api.getSettings.mockResolvedValue(settings());
  api.dismissNotice.mockImplementation((id: string, key: string) => Promise.resolve(settings({ [id]: key })));
});

afterEach(async () => {
  for (const id of Object.keys(current)) Reflect.deleteProperty(current, id);
  vi.clearAllMocks();
  await i18n.changeLanguage('en');
});

describe('notice registry', () => {
  it('has no example provider in production and unique sorted ids', () => {
    const ids = NOTICE_PROVIDERS.map((p) => p.id);
    expect(ids).toEqual([...new Set(ids)].sort());
    for (const id of ids) expect(id).toMatch(/^[a-z0-9][a-z0-9._-]{0,63}$/);
    expect(MAX_NOTICES).toBeGreaterThanOrEqual(1);
  });

  it('renders nothing and reads no settings while no provider has a notice', async () => {
    current.geoip = null;
    renderArea([example('geoip')]);
    const area = screen.getByTestId('notice-area');
    await Promise.resolve();
    expect(area).toBeEmptyDOMElement();
    expect(area).not.toHaveAttribute('role');
    expect(api.getSettings).not.toHaveBeenCalled();
  });
});

describe('NoticeArea', () => {
  it('shows a notice with its detail and actions once the dismissals are known', async () => {
    const onClick = vi.fn();
    current.update = notice('Version 0.2.0 is available', '0.2.0', {
      detail: 'Release notes',
      actions: [{ label: 'Download', onClick, primary: true }, { label: 'Later', onClick: vi.fn(), disabled: true, title: 'Why' }],
    });
    renderArea([example('update')]);
    const banner = await screen.findByTestId('notice-update');
    expect(banner).toHaveTextContent('Version 0.2.0 is available');
    expect(banner).toHaveTextContent('Release notes');
    expect(screen.getByRole('region', { name: 'Application notices' })).toContainElement(banner);
    await setupUser().click(within(banner).getByRole('button', { name: 'Download' }));
    expect(onClick).toHaveBeenCalledOnce();
    expect(within(banner).getByRole('button', { name: 'Later' })).toBeDisabled();
    expect(api.getSettings).toHaveBeenCalledOnce();
  });

  it('keeps a notice dismissed until its key changes', async () => {
    api.getSettings.mockResolvedValue(settings({ geoip: '2026-10' }));
    current.geoip = notice('GeoIP database outdated', '2026-10');
    const { rerenderArea } = renderArea([example('geoip')]);
    await waitFor(() => {
      expect(api.getSettings).toHaveBeenCalled();
    });
    await Promise.resolve();
    expect(screen.queryByTestId('notice-geoip')).not.toBeInTheDocument();

    current.geoip = notice('GeoIP database outdated', '2026-11');
    rerenderArea();
    expect(await screen.findByTestId('notice-geoip')).toBeInTheDocument();
  });

  it('dismisses on the server and hides at once, even when the server refuses', async () => {
    current.geoip = notice('GeoIP database outdated', '2026-11');
    renderArea([example('geoip')]);
    const user = setupUser();
    await user.click(within(await screen.findByTestId('notice-geoip')).getByRole('button', { name: 'Dismiss' }));
    expect(api.dismissNotice).toHaveBeenCalledWith('geoip', '2026-11');
    expect(screen.queryByTestId('notice-geoip')).not.toBeInTheDocument();

    // Read-only server: refused, still hidden for this session.
    api.dismissNotice.mockRejectedValue(new ApiError(403, 'urn:netsift:problem:read-only', 'read-only'));
    current.update = notice('Version 0.2.0 is available', '0.2.0');
    const second = renderArea([example('update')]);
    await user.click(within(await screen.findByTestId('notice-update')).getByRole('button', { name: 'Dismiss' }));
    await waitFor(() => {
      expect(api.dismissNotice).toHaveBeenCalledWith('update', '0.2.0');
    });
    second.rerenderArea();
    expect(screen.queryByTestId('notice-update')).not.toBeInTheDocument();
  });

  it('stacks at most `max` notices in registry order; a dismissal lets the next one in', async () => {
    current.a = notice('First notice');
    current.b = notice('Second notice');
    current.c = notice('Third notice');
    renderArea([example('a'), example('b'), example('c')], 2);
    await screen.findByTestId('notice-a');
    const area = screen.getByTestId('notice-area');
    expect(within(area).getAllByRole('button', { name: 'Dismiss' })).toHaveLength(2);
    expect(area.textContent).toMatch(/First notice.*Second notice/);
    expect(screen.queryByTestId('notice-c')).not.toBeInTheDocument();

    await setupUser().click(within(screen.getByTestId('notice-a')).getByRole('button', { name: 'Dismiss' }));
    expect(await screen.findByTestId('notice-c')).toBeInTheDocument();
    expect(screen.queryByTestId('notice-a')).not.toBeInTheDocument();
  });

  it('shows the notices when the settings cannot be read', async () => {
    api.getSettings.mockRejectedValue(new ApiError(0, 'network', 'down'));
    current.geoip = notice('GeoIP database outdated');
    renderArea([example('geoip')]);
    expect(await screen.findByTestId('notice-geoip')).toBeInTheDocument();
  });

  it('withdraws a notice its provider no longer reports', async () => {
    current.geoip = notice('GeoIP database outdated');
    const { rerenderArea } = renderArea([example('geoip')]);
    await screen.findByTestId('notice-geoip');
    current.geoip = null;
    rerenderArea();
    await waitFor(() => {
      expect(screen.queryByTestId('notice-geoip')).not.toBeInTheDocument();
    });
  });

  it('labels the dismiss button in French', async () => {
    await i18n.changeLanguage('fr');
    current.geoip = notice('Base GeoIP ancienne');
    renderArea([example('geoip')]);
    const banner = await screen.findByTestId('notice-geoip');
    expect(within(banner).getByRole('button', { name: 'Masquer' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: "Notifications de l'application" })).toBeInTheDocument();
  });
});
