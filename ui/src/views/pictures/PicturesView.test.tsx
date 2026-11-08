import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import * as objectsApi from '../../api/objects';
import * as api from '../../api/sessions';
import type { ObjectItem } from '../../api/types/ObjectItem';
import type { ObjectStats } from '../../api/types/ObjectStats';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/objects', async (importOriginal) => ({
  ...(await importOriginal<typeof objectsApi>()),
  getPictureStats: vi.fn(),
  listPictures: vi.fn(),
  fetchRendition: vi.fn(),
  downloadObject: vi.fn(),
}));

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;
const PNG_URL = 'data:image/png;base64,iVBORw0KGgo=';

function picture(overrides: Partial<ObjectItem> = {}): ObjectItem {
  return {
    sha256: 'ab'.repeat(32),
    size: 16_131,
    mime: 'image/jpeg',
    declared_type: 'image/jpeg',
    width: 640,
    height: 420,
    thumb: 'ready',
    occurrences: 1,
    first_ts_us: T0,
    last_ts_us: T0,
    flow_id: '42',
    client_ip: '192.168.1.24',
    server_ip: '198.51.100.31',
    server_port: 80,
    host: 'images.example.test',
    uri: '/gallery/harbour.jpg',
    url: 'http://images.example.test/gallery/harbour.jpg',
    file_name: 'harbour-abababababab.jpg',
    ...overrides,
  };
}

const ITEMS: ObjectItem[] = [
  picture(),
  picture({
    sha256: 'cd'.repeat(32),
    mime: 'image/png',
    uri: '/mirror/night.png',
    url: 'http://cdn.example.test/mirror/night.png',
    host: 'cdn.example.test',
    occurrences: 2,
    file_name: 'night-cdcdcdcdcdcd.png',
  }),
  picture({
    sha256: 'ef'.repeat(32),
    mime: 'image/svg+xml',
    thumb: 'none',
    width: null,
    height: null,
    uri: '/brand/logo.svg',
    url: 'http://cdn.example.test/brand/logo.svg',
  }),
  picture({ sha256: '01'.repeat(32), thumb: 'failed', width: null, height: null, uri: '/broken/cut.jpg' }),
];

function stats(overrides: Partial<ObjectStats> = {}): ObjectStats {
  return {
    count: 4,
    bytes: 64_000,
    occurrences: 5,
    types: [
      { mime: 'image/jpeg', count: 2 },
      { mime: 'image/png', count: 1 },
      { mime: 'image/svg+xml', count: 1 },
    ],
    hosts: [
      { host: 'images.example.test', count: 2 },
      { host: 'cdn.example.test', count: 2 },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(objectsApi.getPictureStats).mockResolvedValue(stats());
  vi.mocked(objectsApi.listPictures).mockResolvedValue(page(ITEMS));
  vi.mocked(objectsApi.fetchRendition).mockResolvedValue(PNG_URL);
  vi.mocked(objectsApi.downloadObject).mockResolvedValue();
});

it('shows a grid of backend thumbnails, never the original objects', async () => {
  renderApp(`/sessions/${ID}/pictures`);
  const grid = await screen.findByRole('list', { name: 'Extracted images' });
  expect(within(grid).getAllByRole('listitem')).toHaveLength(4);
  await waitFor(() => expect(grid.querySelectorAll('img')).toHaveLength(2));
  for (const img of grid.querySelectorAll('img')) expect(img.getAttribute('src')).toBe(PNG_URL);
  // Only thumbnails are requested, and only for raster images with a rendition.
  const calls = vi.mocked(objectsApi.fetchRendition).mock.calls;
  expect(calls.map((c) => c[2])).toEqual(['thumb', 'thumb']);
  expect(calls.map((c) => c[1])).not.toContain('ef'.repeat(32));
  expect(within(grid).getByText('SVG not displayed')).toBeInTheDocument();
  expect(within(grid).getByText('No preview')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /^harbour\.jpg, / })).toHaveAttribute(
    'title',
    'http://images.example.test/gallery/harbour.jpg',
  );
  const summary = screen.getByTestId('pictures-summary');
  expect(within(summary).getByText('5')).toBeInTheDocument();
});

it('opens the viewer with metadata, navigation and download', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/pictures`);
  await user.click(await screen.findByRole('button', { name: /^harbour\.jpg, / }));
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).getByText('1 of 4')).toBeInTheDocument();
  expect(within(dialog).getByText('http://images.example.test/gallery/harbour.jpg')).toBeInTheDocument();
  expect(within(dialog).getByText('640 \u00d7 420')).toBeInTheDocument();
  await waitFor(() => expect(within(dialog).getByRole('img', { name: 'harbour.jpg' })).toHaveAttribute('src', PNG_URL));
  expect(vi.mocked(objectsApi.fetchRendition).mock.calls.some((c) => c[2] === 'preview')).toBe(true);

  await user.click(within(dialog).getByRole('button', { name: 'Download' }));
  expect(objectsApi.downloadObject).toHaveBeenCalledWith(ID, expect.objectContaining({ sha256: 'ab'.repeat(32) }));

  await user.click(within(dialog).getByRole('button', { name: 'Next image' }));
  expect(within(dialog).getByText('2 of 4')).toBeInTheDocument();
  fireEvent.keyDown(document, { key: 'ArrowRight' });
  expect(within(dialog).getByText('3 of 4')).toBeInTheDocument();
  // The SVG is never rendered: a note instead of a preview.
  expect(within(dialog).getByText(/SVG files are never displayed/)).toBeInTheDocument();
  expect(within(dialog).queryByRole('img')).toBeNull();
  fireEvent.keyDown(document, { key: 'ArrowLeft' });
  expect(within(dialog).getByText('2 of 4')).toBeInTheDocument();
  await user.click(within(dialog).getByRole('button', { name: 'Previous image' }));
  expect(within(dialog).getByRole('button', { name: 'Previous image' })).toBeDisabled();
});

it('filters by type, host and text on the server', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/pictures`);
  await screen.findByRole('list', { name: 'Extracted images' });
  await user.selectOptions(screen.getByRole('combobox', { name: 'Type' }), 'image/png');
  await waitFor(() =>
    expect(objectsApi.listPictures).toHaveBeenLastCalledWith(
      ID,
      expect.objectContaining({ type: 'image/png' }),
      expect.anything(),
      expect.anything(),
    ),
  );
  await user.selectOptions(screen.getByRole('combobox', { name: 'Host' }), 'cdn.example.test');
  await user.selectOptions(screen.getByRole('combobox', { name: 'Order' }), 'size');
  await user.type(screen.getByRole('searchbox'), 'night');
  await waitFor(() =>
    expect(objectsApi.listPictures).toHaveBeenLastCalledWith(
      ID,
      { type: 'image/png', host: 'cdn.example.test', q: 'night', sort: 'size' },
      expect.anything(),
      expect.anything(),
    ),
  );
  vi.mocked(objectsApi.listPictures).mockResolvedValue(page([]));
  await user.type(screen.getByRole('searchbox'), 'x');
  expect(await screen.findByText('No image matches these filters')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Clear filters' }));
  expect(screen.getByRole('searchbox')).toHaveValue('');
});

it('virtualizes long grids', async () => {
  // jsdom has no layout: give the scrolling area a size, as a browser would.
  vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockReturnValue(720);
  vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(1000);
  const many = Array.from({ length: 1200 }, (_, i) =>
    picture({ sha256: i.toString(16).padStart(64, '0'), uri: `/img/${i}.jpg` }),
  );
  vi.mocked(objectsApi.listPictures).mockResolvedValue(page(many));
  vi.mocked(objectsApi.getPictureStats).mockResolvedValue(stats({ count: 1200 }));
  renderApp(`/sessions/${ID}/pictures`);
  const grid = await screen.findByRole('list', { name: 'Extracted images' });
  const rendered = within(grid).getAllByRole('listitem').length;
  expect(rendered).toBeGreaterThan(0);
  expect(rendered).toBeLessThan(200);
  vi.restoreAllMocks();
});

it('explains an empty session', async () => {
  vi.mocked(objectsApi.listPictures).mockResolvedValue(page([]));
  vi.mocked(objectsApi.getPictureStats).mockResolvedValue(stats({ count: 0, bytes: 0, occurrences: 0, types: [], hosts: [] }));
  renderApp(`/sessions/${ID}/pictures`);
  expect(await screen.findByText('No image in this session')).toBeInTheDocument();
});
