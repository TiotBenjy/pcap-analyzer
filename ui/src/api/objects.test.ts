import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { fetchRendition, hasRendition, listPictures } from './objects';

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  fetchMock.mockReset();
  vi.unstubAllGlobals();
});

const SHA = 'ab'.repeat(32);

it('lists images with the server-side filters', async () => {
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ items: [], next_cursor: null, total_estimate: 0 }), {
      headers: { 'Content-Type': 'application/json' },
    }),
  );
  await listPictures('S1', { q: ' night ', type: 'image/png', host: 'cdn.test', sort: 'size' }, { limit: 50 });
  const url = String(fetchMock.mock.calls[0]?.[0]);
  expect(url).toBe('/api/v1/sessions/S1/objects?limit=50&kind=image&sort=size&order=desc&type=image%2Fpng&host=cdn.test&q=night');
});

it('turns a PNG rendition into a data URL and refuses anything else', async () => {
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
  fetchMock.mockResolvedValueOnce(new Response(png, { headers: { 'Content-Type': 'image/png' } }));
  const url = await fetchRendition('S1', SHA, 'thumb');
  expect(url).toBe('data:image/png;base64,iVBORw==');
  expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`/api/v1/sessions/S1/objects/${SHA}/thumb`);

  fetchMock.mockResolvedValueOnce(new Response('<svg/>', { headers: { 'Content-Type': 'image/svg+xml' } }));
  await expect(fetchRendition('S1', SHA, 'preview')).rejects.toThrow();
});

it('knows which objects have a rendition', () => {
  expect(hasRendition({ thumb: 'ready' })).toBe(true);
  expect(hasRendition({ thumb: 'pending' })).toBe(true);
  expect(hasRendition({ thumb: 'none' })).toBe(false);
  expect(hasRendition({ thumb: 'failed' })).toBe(false);
});
