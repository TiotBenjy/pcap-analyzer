import { describe, expect, it, vi } from 'vitest';
import { fetchAll } from './sessionQueries';
import type { Page } from './types/Page';

const page = (items: number[], next: string | null): Page<number> => ({ items, next_cursor: next, total_estimate: null });

describe('fetchAll', () => {
  it('follows cursors to the last page', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce(page([1, 2], 'a'))
      .mockResolvedValueOnce(page([3], null));
    expect(await fetchAll(fetchPage)).toEqual({ items: [1, 2, 3], truncated: false });
    expect(fetchPage).toHaveBeenLastCalledWith({ limit: 1000, cursor: 'a' });
  });

  it('stops at the row limit', async () => {
    const fetchPage = vi.fn().mockResolvedValue(page([1, 2, 3], 'more'));
    expect(await fetchAll(fetchPage, 4)).toEqual({ items: [1, 2, 3, 1], truncated: true });
  });

  it('stops on an empty page that still has a cursor', async () => {
    const fetchPage = vi.fn().mockResolvedValueOnce(page([1], 'a')).mockResolvedValue(page([], 'b'));
    expect(await fetchAll(fetchPage)).toEqual({ items: [1], truncated: true });
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  it('bounds the number of pages', async () => {
    const fetchPage = vi.fn().mockResolvedValue(page([1], 'again'));
    const res = await fetchAll(fetchPage, 2000);
    expect(res.truncated).toBe(true);
    expect(fetchPage).toHaveBeenCalledTimes(3);
  });
});
