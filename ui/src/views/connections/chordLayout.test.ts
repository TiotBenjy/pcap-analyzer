import { describe, expect, it } from 'vitest';
import { layoutChord, MAX_LABEL_CHARS, rankedPairs, truncateLabel } from './chordLayout';

/** Star around node 0 with `n` leaves of decreasing volume, plus some leaf-to-leaf traffic. */
function star(n: number): number[][] {
  const m = Array.from({ length: n + 1 }, () => Array<number>(n + 1).fill(0));
  for (let i = 1; i <= n; i++) {
    const row = m[i];
    const hub = m[0];
    if (row === undefined || hub === undefined) continue;
    row[0] = 10_000 / i ** 2;
    hub[i] = 2_000 / i;
  }
  return m;
}

const overlap = (a: { left: number; right: number; top: number; bottom: number }, b: typeof a) =>
  a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;

describe('chord layout', () => {
  it('has nothing to draw without traffic or room', () => {
    expect(layoutChord([], [], 800)).toBeNull();
    expect(layoutChord([[0, 0], [0, 0]], ['a', 'b'], 800)).toBeNull();
    expect(layoutChord(star(3), ['a', 'b', 'c', 'd'], 150)).toBeNull();
  });

  it('places one arc per node and one ribbon per direction with traffic', () => {
    const geo = layoutChord(star(3), ['hub', 'a', 'b', 'c'], 600);
    expect(geo).not.toBeNull();
    if (geo === null) return;
    expect(geo.groups).toHaveLength(4);
    expect(geo.ribbons).toHaveLength(6);
    expect(geo.size).toBe(600);
    for (const g of geo.groups) expect(g.path).toMatch(/^M/);
    const toHub = geo.ribbons.find((r) => r.source === 1 && r.target === 0);
    expect(toHub?.forward).toBe(10_000);
    expect(toHub?.backward).toBe(2_000);
    expect(geo.labels.every((l) => l.visible)).toBe(true);
  });

  it.each([560, 640, 900])('keeps visible labels apart and inside the drawing at %i px', (width) => {
    const names = Array.from({ length: 16 }, (_, i) => (i === 0 ? '192.168.100.200' : `host-${i}.very-long-domain.example.test`));
    const geo = layoutChord(star(15), names, width);
    expect(geo).not.toBeNull();
    if (geo === null) return;
    const half = geo.size / 2;
    const visible = geo.labels.filter((l) => l.visible);
    expect(visible.length).toBeGreaterThan(2);
    // The smallest arcs are too close to their neighbours: their labels are hidden.
    expect(visible.length).toBeLessThan(geo.labels.length);
    visible.forEach((a, i) => {
      expect(a.text.length).toBeLessThanOrEqual(MAX_LABEL_CHARS);
      expect(a.box.left).toBeGreaterThanOrEqual(-half);
      expect(a.box.right).toBeLessThanOrEqual(half);
      expect(a.box.top).toBeGreaterThanOrEqual(-half);
      expect(a.box.bottom).toBeLessThanOrEqual(half);
      for (const b of visible.slice(i + 1)) expect(overlap(a.box, b.box), `${a.text} / ${b.text}`).toBe(false);
    });
    // The largest group (the hub) always keeps its label.
    expect(geo.labels.find((l) => l.index === 0)?.visible).toBe(true);
  });

  it('orients labels outwards on both halves', () => {
    const geo = layoutChord(star(3), ['hub', 'a', 'b', 'c'], 600);
    const anchors = new Set(geo?.labels.map((l) => l.anchor));
    expect(anchors).toEqual(new Set(['start', 'end']));
  });

  it('truncates labels to 18 characters', () => {
    expect(truncateLabel('short')).toBe('short');
    const t = truncateLabel('a-very-long-host-name.example.test');
    expect(t).toHaveLength(18);
    expect(t.endsWith('…')).toBe(true);
  });

  it('ranks pairs by bytes in both directions', () => {
    const m = [
      [0, 5, 1],
      [50, 0, 0],
      [0, 7, 3],
    ];
    expect(rankedPairs(m)).toEqual([
      { a: 0, b: 1, ab: 5, ba: 50 },
      { a: 1, b: 2, ab: 0, ba: 7 },
      { a: 2, b: 2, ab: 3, ba: 0 },
      { a: 0, b: 2, ab: 1, ba: 0 },
    ]);
  });
});
