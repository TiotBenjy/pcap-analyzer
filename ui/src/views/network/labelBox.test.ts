import { describe, expect, it } from 'vitest';
import { discHitsBox } from './labelBox';

describe('discHitsBox', () => {
  const box = { left: 100, top: 50, width: 80, height: 16 };

  it('detects a node under the label or touching its edge', () => {
    expect(discHitsBox({ x: 140, y: 58, r: 4 }, box)).toBe(true);
    expect(discHitsBox({ x: 95, y: 58, r: 6 }, box)).toBe(true);
    expect(discHitsBox({ x: 185, y: 70, r: 7 }, box)).toBe(true);
  });

  it('ignores nodes clear of the label, corners included', () => {
    expect(discHitsBox({ x: 90, y: 58, r: 6 }, box)).toBe(false);
    expect(discHitsBox({ x: 140, y: 80, r: 10 }, box)).toBe(false);
    expect(discHitsBox({ x: 186, y: 72, r: 7 }, box)).toBe(false);
  });
});
