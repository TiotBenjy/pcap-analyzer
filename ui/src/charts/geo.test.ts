import { describe, expect, it } from 'vitest';
import { anchorOf, clampRing } from './geo';
import { NUMERIC_TO_ALPHA2 } from './isoCountries';

describe('world map geometry', () => {
  it('moves the minority side of an antimeridian ring onto the 180th meridian', () => {
    const ring = [
      [170, 60],
      [179, 60],
      [-179, 62],
      [-178, 65],
      [175, 66],
      [170, 60],
    ];
    expect(clampRing(ring).map((p) => p[0])).toEqual([170, 179, 180, 180, 175, 170]);
    const plain = [
      [0, 0],
      [1, 0],
      [1, 1],
      [0, 0],
    ];
    expect(clampRing(plain)).toEqual(plain);
  });

  it('anchors a country at the centroid of its largest polygon', () => {
    const square = (x: number, y: number, size: number) => [
      [
        [x, y],
        [x + size, y],
        [x + size, y + size],
        [x, y + size],
        [x, y],
      ],
    ];
    expect(anchorOf({ type: 'MultiPolygon', coordinates: [square(0, 0, 1), square(10, 10, 4)] })).toEqual([12, 12]);
    expect(anchorOf({ type: 'Point', coordinates: [1, 2] })).toBeNull();
    expect(anchorOf(null)).toBeNull();
  });

  it('maps ISO numeric codes to alpha-2 codes', () => {
    expect(NUMERIC_TO_ALPHA2.get('250')).toBe('FR');
    expect(NUMERIC_TO_ALPHA2.get('840')).toBe('US');
    expect(NUMERIC_TO_ALPHA2.get('999')).toBeUndefined();
  });
});
