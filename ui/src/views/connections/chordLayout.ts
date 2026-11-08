import { type Chord, type ChordSubgroup, chordDirected, ribbon } from 'd3-chord';
import { arc } from 'd3-shape';

// Geometry of the chord diagram (pure: unit-tested without a browser).
//
// Labels sit outside the circle, oriented along the radius, in a monospace font whose width is
// known (0.6 em per character), so their boxes can be computed exactly. A label is shown only
// when its axis-aligned box (what the visual tests measure) overlaps no label already placed,
// larger groups first; hidden labels appear on hover.

/** Labels are cut to this many characters. */
export const MAX_LABEL_CHARS = 18;
export const LABEL_FONT_SIZE = 12;
/** Advance of one character of the label font (JetBrains Mono: 0.6 em). */
const CHAR_WIDTH = LABEL_FONT_SIZE * 0.6;
/** Height reserved for a label line (ascent + descent of the font, with margin). */
const LABEL_HEIGHT = 18;
/** Gap between the arcs and the labels. */
const LABEL_GAP = 6;
const ARC_WIDTH = 14;
/** Angular step and largest slide of a label along its arc, in radians (1 and 8 degrees). */
const SHIFT_STEP = Math.PI / 180;
const MAX_SHIFT = (8 * Math.PI) / 180;

/** Offsets tried for a label, nearest to the middle of its arc first: 0, +1, -1, +2, -2... degrees. */
function shifts(reach: number): number[] {
  const out = [0];
  for (let d = SHIFT_STEP; d <= reach + 1e-9; d += SHIFT_STEP) out.push(d, -d);
  return out;
}

/** Largest diagram side, in px. */
export const MAX_SIZE = 640;
/** Below this outer radius the diagram is unreadable: the caller shows a ranked list instead. */
export const MIN_RADIUS = 70;

export function truncateLabel(s: string, max = MAX_LABEL_CHARS): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

interface Box {
  left: number;
  right: number;
  top: number;
  bottom: number;
}

export interface ChordGroupShape {
  index: number;
  startAngle: number;
  endAngle: number;
  path: string;
}

export interface ChordRibbonShape {
  /** Sending node. */
  source: number;
  /** Receiving node. */
  target: number;
  /** Bytes from `source` to `target` (the ribbon), and back (another ribbon). */
  forward: number;
  backward: number;
  path: string;
}

export interface ChordLabel {
  index: number;
  text: string;
  /** SVG transform placing the text (origin at the center of the diagram). */
  transform: string;
  anchor: 'start' | 'end';
  visible: boolean;
  box: Box;
}

export interface ChordGeometry {
  /** Side of the square SVG; its viewBox is centered on the origin. */
  size: number;
  outer: number;
  inner: number;
  groups: ChordGroupShape[];
  ribbons: ChordRibbonShape[];
  labels: ChordLabel[];
}

/** Axis-aligned box of a label along the radius at `angle` (d3: 0 at noon, clockwise). */
function labelBox(angle: number, from: number, width: number): Box {
  const d = { x: Math.sin(angle), y: -Math.cos(angle) };
  const n = { x: Math.cos(angle), y: Math.sin(angle) };
  const xs: number[] = [];
  const ys: number[] = [];
  for (const t of [from, from + width]) {
    for (const s of [-LABEL_HEIGHT / 2, LABEL_HEIGHT / 2]) {
      xs.push(d.x * t + n.x * s);
      ys.push(d.y * t + n.y * s);
    }
  }
  return { left: Math.min(...xs), right: Math.max(...xs), top: Math.min(...ys), bottom: Math.max(...ys) };
}

function overlaps(a: Box, b: Box): boolean {
  return a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
}

/**
 * Layout of `matrix` (`matrix[i][j]`: bytes from node `i` to node `j`) in a container `width`
 * px wide. `null` when there is nothing to draw or not enough room.
 */
export function layoutChord(matrix: readonly (readonly number[])[], names: readonly string[], width: number): ChordGeometry | null {
  const n = matrix.length;
  const total = matrix.reduce((s, row) => s + row.reduce((a, b) => a + b, 0), 0);
  if (n === 0 || total <= 0) return null;
  const texts = names.map((name) => truncateLabel(name));
  const longest = Math.max(...texts.map((s) => s.length), 1);
  const labelSpace = LABEL_GAP + longest * CHAR_WIDTH + 4;
  const size = Math.floor(Math.min(width, MAX_SIZE));
  const outer = size / 2 - labelSpace;
  if (outer < MIN_RADIUS) return null;
  const inner = outer - ARC_WIDTH;

  // Directed layout: one ribbon per direction, as wide at both ends; an arc spans what its node
  // sends and receives.
  const layout = chordDirected()
    .padAngle(Math.min(0.04, (Math.PI * 2) / (n * 8)))
    .sortSubgroups((a, b) => b - a)(matrix.map((row) => [...row]));
  const arcPath = arc<{ startAngle: number; endAngle: number }>().innerRadius(inner).outerRadius(outer);
  const ribbonPath = ribbon<Chord, ChordSubgroup>().radius(inner - 1);

  const groups: ChordGroupShape[] = layout.groups.map((g) => ({
    index: g.index,
    startAngle: g.startAngle,
    endAngle: g.endAngle,
    path: arcPath(g) ?? '',
  }));
  const ribbons: ChordRibbonShape[] = layout.map((c) => ({
    source: c.source.index,
    target: c.target.index,
    forward: matrix[c.source.index]?.[c.target.index] ?? 0,
    backward: c.source.index === c.target.index ? 0 : (matrix[c.target.index]?.[c.source.index] ?? 0),
    path: (ribbonPath(c) as string | null | undefined) ?? '',
  }));

  // Larger groups get their label first.
  const order = [...groups].sort((a, b) => b.endAngle - b.startAngle - (a.endAngle - a.startAngle) || a.index - b.index);
  const placed: Box[] = [];
  const labels = new Map<number, ChordLabel>();
  const from = outer + LABEL_GAP;
  for (const g of order) {
    const text = texts[g.index] ?? '';
    const mid = (g.startAngle + g.endAngle) / 2;
    // The label may slide along its own arc (never past it, at most MAX_SHIFT) to clear a
    // label already placed: a large arc is not left unnamed because of a neighbour.
    const reach = Math.max(0, Math.min((g.endAngle - g.startAngle) / 2 - SHIFT_STEP / 2, MAX_SHIFT));
    let angle = mid;
    let box = labelBox(mid, from, text.length * CHAR_WIDTH);
    let visible = false;
    if (text !== '') {
      for (const offset of shifts(reach)) {
        const candidate = labelBox(mid + offset, from, text.length * CHAR_WIDTH);
        if (!placed.some((p) => overlaps(p, candidate))) {
          angle = mid + offset;
          box = candidate;
          visible = true;
          break;
        }
      }
    }
    if (visible) placed.push(box);
    const degrees = (angle * 180) / Math.PI;
    const right = angle < Math.PI;
    labels.set(g.index, {
      index: g.index,
      text,
      transform: right ? `rotate(${degrees - 90}) translate(${from},0)` : `rotate(${degrees + 90}) translate(${-from},0)`,
      anchor: right ? 'start' : 'end',
      visible,
      box,
    });
  }
  return {
    size,
    outer,
    inner,
    groups,
    ribbons,
    labels: groups.map((g) => labels.get(g.index)).filter((l): l is ChordLabel => l !== undefined),
  };
}

/** Pairs of nodes ranked by bytes exchanged (both directions), for the narrow layout. */
export function rankedPairs(matrix: readonly (readonly number[])[]): { a: number; b: number; ab: number; ba: number }[] {
  const pairs: { a: number; b: number; ab: number; ba: number }[] = [];
  for (let a = 0; a < matrix.length; a++) {
    for (let b = a; b < matrix.length; b++) {
      const ab = matrix[a]?.[b] ?? 0;
      const ba = a === b ? 0 : (matrix[b]?.[a] ?? 0);
      if (ab + ba > 0) pairs.push({ a, b, ab, ba });
    }
  }
  return pairs.sort((x, y) => y.ab + y.ba - (x.ab + x.ba) || x.a - y.a || x.b - y.b);
}
