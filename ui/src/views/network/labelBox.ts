/** Geometry of the graph labels (viewport pixels). */

/** Box of a label in viewport pixels. */
export interface LabelBox {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** A disc (node) in viewport pixels. */
export interface Disc {
  x: number;
  y: number;
  r: number;
}

/** Whether a node disc overlaps a label box (closest point of the box to the center). */
export function discHitsBox(d: Disc, b: LabelBox): boolean {
  const cx = Math.min(Math.max(d.x, b.left), b.left + b.width);
  const cy = Math.min(Math.max(d.y, b.top), b.top + b.height);
  return (d.x - cx) ** 2 + (d.y - cy) ** 2 < d.r * d.r;
}
