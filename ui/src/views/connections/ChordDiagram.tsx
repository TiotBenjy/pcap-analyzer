import { type PointerEvent, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { OTHER_COLOR } from '../../charts/palette';
import { formatBytes } from '../../lib/format';
import { LABEL_FONT_SIZE, layoutChord } from './chordLayout';

export interface ChordNodeView {
  /** Full label (address or name), shown on hover. */
  label: string;
  color: string;
  /** Category or "other hosts", second line of the tooltip. */
  detail: string;
}

interface ChordDiagramProps {
  matrix: readonly (readonly number[])[];
  nodes: readonly ChordNodeView[];
  width: number;
  ariaLabel: string;
}

type Hover = { kind: 'group'; index: number } | { kind: 'ribbon'; index: number } | null;

/**
 * Chord diagram (d3-chord geometry, plain SVG): arcs colored by address category, ribbons by
 * the sending node; hovering (or focusing) an arc highlights its ribbons. `null` when there is
 * not enough room (the caller shows the ranked list).
 */
export function ChordDiagram({ matrix, nodes, width, ariaLabel }: ChordDiagramProps) {
  const { t } = useTranslation();
  const names = useMemo(() => nodes.map((n) => n.label), [nodes]);
  const geo = useMemo(() => layoutChord(matrix, names, width), [matrix, names, width]);
  const [hover, setHover] = useState<Hover>(null);
  const [pointer, setPointer] = useState<{ x: number; y: number } | null>(null);
  const box = useRef<HTMLDivElement>(null);
  if (geo === null) return null;

  const sent = (i: number) => (matrix[i] ?? []).reduce((a, b) => a + b, 0);
  const received = (i: number) => matrix.reduce((s, row) => s + (row[i] ?? 0), 0);
  const color = (i: number) => nodes[i]?.color ?? OTHER_COLOR;
  const touches = (r: { source: number; target: number }, i: number) => r.source === i || r.target === i;

  const move = (e: PointerEvent) => {
    const rect = box.current?.getBoundingClientRect();
    if (rect !== undefined) setPointer({ x: e.clientX - rect.left, y: e.clientY - rect.top });
  };

  let tooltip: string[] | null = null;
  if (hover?.kind === 'group') {
    const n = nodes[hover.index];
    tooltip = [
      n?.label ?? '',
      n?.detail ?? '',
      t('views.connections.chord.sent', { bytes: formatBytes(sent(hover.index)) }),
      t('views.connections.chord.received', { bytes: formatBytes(received(hover.index)) }),
    ];
  } else if (hover?.kind === 'ribbon') {
    const r = geo.ribbons[hover.index];
    if (r !== undefined) {
      const a = nodes[r.source]?.label ?? '';
      const b = nodes[r.target]?.label ?? '';
      tooltip = [t('views.connections.chord.aToB', { a, b, bytes: formatBytes(r.forward) })];
      if (r.source !== r.target) tooltip.push(t('views.connections.chord.aToB', { a: b, b: a, bytes: formatBytes(r.backward) }));
    }
  }
  const half = geo.size / 2;

  return (
    <div ref={box} className="relative mx-auto" style={{ width: geo.size, maxWidth: '100%' }}>
      <svg
        role="img"
        aria-label={ariaLabel}
        viewBox={`${-half} ${-half} ${geo.size} ${geo.size}`}
        width={geo.size}
        height={geo.size}
        className="block max-w-full"
        onPointerMove={move}
        onPointerLeave={() => {
          setHover(null);
          setPointer(null);
        }}
      >
        <g fillOpacity={0.62}>
          {geo.ribbons.map((r, i) => {
            const dim =
              (hover?.kind === 'group' && !touches(r, hover.index)) || (hover?.kind === 'ribbon' && hover.index !== i);
            return (
              <path
                key={`${r.source}-${r.target}`}
                d={r.path}
                fill={color(r.source)}
                opacity={dim ? 0.12 : 1}
                onPointerEnter={() => {
                  setHover({ kind: 'ribbon', index: i });
                }}
              />
            );
          })}
        </g>
        <g>
          {geo.groups.map((g) => (
            <path
              key={g.index}
              d={g.path}
              fill={color(g.index)}
              tabIndex={0}
              role="button"
              aria-label={`${nodes[g.index]?.label ?? ''}, ${nodes[g.index]?.detail ?? ''}`}
              className="cursor-pointer outline-none focus-visible:stroke-[var(--ns-accent)] focus-visible:stroke-2"
              onPointerEnter={() => {
                setHover({ kind: 'group', index: g.index });
              }}
              onFocus={() => {
                setHover({ kind: 'group', index: g.index });
                setPointer({ x: half, y: 24 });
              }}
              onBlur={() => {
                setHover(null);
              }}
            />
          ))}
        </g>
        <g fontSize={LABEL_FONT_SIZE} className="fill-[var(--ns-fg)] font-mono" pointerEvents="none">
          {/* Hidden labels (too close to a larger one) are named by the tooltip on hover. */}
          {geo.labels
            .filter((l) => l.visible)
            .map((l) => (
              <text key={l.index} transform={l.transform} textAnchor={l.anchor} dy="0.35em">
                {l.text}
              </text>
            ))}
        </g>
      </svg>
      {tooltip !== null && pointer !== null && (
        <div
          role="tooltip"
          className="pointer-events-none absolute z-10 max-w-64 rounded-md border border-line bg-surface px-2 py-1.5 text-meta shadow-xs"
          style={{
            left: Math.min(pointer.x + 12, Math.max(0, geo.size - 200)),
            top: pointer.y + 12,
          }}
        >
          {tooltip.map((line, i) => (
            <div key={i} className={i === 0 ? 'font-medium break-all' : 'text-muted'}>
              {line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
