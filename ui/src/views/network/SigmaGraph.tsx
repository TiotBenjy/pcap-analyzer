import type Graph from 'graphology';
import { Maximize, ZoomIn, ZoomOut } from 'lucide-react';
import { useEffect, useRef } from 'react';
import type Sigma from 'sigma';
import type { NodeDisplayData, PartialButFor } from 'sigma/types';
import type { Settings } from 'sigma/settings';
import { Button } from '../../components/Button';
import type { Theme } from '../../theme/theme';
import type { EdgeAttributes, NodeAttributes } from './graphModel';

/**
 * Canvas colors (WebGL needs concrete values, not CSS variables): the zinc scale of the theme
 * tokens (styles/index.css). Edges are opaque light tones: sigma blends with premultiplied alpha,
 * so a translucent rgba() color turns white on a light background.
 */
const THEME_COLORS = {
  light: { label: '#27272a', surface: '#ffffff', line: '#d4d4d8', edge: '#d4d4d8', muted: '#e4e4e7' },
  dark: { label: '#e4e4e7', surface: '#18181b', line: '#3f3f46', edge: '#52525b', muted: '#3f3f46' },
} as const;

/** Rendered size above which a node gets its label at rest (sizes are 4 to 18 px). */
const LABEL_THRESHOLD = 14;

type HoverData = PartialButFor<NodeDisplayData, 'x' | 'y' | 'size' | 'label' | 'color'>;

/** Hover box drawn in the theme colors (sigma's default is a white box). */
function hoverDrawer(colors: (typeof THEME_COLORS)[Theme]) {
  return (ctx: CanvasRenderingContext2D, data: HoverData, settings: Settings<NodeAttributes, EdgeAttributes>): void => {
    const size = settings.labelSize;
    ctx.font = `${settings.labelWeight} ${size}px ${settings.labelFont}`;
    ctx.fillStyle = colors.surface;
    ctx.strokeStyle = colors.line;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(data.x, data.y, data.size + 3, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    const label = data.label;
    if (label === null || label === '') return;
    const width = ctx.measureText(label).width;
    const x = data.x + data.size + 5;
    const top = data.y - size / 2 - 4;
    ctx.beginPath();
    ctx.rect(x - 4, top, width + 8, size + 8);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = colors.label;
    ctx.fillText(label, x, data.y + size / 3);
  };
}

interface SigmaGraphProps {
  graph: Graph<NodeAttributes, EdgeAttributes>;
  theme: Theme;
  selected: string | null;
  /** Node to center (search result). */
  focus: string | null;
  onSelect: (id: string | null) => void;
  /** Double click on a country cluster. */
  onExpand: (id: string) => void;
  ariaLabel: string;
  labels: { zoomIn: string; zoomOut: string; reset: string };
}

/**
 * sigma.js renderer of a laid-out graph (WebGL; the caller checks it is available). Labels: only
 * the large nodes at rest (size threshold and label grid), the neighborhood of the hovered or
 * selected node otherwise. Every text is drawn on the canvas, never as HTML.
 */
export function SigmaGraph({ graph, theme, selected, focus, onSelect, onExpand, ariaLabel, labels }: SigmaGraphProps) {
  const container = useRef<HTMLDivElement>(null);
  const renderer = useRef<Sigma<NodeAttributes, EdgeAttributes> | null>(null);
  const hovered = useRef<string | null>(null);
  const selectedRef = useRef(selected);
  const callbacks = useRef({ onSelect, onExpand });
  useEffect(() => {
    callbacks.current = { onSelect, onExpand };
  }, [onSelect, onExpand]);

  useEffect(() => {
    let cancelled = false;
    let instance: Sigma<NodeAttributes, EdgeAttributes> | null = null;
    const colors = THEME_COLORS[theme];
    const host = container.current;
    void import('sigma').then(({ default: SigmaClass }) => {
      const el = container.current;
      if (cancelled || el === null) return;
      const focusOf = () => hovered.current ?? selectedRef.current;
      instance = new SigmaClass<NodeAttributes, EdgeAttributes>(graph, el, {
        allowInvalidContainer: true,
        zIndex: true,
        labelFont: getComputedStyle(el).fontFamily,
        labelSize: 12,
        labelWeight: '500',
        labelColor: { color: colors.label },
        labelDensity: 0.6,
        labelGridCellSize: 120,
        labelRenderedSizeThreshold: LABEL_THRESHOLD,
        defaultEdgeColor: colors.edge,
        defaultDrawNodeHover: hoverDrawer(colors),
        stagePadding: 24,
        minCameraRatio: 0.1,
        maxCameraRatio: 4,
        nodeReducer: (node, data) => {
          const res: Partial<NodeDisplayData> = { ...data };
          const f = focusOf();
          if (f !== null && graph.hasNode(f)) {
            if (node === f || graph.areNeighbors(node, f)) {
              res.forceLabel = true;
              res.zIndex = 1;
            } else {
              res.color = colors.muted;
              res.label = '';
              res.zIndex = 0;
            }
          }
          if (node === selectedRef.current) {
            res.highlighted = true;
            res.zIndex = 2;
          }
          return res;
        },
        edgeReducer: (edge, data) => {
          const f = focusOf();
          if (f !== null && graph.hasNode(f) && !graph.hasExtremity(edge, f)) return { ...data, hidden: true };
          return data;
        },
      });
      const refresh = () => {
        instance?.refresh({ skipIndexation: true });
      };
      instance.on('enterNode', ({ node }) => {
        hovered.current = node;
        refresh();
      });
      instance.on('leaveNode', () => {
        hovered.current = null;
        refresh();
      });
      instance.on('clickNode', ({ node }) => {
        callbacks.current.onSelect(node);
      });
      instance.on('clickStage', () => {
        callbacks.current.onSelect(null);
      });
      instance.on('doubleClickNode', ({ node, preventSigmaDefault }) => {
        preventSigmaDefault();
        if (graph.getNodeAttribute(node, 'kind') === 'cluster') callbacks.current.onExpand(node);
      });
      renderer.current = instance;
      el.dataset.ready = 'true';
    });
    return () => {
      cancelled = true;
      instance?.kill();
      renderer.current = null;
      hovered.current = null;
      if (host !== null) delete host.dataset.ready;
    };
  }, [graph, theme]);

  useEffect(() => {
    selectedRef.current = selected;
    renderer.current?.refresh({ skipIndexation: true });
  }, [selected]);

  useEffect(() => {
    const r = renderer.current;
    if (r === null || focus === null || !graph.hasNode(focus)) return;
    const d = r.getNodeDisplayData(focus);
    if (d === undefined) return;
    void r.getCamera().animate({ x: d.x, y: d.y, ratio: 0.5 }, { duration: 300 });
  }, [focus, graph]);

  const camera = (action: 'in' | 'out' | 'reset') => {
    const c = renderer.current?.getCamera();
    if (c === undefined) return;
    if (action === 'in') void c.animatedZoom({ duration: 200 });
    else if (action === 'out') void c.animatedUnzoom({ duration: 200 });
    else void c.animatedReset({ duration: 200 });
  };

  return (
    <div className="relative min-w-0">
      <div
        ref={container}
        role="img"
        aria-label={ariaLabel}
        data-testid="network-canvas"
        className="h-[420px] w-full overflow-hidden rounded-md border border-line bg-surface lg:h-[560px]"
      />
      <div className="absolute top-2 right-2 flex flex-col gap-1">
        <Button
          variant="secondary"
          icon
          aria-label={labels.zoomIn}
          title={labels.zoomIn}
          onClick={() => {
            camera('in');
          }}
        >
          <ZoomIn aria-hidden size={16} strokeWidth={1.75} />
        </Button>
        <Button
          variant="secondary"
          icon
          aria-label={labels.zoomOut}
          title={labels.zoomOut}
          onClick={() => {
            camera('out');
          }}
        >
          <ZoomOut aria-hidden size={16} strokeWidth={1.75} />
        </Button>
        <Button
          variant="secondary"
          icon
          aria-label={labels.reset}
          title={labels.reset}
          onClick={() => {
            camera('reset');
          }}
        >
          <Maximize aria-hidden size={16} strokeWidth={1.75} />
        </Button>
      </div>
    </div>
  );
}
