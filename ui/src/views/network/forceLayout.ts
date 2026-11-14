// ForceAtlas2 run with a fixed number of iterations: the layout is computed once, then frozen
// (docs/UI_GUIDELINES.md, "Graphes"). Used by the layout worker, and on the main thread when
// workers are unavailable (tests, a refused worker): the graph is bounded by the server
// (about 200 nodes and 400 edges at most), so either way the cost stays small.

import Graph from 'graphology';
import forceAtlas2 from 'graphology-layout-forceatlas2';

export interface LayoutInput {
  nodes: readonly { id: string; x: number; y: number; size: number }[];
  edges: readonly { source: string; target: string; weight: number }[];
}

export type Positions = Record<string, { x: number; y: number }>;

/** Iterations for a graph of `n` nodes: enough to converge, bounded. */
export function iterationsFor(n: number): number {
  if (n <= 1) return 0;
  return Math.min(600, Math.max(150, Math.round(30_000 / n)));
}

/** Positions after ForceAtlas2; nodes keep their start position when there is nothing to do. */
export function runLayout(input: LayoutInput): Positions {
  const graph = new Graph({ type: 'undirected', multi: false, allowSelfLoops: false });
  for (const n of input.nodes) graph.addNode(n.id, { x: n.x, y: n.y, size: n.size });
  for (const e of input.edges) {
    if (graph.hasNode(e.source) && graph.hasNode(e.target) && !graph.hasEdge(e.source, e.target)) {
      // Log weight: heavy pairs pull closer without collapsing the rest.
      graph.addEdge(e.source, e.target, { weight: Math.log1p(Math.max(0, e.weight)) });
    }
  }
  const iterations = iterationsFor(graph.order);
  if (iterations === 0) {
    const out: Positions = {};
    graph.forEachNode((id, a) => {
      out[id] = { x: a.x as number, y: a.y as number };
    });
    return out;
  }
  const settings = {
    ...forceAtlas2.inferSettings(graph),
    gravity: 1,
    strongGravityMode: true,
    scalingRatio: 10,
    barnesHutOptimize: graph.order > 300,
  };
  return forceAtlas2(graph, { iterations, settings, getEdgeWeight: 'weight' });
}
