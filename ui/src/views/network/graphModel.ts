// Pure model of the Network graph: display attributes of the nodes and edges returned by the API
// (already bounded by the server), the graphology graph drawn by sigma, and the ranked pairs of
// the narrow layout. No React, no WebGL: unit tested in jsdom.

import Graph from 'graphology';
import type { AddressCategory } from '../../api/types/AddressCategory';
import type { NetworkEdge } from '../../api/types/NetworkEdge';
import type { NetworkGraph } from '../../api/types/NetworkGraph';
import type { NetworkNode } from '../../api/types/NetworkNode';
import type { NetworkNodeKind } from '../../api/types/NetworkNodeKind';
import { ADDRESS_CATEGORIES, OTHER_COLOR } from '../../charts/palette';

/** Rendered node size bounds in pixels (docs/UI_GUIDELINES.md, "Graphes"). */
export const NODE_SIZE = { min: 4, max: 18 } as const;
/** Edge thickness bounds in pixels: thin, semi-transparent lines. */
export const EDGE_SIZE = { min: 0.5, max: 3 } as const;
/** Longest label drawn on the canvas (the panel shows the full text). */
export const MAX_LABEL = 32;

export interface NodeAttributes {
  label: string;
  /** Full description (address, names, country): panel and search. */
  title: string;
  size: number;
  color: string;
  x: number;
  y: number;
  kind: NetworkNodeKind;
  /** Address category of a host, `null` for groups. */
  category: AddressCategory | null;
  bytes: number;
  /** Lower-case text matched by the search (address, names, country, label). */
  search: string;
}

export interface EdgeAttributes {
  size: number;
  bytes: number;
}

/** Display texts of the group nodes, resolved by the view (no `t` here: see ROADMAP pitfall). */
export interface NodeLabels {
  other: (hosts: number) => string;
  local: (hosts: number) => string;
  unknown: (hosts: number) => string;
  cluster: (country: string, hosts: number) => string;
  country: (country: string, hosts: number) => string;
}

// Control characters and bidirectional overrides of a hostile name would garble the canvas text
// or reorder it visually; they are dropped. The text is drawn with fillText (never parsed as HTML).
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

/** Label safe for the canvas: no control or bidi characters, at most `max` characters. */
export function cleanLabel(text: string, max: number = MAX_LABEL): string {
  const clean = text.replace(UNSAFE_CHARS, '').trim();
  const chars = [...clean];
  return chars.length <= max ? clean : `${chars.slice(0, max - 1).join('')}…`;
}

/** Log-scaled size between the bounds; `maxBytes` is the largest node of the graph. */
export function nodeSize(bytes: number, maxBytes: number): number {
  if (maxBytes <= 0 || bytes <= 0) return NODE_SIZE.min;
  const ratio = Math.log1p(bytes) / Math.log1p(maxBytes);
  return NODE_SIZE.min + Math.min(1, ratio) * (NODE_SIZE.max - NODE_SIZE.min);
}

/** Log-scaled edge thickness between the bounds. */
export function edgeSize(bytes: number, maxBytes: number): number {
  if (maxBytes <= 0 || bytes <= 0) return EDGE_SIZE.min;
  const ratio = Math.log1p(bytes) / Math.log1p(maxBytes);
  return EDGE_SIZE.min + Math.min(1, ratio) * (EDGE_SIZE.max - EDGE_SIZE.min);
}

/** Color of a node: its address category for hosts, the category of its group otherwise. */
export function nodeColor(n: NetworkNode): string {
  switch (n.kind) {
    case 'host':
      return n.endpoint === null ? OTHER_COLOR : ADDRESS_CATEGORIES[n.endpoint.category].color;
    case 'cluster':
    case 'country':
      return ADDRESS_CATEGORIES.public.color;
    case 'local':
      return ADDRESS_CATEGORIES.private.color;
    case 'unknown':
    case 'other':
      return OTHER_COLOR;
  }
}

/** Text of a node (uncut): the first resolved name or the address of a host, a group name. */
export function nodeText(n: NetworkNode, resolveNames: boolean, labels: NodeLabels): string {
  switch (n.kind) {
    case 'host':
      return (resolveNames ? n.endpoint?.names[0] : undefined) ?? n.endpoint?.ip ?? n.id;
    case 'cluster':
      return labels.cluster(n.country ?? '', n.hosts);
    case 'country':
      return labels.country(n.country ?? '', n.hosts);
    case 'local':
      return labels.local(n.hosts);
    case 'unknown':
      return labels.unknown(n.hosts);
    case 'other':
      return labels.other(n.hosts);
  }
}

/** Full description of a node: address, names and country of a host, the group text otherwise. */
export function nodeTitle(n: NetworkNode, labels: NodeLabels): string {
  if (n.kind !== 'host' || n.endpoint === null) return cleanLabel(nodeText(n, true, labels), 200);
  const e = n.endpoint;
  return cleanLabel([e.ip, ...e.names, ...(e.country === null ? [] : [e.country])].join(' '), 200);
}

/** Ids of the nodes with at least one edge in the graph returned. */
export function connectedIds(data: NetworkGraph): Set<string> {
  const ids = new Set<string>();
  for (const e of data.edges) {
    ids.add(e.source);
    ids.add(e.target);
  }
  return ids;
}

/** Nodes drawn: every node, or only those with an edge when orphans are hidden. */
export function visibleNodes(data: NetworkGraph, hideOrphans: boolean): NetworkNode[] {
  if (!hideOrphans) return data.nodes;
  const connected = connectedIds(data);
  return data.nodes.filter((n) => connected.has(n.id));
}

interface BuildOptions {
  hideOrphans: boolean;
  resolveNames: boolean;
  labels: NodeLabels;
}

/**
 * graphology graph of the API answer: undirected, sizes and colors set, nodes placed on a circle
 * by rank (deterministic start of the force layout).
 */
export function buildGraph(data: NetworkGraph, { hideOrphans, resolveNames, labels }: BuildOptions): Graph<NodeAttributes, EdgeAttributes> {
  const graph = new Graph<NodeAttributes, EdgeAttributes>({ type: 'undirected', multi: false, allowSelfLoops: false });
  const nodes = visibleNodes(data, hideOrphans);
  const maxNode = Math.max(0, ...nodes.map((n) => n.bytes));
  const count = Math.max(1, nodes.length);
  nodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / count;
    const text = nodeText(n, resolveNames, labels);
    const title = nodeTitle(n, labels);
    graph.addNode(n.id, {
      label: cleanLabel(text),
      title,
      size: nodeSize(n.bytes, maxNode),
      color: nodeColor(n),
      x: Math.cos(angle),
      y: Math.sin(angle),
      kind: n.kind,
      category: n.endpoint?.category ?? null,
      bytes: n.bytes,
      search: `${title} ${cleanLabel(text, 200)}`.toLowerCase(),
    });
  });
  const maxEdge = Math.max(0, ...data.edges.map((e) => e.bytes));
  for (const e of data.edges) {
    if (!graph.hasNode(e.source) || !graph.hasNode(e.target) || e.source === e.target) continue;
    if (graph.hasEdge(e.source, e.target)) continue;
    graph.addEdgeWithKey(`${e.source}|${e.target}`, e.source, e.target, { size: edgeSize(e.bytes, maxEdge), bytes: e.bytes });
  }
  return graph;
}

/** First node whose address, names or label contain `query` (case-insensitive), largest first. */
export function findNode(graph: Graph<NodeAttributes, EdgeAttributes>, query: string): string | null {
  const q = query.trim().toLowerCase();
  if (q === '') return null;
  let best: string | null = null;
  let bestBytes = -1;
  graph.forEachNode((id, a) => {
    if (a.search.includes(q) && a.bytes > bestBytes) {
      best = id;
      bestBytes = a.bytes;
    }
  });
  return best;
}

export interface RankedPair {
  edge: NetworkEdge;
  source: NetworkNode;
  target: NetworkNode;
}

/** Edges between visible nodes with their ends, most bytes first (narrow and fallback layout). */
export function rankedPairs(data: NetworkGraph, hideOrphans: boolean, limit: number): RankedPair[] {
  const byId = new Map(visibleNodes(data, hideOrphans).map((n) => [n.id, n]));
  const out: RankedPair[] = [];
  for (const edge of data.edges) {
    const source = byId.get(edge.source);
    const target = byId.get(edge.target);
    if (source === undefined || target === undefined) continue;
    out.push({ edge, source, target });
  }
  out.sort((a, b) => b.edge.bytes - a.edge.bytes || a.edge.source.localeCompare(b.edge.source) || a.edge.target.localeCompare(b.edge.target));
  return out.slice(0, limit);
}

export interface Neighbor {
  node: NetworkNode;
  edge: NetworkEdge;
}

/** Neighbors of a node within the graph returned, most bytes first. */
export function neighborsOf(data: NetworkGraph, id: string, limit: number): Neighbor[] {
  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const out: Neighbor[] = [];
  for (const edge of data.edges) {
    const other = edge.source === id ? edge.target : edge.target === id ? edge.source : null;
    const node = other === null ? undefined : byId.get(other);
    if (node !== undefined) out.push({ node, edge });
  }
  out.sort((a, b) => b.edge.bytes - a.edge.bytes);
  return out.slice(0, limit);
}
