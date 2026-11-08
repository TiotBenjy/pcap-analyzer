import { describe, expect, it } from 'vitest';
import type { Endpoint } from '../../api/types/Endpoint';
import type { NetworkEdge } from '../../api/types/NetworkEdge';
import type { NetworkGraph } from '../../api/types/NetworkGraph';
import type { NetworkNode } from '../../api/types/NetworkNode';
import { ADDRESS_CATEGORIES, OTHER_COLOR } from '../../charts/palette';
import { iterationsFor, runLayout } from './forceLayout';
import {
  buildGraph,
  cleanLabel,
  EDGE_SIZE,
  edgeSize,
  findNode,
  MAX_LABEL,
  type NodeLabels,
  NODE_SIZE,
  neighborsOf,
  nodeSize,
  rankedPairs,
  visibleNodes,
} from './graphModel';

const labels: NodeLabels = {
  other: (n) => `Other ${n}`,
  local: (n) => `Local ${n}`,
  unknown: (n) => `Unknown ${n}`,
  cluster: (cc, n) => `${cc} cluster ${n}`,
  country: (cc, n) => `${cc} ${n}`,
};

const ep = (ip: string, category: Endpoint['category'], names: string[] = [], country: string | null = null): Endpoint => ({
  ip,
  names,
  category,
  country,
});

function host(e: Endpoint, bytes: number): NetworkNode {
  return {
    id: `h:${e.ip}`,
    kind: 'host',
    endpoint: e,
    country: null,
    hosts: 1,
    bytes,
    bytes_sent: bytes / 2,
    bytes_received: bytes / 2,
    packets: 1,
    protocols: ['tcp'],
    role: null,
  };
}

function group(id: string, kind: NetworkNode['kind'], bytes: number, country: string | null = null, hosts = 5): NetworkNode {
  return { id, kind, endpoint: null, country, hosts, bytes, bytes_sent: 0, bytes_received: bytes, packets: 1, protocols: [], role: null };
}

function edge(source: string, target: string, bytes: number): NetworkEdge {
  return {
    source,
    target,
    bytes,
    bytes_fwd: bytes - 1,
    bytes_rev: 1,
    packets: 1,
    flows: 1,
    conversations: 1,
    protocols: ['tls'],
  };
}

function fixture(): NetworkGraph {
  const nodes = [
    host(ep('192.168.1.1', 'private', ['server.lan']), 10_000),
    host(ep('81.2.3.4', 'public', [], 'FR'), 5_000),
    group('k:US', 'cluster', 3_000, 'US', 12),
    host(ep('224.0.0.251', 'multicast'), 0),
    group('other', 'other', 100),
  ];
  return {
    mode: 'hosts',
    nodes,
    edges: [edge('h:192.168.1.1', 'h:81.2.3.4', 5_000), edge('h:192.168.1.1', 'k:US', 3_000), edge('h:192.168.1.1', 'other', 100)],
    hosts: 20,
    hosts_shown: 3,
    edges_total: 3,
    max_edges: 400,
    orphans: 1,
    total_bytes: 8_100,
    protocols: [],
  };
}

describe('graph model', () => {
  it('builds the graphology graph with bounded sizes and category colors', () => {
    const g = buildGraph(fixture(), { hideOrphans: false, resolveNames: true, labels });
    expect(g.order).toBe(5);
    expect(g.size).toBe(3);
    expect(g.getNodeAttribute('h:192.168.1.1', 'label')).toBe('server.lan');
    expect(g.getNodeAttribute('h:192.168.1.1', 'color')).toBe(ADDRESS_CATEGORIES.private.color);
    expect(g.getNodeAttribute('h:192.168.1.1', 'size')).toBe(NODE_SIZE.max);
    expect(g.getNodeAttribute('h:224.0.0.251', 'size')).toBe(NODE_SIZE.min);
    expect(g.getNodeAttribute('k:US', 'label')).toBe('US cluster 12');
    expect(g.getNodeAttribute('k:US', 'color')).toBe(ADDRESS_CATEGORIES.public.color);
    expect(g.getNodeAttribute('other', 'color')).toBe(OTHER_COLOR);
    g.forEachNode((_id, a) => {
      expect(a.size).toBeGreaterThanOrEqual(NODE_SIZE.min);
      expect(a.size).toBeLessThanOrEqual(NODE_SIZE.max);
    });
    g.forEachEdge((_e, a) => {
      expect(a.size).toBeGreaterThanOrEqual(EDGE_SIZE.min);
      expect(a.size).toBeLessThanOrEqual(EDGE_SIZE.max);
    });
    // Without name resolution, the address.
    const raw = buildGraph(fixture(), { hideOrphans: false, resolveNames: false, labels });
    expect(raw.getNodeAttribute('h:192.168.1.1', 'label')).toBe('192.168.1.1');
  });

  it('hides the orphans: nodes without any link', () => {
    expect(visibleNodes(fixture(), true).map((n) => n.id)).not.toContain('h:224.0.0.251');
    const g = buildGraph(fixture(), { hideOrphans: true, resolveNames: true, labels });
    expect(g.order).toBe(4);
    expect(g.hasNode('h:224.0.0.251')).toBe(false);
  });

  it('scales sizes on a log scale', () => {
    expect(nodeSize(0, 100)).toBe(NODE_SIZE.min);
    expect(nodeSize(100, 0)).toBe(NODE_SIZE.min);
    expect(nodeSize(1_000, 1_000_000)).toBeGreaterThan(NODE_SIZE.min);
    expect(nodeSize(1_000, 1_000_000)).toBeLessThan(NODE_SIZE.max);
    expect(edgeSize(5, 5)).toBe(EDGE_SIZE.max);
  });

  it('cleans hostile labels: no control or bidi characters, bounded length', () => {
    // A right-to-left override would visually reverse the rest of the name.
    expect(cleanLabel('evil\u202Egnp.exe')).toBe('evilgnp.exe');
    expect(cleanLabel('a\u0000b\u001bc\u200Bd')).toBe('abcd');
    const long = cleanLabel('x'.repeat(100));
    expect([...long]).toHaveLength(MAX_LABEL);
    expect(long.endsWith('\u2026')).toBe(true);
    // Markup is kept as plain text: labels are drawn on a canvas, never parsed.
    expect(cleanLabel('<img src=x onerror=alert(1)>')).toBe('<img src=x onerror=alert(1)>');
  });

  it('finds the largest node matching the search', () => {
    const g = buildGraph(fixture(), { hideOrphans: false, resolveNames: true, labels });
    expect(findNode(g, 'SERVER')).toBe('h:192.168.1.1');
    expect(findNode(g, '81.2')).toBe('h:81.2.3.4');
    expect(findNode(g, 'fr')).toBe('h:81.2.3.4');
    expect(findNode(g, '  ')).toBeNull();
    expect(findNode(g, 'nothing')).toBeNull();
  });

  it('ranks the pairs and the neighbors by bytes', () => {
    const pairs = rankedPairs(fixture(), true, 2);
    expect(pairs.map((p) => [p.source.id, p.target.id])).toEqual([
      ['h:192.168.1.1', 'h:81.2.3.4'],
      ['h:192.168.1.1', 'k:US'],
    ]);
    expect(neighborsOf(fixture(), 'h:192.168.1.1', 10).map((n) => n.node.id)).toEqual(['h:81.2.3.4', 'k:US', 'other']);
    expect(neighborsOf(fixture(), 'k:US', 10).map((n) => n.node.id)).toEqual(['h:192.168.1.1']);
  });
});

describe('force layout', () => {
  it('bounds the iterations and returns a finite position per node', () => {
    expect(iterationsFor(1)).toBe(0);
    expect(iterationsFor(2)).toBe(600);
    expect(iterationsFor(1_000)).toBe(150);
    const g = buildGraph(fixture(), { hideOrphans: false, resolveNames: true, labels });
    const positions = runLayout({
      nodes: g.mapNodes((id, a) => ({ id, x: a.x, y: a.y, size: a.size })),
      edges: g.mapEdges((_e, a, source, target) => ({ source, target, weight: a.bytes })),
    });
    expect(Object.keys(positions).sort()).toEqual(g.nodes().sort());
    for (const p of Object.values(positions)) {
      expect(Number.isFinite(p.x) && Number.isFinite(p.y)).toBe(true);
    }
    // Deterministic: same input, same layout.
    const again = runLayout({
      nodes: g.mapNodes((id, a) => ({ id, x: a.x, y: a.y, size: a.size })),
      edges: g.mapEdges((_e, a, source, target) => ({ source, target, weight: a.bytes })),
    });
    expect(again).toEqual(positions);
  });
});
