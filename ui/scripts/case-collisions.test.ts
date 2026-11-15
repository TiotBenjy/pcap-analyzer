import { readdirSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

// Windows and macOS file systems ignore case: two paths that differ only by case are one file
// there, and TypeScript resolves `./ServerMap` to `serverMap.ts` as well as `ServerMap.tsx`.
// Linux, where the gate runs, accepts both, so the release build was the first to fail.

const ROOT = resolve(__dirname, '../..');
const SKIP = new Set([
  '.git',
  '.worktrees',
  '.artifacts',
  '.data',
  'captures',
  'dist',
  'node_modules',
  'target',
]);
const MODULE = /\.(tsx?|jsx?|mjs|cjs)$/;

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path, out);
    else out.push(relative(ROOT, path));
  }
}

function collisions(keys: readonly [string, string][]): string[][] {
  const groups = new Map<string, Set<string>>();
  for (const [key, path] of keys) {
    const group = groups.get(key) ?? new Set<string>();
    group.add(path);
    groups.set(key, group);
  }
  return [...groups.values()].filter((g) => g.size > 1).map((g) => [...g].sort());
}

describe('file names', () => {
  const files: string[] = [];
  walk(ROOT, files);

  it('never differ only by case', () => {
    expect(collisions(files.map((f) => [f.toLowerCase(), f]))).toEqual([]);
  });

  it('give each UI module a name unique ignoring case and extension', () => {
    const modules = files.filter((f) => f.startsWith(`ui${'/'}`) && MODULE.test(f));
    expect(collisions(modules.map((f) => [f.replace(MODULE, '').toLowerCase(), f]))).toEqual([]);
  });
});
