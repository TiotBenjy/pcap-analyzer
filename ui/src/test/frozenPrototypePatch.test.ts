import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { patchFrozenPrototype } from '../../vite-plugins/frozenPrototype';

// Build-time fix of ECharts for the desktop webview, whose Object.prototype is frozen by Tauri
// (vite-plugins/frozenPrototype.ts). End to end, `./x.sh shots` runs the desktop smoke test
// (ui/tests/desktop) on the production build in WebKit and Chromium.

const SCHEDULER_ID = '/work/ui/node_modules/echarts/lib/core/Scheduler.js';
// Vitest runs from ui/ (jsdom: `import.meta.url` is not a file URL).
const schedulerSource = readFileSync(resolve(process.cwd(), 'node_modules/echarts/lib/core/Scheduler.js'), 'utf8');

/** `mockMethods` of the given Scheduler source, as a callable function. */
function mockMethodsOf(source: string): (target: object, Clz: { prototype: object }) => void {
  const start = source.indexOf('function mockMethods(');
  const end = source.indexOf('\n}', start);
  expect(start).toBeGreaterThanOrEqual(0);
  const body = source.slice(start, end + 2);
  return new Function('noop', `'use strict'; ${body}; return mockMethods;`)(() => undefined) as never;
}

/** Class whose prototype has an own enumerable `constructor`, as with the tslib `__extends`. */
function extendedClass(): { prototype: object } {
  function Base() {
    /* empty */
  }
  (Base.prototype as Record<string, unknown>).getOption = () => undefined;
  function Derived() {
    /* empty */
  }
  function Proto(this: Record<string, unknown>) {
    this.constructor = Derived;
  }
  Proto.prototype = Base.prototype;
  Derived.prototype = new (Proto as unknown as new () => object)();
  return Derived as unknown as { prototype: object };
}

describe('frozen-prototype patch of ECharts', () => {
  it('matches the installed ECharts and defines the mocked methods', () => {
    const patched = patchFrozenPrototype(schedulerSource, SCHEDULER_ID);
    expect(patched).not.toBeNull();
    expect(patched).not.toContain('target[name_1] = noop;');
    expect(patched).toContain('Object.defineProperty(target, name_1');
  });

  it('ignores other modules and query suffixes', () => {
    expect(patchFrozenPrototype('target[name_1] = noop;', '/work/ui/src/main.tsx')).toBeNull();
    expect(patchFrozenPrototype(schedulerSource, `${SCHEDULER_ID}?v=123`)).not.toBeNull();
    expect(patchFrozenPrototype(schedulerSource, 'C:\\ui\\node_modules\\echarts\\lib\\core\\Scheduler.js')).not.toBeNull();
  });

  it('fails the build when ECharts changed the patched code', () => {
    expect(() => patchFrozenPrototype('function mockMethods() {}', SCHEDULER_ID)).toThrow(/no longer matches/);
  });

  it('fixes the override mistake under a frozen Object.prototype', () => {
    const original = mockMethodsOf(schedulerSource);
    const patched = mockMethodsOf(patchFrozenPrototype(schedulerSource, SCHEDULER_ID) ?? '');
    const Clz = extendedClass();
    // Frozen only for this call (Vitest needs a writable prototype between tests).
    const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'constructor');
    Object.defineProperty(Object.prototype, 'constructor', { ...descriptor, writable: false });
    try {
      expect(() => {
        original({}, Clz);
      }).toThrow(TypeError);
      const target: Record<string, unknown> = {};
      patched(target, Clz);
      expect(Object.keys(target).sort()).toEqual(['constructor', 'getOption']);
      expect(target.getOption).toBeTypeOf('function');
    } finally {
      Object.defineProperty(Object.prototype, 'constructor', descriptor ?? {});
    }
  });
});
