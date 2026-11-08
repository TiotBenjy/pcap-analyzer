import type { Plugin } from 'vite';

// The desktop app sets `freezePrototype: true` (tauri.conf.json): Tauri runs
// `Object.freeze(Object.prototype)` before any page script. In strict code, assigning a property
// that an object inherits from the frozen prototype (`constructor`, `toString`...) then throws:
// the "override mistake" (WebKit: "Attempted to assign to readonly property.").
//
// ECharts 6.0.0 and 6.1.0 hit it while their module is evaluated, in lib/core/Scheduler.js:
//
//     function mockMethods(target, Clz) {
//       for (var name_1 in Clz.prototype) { target[name_1] = noop; }
//     }
//
// `target` is a plain `{}` and `GlobalModel.prototype` has an own enumerable `constructor` (set by
// the tslib `__extends` helper), so `target.constructor = noop` throws and the chart chunk never
// loads: every view with a chart showed the router error screen in the desktop app.
//
// This transform defines the property instead of assigning it (same result, no inherited setter
// or read-only check). It fails the build when the pattern is gone, so an ECharts upgrade forces a
// new check (desktop smoke test, ui/tests/desktop). Remove it once ECharts no longer assigns there.
// Applies to production builds (desktop, shots). `vite dev` pre-bundles dependencies without it,
// which is fine: the web page has no frozen prototype.

/** Patches applied to dependency modules: file suffix, exact source, replacement. */
const PATCHES: readonly { file: string; from: string; to: string }[] = [
  {
    file: '/node_modules/echarts/lib/core/Scheduler.js',
    from: 'target[name_1] = noop;',
    to: 'Object.defineProperty(target, name_1, { value: noop, writable: true, enumerable: true, configurable: true });',
  },
];

/** Applies the patch matching `id`; `null` when the module needs none. Throws on a stale patch. */
export function patchFrozenPrototype(code: string, id: string): string | null {
  const path = id.split('?')[0]?.replaceAll('\\', '/') ?? '';
  const patch = PATCHES.find((p) => path.endsWith(p.file));
  if (patch === undefined) return null;
  if (!code.includes(patch.from)) {
    throw new Error(
      `frozen-prototype patch for ${patch.file} no longer matches: check the module under a frozen ` +
        'Object.prototype (./x.sh shots desktop) and update or remove the patch in vite-plugins/frozenPrototype.ts',
    );
  }
  return code.replaceAll(patch.from, patch.to);
}

/** Vite plugin: dependency fixes for a frozen `Object.prototype` (Tauri `freezePrototype`). */
export function frozenPrototype(): Plugin {
  return {
    name: 'netsift:frozen-prototype',
    enforce: 'pre',
    transform(code, id) {
      const patched = patchFrozenPrototype(code, id);
      return patched === null ? null : { code: patched, map: null };
    },
  };
}
