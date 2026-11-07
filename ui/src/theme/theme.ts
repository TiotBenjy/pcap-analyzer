import { useCallback, useSyncExternalStore } from 'react';
import { readPref, writePref } from '../lib/storage';

// Theme preference. The initial class is applied before paint by public/theme-init.js
// (same storage key and rules); this module keeps it in sync afterwards.

export type ThemePref = 'system' | 'light' | 'dark';
export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'netsift.theme';
const QUERY = '(prefers-color-scheme: dark)';

export function resolveTheme(pref: ThemePref, systemDark: boolean): Theme {
  if (pref === 'system') return systemDark ? 'dark' : 'light';
  return pref;
}

function readThemePref(): ThemePref {
  const v = readPref(STORAGE_KEY);
  return v === 'light' || v === 'dark' ? v : 'system';
}

function systemDark(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia(QUERY).matches;
}

// --- tiny external store (shared by every component using the hook) ---
const listeners = new Set<() => void>();
let pref: ThemePref = readThemePref();

function apply(): void {
  document.documentElement.classList.toggle('dark', resolveTheme(pref, systemDark()) === 'dark');
  listeners.forEach((l) => {
    l();
  });
}

if (typeof window.matchMedia === 'function') {
  window.matchMedia(QUERY).addEventListener('change', apply);
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function snapshot(): string {
  return `${pref}:${resolveTheme(pref, systemDark())}`;
}

export function useTheme(): { pref: ThemePref; theme: Theme; setPref: (p: ThemePref) => void } {
  const snap = useSyncExternalStore(subscribe, snapshot, snapshot);
  const [p, t] = snap.split(':') as [ThemePref, Theme];
  const setPref = useCallback((next: ThemePref) => {
    pref = next;
    writePref(STORAGE_KEY, next === 'system' ? null : next);
    apply();
  }, []);
  return { pref: p, theme: t, setPref };
}
