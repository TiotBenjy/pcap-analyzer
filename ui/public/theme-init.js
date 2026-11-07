// Applies the stored theme before first paint (no flash). Kept in sync with src/theme/theme.ts.
(function () {
  var pref = 'system';
  try {
    pref = localStorage.getItem('netsift.theme') || 'system';
  } catch (_e) {
    /* storage unavailable: follow the system */
  }
  var dark = pref === 'dark' || (pref !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.classList.toggle('dark', dark);
})();
