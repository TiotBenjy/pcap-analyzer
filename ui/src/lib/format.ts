import i18n from '../i18n';

/** Locale-aware integer formatting (tabular in the UI via the `num` utility). */
export function formatCount(n: number): string {
  return new Intl.NumberFormat(i18n.language).format(n);
}

const UNITS = {
  en: ['B', 'KiB', 'MiB', 'GiB', 'TiB'],
  fr: ['o', 'Kio', 'Mio', 'Gio', 'Tio'],
} as const;

/** IEC byte sizes: KiB/MiB/GiB in English, Kio/Mio/Gio in French (docs/UI_GUIDELINES.md). */
export function formatBytes(bytes: number, lang: string = i18n.language): string {
  const units = lang.startsWith('fr') ? UNITS.fr : UNITS.en;
  let value = Math.max(0, bytes);
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  const digits = i === 0 || value >= 100 ? 0 : 1;
  const num = new Intl.NumberFormat(lang, { maximumFractionDigits: digits, minimumFractionDigits: digits }).format(
    value,
  );
  return `${num}\u00a0${units[i] ?? units[0]}`;
}
