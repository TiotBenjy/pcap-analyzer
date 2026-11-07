import 'i18next';
import type { en } from './en';

// Typed translation keys: t('nav.items.dns') is checked at compile time.
declare module 'i18next' {
  interface CustomTypeOptions {
    defaultNS: 'translation';
    resources: { translation: typeof en };
    returnNull: false;
  }
}
