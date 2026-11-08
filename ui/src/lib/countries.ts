/** ISO 3166-1 alpha-2 country code. */
export const COUNTRY_CODE = /^[A-Za-z]{2}$/;

/** Localized name of an ISO 3166-1 alpha-2 country code (the code itself when unknown). */
export function countryName(code: string, lang: string): string {
  if (!COUNTRY_CODE.test(code)) return code;
  try {
    return new Intl.DisplayNames([lang], { type: 'region' }).of(code.toUpperCase()) ?? code.toUpperCase();
  } catch {
    return code.toUpperCase();
  }
}

