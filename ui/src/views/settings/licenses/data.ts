import type { ThirdPartyLicenses, ThirdPartyPackage } from './types';

/** The generated list, a separate chunk loaded when the dialog opens. */
export const loadLicenses = async (): Promise<ThirdPartyLicenses> =>
  (await import('./third-party-licenses.json')).default as ThirdPartyLicenses;

export interface Group {
  license: string;
  packages: ThirdPartyPackage[];
}

/** Packages matching `query` (name, version or license), grouped by license, largest group first. */
export function groupPackages(data: ThirdPartyLicenses, query: string): Group[] {
  const q = query.trim().toLowerCase();
  const groups = new Map<string, ThirdPartyPackage[]>();
  for (const p of data.packages) {
    if (
      q !== '' &&
      !p.name.toLowerCase().includes(q) &&
      !p.version.toLowerCase().includes(q) &&
      !p.license.toLowerCase().includes(q) &&
      !p.declared.toLowerCase().includes(q)
    ) {
      continue;
    }
    const list = groups.get(p.license) ?? [];
    list.push(p);
    groups.set(p.license, list);
  }
  return [...groups]
    .map(([license, packages]) => ({ license, packages }))
    .sort((a, b) => b.packages.length - a.packages.length || a.license.localeCompare(b.license, 'en'));
}
