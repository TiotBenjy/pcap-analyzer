// Third-party licenses of the shipped application: the Rust crates of the desktop binary
// (cargo-about JSON, about.toml) and the npm packages of the UI bundle (production entries of
// ui/package-lock.json, texts read from ui/node_modules). Writes, or checks with `--check`:
//   - ui/src/views/settings/licenses/third-party-licenses.json  (Settings > About, lazy-loaded)
//   - THIRD_PARTY_LICENSES (repository root, cited by NOTICE, shipped in every bundle)
// Run by scripts/ct/licenses.sh (`./x.sh licenses [--check]`), never by the application: no
// network access, deterministic output (no date, no version, no absolute path).
//
//   node --experimental-strip-types ui/scripts/third-party-licenses.ts --cargo <about.json> [--check]
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export type Source = 'cargo' | 'npm';

export interface LicenseText {
  /** License name (crates) or file name inside the package (npm). */
  title: string;
  text: string;
}

export interface ThirdPartyPackage {
  name: string;
  version: string;
  source: Source;
  /** License expression declared by the package, whitespace normalized. */
  declared: string;
  /** License(s) whose terms are reproduced, joined with " AND ": the grouping key in the UI. */
  license: string;
  /** Indexes into `texts`: license texts first, then NOTICE files. */
  texts: number[];
  /** No license file in the package: the reference text of the license is reproduced. */
  reference?: true;
}

export interface ThirdPartyLicenses {
  packages: ThirdPartyPackage[];
  texts: LicenseText[];
}

/** Licenses accepted for npm packages on top of about.toml (fonts, public-domain dedications). */
export const NPM_EXTRA_LICENSES = ['0BSD', 'Unlicense', 'OFL-1.1'];

// --- SPDX expressions -------------------------------------------------------------------

/**
 * Alternatives of an SPDX expression in disjunctive normal form: each alternative is the list of
 * licenses that apply together. `WITH` exceptions stay attached to their license.
 */
export function alternatives(expression: string): string[][] {
  const tokens = expression
    .replace(/\(/g, ' ( ')
    .replace(/\)/g, ' ) ')
    .split(/\s+/)
    .filter((t) => t !== '');
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => {
    const t = tokens[pos];
    if (t === undefined) throw new Error(`unexpected end of license expression: ${expression}`);
    pos += 1;
    return t;
  };
  const parseOr = (): string[][] => {
    let result = parseAnd();
    while (peek()?.toUpperCase() === 'OR') {
      next();
      result = [...result, ...parseAnd()];
    }
    return result;
  };
  const parseAnd = (): string[][] => {
    let result = parseAtom();
    while (peek()?.toUpperCase() === 'AND') {
      next();
      const right = parseAtom();
      result = result.flatMap((l) => right.map((r) => [...l, ...r]));
    }
    return result;
  };
  const parseAtom = (): string[][] => {
    const t = next();
    if (t === '(') {
      const inner = parseOr();
      if (next() !== ')') throw new Error(`unbalanced parentheses in license expression: ${expression}`);
      return inner;
    }
    if (t === ')' || /^(AND|OR|WITH)$/i.test(t)) throw new Error(`invalid license expression: ${expression}`);
    if (peek()?.toUpperCase() === 'WITH') {
      next();
      return [[`${t} WITH ${next()}`]];
    }
    return [[t]];
  };
  const result = parseOr();
  if (pos !== tokens.length) throw new Error(`invalid license expression: ${expression}`);
  return result;
}

/**
 * Licenses to comply with for `expression`: the alternative made only of accepted licenses whose
 * least preferred license comes first in `accepted`, or `null` if none is acceptable.
 */
export function chooseLicenses(expression: string, accepted: readonly string[]): string[] | null {
  let best: { rank: number; licenses: string[] } | null = null;
  for (const alt of alternatives(expression)) {
    const ranks = alt.map((l) => accepted.indexOf(l));
    if (ranks.some((r) => r < 0)) continue;
    const rank = Math.max(...ranks);
    if (best === null || rank < best.rank) {
      best = { rank, licenses: [...new Set(alt)].sort((a, b) => accepted.indexOf(a) - accepted.indexOf(b)) };
    }
  }
  return best?.licenses ?? null;
}

/**
 * String array `key = [...]` of a TOML file, at the top level or in `[section]` (string literals
 * only, comments ignored): enough for the license lists of about.toml and deny.toml.
 */
export function tomlStringArray(toml: string, key: string, section?: string): string[] {
  let text = toml.replace(/#.*$/gm, '');
  if (section !== undefined) {
    const header = text.split('\n').findIndex((l) => l.trim() === `[${section}]`);
    if (header < 0) throw new Error(`no [${section}] section`);
    const lines = text.split('\n').slice(header + 1);
    const end = lines.findIndex((l) => l.startsWith('['));
    text = (end < 0 ? lines : lines.slice(0, end)).join('\n');
  } else {
    const firstSection = text.search(/^\[/m);
    if (firstSection >= 0) text = text.slice(0, firstSection);
  }
  const block = new RegExp(`^${key}\\s*=\\s*\\[([\\s\\S]*?)\\]`, 'm').exec(text)?.[1];
  if (block === undefined) throw new Error(`no ${key} = [...]${section === undefined ? '' : ` in [${section}]`}`);
  return [...block.matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? '');
}

/** `accepted = [...]` of about.toml, in order of preference. */
export const acceptedFromAboutToml = (toml: string): string[] => tomlStringArray(toml, 'accepted');

// --- Inputs -------------------------------------------------------------------------------

/** Line endings, trailing spaces and surrounding blank lines removed; nothing else changes. */
export function normalizeText(text: string): string {
  return text
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((l) => l.trimEnd())
    .join('\n')
    .replace(/^\n+/, '')
    .replace(/\n+$/, '');
}

const normalizeExpression = (e: string) => e.trim().replace(/\s+/g, ' ');

interface RawPackage {
  name: string;
  version: string;
  source: Source;
  declared: string;
  license: string;
  texts: LicenseText[];
  reference?: true;
}

/** NOTICE, NOTICES.md, THIRDPARTYNOTICES...: any file whose name says it holds notices. */
const NOTICE_RE = /notice/i;
const LICENSE_FILE_RE = /^(licen[cs]e|copying)([-._].*)?$/i;

/** Notice files at the root of a package directory (Apache-2.0 section 4 d, bundled code). */
function noticeFiles(dir: string): LicenseText[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => NOTICE_RE.test(f) && statSync(join(dir, f)).isFile())
    .sort()
    .map((f) => ({ title: f, text: normalizeText(readFileSync(join(dir, f), 'utf8')) }));
}

interface CargoAboutJson {
  licenses: {
    id: string;
    name: string;
    text: string;
    used_by: { crate: { name: string; version: string } }[];
  }[];
  crates: { license: string; package: { name: string; version: string; manifest_path: string } }[];
}

/** Rust crates from `cargo about generate --format json` (about.toml chose the texts). */
export function cargoPackages(about: CargoAboutJson, accepted: readonly string[]): RawPackage[] {
  const key = (name: string, version: string) => `${name}@${version}`;
  const texts = new Map<string, { id: string; text: LicenseText }[]>();
  for (const l of about.licenses) {
    for (const u of l.used_by) {
      const k = key(u.crate.name, u.crate.version);
      const list = texts.get(k) ?? [];
      list.push({ id: l.id, text: { title: l.name, text: normalizeText(l.text) } });
      texts.set(k, list);
    }
  }
  return about.crates.map((c) => {
    const found = texts.get(key(c.package.name, c.package.version));
    if (found === undefined || found.length === 0) {
      throw new Error(`crate ${c.package.name} ${c.package.version}: no license text`);
    }
    const ids = [...new Set(found.map((f) => f.id))].sort((a, b) => accepted.indexOf(a) - accepted.indexOf(b));
    return {
      name: c.package.name,
      version: c.package.version,
      source: 'cargo' as const,
      declared: normalizeExpression(c.license),
      license: ids.join(' AND '),
      texts: [...found.map((f) => f.text), ...noticeFiles(dirname(c.package.manifest_path))],
    };
  });
}

interface PackageLock {
  packages: Record<string, { version?: string; license?: string; dev?: boolean; devOptional?: boolean; optional?: boolean; link?: boolean }>;
}

/** Files of a package that hold license terms: LICENSE*, COPYING*, and `licenses/` (bundled code). */
function npmLicenseFiles(dir: string): LicenseText[] {
  const files: string[] = [];
  for (const f of readdirSync(dir).sort()) {
    const path = join(dir, f);
    const stat = statSync(path);
    // LICENSE.spdx is an SPDX document (metadata), not license terms.
    if (stat.isFile() && LICENSE_FILE_RE.test(f) && !/\.spdx$/i.test(f)) files.push(f);
    if (stat.isDirectory() && /^licen[cs]es$/i.test(f)) {
      for (const g of readdirSync(path).sort()) {
        if (statSync(join(path, g)).isFile()) files.push(`${f}/${g}`);
      }
    }
  }
  return files.map((f) => ({ title: f, text: normalizeText(readFileSync(join(dir, f), 'utf8')) }));
}

/**
 * npm packages of the UI bundle: every production entry of package-lock.json (not `dev`), read in
 * `uiDir/node_modules`. `reference` gives the text of a license for a package without license file.
 */
export function npmPackages(
  uiDir: string,
  accepted: readonly string[],
  reference: ReadonlyMap<string, LicenseText>,
): RawPackage[] {
  const lock = JSON.parse(readFileSync(join(uiDir, 'package-lock.json'), 'utf8')) as PackageLock;
  const out: RawPackage[] = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === '' || entry.dev === true || entry.devOptional === true || entry.link === true) continue;
    const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
    const dir = join(uiDir, path);
    if (!existsSync(dir)) {
      // Optional packages of other platforms are not installed, and not shipped from this one.
      if (entry.optional === true) continue;
      throw new Error(`${name}: not installed in ui/node_modules (run npm ci)`);
    }
    const declared = normalizeExpression(entry.license ?? '');
    if (declared === '') throw new Error(`${name} ${entry.version ?? ''}: no license in package-lock.json`);
    const chosen = chooseLicenses(declared, accepted);
    if (chosen === null) throw new Error(`${name} ${entry.version ?? ''}: license not accepted: ${declared}`);
    let texts = npmLicenseFiles(dir);
    let isReference = false;
    if (texts.length === 0) {
      texts = chosen.map((l) => {
        const ref = reference.get(l);
        if (ref === undefined) throw new Error(`${name}: no license file and no reference text for ${l}`);
        return ref;
      });
      isReference = true;
    }
    out.push({
      name,
      version: entry.version ?? '',
      source: 'npm',
      declared,
      license: chosen.join(' AND '),
      texts: [...texts, ...noticeFiles(dir)],
      ...(isReference ? { reference: true as const } : {}),
    });
  }
  return out;
}

/**
 * Reference texts by license id: the texts cargo-about synthesized from the SPDX list for crates
 * without a license file (no copyright line), used for npm packages in the same situation.
 */
export function referenceTexts(about: CargoAboutJson & { licenses: { source_path?: string }[] }): Map<string, LicenseText> {
  const refs = new Map<string, LicenseText>();
  for (const l of about.licenses) {
    if ((l.source_path ?? '') === '' && !refs.has(l.id)) refs.set(l.id, { title: l.name, text: normalizeText(l.text) });
  }
  return refs;
}

// --- Outputs ------------------------------------------------------------------------------

const collator = new Intl.Collator('en', { numeric: true, sensitivity: 'base' });

/** Sorted packages and deduplicated texts, in a stable order. */
export function assemble(raw: RawPackage[]): ThirdPartyLicenses {
  const sorted = [...raw].sort(
    (a, b) =>
      collator.compare(a.name, b.name) ||
      a.name.localeCompare(b.name, 'en') ||
      collator.compare(a.version, b.version) ||
      a.source.localeCompare(b.source),
  );
  const texts: LicenseText[] = [];
  const index = new Map<string, number>();
  const packages = sorted.map((p) => {
    const ids: number[] = [];
    for (const t of p.texts) {
      const k = `${t.title}\0${t.text}`;
      let i = index.get(k);
      if (i === undefined) {
        i = texts.length;
        texts.push(t);
        index.set(k, i);
      }
      if (!ids.includes(i)) ids.push(i);
    }
    return {
      name: p.name,
      version: p.version,
      source: p.source,
      declared: p.declared,
      license: p.license,
      texts: ids,
      ...(p.reference === true ? { reference: true as const } : {}),
    };
  });
  return { packages, texts };
}

const SOURCE_LABEL: Record<Source, string> = { cargo: 'Rust crate', npm: 'npm package' };

/** Where to get the source code of a package at this version (MPL-2.0 section 3.2). */
export function sourceUrl(p: Pick<ThirdPartyPackage, 'name' | 'version' | 'source'>): string {
  return p.source === 'cargo'
    ? `https://crates.io/crates/${p.name}/${p.version}`
    : `https://www.npmjs.com/package/${p.name}/v/${p.version}`;
}

/** Packages under a license that requires telling where their source code is (file-level copyleft). */
const SOURCE_REQUIRED = /\bMPL-2\.0\b/;

/** Plain-text licenses and notices shipped next to the binaries (THIRD_PARTY_LICENSES). */
export function noticesText(data: ThirdPartyLicenses): string {
  const out: string[] = [];
  const rule = '='.repeat(78);
  out.push(
    'NetSift - third-party software licenses and notices',
    '',
    'NetSift is licensed under the Apache License 2.0 (LICENSE, NOTICE).',
    'Source: https://github.com/TiotBenjy/pcap-analyzer',
    '',
    'NetSift includes the third-party software listed below; each package is followed by the',
    'number of the license texts and notices that apply to it, reproduced afterwards.',
    '',
    'IP geolocation by DB-IP (https://db-ip.com): the bundled country database',
    '(dbip-country-lite.mmdb) is licensed under the Creative Commons Attribution 4.0',
    'International license (https://creativecommons.org/licenses/by/4.0/).',
    '',
    rule,
    `Packages (${String(data.packages.length)})`,
    rule,
    '',
  );
  for (const p of data.packages) {
    const refs = p.texts.map((i) => `[${String(i + 1)}]`).join(' ');
    out.push(`${p.name} ${p.version} (${SOURCE_LABEL[p.source]}) - ${p.declared} - ${refs}`);
  }
  const mpl = data.packages.filter((p) => SOURCE_REQUIRED.test(p.license));
  if (mpl.length > 0) {
    out.push(
      '',
      rule,
      'Source code of the MPL-2.0 packages',
      rule,
      '',
      'These packages are distributed in executable form under the Mozilla Public License 2.0;',
      'their source code, unmodified, is available at:',
      '',
      ...mpl.map((p) => `${p.name} ${p.version}: ${sourceUrl(p)}`),
    );
  }
  data.texts.forEach((t, i) => {
    const users = data.packages.filter((p) => p.texts.includes(i)).map((p) => `${p.name} ${p.version}`);
    out.push('', rule, `[${String(i + 1)}] ${t.title}`, `Used by: ${users.join(', ')}`, rule, '', t.text);
  });
  return `${out.join('\n')}\n`;
}

// --- Command line -------------------------------------------------------------------------

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const OUTPUT_JSON = 'ui/src/views/settings/licenses/third-party-licenses.json';
export const OUTPUT_TXT = 'THIRD_PARTY_LICENSES';

function main(argv: string[]): number {
  const cargoIdx = argv.indexOf('--cargo');
  const cargoPath = cargoIdx >= 0 ? argv[cargoIdx + 1] : undefined;
  const check = argv.includes('--check');
  if (cargoPath === undefined) {
    console.error('usage: third-party-licenses.ts --cargo <cargo-about.json> [--check]');
    return 2;
  }
  const accepted = acceptedFromAboutToml(readFileSync(join(ROOT, 'about.toml'), 'utf8'));
  const about = JSON.parse(readFileSync(cargoPath, 'utf8')) as CargoAboutJson;
  const data = assemble([
    ...cargoPackages(about, accepted),
    ...npmPackages(join(ROOT, 'ui'), [...accepted, ...NPM_EXTRA_LICENSES], referenceTexts(about)),
  ]);
  const outputs: [string, string][] = [
    // Indented: a dependency change shows as a few changed lines, not one rewritten 400 KB line.
    [OUTPUT_JSON, `${JSON.stringify(data, null, 1)}\n`],
    [OUTPUT_TXT, noticesText(data)],
  ];
  let stale = 0;
  for (const [file, content] of outputs) {
    const path = join(ROOT, file);
    const current = existsSync(path) ? readFileSync(path, 'utf8') : null;
    if (current === content) continue;
    if (check) {
      console.error(`licenses: ${file} is out of date (./x.sh licenses, then commit it)`);
      stale += 1;
    } else {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content);
      console.warn(`licenses: ${file} written`);
    }
  }
  const counts = { cargo: 0, npm: 0 };
  for (const p of data.packages) counts[p.source] += 1;
  console.warn(
    `licenses: ${String(counts.cargo)} crates, ${String(counts.npm)} npm packages, ${String(data.texts.length)} texts${check && stale === 0 ? ', up to date' : ''}`,
  );
  return stale === 0 ? 0 : 1;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    console.error(`licenses: ${e instanceof Error ? e.message : String(e)}`);
    process.exitCode = 1;
  }
}
