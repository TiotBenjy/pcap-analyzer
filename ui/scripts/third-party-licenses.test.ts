import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import {
  acceptedFromAboutToml,
  alternatives,
  assemble,
  cargoPackages,
  chooseLicenses,
  noticesText,
  normalizeText,
  npmPackages,
  OUTPUT_JSON,
  referenceTexts,
  type ThirdPartyLicenses,
  tomlStringArray,
} from './third-party-licenses';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const ACCEPTED = ['MIT', 'Apache-2.0', 'Apache-2.0 WITH LLVM-exception', 'BSD-3-Clause', 'ISC', 'Unicode-3.0'];

describe('SPDX expressions', () => {
  it('expands OR, AND, WITH and parentheses', () => {
    expect(alternatives('MIT')).toEqual([['MIT']]);
    expect(alternatives('MIT OR Apache-2.0')).toEqual([['MIT'], ['Apache-2.0']]);
    expect(alternatives('(MIT OR Apache-2.0) AND Unicode-3.0')).toEqual([
      ['MIT', 'Unicode-3.0'],
      ['Apache-2.0', 'Unicode-3.0'],
    ]);
    expect(alternatives('Apache-2.0 WITH LLVM-exception OR MIT')).toEqual([['Apache-2.0 WITH LLVM-exception'], ['MIT']]);
    expect(alternatives('Apache-2.0  or  MIT')).toEqual([['Apache-2.0'], ['MIT']]);
  });

  it('rejects malformed expressions', () => {
    for (const bad of ['', 'MIT OR', '(MIT', 'MIT)', 'AND MIT', 'MIT Apache-2.0']) {
      expect(() => alternatives(bad), bad).toThrow();
    }
  });

  it('chooses the preferred acceptable alternative', () => {
    expect(chooseLicenses('Apache-2.0 OR MIT', ACCEPTED)).toEqual(['MIT']);
    expect(chooseLicenses('BSD-3-Clause AND MIT', ACCEPTED)).toEqual(['MIT', 'BSD-3-Clause']);
    expect(chooseLicenses('GPL-3.0-only OR ISC', ACCEPTED)).toEqual(['ISC']);
    expect(chooseLicenses('GPL-3.0-only', ACCEPTED)).toBeNull();
    expect(chooseLicenses('MIT AND GPL-3.0-only', ACCEPTED)).toBeNull();
  });

  it('accepts exactly the licenses allowed by deny.toml', () => {
    const accepted = acceptedFromAboutToml(readFileSync(join(ROOT, 'about.toml'), 'utf8'));
    const allowed = tomlStringArray(readFileSync(join(ROOT, 'deny.toml'), 'utf8'), 'allow', 'licenses');
    expect(allowed.length).toBeGreaterThan(5);
    expect([...accepted].sort()).toEqual([...allowed].sort());
  });

  it('reads string arrays of a TOML section only', () => {
    const toml = 'allow = ["top"]\n[a]\nallow = [\n  "x", # "comment"\n  "y WITH z",\n]\n[b]\nallow = ["other"]\n';
    expect(tomlStringArray(toml, 'allow')).toEqual(['top']);
    expect(tomlStringArray(toml, 'allow', 'a')).toEqual(['x', 'y WITH z']);
    expect(tomlStringArray(toml, 'allow', 'b')).toEqual(['other']);
    expect(() => tomlStringArray(toml, 'allow', 'c')).toThrow(/no \[c\]/);
    expect(() => tomlStringArray(toml, 'deny', 'a')).toThrow(/no deny/);
  });

  it('reads the accepted licenses of about.toml in order', () => {
    const accepted = acceptedFromAboutToml(readFileSync(join(ROOT, 'about.toml'), 'utf8'));
    expect(accepted[0]).toBe('MIT');
    expect(accepted).toContain('Apache-2.0');
    expect(accepted).not.toContain('GPL-3.0-only');
  });
});

describe('texts', () => {
  it('normalizes line endings and surrounding blank lines only', () => {
    expect(normalizeText('\r\n\nMIT License  \r\n\r\n  Copyright (c) A\n\n')).toBe('MIT License\n\n  Copyright (c) A');
  });
});

describe('npm packages', () => {
  let dir: string;
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const write = (path: string, content: string) => {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  };
  const lock = (packages: Record<string, object>) => {
    write('package-lock.json', JSON.stringify({ packages: { '': { name: 'ui' }, ...packages } }));
  };
  const reference = new Map([['MIT', { title: 'MIT License', text: 'MIT reference text' }]]);

  it('keeps production packages and their license files, NOTICE and licenses/ included', () => {
    dir = mkdtempSync(join(tmpdir(), 'licenses-'));
    lock({
      'node_modules/a': { version: '1.0.0', license: 'MIT' },
      'node_modules/@s/b': { version: '2.0.0', license: 'Apache-2.0 OR MIT' },
      'node_modules/a/node_modules/c': { version: '0.1.0', license: 'ISC' },
      'node_modules/dev-only': { version: '1.0.0', license: 'GPL-3.0-only', dev: true },
      'node_modules/other-os': { version: '1.0.0', license: 'MIT', optional: true },
    });
    write('node_modules/a/LICENSE', 'MIT License\r\nCopyright A\r\n');
    write('node_modules/a/NOTICE', 'Notice of A');
    write('node_modules/a/licenses/LICENSE-d3', 'ISC License d3');
    write('node_modules/@s/b/LICENSE-MIT', 'MIT B');
    write('node_modules/@s/b/LICENSE.spdx', 'SPDXVersion: SPDX-2.1');
    write('node_modules/a/node_modules/c/license.md', 'ISC C');
    const pkgs = npmPackages(dir, ACCEPTED, reference);
    expect(pkgs.map((p) => [p.name, p.version, p.license, p.texts.map((t) => t.title)])).toEqual([
      ['a', '1.0.0', 'MIT', ['LICENSE', 'licenses/LICENSE-d3', 'NOTICE']],
      ['@s/b', '2.0.0', 'MIT', ['LICENSE-MIT']],
      ['c', '0.1.0', 'ISC', ['license.md']],
    ]);
    expect(pkgs[0]?.texts[0]?.text).toBe('MIT License\nCopyright A');
  });

  it('reproduces the reference text when a package has no license file', () => {
    dir = mkdtempSync(join(tmpdir(), 'licenses-'));
    lock({ 'node_modules/bare': { version: '1.0.0', license: 'MIT OR Apache-2.0' } });
    write('node_modules/bare/LICENSE.spdx', 'SPDXVersion: SPDX-2.1');
    const [pkg] = npmPackages(dir, ACCEPTED, reference);
    expect(pkg?.reference).toBe(true);
    expect(pkg?.texts).toEqual([{ title: 'MIT License', text: 'MIT reference text' }]);
  });

  it('fails on a license outside the allow-list, a missing license or a missing package', () => {
    dir = mkdtempSync(join(tmpdir(), 'licenses-'));
    write('node_modules/x/LICENSE', 'text');
    lock({ 'node_modules/x': { version: '1.0.0', license: 'GPL-3.0-only' } });
    expect(() => npmPackages(dir, ACCEPTED, reference)).toThrow(/not accepted/);
    lock({ 'node_modules/x': { version: '1.0.0' } });
    expect(() => npmPackages(dir, ACCEPTED, reference)).toThrow(/no license/);
    lock({ 'node_modules/y': { version: '1.0.0', license: 'MIT' } });
    expect(() => npmPackages(dir, ACCEPTED, reference)).toThrow(/not installed/);
    lock({ 'node_modules/x': { version: '1.0.0', license: 'BSD-3-Clause' } });
    rmSync(join(dir, 'node_modules/x/LICENSE'));
    expect(() => npmPackages(dir, ACCEPTED, reference)).toThrow(/no reference text for BSD-3-Clause/);
  });
});

describe('crates', () => {
  const about = {
    licenses: [
      { id: 'MIT', name: 'MIT License', text: 'MIT X\n', source_path: '/r/x/LICENSE-MIT', used_by: [{ crate: { name: 'x', version: '1.0.0' } }] },
      {
        id: 'Unicode-3.0',
        name: 'Unicode License v3',
        text: 'Unicode',
        source_path: '/r/x/LICENSE-UNICODE',
        used_by: [{ crate: { name: 'x', version: '1.0.0' } }],
      },
      { id: 'MIT', name: 'MIT License', text: 'MIT template', source_path: '', used_by: [{ crate: { name: 'y', version: '0.2.0' } }] },
    ],
    crates: [
      { license: '(MIT OR Apache-2.0) AND Unicode-3.0', package: { name: 'x', version: '1.0.0', manifest_path: '/nonexistent/x/Cargo.toml' } },
      { license: 'MIT', package: { name: 'y', version: '0.2.0', manifest_path: '/nonexistent/y/Cargo.toml' } },
    ],
  };

  it('takes the texts chosen by cargo-about', () => {
    const pkgs = cargoPackages(about, ACCEPTED);
    expect(pkgs.map((p) => [p.name, p.declared, p.license, p.texts.length])).toEqual([
      ['x', '(MIT OR Apache-2.0) AND Unicode-3.0', 'MIT AND Unicode-3.0', 2],
      ['y', 'MIT', 'MIT', 1],
    ]);
    expect(referenceTexts(about).get('MIT')).toEqual({ title: 'MIT License', text: 'MIT template' });
  });

  it('fails on a crate without license text', () => {
    expect(() =>
      cargoPackages({ ...about, crates: [{ license: 'MIT', package: { name: 'z', version: '1.0.0', manifest_path: '/z' } }] }, ACCEPTED),
    ).toThrow(/z 1.0.0: no license text/);
  });
});

describe('outputs', () => {
  const shared = { title: 'MIT License', text: 'MIT shared' };
  const data = assemble([
    { name: 'zeta', version: '1.0.0', source: 'cargo', declared: 'MIT', license: 'MIT', texts: [shared] },
    { name: 'Alpha', version: '10.0.0', source: 'npm', declared: 'MIT', license: 'MIT', texts: [shared] },
    { name: 'alpha', version: '9.1.0', source: 'cargo', declared: 'ISC', license: 'ISC', texts: [{ title: 'ISC', text: 'ISC A' }] },
  ]);

  it('sorts packages and deduplicates texts', () => {
    expect(data.packages.map((p) => `${p.name} ${p.version} ${p.texts.join(',')}`)).toEqual([
      'alpha 9.1.0 0',
      'Alpha 10.0.0 1',
      'zeta 1.0.0 1',
    ]);
    expect(data.texts).toEqual([{ title: 'ISC', text: 'ISC A' }, shared]);
  });

  it('writes plain-text notices with the users of each text', () => {
    const txt = noticesText(data);
    expect(txt).toContain('Packages (3)');
    expect(txt).toContain('Alpha 10.0.0 (npm package) - MIT - [2]');
    expect(txt).toContain('[2] MIT License\nUsed by: Alpha 10.0.0, zeta 1.0.0');
    expect(txt).toContain('DB-IP');
    expect(txt.endsWith('MIT shared\n')).toBe(true);
  });

  it('the committed list has well-formed references', () => {
    const committed = JSON.parse(readFileSync(join(ROOT, OUTPUT_JSON), 'utf8')) as ThirdPartyLicenses;
    expect(committed.packages.length).toBeGreaterThan(100);
    for (const p of committed.packages) {
      expect(p.texts.length, p.name).toBeGreaterThan(0);
      for (const i of p.texts) expect(committed.texts[i], `${p.name} text ${String(i)}`).toBeDefined();
    }
    expect(committed.packages.some((p) => p.source === 'npm' && p.name === 'react')).toBe(true);
    expect(committed.packages.some((p) => p.source === 'cargo' && p.name === 'tauri')).toBe(true);
  });
});
