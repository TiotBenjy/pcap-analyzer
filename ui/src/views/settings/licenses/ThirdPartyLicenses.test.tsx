import '../../../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import { setupUser } from '../../../test/user';
import { groupPackages } from './data';
import { ThirdPartyLicensesDialog } from './ThirdPartyLicenses';
import type { ThirdPartyLicenses } from './types';

const DATA = vi.hoisted(
  (): ThirdPartyLicenses => ({
  packages: [
    { name: 'react', version: '19.2.0', source: 'npm', declared: 'MIT', license: 'MIT', texts: [0] },
    { name: 'serde', version: '1.0.229', source: 'cargo', declared: 'MIT OR Apache-2.0', license: 'MIT', texts: [1] },
    { name: 'ring', version: '0.17.14', source: 'cargo', declared: 'Apache-2.0 AND ISC', license: 'Apache-2.0 AND ISC', texts: [2, 3] },
    { name: 'bare', version: '1.0.0', source: 'npm', declared: 'MIT', license: 'MIT', texts: [1], reference: true },
  ],
  texts: [
    { title: 'LICENSE', text: 'MIT License\n\nCopyright (c) Meta <b>bold</b><img src=x onerror=alert(1)>' },
    { title: 'MIT License', text: 'Permission is hereby granted' },
    { title: 'Apache License 2.0', text: 'Apache License' },
    { title: 'ISC License', text: 'ISC' },
  ],
  }),
);

vi.mock('./third-party-licenses.json', () => ({ default: DATA }));

function renderDialog() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ThirdPartyLicensesDialog onClose={() => undefined} />
    </QueryClientProvider>,
  );
}

describe('groupPackages', () => {
  it('groups by reproduced license, largest group first, and searches names and licenses', () => {
    expect(groupPackages(DATA, '').map((g) => [g.license, g.packages.length])).toEqual([
      ['MIT', 3],
      ['Apache-2.0 AND ISC', 1],
    ]);
    expect(groupPackages(DATA, 'SER').map((g) => g.packages.map((p) => p.name))).toEqual([['serde']]);
    expect(groupPackages(DATA, 'isc').map((g) => g.license)).toEqual(['Apache-2.0 AND ISC']);
    expect(groupPackages(DATA, 'apache').map((g) => g.license)).toEqual(['Apache-2.0 AND ISC', 'MIT']);
    expect(groupPackages(DATA, 'nothing')).toEqual([]);
  });
});

describe('ThirdPartyLicensesDialog', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('lists the groups closed, then opens a package text as plain text', async () => {
    await i18n.changeLanguage('en');
    const user = setupUser();
    renderDialog();
    expect(await screen.findByTestId('licenses-count')).toHaveTextContent('4 of 4 packages');
    const mit = screen.getByRole('button', { name: /^MIT\s*3 packages$/ });
    expect(mit).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('license-package')).toBeNull();

    await user.click(mit);
    const rows = within(screen.getByRole('list', { name: 'MIT' })).getAllByTestId('license-package');
    expect(rows.map((r) => r.textContent)).toEqual([
      expect.stringContaining('react19.2.0npm package'),
      expect.stringContaining('serde1.0.229Rust crate'),
      expect.stringContaining('bare1.0.0npm package'),
    ]);
    expect(rows[1]).toHaveTextContent('Declared license: MIT OR Apache-2.0');

    const react = rows[0];
    if (react === undefined) throw new Error('no react row');
    await user.click(within(react).getByRole('button', { name: 'Show license' }));
    const pre = react.querySelector('pre');
    expect(pre?.textContent).toBe(DATA.texts[0]?.text);
    // Rendered as text: no element is created from the markup in the license file.
    expect(pre?.querySelector('b, img')).toBeNull();
    expect(within(react).getByRole('button', { name: 'Hide license' })).toHaveAttribute('aria-expanded', 'true');

    const bare = rows[2];
    if (bare === undefined) throw new Error('no bare row');
    await user.click(within(bare).getByRole('button', { name: 'Show license' }));
    expect(bare).toHaveTextContent('No license file in the package');
  });

  it('opens the matching groups while searching, in French', async () => {
    await i18n.changeLanguage('fr');
    const user = setupUser();
    renderDialog();
    await user.type(await screen.findByRole('searchbox', { name: 'Rechercher un paquet ou une licence' }), 'ring');
    expect(screen.getByTestId('licenses-count')).toHaveTextContent('1 sur 4 paquets');
    const group = screen.getByRole('button', { name: /^Apache-2\.0 AND ISC\s*1 paquet$/ });
    expect(group).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('button', { name: 'Voir la licence' })).toBeInTheDocument();

    await user.clear(screen.getByRole('searchbox'));
    await user.type(screen.getByRole('searchbox'), 'zzz');
    expect(screen.getByText('Aucun paquet ne correspond à cette recherche.')).toBeInTheDocument();
  });
});
