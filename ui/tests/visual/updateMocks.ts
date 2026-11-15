import type { Page } from '@playwright/test';
import type { UpdateState } from '../../src/api/types/UpdateState';

// Update check of the `settings-update*` views: the screenshot server never contacts GitHub, so
// `GET /api/v1/updates` answers a newer release with long notes (banner and Settings > About).

const REPO = 'https://github.com/TiotBenjy/pcap-analyzer';
const commit = (id: string) => `([${id}](${REPO}/commit/${id}0000000000000000000000000000000))`;

/** Release notes as `release.yml` publishes them: git-cliff (`cliff.toml`, `--strip all`) and the footer. */
const NOTES = [
  `## [0.2.0](${REPO}/releases/tag/v0.2.0) - 2026-11-20`,
  '',
  '### Fonctionnalités',
  '',
  `- **update** : Check GitHub releases from Settings and at startup, download the installer on click ${commit('e1edaec')}`,
  `- **geoip** : Offer a newer country database at startup ${commit('a1b2c3d')}`,
  `- **dns** : Parse very long names such as a-very-long-label-that-goes-on-and-on-without-any-break.example.org ${commit('b2c3d4e')}`,
  '',
  '### Corrections',
  '',
  `- **api** : Skip temporary names left by a crashed run with the same PID ${commit('d679909')}`,
  '- <b>Markup stays text</b>',
  '',
  `**Comparaison** : [v0.1.0...v0.2.0](${REPO}/compare/v0.1.0...v0.2.0)`,
  '### Installation',
  '',
  '| Système | Fichier |',
  '|---|---|',
  '| Linux (Debian, Ubuntu) | `.deb` |',
  '',
  'Vérifier un téléchargement : `sha256sum -c SHA256SUMS.txt --ignore-missing`.',
].join('\n');

export const UPDATE_STATE: UpdateState = {
  current_version: '0.1.0',
  checking: false,
  can_download: false,
  check: {
    status: 'available',
    current_version: '0.1.0',
    latest_version: '0.2.0',
    checked_at_us: 1_794_139_200_000_000,
    release: {
      version: '0.2.0',
      notes: NOTES,
      notes_truncated: false,
      html_url: `${REPO}/releases/tag/v0.2.0`,
      installers: [
        { name: 'NetSift_0.2.0_amd64.AppImage', size: 130_000_000, format: 'appimage' },
        { name: 'NetSift_0.2.0_amd64.deb', size: 120_000_000, format: 'deb' },
      ],
      format_known: false,
    },
  },
};

export async function mockUpdate(page: Page): Promise<void> {
  await page.route('**/api/v1/updates', (route) => route.fulfill({ json: UPDATE_STATE }));
}
