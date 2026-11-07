// English dictionary: the reference shape. Every key here must exist in fr.ts (checked by tests).
// Rules: short, factual labels; no emoji, no decorative characters, no exclamation marks.
export const en = {
  app: {
    name: 'NetSift',
    skipToContent: 'Skip to content',
  },
  nav: {
    groups: {
      session: 'Session',
      analysis: 'Analysis',
      more: 'More',
    },
    items: {
      captures: 'Captures',
      overview: 'Overview',
      dns: 'DNS',
      http: 'HTTP',
      httpHeaders: 'HTTP Headers',
      tls: 'SSL/TLS',
      connections: 'Connections',
      openPorts: 'Open Ports',
      smb: 'SMB',
      pictures: 'Pictures',
      credentials: 'Credentials',
      servers: 'Servers',
      network: 'Network',
      hosts: 'Hosts',
      documents: 'Documents',
      ftp: 'FTP',
      telnet: 'Telnet',
      ssdp: 'SSDP',
      sip: 'SIP',
      arp: 'ARP',
      ethernet: 'Ethernet',
      wifi: 'WiFi',
      settings: 'Settings',
    },
    openMenu: 'Open navigation',
    closeMenu: 'Close navigation',
    collapse: 'Collapse sidebar',
    expand: 'Expand sidebar',
    unavailable: 'Available in a later version',
    unavailableItem: '{{label}}: available in a later version',
    drawer: 'Navigation',
  },
  theme: {
    label: 'Theme',
    system: 'System',
    light: 'Light',
    dark: 'Dark',
    toggle: 'Switch theme',
  },
  language: {
    label: 'Language',
    system: 'System',
    en: 'English',
    fr: 'Français',
  },
  views: {
    captures: {
      subtitle: 'Imported capture sessions',
      emptyTitle: 'No capture imported',
      emptyText: 'Import a pcap or pcapng file, or a folder of chunks, to start an analysis.',
    },
    overview: {
      subtitle: 'Traffic summary of the current session',
      emptyTitle: 'No session open',
      emptyText: 'Open a session from Captures to see its overview.',
    },
    placeholder: {
      subtitle: 'Not implemented yet',
      emptyTitle: 'Not available yet',
      emptyText: 'This view will be added in a later version.',
    },
    settings: {
      subtitle: 'Display preferences, stored on this device',
      appearance: 'Appearance',
      about: 'About',
      backend: 'Backend',
      backendOk: 'Connected, version {{version}}',
      backendDown: 'Unavailable',
      checking: 'Checking',
      mode: 'Mode',
      readOnly: 'Read-only',
      readWrite: 'Read and write',
    },
    notFound: {
      title: 'Page not found',
      text: 'This address does not match any view.',
      back: 'Go to Captures',
    },
  },
  common: {
    loading: 'Loading',
    retry: 'Retry',
    error: 'Something went wrong',
    noData: 'No data',
    search: 'Search',
    filters: 'Filters',
    enableAll: 'Enable all',
    disableAll: 'Disable all',
    rows_one: '{{count}} row',
    rows_other: '{{count}} rows',
    other: 'Other',
  },
} as const;

type Widen<T> = { readonly [K in keyof T]: T[K] extends string ? string : Widen<T[K]> };

/** Shape every translation must implement (same keys, any string values). */
export type Dictionary = Widen<typeof en>;
