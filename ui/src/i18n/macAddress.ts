// Strings of the shared MAC address parts (`macAddress`: components/MacAddress.tsx), used by the
// Ethernet and ARP views. Same keys in both languages (i18n.test.ts).

export const macAddressEn = {
  copy: 'MAC address',
  broadcast: 'Broadcast',
  multicast: 'Multicast',
  local: 'Local',
  localTitle: 'Locally administered address: not registered with the IEEE, possibly random',
  noVendor: 'No vendor',
  localVendor: 'Locally administered',
  group: {
    ipv4_multicast: 'IPv4 multicast',
    ipv6_multicast: 'IPv6 multicast',
    ieee8021_reserved: 'IEEE 802.1 reserved',
  },
  registry: {
    'ma-l': 'IEEE MA-L assignment (24-bit prefix)',
    'ma-m': 'IEEE MA-M assignment (28-bit prefix)',
    'ma-s': 'IEEE MA-S assignment (36-bit prefix)',
  },
};

export const macAddressFr: typeof macAddressEn = {
  copy: 'adresse MAC',
  broadcast: 'Diffusion',
  multicast: 'Multicast',
  local: 'Locale',
  localTitle: "Adresse administrée localement\u00a0: non enregistrée auprès de l'IEEE, aléatoire possible",
  noVendor: 'Sans constructeur',
  localVendor: 'Administrées localement',
  group: {
    ipv4_multicast: 'Multicast IPv4',
    ipv6_multicast: 'Multicast IPv6',
    ieee8021_reserved: 'Réservée IEEE 802.1',
  },
  registry: {
    'ma-l': 'Attribution IEEE MA-L (préfixe de 24 bits)',
    'ma-m': 'Attribution IEEE MA-M (préfixe de 28 bits)',
    'ma-s': 'Attribution IEEE MA-S (préfixe de 36 bits)',
  },
};
