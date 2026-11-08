/** pcap link-layer types (tcpdump.org/linktypes.html) shown by name. */
const LINKTYPE_NAMES: Readonly<Record<number, string>> = {
  0: 'Loopback',
  1: 'Ethernet',
  101: 'Raw IP',
  105: '802.11',
  113: 'Linux SLL',
  127: 'Radiotap',
  228: 'IPv4',
  229: 'IPv6',
  276: 'Linux SLL2',
};

export const linktypeName = (lt: number) => LINKTYPE_NAMES[lt] ?? `LINKTYPE ${lt}`;
