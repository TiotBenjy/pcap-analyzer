import { useTranslation } from 'react-i18next';
import type { MacAddress as MacAddressDto } from '../../api/types/MacAddress';
import { Badge } from '../../components/Badge';
import { CopyButton } from '../../components/CopyButton';
import { cn } from '../../lib/cn';
import type { ethernetEn } from '../../i18n/ethernet';

type GroupKey = keyof (typeof ethernetEn)['address']['group'];
type RegistryKey = keyof (typeof ethernetEn)['address']['registry'];

const isGroup = (g: string): g is GroupKey => g === 'ipv4_multicast' || g === 'ipv6_multicast' || g === 'ieee8021_reserved';
const isRegistry = (r: string): r is RegistryKey => r === 'ma-l' || r === 'ma-m' || r === 'ma-s';

/** Class badge of an address: broadcast, well-known group, multicast or locally administered. */
export function MacClassBadge({ address }: { address: MacAddressDto }) {
  const { t } = useTranslation();
  if (address.kind === 'broadcast') return <Badge>{t('views.ethernet.address.broadcast')}</Badge>;
  if (address.kind === 'multicast') {
    const label =
      address.group !== null && isGroup(address.group)
        ? t(`views.ethernet.address.group.${address.group}`)
        : t('views.ethernet.address.multicast');
    return (
      <Badge title={label} className="max-w-full min-w-0 overflow-hidden">
        <span className="truncate">{label}</span>
      </Badge>
    );
  }
  if (address.local)
    return (
      <Badge tone="warning" title={t('views.ethernet.address.localTitle')}>
        {t('views.ethernet.address.local')}
      </Badge>
    );
  return null;
}

/** Vendor of an address, or why it has none; the IEEE registry in the tooltip. */
export function VendorName({ address, registry = null, small = false }: { address: MacAddressDto; registry?: string | null; small?: boolean }) {
  const { t } = useTranslation();
  if (address.vendor === null) {
    const why = address.local && address.kind === 'unicast' ? t('views.ethernet.vendors.local') : t('views.ethernet.address.noVendor');
    return (
      <span data-testid="truncatable" title={why} className={cn('block truncate text-faint', small && 'text-meta')}>
        {why}
      </span>
    );
  }
  const title =
    registry !== null && isRegistry(registry) ? `${address.vendor}\n${t(`views.ethernet.address.registry.${registry}`)}` : address.vendor;
  return (
    <span data-testid="truncatable" title={title} className={cn('block truncate', small && 'text-meta text-muted')}>
      {address.vendor}
    </span>
  );
}

interface MacAddressProps {
  address: MacAddressDto;
  /** Vendor on a second line (pairs). */
  withVendor?: boolean;
  /** Copy button after the address (address list). */
  copy?: boolean;
}

/** A MAC address: monospace, its class badge, optionally its vendor and a copy button. */
export function MacAddress({ address, withVendor = false, copy = false }: MacAddressProps) {
  const { t } = useTranslation();
  return (
    <span className="flex min-w-0 flex-col">
      <span className="flex min-w-0 items-center gap-1.5">
        <span className="shrink-0 font-mono text-meta">{address.mac}</span>
        <MacClassBadge address={address} />
        {copy && <CopyButton value={address.mac} name={t('views.ethernet.address.copy')} className="-my-1.5" />}
      </span>
      {withVendor && <VendorName address={address} small />}
    </span>
  );
}
