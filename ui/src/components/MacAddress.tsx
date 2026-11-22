import { useTranslation } from 'react-i18next';
import type { MacAddress as MacAddressDto } from '../api/types/MacAddress';
import type { macAddressEn } from '../i18n/macAddress';
import { cn } from '../lib/cn';
import { Badge } from './Badge';
import { CopyButton } from './CopyButton';

type GroupKey = keyof (typeof macAddressEn)['group'];
type RegistryKey = keyof (typeof macAddressEn)['registry'];

const isGroup = (g: string): g is GroupKey => g === 'ipv4_multicast' || g === 'ipv6_multicast' || g === 'ieee8021_reserved';
const isRegistry = (r: string): r is RegistryKey => r === 'ma-l' || r === 'ma-m' || r === 'ma-s';

/** Class badge of an address: broadcast, well-known group, multicast or locally administered. */
export function MacClassBadge({ address }: { address: MacAddressDto }) {
  const { t } = useTranslation();
  if (address.kind === 'broadcast') return <Badge>{t('macAddress.broadcast')}</Badge>;
  if (address.kind === 'multicast') {
    const label =
      address.group !== null && isGroup(address.group)
        ? t(`macAddress.group.${address.group}`)
        : t('macAddress.multicast');
    return (
      <Badge title={label} className="max-w-full min-w-0 overflow-hidden">
        <span className="truncate">{label}</span>
      </Badge>
    );
  }
  if (address.local)
    return (
      <Badge tone="warning" title={t('macAddress.localTitle')}>
        {t('macAddress.local')}
      </Badge>
    );
  return null;
}

/** Vendor of an address, or why it has none; the IEEE registry in the tooltip. */
export function VendorName({ address, registry = null, small = false }: { address: MacAddressDto; registry?: string | null; small?: boolean }) {
  const { t } = useTranslation();
  if (address.vendor === null) {
    const why = address.local && address.kind === 'unicast' ? t('macAddress.localVendor') : t('macAddress.noVendor');
    return (
      <span data-testid="truncatable" title={why} className={cn('block truncate text-faint', small && 'text-meta')}>
        {why}
      </span>
    );
  }
  const title =
    registry !== null && isRegistry(registry) ? `${address.vendor}\n${t(`macAddress.registry.${registry}`)}` : address.vendor;
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
    <span className={cn('flex min-w-0 flex-col', withVendor && 'py-1')}>
      <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5">
        <span className="shrink-0 font-mono text-meta">{address.mac}</span>
        <MacClassBadge address={address} />
        {copy && <CopyButton value={address.mac} name={t('macAddress.copy')} className="-my-1.5 ml-auto" />}
      </span>
      {withVendor && <VendorName address={address} small />}
    </span>
  );
}

interface MacTextProps {
  /** Address as text (`aa:bb:cc:dd:ee:ff`), when the view has no class nor vendor for it. */
  mac: string;
  /** Copy button after the address. */
  copy?: boolean;
  /** Faint text (placeholder address such as `00:00:00:00:00:00`). */
  muted?: boolean;
  className?: string;
}

/** A MAC address given as text: monospace, truncated with a tooltip, optionally copyable. */
export function MacText({ mac, copy = false, muted = false, className }: MacTextProps) {
  const { t } = useTranslation();
  const text = (
    <span data-testid="truncatable" title={mac} className={cn('truncate font-mono', !copy && 'block', muted && 'text-faint', !copy && className)}>
      {mac}
    </span>
  );
  if (!copy) return text;
  return (
    <span className={cn('inline-flex max-w-full min-w-0 items-center', className)}>
      {text}
      <CopyButton value={mac} name={t('macAddress.copy')} />
    </span>
  );
}
