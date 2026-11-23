import { useTranslation } from 'react-i18next';
import { FilterChip } from '../../components/FilterChip';
import { type ConnectionFilters, type MessageFilters, hostPort } from './filterState';

interface Chip {
  key: string;
  label: string;
  clear: () => void;
}

function Chips({ chips }: { chips: Chip[] }) {
  const { t } = useTranslation();
  if (chips.length === 0) return null;
  return (
    <div className="flex min-w-0 flex-wrap gap-2">
      {chips.map((c) => (
        <FilterChip key={c.key} label={c.label} removeLabel={t('views.mqtt.filter.remove', { label: c.label })} onRemove={c.clear} />
      ))}
    </div>
  );
}

/** Removable chips of the active filters of one list. */
export function FilterChips(
  props:
    | { connection: ConnectionFilters; onConnection: (f: ConnectionFilters) => void }
    | { message: MessageFilters; onMessage: (f: MessageFilters) => void },
) {
  const { t } = useTranslation();
  const chips: Chip[] = [];
  if ('connection' in props) {
    const f = props.connection;
    const set = (next: Partial<ConnectionFilters>) => {
      props.onConnection({ ...f, ...next });
    };
    if (f.client !== null)
      chips.push({ key: 'client', label: t('views.mqtt.filter.client', { client: f.client.label }), clear: () => set({ client: null }) });
    if (f.broker !== null)
      chips.push({
        key: 'broker',
        label: t('views.mqtt.filter.broker', { broker: hostPort(f.broker.ip, f.broker.port) }),
        clear: () => set({ broker: null }),
      });
    if (f.signal !== null)
      chips.push({
        key: 'signal',
        label: t('views.mqtt.filter.signal', { signal: t(`views.mqtt.signals.kind.${f.signal}`) }),
        clear: () => set({ signal: null }),
      });
    if (f.flow !== null)
      chips.push({ key: 'flow', label: t('views.mqtt.filter.connection', { client: f.flow.label }), clear: () => set({ flow: null }) });
  } else {
    const f = props.message;
    const set = (next: Partial<MessageFilters>) => {
      props.onMessage({ ...f, ...next });
    };
    if (f.topic !== null) chips.push({ key: 'topic', label: t('views.mqtt.filter.topic', { topic: f.topic }), clear: () => set({ topic: null }) });
    if (f.prefix !== null)
      chips.push({ key: 'prefix', label: t('views.mqtt.filter.prefix', { topic: f.prefix }), clear: () => set({ prefix: null }) });
    if (f.client !== null)
      chips.push({ key: 'client', label: t('views.mqtt.filter.client', { client: f.client.label }), clear: () => set({ client: null }) });
  }
  return <Chips chips={chips} />;
}
