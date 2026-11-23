import { Link, getRouteApi } from '@tanstack/react-router';
import { ArrowRight, MessageSquare, Monitor, RadioTower, Server, Waypoints } from 'lucide-react';
import { type ReactNode, useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMqttSignals, useMqttStats } from '../../api/mqttQueries';
import type { MqttPacketInfo } from '../../api/types/MqttPacketInfo';
import type { MqttSignal } from '../../api/types/MqttSignal';
import type { MqttSignalItem } from '../../api/types/MqttSignalItem';
import type { MqttSignalKind } from '../../api/types/MqttSignalKind';
import type { MqttStats } from '../../api/types/MqttStats';
import { useViewRange } from '../../app/timeRange';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import { formatBytes, formatCount } from '../../lib/format';
import { SessionGate } from '../connections/SessionGate';
import { useViewableSession } from '../http/state';
import { ConnectionsTab } from './ConnectionsTab';
import { type ConnectionFilters, type MessageFilters, NO_CONNECTION_FILTERS, NO_MESSAGE_FILTERS } from './filterState';
import { BrokersTab, ClientsTab } from './GroupTabs';
import { MessagesTab } from './MessagesTab';
import { Choice } from './parts';
import { TopicsTab } from './TopicsTab';

const route = getRouteApi('/sessions/$sessionId');

const TABS = ['connections', 'clients', 'brokers', 'topics', 'messages'] as const;
type Tab = (typeof TABS)[number];

/** Reads the `tab` query parameter from the hash location (`#/.../mqtt?tab=topics`). */
function initialTab(): Tab {
  const hash = window.location.hash;
  const query = hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '';
  const tab = new URLSearchParams(query).get('tab');
  return TABS.find((t) => t === tab) ?? 'connections';
}

/** Items of a signal shown in its row; the others are counted. */
const SIGNAL_ITEMS = 3;

/** MQTT view (docs/specs/mqtt.md): figures, signals, then connections, clients, brokers, topics and messages. */
export default function MqttView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const { session, viewable, oneDay } = useViewableSession(sessionId);
  const stats = useMqttStats(sessionId, viewable);
  const ranged = useViewRange() !== null;
  // The active tab is addressable (`?tab=topics`) so it can be linked to and captured.
  const [tab, setTab] = useState<Tab>(initialTab);
  const [connectionFilters, setConnectionFilters] = useState<ConnectionFilters>(NO_CONNECTION_FILTERS);
  const [messageFilters, setMessageFilters] = useState<MessageFilters>(NO_MESSAGE_FILTERS);
  const tabsRef = useRef<HTMLDivElement>(null);

  const show = useCallback((next: Tab) => {
    setTab(next);
    tabsRef.current?.scrollIntoView?.({ block: 'start' });
  }, []);
  const showConnections = useCallback(
    (f: Partial<ConnectionFilters>) => {
      setConnectionFilters({ ...NO_CONNECTION_FILTERS, ...f });
      show('connections');
    },
    [show],
  );
  const showMessages = useCallback(
    (f: Partial<MessageFilters>) => {
      setMessageFilters({ ...NO_MESSAGE_FILTERS, ...f });
      show('messages');
    },
    [show],
  );

  const s = stats.data;
  let content: ReactNode;
  if (stats.isError)
    content = (
      <Card>
        <ErrorState
          message={t('views.mqtt.loadError')}
          onRetry={() => {
            void stats.refetch();
          }}
        />
      </Card>
    );
  else if (s === undefined)
    content = (
      <div className="flex flex-col gap-4" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        <Skeleton height={88} />
        <Skeleton height={240} />
      </div>
    );
  else if (s.connections === 0)
    content = (
      <Card>
        <EmptyState icon={RadioTower} title={ranged ? t('timeRange.emptyTitle') : t('views.mqtt.empty')} />
      </Card>
    );
  else {
    const props = { sessionId, enabled: viewable, oneDay, ranged };
    let panel: ReactNode;
    switch (tab) {
      case 'connections':
        panel = <ConnectionsTab {...props} filters={connectionFilters} onFilters={setConnectionFilters} />;
        break;
      case 'clients':
        panel = (
          <ClientsTab
            {...props}
            onSelect={(c) => {
              showConnections({ client: { key: c.key, label: c.client_id ?? c.addresses[0]?.ip ?? c.key } });
            }}
          />
        );
        break;
      case 'brokers':
        panel = (
          <BrokersTab
            {...props}
            onSelect={(b) => {
              showConnections({ broker: { ip: b.broker.ip, port: b.port } });
            }}
          />
        );
        break;
      case 'topics':
        panel = (
          <TopicsTab
            {...props}
            onShowMessages={(path, exact) => {
              showMessages(exact ? { topic: path } : { prefix: path });
            }}
          />
        );
        break;
      case 'messages':
        panel = (
          <MessagesTab
            {...props}
            filters={messageFilters}
            onFilters={setMessageFilters}
            onShowConnection={(m: MqttPacketInfo) => {
              showConnections({ flow: { id: m.flow_id, label: m.client_id === null || m.client_id === '' ? (m.client?.ip ?? '') : m.client_id } });
            }}
          />
        );
        break;
    }
    content = (
      <>
        <StatBand stats={s} />
        <SignalsCard
          sessionId={sessionId}
          enabled={viewable}
          onShow={(signal) => {
            showConnections({ signal });
          }}
        />
        <div ref={tabsRef} className="flex min-w-0 scroll-mt-4 flex-col gap-4">
          <Choice
            label={t('views.mqtt.tabs.label')}
            value={tab}
            options={TABS.map((v) => ({ value: v, label: t(`views.mqtt.tabs.${v}`) }))}
            onChange={setTab}
          />
          {panel}
        </div>
      </>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.mqtt')}
        subtitle={session.data?.name ?? t('views.mqtt.subtitle')}
        {...(s === undefined ? {} : { count: <Badge>{formatCount(s.connections)}</Badge> })}
      />
      <SessionGate session={session}>{content}</SessionGate>
    </div>
  );
}

function StatBand({ stats: s }: { stats: MqttStats }) {
  const { t } = useTranslation();
  return (
    <section aria-label={t('views.mqtt.stat.label')} data-testid="mqtt-summary" className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
      <StatCard
        icon={Waypoints}
        label={t('views.mqtt.stat.connections')}
        value={formatCount(s.connections)}
        hint={t('views.mqtt.stat.connectionsHint', { accepted: formatCount(s.accepted), rejected: formatCount(s.rejected) })}
      />
      <StatCard icon={Monitor} label={t('views.mqtt.stat.clients')} value={formatCount(s.clients)} hint=" " />
      <StatCard
        icon={Server}
        label={t('views.mqtt.stat.brokers')}
        value={formatCount(s.brokers)}
        hint={s.public_brokers > 0 ? t('views.mqtt.stat.publicBrokers', { count: s.public_brokers }) : ' '}
        {...(s.public_brokers > 0 ? { tone: 'warning' as const } : {})}
      />
      <StatCard
        icon={MessageSquare}
        label={t('views.mqtt.stat.published')}
        value={formatCount(s.publish_c2s)}
        hint={t('views.mqtt.stat.publishedHint', { delivered: formatCount(s.publish_s2c) })}
      />
      <StatCard
        icon={RadioTower}
        label={t('views.mqtt.stat.topics')}
        value={formatCount(s.topics)}
        hint={t('views.mqtt.stat.topicsHint', { bytes: formatBytes(s.payload_bytes) })}
      />
    </section>
  );
}

function ItemText({ item }: { item: MqttSignalItem }) {
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 text-meta">
      {item.client !== null && (
        <>
          <span className="min-w-0 max-w-full">
            <Endpoint endpoint={item.client} show="address" className="text-meta" />
          </span>
          {item.broker !== null && <ArrowRight aria-hidden size={14} strokeWidth={1.75} className="shrink-0 text-faint" />}
        </>
      )}
      {item.broker !== null && (
        <span className="min-w-0 max-w-full">
          <Endpoint endpoint={item.broker} port={item.broker_port} show="address" className="text-meta" />
        </span>
      )}
      {item.filter !== null && <span className="min-w-0 font-mono break-all">{item.filter}</span>}
      <span className="num text-muted">{formatCount(item.connections)}</span>
    </span>
  );
}

function SignalRow({ sessionId, signal: g, onShow }: { sessionId: string; signal: MqttSignal; onShow: (k: MqttSignalKind) => void }) {
  const { t } = useTranslation();
  const label = t(`views.mqtt.signals.kind.${g.kind}`);
  const shown = g.items.slice(0, SIGNAL_ITEMS);
  const rest = g.items.length - shown.length;
  return (
    <li className="flex min-w-0 flex-col gap-1.5 border-b border-line py-3 last:border-b-0 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
      <div className="flex min-w-0 flex-col gap-1">
        <span className="flex min-w-0 flex-wrap items-baseline gap-x-2">
          <span className="font-medium text-warning">{label}</span>
          <span className="num text-meta text-muted">{t('views.mqtt.signals.connections', { count: g.connections })}</span>
        </span>
        <p className="max-w-[80ch] text-meta text-muted">{t(`views.mqtt.signals.why.${g.kind}`)}</p>
        <ul className="flex min-w-0 flex-col gap-0.5">
          {shown.map((item, i) => (
            <li key={i} className="min-w-0">
              <ItemText item={item} />
            </li>
          ))}
          {rest > 0 && <li className="text-meta text-muted">{t('views.mqtt.signals.more', { count: rest })}</li>}
        </ul>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2">
        <Button
          variant="secondary"
          aria-label={t('views.mqtt.signals.showLabel', { label })}
          onClick={() => {
            onShow(g.kind);
          }}
        >
          {t('views.mqtt.signals.show')}
        </Button>
        {g.kind === 'cleartext-credentials' && (
          <Link to="/sessions/$sessionId/credentials" params={{ sessionId }} className="text-meta text-accent hover:underline">
            {t('views.mqtt.signals.credentials')}
          </Link>
        )}
      </div>
    </li>
  );
}

/** Signals of the traffic, each explained, with a shortcut to its connections. Absent without any. */
function SignalsCard({ sessionId, enabled, onShow }: { sessionId: string; enabled: boolean; onShow: (k: MqttSignalKind) => void }) {
  const { t } = useTranslation();
  const signals = useMqttSignals(sessionId, enabled);
  if (signals.isError)
    return (
      <Card title={t('views.mqtt.signals.title')}>
        <ErrorState
          message={t('views.mqtt.loadError')}
          onRetry={() => {
            void signals.refetch();
          }}
        />
      </Card>
    );
  if (signals.data === undefined) return <Skeleton height={120} />;
  if (signals.data.length === 0) return null;
  return (
    <Card title={t('views.mqtt.signals.title')}>
      <ul aria-label={t('views.mqtt.signals.label')} data-testid="mqtt-signals" className="-my-3 flex min-w-0 flex-col">
        {signals.data.map((g) => (
          <SignalRow key={g.kind} sessionId={sessionId} signal={g} onShow={onShow} />
        ))}
      </ul>
    </Card>
  );
}
