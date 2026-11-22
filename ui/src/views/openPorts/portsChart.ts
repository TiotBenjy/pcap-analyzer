import type { OpenPortStats } from '../../api/types/OpenPortStats';
import { CATEGORICAL } from '../../charts/palette';
import type { BarItem } from '../../components/BarList';
import { labelled } from '../../lib/format';
import { barLabel } from './services';

// Rows of the "Most exposed ports" bars (pure: unit-tested without the DOM).

export interface PortsFormat {
  /** Tooltip value: `3 hosts`. */
  hosts: (n: number) => string;
  /** Count at the end of a bar, grouped for the language. */
  count: (n: number) => string;
}

/** One bar per port, most exposed first (the API order), the port in mono. */
export function portBars(stats: OpenPortStats, format: PortsFormat): BarItem[] {
  return stats.top.map((p) => {
    const label = barLabel(p);
    return {
      key: `${p.port}/${p.transport}`,
      label,
      title: labelled(label, format.hosts(p.hosts)),
      mono: true,
      value: p.hosts,
      valueText: format.count(p.hosts),
      color: CATEGORICAL[0],
    };
  });
}
