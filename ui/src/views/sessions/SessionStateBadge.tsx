import { useTranslation } from 'react-i18next';
import type { SessionState } from '../../api/types/SessionState';
import { Badge, type BadgeTone } from '../../components/Badge';

const TONES: Record<SessionState, BadgeTone> = {
  importing: 'accent',
  ready: 'success',
  incomplete: 'warning',
  failed: 'danger',
};

/** Session state as a badge (text, not color alone); `detail` becomes the tooltip. */
export function SessionStateBadge({ state, detail }: { state: SessionState; detail?: string | null }) {
  const { t } = useTranslation();
  return (
    <Badge tone={TONES[state]} {...(detail === null || detail === undefined ? {} : { title: detail })}>
      {t(`views.captures.state.${state}`)}
    </Badge>
  );
}
