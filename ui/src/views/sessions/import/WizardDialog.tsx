import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { closeImportWizard, type PickKind } from '../../../app/importTracker';
import { Dialog } from '../../../components/Dialog';

const STEP_LABELS = {
  1: 'views.import.stepSelect',
  2: 'views.import.stepReview',
  3: 'views.import.stepProgress',
} as const;

interface WizardDialogProps {
  step: 1 | 2 | 3;
  kind: PickKind;
  children: ReactNode;
  footer: ReactNode;
}

/** Frame shared by the wizard steps. Closing it never stops a running import. */
export function WizardDialog({ step, kind, children, footer }: WizardDialogProps) {
  const { t } = useTranslation();
  const title =
    step === 3
      ? t('views.import.titleProgress')
      : kind === 'folder'
        ? t('views.import.titleFolder')
        : t('views.import.titleFile');
  return (
    <Dialog
      open
      size="lg"
      onClose={closeImportWizard}
      title={title}
      description={t('views.import.step', { n: step, label: t(STEP_LABELS[step]) })}
      footer={footer}
    >
      {children}
    </Dialog>
  );
}
