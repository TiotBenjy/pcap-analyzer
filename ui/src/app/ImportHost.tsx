import { useQueryClient } from '@tanstack/react-query';
import { lazy, Suspense, useEffect } from 'react';
import { sessionKeys } from '../api/sessionQueries';
import { onImportSettled, useImportState } from './importTracker';

// The wizard is code-split: it loads the first time an import is started.
const ImportWizard = lazy(() => import('../views/sessions/import/ImportWizard'));

/**
 * Mounted once by the AppShell: renders the import wizard when it is open (from any view) and
 * refreshes the session queries when the tracked import ends.
 */
export function ImportHost() {
  const qc = useQueryClient();
  const { wizardOpen } = useImportState();

  useEffect(
    () =>
      onImportSettled(() => {
        void qc.invalidateQueries({ queryKey: sessionKeys.all });
      }),
    [qc],
  );

  if (!wizardOpen) return null;
  return (
    <Suspense fallback={null}>
      <ImportWizard />
    </Suspense>
  );
}
