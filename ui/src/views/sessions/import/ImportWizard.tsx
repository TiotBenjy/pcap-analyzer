import { useState } from 'react';
import { useImportState } from '../../../app/importTracker';
import { ProgressStep } from './ProgressStep';
import { ReviewStep } from './ReviewStep';
import { SelectStep } from './SelectStep';

/**
 * Import wizard (docs/specs/captures.md): 1. select a folder or file, 2. review the scan and
 * choose the groups, 3. follow the progress. Rendered by the AppShell, so it can be closed while
 * the import goes on and reopened from the header indicator.
 */
export default function ImportWizard() {
  const { current, wizardKind } = useImportState();
  const [path, setPath] = useState<string | null>(null);

  if (current !== null) return <ProgressStep imp={current} />;
  if (path === null) return <SelectStep kind={wizardKind} onPick={setPath} />;
  return (
    <ReviewStep
      kind={wizardKind}
      path={path}
      onBack={() => {
        setPath(null);
      }}
    />
  );
}
