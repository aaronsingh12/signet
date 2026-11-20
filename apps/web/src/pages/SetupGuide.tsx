import { useState } from 'react';
import { Card, ErrorNote, PageHeader } from '../components/ui';
import { saveServiceNowGuideEnabled, useServiceNowGuideEnabled } from '../lib/setup-guide';

export function SetupGuide() {
  const enabled = useServiceNowGuideEnabled();
  const [error, setError] = useState<Error | null>(null);
  const toggle = (): void => {
    try {
      saveServiceNowGuideEnabled(!enabled);
      setError(null);
    } catch (failure) {
      if (!(failure instanceof DOMException)) throw failure;
      setError(new Error(`Could not save the ServiceNow Setup Guide preference in this browser: ${failure.message}. Allow browser storage and try again.`));
    }
  };
  return <>
    <PageHeader title="Setup Guide" subtitle="Choose which setup guides appear while you connect your systems." />
    <Card>
      <div className="flex items-center justify-between gap-4">
        <div><h2 id="servicenow-guide-setting-label" className="font-semibold">ServiceNow</h2>
          <p id="servicenow-guide-setting-help" className="mt-1 text-sm text-ink-2">Animated walkthrough and field explanations, from AI agent setup to Guardian.</p>
        </div>
        <button type="button" role="switch" aria-checked={enabled} aria-labelledby="servicenow-guide-setting-label" aria-describedby="servicenow-guide-setting-help"
          data-testid="servicenow-guide-toggle" className="inline-flex shrink-0 items-center gap-3 rounded-lg p-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-royal" onClick={toggle}>
          <span className="text-sm font-semibold">{enabled ? 'On' : 'Off'}</span>
          <span aria-hidden="true" className={`relative inline-block h-6 w-11 rounded-full transition-colors motion-reduce:transition-none ${enabled ? 'bg-royal' : 'bg-ink-3'}`}>
            <span className={`absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white shadow-sm transition-transform motion-reduce:transition-none ${enabled ? 'translate-x-5' : 'translate-x-0'}`} />
          </span>
        </button>
      </div>
      <p className="mt-4 text-xs text-ink-3">On by default. Changes are saved automatically for this browser.</p>
      <div className="mt-3"><ErrorNote error={error} /></div>
    </Card>
  </>;
}
