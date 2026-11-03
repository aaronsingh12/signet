import { useState } from 'react';

export function CopyCode({ text, testId }: { text: string; testId: string }) {
  const [copied, setCopied] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const copy = async (): Promise<void> => {
    try { await navigator.clipboard.writeText(text); setCopied(text); setError(null); }
    catch (error) { setError(error instanceof Error ? error.message : String(error)); }
  };
  return <div className="relative"><pre data-testid={testId} className="mono overflow-x-auto whitespace-pre rounded-md bg-canvas p-4 pr-20 text-xs">{text}</pre><button data-testid={`${testId}-copy`} className="absolute right-2 top-2 rounded border border-line bg-white px-2 py-1 text-xs" onClick={() => void copy()}>{copied === text ? 'Copied' : 'Copy'}</button>{error && <p role="alert" className="text-xs text-bad">Copy failed: {error}. Select and copy the settings manually.</p>}</div>;
}

