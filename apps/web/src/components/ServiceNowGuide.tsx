import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, Hand, MapPin, Play, X } from 'lucide-react';
import { Modal } from './ui';
import { serviceNowGuide } from './servicenow-guide';
import { useServiceNowGuideEnabled } from '../lib/setup-guide';
import './ServiceNowGuide.css';

/** A navigable preview, never a claim that external configuration has been completed. */
export function ServiceNowGuide() {
  const enabled = useServiceNowGuideEnabled();
  return enabled ? <ServiceNowGuideContent /> : null;
}

function ServiceNowGuideContent() {
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(0);
  const [fieldIndex, setFieldIndex] = useState(0);
  const step = serviceNowGuide[index]!;
  const changeStep = (next: number): void => { setIndex(next); setFieldIndex(0); };
  return <>
    <button type="button" className="btn-ghost inline-flex items-center gap-2" data-testid="servicenow-start-guide" onClick={() => setOpen(true)}><Play size={15} />Animated setup guide</button>
    {open && <div onKeyDown={event => { if (event.key === 'Escape') event.stopPropagation(); }}><Modal title="ServiceNow AI agent → Signet → Guardian" width="max-w-4xl" onClose={() => setOpen(false)}>
      <div className="space-y-4" data-testid="servicenow-guide">
        <p className="text-sm text-ink-2">Follow the hand, one step at a time. All instructions stay here in Signet. ServiceNow screens below are guided previews; perform those actions in your ServiceNow tab. Labels may vary by release.</p>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <label className="label flex-1" htmlFor="servicenow-guide-step">Jump to a step
            <select id="servicenow-guide-step" data-testid="servicenow-guide-step" className="input mt-1" value={index} onChange={event => changeStep(Number(event.target.value))}>
              {serviceNowGuide.map((item, position) => <option key={item.title} value={position}>{position + 1}. {item.title}</option>)}
            </select>
          </label>
          <span className="text-sm text-ink-3" data-testid="servicenow-guide-progress">Step {index + 1} of {serviceNowGuide.length}</span>
        </div>
        <progress className="h-1.5 w-full accent-royal" max={serviceNowGuide.length} value={index + 1} aria-label="Guide position" />
        <div key={index} className="sn-guide-enter space-y-4" aria-live="polite" aria-atomic="true">
          <div>
            <span className="inline-flex items-center gap-1 rounded-full bg-royal-50 px-2.5 py-1 text-xs font-semibold text-royal"><MapPin size={12} />In {step.location}</span>
            <h3 className="mt-2 text-lg font-semibold">{step.title}</h3>
            <p className="mt-1 break-words text-xs text-ink-3">{step.path}</p>
            <p className="mt-3 text-sm text-ink-2">{step.instruction}</p>
          </div>
          <div className="rounded-xl border border-line bg-canvas p-3 sm:p-5">
            <div className="mb-4 flex items-center justify-between border-b border-line pb-2 text-xs text-ink-3"><span>{step.location} · Guided screen preview</span><span>Hover or select a field for details</span></div>
            <div className="space-y-3 pl-7">
              {step.fields.map((field, position) => <button key={field.label} type="button" data-testid={`servicenow-guide-field-${position}`} aria-pressed={fieldIndex === position}
                className={`sn-guide-preview-field relative block w-full rounded-lg border p-3 text-left ${fieldIndex === position ? 'border-royal bg-royal-50' : 'border-line bg-white'}`} onPointerEnter={() => setFieldIndex(position)} onFocus={() => setFieldIndex(position)} onClick={() => setFieldIndex(position)}>
                {fieldIndex === position && <span className="sn-guide-hand absolute -left-8 top-3 text-royal" aria-hidden="true"><Hand size={28} className="rotate-90" /></span>}
                <span className="block text-xs font-semibold text-ink-2">{field.label}</span>
                <span className="mt-1 block break-words text-sm [overflow-wrap:anywhere]">{field.value}</span>
                {fieldIndex === position && <span className="mt-2 block border-t border-royal/20 pt-2 text-xs leading-relaxed text-ink-2"><strong>Where to get it / what it means: </strong>{field.source}</span>}
              </button>)}
            </div>
            <div className="mt-4 flex items-start gap-2 rounded-lg bg-white p-3 text-sm"><ArrowRight className="mt-0.5 shrink-0 text-royal" size={17} /><p><strong>Then: </strong>{step.action}</p></div>
          </div>
          <p className="rounded-lg border border-ok/20 bg-ok-50 p-3 text-sm text-ink-2"><strong>What should happen next: </strong>{step.expected}</p>
        </div>
        <div className="flex flex-wrap justify-between gap-2 border-t border-line pt-3">
          <button type="button" className="btn-ghost inline-flex items-center gap-1" data-testid="servicenow-guide-back" disabled={index === 0} onClick={() => changeStep(index - 1)}><ArrowLeft size={15} />Back</button>
          {index < serviceNowGuide.length - 1
            ? <button type="button" className="btn-primary inline-flex items-center gap-1" data-testid="servicenow-guide-next" onClick={() => changeStep(index + 1)}>Next step<ArrowRight size={15} /></button>
            : <button type="button" className="btn-primary" data-testid="servicenow-guide-close" onClick={() => setOpen(false)}>Close guide</button>}
        </div>
        <p className="text-xs text-ink-3">Based on ServiceNow_AI_Agent_Onboarding_to_Guardian_Easy_Guide.docx. Moving through this guide does not save settings or verify your connection. You can reopen it and jump to any step.</p>
      </div>
    </Modal></div>}
  </>;
}

const connectionFields = [
  { id: 'servicenow-connection-name', title: 'Name this connection', help: 'Choose a recognizable name, such as Incident management. This identifies the upstream connection in Signet.' },
  { id: 'servicenow-gateway-url', title: 'Enter the public Signet address', help: 'Use the HTTPS origin supplied by your administrator, without a path. ServiceNow must be able to reach the console API and gateway here.' },
  { id: 'servicenow-redirect-url', title: 'Copy this callback to ServiceNow', help: 'This read-only URL is generated from the public Signet address. In ServiceNow, open the inbound OAuth integration and paste it into Redirect URLs exactly.' },
  { id: 'servicenow-instance-url', title: 'Enter your ServiceNow instance', help: 'Copy the origin from your ServiceNow browser address, for example https://your-instance.service-now.com. Leave out the page path.' },
  { id: 'servicenow-mcp-url', title: 'Paste the upstream MCP server URL', help: 'In ServiceNow: MCP Server Console > Servers > your active server > Server URL. Copy the full URL; do not use the Signet gateway route here.' },
  { id: 'servicenow-client-id', title: 'Paste the ServiceNow Client ID', help: 'Use the Client ID from the ServiceNow inbound Authorization Code OAuth integration you registered for Signet. This is issued by ServiceNow.' },
  { id: 'servicenow-client-secret', title: 'Paste the matching ServiceNow secret', help: 'Copy the secret from that same ServiceNow inbound OAuth integration. Keep it private. When editing an existing connection, a blank secret keeps the saved one.' },
  { id: 'servicenow-save-settings', title: 'Save, then authorize access', help: 'Check the callback matches ServiceNow, then click Save and connect yourself. Complete login and consent in ServiceNow. Back in Signet, open this connection and Discover tools. Use the full animated guide for linking, approval, monitoring and Guardian.' },
] as const;

interface FieldCalloutPosition {
  left: number; top: number; width: number; path: string;
  fieldLeft: number; fieldTop: number; fieldWidth: number; fieldHeight: number;
  visible: boolean;
}

/** Anchors an animated explanation to the selected control without moving keyboard focus. */
export function ServiceNowFieldGuide() {
  const enabled = useServiceNowGuideEnabled();
  return enabled ? <ServiceNowFieldExplanation /> : null;
}

function ServiceNowFieldExplanation() {
  const [index, setIndex] = useState<number | null>(null);
  const [position, setPosition] = useState<FieldCalloutPosition | null>(null);
  const guide = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLElement>(null);
  const titleId = useId();
  useEffect(() => {
    const form = guide.current?.closest('form');
    if (!form) throw new Error('ServiceNow field guide must be rendered inside its connection form');
    const followField = (event: FocusEvent | MouseEvent): void => {
      if (!(event.target instanceof HTMLElement)) return;
      const control = event.target.closest('input, button, label');
      const targetId = control instanceof HTMLLabelElement ? control.htmlFor : control?.id;
      const position = connectionFields.findIndex(field => field.id === targetId);
      if (position >= 0) setIndex(position);
    };
    form.addEventListener('focusin', followField);
    form.addEventListener('click', followField);
    return () => {
      form.removeEventListener('focusin', followField);
      form.removeEventListener('click', followField);
    };
  }, []);
  useLayoutEffect(() => {
    if (index === null) return;
    const target = document.getElementById(connectionFields[index]!.id);
    if (!target) throw new Error(`ServiceNow field guide cannot find control ${connectionFields[index]!.id}`);
    const form = target.closest('form');
    const dialog = target.closest('[role="dialog"]');
    const callout = panel.current;
    if (!form || !dialog || !callout) throw new Error('ServiceNow field guide requires its form, dialog and explanation panel');
    const updatePosition = (): void => {
      const rect = target.getBoundingClientRect();
      const dialogRect = dialog.getBoundingClientRect();
      const rightSpace = window.innerWidth - dialogRect.right - 40;
      const beside = rightSpace >= 240;
      const width = beside ? Math.min(320, rightSpace) : Math.min(320, window.innerWidth - 32);
      const height = callout.offsetHeight;
      const left = beside ? dialogRect.right + 24 : Math.max(16, Math.min(rect.left, window.innerWidth - width - 16));
      const top = Math.max(16, Math.min(
        beside ? rect.top + rect.height / 2 - height / 2
          : rect.bottom + height + 40 <= window.innerHeight ? rect.bottom + 24 : rect.top - height - 24,
        window.innerHeight - height - 16,
      ));
      const startX = beside ? rect.right + 6 : Math.min(rect.right - 20, left + width / 2);
      const startY = beside ? rect.top + rect.height / 2 : top > rect.bottom ? rect.bottom + 6 : rect.top - 6;
      const endX = beside ? left - 2 : startX;
      const endY = beside ? top + height / 2 : top > rect.bottom ? top - 2 : top + height + 2;
      const middleX = (startX + endX) / 2;
      const middleY = (startY + endY) / 2;
      const path = beside ? `M ${startX} ${startY} C ${middleX} ${startY}, ${middleX} ${endY}, ${endX} ${endY}`
        : `M ${startX} ${startY} C ${startX + 20} ${middleY}, ${endX + 20} ${middleY}, ${endX} ${endY}`;
      setPosition({ left, top, width, path, fieldLeft: rect.left - 3, fieldTop: rect.top - 3,
        fieldWidth: rect.width + 6, fieldHeight: rect.height + 6, visible: rect.bottom > 16 && rect.top < window.innerHeight - 16 });
    };
    updatePosition();
    const observer = new ResizeObserver(updatePosition);
    observer.observe(form);
    observer.observe(dialog);
    observer.observe(callout);
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      observer.disconnect();
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [index]);
  const field = index === null ? null : connectionFields[index]!;
  return <div ref={guide} className="sn-field-guide" data-testid="servicenow-field-guide">
    {field && <>
      {position && <svg key={`${field.id}-line`} className="sn-field-connector" aria-hidden="true" style={{ visibility: position.visible ? 'visible' : 'hidden' }}>
        <rect x={position.fieldLeft} y={position.fieldTop} width={position.fieldWidth} height={position.fieldHeight} rx="12" className="sn-field-outline" />
        <path d={position.path} pathLength="1" className="sn-field-line" />
      </svg>}
      <aside key={`${field.id}-note`} ref={panel} role="note" aria-labelledby={titleId} className="sn-field-callout" data-testid="servicenow-field-callout"
        style={{ left: position?.left ?? -9999, top: position?.top ?? 0, width: position?.width ?? Math.min(320, window.innerWidth - 32), visibility: position?.visible ? 'visible' : 'hidden' }}
        onKeyDown={event => { if (event.key === 'Escape') { event.stopPropagation(); setIndex(null); } }}>
        <div className="flex items-center justify-between gap-2"><span className="text-xs font-semibold uppercase tracking-wide text-royal">Field {index! + 1} of {connectionFields.length}</span><button type="button" className="text-ink-3 hover:text-ink" aria-label="Close field explanation" data-testid="servicenow-field-guide-stop" onClick={() => setIndex(null)}><X size={16} /></button></div>
        <h3 id={titleId} className="mt-2 text-sm font-semibold">{field.title}</h3>
        <p className="mt-2 text-sm leading-relaxed text-ink-2" aria-live="polite">{field.help}</p>
        <p className="mt-3 border-t border-royal/15 pt-2 text-xs text-ink-3">Select another field to see its details.</p>
      </aside>
    </>}
  </div>;
}
