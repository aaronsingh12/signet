import { ArrowLeft, CircleHelp, Search, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { GUIDE_TOPICS, guideTopicFor, searchGuide, type GuideBlock } from '../lib/guide';

function Block({ b }: { b: GuideBlock }) {
  return (
    <div className="guide-block">
      {b.heading && <h3>{b.heading}</h3>}
      {b.text && <p>{b.text}</p>}
      {b.steps && <ol>{b.steps.map((s) => <li key={s}>{s}</li>)}</ol>}
      {b.points && <ul>{b.points.map((s) => <li key={s}>{s}</li>)}</ul>}
      {b.code && <pre>{b.code}</pre>}
      {b.table && <dl>{b.table.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>}
    </div>
  );
}

// No scrim: the page stays usable, so people can read a step and fill in the form beside it.
export function OnboardingGuide() {
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const [topicId, setTopicId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  useEffect(() => { if (!open) return; const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); }; window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey); }, [open]);
  const show = () => { setTopicId(guideTopicFor(pathname)); setQuery(''); setOpen(true); };
  const topic = GUIDE_TOPICS.find((t) => t.id === topicId);
  const results = searchGuide(query);
  const groups = [...new Set(results.map((t) => t.group))];
  return (
    <>
      <button type="button" className="btn-ghost" data-testid="guide-open" aria-expanded={open} onClick={() => (open ? setOpen(false) : show())}><CircleHelp size={15} />Help</button>
      {open && (
        <aside className="guide-panel" role="complementary" aria-label="Onboarding guide" data-testid="guide-panel">
          <div className="flex items-center justify-between gap-3"><h2 className="text-lg font-semibold">Onboarding guide</h2><button aria-label="Close guide" className="icon-button" onClick={() => setOpen(false)}><X size={17} /></button></div>
          <div className="guide-search"><Search size={15} aria-hidden="true" /><input data-testid="guide-search" aria-label="Search the guide" value={query} placeholder="Search, or paste an error code" onChange={(e) => { setQuery(e.target.value); setTopicId(null); }} /></div>
          {topic ? <>
            <button type="button" className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-royal" data-testid="guide-all" onClick={() => setTopicId(null)}><ArrowLeft size={14} />All topics</button>
            <h2 className="mt-3 text-xl font-semibold" data-testid="guide-title">{topic.title}</h2>
            <p className="mt-1 text-sm text-ink-2">{topic.summary}</p>
            {topic.blocks.map((b, i) => <Block key={i} b={b} />)}
          </> : results.length ? groups.map((g) => (
            <section key={g} className="mt-5">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-3">{g}</h3>
              {results.filter((t) => t.group === g).map((t) => <button type="button" key={t.id} className="guide-topic" data-testid={`guide-topic-${t.id}`} onClick={() => setTopicId(t.id)}><b>{t.title}</b><small>{t.summary}</small></button>)}
            </section>
          )) : <p className="mt-6 text-sm text-ink-2" role="status">Nothing matches that. Try one word from the error, such as "mapped" or "404".</p>}
        </aside>
      )}
    </>
  );
}
