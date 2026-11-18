import { Moon, Sun } from 'lucide-react';
import { useState } from 'react';
import { createPortal } from 'react-dom';
import './ThemeToggle.css';

export function ThemeToggle() {
  const [dark, setDark] = useState(document.documentElement.dataset.theme === 'dark');
  const [flight, setFlight] = useState<'cover' | 'reveal' | null>(null);
  const [destination, setDestination] = useState<'light' | 'dark'>('light');
  const label = dark ? 'Switch to light mode' : 'Switch to dark mode';
  function applyTheme(theme: 'light' | 'dark'): void {
    localStorage.setItem('signet-theme', theme);
    document.documentElement.dataset.theme = theme;
    setDark(theme === 'dark');
  }

  function switchTheme(): void {
    const theme = dark ? 'light' : 'dark';
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      applyTheme(theme);
      return;
    }
    setDestination(theme);
    setFlight('cover');
  }

  return (
    <>
    <button type="button" className="icon-button" data-testid="theme-toggle" aria-label={label} title={label} aria-pressed={dark} disabled={flight !== null} onClick={switchTheme}>
      {dark ? <Sun size={19} aria-hidden="true" /> : <Moon size={19} aria-hidden="true" />}
    </button>
    {flight !== null && createPortal(
      <div className={`theme-flight theme-flight--${destination}`} data-testid="theme-flight" aria-hidden="true">
        <div key={flight} className={`theme-flight-sweep theme-flight-sweep--${flight}`} onAnimationEnd={(event) => {
          if (event.target !== event.currentTarget) return;
          if (flight === 'cover') {
            applyTheme(destination);
            setFlight('reveal');
          } else {
            setFlight(null);
          }
        }} />
        {[0, 1, 2, 3, 4].map((bird) => (
          <div key={bird} className={`theme-flight-bird theme-flight-bird--${bird}`}>
            <svg viewBox="0 0 80 60" fill="currentColor">
              <path className="theme-flight-wing" d="M40 31C31 9 13 4 2 7c12 5 19 16 30 29Z" />
              <path className="theme-flight-wing theme-flight-wing--right" d="M40 31C49 9 67 4 78 7c-12 5-19 16-30 29Z" />
              <path d="m33 31 7-10 7 10-3 12 7 13-11-5-11 5 7-13Z" />
            </svg>
          </div>
        ))}
      </div>, document.body,
    )}
    </>
  );
}
