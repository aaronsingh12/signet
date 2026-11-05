import { Moon, Sun } from 'lucide-react';
import { useState } from 'react';

export function ThemeToggle() {
  const [dark, setDark] = useState(document.documentElement.dataset.theme === 'dark');
  const label = dark ? 'Switch to light mode' : 'Switch to dark mode';
  return (
    <button type="button" className="icon-button" data-testid="theme-toggle" aria-label={label} title={label} aria-pressed={dark} onClick={() => {
      const theme = dark ? 'light' : 'dark';
      localStorage.setItem('signet-theme', theme);
      document.documentElement.dataset.theme = theme;
      setDark(!dark);
    }}>
      {dark ? <Sun size={19} aria-hidden="true" /> : <Moon size={19} aria-hidden="true" />}
    </button>
  );
}
