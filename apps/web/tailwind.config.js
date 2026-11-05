/** Clay surfaces use cool neutrals, blue actions and distinct safety colors. */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        shell: { DEFAULT: '#0B1220', 2: '#111A2E', line: '#1E293B', text: '#94A3B8' },
        canvas: 'rgb(var(--color-canvas) / <alpha-value>)',
        line: 'rgb(var(--color-line) / <alpha-value>)',
        ink: { DEFAULT: 'rgb(var(--color-ink) / <alpha-value>)', 2: 'rgb(var(--color-ink-2) / <alpha-value>)', 3: 'rgb(var(--color-ink-3) / <alpha-value>)' },
        royal: { DEFAULT: 'rgb(var(--color-royal) / <alpha-value>)', 600: 'rgb(var(--color-royal-600) / <alpha-value>)', 50: 'rgb(var(--color-royal-50) / <alpha-value>)' },
        ok: { DEFAULT: 'rgb(var(--color-ok) / <alpha-value>)', 50: 'rgb(var(--color-ok-50) / <alpha-value>)' },
        warn: { DEFAULT: 'rgb(var(--color-warn) / <alpha-value>)', 50: 'rgb(var(--color-warn-50) / <alpha-value>)' },
        bad: { DEFAULT: 'rgb(var(--color-bad) / <alpha-value>)', 50: 'rgb(var(--color-bad-50) / <alpha-value>)' },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'Cascadia Code', 'Consolas', 'monospace'],
      },
      boxShadow: { card: '0 1px 2px rgba(15, 23, 42, 0.06)' },
    },
  },
  plugins: [],
};
