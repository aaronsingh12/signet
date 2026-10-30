/** Design tokens from "Signet — Console UI & UX": navy shell, light canvas, royal-blue action. */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        shell: { DEFAULT: '#0B1220', 2: '#111A2E', line: '#1E293B', text: '#94A3B8' },
        canvas: '#F4F5F7',
        line: '#E3E6EB',
        ink: { DEFAULT: '#0F172A', 2: '#475569', 3: '#64748B' },
        royal: { DEFAULT: '#2F43C9', 600: '#2738AE', 50: '#EEF1FD' },
        ok: { DEFAULT: '#15803D', 50: '#ECFDF3' },
        warn: { DEFAULT: '#B45309', 50: '#FFF7E6' },
        bad: { DEFAULT: '#B42318', 50: '#FEF0EE' },
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
