/** Clay surfaces use warm neutrals, a green seal and distinct safety colors. */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        shell: { DEFAULT: '#0B1220', 2: '#111A2E', line: '#1E293B', text: '#94A3B8' },
        canvas: '#F3F1EA',
        line: '#E3E0D6',
        ink: { DEFAULT: '#1C2826', 2: '#51605C', 3: '#6B7875' },
        royal: { DEFAULT: '#0F6B5C', 600: '#0A5044', 50: '#E4F2EE' },
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
