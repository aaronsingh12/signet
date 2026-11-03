/** Clay surfaces use cool neutrals, blue actions and distinct safety colors. */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        shell: { DEFAULT: '#0B1220', 2: '#111A2E', line: '#1E293B', text: '#94A3B8' },
        canvas: '#EDF1F8',
        line: '#DCE3EF',
        ink: { DEFAULT: '#23334D', 2: '#50617C', 3: '#65758D' },
        royal: { DEFAULT: '#4F63BB', 600: '#3E509D', 50: '#E9EDFC' },
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
