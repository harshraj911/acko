/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: 'var(--dw-bg)',
        night: 'var(--dw-secondary)',
        panel: 'var(--dw-panel)',
        elevated: 'var(--dw-elevated)',
        line: 'var(--dw-border)',
        signal: 'var(--dw-red)',
        crimson: 'var(--dw-crimson)',
        magenta: 'var(--dw-magenta)',
        paper: 'var(--dw-white)',
        muted: 'var(--dw-muted)',
        quiet: 'var(--dw-quiet)',
        critical: 'var(--dw-critical)',
        success: 'var(--dw-success)',
      },
      fontFamily: {
        display: ['Space Grotesk', 'sans-serif'],
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      boxShadow: { signal: '0 0 36px rgba(229, 9, 50, .18)' },
    },
  },
  plugins: [],
}
