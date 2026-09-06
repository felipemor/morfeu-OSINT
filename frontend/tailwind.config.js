/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: '#080c18',
          secondary: '#0d1224',
          tertiary: '#141e35',
          card: '#111827',
          border: '#1e2d45',
        },
        accent: {
          cyan: '#00d4ff',
          red: '#ff4757',
          orange: '#ff6b35',
          green: '#00e676',
          purple: '#9c27b0',
          yellow: '#ffc107',
        },
        severity: {
          critical: '#dc3545',
          high: '#ff6b35',
          medium: '#ffc107',
          low: '#28a745',
          info: '#17a2b8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.3s ease-in-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: 0 }, '100%': { opacity: 1 } },
        slideIn: { '0%': { transform: 'translateY(-10px)', opacity: 0 }, '100%': { transform: 'translateY(0)', opacity: 1 } },
        glow: { '0%': { boxShadow: '0 0 5px #00d4ff33' }, '100%': { boxShadow: '0 0 20px #00d4ff66, 0 0 40px #00d4ff33' } },
      },
      backdropBlur: { xs: '2px' },
    },
  },
  plugins: [],
};
