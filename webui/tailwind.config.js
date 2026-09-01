// Copyright (c) 2026 Timo Duttine
// SPDX-License-Identifier: BUSL-1.1

/** @type {import('tailwindcss').Config} */
// Reskin 2026-08-09: the gray/blue utility palettes are remapped onto the
// design-system tokens so pre-reskin utility classes (text-gray-500,
// border-gray-700, bg-gray-800, …) resolve into the blue system instead of
// Tailwind's neutral grays. Rough mapping: 200-400 → primary text tones,
// 500-600 → secondary, 700+ → lines/wells. app.css rebuilds at container
// start, so this takes effect on the next stack restart.
module.exports = {
  content: ['./templates/**/*.html'],
  theme: {
    extend: {
      colors: {
        gray: {
          50:  '#FFFFFF',
          100: '#F2F5F8',
          200: '#FFFFFF',   // bright text on dark
          300: '#E4EDF6',   // --tx
          400: '#E4EDF6',   // --tx
          500: '#BACCDE',   // --tx2
          600: '#BACCDE',   // --tx2
          700: '#375473',   // --line2 (borders read clearly)
          800: '#1A2A3C',   // --surface (menus, wells)
          900: '#132131',   // --bg
        },
        blue: {
          300: '#4FA3E3',   // --accent
          400: '#4FA3E3',
          500: '#4FA3E3',
          600: '#2E6FA8',
        },
        // Warn/error palettes → muted blue-gray (severity is carried by
        // wording, not hue - design decision), success palettes → data
        // tone, decorative palettes → secondary text. Borders → line2,
        // dark fills → surface.
        // red = the DANGER exception to the neutral system (user decision
        // 2026-08-25): destructive controls read red. amber/yellow/orange/
        // rose stay de-toned.
        red: {
          100: '#F2D8D8', 200: '#EBB6B6', 300: '#E06C6C', 400: '#E06C6C',
          500: '#E06C6C', 600: '#B25454', 700: '#B25454', 800: '#8A4242',
          900: '#3A2430', 950: '#2A1B22',
        },
        ...Object.fromEntries(['amber','yellow','orange','rose'].map(n => [n, {
          100: '#E4EDF6', 200: '#BACCDE', 300: '#8296AE', 400: '#8296AE',
          500: '#8296AE', 600: '#375473', 700: '#375473', 800: '#375473',
          900: '#1A2A3C', 950: '#1A2A3C',
        }])),
        ...Object.fromEntries(['green','emerald','teal','lime'].map(n => [n, {
          100: '#E4EDF6', 200: '#C8D8E8', 300: '#C8D8E8', 400: '#C8D8E8',
          500: '#C8D8E8', 600: '#375473', 700: '#375473', 800: '#375473',
          900: '#1A2A3C', 950: '#1A2A3C',
        }])),
        ...Object.fromEntries(['purple','violet','indigo','sky','cyan','pink'].map(n => [n, {
          100: '#E4EDF6', 200: '#BACCDE', 300: '#BACCDE', 400: '#BACCDE',
          500: '#BACCDE', 600: '#375473', 700: '#375473', 800: '#375473',
          900: '#1A2A3C', 950: '#1A2A3C',
        }])),
      },
    },
  },
  plugins: [],
};
