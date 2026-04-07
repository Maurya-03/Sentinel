/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono:    ["var(--font-mono)", "JetBrains Mono", "Fira Code", "monospace"],
        display: ["var(--font-display)", "Syne", "sans-serif"],
        body:    ["var(--font-body)", "DM Sans", "sans-serif"],
      },
      colors: {
        void:    "#05070d",
        abyss:   "#080c14",
        surface: "#0d1220",
        overlay: "#111827",
        border:  "#1a2236",
        muted:   "#242f45",
        ghost:   "#334155",
        dim:     "#64748b",
        soft:    "#94a3b8",
        bright:  "#cbd5e1",
        white:   "#f1f5f9",
        // Accent palette
        volt:    "#a3e635",
        breach:  "#f59e0b",
        pulse:   "#22d3ee",
        flaw:    "#f43f5e",
        // Severity
        critical: "#ef4444",
        high:     "#f97316",
        medium:   "#f59e0b",
        low:      "#3b82f6",
        info:     "#6366f1",
      },
      backgroundImage: {
        "grid-faint": "linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)",
        "noise":      "url(\"data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E\")",
      },
      backgroundSize: {
        "grid": "32px 32px",
      },
      boxShadow: {
        "glow-volt":   "0 0 24px -4px rgba(163,230,53,0.3)",
        "glow-pulse":  "0 0 24px -4px rgba(34,211,238,0.3)",
        "glow-flaw":   "0 0 24px -4px rgba(244,63,94,0.3)",
        "glow-breach": "0 0 24px -4px rgba(245,158,11,0.3)",
        "glass":       "0 4px 24px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.05)",
      },
      animation: {
        "pulse-slow":   "pulse 3s ease-in-out infinite",
        "scan-line":    "scanLine 2s linear infinite",
        "fade-up":      "fadeUp 0.4s ease forwards",
        "fade-in":      "fadeIn 0.3s ease forwards",
      },
      keyframes: {
        scanLine: {
          "0%":   { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        fadeUp: {
          from: { opacity: "0", transform: "translateY(8px)" },
          to:   { opacity: "1", transform: "translateY(0)" },
        },
        fadeIn: {
          from: { opacity: "0" },
          to:   { opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};
