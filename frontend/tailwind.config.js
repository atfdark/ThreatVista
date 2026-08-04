/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#080c14",
          card: "#0f1626",
          border: "#1e293b",
          primary: "#06b6d4", // Cyan glow
          secondary: "#3b82f6", // Blue electric
          accent: "#a855f7", // Purple pulse
          text: "#f8fafc",
          muted: "#64748b",
          success: "#10b981",
          warning: "#f59e0b",
          danger: "#ef4444",
        }
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      boxShadow: {
        cyber: "0 0 15px rgba(6, 182, 212, 0.15)",
        "cyber-glow": "0 0 25px rgba(6, 182, 212, 0.25)",
        "cyber-danger": "0 0 20px rgba(239, 68, 68, 0.2)",
      }
    },
  },
  plugins: [],
}
