import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The app is served by FastAPI from /ui, so assets must resolve under that
// base. `dev` proxies API calls to a locally running analyzer so the session
// cookie stays first-party (SameSite=strict would drop it cross-origin).
const API_TARGET = process.env.BGP_API_TARGET ?? "http://127.0.0.1:8000";

export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // No inline scripts/styles: the UI runs under a CSP without
    // 'unsafe-inline', so everything must be an external file.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      ["/auth", "/snapshots", "/diff", "/jobs", "/routers", "/audit", "/health"].map((p) => [
        p,
        { target: API_TARGET, changeOrigin: false },
      ]),
    ),
  },
});
