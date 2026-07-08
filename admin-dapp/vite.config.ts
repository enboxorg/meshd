import path from "path";

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  base: "/",
  define: {
    global: "globalThis"
  },
  plugins: [
    nodePolyfills(),
    react(),
    VitePWA({
      strategies: "injectManifest",
      srcDir: "src",
      filename: "sw.ts",
      registerType: "prompt",
      injectRegister: "auto",

      pwaAssets: {
        disabled: false,
        config: true
      },

      manifest: {
        name: "meshd Admin",
        short_name: "meshd",
        description: "Dashboard for managing meshd WireGuard networks over DWN",
        theme_color: "#101820",
        background_color: "#101820"
      },

      injectManifest: {
        maximumFileSizeToCacheInBytes: 5000000,
        globPatterns: ["**/*.{js,css,html,json,svg,png,ico}"]
      },

      devOptions: {
        enabled: true,
        navigateFallback: "index.html",
        suppressWarnings: false,
        type: "module"
      }
    })
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src")
    }
  }
});
