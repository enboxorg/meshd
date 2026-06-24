import path from "path";

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

export default defineConfig({
  base: "/",
  define: {
    global: "globalThis"
  },
  plugins: [
    nodePolyfills(),
    react()
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src")
    }
  }
});
