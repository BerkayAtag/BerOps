/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Geliştirmede API istekleri yerel berops-server'a (https://localhost:8443) aktarılır.
// Sunucu iç CA'dan sertifika ürettiği için vekil sertifikayı doğrulamaz (yalnızca geliştirme).
const apiTarget = process.env.BER_API_URL ?? "https://localhost:8443";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true, secure: false },
    },
    fs: {
      // Ortak tasarım token'ları depo kökündeki design/ klasöründe.
      allow: [".."],
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
