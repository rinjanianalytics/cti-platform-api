import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  root: resolve(__dirname, "src/ui"),
  base: "./",
  build: {
    outDir: resolve(__dirname, "dist/ui"),
    emptyOutDir: true,
    // Vite defaults to the 'modules' preset (chrome87+edge88+es2020+
    // firefox78+safari14), which includes es2020 — and esbuild 0.28
    // no longer silently transforms certain destructuring patterns
    // for es2020 targets. The vendored TanStack Router / bull-board
    // bundle uses those patterns, so the build fails with
    // "Transforming destructuring to the configured target environment
    // is not supported yet". Target 'esnext' so the bundler ships the
    // patterns verbatim and we don't depend on esbuild's transform
    // capabilities. Workbench is served only to modern browsers
    // (Chrome/Edge/Firefox/Safari latest), so esnext is safe.
    target: "esnext",
    rollupOptions: {
      input: resolve(__dirname, "src/ui/index.html"),
      output: {
        entryFileNames: "assets/[name].js",
        chunkFileNames: "assets/[name].js",
        assetFileNames: "assets/[name].[ext]",
      },
    },
  },
  resolve: {
    alias: [
      { find: "@/core", replacement: resolve(__dirname, "src/core") },
      { find: "@", replacement: resolve(__dirname, "src/ui") },
    ],
  },
});
