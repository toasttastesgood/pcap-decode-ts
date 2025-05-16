import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'), // Adjust entry point if needed
      name: 'PcapDecoder', // Global variable name for UMD build
      fileName: (format) => `pcap-decoder.${format}.js`,
      formats: ['es', 'umd'], // Build for ESM and UMD
    },
    rollupOptions: {
      // Externalize dependencies that shouldn't be bundled
      // For a library, you typically externalize peer dependencies
      external: [], // Add external dependencies here if any
      output: {
        // Global variables to use for externalized deps in UMD build
        globals: {}, // Add globals here if externalizing
      },
    },
    sourcemap: true,
    emptyOutDir: true,
  },
});
