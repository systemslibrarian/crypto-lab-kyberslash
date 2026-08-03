import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-kyberslash/',
  // Pin the preview port. Without this, `vite preview` binds its default 4173 —
  // a port a dozen labs in this fleet used to share — so this lab could squat
  // on a sibling's harness even after its own scripts moved off 4173. It also
  // matches the default BASE in scripts/verify-ui*.mjs.
  preview: { port: 4705, strictPort: true },
});