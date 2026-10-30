import { build } from 'esbuild';
import { mkdirSync, copyFileSync } from 'node:fs';
mkdirSync('dist/web', { recursive: true });
await build({
  entryPoints: ['web/app.ts'],
  bundle: true,
  minify: true,
  outfile: 'dist/web/app.js',
  target: 'es2023',
});
for (const file of ['index.html', 'style.css']) copyFileSync(`web/${file}`, `dist/web/${file}`);
