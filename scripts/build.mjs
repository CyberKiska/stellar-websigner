import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

function normalizeBasePath(value) {
  if (!value || value.trim() === '') return '/';
  let out = value.trim();
  if (!out.startsWith('/')) out = `/${out}`;
  if (!out.endsWith('/')) out = `${out}/`;
  return out;
}

async function tryLoadEsbuild() {
  try {
    const mod = await import('esbuild');
    if (typeof mod.build === 'function') return mod.build;
  } catch (_err) {
    return null;
  }
  return null;
}

async function writeIndexHtml(srcDir, distDir, { basePath, appEntry }) {
  const htmlTemplate = await readFile(path.join(srcDir, 'index.html'), 'utf8');
  const html = htmlTemplate.replaceAll('%BASE_PATH%', basePath).replaceAll('%APP_ENTRY%', appEntry);
  await writeFile(path.join(distDir, 'index.html'), html, 'utf8');
}

async function buildBundle({ srcDir, distDir, basePath, minify, buildFn }) {
  const assetsDir = path.join(distDir, 'assets');
  await mkdir(assetsDir, { recursive: true });

  await buildFn({
    entryPoints: {
      app: path.join(srcDir, 'main.js'),
    },
    outdir: assetsDir,
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: ['es2022'],
    sourcemap: true,
    minify,
    logLevel: 'info',
  });

  const css = await readFile(path.join(srcDir, 'styles.css'), 'utf8');
  await Promise.all([
    writeIndexHtml(srcDir, distDir, { basePath, appEntry: 'assets/app.js' }),
    writeFile(path.join(distDir, 'styles.css'), css, 'utf8'),
    writeFile(path.join(distDir, '.nojekyll'), '', 'utf8'),
  ]);
}

async function buildCopy({ srcDir, distDir, basePath }) {
  await cp(srcDir, distDir, { recursive: true });
  await Promise.all([
    writeIndexHtml(srcDir, distDir, { basePath, appEntry: 'main.js' }),
    writeFile(path.join(distDir, '.nojekyll'), '', 'utf8'),
  ]);
}

export async function buildProject({ minify = true, mode = process.env.BUILD_MODE || 'auto' } = {}) {
  const srcDir = path.join(root, 'src');
  const distDir = path.join(root, 'dist');
  const basePath = normalizeBasePath(process.env.BASE_PATH || '/');

  await rm(distDir, { recursive: true, force: true });
  await mkdir(distDir, { recursive: true });

  const normalizedMode = String(mode || 'auto').toLowerCase();
  if (!['auto', 'bundle', 'copy'].includes(normalizedMode)) {
    throw new Error(`Unsupported BUILD_MODE: ${mode}`);
  }

  if (normalizedMode === 'copy') {
    await buildCopy({ srcDir, distDir, basePath });
    console.log(`Build completed (copy mode). basePath=${basePath}`);
    return;
  }

  const buildFn = await tryLoadEsbuild();
  if (!buildFn) {
    if (normalizedMode === 'bundle') {
      throw new Error('esbuild is not installed, but BUILD_MODE=bundle was requested.');
    }
    await buildCopy({ srcDir, distDir, basePath });
    console.log(`Build completed (copy fallback). basePath=${basePath}`);
    return;
  }

  await buildBundle({
    srcDir,
    distDir,
    basePath,
    minify,
    buildFn,
  });
  console.log(`Build completed (bundle mode). basePath=${basePath}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  buildProject().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
