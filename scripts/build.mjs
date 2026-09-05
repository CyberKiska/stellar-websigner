import { cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeSecurityHeaders } from './security-headers.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

function normalizeBasePath(value) {
  if (!value || value.trim() === '') return '/';
  let out = value.trim();
  if (!out.startsWith('/')) out = `/${out}`;
  if (!out.endsWith('/')) out = `${out}/`;
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*$/.test(out) || out.split('/').some((part) => part === '.' || part === '..')) {
    throw new Error('BASE_PATH must contain only unreserved URL path segments.');
  }
  return out;
}

function buildCommit() {
  let commit = process.env.GITHUB_SHA || process.env.BUILD_COMMIT;
  if (!commit) {
    try {
      commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      return 'development';
    }
  }
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(commit)) throw new Error('Build commit must be a full Git object ID.');
  return commit.slice(0, 12);
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

async function writeIndexHtml(srcDir, distDir, { basePath, appEntry, version, commit, localSecretPolicy }) {
  const htmlTemplate = await readFile(path.join(srcDir, 'index.html'), 'utf8');
  const html = htmlTemplate
    .replaceAll('%BASE_PATH%', basePath)
    .replaceAll('%APP_ENTRY%', appEntry)
    .replaceAll('%APP_VERSION%', version)
    .replaceAll('%APP_COMMIT%', commit)
    .replaceAll('%LOCAL_SECRET_POLICY%', localSecretPolicy);
  await writeFile(path.join(distDir, 'index.html'), html, 'utf8');
}

async function buildBundle({ srcDir, distDir, basePath, minify, buildFn, version, commit, localSecretPolicy }) {
  const assetsDir = path.join(distDir, 'assets');
  await mkdir(assetsDir, { recursive: true });

  const result = await buildFn({
    entryPoints: {
      app: path.join(srcDir, 'main.js'),
    },
    outdir: assetsDir,
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: ['es2022'],
    sourcemap: true,
    entryNames: '[name]-[hash]',
    metafile: true,
    minify,
    logLevel: 'info',
  });
  const appOutput = Object.entries(result.metafile.outputs).find(([, details]) => details.entryPoint?.endsWith('src/main.js'));
  if (!appOutput) throw new Error('Cannot identify bundled application entry output.');
  const appEntry = path.relative(distDir, path.resolve(root, appOutput[0])).split(path.sep).join('/');

  const css = await readFile(path.join(srcDir, 'styles.css'), 'utf8');
  await Promise.all([
    writeIndexHtml(srcDir, distDir, { basePath, appEntry, version, commit, localSecretPolicy }),
    writeFile(path.join(distDir, 'styles.css'), css, 'utf8'),
    writeFile(path.join(distDir, '.nojekyll'), '', 'utf8'),
  ]);
}

async function buildCopy({ srcDir, distDir, basePath, version, commit, localSecretPolicy }) {
  await cp(srcDir, distDir, { recursive: true });
  await Promise.all([
    writeIndexHtml(srcDir, distDir, { basePath, appEntry: 'main.js', version, commit, localSecretPolicy }),
    writeFile(path.join(distDir, '.nojekyll'), '', 'utf8'),
  ]);
}

export async function buildProject({
  minify = true,
  mode = process.env.BUILD_MODE || 'auto',
  target = process.env.BUILD_TARGET || 'standalone',
  variant = process.env.BUILD_VARIANT || '',
  basePath: requestedBasePath = process.env.BASE_PATH || '/',
  localSecretPolicy = process.env.LOCAL_SECRET_POLICY || 'enabled',
} = {}) {
  const srcDir = path.join(root, 'src');
  const distDir = resolveBuildOutputDirectory(variant);
  const basePath = normalizeBasePath(requestedBasePath);
  const normalizedMode = String(mode || 'auto').toLowerCase();
  if (!['auto', 'bundle', 'copy'].includes(normalizedMode)) throw new Error(`Unsupported BUILD_MODE: ${mode}`);
  if (!['standalone', 'pages'].includes(target)) throw new Error(`Unsupported BUILD_TARGET: ${target}`);
  if (!['enabled', 'disabled'].includes(localSecretPolicy)) throw new Error('LOCAL_SECRET_POLICY must be enabled or disabled.');
  if (target === 'pages' && localSecretPolicy !== 'disabled') throw new Error('Pages builds require LOCAL_SECRET_POLICY=disabled.');
  const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const version = String(packageJson.version || 'unknown');
  const commit = buildCommit();

  await rm(distDir, { recursive: true, force: true });
  await mkdir(distDir, { recursive: true });

  if (normalizedMode === 'copy') {
    await buildCopy({ srcDir, distDir, basePath, version, commit, localSecretPolicy });
    await finalizeArtifact(distDir, target);
    console.log(`Build completed (copy mode). basePath=${basePath}`);
    return;
  }

  const buildFn = await tryLoadEsbuild();
  if (!buildFn) {
    if (normalizedMode === 'bundle') {
      throw new Error('esbuild is not installed, but BUILD_MODE=bundle was requested.');
    }
    await buildCopy({ srcDir, distDir, basePath, version, commit, localSecretPolicy });
    await finalizeArtifact(distDir, target);
    console.log(`Build completed (copy fallback). basePath=${basePath}`);
    return;
  }

  await buildBundle({
    srcDir,
    distDir,
    basePath,
    minify,
    buildFn,
    version,
    commit,
    localSecretPolicy,
  });
  await finalizeArtifact(distDir, target);
  console.log(`Build completed (bundle mode). basePath=${basePath}`);
}

async function finalizeArtifact(distDir, target) {
  // Header-limited previews omit the marker before the final file set is hashed.
  if (target === 'standalone') await writeSecurityHeaders(distDir);
  await writeArtifactManifest(distDir);
}

export function resolveBuildOutputDirectory(variant = process.env.BUILD_VARIANT || '') {
  const name = String(variant || '').trim();
  if (!name) return path.join(root, 'dist');
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) {
    throw new Error(`Unsafe BUILD_VARIANT: ${variant}`);
  }
  return path.join(root, '.playwright-dist', name);
}

async function writeArtifactManifest(distDir) {
  const files = await listFiles(distDir);
  const lines = [];
  for (const filePath of files) {
    if (path.basename(filePath) === 'artifact-manifest.sha256') continue;
    const data = await readFile(filePath);
    const digest = createHash('sha256').update(data).digest('hex');
    lines.push(`${digest}  ${path.relative(distDir, filePath).split(path.sep).join('/')}`);
  }
  await writeFile(path.join(distDir, 'artifact-manifest.sha256'), `${lines.sort().join('\n')}\n`, 'utf8');
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) return listFiles(absolute);
      if (!entry.isFile()) throw new Error(`Build output contains a non-regular file: ${absolute}`);
      return [absolute];
    })
  );
  return nested.flat();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  buildProject().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
