import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const MANIFEST_NAME = 'artifact-manifest.sha256';

export async function verifyArtifactManifest(directory = path.join(root, 'dist')) {
  const distDir = path.resolve(directory);
  const manifestPath = path.join(distDir, MANIFEST_NAME);
  const text = await readFile(manifestPath, 'utf8');
  if (!text.endsWith('\n')) throw new Error('Artifact manifest must end with a newline.');

  const declared = new Map();
  for (const [index, line] of text.slice(0, -1).split('\n').entries()) {
    const match = line.match(/^([0-9a-f]{64})  ([^\0]+)$/);
    if (!match) throw new Error(`Malformed artifact manifest line ${index + 1}.`);
    const relativePath = match[2];
    assertSafeRelativePath(relativePath);
    if (relativePath === MANIFEST_NAME) throw new Error('Artifact manifest must not list itself.');
    if (declared.has(relativePath)) throw new Error(`Duplicate artifact manifest path: ${relativePath}`);
    declared.set(relativePath, match[1]);
  }
  if (declared.size === 0) throw new Error('Artifact manifest is empty.');

  const actualFiles = (await listRegularFiles(distDir))
    .map((absolute) => path.relative(distDir, absolute).split(path.sep).join('/'))
    .filter((relative) => relative !== MANIFEST_NAME)
    .sort();
  const declaredFiles = [...declared.keys()].sort();
  if (actualFiles.length !== declaredFiles.length || actualFiles.some((value, index) => value !== declaredFiles[index])) {
    throw new Error('Artifact manifest file set does not exactly match the build output.');
  }

  for (const relativePath of declaredFiles) {
    const bytes = await readFile(path.join(distDir, ...relativePath.split('/')));
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (digest !== declared.get(relativePath)) {
      throw new Error(`Artifact digest mismatch: ${relativePath}`);
    }
  }
  return { directory: distDir, files: declaredFiles.length };
}

function assertSafeRelativePath(relativePath) {
  if (
    !relativePath ||
    path.posix.isAbsolute(relativePath) ||
    path.win32.isAbsolute(relativePath) ||
    relativePath.includes('\\') ||
    /[^\x20-\x7e]/.test(relativePath) ||
    relativePath.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new Error(`Unsafe artifact manifest path: ${relativePath}`);
  }
}

async function listRegularFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return listRegularFiles(absolute);
    if (!entry.isFile()) throw new Error(`Build output contains a non-regular file: ${absolute}`);
    return [absolute];
  }));
  return nested.flat();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  verifyArtifactManifest(process.argv[2])
    .then(({ directory, files }) => console.log(`Artifact manifest verified: ${files} files in ${directory}`))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
