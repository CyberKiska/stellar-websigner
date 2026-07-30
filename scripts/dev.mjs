import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, watch } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProject, resolveBuildOutputDirectory } from './build.mjs';
import { SECURITY_HEADERS } from './security-headers.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const srcDir = path.join(root, 'src');
const distDir = resolveBuildOutputDirectory();
const port = Number(process.env.PORT || 5173);
const securityHeaders = Object.fromEntries(SECURITY_HEADERS);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

async function serveFile(urlPath) {
  const normalized = resolveSafeFilePath(urlPath, distDir);
  if (!normalized) {
    return { status: 403, body: 'Forbidden', type: 'text/plain; charset=utf-8' };
  }

  if (!existsSync(normalized)) {
    return { status: 404, body: 'Not Found', type: 'text/plain; charset=utf-8' };
  }

  const ext = path.extname(normalized);
  const type = MIME[ext] || 'application/octet-stream';
  const body = await readFile(normalized);
  return { status: 200, body, type };
}

export function resolveSafeFilePath(urlPath, rootDirectory) {
  let pathname;
  try {
    pathname = decodeURIComponent(String(urlPath || '/').split(/[?#]/, 1)[0]);
  } catch {
    return null;
  }
  if (!pathname.startsWith('/') || pathname.includes('\\') || pathname.includes('\0')) return null;
  if (pathname.split('/').some((segment) => segment === '..')) return null;
  const relativeUrlPath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const candidate = path.resolve(rootDirectory, relativeUrlPath);
  const relative = path.relative(rootDirectory, candidate);
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) return null;
  return candidate;
}

async function runBuild() {
  await buildProject({
    minify: false,
    mode: process.env.BUILD_MODE || 'auto',
  });
}

async function main() {
  await runBuild();

  const server = createServer(async (req, res) => {
    try {
      const response = await serveFile(req.url || '/');
      res.writeHead(response.status, { ...securityHeaders, 'Content-Type': response.type });
      res.end(response.body);
    } catch (err) {
      res.writeHead(500, { ...securityHeaders, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(err?.message || 'Internal Server Error');
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`Dev server: http://localhost:${port}`);
  });

  let timer = null;
  watch(srcDir, { recursive: true }, () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try {
        await runBuild();
        console.log('Rebuilt.');
      } catch (err) {
        console.error('Build failed:', err?.message || err);
      }
    }, 120);
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
