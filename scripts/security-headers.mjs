import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

export const META_CSP =
  "default-src 'self'; connect-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types 'none'";

export const HTTP_CSP = `${META_CSP}; frame-ancestors 'none'`;

export const SECURITY_HEADERS = Object.freeze([
  ['Content-Security-Policy', HTTP_CSP],
  ['X-Frame-Options', 'DENY'],
  ['X-Content-Type-Options', 'nosniff'],
  ['Strict-Transport-Security', 'max-age=31536000'],
  ['Cache-Control', 'no-cache'],
  ['Referrer-Policy', 'no-referrer'],
  ['Cross-Origin-Opener-Policy', 'same-origin'],
  ['Cross-Origin-Resource-Policy', 'same-origin'],
  ['Permissions-Policy', 'clipboard-read=(self), clipboard-write=(self)'],
]);

export function securityHeadersText() {
  const lines = ['/*'];
  for (const [name, value] of SECURITY_HEADERS) {
    lines.push(`  ${name}: ${value}`);
  }
  return `${lines.join('\n')}\n`;
}

export async function writeSecurityHeaders(distDir = path.join(root, 'dist')) {
  await mkdir(distDir, { recursive: true });
  await writeFile(path.join(distDir, '_headers'), securityHeadersText(), 'utf8');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  writeSecurityHeaders(process.argv[2] ? path.resolve(process.argv[2]) : undefined).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
