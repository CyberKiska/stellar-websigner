import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { buildProject, resolveBuildOutputDirectory } from '../../scripts/build.mjs';
import { verifyArtifactManifest } from '../../scripts/verify-artifact-manifest.mjs';

test('standalone and Pages artifacts verify after all packaging in bundle and copy modes', async () => {
  for (const mode of ['bundle', 'copy']) {
    for (const target of ['standalone', 'pages']) {
      const variant = `core-${process.pid}-${mode}-${target}`;
      const directory = resolveBuildOutputDirectory(variant);
      try {
        await buildProject({ mode, target, variant, localSecretPolicy: 'disabled', basePath: '/stellar-websigner/' });
        await verifyArtifactManifest(directory);
        const manifest = await readFile(path.join(directory, 'artifact-manifest.sha256'), 'utf8');
        assert.equal(manifest.includes('  _headers\n'), target === 'standalone');
        const html = await readFile(path.join(directory, 'index.html'), 'utf8');
        assert.match(html, /name="local-secret-operations" content="disabled"/);
        assert(html.includes('/stellar-websigner/'));
        if (target === 'pages') await assert.rejects(() => readFile(path.join(directory, '_headers')), { code: 'ENOENT' });
        // The exact package, including unexpected files, is the verification boundary.
        await writeFile(path.join(directory, 'unexpected.js'), '');
        await assert.rejects(() => verifyArtifactManifest(directory), /file set/);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  }
});

test('invalid build policy and URL settings fail before touching an existing artifact', async () => {
  const variant = `core-${process.pid}-invalid-policy`;
  const directory = resolveBuildOutputDirectory(variant);
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, 'sentinel'), 'existing artifact');
  try {
    for (const options of [
      { mode: 'typo' }, { target: 'typo' }, { localSecretPolicy: 'diabled' },
      { target: 'pages', localSecretPolicy: 'enabled' },
      { basePath: '/" onload="alert(1)/' }, { basePath: '/../' }, { basePath: '/x?y/' },
    ]) {
      await assert.rejects(() => buildProject({ mode: 'copy', target: 'standalone', localSecretPolicy: 'disabled', basePath: '/', ...options, variant }));
      assert.equal(await readFile(path.join(directory, 'sentinel'), 'utf8'), 'existing artifact');
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
