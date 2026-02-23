import { runSelfTest } from '../src/core/selftest.js';

async function main() {
  const report = await runSelfTest();
  console.log(`Self-test: ${report.ok ? 'PASS' : 'FAIL'} (${report.passed}/${report.total})`);
  for (const item of report.results) {
    if (item.ok) console.log(`  OK   ${item.name}`);
    else console.log(`  FAIL ${item.name}: ${item.error}`);
  }
  if (!report.ok) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
