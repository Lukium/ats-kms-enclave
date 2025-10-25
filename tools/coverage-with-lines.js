#!/usr/bin/env node
/**
 * Enhanced coverage reporter that shows line counts alongside coverage metrics
 *
 * Reads v8 coverage JSON and adds total line count column
 */

// ANSI color codes
const GREEN = '\x1b[32m';
const RESET = '\x1b[0m';

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

/**
 * Count lines in a file
 */
function countLines(filePath) {
  try {
    const content = readFileSync(filePath, 'utf-8');
    return content.split('\n').length;
  } catch {
    return 0;
  }
}

/**
 * Find all source files (V2 only)
 */
function findSourceFiles(dir, files = []) {
  const entries = readdirSync(dir);

  for (const entry of entries) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory() && !['node_modules', 'dist', 'coverage', '.git'].includes(entry)) {
      findSourceFiles(fullPath, files);
    } else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts') && !entry.endsWith('.d.ts')) {
      // Only include v2 files
      if (fullPath.includes('/v2/')) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

/**
 * Parse coverage JSON
 */
function parseCoverage() {
  try {
    const coveragePath = join(rootDir, 'coverage', 'coverage-summary.json');
    const coverage = JSON.parse(readFileSync(coveragePath, 'utf-8'));
    return coverage;
  } catch (error) {
    console.error('Failed to read coverage data:', error.message);
    return null;
  }
}

/**
 * Format percentage
 */
function formatPct(value) {
  return value === 100 ? '100' : value.toFixed(2);
}

/**
 * Main function
 */
function main() {
  const coverage = parseCoverage();
  if (!coverage) {
    process.exit(1);
  }

  const srcDir = join(rootDir, 'src');
  const sourceFiles = findSourceFiles(srcDir);

  // Build line count map
  const lineCounts = {};
  for (const file of sourceFiles) {
    const relPath = relative(srcDir, file);
    lineCounts[relPath] = countLines(file);
  }

  console.log('\n📊 Coverage Report with Line Counts (V2 only)\n');
  console.log('─'.repeat(100));
  console.log(
    'File'.padEnd(20) +
    '│ Lines'.padEnd(10) +
    '│ % Stmts'.padEnd(10) +
    '│ % Branch'.padEnd(11) +
    '│ % Funcs'.padEnd(10) +
    '│ % Lines'.padEnd(10) +
    '│ Uncovered'
  );
  console.log('─'.repeat(100));

  // Print totals
  const total = coverage.total;
  const totalLines = Object.values(lineCounts).reduce((sum, count) => sum + count, 0);

  console.log(
    GREEN + 'All files'.padEnd(20) + RESET +
    '│' + GREEN + ` ${String(totalLines).padEnd(8)}` + RESET +
    '│' + GREEN + ` ${formatPct(total.statements.pct).padStart(7)}` + RESET +
    '│' + GREEN + ` ${formatPct(total.branches.pct).padStart(9)}` + RESET +
    '│' + GREEN + ` ${formatPct(total.functions.pct).padStart(8)}` + RESET +
    '│' + GREEN + ` ${formatPct(total.lines.pct).padStart(8)}` + RESET +
    '│'
  );

  // Print per-file stats
  for (const [filePath, stats] of Object.entries(coverage)) {
    if (filePath === 'total') continue;

    const relPath = relative(join(rootDir, 'src'), filePath);
    const lineCount = lineCounts[relPath] || 0;

    const uncovered = stats.lines.total - stats.lines.covered;
    const uncoveredStr = uncovered > 0 ? `${uncovered} lines` : '';

    console.log(
      GREEN + ` ${relPath}`.padEnd(20) + RESET +
      '│' + GREEN + ` ${String(lineCount).padEnd(8)}` + RESET +
      '│' + GREEN + ` ${formatPct(stats.statements.pct).padStart(7)}` + RESET +
      '│' + GREEN + ` ${formatPct(stats.branches.pct).padStart(9)}` + RESET +
      '│' + GREEN + ` ${formatPct(stats.functions.pct).padStart(8)}` + RESET +
      '│' + GREEN + ` ${formatPct(stats.lines.pct).padStart(8)}` + RESET +
      '│' + GREEN + ` ${uncoveredStr}` + RESET
    );
  }

  console.log('─'.repeat(100));

  // Check if coverage meets threshold (80% for V2)
  const threshold = 80;
  const meetsThreshold =
    total.lines.pct >= threshold &&
    total.statements.pct >= threshold &&
    total.branches.pct >= threshold &&
    total.functions.pct >= threshold;

  if (meetsThreshold) {
    console.log(`\n✅ Coverage meets ${threshold}% threshold for all metrics (V2)\n`);
  } else {
    console.log(`\n⚠️  Coverage does not meet ${threshold}% threshold (V2)\n`);
    console.log('   Lines:', total.lines.pct.toFixed(2) + '%');
    console.log('   Statements:', total.statements.pct.toFixed(2) + '%');
    console.log('   Branches:', total.branches.pct.toFixed(2) + '%');
    console.log('   Functions:', total.functions.pct.toFixed(2) + '%');
    console.log();
  }
}

main();
