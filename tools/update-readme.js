#!/usr/bin/env node
/**
 * Updates README.md with latest test statistics and coverage report
 *
 * This script:
 * 1. Reads test output from vitest
 * 2. Reads coverage data from coverage-summary.json
 * 3. Updates the auto-generated section in README.md
 *
 * Only updates if all tests passed (100% coverage)
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import * as yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

/**
 * Count lines in source files
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
 * Build coverage table
 */
function buildCoverageTable() {
  const coverage = parseCoverage();
  if (!coverage) {
    return null;
  }

  const srcDir = join(rootDir, 'src');

  // Count lines in source files
  const lineCounts = {};
  function walkDir(dir) {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      const stat = statSync(fullPath);
      if (stat.isDirectory() && !['node_modules', 'dist', 'coverage', '.git'].includes(entry)) {
        walkDir(fullPath);
      } else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts')) {
        const relPath = relative(srcDir, fullPath);
        lineCounts[relPath] = countLines(fullPath);
      }
    }
  }
  walkDir(srcDir);

  const total = coverage.total;
  const totalLines = Object.values(lineCounts).reduce((sum, count) => sum + count, 0);

  let table = 'File                │ Lines   │ % Stmts │ % Branch │ % Funcs │ % Lines │ Uncovered\n';
  table += '────────────────────────────────────────────────────────────────────────────────────────────────────\n';

  // Total row
  table += 'All files           │ ' + String(totalLines).padEnd(7) + ' │ ' +
    formatPct(total.statements.pct).padStart(7) + '│ ' +
    formatPct(total.branches.pct).padStart(8) + ' │ ' +
    formatPct(total.functions.pct).padStart(7) + '│ ' +
    formatPct(total.lines.pct).padStart(7) + ' │\n';

  // Per-file rows
  for (const [filePath, stats] of Object.entries(coverage)) {
    if (filePath === 'total') continue;

    const relPath = relative(join(rootDir, 'src'), filePath);
    const lineCount = lineCounts[relPath] || 0;
    const uncovered = stats.lines.total - stats.lines.covered;
    const uncoveredStr = uncovered > 0 ? `${uncovered} lines` : '';

    table += ' ' + relPath.padEnd(19) + '│ ' +
      String(lineCount).padEnd(7) + ' │ ' +
      formatPct(stats.statements.pct).padStart(7) + '│ ' +
      formatPct(stats.branches.pct).padStart(8) + ' │ ' +
      formatPct(stats.functions.pct).padStart(7) + '│ ' +
      formatPct(stats.lines.pct).padStart(7) + ' │ ' +
      uncoveredStr + '\n';
  }

  return table;
}

/**
 * Count coverage exceptions from COVERAGE_EXCEPTIONS.yml
 * Parses patterns to count actual number of lines excluded
 */
function countCoverageExceptions() {
  try {
    const exceptionsPath = join(rootDir, 'COVERAGE_EXCEPTIONS.yml');
    const exceptionsContent = readFileSync(exceptionsPath, 'utf-8');
    const exceptions = yaml.parse(exceptionsContent);

    let totalLines = 0;
    for (const fileExceptions of Object.values(exceptions)) {
      if (Array.isArray(fileExceptions)) {
        for (const exc of fileExceptions) {
          const pattern = exc.pattern || '';

          // Parse "/* c8 ignore next N */" or "/* v8 ignore next N */"
          const nextMatch = pattern.match(/ignore next (\d+)/);
          if (nextMatch) {
            totalLines += parseInt(nextMatch[1], 10);
          }
          // Parse "/* c8 ignore next */" (default to 1 line)
          else if (pattern.includes('ignore next')) {
            totalLines += 1;
          }
        }
      }
    }

    return totalLines;
  } catch (error) {
    console.warn('Failed to read coverage exceptions:', error.message);
    return 0;
  }
}

/**
 * Count test files in tests directory
 */
function countTestFiles() {
  const testsDir = join(rootDir, 'tests');
  let count = 0;

  function walkDir(dir) {
    try {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          walkDir(fullPath);
        } else if (entry.endsWith('.test.ts')) {
          count++;
        }
      }
    } catch {
      // Ignore errors
    }
  }

  walkDir(testsDir);
  return count;
}

/**
 * Get test stats by running vitest and parsing output
 */
async function getTestStats() {
  const { execSync } = await import('child_process');

  try {
    // Run vitest with default reporter
    const output = execSync('pnpm vitest run', {
      cwd: rootDir,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    // Parse standard output for summary lines
    // Example: "Test Files  8 passed (8)"
    // Example: "Tests  190 passed (190)"
    // Example: "Duration  3.77s"
    const testFileMatch = output.match(/Test Files\s+(\d+)\s+passed/);
    const testMatch = output.match(/Tests\s+(\d+)\s+passed/);
    const durationMatch = output.match(/Duration\s+([\d.]+s)/);

    if (testFileMatch && testMatch) {
      const numTestFiles = parseInt(testFileMatch[1], 10);
      const numTests = parseInt(testMatch[1], 10);
      const duration = durationMatch ? durationMatch[1] : '~1s';

      return {
        testFiles: `${numTestFiles} passed (${numTestFiles})`,
        tests: `${numTests} passed (${numTests})`,
        duration,
      };
    }

    throw new Error('Could not parse vitest output');
  } catch (error) {
    console.error('Failed to run tests:', error.message);

    // Fallback to file counting
    const testFileCount = countTestFiles();
    return {
      testFiles: `${testFileCount} files`,
      tests: 'Unknown',
      duration: 'Unknown',
    };
  }
}

/**
 * Update README.md with new stats
 */
async function updateReadme() {
  const readmePath = join(rootDir, 'README.md');
  const readme = readFileSync(readmePath, 'utf-8');

  const stats = await getTestStats();
  const coverageTable = buildCoverageTable();

  if (!stats || !coverageTable) {
    console.error('Failed to generate stats or coverage table');
    process.exit(1);
  }

  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const exceptionsCount = countCoverageExceptions();

  const newSection = `### Test Coverage & Statistics

<!-- AUTO-GENERATED: Do not edit manually -->
*Last updated: ${timestamp} UTC*

**Test Results:**
- Test Files: ${stats.testFiles}
- Tests: ${stats.tests}
- Duration: ${stats.duration}

**Coverage Report:**
\`\`\`
${coverageTable}\`\`\`

**Coverage Exceptions:** ${exceptionsCount} lines excluded ([view exceptions](COVERAGE_EXCEPTIONS.yml))
<!-- END AUTO-GENERATED -->`;

  // Find and replace the auto-generated section
  const startMarker = '### Test Coverage & Statistics\n\n<!-- AUTO-GENERATED: Do not edit manually -->';
  const endMarker = '<!-- END AUTO-GENERATED -->';

  const startIdx = readme.indexOf(startMarker);

  if (startIdx === -1) {
    // Section doesn't exist, append it after "Current Status" section
    const currentStatusEnd = readme.indexOf('\n## ', readme.indexOf('## Current Status') + 1);
    if (currentStatusEnd === -1) {
      console.error('Could not find Current Status section');
      process.exit(1);
    }

    const before = readme.substring(0, currentStatusEnd);
    const after = readme.substring(currentStatusEnd);
    const updated = before + '\n\n' + newSection + '\n' + after;
    writeFileSync(readmePath, updated, 'utf-8');
  } else {
    // Section exists, replace it
    const endIdx = readme.indexOf(endMarker, startIdx) + endMarker.length;
    const before = readme.substring(0, startIdx);
    const after = readme.substring(endIdx);
    const updated = before + newSection + after;
    writeFileSync(readmePath, updated, 'utf-8');
  }

  console.log('✅ README.md updated with latest test statistics');
}

// Check if coverage meets 100% threshold
const coverage = parseCoverage();
if (!coverage) {
  console.error('❌ No coverage data found');
  process.exit(1);
}

const { total } = coverage;
if (total.lines.pct !== 100 || total.statements.pct !== 100 ||
    total.branches.pct !== 100 || total.functions.pct !== 100) {
  console.error('❌ Coverage is not 100%, skipping README update');
  process.exit(1);
}

await updateReadme();
