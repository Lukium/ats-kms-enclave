/**
 * Coverage Exceptions Validation Test
 *
 * This test ensures that all coverage ignore directives (c8 ignore and v8 ignore comments)
 * in the source code are documented in COVERAGE_EXCEPTIONS.yml with a clear rationale.
 *
 * Why this matters:
 * - Prevents unchecked growth of coverage exceptions
 * - Ensures every exception has a documented reason
 * - Makes code review easier (reviewers can see why something is ignored)
 * - Prevents accidental ignores from being committed
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import * as yaml from 'yaml';

interface CoverageException {
  line: number;
  pattern: string;
  reason: string;
}

interface CoverageExceptions {
  [filePath: string]: CoverageException[];
}

/**
 * Recursively find all TypeScript files in a directory
 * Returns paths relative to project root (e.g., "src/audit.ts")
 */
function findTypeScriptFiles(dir: string, projectRoot: string): string[] {
  const files: string[] = [];
  const entries = readdirSync(dir);

  for (const entry of entries) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      files.push(...findTypeScriptFiles(fullPath, projectRoot));
    } else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) {
      // Return relative path from project root
      const relativePath = fullPath.replace(projectRoot + '/', '');
      files.push(relativePath);
    }
  }

  return files;
}

/**
 * Find all coverage ignore comments in a file
 */
function findIgnoreComments(filePath: string): Array<{ line: number; pattern: string }> {
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const ignores: Array<{ line: number; pattern: string }> = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;

    // Match both c8 and v8 ignore comments
    const match = line.match(/\/\*\s*[cv]8\s+ignore[^*]*\*\//);
    if (match) {
      ignores.push({
        line: i + 1, // Lines are 1-indexed
        pattern: match[0].trim(),
      });
    }
  }

  return ignores;
}

describe.skip('Coverage Exceptions Registry', () => {
  const projectRoot = process.cwd();
  const srcDir = join(projectRoot, 'src');
  const exceptionsFile = join(projectRoot, 'COVERAGE_EXCEPTIONS.yml');

  it('should have a COVERAGE_EXCEPTIONS.yml file', () => {
    expect(() => readFileSync(exceptionsFile, 'utf-8')).not.toThrow();
  });

  it('should have valid YAML format', () => {
    const content = readFileSync(exceptionsFile, 'utf-8');
    expect(() => yaml.parse(content) as CoverageExceptions).not.toThrow();
  });

  it('should document all coverage ignore directives in source code', () => {
    // Load documented exceptions
    const exceptionsContent = readFileSync(exceptionsFile, 'utf-8');
    const exceptions: CoverageExceptions = yaml.parse(exceptionsContent) as CoverageExceptions;

    // Find all TypeScript files in src/
    const tsFiles = findTypeScriptFiles(srcDir, projectRoot);

    // Track all ignores found in code and which are documented
    const foundIgnores: Array<{ file: string; line: number; pattern: string }> = [];
    const undocumentedIgnores: Array<{ file: string; line: number; pattern: string }> = [];

    for (const file of tsFiles) {
      const fullPath = join(projectRoot, file);
      const ignores = findIgnoreComments(fullPath);

      for (const ignore of ignores) {
        foundIgnores.push({ file, line: ignore.line, pattern: ignore.pattern });

        // Check if this ignore is documented
        const fileExceptions = exceptions[file];
        const isDocumented = fileExceptions?.some(
          (exc) => exc.line === ignore.line
        );

        if (!isDocumented) {
          undocumentedIgnores.push({ file, line: ignore.line, pattern: ignore.pattern });
        }
      }
    }

    // Report findings
    if (undocumentedIgnores.length > 0) {
      const message = [
        'Found undocumented coverage ignore directives:',
        '',
        ...undocumentedIgnores.map(
          (ignore) => `  ${ignore.file}:${ignore.line} - ${ignore.pattern}`
        ),
        '',
        'Please add these to COVERAGE_EXCEPTIONS.yml with a clear rationale.',
      ].join('\n');

      expect.fail(message);
    }

    // If we get here, all ignores are documented
    expect(foundIgnores.length).toBeGreaterThan(0); // Sanity check
  });

  it('should not have stale entries (documented but not in code)', () => {
    // Load documented exceptions
    const exceptionsContent = readFileSync(exceptionsFile, 'utf-8');
    const exceptions: CoverageExceptions = yaml.parse(exceptionsContent) as CoverageExceptions;

    // Find all TypeScript files in src/
    const tsFiles = findTypeScriptFiles(srcDir, projectRoot);

    // Build a map of actual ignores in code
    const actualIgnores = new Map<string, Set<number>>();
    for (const file of tsFiles) {
      const fullPath = join(projectRoot, file);
      const ignores = findIgnoreComments(fullPath);
      const lines = new Set(ignores.map((i) => i.line));
      actualIgnores.set(file, lines);
    }

    // Check for stale entries
    const staleEntries: Array<{ file: string; line: number }> = [];

    for (const [file, fileExceptions] of Object.entries(exceptions)) {
      const actualLines = actualIgnores.get(file) || new Set();

      for (const exc of fileExceptions) {
        if (!actualLines.has(exc.line)) {
          staleEntries.push({ file, line: exc.line });
        }
      }
    }

    if (staleEntries.length > 0) {
      const message = [
        'Found stale entries in COVERAGE_EXCEPTIONS.yml (documented but not in code):',
        '',
        ...staleEntries.map((entry) => `  ${entry.file}:${entry.line}`),
        '',
        'Please remove these entries from COVERAGE_EXCEPTIONS.yml.',
      ].join('\n');

      expect.fail(message);
    }
  });

  it('should have non-empty reason for each exception', () => {
    const exceptionsContent = readFileSync(exceptionsFile, 'utf-8');
    const exceptions: CoverageExceptions = yaml.parse(exceptionsContent) as CoverageExceptions;

    const missingReasons: Array<{ file: string; line: number }> = [];

    for (const [file, fileExceptions] of Object.entries(exceptions)) {
      for (const exc of fileExceptions) {
        if (!exc.reason || exc.reason.trim().length === 0) {
          missingReasons.push({ file, line: exc.line });
        }
      }
    }

    if (missingReasons.length > 0) {
      const message = [
        'Found coverage exceptions without reason:',
        '',
        ...missingReasons.map((entry) => `  ${entry.file}:${entry.line}`),
        '',
        'Please add a clear rationale for each exception.',
      ].join('\n');

      expect.fail(message);
    }
  });
});
