#!/usr/bin/env tsx
/**
 * KMS Verification Badge Generator
 *
 * Generates an SVG badge showing:
 * - Verification status (✅/❌)
 * - Time since last verification
 * - Worker hash (short form)
 *
 * Badge format: [KMS Verified ✅ | 2 hours ago | d5333940]
 *
 * Part of Phase 2.1: Verifiable Builds
 */

import { writeFileSync } from 'fs';
import { join } from 'path';

interface BadgeData {
  passed: boolean;
  timestamp: string;
  hash: string;
  runUrl?: string;
}

/**
 * Format timestamp as compact date/time (e.g., "Nov 2, 11:10 UTC")
 * Static SVG cannot update, so we show the actual verification time
 */
function formatCompactTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  const month = date.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' });
  const day = date.getUTCDate();
  const hours = date.getUTCHours().toString().padStart(2, '0');
  const minutes = date.getUTCMinutes().toString().padStart(2, '0');
  return `${month} ${day}, ${hours}:${minutes} UTC`;
}

/**
 * Generate SVG badge
 */
export function generateBadge(data: BadgeData): string {
  const status = data.passed ? '✅' : '❌';
  const statusText = data.passed ? 'Verified' : 'FAILED';
  const statusColor = data.passed ? '#4CAF50' : '#F44336';
  const verifiedTime = formatCompactTimestamp(data.timestamp);
  const shortHash = data.hash.substring(0, 8);

  // Calculate widths for each section (approximate)
  const section1Width = 110; // "KMS Verified ✅"
  const section2Width = 150; // "Nov 2, 11:10 UTC"
  const section3Width = 80;  // "d5333940"
  const totalWidth = section1Width + section2Width + section3Width;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img">
  <title>KMS Verification Status</title>

  <!-- Background -->
  <linearGradient id="bg" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>

  <!-- Section 1: Status -->
  <rect width="${section1Width}" height="20" fill="#555"/>
  <rect x="${section1Width}" width="${section2Width}" height="20" fill="${statusColor}"/>
  <rect x="${section1Width + section2Width}" width="${section3Width}" height="20" fill="#444"/>

  <rect width="${totalWidth}" height="20" fill="url(#bg)"/>

  <!-- Text -->
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <!-- "KMS Verified" text -->
    <text x="${section1Width / 2}" y="15" fill="#000" fill-opacity=".3">KMS ${statusText}</text>
    <text x="${section1Width / 2 - 1}" y="14">KMS ${statusText}</text>

    <!-- Timestamp -->
    <text x="${section1Width + section2Width / 2}" y="15" fill="#000" fill-opacity=".3">${verifiedTime}</text>
    <text x="${section1Width + section2Width / 2 - 1}" y="14">${verifiedTime}</text>

    <!-- Hash -->
    <text x="${section1Width + section2Width + section3Width / 2}" y="15" fill="#fff" fill-opacity=".8">${shortHash}</text>
    <text x="${section1Width + section2Width + section3Width / 2 - 1}" y="14" fill="#fff" fill-opacity=".9">${shortHash}</text>
  </g>
</svg>`;

  return svg;
}

/**
 * Generate badge JSON metadata (for KMS to display)
 */
export function generateBadgeMetadata(data: BadgeData): string {
  return JSON.stringify({
    status: data.passed ? 'verified' : 'failed',
    timestamp: data.timestamp,
    hash: data.hash,
    shortHash: data.hash.substring(0, 8),
    verifiedTime: formatCompactTimestamp(data.timestamp),
    runUrl: data.runUrl,
    generatedAt: new Date().toISOString(),
  }, null, 2);
}

/**
 * Main entry point
 */
async function main() {
  // Read verification result from environment or file
  const passed = process.env.VERIFICATION_PASSED === 'true';
  const timestamp = process.env.VERIFICATION_TIMESTAMP || new Date().toISOString();
  const hash = process.env.WORKER_HASH || 'unknown';
  const runUrl = process.env.GITHUB_RUN_URL;

  const badgeData: BadgeData = {
    passed,
    timestamp,
    hash,
    runUrl,
  };

  // Generate badge SVG
  const svg = generateBadge(badgeData);
  const metadata = generateBadgeMetadata(badgeData);

  // Write to files
  const outputDir = process.env.OUTPUT_DIR || './verifier';
  writeFileSync(join(outputDir, 'verification-badge.svg'), svg);
  writeFileSync(join(outputDir, 'verification-badge.json'), metadata);

  console.log('✅ Badge generated successfully!');
  console.log(`   Status: ${badgeData.passed ? 'VERIFIED ✅' : 'FAILED ❌'}`);
  console.log(`   Timestamp: ${badgeData.timestamp}`);
  console.log(`   Hash: ${badgeData.hash.substring(0, 8)}`);
  console.log(`   SVG: ${join(outputDir, 'verification-badge.svg')}`);
  console.log(`   Metadata: ${join(outputDir, 'verification-badge.json')}`);
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
