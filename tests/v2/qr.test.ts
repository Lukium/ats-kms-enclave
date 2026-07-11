import { describe, it, expect } from 'vitest';
import { qrSvg } from '../../src/v2/qr';

/** Parse the square viewBox dimension (modules + quiet zone) out of the SVG. */
function viewBoxDim(svg: string): number {
  const m = svg.match(/viewBox="0 0 (\d+) (\d+)"/);
  if (!m) throw new Error('no viewBox in SVG');
  expect(m[1]).toBe(m[2]); // square
  return Number(m[1]);
}

describe('qrSvg', () => {
  it('produces a self-contained square SVG with a module path', () => {
    const svg = qrSvg('HELLO WORLD');
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
    expect(svg).toContain('<rect width="100%" height="100%" fill="#ffffff"/>');
    expect(svg).toMatch(/<path d="M/); // at least one dark module
    expect(svg).toContain('fill="#000000"');
    expect(svg.endsWith('</svg>')).toBe(true);
  });

  it('sizes the viewBox to QR modules + the default quiet zone (border 4)', () => {
    const dim = viewBoxDim(qrSvg('AB'));
    // QR symbol sizes are 21, 25, 29, ... = 17 + 4*version, so size % 4 == 1.
    // The default border adds 4 modules on each side (dim = size + 8).
    expect(dim).toBeGreaterThanOrEqual(21 + 8);
    expect((dim - 8) % 4).toBe(1);
  });

  it('honors a custom border (quiet zone) width', () => {
    const a = viewBoxDim(qrSvg('same-payload', 4));
    const b = viewBoxDim(qrSvg('same-payload', 8));
    expect(b - a).toBe(8); // +4 modules on each side
  });

  it('is deterministic for a given input', () => {
    expect(qrSvg('ats-connect')).toBe(qrSvg('ats-connect'));
  });

  it('encodes a full-length Connect invite URL and grows with payload size', () => {
    const blob = 'A'.repeat(220); // stands in for the base64url invite blob
    const url = `https://kms.ats.run/connect#c=${blob}`;
    const svg = qrSvg(url);
    expect(svg.startsWith('<svg')).toBe(true);
    expect(viewBoxDim(svg)).toBeGreaterThan(viewBoxDim(qrSvg('AB')));
  });

  it('does not interpolate the payload text into the markup (injection-safe)', () => {
    const svg = qrSvg('https://kms.ats.run/connect#c=<script>&"quote"');
    expect(svg).not.toContain('<script>');
    expect(svg).not.toContain('&"quote"');
  });
});
