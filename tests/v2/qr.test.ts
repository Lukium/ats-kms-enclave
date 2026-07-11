import { describe, it, expect } from 'vitest';
import { qrSvg, decodeQr } from '../../src/v2/qr';
import { qrcodegen } from '../../src/v2/qrcodegen';

/**
 * Render a QR of `text` to an RGBA pixel buffer (white background, black modules,
 * `scale` px per module, `border`-module quiet zone) — a synthetic "camera frame"
 * for exercising decodeQr without a camera.
 */
function renderQrToImageData(
  text: string,
  scale = 8,
  border = 4
): { data: Uint8ClampedArray; width: number; height: number } {
  const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
  const dim = (qr.size + border * 2) * scale;
  const data = new Uint8ClampedArray(dim * dim * 4).fill(255); // opaque white
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (!qr.getModule(x, y)) continue;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const px = ((y + border) * scale + dy) * dim + ((x + border) * scale + dx);
          const i = px * 4;
          data[i] = 0;
          data[i + 1] = 0;
          data[i + 2] = 0;
          // alpha stays 255
        }
      }
    }
  }
  return { data, width: dim, height: dim };
}

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

describe('decodeQr', () => {
  it('round-trips an encoded QR back to its text (encode -> render -> decode)', () => {
    const text = 'https://kms.ats.run/connect#c=' + 'A'.repeat(40);
    const { data, width, height } = renderQrToImageData(text);
    expect(decodeQr(data, width, height)).toBe(text);
  });

  it('returns null for a blank (all-white) frame', () => {
    const width = 64;
    const height = 64;
    const data = new Uint8ClampedArray(width * height * 4).fill(255);
    expect(decodeQr(data, width, height)).toBeNull();
  });
});
