import { qrcodegen } from './qrcodegen';

/**
 * Render `text` as a QR code and return a self-contained SVG string.
 *
 * Used to show an in-person-scannable QR of the Connect invite link inside the
 * enclave iframe — the link carries the room secret, so (like the rest of the
 * ceremony) it must be encoded enclave-side and never handed to the PWA. MEDIUM
 * error correction (~15%) balances density against resilience for a
 * screen-to-camera scan.
 *
 * `border` is the quiet-zone width in modules (the QR spec requires >= 4). The
 * output is dependency-free and interpolates NO untrusted text into markup — only
 * numeric rectangles derived from the boolean module grid — so it is injection-safe
 * to assign via innerHTML in the enclave's own DOM.
 */
export function qrSvg(text: string, border = 4): string {
  const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
  const dim = qr.size + border * 2;

  const parts: string[] = [];
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.getModule(x, y)) {
        parts.push(`M${x + border},${y + border}h1v1h-1z`);
      }
    }
  }

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" `,
    `shape-rendering="crispEdges" role="img" aria-label="QR code for the connect link">`,
    `<rect width="100%" height="100%" fill="#ffffff"/>`,
    `<path d="${parts.join('')}" fill="#000000"/>`,
    `</svg>`,
  ].join('');
}
