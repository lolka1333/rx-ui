/** A PEM block header, e.g. `-----BEGIN CERTIFICATE-----`.
 *
 *  No digits in the character class, deliberately: every header this panel
 *  accepts (`CERTIFICATE`, `PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`,
 *  `ENCRYPTED PRIVATE KEY`) is letters and spaces. Allowing digits would let
 *  `-----BEGIN SSH2 PUBLIC KEY-----` through, which is the exact wrong paste
 *  this check exists to catch. */
const PEM_HEADER_RE = /-----BEGIN [A-Z ]+-----/;

/** antd validator: accept empty (the `required` check is separate) or any
 *  PEM-shaped blob. Loose on the header word, strict on the shape. */
export function pemRule(message: string) {
  return {
    validator: (_: unknown, v: string) =>
      !v || PEM_HEADER_RE.test(v) ? Promise.resolve() : Promise.reject(new Error(message)),
  };
}
