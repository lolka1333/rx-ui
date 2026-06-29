//! Client-side unique id generation. Exists solely to work around
//! `crypto.randomUUID` being unavailable outside secure contexts.

/**
 * RFC 4122 v4 UUID that works everywhere the panel runs.
 *
 * `crypto.randomUUID` is gated to *secure contexts* (HTTPS or localhost).
 * The panel is routinely opened over plain `http://<ip>:<port>`, where the
 * method is simply `undefined` — calling it throws `crypto.randomUUID is
 * not a function`. `crypto.getRandomValues`, by contrast, carries no such
 * gate, so when the native generator is missing we assemble the UUID from
 * 16 random bytes by hand (set the version/variant bits per the spec).
 *
 * These ids only have to be unique within a single config payload, so the
 * fallback's quality is academic — but it's a proper CSPRNG-backed v4 all
 * the same.
 */
export function uuid(): string {
  const c = globalThis.crypto;
  if (typeof c?.randomUUID === 'function') return c.randomUUID();

  const b = new Uint8Array(16);
  c.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0'));
  return (
    `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-` +
    `${hex[6]}${hex[7]}-${hex[8]}${hex[9]}-` +
    `${hex[10]}${hex[11]}${hex[12]}${hex[13]}${hex[14]}${hex[15]}`
  );
}
