//! Shared formatters. Kept tiny — anything beyond byte/duration
//! pretty-printing belongs next to its consumer, not here.

/**
 * Compact human-readable byte count. SI-1024 prefixes, English unit
 * names, one decimal place above the byte threshold. Used for cumulative
 * totals (B/KB/MB/GB) AND live rates (callers append `"/s"`).
 *
 * Dashboard.tsx keeps its own Cyrillic-units variant deliberately —
 * its gauges follow a different precision rule (no decimal at ≥10) and
 * are aimed at the operator UI; merging would force parameter sprawl
 * that isn't worth the dedupe.
 */
export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}
