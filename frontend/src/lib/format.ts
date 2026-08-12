//! Shared formatters. Kept tiny — anything beyond byte/duration
//! pretty-printing belongs next to its consumer, not here.

/**
 * Compact human-readable byte count. SI-1024 prefixes, English unit names,
 * one decimal place above the byte threshold. Used for cumulative totals
 * (B/KB/MB/GB) AND live rates (callers append `"/s"`).
 *
 * `compact` drops the decimal from 10 upwards — the dashboard gauges sit in a
 * narrow fixed column where "15.0 GB / 32.0 GB" wraps and "15 GB / 32 GB"
 * does not. It is the only difference between the two call styles, which is
 * why they are one function.
 */
export function fmtBytes(n: number, { compact = false } = {}): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(compact && v >= 10 ? 0 : 1)} ${units[i]}`;
}
