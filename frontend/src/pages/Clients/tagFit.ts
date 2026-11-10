/** How many of a row of chips fit in `avail` pixels, keeping room for the
 *  "+N" chip whenever some are left out. Always at least one when there is any
 *  chip at all: a row that shows nothing but "+3" tells the operator less than
 *  one clipped name does.
 *
 *  `widths` are the chips in display order, `more` the width of the "+N" chip,
 *  `gap` the space between any two chips. */
export function fitCount(widths: number[], more: number, gap: number, avail: number): number {
  const n = widths.length;
  if (n === 0) return 0;
  const span = (k: number) => widths.slice(0, k).reduce((sum, w) => sum + w, 0) + gap * (k - 1);
  let k = n;
  while (k > 1 && span(k) + (k < n ? gap + more : 0) > avail) k -= 1;
  return k;
}
