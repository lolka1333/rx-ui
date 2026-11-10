/** Traffic-limit units for the client form: the form edits a number and a
 *  unit, the API stores bytes. */


export type TrafficUnit = 'MB' | 'GB' | 'TB';

const TRAFFIC_UNIT_BYTES: Record<TrafficUnit, number> = {
  MB: 1024 ** 2,
  GB: 1024 ** 3,
  TB: 1024 ** 4,
};

/**
 * Pick the largest unit where the byte count divides cleanly, falling
 * back to MB with a fractional value when nothing fits. `null` / 0
 * ≡ "no quota" and renders as an empty input under the GB default —
 * matches the most common operator default ("set 50 GB").
 */
export function bytesToTrafficForm(
  bytes: number | null | undefined,
): { value: number | null; unit: TrafficUnit } {
  if (bytes == null || bytes <= 0) return { value: null, unit: 'GB' };
  for (const unit of ['TB', 'GB', 'MB'] as const) {
    const div = TRAFFIC_UNIT_BYTES[unit];
    if (bytes >= div && bytes % div === 0) {
      return { value: bytes / div, unit };
    }
  }
  return { value: bytes / TRAFFIC_UNIT_BYTES.MB, unit: 'MB' };
}

export function trafficFormToBytes(value: number | null, unit: TrafficUnit): number | null {
  if (value == null || value <= 0) return null;
  return Math.round(value * TRAFFIC_UNIT_BYTES[unit]);
}
