/**
 * How wide the page content is allowed to run.
 *
 * The panel used to pin the content at 1400px with no auto margins, so on a
 * wide monitor the whole interface sat against the left edge with ~950px of
 * empty background beside it — the "scaling problem" operators report. The cap
 * itself is worth keeping: a settings row stretched across 2500px puts a
 * screen's width between a label and its control. So the cap stays, the
 * content is centred, and the operator picks how far it may grow — the same
 * shape the theme and the locale already use (zustand + persist).
 *
 * `full` is a deliberate escape hatch rather than the default: tables win from
 * it, forms do not.
 */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type LayoutWidth = 'normal' | 'wide' | 'full';

/** CSS `max-width` per choice; `undefined` means no cap at all. */
export const LAYOUT_MAX_WIDTH: Record<LayoutWidth, number | undefined> = {
  normal: 1400,
  wide: 1760,
  full: undefined,
};

interface LayoutWidthState {
  width: LayoutWidth;
  set: (width: LayoutWidth) => void;
}

export const useLayoutWidth = create<LayoutWidthState>()(
  persist(
    (set) => ({
      // `wide` by default, not `normal`: at 1920 the old 1400 cap left a strip
      // of empty background down both sides of a maximised window, and the
      // operator had to find a setting to get their own screen back. 1760 fills
      // a 1080p window outright and still stops a settings row from running the
      // width of an ultrawide.
      width: 'wide',
      set: (width) => set({ width }),
    }),
    { name: 'app-layout-width' },
  ),
);
