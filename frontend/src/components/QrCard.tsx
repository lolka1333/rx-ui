//! Themed QR-code card. Wraps `react-qr-code` with the project's
//! padding / border / theme-aware colours so every QR (per-client
//! share-link, subscription URL, subscription-landing) has one source
//! of truth. Modules stay dark on a slate-50 bg in every theme:
//! inverted (light-on-dark) QR codes scan reliably in iOS Camera but
//! break in several VPN-client readers (older v2rayN, NekoBox,
//! ShadowRocket). `slate-50` instead of pure white softens the punch
//! against a dark panel without losing scanner compatibility.
//!
//! Scannability is decided by the size of ONE MODULE in device pixels, not by
//! how big the picture is. A share-link near the format's 2953-byte ceiling
//! needs QR version 40 — 177×177 modules — so at the old fixed 288px each
//! module was 1.63px, right at the edge of what a phone camera can resolve,
//! and 288/177 being fractional put every module edge on a sub-pixel boundary
//! for the renderer to blur. Two things follow, and this file does both:
//! snap the rendered size to a whole number of pixels per module, and let the
//! operator open the code large enough that a dense one is comfortable.

import { QRCode } from 'react-qr-code';
import qrcode from 'qrcode-generator';
import { Modal, theme } from 'antd';
import { useCallback, useMemo, useState, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';

/** Dark modules / light bg, theme-INSENSITIVE. See file header for why. */
const QR_BG = '#f1f5f9';
const QR_FG = '#0f172a';

/** The format mandates 4 empty modules on every side; scanners use that band
 *  to find the symbol at all. `react-qr-code` draws the symbol alone — its
 *  viewBox IS the module count — so the quiet zone has to come from here.
 *  Expressed in modules, not pixels, so it scales with the code. */
const QUIET_ZONE_MODULES = 4;

/** Pixels per module the enlarged view aims for. Three is the comfortable
 *  floor for a phone camera pointed at a screen; four is roomy. */
const ZOOM_PX_PER_MODULE = 4;

/** Track the viewport so the card and the zoom both survive a rotation or a
 *  window resize. `useSyncExternalStore` rather than an effect: the value is
 *  read during render, and seeding it through state would mean a first paint at
 *  the wrong size followed by a correction. */
function useViewport(): { w: number; h: number } {
  // The snapshot is a STRING because `getSnapshot` must return a stable value
  // between renders — a fresh `{w, h}` object each call is exactly the
  // "getSnapshot should be cached" infinite loop React warns about.
  const snapshot = useSyncExternalStore(
    (onChange) => {
      window.addEventListener('resize', onChange);
      window.addEventListener('orientationchange', onChange);
      return () => {
        window.removeEventListener('resize', onChange);
        window.removeEventListener('orientationchange', onChange);
      };
    },
    () => `${window.innerWidth}x${window.innerHeight}`,
    // Server / pre-hydration: report nothing and let callers fall back to the
    // size they asked for.
    () => '0x0',
  );
  return useMemo(() => {
    const [w, h] = snapshot.split('x').map(Number);
    return { w, h };
  }, [snapshot]);
}

interface QrCardProps {
  value: string;
  size?: number;
  /** QR error-correction level. `L` (7 %) is enough for clean URLs and
   *  packs more data into fewer modules; bump to `M` (15 %) when the
   *  payload is short and the scan environment might be noisy. */
  level?: 'L' | 'M' | 'Q' | 'H';
  /** Click to open the code at `ZOOM_PX_PER_MODULE`. On by default — a code
   *  that is already crisp at card size loses nothing by being openable. */
  zoomable?: boolean;
}

/** How many modules a side of this code has. Computed with the very encoder
 *  `react-qr-code` uses internally (it is that package's own dependency), so
 *  the number cannot disagree with what gets drawn — and it is known during
 *  render, which is what lets the size be snapped on the first paint instead
 *  of after a measure-and-correct flash.
 *
 *  Returns null for a payload past the format's ceiling: the encoder throws
 *  there, and callers already gate on length, but a component that renders a
 *  QR must not be the thing that takes the page down. */
function useModuleCount(value: string, level: 'L' | 'M' | 'Q' | 'H'): number | null {
  return useMemo(() => {
    try {
      const qr = qrcode(0, level);
      qr.addData(value);
      qr.make();
      return qr.getModuleCount();
    } catch {
      return null;
    }
  }, [value, level]);
}

/** The largest whole-pixel-per-module size that still fits `budget`.
 *
 *  Rounds DOWN on purpose: rounding to the nearest multiple would sometimes
 *  overflow the card, and this component no longer carries `maxWidth: 100%`
 *  to rescue it — that rescue is precisely what reintroduces the fractional
 *  module widths this snapping exists to remove. So the budget is a ceiling,
 *  and a dense code simply draws smaller and CRISP rather than bigger and
 *  blurred. It is a preview either way; the zoom view is what gets scanned.
 *
 *  Returns `budget` when the payload has no valid code — nothing is drawn
 *  then anyway. */
function snap(budget: number, modules: number | null): number {
  if (!modules) return budget;
  const perModule = Math.max(1, Math.floor(budget / modules));
  return perModule * modules;
}

export function QrCard({ value, size = 224, level = 'M', zoomable = true }: QrCardProps) {
  const { token } = theme.useToken();
  const { t } = useTranslation();
  const [zoomed, setZoomed] = useState(false);
  const modules = useModuleCount(value, level);
  const vp = useViewport();

  // The requested size is a WISH, not a promise: this card lives in a modal
  // that is ~311px wide on a 375px phone, and the snapped SVG no longer carries
  // `maxWidth: 100%` to rescue an overflow (that rescue is what reintroduced
  // the fractional module widths). So cap the budget by what the viewport can
  // actually hold, quiet zone and card padding included.
  const budget = vp.w > 0 ? Math.min(size, vp.w - 96) : size;
  const drawn = snap(Math.max(64, budget), modules);
  // Four modules is the spec's minimum, but on a version-40 code drawn at one
  // pixel per module that is a 4px band — correct and visually cramped. The
  // floor keeps the card looking like the rest of the panel without ever going
  // under what a scanner needs.
  const quiet = modules ? Math.max(12, (drawn / modules) * QUIET_ZONE_MODULES) : 16;

  const open = useCallback(() => setZoomed(true), []);

  return (
    <>
      <div
        role={zoomable ? 'button' : undefined}
        tabIndex={zoomable ? 0 : undefined}
        aria-label={zoomable ? t('clients.qrEnlarge') : undefined}
        onClick={zoomable ? open : undefined}
        onKeyDown={
          zoomable
            ? (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  open();
                }
              }
            : undefined
        }
        style={{
          display: 'flex',
          justifyContent: 'center',
          // The quiet zone IS the padding — sized in modules so it stays
          // correct whether the code is version 6 or version 40.
          padding: quiet,
          background: QR_BG,
          border: `1px solid ${token.colorBorder}`,
          borderRadius: 8,
          cursor: zoomable ? 'zoom-in' : undefined,
        }}
      >
        <QRCode
          value={value}
          size={drawn}
          level={level}
          bgColor={QR_BG}
          fgColor={QR_FG}
          // No `maxWidth: 100%`: scaling the SVG to a fractional width is
          // exactly what blurs the module edges. The snapped size is the size.
          style={{ display: 'block', shapeRendering: 'crispEdges' }}
        />
      </div>

      {zoomable && (
        <Modal
          open={zoomed}
          onCancel={() => setZoomed(false)}
          footer={null}
          centered
          width="auto"
          styles={{ body: { display: 'flex', justifyContent: 'center' } }}
        >
          <ZoomedQr value={value} level={level} modules={modules} vp={vp} />
        </Modal>
      )}
    </>
  );
}

/** The enlarged code: as many whole pixels per module as the viewport allows,
 *  capped at `ZOOM_PX_PER_MODULE` so a short link doesn't become a poster. */
function ZoomedQr({
  value,
  level,
  modules,
  vp,
}: {
  value: string;
  level: 'L' | 'M' | 'Q' | 'H';
  modules: number | null;
  vp: { w: number; h: number };
}) {
  // Width, not the smaller side: a phone in portrait has plenty of height and
  // it is the width that binds. Taking `min(w, h)` made the "enlarged" code
  // SMALLER than the card it opened from on a 375x812 screen.
  const budget = Math.max(160, vp.w - 64);
  const perModule = modules
    ? Math.max(
        1,
        Math.min(ZOOM_PX_PER_MODULE, Math.floor(budget / (modules + QUIET_ZONE_MODULES * 2))),
      )
    : 0;
  const drawn = modules ? perModule * modules : budget;
  const quiet = perModule ? perModule * QUIET_ZONE_MODULES : 16;

  return (
    <div style={{ padding: quiet, background: QR_BG, borderRadius: 8 }}>
      <QRCode
        value={value}
        size={drawn}
        level={level}
        bgColor={QR_BG}
        fgColor={QR_FG}
        style={{ display: 'block', shapeRendering: 'crispEdges' }}
      />
    </div>
  );
}
