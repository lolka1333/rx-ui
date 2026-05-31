//! Themed QR-code card. Wraps `react-qr-code` with the project's
//! padding / border / theme-aware colours so every QR (per-client
//! share-link, subscription URL, subscription-landing) has one source
//! of truth. Modules stay dark on a slate-50 bg in every theme:
//! inverted (light-on-dark) QR codes scan reliably in iOS Camera but
//! break in several VPN-client readers (older v2rayN, NekoBox,
//! ShadowRocket). `slate-50` instead of pure white softens the punch
//! against a dark panel without losing scanner compatibility.

import { QRCode } from 'react-qr-code';
import { theme } from 'antd';

/** Dark modules / light bg, theme-INSENSITIVE. See file header for why. */
export const QR_BG = '#f1f5f9';
export const QR_FG = '#0f172a';

interface QrCardProps {
  value: string;
  size?: number;
  /** QR error-correction level. `L` (7 %) is enough for clean URLs and
   *  packs more data into fewer modules; bump to `M` (15 %) when the
   *  payload is short and the scan environment might be noisy. */
  level?: 'L' | 'M' | 'Q' | 'H';
  /** Override container padding. Defaults to 16 — gives the camera a
   *  quiet zone wider than the spec-required 4 modules. */
  padding?: number;
}

export function QrCard({ value, size = 224, level = 'M', padding = 16 }: QrCardProps) {
  const { token } = theme.useToken();
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        padding,
        background: QR_BG,
        border: `1px solid ${token.colorBorder}`,
        borderRadius: 8,
      }}
    >
      <QRCode
        value={value}
        size={size}
        level={level}
        bgColor={QR_BG}
        fgColor={QR_FG}
        style={{ maxWidth: '100%', height: 'auto' }}
      />
    </div>
  );
}
