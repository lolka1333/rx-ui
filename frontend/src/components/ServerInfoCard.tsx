import { useState } from 'react';
import { Typography, Button, Tooltip, theme } from 'antd';
import { EyeOutlined, EyeInvisibleOutlined, GlobalOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

interface Props {
  ipv4: string | null;
  ipv6: string | null;
}

/**
 * Compact server-identity strip — sits above the gauges. No Card frame
 * because that doubled-up the surrounding modal chrome; this is just a
 * thin horizontal row with the two IPs and a visibility toggle.
 *
 * The reveal toggle is intentionally local state (not persisted): every
 * page load starts hidden so the user can't accidentally leave the
 * address exposed on a shared screen or in a screenshot.
 */
export function ServerInfoCard({ ipv4, ipv6 }: Props) {
  const { t } = useTranslation();
  const { token } = theme.useToken();
  const [ipVisible, setIpVisible] = useState(false);

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        flexWrap: 'wrap',
        // Small gap between the IP group and the toggle. Bigger gap
        // *between* IPv4 and IPv6 lives in the inner row.
        gap: 8,
        padding: '8px 4px',
        marginBottom: 16,
        color: token.colorTextSecondary,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 18,
        }}
      >
        <IpItem
          label={t('server.ipv4')}
          value={ipv4}
          visible={ipVisible}
          // Match the max width of a v4 address (`255.255.255.255`, 15 ch)
          // so toggling visibility doesn't shift the layout sideways.
          mask="***.***.***.***"
          minCh={15}
          token={token}
          notAvailable={t('server.notAvailable')}
        />
        <IpItem
          label={t('server.ipv6')}
          value={ipv6}
          visible={ipVisible}
          // Short compressed v6 placeholder. `N/A` cases also fit in this slot.
          mask="****:****:****:****"
          minCh={19}
          token={token}
          notAvailable={t('server.notAvailable')}
        />
      </div>
      <Tooltip title={t('server.toggleTooltip')}>
        <Button
          type="text"
          size="small"
          icon={ipVisible ? <EyeOutlined /> : <EyeInvisibleOutlined />}
          onClick={() => setIpVisible((v) => !v)}
          aria-label={t('server.toggleTooltip')}
          style={{ color: token.colorTextTertiary }}
        />
      </Tooltip>
    </div>
  );
}

function IpItem({
  label,
  value,
  visible,
  mask,
  minCh,
  token,
  notAvailable,
}: {
  label: string;
  value: string | null;
  visible: boolean;
  mask: string;
  /** Reserve this much width (in `ch`) so the row doesn't reflow when the
   *  IP toggles between real value and mask. */
  minCh: number;
  token: { colorTextSecondary: string; colorTextTertiary: string };
  notAvailable: string;
}) {
  const display = value === null ? notAvailable : visible ? value : mask;
  const muted = value === null;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        minHeight: 24,
      }}
    >
      <GlobalOutlined style={{ color: token.colorTextTertiary, fontSize: 14 }} />
      <Typography.Text
        type="secondary"
        style={{ fontSize: 12, color: token.colorTextTertiary, marginRight: 2 }}
      >
        {label}
      </Typography.Text>
      <span
        key={display}
        className="app-ip-reveal"
        style={{
          display: 'inline-block',
          // Reserve a stable slot only when there's an actual IP to toggle
          // between real/mask. When the value is missing (N/A) we let the
          // span shrink so the toggle button can sit flush with the text.
          minWidth: value === null ? undefined : `${minCh}ch`,
          // A full uncompressed IPv6 is 39 chars — wider than a 375px
          // phone viewport. Cap to the container and break on any character
          // so it wraps to a second line instead of forcing horizontal scroll.
          maxWidth: '100%',
          overflowWrap: 'anywhere',
          fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
          fontSize: 13,
          fontVariantNumeric: 'tabular-nums',
          color: muted ? token.colorTextTertiary : token.colorTextSecondary,
          letterSpacing: 0,
        }}
      >
        {display}
      </span>
    </span>
  );
}
