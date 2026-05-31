/**
 * Public landing page for `/sub/{token}` — what an end user sees if
 * they paste the subscription URL into a browser instead of importing
 * it from a VPN client. No auth, no sidebar — this page lives outside
 * the admin shell.
 *
 * Layout mirrors remna-style reseller pages: brand bar at top, a user
 * info card (avatar + 2×2 typed-pill grid for name / status / expires
 * / traffic), then an installation card that combines a platform
 * dropdown, a chip-row of clients for that platform, and a vertical
 * stack of per-app step blocks (Install → Add subscription → Manual
 * fallback → Connect). A subtle dot-grid CSS background keeps the
 * otherwise flat dark canvas from looking like a debug screen.
 *
 * Data flow: the same `/sub/{token}` endpoint exposes a JSON-array
 * format when the caller passes `?format=json`. We pull that once,
 * also reading the `Subscription-Userinfo` header for traffic stats
 * so the page doesn't need a dedicated panel API. AbortController
 * cancels the in-flight request if the user navigates away (or
 * React 18 StrictMode double-mounts the effect in dev).
 *
 * Page is intentionally Russian-only — localisation is a separate
 * task.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { LOCALES, type Locale } from '@/i18n';
import { useLocale } from '@/stores/locale';
import {
  AppleOutlined,
  AndroidOutlined,
  CheckCircleFilled,
  CheckOutlined,
  CloudDownloadOutlined,
  CopyOutlined,
  DesktopOutlined,
  DownloadOutlined,
  ExportOutlined,
  GlobalOutlined,
  PlusOutlined,
  QrcodeOutlined,
  SettingOutlined,
  WindowsOutlined,
} from '@ant-design/icons';
import {
  Alert,
  App,
  Button,
  Modal,
  Progress,
  Select,
  Typography,
  theme,
} from 'antd';
import {
  HiddifyIcon,
  NekoBoxIcon,
  ShadowrocketIcon,
  StreisandIcon,
  V2BoxIcon,
  V2rayNGIcon,
  V2rayNIcon,
} from '@/components/AppIcons';
import { QrCard } from '@/components/QrCard';
import { fmtBytes } from '@/lib/format';

interface SubscriptionData {
  links: string[];
  upload: number;
  download: number;
  total: number;
  /** Operator-configured service name from `x-sub-brand` response
   *  header (panel setting `sub_brand_name`). Empty string ≡ no
   *  override — the landing falls back to a generic heading. The
   *  header value is percent-encoded on the wire so non-ASCII
   *  (Cyrillic) names round-trip through HeaderValue. */
  brand: string;
  /** Per-subscription identity from `x-sub-email`. The backend stores
   *  this as the client's email column; we display it as the human-
   *  readable handle in the user card. Same percent-encoding as
   *  `brand`. */
  email: string;
  /** Operator's main-service URL from `x-sub-service`. Empty ≡ the
   *  "Открыть сервис" header button is hidden. Validated http(s)-only
   *  on the backend before storage so it's safe to embed in `<a href>`
   *  here without additional sanitisation. */
  serviceUrl: string;
}

async function fetchSubscription(
  token: string,
  signal: AbortSignal,
): Promise<SubscriptionData> {
  const res = await fetch(`/sub/${token}?format=json`, {
    headers: { Accept: 'application/json' },
    signal,
  });
  if (!res.ok) throw new Error(`subscription fetch failed: ${res.status}`);
  const links: string[] = await res.json();
  const userinfo = res.headers.get('subscription-userinfo') ?? '';
  const brand = decodePctHeader(res.headers.get('x-sub-brand'));
  const email = decodePctHeader(res.headers.get('x-sub-email'));
  const serviceUrl = decodePctHeader(res.headers.get('x-sub-service'));
  return { links, ...parseUserinfo(userinfo), brand, email, serviceUrl };
}

/** Decode the percent-encoded subscription metadata headers
 *  (`x-sub-brand`, `x-sub-email`). The backend encodes them so
 *  non-ASCII chars round-trip through HeaderValue; we restore the
 *  original here, falling back to the raw header on decode error so
 *  a malformed value still surfaces as text. */
function decodePctHeader(raw: string | null): string {
  if (!raw) return '';
  try { return decodeURIComponent(raw); }
  catch { return raw; }
}

function parseUserinfo(s: string): { upload: number; download: number; total: number } {
  const kv = new Map<string, number>();
  for (const part of s.split(';')) {
    const [k, v] = part.trim().split('=');
    if (k && v) kv.set(k.trim(), Number(v.trim()));
  }
  return {
    upload: kv.get('upload') ?? 0,
    download: kv.get('download') ?? 0,
    total: kv.get('total') ?? 0,
  };
}

/** Deeplink helpers — collected here so the platform tabs stay
 *  declarative. v2rayN (Windows) and v2rayNG (Android) have no
 *  reliable URL scheme so they fall through to the copy-and-paste
 *  path; everything else uses its native scheme. */
const b64url = (s: string) =>
  btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function deeplinks(subUrl: string, name: string) {
  const enc = encodeURIComponent(subUrl);
  const encName = encodeURIComponent(name);
  const b64 = b64url(subUrl);
  return {
    v2box: `v2box://install-sub?url=${b64}&name=${encName}`,
    streisand: `streisand://import/${enc}`,
    hiddify: `hiddify://install-config?url=${enc}&name=${encName}`,
    shadowrocket: `sub://${b64}`,
    nekobox: `sn-sub://${b64}`,
  };
}

interface ClientApp {
  /** Stable key used as React identity and as the `Select.value`. */
  key: string;
  name: string;
  /** `null` ≡ no documented URL-scheme handler — the "Add subscription"
   *  step falls back to a "Copy URL + manual import" flow with the
   *  manualImport copy as the instruction. */
  deeplink: string | null;
  /** Where to download the app on this platform. Either a store link
   *  or a GitHub releases page. */
  storeUrl: string;
  storeLabel: string;
  /** Free-text instructions the operator should follow after pressing
   *  the deeplink (or after copying the URL, for no-deeplink apps). */
  manualImport: string;
  /** Free-text "how to actually connect" — common across apps but
   *  worded per-platform when phrasing differs. */
  connectHint: string;
  icon: ReactNode;
}

interface Platform {
  key: string;
  label: string;
  icon: ReactNode;
  apps: ClientApp[];
}

type TFn = (key: string) => string;

function buildPlatforms(t: TFn, links: ReturnType<typeof deeplinks>): Platform[] {
  return [
    {
      key: 'ios',
      label: t('sub.platformIos'),
      icon: <AppleOutlined />,
      apps: [
        {
          key: 'v2box-ios',
          name: 'V2Box',
          deeplink: links.v2box,
          storeUrl: 'https://apps.apple.com/app/v2box-v2ray-client/id6446814690',
          storeLabel: 'App Store',
          icon: <V2BoxIcon />,
          manualImport: t('sub.v2box_iosManual'),
          connectHint: t('sub.v2box_iosConnect'),
        },
        {
          key: 'streisand-ios',
          name: 'Streisand',
          deeplink: links.streisand,
          storeUrl: 'https://apps.apple.com/app/streisand/id6450534064',
          storeLabel: 'App Store',
          icon: <StreisandIcon />,
          manualImport: t('sub.streisandManual'),
          connectHint: t('sub.streisandConnect'),
        },
        {
          key: 'shadowrocket-ios',
          name: 'Shadowrocket',
          deeplink: links.shadowrocket,
          storeUrl: 'https://apps.apple.com/app/shadowrocket/id932747118',
          storeLabel: 'App Store',
          icon: <ShadowrocketIcon />,
          manualImport: t('sub.shadowrocketManual'),
          connectHint: t('sub.shadowrocketConnect'),
        },
      ],
    },
    {
      key: 'android',
      label: t('sub.platformAndroid'),
      icon: <AndroidOutlined />,
      apps: [
        {
          key: 'v2rayng',
          name: 'v2rayNG',
          deeplink: null,
          storeUrl: 'https://play.google.com/store/apps/details?id=com.v2ray.ang',
          storeLabel: 'Google Play',
          icon: <V2rayNGIcon />,
          manualImport: t('sub.v2rayngManual'),
          connectHint: t('sub.v2rayngConnect'),
        },
        {
          key: 'nekobox',
          name: 'NekoBox',
          deeplink: links.nekobox,
          storeUrl: 'https://github.com/MatsuriDayo/NekoBoxForAndroid/releases',
          storeLabel: 'GitHub Releases',
          icon: <NekoBoxIcon />,
          manualImport: t('sub.nekoboxManual'),
          connectHint: t('sub.nekoboxConnect'),
        },
        {
          key: 'hiddify-android',
          name: 'Hiddify',
          deeplink: links.hiddify,
          storeUrl: 'https://play.google.com/store/apps/details?id=app.hiddify.com',
          storeLabel: 'Google Play',
          icon: <HiddifyIcon />,
          manualImport: t('sub.hiddifyAndroidManual'),
          connectHint: t('sub.hiddifyAndroidConnect'),
        },
      ],
    },
    {
      key: 'windows',
      label: t('sub.platformWindows'),
      icon: <WindowsOutlined />,
      apps: [
        {
          key: 'v2rayn',
          name: 'v2rayN',
          deeplink: null,
          storeUrl: 'https://github.com/2dust/v2rayN/releases',
          storeLabel: 'GitHub Releases',
          icon: <V2rayNIcon />,
          manualImport: t('sub.v2raynManual'),
          connectHint: t('sub.v2raynConnect'),
        },
        {
          key: 'hiddify-windows',
          name: 'Hiddify',
          deeplink: links.hiddify,
          storeUrl: 'https://hiddify.com/',
          storeLabel: 'hiddify.com',
          icon: <HiddifyIcon />,
          manualImport: t('sub.hiddifyWindowsManual'),
          connectHint: t('sub.hiddifyWindowsConnect'),
        },
      ],
    },
    {
      key: 'macos',
      label: t('sub.platformMacos'),
      icon: <DesktopOutlined />,
      apps: [
        {
          key: 'v2box-mac',
          name: 'V2Box',
          deeplink: links.v2box,
          storeUrl: 'https://apps.apple.com/app/v2box-v2ray-client/id6446814690',
          storeLabel: 'Mac App Store',
          icon: <V2BoxIcon />,
          manualImport: t('sub.v2box_macManual'),
          connectHint: t('sub.v2box_macConnect'),
        },
        {
          key: 'hiddify-macos',
          name: 'Hiddify',
          deeplink: links.hiddify,
          storeUrl: 'https://hiddify.com/',
          storeLabel: 'hiddify.com',
          icon: <HiddifyIcon />,
          manualImport: t('sub.hiddifyMacManual'),
          connectHint: t('sub.hiddifyMacConnect'),
        },
      ],
    },
  ];
}

/** Pre-select the right platform tab from the user-agent so a phone
 *  visitor doesn't click iOS / Android before seeing their apps. */
function guessPlatform(): string {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/i.test(ua)) return 'ios';
  if (/Android/i.test(ua)) return 'android';
  if (/Windows/i.test(ua)) return 'windows';
  if (/Mac OS X/i.test(ua)) return 'macos';
  return 'ios';
}

export function SubscriptionLanding({ token }: { token: string }) {
  const { message } = App.useApp();
  const { token: t } = theme.useToken();
  const { t: tr } = useTranslation();
  const [data, setData] = useState<SubscriptionData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [platformKey, setPlatformKey] = useState(guessPlatform);
  const [appKey, setAppKey] = useState<string | null>(null);
  const [showQr, setShowQr] = useState(false);
  // Holds the in-flight "show ✓ for 2 s" timer so a double-click on
  // Copy doesn't leave the button glitching between Готово/Копировать
  // when the first timeout fires after the second click already
  // refreshed the state.
  const copiedTimer = useRef<number | null>(null);

  const subUrl = useMemo(() => `${window.location.origin}/sub/${token}`, [token]);
  // Display name: real email if the backend exposed one, otherwise a
  // short token-prefix fallback so the user card never shows blank.
  const profileName = useMemo(
    () => data?.email || `${tr('sub.defaultBrand')} ${token.slice(0, 6)}`,
    [data?.email, token, tr],
  );
  const platforms = useMemo(
    () => buildPlatforms(tr, deeplinks(subUrl, profileName)),
    [tr, subUrl, profileName],
  );

  const platform = platforms.find((p) => p.key === platformKey) ?? platforms[0];
  const app = platform.apps.find((a) => a.key === appKey) ?? platform.apps[0];

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    fetchSubscription(token, ctrl.signal)
      .then((d) => { if (!ctrl.signal.aborted) setData(d); })
      .catch((e: Error) => {
        if (ctrl.signal.aborted) return;
        setError(e.message);
      })
      .finally(() => { if (!ctrl.signal.aborted) setLoading(false); });
    return () => ctrl.abort();
  }, [token]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(subUrl);
      setCopied(true);
      message.success(tr('sub.copyToastSuccess'));
      if (copiedTimer.current !== null) {
        clearTimeout(copiedTimer.current);
      }
      copiedTimer.current = window.setTimeout(() => {
        setCopied(false);
        copiedTimer.current = null;
      }, 2000);
    } catch {
      message.error(tr('sub.copyToastError'));
    }
  };

  // Component unmount kills any pending "reset Copy button" timer so
  // the setCopied(false) callback never fires against a stale tree.
  useEffect(
    () => () => {
      if (copiedTimer.current !== null) clearTimeout(copiedTimer.current);
    },
    [],
  );

  // Backend `static_assets::serve_index_with_title` pre-injects the
  // operator brand into `<title>` so the prod tab is correct from the
  // first paint. In dev Vite hands its own static index.html
  // ("Admin Panel") for every /sub/{token} visit, so this useEffect
  // exists for that path only. Also covers the brand-empty case where
  // we want the locale-translated default ("Подписка" / "Subscription")
  // instead of the literal "Admin Panel" placeholder.
  useEffect(() => {
    if (!data) return;
    const next = data.brand || tr('sub.defaultBrand');
    if (document.title !== next) document.title = next;
  }, [data, tr]);

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: t.colorBgLayout, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Typography.Text type="secondary">{tr('sub.loading')}</Typography.Text>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div style={{ minHeight: '100vh', background: t.colorBgLayout, padding: '40px 16px' }}>
        <div style={{ maxWidth: 720, margin: '0 auto' }}>
          <Alert
            type="error"
            showIcon
            title={tr('sub.loadError')}
            description={error ?? tr('sub.loadErrorHint')}
          />
        </div>
      </div>
    );
  }

  const used = data.upload + data.download;
  const hasLimit = data.total > 0;
  const percent = hasLimit ? pct(used, data.total) : 0;
  const isActive = data.links.length > 0 && (!hasLimit || used < data.total);
  // Quota-bar colour ramps red at hard cap, amber when approaching,
  // brand-primary otherwise. Extracted from JSX so the nested ternary
  // doesn't show up inline next to the rest of the Progress props.
  const progressStroke =
    percent >= 100 ? t.colorError : percent >= 80 ? t.colorWarning : t.colorPrimary;

  return (
    <div
      className="app-sub-landing"
      style={{
        minHeight: '100vh',
        background: t.colorBgLayout,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Soft brand-accent halos top and bottom — gives the dark canvas
          depth without falling into Remnawave's dot-grid texture. */}
      <div
        aria-hidden
        style={{
          position: 'absolute',
          top: -260,
          left: '50%',
          transform: 'translateX(-50%)',
          width: 900,
          height: 600,
          background: `radial-gradient(ellipse, ${t.colorPrimary}2e, transparent 65%)`,
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />
      <div
        aria-hidden
        style={{
          position: 'absolute',
          bottom: -200,
          right: -100,
          width: 500,
          height: 500,
          background: `radial-gradient(circle, ${t.colorPrimary}22, transparent 60%)`,
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '24px 16px 64px', position: 'relative', zIndex: 1 }}>
        {/* Header bar */}
        <header
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 24,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: t.colorPrimary }}>
            <GlobalOutlined style={{ fontSize: 22 }} />
            <Typography.Text strong style={{ fontSize: 18, color: t.colorPrimary, letterSpacing: -0.3 }}>
              {data.brand || tr('sub.defaultBrand')}
            </Typography.Text>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <Button
              size="middle"
              icon={<QrcodeOutlined />}
              onClick={() => setShowQr(true)}
              aria-label={tr('sub.showQrTooltip')}
              title={tr('sub.showQrTooltip')}
            />
            {data.serviceUrl && (
              <Button
                size="middle"
                icon={<ExportOutlined />}
                href={data.serviceUrl}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={tr('sub.openServiceTooltip')}
                title={tr('sub.openServiceTooltip')}
              />
            )}
          </div>
        </header>

        {/* Hero card — focal QR + URL + compact 3-up stat strip. Combines
            "what is this" / "how do I use it" / "how much have I used"
            into a single block so the page reads as a product page,
            not a settings dump. The QR is always visible (toggled
            visibility hid it for first-time visitors who can't yet
            guess that the icon expands it). */}
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 18 }}>
            <div
              style={{
                flexShrink: 0,
                width: 40,
                height: 40,
                borderRadius: 999,
                background: isActive ? `${t.colorSuccess}33` : `${t.colorTextTertiary}33`,
                border: `1px solid ${isActive ? `${t.colorSuccess}66` : t.colorBorder}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: isActive ? t.colorSuccess : t.colorTextTertiary,
                fontSize: 18,
              }}
            >
              <CheckCircleFilled />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <Typography.Text strong style={{ fontSize: 16, display: 'block', lineHeight: 1.2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {profileName}
              </Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {isActive ? tr('sub.statusActive') : tr('sub.statusInactive')}
                {hasLimit ? ` · ${tr('sub.percentUsed', { percent })}` : ` · ${tr('sub.noLimit')}`}
              </Typography.Text>
            </div>
          </div>
          {/* No inline QR or URL — the token IS the credential. The
              card shows identity + stats; QR lives in a modal raised
              from the header icon. */}
          {/* 3-up stat strip — monochrome primary accents, no tinted
              pill backgrounds. Three signals (count / used / limit)
              is the minimum that's actually informative without
              pretending to be a dashboard. */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: 8,
              paddingTop: 16,
              borderTop: `1px solid ${t.colorBorder}`,
            }}
          >
            <InlineStat label={tr('sub.statServers')} value={String(data.links.length)} highlight={t.colorPrimary} />
            <InlineStat label={tr('sub.statUsed')} value={fmtBytes(used)} />
            <InlineStat label={hasLimit ? tr('sub.statLimit') : tr('sub.statNoLimit')} value={hasLimit ? fmtBytes(data.total) : '∞'} />
          </div>
          {hasLimit && (
            <Progress
              percent={percent}
              showInfo={false}
              size="small"
              strokeColor={progressStroke}
              strokeLinecap="butt"
              style={{ marginTop: 12 }}
            />
          )}
        </Card>

        {/* Installation card */}
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <Typography.Title level={4} style={{ margin: 0, fontWeight: 600 }}>
              {tr('sub.installTitle')}
            </Typography.Title>
            <Select
              size="middle"
              value={platformKey}
              onChange={(v) => {
                setPlatformKey(v);
                setAppKey(null);
              }}
              style={{ width: 160 }}
              options={platforms.map((p) => ({
                value: p.key,
                label: (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    {p.icon} {p.label}
                  </span>
                ),
              }))}
            />
          </div>
          {/* App chip-row — horizontal scroll on mobile */}
          <div
            style={{
              display: 'flex',
              gap: 8,
              marginBottom: 16,
              overflowX: 'auto',
              paddingBottom: 4,
            }}
          >
            {platform.apps.map((a) => {
              const active = a.key === app.key;
              return (
                <button
                  key={a.key}
                  type="button"
                  onClick={() => setAppKey(a.key)}
                  className="app-sub-chip"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 8,
                    padding: '8px 14px',
                    background: active ? `${t.colorPrimary}1f` : t.colorBgContainer,
                    border: `1px solid ${active ? t.colorPrimary : t.colorBorder}`,
                    color: active ? t.colorPrimary : t.colorText,
                    borderRadius: 999,
                    cursor: 'pointer',
                    fontSize: 13,
                    fontWeight: active ? 600 : 500,
                    whiteSpace: 'nowrap',
                    flexShrink: 0,
                    transition: 'border-color 0.18s, background 0.18s, color 0.18s',
                  }}
                >
                  <span style={{ width: 18, height: 18, display: 'inline-flex' }}>{a.icon}</span>
                  {a.name}
                </button>
              );
            })}
          </div>

          {/* Steps for the selected app */}
          <Step
            icon={<DownloadOutlined />}
            color={t.colorPrimary}
            title={tr('sub.installAppTitle')}
            description={tr('sub.installAppDescription')}
            action={
              <Button
                href={app.storeUrl}
                target="_blank"
                rel="noopener noreferrer"
                icon={<ExportOutlined />}
                type="primary"
              >
                {app.storeLabel}
              </Button>
            }
          />
          <Step
            icon={<PlusOutlined />}
            color={t.colorPrimary}
            title={tr('sub.addSubTitle')}
            description={app.deeplink ? tr('sub.addSubViaDeeplink') : tr('sub.addSubViaCopy')}
            action={
              app.deeplink ? (
                <Button href={app.deeplink} type="primary" icon={<PlusOutlined />}>
                  {tr('sub.addSubButton')}
                </Button>
              ) : (
                <Button onClick={copy} type="primary" icon={copied ? <CheckOutlined /> : <CopyOutlined />}>
                  {copied ? tr('sub.copyLinkDone') : tr('sub.copyLinkButton')}
                </Button>
              )
            }
          />
          <Step
            icon={<SettingOutlined />}
            color={t.colorTextSecondary}
            title={tr('sub.manualFallbackTitle')}
            description={app.manualImport}
          />
          <Step
            icon={<CheckOutlined />}
            color={t.colorSuccess}
            title={tr('sub.connectTitle')}
            description={app.connectHint}
            last
          />
        </Card>

        {/* Footer */}
        <div
          style={{
            marginTop: 32,
            display: 'flex',
            justifyContent: 'center',
            gap: 24,
            flexWrap: 'wrap',
            color: t.colorTextTertiary,
            fontSize: 12,
          }}
        >
          <span>
            <CloudDownloadOutlined style={{ marginRight: 6 }} />
            {tr('sub.autoUpdate')}
          </span>
          <SubLocalePicker />
        </div>
      </div>

      {/* QR modal — raised from the header icon. Holds the QR code +
          a copy-link button. URL text intentionally absent: the token
          IS the credential and a wide readable strip invites screenshot
          leaks of the full subscription. */}
      <Modal
        open={showQr}
        onCancel={() => setShowQr(false)}
        footer={null}
        title={tr('sub.modalTitle')}
        centered
        width={360}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, alignItems: 'center', paddingTop: 8 }}>
          <QrCard value={subUrl} size={240} />
          <Typography.Text type="secondary" style={{ fontSize: 12, textAlign: 'center' }}>
            {tr('sub.modalHint')}
          </Typography.Text>
          <Button
            type="primary"
            size="middle"
            block
            icon={copied ? <CheckOutlined /> : <CopyOutlined />}
            onClick={copy}
          >
            {copied ? tr('sub.copyDone') : tr('sub.copyLinkButton')}
          </Button>
        </div>
      </Modal>
    </div>
  );
}

function pct(used: number, total: number): number {
  return Math.min(100, Math.round((used / total) * 100));
}

/** End-user language picker mounted in the page footer. Mirrors the
 *  admin-side LanguagePicker pattern: writes the persisted store key
 *  directly + reloads the page, so the user sees one clean transition
 *  rather than mid-render text-swap. The picker reuses `useLocale`
 *  state with the admin panel intentionally — same browser typically
 *  belongs to one operator across both surfaces. */
function SubLocalePicker() {
  const locale = useLocale((s) => s.locale);
  const setLocale = useLocale((s) => s.set);
  const onChange = useCallback(
    (next: Locale) => {
      if (next === locale) return;
      try {
        const raw = localStorage.getItem('app-locale');
        const parsed = raw ? (JSON.parse(raw) as { state?: unknown; version?: number }) : {};
        const state = (parsed.state as Record<string, unknown> | undefined) ?? {};
        localStorage.setItem(
          'app-locale',
          JSON.stringify({
            state: { ...state, locale: next },
            version: parsed.version ?? 0,
          }),
        );
      } catch {
        setLocale(next);
      }
      window.location.reload();
    },
    [locale, setLocale],
  );
  return (
    <Select
      size="small"
      value={locale}
      onChange={onChange}
      variant="borderless"
      style={{ minWidth: 80 }}
      options={LOCALES.map((l) => ({ value: l.value, label: l.short }))}
    />
  );
}

/** Outer card used twice — user-info and installation. Single styled
 *  wrapper keeps surface treatment (border, radius, padding,
 *  background) coherent across both sections. */
function Card({ children }: { children: ReactNode }) {
  const { token: t } = theme.useToken();
  return (
    <div
      style={{
        marginBottom: 16,
        padding: 20,
        background: t.colorBgElevated,
        border: `1px solid ${t.colorBorder}`,
        borderRadius: 16,
      }}
    >
      {children}
    </div>
  );
}

/** Inline stat — minimal three-up display under the URL bar. No
 *  tinted pill background, no coloured icon-square: tabular-nums
 *  digit on top, micro UPPERCASE label below. Reads as data, not as
 *  "four kinds of badge", which is what differentiates this layout
 *  from the colourful Remnawave-style typed-pill grid. */
function InlineStat({ label, value, highlight }: { label: string; value: string; highlight?: string }) {
  const { token: t } = theme.useToken();
  return (
    <div style={{ textAlign: 'center' }}>
      <div
        style={{
          fontSize: 18,
          fontWeight: 700,
          color: highlight ?? t.colorText,
          fontVariantNumeric: 'tabular-nums',
          lineHeight: 1.2,
        }}
      >
        {value}
      </div>
      <div style={{ fontSize: 10, color: t.colorTextTertiary, textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 2 }}>
        {label}
      </div>
    </div>
  );
}

/** One step in the installation guide — circular icon + title + body
 *  + optional action button. `last` flag drops the bottom divider so
 *  the final step doesn't look like there's a missing fifth one
 *  below it. */
function Step({
  icon,
  color,
  title,
  description,
  action,
  last,
}: {
  icon: ReactNode;
  color: string;
  title: string;
  description: string;
  action?: ReactNode;
  last?: boolean;
}) {
  const { token: t } = theme.useToken();
  return (
    <div
      style={{
        display: 'flex',
        gap: 14,
        padding: '14px 0',
        borderBottom: last ? 'none' : `1px solid ${t.colorBorder}`,
      }}
    >
      <div
        style={{
          flexShrink: 0,
          width: 36,
          height: 36,
          borderRadius: 999,
          background: `${color}1f`,
          color,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 16,
        }}
      >
        {icon}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <Typography.Text strong style={{ fontSize: 15, display: 'block', marginBottom: 4 }}>
          {title}
        </Typography.Text>
        <Typography.Text type="secondary" style={{ fontSize: 13, display: 'block', lineHeight: 1.5 }}>
          {description}
        </Typography.Text>
        {action && <div style={{ marginTop: 10 }}>{action}</div>}
      </div>
    </div>
  );
}
