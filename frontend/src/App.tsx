import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Layout, Grid, theme } from 'antd';
import { CloseOutlined, MenuUnfoldOutlined } from '@ant-design/icons';
import { Sidebar } from '@/components/Sidebar';
import { Login } from '@/pages/Login';
import { Dashboard } from '@/pages/Dashboard';
import { Inbounds } from '@/pages/Inbounds';
import { Outbounds } from '@/pages/Outbounds';
import { Clients } from '@/pages/Clients';
import { Settings } from '@/pages/Settings';
import { SubscriptionLanding } from '@/pages/SubscriptionLanding';
import { useAuth } from '@/stores/auth';
import { useNav, isNavPage } from '@/stores/nav';

/** Public route detection. The backend's `/sub/{token}` falls through
 *  to the SPA when the caller asks for HTML (Accept: text/html and no
 *  explicit ?format), so a browser visit lands here. We pick the token
 *  out of `pathname` and render the landing page outside the admin
 *  shell — no auth gate, no sidebar. Token alphabet is intentionally
 *  loose (`[A-Za-z0-9_-]+`) so a future switch to base64url tokens
 *  doesn't require coordinated changes on both ends; today's tokens
 *  are pure lowercase hex from `generate_token()`. */
const SUB_PATH_RE = /^\/sub\/([A-Za-z0-9_-]+)\/?$/;
function subscriptionToken(): string | null {
  const m = window.location.pathname.match(SUB_PATH_RE);
  return m ? m[1] : null;
}

const { Content } = Layout;

const SIDEBAR_WIDTH = 208;
const SIDEBAR_COLLAPSED = 64;
const MOBILE_DRAWER = 260;
const BTN_SIZE = 32;
const BTN_TOP = 60;

/** Top-level router. Splits public subscription landing from the
 *  admin shell BEFORE either side mounts, so the admin component's
 *  hook ladder (useAuth → useNav → useState → useEffect → …) is never
 *  conditional on the URL. Reads of `window.location.pathname` inside
 *  one component for a route-based branch would be a Rules-of-Hooks
 *  hazard the moment the URL ever changes without a remount. */
export default function App() {
  const subToken = subscriptionToken();
  if (subToken) return <SubscriptionLanding token={subToken} />;
  return <AdminApp />;
}

function AdminApp() {
  const authToken = useAuth((s) => s.token);
  // Active page persists across reloads via localStorage (see stores/nav.ts).
  // Subscribed individually so changing `current` doesn't re-render on every
  // unrelated zustand update.
  const current = useNav((s) => s.current);
  const setCurrent = useNav((s) => s.setCurrent);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  // Settings is a modal overlay, not a nav page — it opens
  // over whatever page you're on and closes back to it.
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [animX, setAnimX] = useState(0);
  const [animate, setAnimate] = useState(true);
  const screens = Grid.useBreakpoint();
  const { token } = theme.useToken();

  const isMobile = screens.lg !== undefined && !screens.lg;
  const sidebarOpen = isMobile ? drawerOpen : !collapsed;
  const lastMobileRef = useRef(isMobile);

  const visualWidth = isMobile
    ? drawerOpen
      ? MOBILE_DRAWER
      : 0
    : collapsed
      ? SIDEBAR_COLLAPSED
      : SIDEBAR_WIDTH;

  const targetX = sidebarOpen ? visualWidth : 0;

  useEffect(() => {
    const breakpointChanged = lastMobileRef.current !== isMobile;
    lastMobileRef.current = isMobile;

    if (breakpointChanged) {
      // Snap to correct position without animation when crossing the desktop/mobile breakpoint
      setAnimate(false);
      setAnimX(targetX);
      const id = requestAnimationFrame(() => setAnimate(true));
      return () => cancelAnimationFrame(id);
    }

    // Mirror Antd Drawer's mount-then-transition pattern: it adds the open class
    // on a second RAF after mounting, which causes a ~30ms delay before its transform
    // animation starts. Wait two animation frames so our button stays in sync.
    //
    // `cancelled` is the source of truth — `cancelAnimationFrame(raf2)` alone
    // isn't enough because there's a window between raf1 firing and raf2
    // being assigned where a new effect run can cancel `raf2 === 0` (no-op)
    // and then the inner callback still calls setAnimX with the captured
    // (now-stale) targetX. The flag short-circuits both callbacks regardless
    // of which raf id we hold.
    //
    // <React.StrictMode> in main.tsx double-invokes effects in dev, so two
    // raf chains are scheduled back-to-back. The first one's cleanup runs
    // (sets cancelled=true) before the second begins — both chains converge
    // on the same setAnimX(targetX) call, so the duplication is harmless.
    // Production builds get a single chain.
    let cancelled = false;
    let raf1 = 0;
    let raf2 = 0;
    raf1 = requestAnimationFrame(() => {
      if (cancelled) return;
      raf2 = requestAnimationFrame(() => {
        if (cancelled) return;
        setAnimX(targetX);
      });
    });
    return () => {
      cancelled = true;
      cancelAnimationFrame(raf1);
      cancelAnimationFrame(raf2);
    };
  }, [targetX, isMobile]);

  const toggle = useCallback(() => {
    if (isMobile) setDrawerOpen((v) => !v);
    else setCollapsed((v) => !v);
  }, [isMobile]);

  const handleNavigate = useCallback(
    (key: string) => {
      // Sidebar's menu items may include keys for things that aren't
      // top-level pages (e.g. logout). Settings opens as a modal overlay
      // rather than switching the page; the rest narrow to known NavPages.
      if (key === 'settings') {
        setSettingsOpen(true);
      } else if (isNavPage(key)) {
        setCurrent(key);
      }
      setDrawerOpen(false);
    },
    [setCurrent],
  );

  const onDrawerClose = useCallback(() => setDrawerOpen(false), []);

  // The three tabs stay mounted (to preserve per-tab state) and each runs its
  // own pollers, so they are expensive trees to render. Without this, every
  // AdminApp re-render — including a drawer open/close, which flips
  // `drawerOpen` — would synchronously re-render all three and stall the main
  // thread, which is exactly what made the mobile drawer feel laggy. Memoising
  // the elements gives React a stable reference so it bails out of re-rendering
  // them on unrelated state changes; they still update from their own hooks.
  const dashboardPage = useMemo(() => <Dashboard />, []);
  const inboundsPage = useMemo(() => <Inbounds />, []);
  const outboundsPage = useMemo(() => <Outbounds />, []);
  const clientsPage = useMemo(() => <Clients />, []);

  if (!authToken) return <Login />;

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sidebar
        current={current}
        onNavigate={handleNavigate}
        mobile={isMobile}
        drawerOpen={drawerOpen}
        onDrawerClose={onDrawerClose}
        collapsed={collapsed}
        onToggleCollapsed={toggle}
      />
      <Layout>
        <Content
          style={{
            padding: isMobile ? '16px 12px' : '32px 40px',
            maxWidth: 1400,
            width: '100%',
          }}
        >
          {/* Render all tabs in parallel and hide inactive ones with
              display:none rather than conditionally mounting. This preserves
              per-tab local state (open modals, edit form contents in
              Inbounds, scroll position) across navigation. The pollers
              inside each tab keep running while hidden — for a single-admin
              panel with ~2-3 tabs that's a negligible cost compared to the
              UX hit of losing the user's in-progress edits when they tap
              another nav item. */}
          <div
            className="app-page-fade"
            style={{ display: current === 'dashboard' ? 'block' : 'none' }}
          >
            {dashboardPage}
          </div>
          <div
            className="app-page-fade"
            style={{ display: current === 'inbounds' ? 'block' : 'none' }}
          >
            {inboundsPage}
          </div>
          <div
            className="app-page-fade"
            style={{ display: current === 'outbounds' ? 'block' : 'none' }}
          >
            {outboundsPage}
          </div>
          <div
            className="app-page-fade"
            style={{ display: current === 'clients' ? 'block' : 'none' }}
          >
            {clientsPage}
          </div>
        </Content>
      </Layout>

      {isMobile && (
        <button
          type="button"
          onClick={toggle}
          aria-label="toggle sidebar"
          style={{
            position: 'fixed',
            top: BTN_TOP,
            left: 0,
            width: BTN_SIZE,
            height: BTN_SIZE,
            transform: `translateX(${animX}px)`,
            transition: animate ? 'transform 0.28s cubic-bezier(0.4, 0, 0.2, 1)' : 'none',
            background: token.colorBgElevated,
            borderTop: `1px solid ${token.colorBorderSecondary}`,
            borderRight: `1px solid ${token.colorBorderSecondary}`,
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
            borderLeft: 0,
            borderTopLeftRadius: 0,
            borderBottomLeftRadius: 0,
            borderTopRightRadius: 8,
            borderBottomRightRadius: 8,
            color: token.colorTextSecondary,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 12,
            zIndex: 1001,
            boxShadow: '0 2px 8px rgba(0,0,0,0.25)',
            padding: 0,
            outline: 'none',
            WebkitTapHighlightColor: 'transparent',
            userSelect: 'none',
            touchAction: 'manipulation',
          }}
        >
          <span
            style={{
              position: 'relative',
              display: 'inline-flex',
              width: 14,
              height: 14,
            }}
          >
            <CloseOutlined
              style={{
                position: 'absolute',
                inset: 0,
                opacity: sidebarOpen ? 1 : 0,
                transform: `rotate(${sidebarOpen ? 0 : 90}deg) scale(${sidebarOpen ? 1 : 0.5})`,
                transition: 'opacity 0.18s ease, transform 0.18s ease',
              }}
            />
            <MenuUnfoldOutlined
              style={{
                position: 'absolute',
                inset: 0,
                opacity: sidebarOpen ? 0 : 1,
                transform: `rotate(${sidebarOpen ? -90 : 0}deg) scale(${sidebarOpen ? 0.5 : 1})`,
                transition: 'opacity 0.18s ease, transform 0.18s ease',
              }}
            />
          </span>
        </button>
      )}

      <Settings open={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </Layout>
  );
}
