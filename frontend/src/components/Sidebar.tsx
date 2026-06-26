import { Layout, Menu, Switch, Checkbox, Drawer, Tooltip } from 'antd';
import {
  DashboardOutlined,
  CloudServerOutlined,
  ExportOutlined,
  TeamOutlined,
  ClusterOutlined,
  SettingOutlined,
  LogoutOutlined,
  BulbOutlined,
  LeftOutlined,
  RightOutlined,
} from '@ant-design/icons';
import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/stores/auth';
import { useTheme } from '@/stores/theme';
import { SidebarStatus } from './SidebarStatus';

const { Sider } = Layout;

interface SidebarProps {
  current: string;
  onNavigate: (key: string) => void;
  mobile?: boolean;
  drawerOpen?: boolean;
  onDrawerClose?: () => void;
  collapsed?: boolean;
  onToggleCollapsed?: () => void;
}

interface ThemeMenuItemProps {
  label: string;
  children: React.ReactNode;
}

function ThemeMenuItem({ label, children }: ThemeMenuItemProps) {
  return (
    <div
      onClick={(e) => e.stopPropagation()}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 8,
        userSelect: 'none',
      }}
    >
      <span style={{ fontSize: 13 }}>{label}</span>
      {children}
    </div>
  );
}

export function Sidebar({
  current,
  onNavigate,
  mobile = false,
  drawerOpen = false,
  onDrawerClose,
  collapsed = false,
  onToggleCollapsed,
}: SidebarProps) {
  const { t } = useTranslation();
  const logout = useAuth((s) => s.logout);
  const username = useAuth((s) => s.user?.username ?? 'admin');
  // Track which inline submenus are open ("Тема"). Left free so the collapsed
  // rail's hover-popup theme switcher still works; we only clear it on the
  // collapse click (below) so the open inline submenu doesn't sprawl during the
  // collapse transition.
  const [openKeys, setOpenKeys] = useState<string[]>([]);
  const themeMode = useTheme((s) => s.mode);
  const setThemeMode = useTheme((s) => s.set);

  const isDark = themeMode !== 'light';
  const isDarker = themeMode === 'darker';

  const toggleDark = useCallback(
    (v: boolean) => {
      if (v) {
        setThemeMode(isDarker ? 'darker' : 'dark');
      } else {
        setThemeMode('light');
      }
    },
    [isDarker, setThemeMode],
  );

  const toggleDarker = useCallback(
    (v: boolean) => {
      setThemeMode(v ? 'darker' : 'dark');
    },
    [setThemeMode],
  );

  const themeChildren = useMemo(
    () => [
      {
        key: 'theme-dark',
        label: (
          <ThemeMenuItem label={t('settings.themeDark')}>
            <Switch size="small" checked={isDark} onChange={toggleDark} />
          </ThemeMenuItem>
        ),
      },
      ...(isDark
        ? [
            {
              key: 'theme-darker',
              label: (
                <ThemeMenuItem label={t('settings.themeDarker')}>
                  {/* `name` here satisfies Chrome's "form field needs an id
                      or name" a11y check — Antd's standalone <Checkbox>
                      doesn't auto-generate one. */}
                  <Checkbox
                    name="sidebar-theme-darker"
                    checked={isDarker}
                    onChange={(e) => toggleDarker(e.target.checked)}
                  />
                </ThemeMenuItem>
              ),
            },
          ]
        : []),
    ],
    [isDark, isDarker, toggleDark, toggleDarker, t],
  );

  const menuItems = useMemo(
    () => [
      {
        key: 'theme',
        icon: <BulbOutlined />,
        label: t('sidebar.theme'),
        children: themeChildren,
      },
      {
        type: 'divider' as const,
        style: { borderColor: 'transparent', margin: '4px 0' },
      },
      { key: 'dashboard', icon: <DashboardOutlined />, label: t('sidebar.dashboard') },
      { key: 'inbounds', icon: <CloudServerOutlined />, label: t('sidebar.inbounds') },
      { key: 'outbounds', icon: <ExportOutlined />, label: t('sidebar.outbounds') },
      { key: 'clients', icon: <TeamOutlined />, label: t('sidebar.clients') },
      { key: 'nodes', icon: <ClusterOutlined />, label: t('sidebar.nodes'), disabled: true },
    ],
    [themeChildren, t],
  );

  const handleMenuClick = useCallback(
    (e: { key: string }) => {
      if (e.key === 'logout') logout();
      else if (e.key.startsWith('theme-')) {
        // handled in inline controls
      } else {
        onNavigate(e.key);
      }
    },
    [logout, onNavigate],
  );

  const menuNode = (
    <Menu
      theme={themeMode === 'light' ? 'light' : 'dark'}
      mode="inline"
      selectedKeys={[current]}
      openKeys={openKeys}
      onOpenChange={(keys) => setOpenKeys(keys as string[])}
      inlineIndent={16}
      onClick={handleMenuClick}
      inlineCollapsed={!mobile && collapsed}
      style={{
        flex: 1,
        borderRight: 0,
        background: 'transparent',
        overflow: 'auto',
      }}
      items={menuItems}
    />
  );

  // Settings + sign-out as compact icon-only buttons pinned to the bottom,
  // separate from the page navigation above. Stacks vertically when the rail
  // is collapsed (too narrow for two side by side).
  const footerActions = (
    <div
      className={`sidebar-footer${!mobile && collapsed ? ' sidebar-footer--collapsed' : ''}`}
    >
      <Tooltip
        title={t('sidebar.settings')}
        placement={!mobile && collapsed ? 'right' : 'top'}
        arrow={false}
        mouseEnterDelay={0.3}
      >
        <button
          type="button"
          className="sidebar-footer-btn"
          onClick={() => onNavigate('settings')}
          aria-label={t('sidebar.settings')}
        >
          <SettingOutlined />
        </button>
      </Tooltip>
      <Tooltip
        title={t('sidebar.logout')}
        placement={!mobile && collapsed ? 'right' : 'top'}
        arrow={false}
        mouseEnterDelay={0.3}
      >
        <button
          type="button"
          className="sidebar-footer-btn sidebar-footer-btn--danger"
          onClick={logout}
          aria-label={t('sidebar.logout')}
        >
          <LogoutOutlined />
        </button>
      </Tooltip>
      {!mobile && onToggleCollapsed && (
        <Tooltip
          title={collapsed ? t('sidebar.expand') : t('sidebar.collapse')}
          placement={collapsed ? 'right' : 'top'}
          arrow={false}
          mouseEnterDelay={0.3}
        >
          <button
            type="button"
            className="sidebar-footer-btn sidebar-footer-btn--toggle"
            onClick={() => {
              // Close any open inline submenu in the same batch as the collapse
              // so "Тема" doesn't sprawl during the transition — while leaving
              // openKeys free afterwards so the collapsed hover-popup still works.
              setOpenKeys([]);
              onToggleCollapsed();
            }}
            aria-label={collapsed ? t('sidebar.expand') : t('sidebar.collapse')}
          >
            {collapsed ? <RightOutlined /> : <LeftOutlined />}
          </button>
        </Tooltip>
      )}
    </div>
  );

  // Logged-in account card pinned above the footer — fills the otherwise
  // empty stretch of the rail and shows who's signed in. Collapses to just
  // the avatar when the rail is narrow.
  const accountCard = (
    <div
      className={`sidebar-account${!mobile && collapsed ? ' sidebar-account--collapsed' : ''}`}
    >
      <span className="sidebar-account-avatar">{username.charAt(0).toUpperCase()}</span>
      <span className="sidebar-account-main">
        <span className="sidebar-account-name">{username}</span>
        <span className="sidebar-account-role">{t('sidebar.role')}</span>
      </span>
    </div>
  );

  if (mobile) {
    return (
      <Drawer
        placement="left"
        open={drawerOpen}
        onClose={onDrawerClose}
        closable={false}
        styles={{
          body: { padding: 0, display: 'flex', flexDirection: 'column' },
          header: { display: 'none' },
          section: { width: 260 },
          wrapper: { width: 260 },
        }}
      >
        <div style={{ height: 8 }} />
        {menuNode}
        <SidebarStatus mobile />
        {accountCard}
        {footerActions}
      </Drawer>
    );
  }

  return (
    <Sider
      collapsible
      collapsed={collapsed}
      trigger={null}
      width={208}
      collapsedWidth={64}
      style={{
        height: '100vh',
        position: 'sticky',
        top: 0,
      }}
    >
      <div
        style={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          // Clip content to the rail's animating width so the custom blocks
          // (status / account / footer) reveal cleanly instead of squishing
          // while the width transitions between collapsed and expanded.
          overflow: 'hidden',
        }}
      >
        <div style={{ height: 8 }} />

        {menuNode}

        <SidebarStatus collapsed={collapsed} />

        {accountCard}

        {footerActions}
      </div>
    </Sider>
  );
}
