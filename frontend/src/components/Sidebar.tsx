import { Layout, Menu, Switch, Checkbox, Drawer, Tooltip, theme } from 'antd';
import {
  DashboardOutlined,
  CloudServerOutlined,
  TeamOutlined,
  ClusterOutlined,
  SettingOutlined,
  ToolOutlined,
  LogoutOutlined,
  BulbOutlined,
  LeftOutlined,
  RightOutlined,
} from '@ant-design/icons';
import { useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/stores/auth';
import { useTheme } from '@/stores/theme';

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
  const themeMode = useTheme((s) => s.mode);
  const setThemeMode = useTheme((s) => s.set);
  const { token } = theme.useToken();

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
      { key: 'clients', icon: <TeamOutlined />, label: t('sidebar.clients') },
      { key: 'nodes', icon: <ClusterOutlined />, label: t('sidebar.nodes'), disabled: true },
      { key: 'settings', icon: <SettingOutlined />, label: t('sidebar.settings') },
      { key: 'xray-settings', icon: <ToolOutlined />, label: t('sidebar.xray'), disabled: true },
      { key: 'logout', icon: <LogoutOutlined />, label: t('sidebar.logout') },
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
      inlineIndent={16}
      onClick={handleMenuClick}
      forceSubMenuRender
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
        }}
      >
        <div style={{ height: 8 }} />

        {menuNode}

        {onToggleCollapsed && (
          <div style={{ padding: '4px 12px 6px', flexShrink: 0 }}>
            <Tooltip
              title={collapsed ? t('sidebar.expand') : t('sidebar.collapse')}
              placement="right"
              arrow={false}
              mouseEnterDelay={0.3}
            >
              <button
                type="button"
                onClick={onToggleCollapsed}
                aria-label="toggle sidebar"
                style={{
                  background: 'transparent',
                  border: 0,
                  color: token.colorTextSecondary,
                  width: '100%',
                  height: 28,
                  borderRadius: 8,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 13,
                  transition: 'all 0.15s ease',
                  margin: 0,
                  padding: 0,
                  outline: 'none',
                  WebkitTapHighlightColor: 'transparent',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = isDark
                    ? 'rgba(255,255,255,0.04)'
                    : 'rgba(0,0,0,0.04)';
                  e.currentTarget.style.color = token.colorText;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'transparent';
                  e.currentTarget.style.color = token.colorTextSecondary;
                }}
              >
                {collapsed ? <RightOutlined /> : <LeftOutlined />}
              </button>
            </Tooltip>
          </div>
        )}
      </div>
    </Sider>
  );
}
