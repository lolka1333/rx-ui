import { Popover, Switch, Checkbox, Select, Typography, Button, theme } from 'antd';
import { SettingOutlined } from '@ant-design/icons';
import { useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useTheme } from '@/stores/theme';
import { useLocale } from '@/stores/locale';
import { LOCALES } from '@/i18n';

/**
 * The actual form — theme switches + language picker. Shared between the
 * Popover variant (used on the login page) and the Modal variant (used from
 * the sidebar menu, where there's no good DOM anchor for a popover).
 */
function SettingsContent() {
  const { t } = useTranslation();
  const { token } = theme.useToken();
  const themeMode = useTheme((s) => s.mode);
  const setThemeMode = useTheme((s) => s.set);
  const locale = useLocale((s) => s.locale);
  const setLocale = useLocale((s) => s.set);

  const isDark = themeMode !== 'light';
  const isDarker = themeMode === 'darker';

  const toggleDark = useCallback(
    (v: boolean) => {
      setThemeMode(v ? (isDarker ? 'darker' : 'dark') : 'light');
    },
    [isDarker, setThemeMode],
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <Row label={t('settings.themeDark')}>
        <Switch
          size="small"
          checked={isDark}
          onChange={toggleDark}
          // antd's `size="small"` is already the smallest preset; scale gives
          // it the extra trim the popover needs without inventing a custom size.
          style={{ transform: 'scale(0.85)', transformOrigin: 'center' }}
        />
      </Row>
      {isDark && (
        <Row label={t('settings.themeDarker')}>
          <Checkbox
            checked={isDarker}
            onChange={(e) => setThemeMode(e.target.checked ? 'darker' : 'dark')}
          />
        </Row>
      )}

      <div style={{ marginTop: 4 }}>
        <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block' }}>
          {t('settings.language')}
        </Typography.Text>
        <Select
          value={locale}
          onChange={setLocale}
          size="small"
          style={{ width: 144, marginTop: 4 }}
          options={LOCALES.map((l) => ({
            value: l.value,
            label: (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    color: token.colorTextTertiary,
                    minWidth: 22,
                  }}
                >
                  {l.short}
                </span>
                <span>{l.label}</span>
              </span>
            ),
          }))}
        />
      </div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  // Tight pair: control sits immediately to the right of its own label with
  // a small fixed gap. Pairs are not forced into a shared column, so each
  // control hugs its text instead of being pushed to a far right edge.
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{ fontSize: 14 }}>{label}</span>
      {children}
    </div>
  );
}

/**
 * Floating cog button + popover. Used in the top-right corner of the login
 * screen so users can pick language before authenticating.
 */
export function SettingsPopover({
  placement = 'bottomRight',
}: {
  placement?: 'bottomRight' | 'topRight' | 'rightTop';
}) {
  const { t } = useTranslation();
  return (
    <Popover
      content={
        <div>
          <Typography.Text strong style={{ fontSize: 14, display: 'block', marginBottom: 8 }}>
            {t('settings.title')}
          </Typography.Text>
          <SettingsContent />
        </div>
      }
      trigger="click"
      placement={placement}
      destroyOnHidden
    >
      <Button
        shape="circle"
        icon={<SettingOutlined />}
        size="large"
        aria-label={t('settings.title')}
      />
    </Popover>
  );
}
