import { App, Form, Input, Button, Typography, theme } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useAuth, type UserView } from '@/stores/auth';
import { useLocale } from '@/stores/locale';
import { SettingsPopover } from '@/components/SettingsPopover';

interface LoginCreds {
  username: string;
  password: string;
}

interface LoginResp {
  token: string;
  user: UserView;
}

export function Login() {
  const login = useAuth((s) => s.login);
  const { token } = theme.useToken();
  const { t } = useTranslation();
  const { message } = App.useApp();
  // Re-key the card on locale change so the stagger fade-in re-runs over
  // the new strings — without it the new translations snap in without
  // animation while the rest of the page still carries the old
  // entrance, which reads as a half-applied refresh.
  const locale = useLocale((s) => s.locale);

  // Match the mutation pattern used everywhere else in the app (Dashboard
  // xrayAction, Inbounds save/toggle/del/apply, XrayUpdatesModal install).
  // useMutation gives us isPending for the submit button, an onError hook
  // that runs through the same `apiErrorMessage` formatter, and removes the
  // need for a local `useState(loading)` + try/finally dance.
  const loginMutation = useMutation({
    mutationFn: async (values: LoginCreds) =>
      (await apiClient.post<LoginResp>('/auth/login', values)).data,
    onSuccess: (data) => {
      login(data.token, data.user);
      message.success(t('login.success'));
    },
    onError: (e: unknown) => {
      message.error(apiErrorMessage(e) ?? t('login.failed'));
    },
  });

  const onFinish = (values: LoginCreds) => loginMutation.mutate(values);

  return (
    <div
      style={{
        position: 'relative',
        minHeight: '100dvh',
        overflow: 'hidden',
        background: token.colorBgBase,
        display: 'grid',
        placeItems: 'center',
        padding: '24px 16px',
      }}
    >
      <div className="login-bg-orb login-bg-orb-1" />
      <div className="login-bg-orb login-bg-orb-2" />
      <div className="login-bg-orb login-bg-orb-3" />
      <div className="login-bg-mobile" />

      {/* Pre-login settings: theme + language so users can pick before logging in */}
      <div style={{ position: 'fixed', top: 16, right: 16, zIndex: 2 }}>
        <SettingsPopover placement="bottomRight" />
      </div>

      <div className="login-card-wrap" key={locale}>
        {/* Animated glow halo behind card */}
        <div className="login-card-halo" />

        <div className="login-card">
          <div className="login-anim-stagger" style={{ textAlign: 'center', marginBottom: 28, '--d': '0.05s' } as React.CSSProperties}>
            <Typography.Title
              level={3}
              style={{
                margin: 0,
                fontWeight: 600,
                letterSpacing: '-0.02em',
                fontSize: 24,
              }}
            >
              {t('login.welcome')}
            </Typography.Title>
          </div>

          <div className="login-anim-stagger" style={{ textAlign: 'center', marginBottom: 28, '--d': '0.12s' } as React.CSSProperties}>
            <Typography.Text style={{ color: token.colorTextTertiary, fontSize: 13 }}>
              {t('login.subtitle')}
            </Typography.Text>
          </div>

          <Form layout="vertical" onFinish={onFinish}>
            <div className="login-anim-stagger" style={{ '--d': '0.20s' } as React.CSSProperties}>
              <Form.Item
                name="username"
                label={<span style={{ fontSize: 12, color: token.colorTextSecondary }}>{t('login.username')}</span>}
                rules={[{ required: true, message: t('login.usernameRequired') }]}
              >
                <Input
                  prefix={<UserOutlined style={{ color: token.colorTextTertiary }} />}
                  placeholder={t('login.usernamePlaceholder')}
                  size="large"
                  autoComplete="username"
                />
              </Form.Item>
            </div>

            <div className="login-anim-stagger" style={{ '--d': '0.28s' } as React.CSSProperties}>
              <Form.Item
                name="password"
                label={<span style={{ fontSize: 12, color: token.colorTextSecondary }}>{t('login.password')}</span>}
                rules={[{ required: true, message: t('login.passwordRequired') }]}
              >
                <Input.Password
                  prefix={<LockOutlined style={{ color: token.colorTextTertiary }} />}
                  placeholder="••••••"
                  size="large"
                  autoComplete="current-password"
                />
              </Form.Item>
            </div>

            <div className="login-anim-stagger" style={{ '--d': '0.36s' } as React.CSSProperties}>
              <Form.Item style={{ marginTop: 24, marginBottom: 0 }}>
                <Button type="primary" htmlType="submit" block size="large" loading={loginMutation.isPending}>
                  {t('login.submit')}
                </Button>
              </Form.Item>
            </div>
          </Form>
        </div>
      </div>
    </div>
  );
}
