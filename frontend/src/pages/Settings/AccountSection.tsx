/**
 * Account — the login and password (each changed through its own dialog) and
 * the current session.
 */
import { App, Button, Form, Input, Modal } from 'antd';
import { ClockCircleOutlined, LockOutlined, LogoutOutlined, UserOutlined } from '@ant-design/icons';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useAuth } from '@/stores/auth';
import { SectionFrame, FieldGroup } from './fields';

interface CredentialsFormValues {
  current_password: string;
  new_username: string;
  new_password: string;
  new_password_confirm: string;
}

export function AccountSection() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const logout = useAuth((s) => s.logout);
  const currentUsername = useAuth((s) => s.user?.username ?? '');
  const authToken = useAuth((s) => s.token);
  const qc = useQueryClient();
  const [form] = Form.useForm<CredentialsFormValues>();
  // Each field is a compact read-only row with an "Edit"
  // button; clicking it opens a focused modal dialog for just that field.
  const [editing, setEditing] = useState<'login' | 'password' | null>(null);

  // Active-session info (JWT expiry), shown under "Password & security" next
  // to the password controls.
  const sessionInfo = useMemo(() => decodeSessionInfo(authToken), [authToken]);

  const mutation = useMutation({
    mutationFn: async (values: CredentialsFormValues) => {
      // The backend changes username + password through one endpoint
      // (either may be null). `editing` decides which one this submit
      // touches; the other is left untouched.
      await apiClient.post('/auth/credentials', {
        current_password: values.current_password,
        new_username: editing === 'login' ? values.new_username?.trim() || null : null,
        new_password: editing === 'password' ? values.new_password || null : null,
      });
    },
    onSuccess: () => {
      message.success(t('settings.credentialsUpdated'));
      logout();
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.credentialsError')),
  });

  const close = () => {
    if (!mutation.isPending) setEditing(null);
  };

  return (
    <SectionFrame title={t('settings.accountSection')}>
      <FieldGroup title={t('settings.groupInfo')}>
        <InfoRow
          icon={<UserOutlined />}
          label={t('settings.currentUsername')}
          desc={t('settings.currentUsernameHint')}
          value={currentUsername}
          action={
            <Button
              variant="filled"
              color="default"
              className="app-settings-editbtn"
              onClick={() => setEditing('login')}
            >
              {t('common.edit')}
            </Button>
          }
        />
      </FieldGroup>

      <FieldGroup title={t('settings.groupSecurity')}>
        <InfoRow
          icon={<LockOutlined />}
          label={t('settings.passwordLabel')}
          desc={t('settings.passwordRowHint')}
          value="••••••••••"
          action={
            <Button
              variant="filled"
              color="default"
              className="app-settings-editbtn"
              onClick={() => setEditing('password')}
            >
              {t('common.edit')}
            </Button>
          }
        />
        <InfoRow
          icon={<ClockCircleOutlined />}
          label={t('settings.sectionSession')}
          desc={t('settings.sessionRowHint')}
          value={
            sessionInfo ? (
              <>
                {/* Live dot: the session is the one row on this tab whose value
                    is a STATE rather than a stored setting, so it carries a
                    status marker the others don't need. */}
                <span className="app-settings-inforow-dot" aria-hidden="true" />
                {t('settings.sessionExpiryDescription', { hours: sessionInfo.hoursLeft })}
              </>
            ) : (
              t('settings.sessionExpiryDescriptionInactive')
            )
          }
          action={
            <Button
              variant="filled"
              color="default"
              className="app-settings-logout"
              icon={<LogoutOutlined />}
              onClick={() => {
                logout();
                qc.clear();
              }}
            >
              {t('settings.sessionSignOut')}
            </Button>
          }
        />
      </FieldGroup>

      {/* Edit dialog for changing the login or password. New value first,
          current password to confirm. */}
      <Modal
        open={editing !== null}
        title={
          editing === 'password'
            ? t('settings.editPasswordTitle')
            : t('settings.editLoginTitle')
        }
        width={440}
        okText={t('common.done')}
        cancelText={t('common.cancel')}
        confirmLoading={mutation.isPending}
        mask={{ closable: !mutation.isPending }}
        keyboard={!mutation.isPending}
        onCancel={close}
        onOk={() => form.submit()}
        afterOpenChange={(o) => {
          if (o) form.resetFields();
        }}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          autoComplete="off"
          disabled={mutation.isPending}
          onFinish={(v) => mutation.mutate(v)}
        >
          {editing === 'password' ? (
            <>
              <Form.Item
                name="new_password"
                label={t('settings.newPassword')}
                rules={[
                  { required: true, message: t('settings.newPasswordRequired') },
                  { min: 4, message: t('settings.newPasswordTooShort') },
                ]}
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
              <Form.Item
                name="new_password_confirm"
                label={t('settings.newPasswordConfirm')}
                dependencies={['new_password']}
                rules={[
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      if (getFieldValue('new_password') === value) return Promise.resolve();
                      return Promise.reject(new Error(t('settings.newPasswordMismatch')));
                    },
                  }),
                ]}
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
            </>
          ) : (
            <Form.Item
              name="new_username"
              label={t('settings.newUsername')}
              rules={[{ required: true, message: t('settings.newUsernameRequired') }]}
            >
              <Input autoComplete="off" placeholder={currentUsername} />
            </Form.Item>
          )}
          <Form.Item
            name="current_password"
            label={t('settings.currentPassword')}
            rules={[{ required: true, message: t('settings.currentPasswordRequired') }]}
            style={{ marginBottom: 0 }}
          >
            <Input.Password autoComplete="current-password" />
          </Form.Item>
        </Form>
      </Modal>
    </SectionFrame>
  );
}

/** One account row, on the SAME two-column grid as the form rows on the other
 *  tabs: the left column names the setting, the right column carries its
 *  current value together with the action that changes it (Edit / Sign-out).
 *
 *  Value and action belong side by side: an action pinned to the row's far edge
 *  sits ~700px from the value it acts on. */
function InfoRow({
  icon,
  label,
  desc,
  value,
  action,
}: {
  icon: ReactNode;
  label: string;
  desc?: string;
  value: ReactNode;
  action: ReactNode;
}) {
  return (
    <div className="app-settings-inforow">
      <span className="app-settings-inforow-id">
        <span className="app-settings-inforow-icon" aria-hidden="true">
          {icon}
        </span>
        <span className="app-field-label">
          <span className="app-field-title">{label}</span>
          {desc ? <span className="app-field-desc">{desc}</span> : null}
        </span>
      </span>
      <div className="app-settings-inforow-control">
        <span className="app-settings-inforow-value">{value}</span>
        {action}
      </div>
    </div>
  );
}

function decodeSessionInfo(token: string | null): { hoursLeft: number } | null {
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split('.')[1])) as { exp?: unknown };
    if (typeof payload.exp !== 'number') return null;
    const secondsLeft = payload.exp - Math.floor(Date.now() / 1000);
    if (secondsLeft <= 0) return null;
    return { hoursLeft: Math.max(1, Math.round(secondsLeft / 3600)) };
  } catch {
    return null;
  }
}
