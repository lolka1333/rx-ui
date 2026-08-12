//! Last line of defence around the whole app.
//!
//! React unmounts the entire root when a render throws, and what the operator
//! then sees is a blank page with no hint that anything happened — the panel
//! looks broken rather than "one screen hit an error". A throw from render is
//! not hypothetical here: the QR encoder raises when a share-link exceeds its
//! byte capacity, which is why that call site now measures first.
//!
//! Deliberately plain (no antd, no i18n, no store reads): whatever broke may
//! be the theme, the locale, or a provider above this point, so the fallback
//! must not depend on any of them.

import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // The message the operator can quote and the component path that produced
    // it — the browser console keeps both after the reload button is pressed.
    console.error('unhandled render error', error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div
        role="alert"
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 24,
          background: '#0f172a',
          color: '#e2e8f0',
          fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif',
        }}
      >
        <div style={{ maxWidth: 560 }}>
          <h1 style={{ fontSize: 20, fontWeight: 600, margin: '0 0 8px' }}>
            Something in the panel crashed
          </h1>
          <p style={{ margin: '0 0 16px', color: '#94a3b8', lineHeight: 1.5 }}>
            The page stopped rendering. Nothing was saved or changed by this —
            reload to get back in. The details are in the browser console.
          </p>
          <pre
            style={{
              margin: '0 0 16px',
              padding: 12,
              borderRadius: 8,
              background: 'rgba(148,163,184,0.12)',
              color: '#f8b4b4',
              fontSize: 12,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}
          >
            {error.message}
          </pre>
          <button
            type="button"
            onClick={() => window.location.reload()}
            style={{
              padding: '8px 16px',
              borderRadius: 8,
              border: 'none',
              background: '#6366f1',
              color: '#fff',
              fontSize: 14,
              cursor: 'pointer',
            }}
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
