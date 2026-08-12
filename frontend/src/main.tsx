import React from 'react';
import ReactDOM from 'react-dom/client';
import { Root } from './Root';
import { useTheme } from '@/stores/theme';
import { applyCssVariables } from '@/theme/tokens';
import './index.css';

// Paint with the persisted palette from the very first frame.
//
// `applyCssVariables` also runs from an effect in Root, which covers later
// theme switches — but an effect fires AFTER the first paint. Until it did,
// `--sidebar` / `--surface` / `--text` / `--border` were unset and every rule
// fell back to its hard-coded default, so the whole UI painted one frame in the
// wrong palette and then repainted. It read as the sidebar flickering on
// reload, because that is where most of the variable-driven colour lives.
//
// The pre-paint script in index.html only covers `--bg` and `data-theme` (it
// can't import from the bundle, so it duplicates a single colour on purpose).
// This runs before `render()` and reuses the real palette, so nothing is
// duplicated and nothing can drift. zustand's persist middleware hydrates
// localStorage synchronously, so the mode here is already the stored one.
applyCssVariables(useTheme.getState().mode);

// HMR safety: when this entry module is re-evaluated by Vite (which
// happens on hot reload), calling `createRoot` a second time on the
// same DOM node would trigger React's "container has already been
// passed to createRoot()" warning. Stash the root on the container
// itself so subsequent module runs reuse the same React root.
type ContainerWithRoot = HTMLElement & {
  __reactRoot?: ReactDOM.Root;
};

const container = document.getElementById('root') as ContainerWithRoot | null;
if (!container) {
  throw new Error('#root is missing from index.html');
}
if (!container.__reactRoot) {
  container.__reactRoot = ReactDOM.createRoot(container);
}
container.__reactRoot.render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
