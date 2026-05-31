import React from 'react';
import ReactDOM from 'react-dom/client';
import { Root } from './Root';
import './index.css';

// HMR safety: when this entry module is re-evaluated by Vite (which
// happens on hot reload), calling `createRoot` a second time on the
// same DOM node would trigger React's "container has already been
// passed to createRoot()" warning. Stash the root on the container
// itself so subsequent module runs reuse the same React root.
type ContainerWithRoot = HTMLElement & {
  __reactRoot?: ReactDOM.Root;
};

const container = document.getElementById('root') as ContainerWithRoot;
if (!container.__reactRoot) {
  container.__reactRoot = ReactDOM.createRoot(container);
}
container.__reactRoot.render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
