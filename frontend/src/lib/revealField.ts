//! Bring a form field the operator cannot see into view.
//!
//! Forms in this panel hide fields two ways: tabs and collapsible sections.
//! Both mount their contents eagerly now (`forceRender`), so every rule is
//! registered and actually runs — but a rule that fails on a hidden field is
//! still a submit that appears to do nothing. This is the other half: given
//! the name antd reports for the offending field, open whatever hides it.

/** Bring a field the operator cannot see into view: switch to the tab that
 *  holds it, open every collapsed section on the way down, then scroll to it.
 *
 *  Driven off the DOM rather than a field→section map, because the map would
 *  be a second copy of the form's structure and would rot the first time a
 *  field moved. antd gives each control an id built by joining the name path
 *  with `_`, which is the only contract this needs.
 */
export function revealField(name: ReadonlyArray<string | number>) {
  const node = document.getElementById(name.join('_'));
  if (!node) return;

  // Collapsed ancestors, innermost first — sections do nest.
  let cursor: HTMLElement | null = node;
  while (cursor) {
    const panel: HTMLElement | null = cursor.closest('.ant-collapse-item');
    if (!panel) break;
    if (!panel.classList.contains('ant-collapse-item-active')) {
      panel.querySelector<HTMLElement>('.ant-collapse-header')?.click();
    }
    cursor = panel.parentElement;
  }

  // The tab pane that holds it. Matched by role rather than class: the pane
  // carries no `ant-tabs-tabpane` class in this antd version, but it is always
  // the tabpanel, and its id pairs with the tab's — `…-panel-KEY` / `…-tab-KEY`.
  const pane = node.closest<HTMLElement>('[role="tabpanel"]');
  if (pane?.id) {
    document.getElementById(pane.id.replace('-panel-', '-tab-'))?.click();
  }

  node.scrollIntoView({ block: 'center', behavior: 'smooth' });
}
