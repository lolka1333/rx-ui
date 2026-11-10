/**
 * The row primitives every settings section is built from: the section frame,
 * field labels and groups, and the switch whose whole row is the hit target.
 */
import { Switch, Tooltip } from 'antd';
import type { SwitchProps } from 'antd';
import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';

/**
 * Section wrapper: the section's heading, then the body (form, field groups).
 * The column width is capped in CSS (`.app-settings-section`) so it fills the
 * content pane on wide displays without leaving a dead gap on the right —
 * values and controls align to the column edge.
 *
 * The heading is for the document outline and screen readers only. On screen
 * the tab strip (or the sidebar, for the Xray page) already names the category,
 * so it is taken off the screen without being taken out of the document (see
 * `.app-settings-page .app-settings-section-title`).
 */
export function SectionFrame({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="app-settings-section">
      <h1 className="app-settings-section-title">{title}</h1>
      <div>{children}</div>
    </section>
  );
}

/** A field's name, with its explanation either under it or behind it.
 *
 *  `desc` prints the explanation as a paragraph — right for a handful of
 *  settings, wrong for a screenful: six paragraphs stacked turn a group into a
 *  wall of prose and push every control into a narrow gutter. `hint` puts the
 *  same sentence in a tooltip instead, which is what the DNS tab does. The
 *  pair fills the row's left column; the control sits in the right one. */
export function FieldLabel({ title, desc, hint }: { title: string; desc?: string; hint?: string }) {
  const name = <span className="app-field-title">{title}</span>;
  return (
    <span className="app-field-label">
      {hint ? (
        <Tooltip title={hint}>
          <span className="app-field-title-hint">{name}</span>
        </Tooltip>
      ) : (
        name
      )}
      {desc ? <span className="app-field-desc">{desc}</span> : null}
    </span>
  );
}

/** A titled block of rows within a section — the "Account information" /
 *  "Password & security" headings grouping related rows. Consecutive
 *  groups get a hairline divider above them (see CSS). */
export function FieldGroup({
  title,
  sub,
  className,
  children,
}: {
  title?: string;
  /** Sits beside the heading, quieter — the one line a group needs to say
   *  about itself once, instead of repeating it per row. */
  sub?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={className ? `app-settings-fieldgroup ${className}` : 'app-settings-fieldgroup'}>
      {title && (
        <h2 className="app-settings-fieldgroup-title">
          {title}
          {sub && <span className="app-settings-fieldgroup-sub">{sub}</span>}
        </h2>
      )}
      <div className="app-settings-group">{children}</div>
    </div>
  );
}

/**
 * A Switch whose whole settings row is the hit target: clicking anywhere in
 * the row toggles it, and the row washes on hover to advertise that. A 44px
 * pill at the far end of a 1000px row is a small thing to aim at, and the rest
 * of the row was doing nothing.
 *
 * The row click is REPLAYED as a real click on the switch button rather than
 * writing the field directly: `form.setFieldValue` does not fire
 * `onValuesChange`, so a direct write would flip the control while leaving the
 * page's unsaved-changes tracking blind to it. Going through the button keeps
 * one code path — validation, dirty tracking and the disabled state all behave
 * exactly as they do for a click on the switch itself.
 *
 * Mouse affordance only: the switch stays the keyboard target, so no second
 * tab stop is introduced for the row.
 */
export function RowSwitch(props: SwitchProps) {
  const btn = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const row = btn.current?.closest('.app-field-switch');
    if (!row) return undefined;
    const onRowClick = (e: Event) => {
      const target = e.target as HTMLElement | null;
      // The switch handles clicks on itself; replaying one would undo it.
      if (target?.closest('.ant-switch')) return;
      btn.current?.click();
    };
    row.addEventListener('click', onRowClick);
    return () => row.removeEventListener('click', onRowClick);
  }, []);
  return <Switch {...props} ref={btn} />;
}
