/**
 * The PEM certificate / key field the HTTPS and Subscription sections share.
 */
import { App } from 'antd';
import { CloudUploadOutlined } from '@ant-design/icons';
import { forwardRef, useEffect, useRef, useState } from 'react';
import type { DragEvent, FocusEventHandler, PointerEvent, ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

interface PemDropFieldProps {
  value?: string;
  onChange?: (e: { target: { value: string } }) => void;
  onBlur?: FocusEventHandler<HTMLTextAreaElement>;
  id?: string;
  placeholder?: string;
  fieldName: string;
  hintSub: string;
  chipText: string;
  chipDot?: boolean;
  icon: ReactNode;
  disabled?: boolean;
}

/** At most one PEM field may have a caret on the way to it. Shared across the
 *  instances on purpose: clicking the second field while the first one's caret
 *  was still pending let that timer fire mid-growth and focus the OTHER field,
 *  which is exactly what kills a height animation. Whoever is opening now owns
 *  the caret, and cancels whatever was queued before it. */
let pendingCaret: number | null = null;
let pendingCaretCleanup: (() => void) | null = null;
function cancelPendingCaret() {
  if (pendingCaret !== null) {
    window.clearTimeout(pendingCaret);
    pendingCaret = null;
  }
  if (pendingCaretCleanup) {
    pendingCaretCleanup();
    pendingCaretCleanup = null;
  }
}

/** Every mounted PEM field's "close yourself" handle. A field normally closes on
 *  blur, but one that was opened and then abandoned before its caret arrived
 *  never gets a blur to close on — click one field, click the next, and the
 *  first would sit open for good. Handing over closes them all; the one taking
 *  over reopens itself in the same render. A field holding a certificate stays
 *  tall regardless: that comes from `:not(:placeholder-shown)`, not from here. */
const pemClosers = new Set<() => void>();

/**
 * A PEM field styled as a compact dashed drop target: a name row always on top,
 * then a short mono textarea that grows on focus/content, with an upload
 * invitation that fades once the field is focused or filled. Dropping a .pem
 * file reads it straight into the field.
 *
 * Controlled the antd way — `value`/`onChange` come from the wrapping
 * `Form.Item`, so validation and dirty-tracking work unchanged. `forwardRef`
 * lets antd scroll-to-error focus the textarea.
 */
export const PemDropField = forwardRef<HTMLTextAreaElement, PemDropFieldProps>(function PemDropField(
  { value, onChange, onBlur, id, placeholder, fieldName, hintSub, chipText, chipDot, icon, disabled },
  ref,
) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [dragOver, setDragOver] = useState(false);
  // Open/closed is tracked here rather than left to `:focus` in CSS, and the
  // click opens the box BEFORE the caret lands in it.
  //
  // Chrome will not animate the height of a focused textarea. Measured on this
  // very field: the same 44→128 transition runs frame by frame while the field
  // is unfocused (45.3 → 54.2 → 69.6 → 85.7 …) and collapses to the final value
  // the instant focus arrives — mid-flight, even. It is not the trigger and not
  // the element: animating an ancestor while the textarea inside holds focus
  // snaps just the same. So the growth has to finish before the field is
  // focused, which is what the pointer handler below does.
  const [open, setOpen] = useState(false);
  /** Matches the box's transition in the stylesheet, plus a frame of slack. */
  const OPEN_MS = 180;
  /** Corner square the browser draws the resize grip in. */
  const GRIP = 20;
  /** The resting strip, and a ceiling for a dragged-open box. Both mirror the
   *  stylesheet's `.app-tls-ta` height and its `--open-h` fallback. */
  const CLOSED_H = 44;
  const MAX_OPEN = 800;

  /** Releases an in-flight resize drag; set while the grip is held. */
  const releaseGrip = useRef<(() => void) | null>(null);

  useEffect(() => {
    const close = () => setOpen(false);
    pemClosers.add(close);
    return () => {
      pemClosers.delete(close);
      // A drag or a queued caret can still be in flight when this field goes
      // away — switching settings tabs unmounts it. Both hang listeners on
      // `document`, and one of them holds a timer that would focus a detached
      // node; nothing else would ever reach them again.
      releaseGrip.current?.();
      cancelPendingCaret();
    };
  }, []);

  /** Click on a closed field: grow it first, put the caret in afterwards. The
   *  default action is what focuses a textarea, so suppressing it is what buys
   *  the animation its 180ms. Only for the closed, empty state — a field that
   *  is already open behaves like an ordinary textarea, caret placement and
   *  all. Reduced-motion users get the caret immediately; there is no animation
   *  for them to wait on. */
  const onPointerDown = (e: PointerEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;

    // The resize grip lives in the bottom-right corner and is dragged with the
    // same pointerdown this handler intercepts. Suppressing the default action
    // — which is what buys the open animation its 180ms — also cancels the
    // browser's resize drag, so the grip stopped working entirely. Leave the
    // corner alone, and switch the height transition off for the duration of
    // the drag: with it on, the box eased toward the pointer 160ms behind and
    // the whole thing felt like it was sagging.
    const box = el.getBoundingClientRect();
    if (e.clientX > box.right - GRIP && e.clientY > box.bottom - GRIP) {
      const drop = el.closest('.app-tls-drop');
      drop?.classList.add('is-resizing');
      const done = () => {
        releaseGrip.current = null;
        drop?.classList.remove('is-resizing');
        document.removeEventListener('pointerup', done);
        document.removeEventListener('pointercancel', done);
        // A drag leaves the height written onto the element itself, which
        // outranks every rule in the stylesheet — the box could no longer
        // collapse. Keep the size as this field's OPEN height instead and give
        // the stylesheet back control: the box still closes to the strip, and
        // reopens at the size the operator chose. Clearing the inline height
        // and focusing happen in the same task, so nothing is painted in
        // between and there is no flash.
        const dragged = Math.round(el.getBoundingClientRect().height);
        el.style.height = '';
        if (drop instanceof HTMLElement && dragged > CLOSED_H + 4) {
          drop.style.setProperty('--open-h', `${Math.min(dragged, MAX_OPEN)}px`);
        }
        el.focus();
      };
      releaseGrip.current = done;
      document.addEventListener('pointerup', done);
      document.addEventListener('pointercancel', done);
      return;
    }

    if (open || (value ?? '').length > 0) return;
    // A focused textarea suppresses height animations for the whole document,
    // not just for itself — so opening the second field while the first still
    // held the caret made the second one snap. Suppressing the default action
    // (below) is what keeps the old field focused, so the blur has to be
    // explicit. It also gives the other field its own closing animation, and
    // fires the form's blur handler exactly as clicking away normally would.
    // Order matters: cancel first, then blur (the old field's blur handler
    // cancels too, and must not be able to kill the caret queued below).
    cancelPendingCaret();
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== el) active.blur();
    pemClosers.forEach((close) => close());
    // Two cases skip the deferral and let the browser focus normally, with
    // `:focus` holding the box open: reduced motion, where there is no
    // animation to wait for; and touch or pen, where the software keyboard only
    // comes up if focus lands in the same task as the tap — from a timer it
    // stays down. A finger also pans: suppressing the default here would arm a
    // caret that fires 180ms into a scroll and drags the page back.
    if (
      e.pointerType !== 'mouse' ||
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    ) {
      return;
    }
    setOpen(true);
    e.preventDefault();

    // Give the caret up if the operator's next action lands anywhere else
    // before it is due. Without this, clicking the field and then quickly
    // clicking something else — a toggle, another tab — pulled focus back into
    // the field 180ms later, over whatever they had just clicked, and left the
    // box open with no blur coming to close it.
    // `pointercancel` targets this very field — it fires when the browser takes
    // the gesture over — so it cannot be filtered by target like the other two.
    const abort = (ev: Event) => {
      if (ev.type === 'pointercancel' || ev.target !== el) {
        cancelPendingCaret();
        setOpen(false);
      }
    };
    pendingCaretCleanup = () => {
      document.removeEventListener('pointerdown', abort, true);
      document.removeEventListener('pointercancel', abort, true);
      document.removeEventListener('focusin', abort, true);
    };
    document.addEventListener('pointerdown', abort, true);
    document.addEventListener('pointercancel', abort, true);
    document.addEventListener('focusin', abort, true);

    pendingCaret = window.setTimeout(() => {
      pendingCaret = null;
      pendingCaretCleanup?.();
      pendingCaretCleanup = null;
      // The field was just clicked, so it is already in view; scrolling to it
      // could only move the page out from under the operator.
      el.focus({ preventScroll: true });
      // Hand the open state over to `:focus` and drop the flag. The flag exists
      // only to cover the window before the caret arrives, so it can never be
      // left set on a field nobody is in.
      setOpen(false);
    }, OPEN_MS);
  };

  const onDrop = (e: DragEvent<HTMLTextAreaElement>) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      // A dropped folder also arrives as a File, and reading it rejects. Say so
      // rather than leaving the drop to fail silently on an unhandled rejection.
      void file
        .text()
        .then((txt) => onChange?.({ target: { value: txt.trim() } }))
        .catch(() => message.error(t('settings.tlsDropUnreadable')));
      return;
    }
    // Text dragged from an editor or another field carries no File at all. It
    // is a PEM just the same, and the hint invites pasting one.
    const text = e.dataTransfer.getData('text/plain').trim();
    if (text) onChange?.({ target: { value: text } });
  };
  return (
    <div className="app-tls-field-inner">
      <div className="app-tls-flabel">
        <span className="app-tls-tile-sm" aria-hidden="true">
          {icon}
        </span>
        <span className="app-tls-fname">{fieldName}</span>
        <span className={`app-tls-chip${chipDot ? ' is-set' : ''}`}>
          {chipDot ? <span className="app-tls-chip-dot" aria-hidden="true" /> : null}
          {chipText}
        </span>
      </div>
      <div className={`app-tls-drop${dragOver ? ' is-drag' : ''}${open ? ' is-open' : ''}`}>
        <textarea
          ref={ref}
          id={id}
          className="app-tls-ta"
          spellCheck={false}
          value={value ?? ''}
          placeholder={placeholder}
          disabled={disabled}
          onChange={(e) => onChange?.(e)}
          onPointerDown={onPointerDown}
          onBlur={(e) => {
            // Clicking away before the caret arrived: drop it, or it would pull
            // focus back into a field the operator has already left.
            cancelPendingCaret();
            setOpen(false);
            onBlur?.(e);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
        />
        {/* The resting field is one strip, so it carries both halves of what an
            operator needs: the PEM header says WHAT belongs here — and differs
            between the two fields, which is what tells them apart at a glance —
            while the sub says HOW to get it in. The header is the textarea's own
            placeholder, reused rather than duplicated, so the two can't drift. */}
        <div className="app-tls-hint" aria-hidden="true">
          <span className="app-tls-hint-ic">
            <CloudUploadOutlined />
          </span>
          <span className="app-tls-hint-ghost">{placeholder}</span>
          <span className="app-tls-hint-sub">{hintSub}</span>
        </div>
      </div>
    </div>
  );
});
