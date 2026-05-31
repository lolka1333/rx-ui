//! Recommended-clients app icons. Uniform "wordmark" style: a bold
//! white 2-letter mark rendered straight onto the row background — no
//! coloured tile behind. Operator preference: a curated list of
//! similarly-styled marks reads cleaner than seven mismatched
//! illustrated icons, especially at the 44 px size where launcher-icon
//! detail crushes into noise anyway.
//!
//! Each icon fills its 44 × 44 container.

import type { CSSProperties } from 'react';

const STYLE: CSSProperties = {
  width: '100%',
  height: '100%',
  display: 'block',
};

// Shared text style. Inter is the page's body font; falling back to
// system stack keeps the icon crisp when the woff hasn't loaded yet
// (e.g. very first paint on a cold cache).
const FONT_FAMILY =
  'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

interface WordmarkProps {
  /** Two-letter wordmark. Letter-spacing is tightened so "V2" / "SR"
   *  don't drift apart at the icon's small render size. */
  letters: string;
}

/** Shared wordmark frame — bold 2-letter mark, no background fill.
 *  Per-app components below just supply their initials. */
function Wordmark({ letters }: WordmarkProps) {
  const fontSize = letters.length === 1 ? 36 : 30;
  return (
    <svg viewBox="0 0 64 64" style={STYLE} aria-hidden>
      <text
        x="32"
        y="32"
        fill="white"
        fontFamily={FONT_FAMILY}
        fontSize={fontSize}
        fontWeight="700"
        textAnchor="middle"
        dominantBaseline="central"
        letterSpacing="-1.5"
      >
        {letters}
      </text>
    </svg>
  );
}

export function V2BoxIcon() {
  return <Wordmark letters="V2" />;
}

export function StreisandIcon() {
  return <Wordmark letters="ST" />;
}

export function ShadowrocketIcon() {
  return <Wordmark letters="SR" />;
}

export function V2rayNGIcon() {
  return <Wordmark letters="NG" />;
}

export function NekoBoxIcon() {
  return <Wordmark letters="NB" />;
}

export function HiddifyIcon() {
  return <Wordmark letters="HD" />;
}

export function V2rayNIcon() {
  return <Wordmark letters="VN" />;
}
