/**
 * Three-way theme control: light, dark, or follow the system.
 *
 * A segmented control rather than a flip switch, because "follow the system"
 * is a real third state — with a two-way toggle there is no way back to it
 * once you have touched the control.
 */

import type { ThemeChoice } from '../lib/state.js';

interface Props {
  choice: ThemeChoice;
  onChoose: (choice: ThemeChoice) => void;
}

/*
 * Solid icons rather than outlines. At 16px an outline weight of 1–2px is
 * most of the glyph, so filled shapes stay legible and read as one mark
 * instead of a wire drawing.
 */
const OPTIONS: { value: ThemeChoice; label: string; icon: JSX.Element }[] = [
  {
    value: 'light',
    label: 'Light',
    icon: (
      <>
        <circle cx="12" cy="12" r="4.6" />
        <g stroke="currentColor" strokeWidth="2.1" strokeLinecap="round">
          <path d="M12 1.7v2.5M12 19.8v2.5M22.3 12h-2.5M4.2 12H1.7M19.28 4.72l-1.77 1.77M6.49 17.51l-1.77 1.77M19.28 19.28l-1.77-1.77M6.49 6.49L4.72 4.72" />
        </g>
      </>
    ),
  },
  {
    value: 'dark',
    label: 'Dark',
    icon: <path d="M20.9 13.75A8.9 8.9 0 1 1 10.25 3.1a7.05 7.05 0 0 0 10.65 10.65z" />,
  },
  {
    value: 'system',
    label: 'System',
    icon: (
      <>
        <rect x="2.4" y="4.6" width="19.2" height="12.5" rx="2.4" />
        <path d="M10.8 17.1h2.4v3.1h-2.4z" />
        <path d="M8.4 20.2h7.2" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" />
      </>
    ),
  },
];

export function ThemeToggle({ choice, onChoose }: Props): JSX.Element {
  return (
    <div className="theme-toggle" role="group" aria-label="Colour theme">
      {OPTIONS.map((option) => (
        <button
          key={option.value}
          type="button"
          className="theme-option"
          aria-pressed={choice === option.value}
          aria-label={option.label}
          title={`${option.label} theme`}
          onClick={() => onChoose(option.value)}
        >
          <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            {option.icon}
          </svg>
        </button>
      ))}
    </div>
  );
}
