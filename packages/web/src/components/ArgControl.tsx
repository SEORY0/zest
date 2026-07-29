import { defaultFor, type ArgDef, type ArgValue, type KeyEncoding, type KeyValue } from '@zest/core';

interface Props {
  def: ArgDef;
  value: ArgValue | undefined;
  onChange: (value: ArgValue) => void;
}

const KEY_ENCODINGS: KeyEncoding[] = ['utf8', 'hex', 'base64', 'latin1'];

function asKeyValue(value: ArgValue | undefined, def: ArgDef): KeyValue {
  if (value && typeof value === 'object') return value;
  const fallback = defaultFor(def);
  if (fallback && typeof fallback === 'object') {
    return typeof value === 'string' ? { ...fallback, value } : fallback;
  }
  return { value: typeof value === 'string' ? value : '', encoding: 'utf8' };
}

export function ArgControl({ def, value, onChange }: Props): JSX.Element {
  switch (def.type) {
    case 'boolean':
      // The label lives on the control itself, so the row spans both columns
      // and the hint becomes a tooltip rather than a second line of prose.
      return (
        <label className="checkbox" title={def.hint}>
          <input
            type="checkbox"
            checked={value === true || value === 'true'}
            onChange={(event) => onChange(event.target.checked)}
          />
          {def.label ?? def.name}
        </label>
      );

    case 'select':
      return (
        <select className="field" value={String(value ?? def.default ?? def.options[0])} onChange={(e) => onChange(e.target.value)}>
          {def.options.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      );

    case 'number':
      return (
        <input
          className="field mono"
          type="number"
          value={String(value ?? def.default ?? 0)}
          min={def.min}
          max={def.max}
          step={def.step}
          onChange={(event) => onChange(event.target.value === '' ? 0 : Number(event.target.value))}
        />
      );

    case 'key': {
      const key = asKeyValue(value, def);
      return (
        <>
          <input
            className="field mono"
            type="text"
            value={key.value}
            placeholder={def.hint}
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => onChange({ ...key, value: event.target.value })}
          />
          <select
            className="field encoding-select"
            value={key.encoding}
            aria-label={`${def.label ?? def.name} encoding`}
            onChange={(event) => onChange({ ...key, encoding: event.target.value as KeyEncoding })}
          >
            {(def.encodings ?? KEY_ENCODINGS).map((encoding) => (
              <option key={encoding} value={encoding}>
                {encoding}
              </option>
            ))}
          </select>
        </>
      );
    }

    default:
      return (
        <input
          className="field mono"
          type="text"
          value={String(value ?? def.default ?? '')}
          placeholder={def.placeholder}
          spellCheck={false}
          autoComplete="off"
          onChange={(event) => onChange(event.target.value)}
        />
      );
  }
}
