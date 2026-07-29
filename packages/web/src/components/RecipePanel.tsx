import { useState } from 'react';
import { getOperation, withDefaults, type ArgValue, type Recipe, type StepResult } from '@zest/core';

import { ArgControl } from './ArgControl.js';

interface Props {
  recipe: Recipe;
  steps: StepResult[];
  failedAt?: number;
  onChange: (recipe: Recipe) => void;
}

export function RecipePanel({ recipe, steps, failedAt, onChange }: Props): JSX.Element {
  const [dragging, setDragging] = useState<number | null>(null);
  const [dropTarget, setDropTarget] = useState<number | null>(null);

  const update = (index: number, patch: Partial<Recipe[number]>): void => {
    onChange(recipe.map((step, i) => (i === index ? { ...step, ...patch } : step)));
  };

  const remove = (index: number): void => {
    onChange(recipe.filter((_, i) => i !== index));
  };

  const move = (from: number, to: number): void => {
    if (to < 0 || to >= recipe.length || from === to) return;
    const next = [...recipe];
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    onChange(next);
  };

  return (
    <section className="panel" aria-label="Recipe">
      <header className="panel-header">
        <h2 className="panel-title">Recipe</h2>
        {recipe.length > 0 && <span className="badge">{recipe.length} steps</span>}
        <div className="panel-actions">
          <button type="button" className="button is-quiet" onClick={() => onChange([])} disabled={recipe.length === 0}>
            Clear
          </button>
        </div>
      </header>

      {recipe.length === 0 ? (
        <div className="recipe-empty">
          <p className="recipe-empty-title">No steps yet.</p>
          <p className="recipe-empty-hint">Pick an operation on the left to start building a pipeline.</p>
        </div>
      ) : (
        <div className="recipe-list">
          {recipe.map((step, index) => {
            const operation = safeOperation(step.op);
            const result = steps[index];
            const args = withDefaults(operation?.args, step.args);

            const classes = ['step'];
            if (step.disabled) classes.push('is-disabled');
            if (failedAt === index) classes.push('is-failed');
            if (dragging === index) classes.push('is-dragging');
            if (dropTarget === index && dragging !== null && dragging !== index) classes.push('is-drop-target');

            return (
              <article
                key={`${step.op}-${index}`}
                className={classes.join(' ')}
                onDragOver={(event) => {
                  event.preventDefault();
                  setDropTarget(index);
                }}
                onDrop={(event) => {
                  event.preventDefault();
                  if (dragging !== null) move(dragging, index);
                  setDragging(null);
                  setDropTarget(null);
                }}
              >
                <div className="step-head">
                  <span
                    className="step-index"
                    draggable
                    title="Drag to reorder"
                    onDragStart={() => setDragging(index)}
                    onDragEnd={() => {
                      setDragging(null);
                      setDropTarget(null);
                    }}
                  >
                    {String(index + 1).padStart(2, '0')}
                  </span>

                  <span className="step-name" title={operation?.description}>
                    {operation?.name ?? step.op}
                  </span>

                  {result?.ok && !result.skipped && (
                    <span className="step-timing">{formatDuration(result.durationMs)}</span>
                  )}

                  <div className="step-controls" style={{ marginLeft: result?.ok && !result.skipped ? '0.5rem' : 'auto' }}>
                    <button
                      type="button"
                      className="icon-button"
                      aria-label="Move up"
                      disabled={index === 0}
                      onClick={() => move(index, index - 1)}
                    >
                      ↑
                    </button>
                    <button
                      type="button"
                      className="icon-button"
                      aria-label="Move down"
                      disabled={index === recipe.length - 1}
                      onClick={() => move(index, index + 1)}
                    >
                      ↓
                    </button>
                    <button
                      type="button"
                      className="icon-button"
                      aria-pressed={!step.disabled}
                      aria-label={step.disabled ? 'Enable step' : 'Disable step'}
                      title={step.disabled ? 'Enable step' : 'Disable step'}
                      onClick={() => update(index, { disabled: !step.disabled })}
                    >
                      {step.disabled ? '○' : '●'}
                    </button>
                    <button type="button" className="icon-button" aria-label="Remove step" onClick={() => remove(index)}>
                      ✕
                    </button>
                  </div>
                </div>

                {operation && operation.args && operation.args.length > 0 && (
                  <div className="step-args">
                    {operation.args.map((def) => (
                      <ArgFieldRow
                        key={def.name}
                        label={def.label ?? def.name}
                        hint={def.hint}
                        def={def}
                        value={args[def.name]}
                        onChange={(value) => update(index, { args: { ...args, [def.name]: value } })}
                      />
                    ))}
                  </div>
                )}

                {result && !result.ok && result.error && <p className="step-error">{result.error}</p>}
                {!operation && <p className="step-error">Unknown operation “{step.op}”.</p>}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function ArgFieldRow({
  label,
  hint,
  def,
  value,
  onChange,
}: {
  label: string;
  hint?: string;
  def: Parameters<typeof ArgControl>[0]['def'];
  value: ArgValue | undefined;
  onChange: (value: ArgValue) => void;
}): JSX.Element {
  if (def.type === 'boolean') {
    return (
      <div className="step-arg-control is-full">
        <ArgControl def={def} value={value} onChange={onChange} />
      </div>
    );
  }

  return (
    <>
      <label className="step-arg-label" title={hint ?? label}>
        {label}
      </label>
      <div className="step-arg-control">
        <ArgControl def={def} value={value} onChange={onChange} />
      </div>
    </>
  );
}

function safeOperation(id: string) {
  try {
    return getOperation(id);
  } catch {
    return undefined;
  }
}

function formatDuration(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
  if (ms < 1000) return `${ms.toFixed(1)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}
