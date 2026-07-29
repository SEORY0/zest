/**
 * Recipe execution.
 *
 * A run never throws for an operation-level failure. It reports which step
 * failed and returns the output produced up to that point, because a partial
 * pipeline is usually the most useful thing to look at when debugging one.
 */

import { withDefaults } from './args.js';
import { getOperation } from './registry.js';
import type { Bytes, Recipe, RunResult, StepResult } from './types.js';

export interface RunOptions {
  /** Abort a step that runs longer than this. Zero disables the limit. */
  timeoutMs?: number;
  /** Called after each step, for progressive UI updates. */
  onStep?: (result: StepResult, index: number) => void;
}

export async function runRecipe(input: Bytes, recipe: Recipe, options: RunOptions = {}): Promise<RunResult> {
  const steps: StepResult[] = [];
  let data = input;

  for (let index = 0; index < recipe.length; index++) {
    const step = recipe[index];

    if (step.disabled) {
      const skipped: StepResult = { op: step.op, ok: true, skipped: true, output: data, durationMs: 0 };
      steps.push(skipped);
      options.onStep?.(skipped, index);
      continue;
    }

    const started = performance.now();
    try {
      const operation = getOperation(step.op);
      const args = withDefaults(operation.args, step.args);
      const output = await withTimeout(
        Promise.resolve(operation.run(data, args)),
        options.timeoutMs ?? 0,
        `${operation.name} exceeded the ${options.timeoutMs}ms time limit.`,
      );

      data = output;
      const result: StepResult = {
        op: step.op,
        ok: true,
        skipped: false,
        output,
        durationMs: performance.now() - started,
      };
      steps.push(result);
      options.onStep?.(result, index);
    } catch (error) {
      const result: StepResult = {
        op: step.op,
        ok: false,
        skipped: false,
        error: error instanceof Error ? error.message : String(error),
        durationMs: performance.now() - started,
      };
      steps.push(result);
      options.onStep?.(result, index);

      return {
        ok: false,
        output: data,
        steps,
        error: `Step ${index + 1} (${step.op}): ${result.error}`,
        failedAt: index,
      };
    }
  }

  return { ok: true, output: data, steps };
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  if (!timeoutMs || timeoutMs <= 0) return promise;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}
