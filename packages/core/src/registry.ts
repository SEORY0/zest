/**
 * Operation registry.
 *
 * The registry is the single source of truth shared by the UI, the CLI and the
 * agent skill, so an operation added here shows up in all three at once.
 */

import { OperationError, type Category, type Operation } from './types.js';

const operations = new Map<string, Operation>();
const order: string[] = [];

export function register(...ops: Operation[]): void {
  for (const op of ops) {
    if (operations.has(op.id)) {
      throw new Error(`Duplicate operation id ${JSON.stringify(op.id)}.`);
    }
    operations.set(op.id, op);
    order.push(op.id);
  }
}

export function listOperations(): Operation[] {
  return order.map((id) => operations.get(id)!);
}

export function getOperation(id: string): Operation {
  const op = operations.get(id);
  if (op) return op;

  const suggestion = closestOperationId(id);
  throw new OperationError(
    `Unknown operation ${JSON.stringify(id)}.${suggestion ? ` Did you mean ${JSON.stringify(suggestion)}?` : ''}`,
  );
}

export function hasOperation(id: string): boolean {
  return operations.has(id);
}

export function operationsByCategory(): Map<Category, Operation[]> {
  const grouped = new Map<Category, Operation[]>();
  for (const op of listOperations()) {
    const bucket = grouped.get(op.category);
    if (bucket) bucket.push(op);
    else grouped.set(op.category, [op]);
  }
  return grouped;
}

/**
 * Rank operations against a free-text query. Matches on id, name, category and
 * keywords, weighted so an exact id wins and a description brush wins least.
 */
export function searchOperations(query: string): Operation[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return listOperations();

  const scored: { op: Operation; score: number }[] = [];
  for (const op of listOperations()) {
    let score = 0;
    const id = op.id.toLowerCase();
    const name = op.name.toLowerCase();

    if (id === needle || name === needle) score = 100;
    else if (id.startsWith(needle) || name.startsWith(needle)) score = 80;
    else if (id.includes(needle) || name.includes(needle)) score = 60;
    else if (op.keywords?.some((k) => k.toLowerCase().includes(needle))) score = 40;
    else if (op.category.toLowerCase().includes(needle)) score = 20;
    else if (op.description.toLowerCase().includes(needle)) score = 10;

    if (score > 0) scored.push({ op, score });
  }

  return scored.sort((a, b) => b.score - a.score || a.op.name.localeCompare(b.op.name)).map((s) => s.op);
}

function closestOperationId(id: string): string | undefined {
  const needle = id.toLowerCase();
  let best: { id: string; distance: number } | undefined;
  for (const candidate of order) {
    const distance = levenshtein(needle, candidate);
    if (!best || distance < best.distance) best = { id: candidate, distance };
  }
  // Only suggest when the guess is close enough to be plausible.
  return best && best.distance <= Math.max(3, Math.floor(needle.length / 2)) ? best.id : undefined;
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 0; i < a.length; i++) {
    const current = [i + 1];
    for (let j = 0; j < b.length; j++) {
      current.push(Math.min(previous[j + 1] + 1, current[j] + 1, previous[j] + (a[i] === b[j] ? 0 : 1)));
    }
    previous = current;
  }
  return previous[b.length];
}
