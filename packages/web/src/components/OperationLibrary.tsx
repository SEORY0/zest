import { useMemo, useState } from 'react';
import { CATEGORIES, listOperations, searchOperations, type Category, type Operation } from '@zest/core';

interface Props {
  onAdd: (operation: Operation) => void;
}

export function OperationLibrary({ onAdd }: Props): JSX.Element {
  const [query, setQuery] = useState('');

  const grouped = useMemo(() => {
    const matches = query.trim() ? searchOperations(query) : listOperations();
    const groups = new Map<Category, Operation[]>();
    for (const operation of matches) {
      const bucket = groups.get(operation.category);
      if (bucket) bucket.push(operation);
      else groups.set(operation.category, [operation]);
    }
    // Search results keep their relevance order; the full list follows the
    // canonical category order.
    const order = query.trim() ? Array.from(groups.keys()) : CATEGORIES.filter((c) => groups.has(c));
    return order.map((category) => ({ category, operations: groups.get(category)! }));
  }, [query]);

  const total = grouped.reduce((sum, group) => sum + group.operations.length, 0);

  return (
    <section className="panel library" aria-label="Operation library">
      <header className="panel-header">
        <h2 className="panel-title">Operations</h2>
        <span className="badge">{total}</span>
      </header>

      <div className="library-search">
        <input
          className="field"
          type="search"
          value={query}
          placeholder="Search — base64, jwt, entropy…"
          aria-label="Search operations"
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>

      <div className="library-list">
        {total === 0 ? (
          <p className="empty-note">Nothing matches “{query}”.</p>
        ) : (
          grouped.map(({ category, operations }) => (
            <div className="library-group" key={category}>
              <div className="library-group-label eyebrow">{category}</div>
              {operations.map((operation) => (
                <button
                  key={operation.id}
                  type="button"
                  className="op-button"
                  title={operation.description}
                  onClick={() => onAdd(operation)}
                >
                  <span className="op-button-name">{operation.name}</span>
                  <span className="op-button-id">{operation.id}</span>
                </button>
              ))}
            </div>
          ))
        )}
      </div>
    </section>
  );
}
