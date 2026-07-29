import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  decodeAs,
  runRecipe,
  withDefaults,
  type Bytes,
  type KeyEncoding,
  type Operation,
  type Recipe,
  type RunResult,
} from '@zest/core';

import { InputPanel, OutputPanel } from './components/IOPanel.js';
import { OperationLibrary } from './components/OperationLibrary.js';
import { RecipePanel } from './components/RecipePanel.js';
import { AboutPage } from './pages/AboutPage.js';
import { SkillPage } from './pages/SkillPage.js';
import { encodeRecipe, readRecipeFromUrl, useDebounced, useRoute, useTheme } from './lib/state.js';

const EMPTY: RunResult = { ok: true, output: new Uint8Array(0) as Bytes, steps: [] };

export function App(): JSX.Element {
  const [route, navigate] = useRoute();
  const [dark, toggleTheme] = useTheme();

  const [input, setInput] = useState('');
  const [inputEncoding, setInputEncoding] = useState<KeyEncoding>('utf8');
  const [rawInput, setRawInput] = useState<Bytes | null>(null);
  const [recipe, setRecipe] = useState<Recipe>(() => readRecipeFromUrl() ?? []);
  const [result, setResult] = useState<RunResult>(EMPTY);
  const [running, setRunning] = useState(false);

  const debouncedInput = useDebounced(input, 120);
  const debouncedRecipe = useDebounced(recipe, 120);

  // A file load keeps the exact bytes; typing replaces them with the text.
  const inputBytes = useMemo<Bytes>(() => {
    if (rawInput) return rawInput;
    try {
      return decodeAs(debouncedInput, inputEncoding);
    } catch {
      return new Uint8Array(0) as Bytes;
    }
  }, [debouncedInput, inputEncoding, rawInput]);

  // Guards against an earlier, slower run overwriting a later one.
  const runToken = useRef(0);

  useEffect(() => {
    const token = ++runToken.current;
    setRunning(true);

    void runRecipe(inputBytes, debouncedRecipe, { timeoutMs: 10_000 }).then((next) => {
      if (runToken.current !== token) return;
      setResult(next);
      setRunning(false);
    });
  }, [inputBytes, debouncedRecipe]);

  // Keep the recipe in the URL so a pipeline can be shared or bookmarked.
  useEffect(() => {
    if (route !== 'workbench') return;
    const fragment = recipe.length > 0 ? `#/?r=${encodeRecipe(recipe)}` : '#/';
    if (window.location.hash !== fragment) {
      window.history.replaceState(null, '', fragment);
    }
  }, [recipe, route]);

  const addOperation = useCallback((operation: Operation) => {
    setRecipe((previous) => [...previous, { op: operation.id, args: withDefaults(operation.args, {}) }]);
  }, []);

  const loadFile = useCallback((bytes: Bytes, name: string) => {
    setRawInput(bytes);
    setInputEncoding('utf8');
    setInput(`⟨${name} — ${bytes.length} bytes loaded⟩`);
  }, []);

  const changeInput = useCallback((value: string) => {
    setRawInput(null);
    setInput(value);
  }, []);

  return (
    <>
      <header className="header">
        <a className="brand" href="#/" onClick={() => navigate('workbench')}>
          <span className="brand-mark">zest</span>
          <span className="brand-note">runs entirely in your browser</span>
        </a>

        <nav className="header-nav">
          <a
            className="nav-link"
            href="#/"
            aria-current={route === 'workbench' ? 'page' : undefined}
            onClick={() => navigate('workbench')}
          >
            Workbench
          </a>
          <a
            className="nav-link"
            href="#/skill"
            aria-current={route === 'skill' ? 'page' : undefined}
            onClick={() => navigate('skill')}
          >
            Agent skill
          </a>
          <a
            className="nav-link"
            href="#/about"
            aria-current={route === 'about' ? 'page' : undefined}
            onClick={() => navigate('about')}
          >
            About
          </a>
          <button
            type="button"
            className="icon-button"
            onClick={toggleTheme}
            aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
            title={dark ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {dark ? '☀' : '☾'}
          </button>
        </nav>
      </header>

      {route === 'skill' ? (
        <SkillPage />
      ) : route === 'about' ? (
        <AboutPage />
      ) : (
        <main className="workbench">
          <div className="column">
            <OperationLibrary onAdd={addOperation} />
          </div>

          <div className="column">
            <RecipePanel recipe={recipe} steps={result.steps} failedAt={result.failedAt} onChange={setRecipe} />
          </div>

          <div className="column">
            <InputPanel
              value={input}
              encoding={inputEncoding}
              byteLength={inputBytes.length}
              onChange={changeInput}
              onEncodingChange={setInputEncoding}
              onLoadFile={loadFile}
            />
            <OutputPanel output={result.output} ok={result.ok} error={result.error} running={running} />
          </div>
        </main>
      )}

      <footer className="footer">
        Zest · no data leaves this page · <a href="#/about">how it works</a> ·{' '}
        <a href="#/skill">install the agent skill</a>
      </footer>
    </>
  );
}
