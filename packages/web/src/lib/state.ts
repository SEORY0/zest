/**
 * Workbench state helpers: theme, routing and recipe persistence.
 *
 * The recipe lives in the URL fragment rather than on a server, so a link is
 * shareable without anything leaving the browser. Input is deliberately not
 * included — it is often the sensitive part.
 */

import { useCallback, useEffect, useState } from 'react';
import type { Recipe } from '@zest/core';

const THEME_KEY = 'zest-theme';

export function useTheme(): [boolean, () => void] {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));

  const toggle = useCallback(() => {
    setDark((previous) => {
      const next = !previous;
      document.documentElement.classList.toggle('dark', next);
      localStorage.setItem(THEME_KEY, next ? 'dark' : 'light');
      return next;
    });
  }, []);

  return [dark, toggle];
}

export type Route = 'workbench' | 'skill' | 'about';

function readRoute(): Route {
  const hash = window.location.hash;
  if (hash.startsWith('#/skill')) return 'skill';
  if (hash.startsWith('#/about')) return 'about';
  return 'workbench';
}

export function useRoute(): [Route, (route: Route) => void] {
  const [route, setRoute] = useState<Route>(readRoute);

  useEffect(() => {
    const onChange = (): void => setRoute(readRoute());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  const navigate = useCallback((next: Route) => {
    window.location.hash = next === 'workbench' ? '#/' : `#/${next}`;
  }, []);

  return [route, navigate];
}

const RECIPE_PARAM = 'r';

export function readRecipeFromUrl(): Recipe | null {
  const hash = window.location.hash.replace(/^#\/?/, '');
  const params = new URLSearchParams(hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '');
  const encoded = params.get(RECIPE_PARAM);
  if (!encoded) return null;

  try {
    const json = decodeURIComponent(escape(atob(encoded.replace(/-/g, '+').replace(/_/g, '/'))));
    const parsed: unknown = JSON.parse(json);
    return Array.isArray(parsed) ? (parsed as Recipe) : null;
  } catch {
    return null;
  }
}

export function encodeRecipe(recipe: Recipe): string {
  const json = JSON.stringify(recipe);
  return btoa(unescape(encodeURIComponent(json))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}
