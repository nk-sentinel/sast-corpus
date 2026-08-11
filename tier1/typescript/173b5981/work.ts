const REFUSED = new Set(['__proto__', 'constructor', 'prototype']);

export function render(blob: string): string {
  const target: Record<string, unknown> = Object.create(null);
  const source = JSON.parse(blob);
  for (const key of Object.keys(source)) {
    if (REFUSED.has(key)) {
      continue;
    }
    target[key] = source[key];
  }
  return String(Object.keys(target).length);
}
