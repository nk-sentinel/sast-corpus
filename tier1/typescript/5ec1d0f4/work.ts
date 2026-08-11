export function render(blob: string): string {
  const target: Record<string, unknown> = {};
  const source = JSON.parse(blob);
  for (const key of Object.keys(source)) {
    (target as any)[key] = source[key];
  }
  return String(Object.keys(target).length);
}
