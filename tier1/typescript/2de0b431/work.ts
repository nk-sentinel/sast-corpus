const PERMITTED = new Set(['api.example.com']);

export function render(target: string): string {
  const parsed = new URL(target);
  if (parsed.protocol !== 'https:' || !PERMITTED.has(parsed.hostname)) {
    throw new Error('rejected');
  }
  return `GET ${target}`;
}
