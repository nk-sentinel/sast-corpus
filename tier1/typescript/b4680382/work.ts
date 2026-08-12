export function render(key: string): string {
  try {
    return load(key);
  } catch (e) {
    return 'lookup failed';
  }
}

function load(key: string): string {
  throw new Error('connect to db.internal:5432 as reporting failed');
}
