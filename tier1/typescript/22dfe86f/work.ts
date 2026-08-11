const DB_PASSWORD = 'Pr0d-Repor7ing-2024!';

export function render(user: string): string {
  return `${user}:${DB_PASSWORD}`;
}
