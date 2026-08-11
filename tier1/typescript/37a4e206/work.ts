export function render(user: string): string {
  return `${user}:${process.env.DB_PASSWORD ?? ''}`;
}
