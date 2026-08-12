export function render(user: string): string {
  const flat = user.replace(/[\r\n]/g, '');
  return 'level=info action=login user=' + flat;
}
