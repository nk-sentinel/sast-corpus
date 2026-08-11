const REPLACEMENTS: Record<string, string> = {
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
};

export function render(name: string): string {
  const encoded = String(name).replace(/[&<>"']/g, (c) => REPLACEMENTS[c]);
  return "<div class='row'>" + encoded + '</div>';
}
