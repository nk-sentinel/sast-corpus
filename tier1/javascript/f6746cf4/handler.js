const ALLOWED = new Set(['api.example.com']);

function handle(target) {
  let parsed;
  try {
    parsed = new URL(target);
  } catch (e) {
    return '';
  }
  if (parsed.protocol !== 'https:' || !ALLOWED.has(parsed.hostname)) {
    return '';
  }
  return fetchIt(parsed.toString());
}

function fetchIt(target) {
  return String(target);
}

module.exports = { handle };
