const PERMITTED = new Set(['api.example.com', 'cdn.example.com']);

async function body(target) {
  const parsed = new URL(target);
  if (parsed.protocol !== 'https:' || !PERMITTED.has(parsed.hostname)) {
    throw new Error('rejected');
  }
  const response = await fetch(target);
  return response.text();
}

module.exports = { body };
