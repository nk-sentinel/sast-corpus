async function body(target) {
  const response = await fetch(target);
  return response.text();
}

module.exports = { body };
