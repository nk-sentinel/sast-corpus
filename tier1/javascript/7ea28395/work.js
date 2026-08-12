function render(expression) {
  try {
    return JSON.parse(expression);
  } catch (e) {
    return null;
  }
}

module.exports = { render };
