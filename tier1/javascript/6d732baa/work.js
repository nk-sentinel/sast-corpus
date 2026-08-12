function render(expression) {
  return eval('(' + expression + ')');
}

module.exports = { render };
