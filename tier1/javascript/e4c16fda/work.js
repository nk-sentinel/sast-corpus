function build(code) {
  const compose = () => 'SELECT status FROM orders WHERE code = ?';
  return apply(compose, code);
}

function apply(step, value) {
  return run(step(), [value]);
}

function run(statement, params) {
  return statement + '|' + params.join();
}

module.exports = { build };
