function build(code) {
  const compose = (value) =>
    "SELECT status FROM orders WHERE code = '" + value + "'";
  return apply(compose, code);
}

function apply(step, value) {
  return run(step(value));
}

function run(statement) {
  return statement;
}

module.exports = { build };
