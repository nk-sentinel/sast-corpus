function build(code) {
  const holder = [];
  const same = holder;
  holder.push(code);
  return run("SELECT status FROM orders WHERE code = '" + same[0] + "'");
}

function run(statement) {
  return statement;
}

module.exports = { build };
