function build(code) {
  return run('SELECT status FROM orders WHERE code = ?', [code]);
}

function run(statement, params) {
  return statement + '|' + params.join();
}

module.exports = { build };
