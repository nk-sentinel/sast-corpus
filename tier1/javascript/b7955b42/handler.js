function handle(raw) {
  const code = raw.replace(/[^A-Z0-9]/g, '');
  if (!/^[A-Z0-9]{1,12}$/.test(code)) {
    return '';
  }
  return run('SELECT status FROM orders WHERE code = ?', [code]);
}

function run(statement, params) {
  return statement + '|' + params.join();
}

module.exports = { handle };
