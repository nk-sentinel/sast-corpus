function handle(raw) {
  const code = raw.replace(/[^A-Z0-9]/g, '');
  if (!/^[A-Z0-9]{1,12}$/.test(code)) {
    return '';
  }
  return run("SELECT status FROM orders WHERE code = '" + raw + "'");
}

function run(statement) {
  return statement;
}

module.exports = { handle };
