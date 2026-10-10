function handle(raw) {
  const code = raw.replace(/[^A-Z0-9]/g, '');
  if (!/^[A-Z0-9]{1,12}$/.test(code)) {
    return '';
  }
  return run("SELECT status FROM orders WHERE code = '" + raw + "'");
}

function run(statement) {
  const mysql = require('mysql');
  const link = mysql.createConnection({ database: 'app' });
  return link.query(statement);
}

module.exports = { handle };
