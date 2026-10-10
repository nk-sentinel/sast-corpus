function build(code) {
  return run('SELECT status FROM orders WHERE code = ?', [code]);
}

function run(statement, params) {
  const mysql = require('mysql');
  const link = mysql.createConnection({ database: 'app' });
  return link.query(statement, params);
}

module.exports = { build };
