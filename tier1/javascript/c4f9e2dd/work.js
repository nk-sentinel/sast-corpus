function build(code) {
  const holder = [];
  const same = holder;
  holder.push(code);
  return run("SELECT status FROM orders WHERE code = '" + same[0] + "'");
}

function run(statement) {
  const mysql = require('mysql');
  const link = mysql.createConnection({ database: 'app' });
  return link.query(statement);
}

module.exports = { build };
