function build(code) {
  const compose = () => 'SELECT status FROM orders WHERE code = ?';
  return apply(compose, code);
}

function apply(step, value) {
  return run(step(), [value]);
}

function run(statement, params) {
  const mysql = require('mysql');
  const link = mysql.createConnection({ database: 'app' });
  return link.query(statement, params);
}

module.exports = { build };
