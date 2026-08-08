const { pool } = require('./db');

function lookup(code) {
  const statement = 'SELECT status FROM orders WHERE code = $1';
  return pool.query(statement, [code]);
}

module.exports = { lookup };
