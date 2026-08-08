const { pool } = require('./db');

function lookup(code) {
  const statement = "SELECT status FROM orders WHERE code = '" + code + "'";
  return pool.query(statement);
}

module.exports = { lookup };
