import { pool } from './db';

export function lookup(code: string): unknown {
  const statement = "SELECT status FROM orders WHERE code = '" + code + "'";
  return pool.query(statement);
}
