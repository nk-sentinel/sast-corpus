import { pool } from './db';

export function lookup(code: string): unknown {
  const statement = 'SELECT status FROM orders WHERE code = $1';
  return pool.query(statement, [code]);
}
