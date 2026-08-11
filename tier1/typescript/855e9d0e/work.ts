import * as fs from 'fs';
import * as path from 'path';

const BASE = '/srv/reports';

export function render(name: string): string {
  const target = path.resolve(BASE, path.basename(name));
  if (!target.startsWith(BASE + path.sep)) {
    throw new Error('rejected');
  }
  return fs.readFileSync(target, 'utf8');
}
