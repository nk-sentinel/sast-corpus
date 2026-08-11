import * as fs from 'fs';
import * as path from 'path';

const BASE = '/srv/reports';

export function render(name: string): string {
  return fs.readFileSync(path.join(BASE, name), 'utf8');
}
