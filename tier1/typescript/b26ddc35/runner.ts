import { execSync } from 'child_process';

export function archive(name: string): Buffer {
  const line = 'tar -cf backup.tar ' + name;
  return execSync(line);
}
