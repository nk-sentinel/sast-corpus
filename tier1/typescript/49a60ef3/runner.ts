import { execFileSync } from 'child_process';

export function archive(name: string): Buffer {
  const argv = ['-cf', 'backup.tar', name];
  return execFileSync('tar', argv);
}
