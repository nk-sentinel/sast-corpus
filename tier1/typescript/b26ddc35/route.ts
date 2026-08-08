import { archive } from './runner';

export function show(name: string): unknown {
  return archive(name);
}
