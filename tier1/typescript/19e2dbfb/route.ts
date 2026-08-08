import { lookup } from './store';

export function show(code: string): unknown {
  return lookup(code);
}
