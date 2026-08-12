const { execFileSync } = require('child_process');

const ALLOWED = new Map([['daily', 'daily'], ['weekly', 'weekly']]);

function build(name) {
  const target = ALLOWED.get(name);
  if (target === undefined) {
    return '';
  }
  return run(target);
}

function run(target) {
  execFileSync('/usr/bin/report', [target]);
  return target;
}

module.exports = { build };
