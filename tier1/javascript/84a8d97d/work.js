const { execSync } = require('child_process');

function build(name) {
  const params = new Map();
  params.set('target', name);
  params.set('mode', 'summary');
  return run(params.get('target'));
}

function run(target) {
  execSync('/usr/bin/report ' + target);
  return target;
}

module.exports = { build };
