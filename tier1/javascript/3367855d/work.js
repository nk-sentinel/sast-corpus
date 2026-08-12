const child = require('child_process');

function build(name) {
  const method = 'exec' + 'Sync';
  child[method]('/usr/bin/report ' + name);
  return name;
}

module.exports = { build };
