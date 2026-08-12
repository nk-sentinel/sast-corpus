const fs = require('fs');
const path = require('path');

const BASE = '/srv/reports';

function handle(name) {
  const target = path.resolve(BASE, path.basename(name));
  if (!target.startsWith(BASE + path.sep)) {
    return '';
  }
  return fs.readFileSync(target, 'utf8');
}

module.exports = { handle };
