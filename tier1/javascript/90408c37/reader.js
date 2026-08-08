const fs = require('fs');
const path = require('path');

const BASE = '/srv/reports';

function contents(name) {
  const target = path.resolve(BASE, path.basename(name));
  if (!target.startsWith(BASE + path.sep)) {
    throw new Error('rejected');
  }
  return fs.readFileSync(target, 'utf8');
}

module.exports = { contents };
