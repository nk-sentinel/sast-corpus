const fs = require('fs');
const path = require('path');

const BASE = '/srv/reports';

function contents(name) {
  const target = path.join(BASE, name);
  return fs.readFileSync(target, 'utf8');
}

module.exports = { contents };
