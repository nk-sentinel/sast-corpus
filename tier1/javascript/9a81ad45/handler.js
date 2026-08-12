const fs = require('fs');

function handle(name) {
  name.replace(/\.\./g, '');
  return fs.readFileSync('/srv/reports/' + name, 'utf8');
}

module.exports = { handle };
