const fs = require('fs');
const path = require('path');

function handle(name) {
  const cleaned = path.basename(name);
  return fs.readFileSync('/srv/reports/' + cleaned, 'utf8');
}

module.exports = { handle };
