const fs = require('fs');

function handle(name) {
  const cleaned = name.replace('../', '');
  return fs.readFileSync('/srv/reports/' + cleaned, 'utf8');
}

module.exports = { handle };
