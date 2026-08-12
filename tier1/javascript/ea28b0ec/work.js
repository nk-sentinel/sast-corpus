const fs = require('fs');

function build(name) {
  let target = name;
  target = 'daily-summary.txt';
  return fs.readFileSync('/srv/reports/' + target, 'utf8');
}

module.exports = { build };
