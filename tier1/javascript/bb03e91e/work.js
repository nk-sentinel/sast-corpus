const fs = require('fs');

function build(name) {
  let target = name;
  return fs.readFileSync('/srv/reports/' + target, 'utf8');
}

module.exports = { build };
