const { execSync } = require('child_process');

function permitted(name) {
  return /^[a-z-]{1,20}$/.test(name);
}

function handle(name) {
  permitted(name);
  execSync('/usr/bin/report ' + name);
  return name;
}

module.exports = { handle };
