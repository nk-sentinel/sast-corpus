const { execFileSync } = require('child_process');

function permitted(name) {
  return /^[a-z-]{1,20}$/.test(name);
}

function handle(name) {
  if (!permitted(name)) {
    return '';
  }
  execFileSync('/usr/bin/report', [name]);
  return name;
}

module.exports = { handle };
