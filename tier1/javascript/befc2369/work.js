const fs = require('fs');

class Request {
  constructor() {
    this.name = null;
  }
}

function build(name) {
  const request = new Request();
  request.name = name;
  return read(request);
}

function read(request) {
  return fs.readFileSync('/srv/reports/' + request.name, 'utf8');
}

module.exports = { build };
