const fs = require('fs');
const path = require('path');

const BASE = '/srv/reports';

class Request {
  constructor() {
    this.name = null;
  }
}

function build(name) {
  const request = new Request();
  request.name = path.basename(name);
  return read(request);
}

function read(request) {
  const target = path.resolve(BASE, request.name);
  if (!target.startsWith(BASE + path.sep)) {
    return '';
  }
  return fs.readFileSync(target, 'utf8');
}

module.exports = { build };
