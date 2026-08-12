const https = require('https');

const ALLOWED = /api\.example\.com/;

function handle(target) {
  if (!ALLOWED.test(target)) {
    return '';
  }
  return fetchIt(target);
}

function fetchIt(target) {
  return String(target);
}

module.exports = { handle };
