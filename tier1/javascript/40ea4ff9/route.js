const { body } = require('./fetcher');

function show(req, res) {
  return body(req.query.target).then((t) => res.send(t));
}

module.exports = { show };
