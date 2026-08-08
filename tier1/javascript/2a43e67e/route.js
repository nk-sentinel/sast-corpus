const { contents } = require('./reader');

function show(req, res) {
  return res.send(contents(req.params.name));
}

module.exports = { show };
