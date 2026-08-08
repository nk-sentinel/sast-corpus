const { lookup } = require('./store');

function show(req, res) {
  return res.json(lookup(req.params.code));
}

module.exports = { show };
