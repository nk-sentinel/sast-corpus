const { archive } = require('./runner');

function show(req, res) {
  return archive(req.params.name, res);
}

module.exports = { show };
