const { renderRow } = require('./page');

function show(req, res) {
  return res.send(renderRow(req.query.name));
}

module.exports = { show };
