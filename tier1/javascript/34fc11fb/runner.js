const { execFile } = require('child_process');

function archive(name, res) {
  const argv = ['-cf', 'backup.tar', name];
  return execFile('tar', argv, (err, out) => res.send(out));
}

module.exports = { archive };
