const { exec } = require('child_process');

function archive(name, res) {
  const line = 'tar -cf backup.tar ' + name;
  return exec(line, (err, out) => res.send(out));
}

module.exports = { archive };
