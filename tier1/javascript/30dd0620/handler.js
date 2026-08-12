function handle(name) {
  const encoded = encodeURIComponent(name);
  return '<div onclick="show(\'' + encoded + '\')">report</div>';
}

module.exports = { handle };
