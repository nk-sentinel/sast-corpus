function handle(name) {
  const encoded = String(name).replace(/[&<>"'/]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;',
              '"': '&quot;', "'": '&#x27;', '/': '&#x2F;' })[c]);
  return '<div title="' + encoded + '">report</div>';
}

module.exports = { handle };
