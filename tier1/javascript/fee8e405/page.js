const REPLACEMENTS = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function renderRow(name) {
  const encoded = String(name).replace(/[&<>"']/g, (c) => REPLACEMENTS[c]);
  return "<div class='row'>" + encoded + "</div>";
}

module.exports = { renderRow };
