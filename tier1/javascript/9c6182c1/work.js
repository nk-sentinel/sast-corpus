function render(user) {
  const flat = String(user).replace(/[\r\n]/g, '');
  return 'level=info action=login user=' + flat;
}

module.exports = { render };
