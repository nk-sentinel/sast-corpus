function render(key) {
  try {
    return load(key);
  } catch (e) {
    return 'lookup failed';
  }
}

function load(key) {
  throw new Error('connect to db.internal:5432 as reporting failed');
}

module.exports = { render };
