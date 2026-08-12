const { build } = require('./work');

console.log(build(process.argv[2] || ''));
