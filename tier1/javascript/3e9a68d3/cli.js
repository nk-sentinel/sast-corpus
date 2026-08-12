const { handle } = require('./handler');

console.log(handle(process.argv[2] || ''));
