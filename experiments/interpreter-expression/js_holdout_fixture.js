'use strict';
const fs = require('node:fs');

function innerAdd(value) {
  return value + 5;
}

function wrappedAdd(value) {
  return innerAdd(value);
}

const input = Number(process.argv[2]);
const marker = process.argv[3];
fs.writeFileSync(marker, JSON.stringify({phase: 'ready'}));
process.kill(process.pid, 'SIGSTOP');
console.log(JSON.stringify({result: wrappedAdd(input)}));
