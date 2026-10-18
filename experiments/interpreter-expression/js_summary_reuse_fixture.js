'use strict';
const fs = require('node:fs');

function twoAdds(value) {
  const first = value + 5;
  return first + 5;
}

const input = Number(process.argv[2]);
const marker = process.argv[3];
if (marker) {
  fs.writeFileSync(marker, JSON.stringify({phase: 'ready'}));
  process.kill(process.pid, 'SIGSTOP');
}
console.log(JSON.stringify({result: twoAdds(input)}));
