// Evaluation fixture. Analysis uses collected bytecode/native observations.
'use strict';
const fs = require('node:fs');

function addFive(value) {
  return value + 5;
}

function branchCall(value) {
  if (value === 0) return addFive(5);
  return addFive(value);
}

function main() {
  const args = process.argv.slice(2);
  let mode = 'number';
  let mark = null;
  let sync = false;
  let input = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--mode') mode = args[++i];
    else if (args[i] === '--mark') mark = args[++i];
    else if (args[i] === '--native-sync') sync = true;
    else input = args[i];
  }
  if (input === null || !['number', 'object'].includes(mode)) process.exit(2);
  let effects = 0;
  const value = mode === 'number' ? Number(input) : {
    valueOf() { effects++; return 1; },
  };
  if (mark) fs.writeFileSync(mark, JSON.stringify({phase: 'ready'}));
  if (sync) process.kill(process.pid, 'SIGSTOP');
  const result = branchCall(value);
  console.log(JSON.stringify({result: String(result), effects}));
}

main();
