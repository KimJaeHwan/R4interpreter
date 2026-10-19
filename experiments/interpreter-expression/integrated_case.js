// Independent Ignition oracle; invoke Node with --jitless.
'use strict';
function addFive(value) { return value + 5; }
function branchCall(value) { return value === 0 ? addFive(5) : addFive(value); }
function appendFive(value) { return value + '5'; }
const [mode, value] = process.argv.slice(2);
console.log(mode === 'branch' ? branchCall(Number(value)) : appendFive(value));
