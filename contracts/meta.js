const fs = require('fs');
var contract = JSON.parse(fs.readFileSync('./build/contracts/Proxy.json', 'utf8'));
var metadata = JSON.parse(contract.metadata, 'utf8');
delete metadata.output;
delete metadata.compiler;
delete metadata.version;
delete metadata.settings.compilationTarget;
//console.log(metadata);
console.log(JSON.stringify(metadata));

