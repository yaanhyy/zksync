const fs = require('fs');
var contract = JSON.parse(fs.readFileSync('./build/contracts/Governance.json', 'utf8'));
//console.log(metadata);
console.log(JSON.stringify(contract.abi));

