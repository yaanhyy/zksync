const HDWalletProvider = require('truffle-hdwallet-provider');
const PrivateKeyProvider = require('truffle-privatekey-provider');
const fs = require('fs');
let secrets;
if (fs.existsSync('secrets.json')) {
  secrets = JSON.parse(fs.readFileSync('secrets.json', 'utf8'));
}

module.exports = {
  compilers: {
    solc: {
      version: "^0.7.0", // A version or constraint - Ex. "^0.5.0"
                         // Can also be set to "native" to use a native solc
      parser: "solcjs",  // Leverages solc-js purely for speedy parsing
      settings: {          // See the solidity docs for advice about optimization and evmVersion
        optimizer: {
          enabled: true,
          runs: 200
        },
        "metadata": {
          "useLiteralContent": true
        },
        "libraries": {},
        "remappings": [],
        "outputSelection": {
          "*": {
            "*": [
              "evm.bytecode",
              "evm.deployedBytecode",
              "abi"
            ]
          }
        },
        evmVersion: "istanbul"
      }

    }
  },

  // Uncommenting the defaults below 
  // provides for an easier quick-start with Ganache.
  // You can also follow this format for other networks;
  // see <http://truffleframework.com/docs/advanced/configuration>
  // for more details on how to specify configuration options!
  //
  networks: {
    rinkeby: {
      host: "172.18.11.37",
      port: 8545,
      network_id: "4"
    },
    ropsten: {
      host: "172.18.11.37",
      port: 8545,
      network_id: "3"
    },
    goerli: {
      provider: new HDWalletProvider("forest antenna burden wheel prefer isolate claw fire chief iron happy nest", 'https://goerli.infura.io/v3/3be7a6998574443381559f7075192e70'),
      host: "172.18.11.36",
      port: 10234,
      network_id: "5",
      networkCheckTimeout: 999999, 
    },
    heco: {
	
      network_id: "256",
    },
    local: {
      host: "172.18.18.141",
      port: 8545,
      network_id: "*"
    },
    test: {
      provider: new PrivateKeyProvider("0dae11faa7b5075c426a88888f4d2250aeea58b2f0c68c4c428f28df8d56e129", 'https://http-testnet.huobichain.com'),	
      network_id: "256",
      gas: 0x600000, 
    }
  }
  //
};
