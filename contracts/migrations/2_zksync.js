var  ZkSync = artifacts.require("ZkSync");
  
module.exports = function(deployer) {
  deployer.deploy(ZkSync);
  //deployer.deploy(PriceConsumer);
};
