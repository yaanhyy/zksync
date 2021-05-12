var  Governance = artifacts.require("Governance");

module.exports = function(deployer) {
    deployer.deploy(Governance);
    //deployer.deploy(PriceConsumer);
};