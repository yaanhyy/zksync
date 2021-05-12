var  Verifier = artifacts.require("Verifier");

module.exports = function(deployer) {
    deployer.deploy(Verifier);
    //deployer.deploy(PriceConsumer);
};
