var  DeployFactory = artifacts.require("DeployFactory");

module.exports = function(deployer) {
    deployer.deploy(DeployFactory,"0xCdB47260abff830498c8Bff3B64Da9AB3931306F","0x988885b3b722b7C5C8C2536bcFc2aDc9d8F84664","0x2e6b0f1DD69eADb012320B7A39B38102B5183D4c","0x21dfeea6c82d47203f91aba30af5e5ef3d623aa8206596fbd8c466a5b1586f02","0x446C371C322A8de34cB056ff19CC476A417B5DBe","0x3ff43e1656d514864b6347E6B85eAafCbf4c8f40","0x446C371C322A8de34cB056ff19CC476A417B5DBe");
    //deployer.deploy(PriceConsumer);
};
