var  DeployFactory = artifacts.require("DeployFactory");

module.exports = function(deployer) {
    //     Governance _govTarget,
    //     Verifier _verifierTarget,
    //     ZkSync _zkSyncTarget,
    //     bytes32 _genesisRoot,
    //     address _firstValidator,
    //     address _governor,
    //     address _feeAccountAddress
    deployer.deploy(DeployFactory,
        "0xD7933751146Fe38dBA64210daafBB0a478dc5f12",
        "0x75a7F9d74F2893019cFd2a1e9714aE70b71b14C7",
        "0x78ffd977214e9E2cba9c41C1642aDB950450F07A",
        "0x05bd7dacd2df23624ac0dfc22efbc032c69dfef3f4df6022d2bc5a19d22a8ce1",
        "0x0005DdDCCBd5AF0880564BCB6a3eA308B214FB50",
        "0xfDaCb301dC53Bcd62c5E43ff16FAB051e7c450b8",
        "0x0005DdDCCBd5AF0880564BCB6a3eA308B214FB50");
    //deployer.deploy(PriceConsumer);
};
