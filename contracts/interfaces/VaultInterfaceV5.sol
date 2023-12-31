pragma solidity 0.8.20;

interface VaultInterfaceV5{
    function sendDaiToTrader(address, uint) external;
    function receiveDaiFromTrader(address, uint, uint) external;
    function currentBalanceDai() external view returns(uint);
    function distributeRewardDai(uint) external;
}
