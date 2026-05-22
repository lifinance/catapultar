// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

contract McopyTestTron {
    uint256 public storageProbe;

    function mcopyDirect() public pure returns (uint256 result) {
        assembly {
            mstore(0x00, 1)
            mcopy(0x20, 0x00, 0x20)
            result := mload(0x20)
        }
    }

    function mcopyCheck() public view returns (uint256) {
        (bool ok,) = address(this).staticcall(abi.encodeCall(this.mcopyDirect, ()));
        return ok ? 1 : 0;
    }

    function mcopyCheckWithStore() public returns (uint256) {
        storageProbe = block.timestamp;
        (bool ok,) = address(this).staticcall(abi.encodeCall(this.mcopyDirect, ()));
        return ok ? 1 : 0;
    }
}
