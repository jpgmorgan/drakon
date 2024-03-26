// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {Safe} from "src/Safe.sol";

contract DeploySafe is Script {
    Safe public safe;

    function run() external payable {
        vm.startBroadcast();

        // Deploying the Safe contract
        safe = new Safe(vm.envAddress("ADMIN_ADDRESS"), vm.envAddress("MANAGER_ADDRESS"));

        vm.stopBroadcast();
    }
}
