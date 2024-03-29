// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {Safe} from "src/Safe.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeploySafe is Script {
    Safe public safe;

    function run(address OWNER) external payable {
        vm.startBroadcast();

        // Deploying the Safe contract
        safe = new Safe();

        // Encode the initializer function call
        bytes memory initData = abi.encodeWithSelector(Safe.initialize.selector, OWNER);

        // Deploy the proxy, pointing to the implementation and including initializer call
        new ERC1967Proxy(address(safe), initData);

        // For further interactions, use Safe at the proxy's address
        // Safe safeProxy = Safe(address(proxy));

        vm.stopBroadcast();
    }
}
