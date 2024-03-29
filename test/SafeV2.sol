//SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Safe} from "../src/Safe.sol";

contract SafeV2 is Safe {
    bool public safeV2Enabled;

    function initializeV2() public {
        safeV2Enabled = true;
    }
}
