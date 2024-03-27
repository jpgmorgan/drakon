// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {Safe} from "../src/Safe.sol";

interface IWETH {
    function deposit() external payable;
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
    function ownerOf(uint256 tokenId) external view returns (address owner);
}

contract SafeTest is Test {
    Safe public safe;
    address private constant WETH_ADDRESS = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address private constant BAYC_ADDRESS = address(0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D);
    address private constant ADMIN_ADDRESS = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    address private constant MANAGER_ADDRESS = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
    address private constant NULL_ADDRESS = address(0x0000000000000000000000000000000000000000);
    IERC721 private bayc = IERC721(BAYC_ADDRESS);

    function setUp() public {
        vm.startBroadcast();
        safe = new Safe(ADMIN_ADDRESS, MANAGER_ADDRESS);
        vm.stopBroadcast();
    }

    //////////////////
    // setAllowance //
    //////////////////

    function testSetAllowanceFromAdmin() public {
        // Test that the allowance is 0 by default
        assertEq(
            IWETH(WETH_ADDRESS).allowance(address(safe), NULL_ADDRESS),
            0,
            "The allowance does not match the expected value."
        );

        // Test that the allowance can be changed to infinite
        vm.prank(ADMIN_ADDRESS);
        safe.setAllowance(WETH_ADDRESS, NULL_ADDRESS, type(uint256).max);
        assertEq(
            IWETH(WETH_ADDRESS).allowance(address(safe), NULL_ADDRESS),
            type(uint256).max,
            "The allowance does not match the expected value."
        );

        // Test that the allowance can be reverted to 0 thereafter
        vm.prank(ADMIN_ADDRESS);
        safe.setAllowance(WETH_ADDRESS, NULL_ADDRESS, 0);
        assertEq(
            IWETH(WETH_ADDRESS).allowance(address(safe), NULL_ADDRESS),
            0,
            "The allowance does not match the expected value."
        );
    }

    function testSetAllowanceFromNonAdmin() public {
        // Test that the allowance can't be changed by a non admin address
        vm.prank(MANAGER_ADDRESS);
        vm.expectRevert();
        safe.setAllowance(WETH_ADDRESS, NULL_ADDRESS, type(uint256).max);
    }

    ///////////////////////
    // updateAdminSigner //
    ///////////////////////

    function testUpdateAdminSignerFromAdmin() public {
        // Test that the admin address can only be updated from the admin signer
        vm.prank(ADMIN_ADDRESS);
        safe.updateAdminSigner(NULL_ADDRESS);
        assertEq(safe.adminAddress(), NULL_ADDRESS, "The admin signer address does not match the expected value.");
    }

    function testUpdateAdminSignerFromNonAdmin() public {
        // Test that the admin address cannot be updated from a non admin signer
        vm.prank(NULL_ADDRESS);
        vm.expectRevert();
        safe.updateAdminSigner(NULL_ADDRESS);
    }

    /////////////////////////
    // updateManagerSigner //
    /////////////////////////

    function testUpdateManagerSignerFromAdmin() public {
        // Test that the signer address can only be updated from the admin signer
        vm.prank(ADMIN_ADDRESS);
        safe.updateManagerSigner(NULL_ADDRESS);
        assertEq(safe.managerAddress(), NULL_ADDRESS, "The manager signer address does not match the expected value.");
    }

    function testUpdateManagerSignerFromNonAdmin() public {
        // Test that the manager address cannot be updated from a non admin signer
        vm.prank(NULL_ADDRESS);
        vm.expectRevert();
        safe.updateManagerSigner(NULL_ADDRESS);
    }

    //////////////////////////
    // transferERC20ToAdmin //
    //////////////////////////

    function testTransferERC20ToAdminFromAdmin() public {
        // Transfer 10 WETH to the safe
        uint256 balance = IWETH(WETH_ADDRESS).balanceOf(ADMIN_ADDRESS);
        vm.prank(NULL_ADDRESS);
        IWETH(WETH_ADDRESS).transfer(address(safe), 10 ether);
        assertEq(IWETH(WETH_ADDRESS).balanceOf(address(safe)), 10 ether);

        // Withraw the 10 WETH to the admin address
        vm.prank(ADMIN_ADDRESS);
        safe.transferERC20ToAdmin(WETH_ADDRESS, 10 ether);
        assertEq(IWETH(WETH_ADDRESS).balanceOf(ADMIN_ADDRESS), balance + 10 ether);
    }

    function testTransferERC20ToAdminFromNonAdmin() public {
        // Transfer 10 WETH to the safe
        vm.prank(NULL_ADDRESS);
        IWETH(WETH_ADDRESS).transfer(address(safe), 10 ether);
        assertEq(IWETH(WETH_ADDRESS).balanceOf(address(safe)), 10 ether);

        // Try to withraw the 10 WETH from a non admin address => expecting to revert
        vm.prank(NULL_ADDRESS);
        vm.expectRevert();
        safe.transferERC20ToAdmin(WETH_ADDRESS, 10 ether);
    }

    ///////////////////////////
    // transferERC721ToAdmin //
    ///////////////////////////

    function testTransferERC721ToAdminFromAdmin() public {
        // Transfer BAYC 69 to the safe
        vm.startPrank(bayc.ownerOf(69));
        IERC721(BAYC_ADDRESS).transferFrom(bayc.ownerOf(69), address(safe), 69); // Transfer the BAYC
        vm.stopPrank();
        assertEq(bayc.ownerOf(69), address(safe), "The ownership of the BAYC token did not transfer correctly.");

        // Withraw the ape
        vm.prank(ADMIN_ADDRESS);
        safe.transferERC721ToAdmin(BAYC_ADDRESS, 69);
        assertEq(bayc.ownerOf(69), ADMIN_ADDRESS, "The ownership of the BAYC token did not transfer correctly.");
    }

    function testTransferERC721ToAdminFromNonAdmin() public {
        // Transfer BAYC 69 to the safe
        vm.startPrank(bayc.ownerOf(69));
        IERC721(BAYC_ADDRESS).transferFrom(bayc.ownerOf(69), address(safe), 69); // Transfer the BAYC
        vm.stopPrank();
        assertEq(bayc.ownerOf(69), address(safe), "The ownership of the BAYC token did not transfer correctly.");

        // Withraw the ape
        vm.prank(NULL_ADDRESS);
        vm.expectRevert();
        safe.transferERC721ToAdmin(BAYC_ADDRESS, 69);
        assertEq(bayc.ownerOf(69), address(safe), "The ownership of the BAYC token did not transfer correctly.");
    }

    //////////////////////
    // isValidSignature //
    //////////////////////

    function testValidSignature() public {
        bytes32 data = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n8payload1"));
        // Signature for the above message using the manager signer
        bytes memory signature =
            hex"869987f4d91d86d9170f692b4826d262aef31b1f6c41dd62b5bdbfd1ad2ca98b5379f81bad2295afa9a2aad7ffbf214f2750be4a9eef785c8a63ac0c9264d0dc1b";
        assertEq(safe.isValidSignature(data, signature), bytes4(0x1626ba7e), "The signature should be valid");
    }

    function testValidSignerButInvalidSignature() public {
        bytes32 data = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n8payload1"));
        // Signature for "payload2" using the manager signer
        bytes memory signature =
            hex"11ab9a183ecb8c423958a0b8f0680d2b76399052031b5bce14593cac500ee50b05b1c88fcdeea041b1da0f151b6ee2c94824e01c78d31917a0a11dc1362999f11b";
        assertEq(safe.isValidSignature(data, signature), bytes4(0), "The signature should be invalid");
    }

    function testInvalidSigner() public {
        bytes32 data = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n8payload1"));
        // Signature for the above message using the admin signer
        bytes memory signature =
            hex"e69397c4bf4def47ecc97afc5e6fedc3c0d43d29d3941fbd42401a25aec657283ff44d84b395bd25b0d6e315865a1fd6ad0b761f7792f615960966e6289e2dc21b";
        assertEq(safe.isValidSignature(data, signature), bytes4(0), "The signature should be invalid");
    }
}
