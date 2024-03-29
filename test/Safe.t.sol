// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {Safe} from "../src/Safe.sol";
import {SafeV2} from "./SafeV2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

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
    Safe public safeLogic;
    ERC1967Proxy public proxy;

    address private constant WETH = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address private constant BAYC = address(0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D);
    address private constant OWNER = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    address private constant MANAGER = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
    address private constant NULL = address(0x0000000000000000000000000000000000000000);

    IERC721 private bayc = IERC721(BAYC);

    function setUp() public {
        // Deploy the safe
        safeLogic = new Safe();

        // Deploy the proxy, pointing to the implementation and initializing it
        vm.prank(OWNER);
        bytes memory initData = abi.encodeWithSelector(Safe.initialize.selector, MANAGER);
        proxy = new ERC1967Proxy(address(safeLogic), initData);

        // Cast the proxy to the SafeUUPSUpgradeable interface to interact with it
        safe = Safe(address(proxy));

        // Ensure initialization
        assertEq(safe.manager(), MANAGER, "Manager address incorrect after initialization.");
        assertEq(safe.owner(), OWNER, "Owner address incorrect after initialization.");
        assertTrue(safe.owner() != address(0), "Owner not initialized correctly.");
    }

    ///////////
    // proxy //
    ///////////

    error OwnableUnauthorizedAccount(address caller);

    /**
     * Test that the logic cannot be re-initialized
     */
    function testReInitialization() public {
        vm.expectRevert(bytes4(keccak256("InvalidInitialization()")));
        safe.initialize(NULL);
    }

    /**
     * Test that:
     * - proxy can upgrade to a new logic successfully
     * - state is preserved after the upgrade
     */
    function testUpgradeFunctionalityFromAdmin() public {
        // Deploy the new version of the contract
        Safe safeV2Logic = new SafeV2();
        assertTrue(address(safeV2Logic) != address(safeLogic));

        // Perform the upgrade
        vm.prank(OWNER);
        bytes memory payload = abi.encodeWithSignature("initializeV2()");
        safe.upgradeToAndCall(address(safeV2Logic), payload);

        // Validate that the proxy now delegates calls to the new logic
        SafeV2 safeV2 = SafeV2(address(proxy));
        assertTrue(safeV2.safeV2Enabled(), "Proxy not redirecting to the SafeV2 logic.");

        // Check that the state is intact
        assertEq(safeV2.owner(), OWNER, "Admin address is incorrect after upgrade.");
        assertEq(safeV2.manager(), MANAGER, "Manager address is incorrect after upgrade.");
    }

    /**
     * Test that the proxy logic cannot be changed from a non owner address
     */
    function testUpgradeFunctionalityFromNonAdmin() public {
        Safe safeV2Logic = new SafeV2();
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, MANAGER));
        safe.upgradeToAndCall(address(safeV2Logic), abi.encodeWithSignature("initializeV2()"));
    }

    //////////////////
    // setAllowance //
    //////////////////

    /**
     * Test:
     * - allowance is 0 by default
     * - allowance can be changed to infinite
     * - can be reverted to 0 thereafter
     */
    function testSetAllowanceFromOwner() public {
        // Test that the allowance is 0 by default
        assertEq(
            IWETH(WETH).allowance(address(safe), NULL),
            0,
            "The allowance does not match the expected value."
        );

        // Test that the allowance can be changed to infinite
        vm.prank(OWNER);
        safe.setAllowance(WETH, NULL, type(uint256).max);
        assertEq(
            IWETH(WETH).allowance(address(safe), NULL),
            type(uint256).max,
            "The allowance does not match the expected value."
        );

        // Test that the allowance can be reverted to 0 thereafter
        vm.prank(OWNER);
        safe.setAllowance(WETH, NULL, 0);
        assertEq(
            IWETH(WETH).allowance(address(safe), NULL),
            0,
            "The allowance does not match the expected value."
        );
    }

    /**
     * Test that the allowance can't be changed by a non owner address
     */
    function testSetAllowanceFromNonOwner() public {
        vm.prank(MANAGER);
        vm.expectRevert();
        safe.setAllowance(WETH, NULL, type(uint256).max);
    }

    ///////////////////////
    // transferOwnership //
    ///////////////////////

    /**
     * Test that the owner can only be updated by the owner
     */
    function testTransferOwnershipFromOwner() public {
        vm.prank(OWNER);
        safe.transferOwnership(MANAGER);
        assertEq(safe.owner(), MANAGER, "The admin signer address does not match the expected value.");
    }

    /**
     * Test that the owner cannot be updated from a non owner
     */
    function testTransferOwnershipFromNonOwner() public {
        vm.prank(MANAGER);
        vm.expectRevert();
        safe.transferOwnership(MANAGER);
    }

    ////////////////////////
    // transferManagement //
    ////////////////////////

    /** 
     * Test that the manager can only be updated by the owner
     */ 
    function testTransferManagementFromOwner() public {
        vm.prank(OWNER);
        safe.transferManagement(NULL);
        assertEq(safe.manager(), NULL, "The manager signer address does not match the expected value.");
    }

    /** 
     * Test that the manager cannot be updated from a non owner
     */ 
    function testTransferManagementFromNonOwner() public {
        vm.prank(NULL);
        vm.expectRevert();
        safe.transferManagement(NULL);
    }

    //////////////////////////
    // transferERC20ToAdmin //
    //////////////////////////

    function testTransferERC20ToAdminFromOwner() public {
        // Transfer 10 WETH to the safe
        uint256 balance = IWETH(WETH).balanceOf(OWNER);
        vm.prank(NULL);
        IWETH(WETH).transfer(address(safe), 10 ether);
        assertEq(IWETH(WETH).balanceOf(address(safe)), 10 ether);

        // Withraw the 10 WETH to the admin address
        vm.prank(OWNER);
        safe.transferERC20ToAdmin(WETH, 10 ether);
        assertEq(IWETH(WETH).balanceOf(OWNER), balance + 10 ether);
    }

    function testTransferERC20ToAdminFromNonOwner() public {
        // Transfer 10 WETH to the safe
        vm.prank(NULL);
        IWETH(WETH).transfer(address(safe), 10 ether);
        assertEq(IWETH(WETH).balanceOf(address(safe)), 10 ether);

        // Try to withraw the 10 WETH from a non admin address => expecting to revert
        vm.prank(NULL);
        vm.expectRevert();
        safe.transferERC20ToAdmin(WETH, 10 ether);
    }

    ///////////////////////////
    // transferERC721ToAdmin //
    ///////////////////////////

    function testTransferERC721ToAdminFromOwner() public {
        // Transfer BAYC 69 to the safe
        vm.startPrank(bayc.ownerOf(69));
        bayc.transferFrom(bayc.ownerOf(69), address(safe), 69); // Transfer the BAYC
        vm.stopPrank();
        assertEq(bayc.ownerOf(69), address(safe), "The ownership of the BAYC token did not transfer correctly.");

        // Withraw the ape
        vm.prank(OWNER);
        safe.transferERC721ToAdmin(BAYC, 69);
        assertEq(bayc.ownerOf(69), OWNER, "The ownership of the BAYC token did not transfer correctly.");
    }

    function testTransferERC721ToAdminFromNonOwner() public {
        // Transfer BAYC 69 to the safe
        vm.startPrank(bayc.ownerOf(69));
        bayc.transferFrom(bayc.ownerOf(69), address(safe), 69); // Transfer the BAYC
        vm.stopPrank();
        assertEq(bayc.ownerOf(69), address(safe), "The ownership of the BAYC token did not transfer correctly.");

        // Withraw the ape
        vm.prank(NULL);
        vm.expectRevert();
        safe.transferERC721ToAdmin(BAYC, 69);
        assertEq(bayc.ownerOf(69), address(safe), "The ownership of the BAYC token did not transfer correctly.");
    }

    //////////////////////
    // isValidSignature //
    //////////////////////

    function testValidSignature() public view {
        bytes32 data = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n8payload1"));
        // Signature for the above message using the manager signer
        bytes memory signature =
            hex"869987f4d91d86d9170f692b4826d262aef31b1f6c41dd62b5bdbfd1ad2ca98b5379f81bad2295afa9a2aad7ffbf214f2750be4a9eef785c8a63ac0c9264d0dc1b";
        assertEq(safe.isValidSignature(data, signature), bytes4(0x1626ba7e), "The signature should be valid");
    }

    function testValidSignerButInvalidSignature() public view {
        bytes32 data = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n8payload1"));
        // Signature for "payload2" using the manager signer
        bytes memory signature =
            hex"11ab9a183ecb8c423958a0b8f0680d2b76399052031b5bce14593cac500ee50b05b1c88fcdeea041b1da0f151b6ee2c94824e01c78d31917a0a11dc1362999f11b";
        assertEq(safe.isValidSignature(data, signature), bytes4(0), "The signature should be invalid");
    }

    function testInvalidSigner() public view {
        bytes32 data = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n8payload1"));
        // Signature for the above message using the owner signer
        bytes memory signature =
            hex"e69397c4bf4def47ecc97afc5e6fedc3c0d43d29d3941fbd42401a25aec657283ff44d84b395bd25b0d6e315865a1fd6ad0b761f7792f615960966e6289e2dc21b";
        assertEq(safe.isValidSignature(data, signature), bytes4(0), "The signature should be invalid");
    }
}
