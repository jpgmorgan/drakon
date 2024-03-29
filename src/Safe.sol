pragma solidity ^0.8.25;

// SPDX-License-Identifier: MIT
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract Safe is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    // Signers
    address public admin;
    address public manager;

    // Events
    event AdminAddressUpdated(address indexed newSigner);
    event ManagerAddressUpdated(address indexed newSigner);

    // Errors
    error Unauthorized();
    error TokenApprovalFailed();
    error TokenTransferFailed();

    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin, address _manager) public initializer {
        __Ownable_init(msg.sender); //sets owner to msg.sender
        __UUPSUpgradeable_init();
        admin = _admin;
        manager = _manager;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    function setAllowance(address tokenAddr, address contractAddr, uint256 allowance) external onlyAdmin {
        bool success = IERC20(tokenAddr).approve(contractAddr, allowance);
        if (!success) revert TokenApprovalFailed();
    }

    function updateAdmin(address newSigner) external onlyAdmin {
        admin = newSigner;
        emit AdminAddressUpdated(newSigner);
    }

    function updateManager(address newSigner) external onlyAdmin {
        manager = newSigner;
        emit ManagerAddressUpdated(newSigner);
    }

    function transferERC20ToAdmin(address tokenContract, uint256 amount) external onlyAdmin {
        bool success = IERC20(tokenContract).transferFrom(address(this), admin, amount);
        if (!success) revert TokenTransferFailed();
    }

    function transferERC721ToAdmin(address nftContract, uint256 tokenId) external onlyAdmin {
        IERC721(nftContract).safeTransferFrom(address(this), admin, tokenId);
    }

    function isValidSignature(bytes32 _data, bytes memory _signature) external view returns (bytes4 magicValue) {
        // Using ecrecover to ensure that the signature is valid and comes from the manager
        uint8 v = uint8(_signature[64]);
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
        }

        if (ecrecover(_data, v, r, s) == manager) {
            return bytes4(0x1626ba7e); // Return magic value for ERC-1271 compliant validation
        }

        return bytes4(0); // Return an invalid magic value otherwise
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
