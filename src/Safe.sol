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
    address public manager;

    // Events
    event ManagerAddressUpdated(address indexed newSigner);

    // Errors
    error TokenApprovalFailed();
    error TokenTransferFailed();

    constructor() {
        _disableInitializers();
    }

    function initialize(address _manager) public initializer {
        __Ownable_init(msg.sender); //sets owner to msg.sender
        __UUPSUpgradeable_init();
        manager = _manager;
    }

    function setAllowance(address tokenAddr, address contractAddr, uint256 allowance) external onlyOwner {
        bool success = IERC20(tokenAddr).approve(contractAddr, allowance);
        if (!success) revert TokenApprovalFailed();
    }

    function transferManagement(address newSigner) external onlyOwner {
        manager = newSigner;
        emit ManagerAddressUpdated(newSigner);
    }

    function transferERC20ToOwner(address tokenContract, uint256 amount) external onlyOwner {
        bool success = IERC20(tokenContract).transferFrom(address(this), owner(), amount);
        if (!success) revert TokenTransferFailed();
    }

    function transferERC721ToOwner(address nftContract, uint256 tokenId) external onlyOwner {
        IERC721(nftContract).safeTransferFrom(address(this), owner(), tokenId);
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
