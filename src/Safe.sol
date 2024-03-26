// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract Safe {
    // Signers
    address public adminAddress;
    address public managerAddress;

    // Events
    event AdminAddressUpdated(address indexed newSigner);
    event ManagerAddressUpdated(address indexed newSigner);

    constructor(address _adminAddress, address _managerAddress) {
        adminAddress = _adminAddress;
        managerAddress = _managerAddress;
    }

    modifier onlyAdmin() {
        require(msg.sender == adminAddress, "Only the allowed signer can execute this");
        _;
    }

    function setAllowance(address tokenAddr, address contractAddr, uint256 allowance) external onlyAdmin {
        bool success = IERC20(tokenAddr).approve(contractAddr, allowance);
        require(success, "Token approval failed");
    }

    function updateAdminSigner(address newSigner) external onlyAdmin {
        adminAddress = newSigner;
        emit AdminAddressUpdated(newSigner);
    }

    function updateManagerSigner(address newSigner) external onlyAdmin {
        managerAddress = newSigner;
        emit ManagerAddressUpdated(newSigner);
    }

    function transferERC20ToAdmin(address tokenContract, uint256 amount) external onlyAdmin {
        bool success = IERC20(tokenContract).transferFrom(address(this), adminAddress, amount);
        require(success, "Transfer failed");
    }

    function transferERC721ToAdmin(address nftContract, uint256 tokenId) external onlyAdmin {
        IERC721(nftContract).safeTransferFrom(address(this), adminAddress, tokenId);
    }

    function isValidSignature(bytes32 _data, bytes memory _signature) external view returns (bytes4 magicValue) {
        // Using ecrecover to ensure that the signature is valid and comes from the managerSignerAddress
        uint8 v = uint8(_signature[64]);
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
        }

        if (ecrecover(_data, v, r, s) == managerAddress) {
            return bytes4(0x1626ba7e); // Return magic value for ERC-1271 compliant validation
        }

        return bytes4(0); // Return an invalid magic value otherwise
    }
}
