// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title LibReceipt
 * @notice Address derivation and lookup for CREATE2 receipts.
 *
 * A fact is the triple (issuer, receipt creation code, claim). Its receipt lives at
 *
 *     CREATE2(issuer, salt = 0, keccak256(creationCode ‖ abi.encode(claim)))
 *
 * and the fact is proven if and only if that address holds the 1-byte receipt marker.
 * Looking a fact up never calls into anything: it is one hash plus one EXTCODEHASH.
 */
library LibReceipt {
    /// @notice Runtime code of every receipt: a single STOP byte.
    bytes1 internal constant MARKER = 0x00;

    /// @notice keccak256 of the receipt marker. EXTCODEHASH of a live receipt equals this.
    bytes32 internal constant MARKER_HASH = keccak256(hex"00");

    /// @notice Initcode that issues the receipt for `claim` under receipt type `creationCode`.
    function initcode(bytes memory creationCode, bytes memory claim) internal pure returns (bytes memory) {
        return abi.encodePacked(creationCode, abi.encode(claim));
    }

    /// @notice Address of a receipt given its issuer and initcode hash.
    function addressOf(address issuer, bytes32 initcodeHash) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), issuer, bytes32(0), initcodeHash)))));
    }

    /// @notice Address of the receipt for `claim` under receipt type `creationCode`.
    function addressOf(address issuer, bytes memory creationCode, bytes memory claim) internal pure returns (address) {
        return addressOf(issuer, keccak256(initcode(creationCode, claim)));
    }

    /// @notice Whether `account` holds a live receipt marker.
    /// @dev Checks the exact marker codehash rather than just non-empty code. An account
    ///      with arbitrary code (or an EIP-7702 delegation designator) at a colliding
    ///      address is therefore never mistaken for a receipt; only an attacker who both
    ///      wins a ~2^80 address collision AND deploys the marker could fake one.
    function isReceipt(address account) internal view returns (bool) {
        return account.codehash == MARKER_HASH;
    }

    /// @notice Whether the fact (issuer, creationCode, claim) has been proven.
    function isProven(address issuer, bytes memory creationCode, bytes memory claim) internal view returns (bool) {
        return isReceipt(addressOf(issuer, creationCode, claim));
    }
}
