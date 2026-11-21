// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IWitnessSource} from "./IWitnessSource.sol";

/**
 * @title Receipt
 * @notice Base contract for CREATE2 receipts: contracts whose existence proves a claim.
 *
 * A receipt type is a contract inheriting `Receipt` that implements `_verify`. Its
 * constructor runs `_verify(claim)`; if the claim is false, `_verify` reverts
 * and nothing is ever deployed. If the claim holds, the constructor returns a single
 * 0x00 byte as the contract's runtime code: the receipt marker.
 *
 * Soundness rests on two facts about CREATE2:
 *   1. The legitimate constructor with a false claim reverts, so the legitimate
 *      address for that claim stays empty forever.
 *   2. Any other initcode (another constructor, or this one with different
 *      arguments) hashes differently and lands at a different address.
 * So a marker at the legitimate address means this exact constructor accepted this
 * exact claim. The only way around it is a ~2^80 CREATE2 address collision.
 *
 * Rules for receipt types:
 *   - `_verify` is `view`: verification cannot change any state.
 *   - Claims must be eternal: about pure computation, or about code that can never
 *     change (see LibBytecode.INDESTRUCTIBLE_MASK), never about mutable state.
 *   - Anything read via `_witness()` must be verified; it is untrusted input.
 *   - The derived contract's own constructor body must be empty: this base
 *     constructor ends creation with RETURN, so nothing after it runs.
 */
abstract contract Receipt {
    /// @notice Generic rejection; receipt types may use more specific errors.
    error ClaimRejected();

    constructor(bytes memory claim) {
        _verify(claim);
        assembly ("memory-safe") {
            mstore(0, 0)
            return(0, 1) // runtime code = 0x00 (the receipt marker)
        }
    }

    /// @notice Revert unless `claim` holds.
    function _verify(bytes memory claim) internal view virtual;

    /// @notice Fetches the untrusted witness from the issuer (msg.sender during construction).
    /// @dev Lazy: only receipt types that need a witness call this, so plain receipts work
    ///      with any CREATE2 deployer, including ones without a witness channel. Any
    ///      failure yields an empty witness. That is safe: the witness is never trusted,
    ///      so a missing one can only make verification fail.
    function _witness() internal view returns (bytes memory w) {
        (bool ok, bytes memory ret) = msg.sender.staticcall(abi.encodeCall(IWitnessSource.witness, ()));
        if (ok && ret.length >= 64) w = abi.decode(ret, (bytes));
    }

    /// @notice This receipt type's own creation code, recovered from the running initcode.
    /// @dev During construction, CODECOPY reads the initcode, which is the creation code
    ///      followed by abi.encode(claim). That lets a receipt type compute the addresses
    ///      of other receipts of the same type (e.g. its predecessor in an inductive
    ///      chain), something `type(C).creationCode` cannot do from inside C.
    ///      Assumes the canonical encoding LibReceipt produces. A non-canonical encoding
    ///      only makes those lookups miss (a false negative), never a false positive.
    function _selfCreationCode(uint256 claimLength) internal pure returns (bytes memory code) {
        // abi.encode(bytes): offset word + length word + data padded to 32 bytes.
        uint256 argsLength = 64 + ((claimLength + 31) & ~uint256(31));
        assembly ("memory-safe") {
            let size := sub(codesize(), argsLength)
            code := mload(0x40)
            mstore(code, size)
            codecopy(add(code, 32), 0, size)
            mstore(0x40, add(add(code, 32), and(add(size, 31), not(31))))
        }
    }
}
