// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

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
 * exact claim. The only way around it is a CREATE2 address collision.
 *
 * Rules for receipt types:
 *   - `_verify` is `view`: verification cannot change any state.
 *   - Claims must be eternal: about pure computation, or about code that can never
 *     change (see LibBytecode.INDESTRUCTIBLE_MASK), never about mutable state.
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
}
