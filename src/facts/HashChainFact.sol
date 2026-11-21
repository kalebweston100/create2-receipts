// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Receipt} from "../Receipt.sol";
import {LibReceipt} from "../LibReceipt.sol";

/**
 * @title HashChainFact
 * @notice Proves: "applying keccak256 to `seed` `n` times gives `result`." Built
 *         inductively, so arbitrarily long computations are proven across many
 *         transactions and still checked with a single lookup.
 *
 * Claim:   abi.encode(bytes32 seed, uint256 n, bytes32 result)
 * Witness: abi.encode(bytes32 previous) when n > STEP
 *
 * Base case (n <= STEP): compute all n iterations directly.
 * Inductive step (n > STEP): require that the receipt for (seed, n - STEP, previous)
 * already exists under the same issuer, then compute STEP more iterations from
 * `previous`. The witness supplies `previous` without making it part of this
 * receipt's address, and it is trustworthy only because its receipt is checked.
 *
 * By induction over creation order, every receipt of this type is correct, so one
 * existence check at the end vouches for the whole chain.
 */
contract HashChainFact is Receipt {
    /// @notice Iterations computed per receipt.
    uint256 public constant STEP = 256;

    error WrongResult(bytes32 expected, bytes32 actual);
    error MissingPredecessor(bytes32 seed, uint256 n, bytes32 previous);

    constructor(bytes memory claim) Receipt(claim) {}

    function _verify(bytes memory claim) internal view override {
        (bytes32 seed, uint256 n, bytes32 result) = abi.decode(claim, (bytes32, uint256, bytes32));

        bytes32 h = seed;
        uint256 iterations = n;
        if (n > STEP) {
            bytes32 previous = abi.decode(_witness(), (bytes32));
            bytes memory previousClaim = abi.encode(seed, n - STEP, previous);
            // msg.sender is the issuer creating this receipt; the predecessor must have
            // come from the same issuer and the same receipt type.
            if (!LibReceipt.isProven(msg.sender, _selfCreationCode(claim.length), previousClaim)) {
                revert MissingPredecessor(seed, n - STEP, previous);
            }
            h = previous;
            iterations = STEP;
        }

        h = iterate(h, iterations);
        if (h != result) revert WrongResult(result, h);
    }

    /// @notice keccak256 applied `n` times to `h`.
    function iterate(bytes32 h, uint256 n) internal pure returns (bytes32) {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(0, h)
                h := keccak256(0, 32)
            }
        }
        return h;
    }
}
