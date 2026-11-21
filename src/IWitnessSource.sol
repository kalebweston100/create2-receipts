// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title IWitnessSource
 * @notice Out-of-band hint channel for receipt constructors.
 *
 * A receipt's address commits to its creation code and its claim. Some claims are
 * cheap to verify only with extra data (a "witness"): for example, the predecessor
 * value in an inductive chain. Putting that data in the claim would make the receipt
 * address depend on it, so anyone looking the fact up would have to know it too.
 *
 * Instead, the issuer exposes the witness for the duration of one `issue` call, and the
 * receipt constructor pulls it from `msg.sender`. The witness is never trusted: a
 * constructor must verify anything it reads from it, so a lying issuer can only make
 * issuance fail, never make a false receipt exist.
 */
interface IWitnessSource {
    /// @notice The witness for the receipt currently being created, or empty bytes.
    function witness() external view returns (bytes memory);
}
