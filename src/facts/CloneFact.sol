// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Receipt} from "../Receipt.sol";
import {LibBytecode} from "../LibBytecode.sol";

/**
 * @title CloneFact
 * @notice Proves: "`clone` is an EIP-1167 minimal proxy permanently bound to `implementation`."
 *
 * Claim: abi.encode(address clone, address implementation)
 *
 * The clone's code must be exactly the 45-byte EIP-1167 runtime pointing at
 * `implementation`. Because a clone DELEGATECALLs into its implementation, the
 * implementation's code runs in the clone's context. If it could SELFDESTRUCT (directly
 * or through further delegation), a clone created in the same transaction could be
 * destroyed and replaced. So the implementation must also be indestructible.
 */
contract CloneFact is Receipt {
    error NotAClone(address clone, address implementation);
    error NotAnalyzable(address implementation);
    error ImplementationNotEternal(address implementation, uint256 pc);

    constructor(bytes memory claim) Receipt(claim) {}

    function _verify(bytes memory claim) internal view override {
        (address clone, address implementation) = abi.decode(claim, (address, address));

        bytes32 expected =
            keccak256(abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3"));
        if (clone.codehash != expected) revert NotAClone(clone, implementation);

        bytes memory implCode = implementation.code;
        if (!LibBytecode.isAnalyzable(implCode)) revert NotAnalyzable(implementation);
        (bool found, uint256 pc) = LibBytecode.findReachable(implCode, LibBytecode.INDESTRUCTIBLE_MASK);
        if (found) revert ImplementationNotEternal(implementation, pc);
    }
}
