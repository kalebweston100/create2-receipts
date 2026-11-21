// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Receipt} from "../Receipt.sol";
import {LibBytecode} from "../LibBytecode.sol";

/**
 * @title OpcodeFreeFact
 * @notice Proves: "no reachable instruction in `target`'s code uses an opcode in `mask`."
 *
 * Claim: abi.encode(address target, uint256 mask)
 *
 * Examples of what this can certify, permanently and without trusting anyone:
 *   - mask = INDESTRUCTIBLE_MASK: the code can never change or disappear.
 *   - add SSTORE (0x55): the contract can never write storage.
 *   - add CALL/CREATE/CREATE2/LOG*: the contract can never call out, deploy or emit.
 *
 * The mask must include INDESTRUCTIBLE_MASK. Otherwise the target might be destroyed
 * and replaced with different code (see LibBytecode), and the fact would not be eternal.
 */
contract OpcodeFreeFact is Receipt {
    error NotEternal();
    error NotAnalyzable(address target);
    error ForbiddenOpcode(address target, uint256 pc, uint8 opcode);

    constructor(bytes memory claim) Receipt(claim) {}

    function _verify(bytes memory claim) internal view override {
        (address target, uint256 mask) = abi.decode(claim, (address, uint256));
        if (mask & LibBytecode.INDESTRUCTIBLE_MASK != LibBytecode.INDESTRUCTIBLE_MASK) revert NotEternal();

        bytes memory code = target.code;
        if (!LibBytecode.isAnalyzable(code)) revert NotAnalyzable(target);

        (bool found, uint256 pc) = LibBytecode.findReachable(code, mask);
        if (found) revert ForbiddenOpcode(target, pc, uint8(code[pc]));
    }
}
