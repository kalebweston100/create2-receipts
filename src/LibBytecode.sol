// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title LibBytecode
 * @notice Sound static analysis of EVM bytecode.
 *
 * `findReachable` reports the first instruction that could ever execute and whose
 * opcode is in a forbidden set. It is sound (no false negatives) because it mirrors how
 * the EVM itself decides what can run:
 *
 *   - Instruction boundaries come from a linear sweep that skips PUSH immediates. The
 *     EVM's JUMPDEST analysis uses the same sweep, so bytes inside PUSH data can never
 *     execute and are correctly ignored.
 *   - After an instruction that never falls through (STOP, JUMP, RETURN, REVERT,
 *     INVALID, SELFDESTRUCT), the following bytes are unreachable until the next
 *     JUMPDEST: falling through is impossible, and jumps may only land on a JUMPDEST.
 *     This skips data appended after code (e.g. solc's metadata trailer) without
 *     trusting any length field the code itself claims.
 *
 * It is incomplete (it may report an instruction that no real execution reaches),
 * which only ever makes a claim fail, never pass.
 */
library LibBytecode {
    uint256 internal constant OP_CALLCODE = 0xf2;
    uint256 internal constant OP_DELEGATECALL = 0xf4;
    uint256 internal constant OP_SELFDESTRUCT = 0xff;

    /**
     * @notice Opcodes whose absence makes code permanent.
     * @dev Since EIP-6780, SELFDESTRUCT deletes an account only within the transaction
     *      that created it. That still allows a metamorphic attack: create a contract,
     *      obtain a receipt about its code, destroy it and later redeploy different code
     *      at the same address, all starting in one transaction. Code with no reachable
     *      SELFDESTRUCT, DELEGATECALL or CALLCODE can never destroy itself, so facts
     *      about it are eternal.
     */
    // forge-lint: disable-start(incorrect-shift)
    uint256 internal constant INDESTRUCTIBLE_MASK = (1 << OP_SELFDESTRUCT) | (1 << OP_DELEGATECALL)
        | (1 << OP_CALLCODE);

    // forge-lint: disable-end(incorrect-shift)

    /// @notice Whether `code` can be analyzed as ordinary contract code.
    /// @dev Rejects empty code and anything starting with 0xEF. EIP-3541 forbids deploying
    ///      such code, so a leading 0xEF means an EIP-7702 delegation designator: an EOA
    ///      whose code its owner can repoint at any time, so it has no permanent code.
    function isAnalyzable(bytes memory code) internal pure returns (bool) {
        return code.length != 0 && code[0] != 0xef;
    }

    /**
     * @notice Finds the first reachable instruction whose opcode bit is set in `mask`.
     * @param code Runtime bytecode to scan.
     * @param mask Bitmap of forbidden opcodes: bit i set forbids opcode i.
     * @return found Whether a forbidden reachable instruction exists.
     * @return offset Its byte offset (0 if none).
     */
    function findReachable(bytes memory code, uint256 mask) internal pure returns (bool found, uint256 offset) {
        assembly ("memory-safe") {
            let start := add(code, 32)
            let end := add(start, mload(code))
            let reachable := 1
            for { let p := start } lt(p, end) {} {
                let op := byte(0, mload(p))

                // A JUMPDEST at an instruction boundary is a valid entry point.
                if and(iszero(reachable), eq(op, 0x5b)) { reachable := 1 }

                if reachable {
                    if and(shr(op, mask), 1) {
                        found := 1
                        offset := sub(p, start)
                        break
                    }
                    // STOP, JUMP, RETURN, REVERT, INVALID, SELFDESTRUCT never fall through.
                    if or(
                        or(iszero(op), eq(op, 0x56)),
                        or(or(eq(op, 0xf3), eq(op, 0xfd)), or(eq(op, 0xfe), eq(op, 0xff)))
                    ) { reachable := 0 }
                }

                // Advance past the opcode and any PUSH1..PUSH32 immediate.
                p := add(p, 1)
                if and(gt(op, 0x5f), lt(op, 0x80)) { p := add(p, sub(op, 0x5f)) }
            }
        }
    }
}
