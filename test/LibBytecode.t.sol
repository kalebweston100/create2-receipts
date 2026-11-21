// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {LibBytecode} from "../src/LibBytecode.sol";

contract LibBytecodeTest is Test {
    uint256 internal constant M = LibBytecode.INDESTRUCTIBLE_MASK;

    function _find(bytes memory code) internal pure returns (bool found, uint256 offset) {
        return LibBytecode.findReachable(code, M);
    }

    // ---------------------------------------------------------------------
    // unit cases
    // ---------------------------------------------------------------------

    function test_flagsReachableForbiddenOpcode() public pure {
        (bool found, uint256 offset) = _find(hex"6000ff"); // PUSH1 0x00, SELFDESTRUCT
        assertTrue(found);
        assertEq(offset, 2);
    }

    function test_ignoresForbiddenByteInsidePushData() public pure {
        (bool found,) = _find(hex"60ff00"); // PUSH1 0xff, STOP
        assertFalse(found);
        (found,) = _find(hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // PUSH32 of 0xff..
        assertFalse(found);
    }

    function test_pushDataRunningPastEndIsHarmless() public pure {
        (bool found,) = _find(hex"7f"); // PUSH32 with no data
        assertFalse(found);
    }

    function test_ignoresBytesAfterTerminatorUntilJumpdest() public pure {
        bytes[6] memory terminators = [bytes(hex"00"), hex"56", hex"f3", hex"fd", hex"fe", hex"ff"];
        for (uint256 i; i < terminators.length; ++i) {
            // terminator, then a forbidden byte nothing can reach
            bytes memory code = abi.encodePacked(terminators[i], hex"f4");
            (bool found, uint256 offset) = _find(code);
            if (uint8(terminators[i][0]) == 0xff) {
                // SELFDESTRUCT is itself forbidden and reached first
                assertTrue(found);
                assertEq(offset, 0);
            } else {
                assertFalse(found, "dead byte after terminator must be ignored");
            }
        }
    }

    function test_jumpdestReopensReachability() public pure {
        (bool found, uint256 offset) = _find(hex"005bf4"); // STOP, JUMPDEST, DELEGATECALL
        assertTrue(found);
        assertEq(offset, 2);
    }

    function test_jumpdestInsidePushDataDoesNotReopen() public pure {
        (bool found,) = _find(hex"00605bf4"); // STOP, PUSH1 0x5b, (0xf4 dead)
        // 0x60 is in dead code; its immediate 0x5b is push data, not a JUMPDEST;
        // the following 0xf4 is still unreachable.
        assertFalse(found);
    }

    function test_jumpiFallsThrough() public pure {
        (bool found, uint256 offset) = _find(hex"6000600057f2"); // PUSH 0, PUSH 0, JUMPI, CALLCODE
        assertTrue(found);
        assertEq(offset, 5);
    }

    function test_solcStyleMetadataTrailerIsIgnored() public pure {
        // STOP, INVALID, then trailer bytes containing 0xff/0xf4 that never execute.
        (bool found,) = _find(hex"00fea264697066735822ff1220f4f2ff0033");
        assertFalse(found);
    }

    function test_isAnalyzable() public pure {
        assertFalse(LibBytecode.isAnalyzable(""));
        assertFalse(LibBytecode.isAnalyzable(hex"ef0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assertTrue(LibBytecode.isAnalyzable(hex"00"));
    }

    // ---------------------------------------------------------------------
    // differential fuzz against an independent two-pass reference
    // ---------------------------------------------------------------------

    /// @dev Pass 1 marks instruction boundaries; pass 2 tracks reachability.
    function _reference(bytes memory code, uint256 mask) internal pure returns (bool, uint256) {
        uint256 len = code.length;
        bool[] memory isInstruction = new bool[](len);
        for (uint256 i; i < len;) {
            isInstruction[i] = true;
            uint8 op = uint8(code[i]);
            i += 1;
            if (op >= 0x60 && op <= 0x7f) i += op - 0x5f;
        }
        bool reachable = true;
        for (uint256 i; i < len; ++i) {
            if (!isInstruction[i]) continue;
            uint8 op = uint8(code[i]);
            if (!reachable && op == 0x5b) reachable = true;
            if (!reachable) continue;
            if ((mask >> op) & 1 == 1) return (true, i);
            if (op == 0x00 || op == 0x56 || op == 0xf3 || op == 0xfd || op == 0xfe || op == 0xff) reachable = false;
        }
        return (false, 0);
    }

    function testFuzz_matchesReference(bytes memory code, uint256 mask) public pure {
        (bool f1, uint256 o1) = LibBytecode.findReachable(code, mask);
        (bool f2, uint256 o2) = _reference(code, mask);
        assertEq(f1, f2);
        assertEq(o1, o2);
    }

    /// @dev Bias toward interesting inputs: few distinct bytes, so terminators, JUMPDESTs,
    ///      PUSHes and forbidden opcodes all show up densely.
    function testFuzz_matchesReferenceDense(bytes32 seed, uint8 length) public pure {
        bytes memory alphabet = hex"005660617f5bf2f4fffefd01";
        bytes memory code = new bytes(length);
        for (uint256 i; i < length; ++i) {
            code[i] = alphabet[uint8(seed[i % 32]) % alphabet.length];
            if (i % 32 == 31) seed = keccak256(abi.encode(seed));
        }
        (bool f1, uint256 o1) = LibBytecode.findReachable(code, M);
        (bool f2, uint256 o2) = _reference(code, M);
        assertEq(f1, f2);
        assertEq(o1, o2);
    }
}
