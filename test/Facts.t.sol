// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {ReceiptIssuer} from "../src/ReceiptIssuer.sol";
import {LibReceipt} from "../src/LibReceipt.sol";
import {LibBytecode} from "../src/LibBytecode.sol";
import {OpcodeFreeFact} from "../src/facts/OpcodeFreeFact.sol";
import {CloneFact} from "../src/facts/CloneFact.sol";

/// @dev A pure contract: no storage writes, no calls, no logs.
contract Adder {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}

/// @dev Writes storage.
contract Counter {
    uint256 public count;

    function increment() external {
        count += 1;
    }
}

contract FactsTest is Test {
    // forge-lint: disable-start(incorrect-shift)
    /// @dev "Pure module": cannot write state, call out, deploy, emit or self-destruct.
    uint256 internal constant PURE_MASK = LibBytecode.INDESTRUCTIBLE_MASK | (1 << 0x55) // SSTORE
        | (1 << 0x5d) // TSTORE
        | (1 << 0xf0) | (1 << 0xf5) // CREATE, CREATE2
        | (1 << 0xf1) | (1 << 0xfa) // CALL, STATICCALL
        | (1 << 0xa0) | (1 << 0xa1) | (1 << 0xa2) | (1 << 0xa3) | (1 << 0xa4); // LOG0..LOG4
    // forge-lint: disable-end(incorrect-shift)

    ReceiptIssuer internal issuer;
    bytes internal opcodeFreeType;
    bytes internal cloneType;

    function setUp() public {
        issuer = new ReceiptIssuer();
        opcodeFreeType = type(OpcodeFreeFact).creationCode;
        cloneType = type(CloneFact).creationCode;
    }

    /// @dev Deploys a standard EIP-1167 minimal proxy pointing at `implementation`.
    function _clone(address implementation) internal returns (address instance) {
        bytes memory initcode = abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3"
        );
        assembly {
            instance := create(0, add(initcode, 32), mload(initcode))
        }
        require(instance != address(0), "clone failed");
    }

    // ---------------------------------------------------------------------
    // OpcodeFreeFact
    // ---------------------------------------------------------------------

    function test_opcodeFree_certifiesPureContract() public {
        address adder = address(new Adder());
        bytes memory claim = abi.encode(adder, PURE_MASK);

        uint256 g = gasleft();
        issuer.issue(opcodeFreeType, claim, "");
        emit log_named_uint("issue gas, pure-module certificate", g - gasleft());

        assertTrue(LibReceipt.isProven(address(issuer), opcodeFreeType, claim));
    }

    function test_opcodeFree_rejectsStorageWriter() public {
        address counter = address(new Counter());
        bytes memory claim = abi.encode(counter, PURE_MASK);

        vm.expectPartialRevert(OpcodeFreeFact.ForbiddenOpcode.selector);
        issuer.issue(opcodeFreeType, claim, "");
        assertFalse(LibReceipt.isProven(address(issuer), opcodeFreeType, claim));
    }

    function test_opcodeFree_reportsOffendingInstruction() public {
        address target = makeAddr("target");
        vm.etch(target, hex"6000f4"); // PUSH1 0, DELEGATECALL

        vm.expectRevert(abi.encodeWithSelector(OpcodeFreeFact.ForbiddenOpcode.selector, target, 2, uint8(0xf4)));
        issuer.issue(opcodeFreeType, abi.encode(target, LibBytecode.INDESTRUCTIBLE_MASK), "");
    }

    function test_opcodeFree_requiresEternalMask() public {
        address adder = address(new Adder());
        vm.expectRevert(OpcodeFreeFact.NotEternal.selector);
        issuer.issue(opcodeFreeType, abi.encode(adder, uint256(1 << 0x55)), "");
    }

    function test_opcodeFree_rejectsAccountsWithoutCode() public {
        address eoa = makeAddr("eoa");
        vm.expectRevert(abi.encodeWithSelector(OpcodeFreeFact.NotAnalyzable.selector, eoa));
        issuer.issue(opcodeFreeType, abi.encode(eoa, PURE_MASK), "");
    }

    function test_opcodeFree_rejectsEip7702Accounts() public {
        address delegated = makeAddr("delegated");
        vm.etch(delegated, abi.encodePacked(hex"ef0100", address(new Adder())));

        vm.expectRevert(abi.encodeWithSelector(OpcodeFreeFact.NotAnalyzable.selector, delegated));
        issuer.issue(opcodeFreeType, abi.encode(delegated, PURE_MASK), "");
    }

    function test_opcodeFree_ignoresDeadCode() public {
        address target = makeAddr("target");
        vm.etch(target, hex"00fff4f2"); // STOP, then unreachable forbidden bytes
        bytes memory claim = abi.encode(target, LibBytecode.INDESTRUCTIBLE_MASK);

        issuer.issue(opcodeFreeType, claim, "");
        assertTrue(LibReceipt.isProven(address(issuer), opcodeFreeType, claim));
    }

    // ---------------------------------------------------------------------
    // CloneFact
    // ---------------------------------------------------------------------

    function test_clone_certifiesMinimalProxy() public {
        address implementation = address(new Adder());
        address clone = _clone(implementation);
        bytes memory claim = abi.encode(clone, implementation);

        issuer.issue(cloneType, claim, "");

        assertTrue(LibReceipt.isProven(address(issuer), cloneType, claim));
        assertEq(Adder(clone).add(2, 3), 5);
    }

    function test_clone_rejectsWrongImplementation() public {
        address implementation = address(new Adder());
        address other = address(new Adder());
        address clone = _clone(implementation);

        vm.expectRevert(abi.encodeWithSelector(CloneFact.NotAClone.selector, clone, other));
        issuer.issue(cloneType, abi.encode(clone, other), "");
    }

    function test_clone_rejectsNonClone() public {
        address implementation = address(new Adder());
        address notAClone = address(new Adder());

        vm.expectRevert(abi.encodeWithSelector(CloneFact.NotAClone.selector, notAClone, implementation));
        issuer.issue(cloneType, abi.encode(notAClone, implementation), "");
    }

    /// @dev An implementation that can SELFDESTRUCT could destroy a same-transaction clone,
    ///      letting different code appear at the clone's address later (a metamorphic
    ///      contract). The fact would not be eternal, so it is refused.
    function test_clone_rejectsDestructibleImplementation() public {
        address implementation = makeAddr("implementation");
        vm.etch(implementation, hex"33ff"); // CALLER, SELFDESTRUCT
        address clone = _clone(implementation);

        vm.expectRevert(abi.encodeWithSelector(CloneFact.ImplementationNotEternal.selector, implementation, 1));
        issuer.issue(cloneType, abi.encode(clone, implementation), "");
    }
}
