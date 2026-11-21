// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {ReceiptIssuer} from "../src/ReceiptIssuer.sol";
import {IWitnessSource} from "../src/IWitnessSource.sol";
import {LibReceipt} from "../src/LibReceipt.sol";
import {HashChainFact} from "../src/facts/HashChainFact.sol";

/// @dev An issuer that serves whatever witness its caller asks for. Used to show that a
///      dishonest issuer can make issuance fail but can never make a false receipt exist.
contract LyingIssuer is IWitnessSource {
    bytes private _witness;

    function issue(bytes calldata creationCode, bytes calldata claim, bytes calldata fakeWitness)
        external
        returns (address receipt)
    {
        _witness = fakeWitness;
        bytes memory code = LibReceipt.initcode(creationCode, claim);
        assembly {
            receipt := create2(0, add(code, 32), mload(code), 0)
            if iszero(receipt) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }

    function witness() external view returns (bytes memory) {
        return _witness;
    }
}

contract ReceiptsTest is Test {
    uint256 internal constant STEP = 256;

    /// @dev Runtime code of the keyless deterministic deployer (Arachnid).
    bytes internal constant KEYLESS_DEPLOYER_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    ReceiptIssuer internal issuer;
    bytes internal chainType;

    function setUp() public {
        issuer = new ReceiptIssuer();
        chainType = type(HashChainFact).creationCode;
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    function _hashN(bytes32 h, uint256 n) internal pure returns (bytes32) {
        for (uint256 i; i < n; ++i) {
            h = keccak256(abi.encode(h));
        }
        return h;
    }

    function _claim(bytes32 seed, uint256 n, bytes32 result) internal pure returns (bytes memory) {
        return abi.encode(seed, n, result);
    }

    /// @dev Issues the full inductive chain for keccak^n(seed): one receipt per STEP.
    function _issueChain(bytes32 seed, uint256 n) internal returns (bytes32 result) {
        uint256 first = n % STEP == 0 ? STEP : n % STEP;
        if (n < first) first = n;
        bytes32 previous = _hashN(seed, first);
        issuer.issue(chainType, _claim(seed, first, previous), "");
        for (uint256 k = first + STEP; k <= n; k += STEP) {
            bytes32 next = _hashN(previous, STEP);
            issuer.issue(chainType, _claim(seed, k, next), abi.encode(previous));
            previous = next;
        }
        return previous;
    }

    // ---------------------------------------------------------------------
    // address derivation and the marker
    // ---------------------------------------------------------------------

    function test_receiptLandsAtPredictedAddress() public {
        bytes32 seed = keccak256("seed");
        bytes memory claim = _claim(seed, 10, _hashN(seed, 10));

        address predicted = LibReceipt.addressOf(address(issuer), chainType, claim);
        assertEq(predicted.code.length, 0);

        address receipt = issuer.issue(chainType, claim, "");

        assertEq(receipt, predicted);
        assertEq(
            receipt,
            vm.computeCreate2Address(bytes32(0), keccak256(LibReceipt.initcode(chainType, claim)), address(issuer))
        );
        assertEq(receipt.code, hex"00", "runtime code is the 1-byte marker");
        assertTrue(LibReceipt.isProven(address(issuer), chainType, claim));
    }

    function test_trueClaimIsProven_falseClaimNeverExists() public {
        bytes32 seed = keccak256("seed");
        bytes32 truth = _hashN(seed, 100);
        bytes32 lie = bytes32(uint256(truth) ^ 1);

        issuer.issue(chainType, _claim(seed, 100, truth), "");
        assertTrue(LibReceipt.isProven(address(issuer), chainType, _claim(seed, 100, truth)));

        vm.expectRevert(abi.encodeWithSelector(HashChainFact.WrongResult.selector, lie, truth));
        issuer.issue(chainType, _claim(seed, 100, lie), "");
        assertFalse(LibReceipt.isProven(address(issuer), chainType, _claim(seed, 100, lie)));
        assertEq(LibReceipt.addressOf(address(issuer), chainType, _claim(seed, 100, lie)).code.length, 0);
    }

    function test_issueIsIdempotent() public {
        bytes32 seed = keccak256("seed");
        bytes memory claim = _claim(seed, 5, _hashN(seed, 5));

        vm.recordLogs();
        address first = issuer.issue(chainType, claim, "");
        address second = issuer.issue(chainType, claim, "");

        assertEq(first, second);
        assertEq(vm.getRecordedLogs().length, 1, "only the first issuance emits");
    }

    function test_issueEmitsEvent() public {
        bytes32 seed = keccak256("seed");
        bytes memory claim = _claim(seed, 3, _hashN(seed, 3));
        address predicted = LibReceipt.addressOf(address(issuer), chainType, claim);

        vm.expectEmit(true, true, false, true, address(issuer));
        emit ReceiptIssuer.ReceiptIssued(predicted, keccak256(chainType), claim);
        issuer.issue(chainType, claim, "");
    }

    function test_receiptsAreScopedToTheirIssuer() public {
        bytes32 seed = keccak256("seed");
        bytes memory claim = _claim(seed, 7, _hashN(seed, 7));
        ReceiptIssuer other = new ReceiptIssuer();

        issuer.issue(chainType, claim, "");

        assertTrue(LibReceipt.isProven(address(issuer), chainType, claim));
        assertFalse(LibReceipt.isProven(address(other), chainType, claim));
    }

    /// @dev Deploying the receipt type directly with `new` puts it at a CREATE address
    ///      unrelated to the fact's address, so it proves nothing about lookups.
    function test_deployingOutsideTheIssuerDoesNotCount() public {
        bytes32 seed = keccak256("seed");
        bytes memory claim = _claim(seed, 4, _hashN(seed, 4));

        address direct = address(new HashChainFact(claim));

        assertEq(direct.code, hex"00");
        assertFalse(LibReceipt.isProven(address(issuer), chainType, claim));
    }

    /// @dev Arbitrary code at an address is never mistaken for a receipt.
    function test_isReceiptRequiresExactMarker() public {
        address someone = makeAddr("someone");
        assertFalse(LibReceipt.isReceipt(someone));

        vm.etch(someone, hex"01");
        assertFalse(LibReceipt.isReceipt(someone));

        vm.etch(someone, abi.encodePacked(hex"ef0100", makeAddr("delegate")));
        assertFalse(LibReceipt.isReceipt(someone), "EIP-7702 designator is not a receipt");

        vm.etch(someone, hex"00");
        assertTrue(LibReceipt.isReceipt(someone));
    }

    // ---------------------------------------------------------------------
    // witness channel
    // ---------------------------------------------------------------------

    function test_witnessIsNotPartOfTheAddress() public {
        bytes32 seed = keccak256("seed");
        bytes memory claim = _claim(seed, 9, _hashN(seed, 9));
        address predicted = LibReceipt.addressOf(address(issuer), chainType, claim);

        // The base case ignores the witness, so any witness yields the same receipt.
        assertEq(issuer.issue(chainType, claim, hex"deadbeef"), predicted);
    }

    function test_witnessIsClearedAfterIssue() public {
        bytes32 seed = keccak256("seed");
        issuer.issue(chainType, _claim(seed, 2, _hashN(seed, 2)), hex"0102030405");
        assertEq(issuer.witness().length, 0);
    }

    // ---------------------------------------------------------------------
    // induction
    // ---------------------------------------------------------------------

    function test_inductiveChainProvesLongComputation() public {
        bytes32 seed = keccak256("seed");
        uint256 n = STEP * 5 + 17;

        bytes32 result = _issueChain(seed, n);

        assertEq(result, _hashN(seed, n));
        assertTrue(LibReceipt.isProven(address(issuer), chainType, _claim(seed, n, result)));
    }

    function test_inductiveStepRequiresPredecessor() public {
        bytes32 seed = keccak256("seed");
        bytes32 previous = _hashN(seed, STEP);
        bytes32 next = _hashN(previous, STEP);

        // Skip issuing the base receipt (seed, STEP, previous).
        vm.expectRevert(abi.encodeWithSelector(HashChainFact.MissingPredecessor.selector, seed, STEP, previous));
        issuer.issue(chainType, _claim(seed, 2 * STEP, next), abi.encode(previous));
    }

    function test_inductiveStepRejectsWrongWitness() public {
        bytes32 seed = keccak256("seed");
        bytes32 previous = _issueChain(seed, STEP);
        bytes32 next = _hashN(previous, STEP);
        bytes32 fake = keccak256("fake");

        vm.expectRevert(abi.encodeWithSelector(HashChainFact.MissingPredecessor.selector, seed, STEP, fake));
        issuer.issue(chainType, _claim(seed, 2 * STEP, next), abi.encode(fake));
    }

    /// @dev A dishonest issuer controls the witness completely, yet cannot prove a false
    ///      inductive claim: the predecessor it points at was never proven.
    function test_lyingIssuerCannotForgeInductiveStep() public {
        LyingIssuer liar = new LyingIssuer();
        bytes32 seed = keccak256("seed");
        bytes32 fakePrevious = keccak256("never computed");
        bytes32 fakeResult = _hashN(fakePrevious, STEP);

        vm.expectRevert(abi.encodeWithSelector(HashChainFact.MissingPredecessor.selector, seed, STEP, fakePrevious));
        liar.issue(chainType, _claim(seed, 2 * STEP, fakeResult), abi.encode(fakePrevious));

        assertFalse(LibReceipt.isProven(address(liar), chainType, _claim(seed, 2 * STEP, fakeResult)));
    }

    function test_lookupCostIsConstantInComputationLength() public {
        bytes32 seed = keccak256("seed");
        uint256 n = STEP * 8;
        bytes32 result = _issueChain(seed, n);
        bytes memory longClaim = _claim(seed, n, result);
        bytes memory shortClaim = _claim(seed, STEP, _hashN(seed, STEP));

        uint256 g0 = gasleft();
        bool longOk = LibReceipt.isProven(address(issuer), chainType, longClaim);
        uint256 g1 = gasleft();
        bool shortOk = LibReceipt.isProven(address(issuer), chainType, shortClaim);
        uint256 g2 = gasleft();

        assertTrue(longOk && shortOk);
        emit log_named_uint("lookup gas, 2048 iterations", g0 - g1);
        emit log_named_uint("lookup gas, 256 iterations", g1 - g2);
        assertApproxEqAbs(g0 - g1, g1 - g2, 3000, "lookup cost does not grow with n");
    }

    // ---------------------------------------------------------------------
    // deterministic deployment through the keyless deployer
    // ---------------------------------------------------------------------

    function _keylessDeployer() internal returns (address deployer) {
        deployer = CREATE2_FACTORY;
        if (deployer.code.length == 0) vm.etch(deployer, KEYLESS_DEPLOYER_RUNTIME);
    }

    /// @dev The issuer's canonical address is a pure function of its own code, so every
    ///      receipt address is ultimately a pure function of public code and the claim.
    function test_issuerAddressIsAFunctionOfItsCode() public {
        address deployer = _keylessDeployer();
        bytes memory code = type(ReceiptIssuer).creationCode;

        (bool ok, bytes memory ret) = deployer.call(abi.encodePacked(bytes32(0), code));
        assertTrue(ok);

        // forge-lint: disable-next-line(unsafe-typecast)
        address canonical = address(bytes20(ret)); // the deployer returns exactly 20 bytes
        assertEq(canonical, vm.computeCreate2Address(bytes32(0), keccak256(code), deployer));
        assertGt(canonical.code.length, 0);
    }

    /// @dev Receipts also work with the keyless deployer itself as the issuer (no witness
    ///      channel, and rejections are silent), which shows the issuer adds convenience,
    ///      not trust.
    function test_keylessDeployerCanIssueBaseCaseReceipts() public {
        address deployer = _keylessDeployer();
        bytes32 seed = keccak256("seed");
        bytes memory truth = _claim(seed, 12, _hashN(seed, 12));
        bytes memory lie = _claim(seed, 12, bytes32(0));

        (bool ok,) = deployer.call(abi.encodePacked(bytes32(0), LibReceipt.initcode(chainType, truth)));
        assertTrue(ok);
        assertTrue(LibReceipt.isProven(deployer, chainType, truth));

        (ok,) = deployer.call(abi.encodePacked(bytes32(0), LibReceipt.initcode(chainType, lie)));
        assertFalse(ok);
        assertFalse(LibReceipt.isProven(deployer, chainType, lie));
    }

    // ---------------------------------------------------------------------
    // fuzz
    // ---------------------------------------------------------------------

    function testFuzz_trueClaimsAreProvable(bytes32 seed, uint256 n) public {
        n = bound(n, 0, STEP);
        bytes memory claim = _claim(seed, n, _hashN(seed, n));
        issuer.issue(chainType, claim, "");
        assertTrue(LibReceipt.isProven(address(issuer), chainType, claim));
    }

    function testFuzz_falseClaimsAreNeverProven(bytes32 seed, uint256 n, bytes32 wrong) public {
        n = bound(n, 0, STEP);
        bytes32 truth = _hashN(seed, n);
        vm.assume(wrong != truth);
        bytes memory claim = _claim(seed, n, wrong);

        vm.expectRevert(abi.encodeWithSelector(HashChainFact.WrongResult.selector, wrong, truth));
        issuer.issue(chainType, claim, "");
        assertFalse(LibReceipt.isProven(address(issuer), chainType, claim));
    }
}
