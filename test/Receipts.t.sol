// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {Receipt} from "../src/Receipt.sol";
import {ReceiptIssuer} from "../src/ReceiptIssuer.sol";
import {LibReceipt} from "../src/LibReceipt.sol";
import {LibBytecode} from "../src/LibBytecode.sol";
import {OpcodeFreeFact} from "../src/facts/OpcodeFreeFact.sol";

/// @dev Minimal receipt type used to test the core mechanism independently of any real
///      fact type. Proves: "y == x * x".
contract SquareFact is Receipt {
    error WrongSquare(uint256 expected, uint256 actual);

    constructor(bytes memory claim) Receipt(claim) {}

    function _verify(bytes memory claim) internal pure override {
        (uint256 x, uint256 y) = abi.decode(claim, (uint256, uint256));
        if (x * x != y) revert WrongSquare(y, x * x);
    }
}

/// @dev A pure contract, used as a realistic target for the lookup-cost measurement.
contract Pure {
    function double(uint256 a) external pure returns (uint256) {
        return a * 2;
    }
}

contract ReceiptsTest is Test {
    /// @dev Runtime code of the keyless deterministic deployer (Arachnid).
    bytes internal constant KEYLESS_DEPLOYER_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    ReceiptIssuer internal issuer;
    bytes internal squareType;

    function setUp() public {
        issuer = new ReceiptIssuer();
        squareType = type(SquareFact).creationCode;
    }

    function _claim(uint256 x, uint256 y) internal pure returns (bytes memory) {
        return abi.encode(x, y);
    }

    // ---------------------------------------------------------------------
    // address derivation and the marker
    // ---------------------------------------------------------------------

    function test_receiptLandsAtPredictedAddress() public {
        bytes memory claim = _claim(12, 144);

        address predicted = LibReceipt.addressOf(address(issuer), squareType, claim);
        assertEq(predicted.code.length, 0);

        address receipt = issuer.issue(squareType, claim);

        assertEq(receipt, predicted);
        assertEq(
            receipt,
            vm.computeCreate2Address(bytes32(0), keccak256(LibReceipt.initcode(squareType, claim)), address(issuer))
        );
        assertEq(receipt.code, hex"00", "runtime code is the 1-byte marker");
        assertTrue(LibReceipt.isProven(address(issuer), squareType, claim));
    }

    function test_trueClaimIsProven_falseClaimNeverExists() public {
        issuer.issue(squareType, _claim(7, 49));
        assertTrue(LibReceipt.isProven(address(issuer), squareType, _claim(7, 49)));

        vm.expectRevert(abi.encodeWithSelector(SquareFact.WrongSquare.selector, 50, 49));
        issuer.issue(squareType, _claim(7, 50));
        assertFalse(LibReceipt.isProven(address(issuer), squareType, _claim(7, 50)));
        assertEq(LibReceipt.addressOf(address(issuer), squareType, _claim(7, 50)).code.length, 0);
    }

    function test_issueIsIdempotent() public {
        bytes memory claim = _claim(5, 25);

        vm.recordLogs();
        address first = issuer.issue(squareType, claim);
        address second = issuer.issue(squareType, claim);

        assertEq(first, second);
        assertEq(vm.getRecordedLogs().length, 1, "only the first issuance emits");
    }

    function test_issueEmitsEvent() public {
        bytes memory claim = _claim(3, 9);
        address predicted = LibReceipt.addressOf(address(issuer), squareType, claim);

        vm.expectEmit(true, true, false, true, address(issuer));
        emit ReceiptIssuer.ReceiptIssued(predicted, keccak256(squareType), claim);
        issuer.issue(squareType, claim);
    }

    function test_receiptsAreScopedToTheirIssuer() public {
        bytes memory claim = _claim(4, 16);
        ReceiptIssuer other = new ReceiptIssuer();

        issuer.issue(squareType, claim);

        assertTrue(LibReceipt.isProven(address(issuer), squareType, claim));
        assertFalse(LibReceipt.isProven(address(other), squareType, claim));
    }

    /// @dev Deploying the receipt type directly with `new` puts it at a CREATE address
    ///      unrelated to the fact's address, so it proves nothing about lookups.
    function test_deployingOutsideTheIssuerDoesNotCount() public {
        bytes memory claim = _claim(2, 4);

        address direct = address(new SquareFact(claim));

        assertEq(direct.code, hex"00");
        assertFalse(LibReceipt.isProven(address(issuer), squareType, claim));
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

    /// @dev A lookup is one hash of the initcode plus one EXTCODEHASH, with no external
    ///      call. Measured for a real receipt type so the README figure is honest.
    function test_lookupCost() public {
        address target = address(new Pure());
        bytes memory opcodeFreeType = type(OpcodeFreeFact).creationCode;
        bytes memory claim = abi.encode(target, LibBytecode.INDESTRUCTIBLE_MASK);
        issuer.issue(opcodeFreeType, claim);

        uint256 g0 = gasleft();
        bool ok = LibReceipt.isProven(address(issuer), opcodeFreeType, claim);
        uint256 used = g0 - gasleft();

        assertTrue(ok);
        emit log_named_uint("isProven gas, OpcodeFreeFact", used);
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

    /// @dev Receipts also work with the keyless deployer itself as the issuer (rejections
    ///      are just silent), which shows the issuer adds convenience, not trust.
    function test_keylessDeployerCanIssueReceipts() public {
        address deployer = _keylessDeployer();
        bytes memory truth = _claim(11, 121);
        bytes memory lie = _claim(11, 120);

        (bool ok,) = deployer.call(abi.encodePacked(bytes32(0), LibReceipt.initcode(squareType, truth)));
        assertTrue(ok);
        assertTrue(LibReceipt.isProven(deployer, squareType, truth));

        (ok,) = deployer.call(abi.encodePacked(bytes32(0), LibReceipt.initcode(squareType, lie)));
        assertFalse(ok);
        assertFalse(LibReceipt.isProven(deployer, squareType, lie));
    }

    // ---------------------------------------------------------------------
    // fuzz
    // ---------------------------------------------------------------------

    function testFuzz_trueClaimsAreProvable(uint128 x) public {
        bytes memory claim = _claim(x, uint256(x) * x);
        issuer.issue(squareType, claim);
        assertTrue(LibReceipt.isProven(address(issuer), squareType, claim));
    }

    function testFuzz_falseClaimsAreNeverProven(uint128 x, uint256 wrong) public {
        uint256 truth = uint256(x) * x;
        vm.assume(wrong != truth);
        bytes memory claim = _claim(x, wrong);

        vm.expectRevert(abi.encodeWithSelector(SquareFact.WrongSquare.selector, wrong, truth));
        issuer.issue(squareType, claim);
        assertFalse(LibReceipt.isProven(address(issuer), squareType, claim));
    }
}
