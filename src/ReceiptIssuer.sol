// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IWitnessSource} from "./IWitnessSource.sol";
import {LibReceipt} from "./LibReceipt.sol";

/**
 * @title ReceiptIssuer
 * @notice Permissionless, stateless CREATE2 deployer for receipts.
 *
 * The issuer has no owner, no upgrade path and no persistent storage. It cannot make a
 * false receipt exist: validity is decided entirely by each receipt's constructor. What
 * it adds over calling CREATE2 directly:
 *   - a fixed salt (0), so every fact maps to exactly one address;
 *   - idempotency: issuing an already-proven fact returns the existing receipt;
 *   - revert reasons bubble up (the keyless deployer swallows them);
 *   - a witness channel (IWitnessSource) held in transient storage for one call;
 *   - an event so indexers can enumerate proven facts.
 *
 * Deploy it through the keyless deterministic deployer so its address, and therefore
 * every receipt address, is the same on every chain and is itself a pure function of
 * this contract's code.
 */
contract ReceiptIssuer is IWitnessSource {
    /// @notice Emitted when a new receipt is created.
    /// @param receipt Address of the receipt.
    /// @param receiptType keccak256 of the receipt type's creation code.
    /// @param claim The claim the receipt proves.
    event ReceiptIssued(address indexed receipt, bytes32 indexed receiptType, bytes claim);

    /// @dev Transient slot holding the witness length; data words follow at keccak256(slot).
    bytes32 private constant _WITNESS_SLOT = keccak256("create2-receipts.witness");

    /// @notice Prove `claim` under receipt type `creationCode`, or return the existing receipt.
    /// @param creationCode Creation code of a contract inheriting Receipt.
    /// @param claim The claim to prove (ABI-encoded, type-specific).
    /// @param witnessData Untrusted hint exposed to the receipt constructor via witness().
    /// @return receipt Address of the receipt. Reverts with the constructor's reason if
    ///         the claim is rejected.
    function issue(bytes calldata creationCode, bytes calldata claim, bytes calldata witnessData)
        external
        returns (address receipt)
    {
        bytes memory code = LibReceipt.initcode(creationCode, claim);
        receipt = LibReceipt.addressOf(address(this), keccak256(code));
        if (LibReceipt.isReceipt(receipt)) return receipt;

        _setWitness(witnessData);
        assembly ("memory-safe") {
            receipt := create2(0, add(code, 32), mload(code), 0)
            if iszero(receipt) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
        _clearWitness();

        emit ReceiptIssued(receipt, keccak256(creationCode), claim);
    }

    /// @inheritdoc IWitnessSource
    function witness() external view returns (bytes memory w) {
        bytes32 slot = _WITNESS_SLOT;
        assembly ("memory-safe") {
            let len := tload(slot)
            w := mload(0x40)
            mstore(w, len)
            mstore(0, slot)
            let base := keccak256(0, 32)
            let words := div(add(len, 31), 32)
            for { let i := 0 } lt(i, words) { i := add(i, 1) } {
                mstore(add(add(w, 32), mul(i, 32)), tload(add(base, i)))
            }
            // Zero any bytes past `len` in the last word so the encoding is clean.
            mstore(add(add(w, 32), len), 0)
            mstore(0x40, add(add(w, 64), mul(words, 32)))
        }
    }

    function _setWitness(bytes calldata data) private {
        bytes32 slot = _WITNESS_SLOT;
        assembly ("memory-safe") {
            let len := data.length
            tstore(slot, len)
            mstore(0, slot)
            let base := keccak256(0, 32)
            for { let i := 0 } lt(mul(i, 32), len) { i := add(i, 1) } {
                tstore(add(base, i), calldataload(add(data.offset, mul(i, 32))))
            }
        }
    }

    function _clearWitness() private {
        bytes32 slot = _WITNESS_SLOT;
        assembly ("memory-safe") {
            tstore(slot, 0)
        }
    }
}
