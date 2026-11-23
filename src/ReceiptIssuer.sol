// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {LibReceipt} from "./LibReceipt.sol";

/**
 * @title ReceiptIssuer
 * @notice Permissionless, stateless CREATE2 deployer for receipts.
 *
 * The issuer has no owner, no upgrade path and no storage. It cannot make a false
 * receipt exist: validity is decided entirely by each receipt's constructor. What it
 * adds over calling CREATE2 directly:
 *   - a fixed salt (0), so every fact maps to exactly one address;
 *   - idempotency: issuing an already-proven fact returns the existing receipt;
 *   - revert reasons bubble up (the keyless deployer swallows them);
 *   - an event so indexers can enumerate proven facts.
 *
 * Deploy it through the keyless deterministic deployer so its address, and therefore
 * every receipt address, is the same on every chain and is itself a pure function of
 * this contract's code.
 */
contract ReceiptIssuer {
    /// @notice Emitted when a new receipt is created.
    /// @param receipt Address of the receipt.
    /// @param receiptType keccak256 of the receipt type's creation code.
    /// @param claim The claim the receipt proves.
    event ReceiptIssued(address indexed receipt, bytes32 indexed receiptType, bytes claim);

    /// @notice Prove `claim` under receipt type `creationCode`, or return the existing receipt.
    /// @param creationCode Creation code of a contract inheriting Receipt.
    /// @param claim The claim to prove (ABI-encoded, type-specific).
    /// @return receipt Address of the receipt. Reverts with the constructor's reason if
    ///         the claim is rejected.
    function issue(bytes calldata creationCode, bytes calldata claim) external returns (address receipt) {
        bytes memory code = LibReceipt.initcode(creationCode, claim);
        receipt = LibReceipt.addressOf(address(this), keccak256(code));
        if (LibReceipt.isReceipt(receipt)) return receipt;

        assembly ("memory-safe") {
            receipt := create2(0, add(code, 32), mload(code), 0)
            if iszero(receipt) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }

        emit ReceiptIssued(receipt, keccak256(creationCode), claim);
    }
}
