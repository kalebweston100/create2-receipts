# CREATE2 Receipts

**Facts proven on-chain, recorded as addresses.**

A receipt is a contract whose constructor verifies a claim and refuses to deploy if
the claim is false. Because CREATE2 addresses commit to the exact initcode, a claim is
proven if and only if code exists at the address that claim determines. No registry,
no storage, no owner, no oracle, no zk: just CREATE2, a constructor, and EXTCODEHASH.

```
receipt(f, x) = CREATE2(issuer, salt = 0, keccak256(creationCode_f ‖ abi.encode(x)))

proven(f, x)  ⇔  EXTCODEHASH(receipt(f, x)) == keccak256(0x00)
```

> **Status:** experimental. Implemented and tested, not audited.

## Why it works

A receipt type is a contract inheriting [`Receipt`](src/Receipt.sol). Its constructor
runs `_verify(claim)`. If the claim is false, `_verify` reverts and nothing is
deployed. If it holds, the constructor returns a single `0x00` byte as the contract's
code: the **marker**.

Soundness has two halves:

1. **The legitimate constructor with a false claim reverts**, so the address for that
   claim stays empty forever.
2. **Any other initcode** (a different constructor, or this one with different
   arguments) hashes differently, so it lands at a **different address**.

So a marker at the legitimate address means *this exact constructor accepted this
exact claim*. Looking a fact up is one hash and one `EXTCODEHASH`, with no call into
anything: about **9k gas** in the tests, whether the proven computation took 256 steps
or 2,048.

## Usage

```solidity
import {ReceiptIssuer} from "create2-receipts/ReceiptIssuer.sol";
import {LibReceipt} from "create2-receipts/LibReceipt.sol";
import {LibBytecode} from "create2-receipts/LibBytecode.sol";
import {OpcodeFreeFact} from "create2-receipts/facts/OpcodeFreeFact.sol";

// Prove once. Anyone can do this; a false claim simply reverts.
bytes memory claim = abi.encode(module, LibBytecode.INDESTRUCTIBLE_MASK | (1 << 0x55)); // no SSTORE
issuer.issue(OPCODE_FREE_CREATION_CODE, claim, "");

// Require it anywhere, forever: one hash plus one EXTCODEHASH, no external call.
require(LibReceipt.isProven(address(issuer), OPCODE_FREE_CREATION_CODE, claim), "module not certified");
```

**Pin receipt types by their exact bytes.** A receipt type *is* its creation code.
Recompiling it with a different solc version or setting changes the bytes and so every
receipt address. Integrators should reference a published creation code (as a
constant, or read from a content-addressed data contract) rather than recompiling
`type(OpcodeFreeFact).creationCode` under their own settings.

Install with Foundry and add a remapping:

```sh
forge install kalebweston100/create2-receipts
# remappings.txt:  create2-receipts/=lib/create2-receipts/src/
```

## Components

| File | Role |
|---|---|
| [`Receipt.sol`](src/Receipt.sol) | Base for receipt types: verify in the constructor, then deploy the marker |
| [`ReceiptIssuer.sol`](src/ReceiptIssuer.sol) | Stateless, ownerless CREATE2 deployer: fixed salt, idempotent, bubbles revert reasons, witness channel, events |
| [`LibReceipt.sol`](src/LibReceipt.sol) | Address derivation and `isProven` lookups |
| [`LibBytecode.sol`](src/LibBytecode.sol) | Sound static analysis of EVM bytecode, used by code facts |
| [`IWitnessSource.sol`](src/IWitnessSource.sol) | Out-of-band hint channel for constructors |

The issuer adds convenience, not trust. Receipt validity is decided entirely by each
receipt's constructor; the tests also issue receipts straight through the keyless
deterministic deployer. Deploying the issuer through that keyless deployer makes its
address (and so every receipt address) a pure function of public code, identical on
every chain.

## Included fact types

| Type | Claim | Proves |
|---|---|---|
| [`OpcodeFreeFact`](src/facts/OpcodeFreeFact.sol) | `(address target, uint256 mask)` | No reachable instruction in `target` uses an opcode in `mask`. E.g. "this contract can never write storage, call out, emit or self-destruct" |
| [`CloneFact`](src/facts/CloneFact.sol) | `(address clone, address implementation)` | `clone` is an EIP-1167 proxy permanently bound to an indestructible `implementation` |
| [`HashChainFact`](src/facts/HashChainFact.sol) | `(bytes32 seed, uint256 n, bytes32 result)` | `keccak256` applied `n` times to `seed` gives `result`, built inductively |

## Witnesses

A receipt's address commits to its claim, so everything in the claim must be known to
anyone looking the fact up. Some claims are cheap to check only with extra data. The
issuer exposes that data (the **witness**) in transient storage for one `issue` call,
and the constructor pulls it from `msg.sender` via `_witness()`.

The witness is **never trusted**. A constructor must verify anything it reads from it,
so a dishonest issuer can only make issuance fail, never make a false receipt exist
(`test_lyingIssuerCannotForgeInductiveStep`). Fetching it is lazy, so receipt types
that don't need one work with any CREATE2 deployer.

## Inductive receipts

A receipt can require that other receipts already exist. `HashChainFact` proves
`keccak^n(seed)` in steps of 256: the step for `n` requires the receipt for `n − 256`,
whose value arrives as the witness, then computes 256 more iterations. By induction over
creation order, every receipt of the type is correct, so **one existence check vouches
for an arbitrarily long computation** spread across many transactions.

To find its predecessor, a receipt needs its own creation code, which
`type(C).creationCode` cannot provide from inside `C`. During construction `CODECOPY`
reads the running initcode (creation code followed by the encoded claim), so
`_selfCreationCode` recovers it directly.

## Writing a receipt type

```solidity
contract MyFact is Receipt {
    constructor(bytes memory claim) Receipt(claim) {} // body must stay empty

    function _verify(bytes memory claim) internal view override {
        (uint256 x, uint256 y) = abi.decode(claim, (uint256, uint256));
        if (expensiveCheck(x) != y) revert ClaimRejected();
    }
}
```

- `_verify` is `view`: verification can never change state.
- **Claims must be eternal.** A receipt is permanent, so it may only state things that
  can never become false: pure computation, or properties of code that can never
  change. Never claims about balances or other mutable state, unless they are pinned to
  a point in history.
- Verify everything read through `_witness()`.
- Leave the derived constructor body empty. The base constructor ends creation with
  `RETURN`, so nothing after it runs.

## Security analysis

### Address collisions: 80-bit security

Making one *specific* false fact look proven means finding initcode that lands on its
address: a second-preimage attack on a 160-bit address, about 2^160 work.

An attacker who only needs *some* false fact to look proven can do better. They
generate many false-claim receipt addresses on one side and many addresses they could
deploy to on the other, and look for any match. That is a birthday collision on 160
bits, about **2^80 work**. They would then deploy a marker at the colliding address.

Checking the exact marker codehash (rather than any non-empty code) forces the attacker
to deploy the marker there, which closes the cheaper paths (an EOA key collision with an
EIP-7702 designator, or arbitrary code). It does not change the 2^80 bound for an
attacker who controls a CREATE2 deployer. 2^80 is far beyond any realistic budget for a
single attacker today, but it is below the 128-bit level most cryptographic assumptions
target. Every CREATE2-based design on Ethereum lives with the same bound.

### Eternal facts and metamorphic contracts

Facts about code assume the code never changes. Since EIP-6780, `SELFDESTRUCT` only
deletes an account in the transaction that created it, but that is still enough for a
**metamorphic attack**: create a contract, obtain a receipt about its code, destroy it
and later redeploy different code at the same address, all starting in one transaction.

Code with no reachable `SELFDESTRUCT`, `DELEGATECALL` or `CALLCODE` can never destroy
itself, so its code is permanent. `OpcodeFreeFact` requires every mask to include those
three opcodes (`NotEternal` otherwise), and `CloneFact` requires the implementation to
be indestructible, since a clone runs its implementation's code in its own context.

### Sound bytecode analysis

`LibBytecode.findReachable` never misses an executable forbidden opcode:

- Instruction boundaries come from a linear sweep that skips PUSH immediates. The EVM's
  JUMPDEST analysis uses the same sweep, so PUSH data can never execute.
- After an instruction that never falls through (`STOP`, `JUMP`, `RETURN`, `REVERT`,
  `INVALID`, `SELFDESTRUCT`), bytes are unreachable until the next `JUMPDEST`. This
  ignores appended data such as solc's metadata without trusting any length field
  inside the code.

It may report instructions no real execution reaches, which only ever makes a claim
fail. It is checked against an independent two-pass reference implementation by
differential fuzzing (`testFuzz_matchesReference*`).

### EIP-7702 accounts

A delegated EOA's code is `0xef0100 ‖ delegate`, and its owner can repoint it at any
time, so it has no permanent code. EIP-3541 forbids deploying code that starts with
`0xEF`, so code facts reject any target whose code starts with it.

### What is and isn't trusted

| Trusted | Why that's reasonable |
|---|---|
| EVM semantics and consensus | The base assumption of everything on Ethereum |
| keccak256 | Collision resistance bounds the address argument above |
| The receipt type's creation code | Audited once, identical everywhere; it *is* the definition of the fact |

Not trusted: the issuer, the witness, whoever pays for issuance, and anyone else.

### Smaller notes

- **Encoding.** `_selfCreationCode` assumes the canonical `abi.encode(claim)` that
  `LibReceipt` produces. A non-canonical encoding can only make predecessor lookups miss
  (a false negative), never a false positive.
- **Same-transaction lookups.** An account's code reads as empty while its constructor
  is still running. Receipts that check other receipts must not depend on ones still
  being constructed.
- **Chains.** zkSync Era derives CREATE2 addresses differently, and some chains lack the
  keyless deployer.

## Prior art

| Prior work | Difference |
|---|---|
| StarkWare's [Fact Registry](https://docs.starkware.co/starkex/fact-registry.html) | Same notion of queryable verified facts, but a `mapping(bytes32 => bool)` inside a registry contract, filled by a zk verifier |
| Vitalik's [storage-rent proposals](https://ethresear.ch/t/common-classes-of-contracts-and-how-they-would-handle-ongoing-storage-maintenance-fees-rent/4441) | CREATE2 addresses as computable *storage locations*; nothing is verified at creation |
| Counterfactual instantiation | An address stands for a contract to be deployed later, not a proven fact |
| SSTORE2 | Data stored as contract code; nothing verified |
| EIP-1011 purity checker | On-chain bytecode scanning, but a one-off purity check for signature validators rather than a general system of permanent facts |

To my knowledge, the combination here has not been described before: a constructor as
the verifier, existence at a derived address as the proof, a registry-free and
permissionless fact space, an untrusted witness channel, and inductive chaining with
constant-cost lookup. Pointers to prior art are very welcome.

## Development

```sh
forge build
forge test -vv
forge fmt --check
```

## License

[MIT](LICENSE)
