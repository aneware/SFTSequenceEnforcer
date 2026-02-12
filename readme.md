# SFTSequenceEnforcer

Execution-layer defense against sequential MEV attack patterns using shift-of-finite-type constraints on the de Bruijn graph.

---

## What This Is

SFTSequenceEnforcer is a Solidity abstract contract that detects and blocks known multi-step attack patterns (sandwich attacks, flash loan exploits, governance manipulation) by maintaining a rolling window of recent operation types and checking each new operation against a forbidden bitmap. The mathematical framework behind it is the shift of finite type (SFT) from symbolic dynamics, which guarantees that enforcement requires examining only the last `n-1` operations regardless of total history length.

No existing on-chain MEV defense operates at this layer. Private mempools address transaction ordering. Reentrancy guards address single-contract re-entry. TWAP oracles and slippage limits address economic impact. This contract addresses the execution-layer structure of attacks: the specific sequences of operations that constitute an exploit.

---

## How It Works

### The Core Idea

Every protocol has a finite set of operation types (swaps, liquidity adds/removes, flash loans, etc.). An attacker's exploit follows a recognizable sequence of these operations. The contract maintains a sliding window of the most recent `n-1` operations per scope (per-address or global) and, on every new operation, forms an n-gram from the window plus the incoming operation. If that n-gram appears in a pre-configured forbidden set, the transaction reverts.

The forbidden set is stored as a bitmap of `k^n` bits, where `k` is the number of operation types and `n` is the lookback depth. Checking a single bit in this bitmap is all that's required per operation.

### The Math

Let `Sigma = {0, 1, ..., k-1}` be the operation alphabet and `F` be a set of forbidden n-grams over `Sigma`. The shift of finite type `X_F` is the set of all operation sequences containing no substring in `F`. Two properties make this enforceable on-chain at bounded cost:

**Markov property.** Verifying whether a new symbol `a` extends a valid sequence requires only the most recent `n-1` symbols (the rolling state `sigma`). The n-gram `(sigma, a)` is valid iff it is not in `F`. This is independent of history length.

**Constant-time verification.** The n-gram index `i = sigma * k + a` is a single multiply-add. The bitmap check `(B[i/256] >> (i%256)) & 1` is a single storage read plus two bitwise operations. The rolling state update `sigma_new = (sigma_old % k^(n-2)) * k + a` is a modulo, multiply, and add. Total computational cost per operation: roughly 20 gas on top of the storage access.

The de Bruijn graph `G(k, n)` has `k^(n-1)` vertices (all possible rolling states) and `k^n` edges (all possible n-grams). Removing forbidden edges produces the constrained graph `G_F`. A sequence of operations is valid iff it traces a walk in `G_F`. The topological entropy `h(X_F) = log_k(lambda_max)`, where `lambda_max` is the spectral radius of the adjacency matrix of `G_F`, quantifies how much of the operation space the constraint removes. This is computed off-chain during policy design using the included Python analyzer.

---

## Architecture

The system has three components matching the spec's architecture (Section 2.1):

### Component 1: Off-Chain Policy Design

Protocol designers define the alphabet, lookback depth, and forbidden set. The Python analyzer (`SFTCapacityAnalyzer.py`) computes the SFT capacity to verify the policy isn't too restrictive, estimates false-positive rates against historical transaction data, generates the bitmap hex values for on-chain deployment, and expands wildcard patterns into explicit forbidden n-grams.

### Component 2: On-Chain Persistent State

The contract stores a forbidden bitmap of `k^n` bits packed into `ceil(k^n / 256)` uint256 storage slots, and a rolling state variable per enforcement scope storing the most recent `n-1` operation types in a single storage slot.

### Component 3: On-Chain Per-Operation Enforcement

On every guarded function call, the contract classifies the operation (via `_classifyOperation()`), computes the n-gram index, checks the bitmap, reverts if forbidden, and updates the rolling state. This executes inline as a modifier.

---

## Contracts

### `SFTSequenceEnforcer.sol`

Abstract base contract. Provides:

**Immutable configuration** — `k` (alphabet size), `n` (lookback depth), precomputed `k^n`, `k^(n-1)`, `k^(n-2)`, and `bitmapSlotCount`. Set once in the constructor, never changed.

**Forbidden bitmap** — Stored at deterministic slots derived from `keccak256("SFTSequenceEnforcer.bitmap.v1")`. Governance-updatable via `forbidNgram()`, `allowNgram()`, `forbidNgrams()`, `allowNgrams()`, `writeBitmapSlot()`, and `writeBitmapSlots()`.

**Three enforcement modifiers:**

`perAddrIntraTxGuard` — Per-address rolling state in transient storage (EIP-1153). Resets at end of transaction. For detecting patterns within a single transaction (flash loan exploits). ~306 gas per operation.

`perAddrCrossTxGuard` — Per-address rolling state in persistent storage. Survives across transactions. For detecting patterns across separate transactions from the same address (sandwich attacks). ~5,206 gas per operation (warm).

`globalIntraTxGuard` — Global rolling state in transient storage. Tracks all callers within a single transaction. For detecting cross-address coordination patterns. Higher false-positive rate. ~306 gas per operation.

**One virtual function** — `_classifyOperation()` must be implemented by the inheriting contract. Maps `msg.sig` to an operation symbol in `[0, k)`.

### `SFTProtectedAMM.sol`

Reference integration for a constant-product AMM with `k=6` operation types and `n=3` lookback depth.

**Alphabet:**

| Symbol | Operation | Selector |
|--------|-----------|----------|
| 0 | `swapAtoB` | Swap token A for token B |
| 1 | `swapBtoA` | Swap token B for token A |
| 2 | `addLiquidity` | Add liquidity to the pool |
| 3 | `removeLiquidity` | Remove liquidity (burn LP shares) |
| 4 | `flashLoan` | Borrow via flash loan |
| 5 | `flashRepay` | Repay flash loan with 9bps fee |

**Modifier assignments per operation type:**

| Operation | Guards | Rationale |
|-----------|--------|-----------|
| `swapAtoB`, `swapBtoA` | `perAddrIntraTxGuard` + `perAddrCrossTxGuard` | Flash loan manipulation is intra-tx; sandwich attacks are cross-tx |
| `addLiquidity`, `removeLiquidity` | `perAddrIntraTxGuard` + `globalIntraTxGuard` | Flash drain is intra-tx; cross-address coordination requires global scope |
| `flashLoan`, `flashRepay` | `perAddrIntraTxGuard` | Always atomic within one transaction |

**Default forbidden 3-grams:**

| Index | Pattern | Target |
|-------|---------|--------|
| 1 | (swap_A2B, swap_A2B, swap_B2A) | Sandwich: double-buy then sell |
| 42 | (swap_B2A, swap_B2A, swap_A2B) | Sandwich: double-sell then buy |
| 147 | (flash, swap_A2B, remove_liq) | Flash loan + swap + drain |
| 153 | (flash, swap_B2A, remove_liq) | Flash loan + swap + drain |
| 159 | (flash, add_liq, remove_liq) | Flash loan + deposit + drain |
| 162 | (flash, remove_liq, swap_A2B) | Flash loan + drain + swap |
| 163 | (flash, remove_liq, swap_B2A) | Flash loan + drain + swap |

All 216 possible 3-grams fit in a single uint256 storage slot (216 bits used, 40 unused). Deployment writes one SSTORE.

### `SFTCapacityAnalyzer.py`

Off-chain analysis tool. Capabilities:

**Capacity computation.** Constructs the adjacency matrix of the constrained de Bruijn graph and computes the spectral radius. For the default AMM forbidden set, the capacity is approximately 0.98, meaning the constraint removes roughly 2% of the valid operation space.

**Bitmap generation.** Outputs hex values for direct use in `writeBitmapSlot()` or `writeBitmapSlots()` governance calls.

**Wildcard expansion.** `forbid_wildcard((4, None, 3))` generates all 6 forbidden 3-grams of the form (flash_loan, *, remove_liquidity).

**False-positive estimation.** Takes a corpus of legitimate operation sequences and computes the fraction that would be blocked. The validation protocol follows Section 8.2 of the spec.

**Success criteria evaluation.** Checks the three thresholds from Section 8.3: true positive rate > 50%, false positive rate < 0.1%, capacity > 0.9.

---

## Gas Costs

### Per-Operation Overhead

| Mode | Load State | Bitmap Check | Store State | Total |
|------|-----------|--------------|-------------|-------|
| Intra-tx (transient) | 100 (TLOAD) | 106 (SLOAD + shift + mask) | 100 (TSTORE) | **306** |
| Cross-tx (persistent, warm) | 100 (SLOAD) | 106 (SLOAD + shift + mask) | 5,000 (SSTORE dirty) | **5,206** |
| Cross-tx (persistent, cold) | 2,100 (SLOAD) | 2,100 (SLOAD) | 20,000 (SSTORE) | **24,200** |

Cold access costs occur once per transaction per unique address. Subsequent operations in the same transaction use warm pricing.

### Overhead as Fraction of Typical Operations

| Operation | Typical Gas | Intra-tx Overhead | Cross-tx Overhead (warm) |
|-----------|------------|-------------------|-------------------------|
| Uniswap v3 swap | 120,000 - 150,000 | 0.20% - 0.26% | 3.5% - 4.3% |
| Uniswap v2 swap | 60,000 - 80,000 | 0.38% - 0.51% | 6.5% - 8.7% |
| Aave borrow | 200,000 - 300,000 | 0.10% - 0.15% | 1.7% - 2.6% |

The intra-transaction mode is viable for all operations. The cross-transaction mode is acceptable for high-gas operations but adds meaningful overhead to simple transfers.

### Deployment Costs

Writing the forbidden bitmap requires one SSTORE (20,000 gas cold, zero-to-nonzero) per slot. For `k=6, n=3`: 1 slot = 20,000 gas. For `k=6, n=4`: 6 slots = 120,000 gas. For `k=8, n=4`: 16 slots = 320,000 gas.

### Governance Update Costs

Adding or removing a single forbidden n-gram: SLOAD (100 warm) + bit manipulation (15) + SSTORE (5,000 warm dirty) = ~5,115 gas.

---

## Deployment

### 1. Design the Policy (Off-Chain)

```bash
python sft_capacity_analyzer.py
```

Review the output. Verify capacity > 0.9. Verify false-positive rate < 0.1% against your protocol's historical transaction data. Note the bitmap hex values.

### 2. Deploy the Contract

For the reference AMM:

```solidity
SFTProtectedAMM pool = new SFTProtectedAMM(tokenA, tokenB, governanceAddress);
```

For a custom protocol, inherit `SFTSequenceEnforcer`, pass `k`, `n`, and the governance address to its constructor, implement `_classifyOperation()`, and apply the appropriate guard modifiers to each external function.

### 3. Initialize the Forbidden Set

Option A — Use the provided initialization function (if your contract has one):

```solidity
pool.initializeDefaultForbiddenSet();
```

Option B — Write bitmap slots directly from the analyzer output:

```solidity
uint256[] memory slots = new uint256[](1);
slots[0] = 0x...; // hex value from analyzer
pool.writeBitmapSlots(0, slots);
```

Option C — Set individual n-grams:

```solidity
uint256[] memory indices = new uint256[](7);
indices[0] = 1;   // (0,0,1)
indices[1] = 42;  // (1,1,0)
// ...
pool.forbidNgrams(indices);
```

### 4. Verify

Call `isForbidden(index)` for each expected forbidden n-gram. Call `readBitmapSlot(0)` and compare against the analyzer's hex output.

---

## Integrating With Your Own Protocol

```solidity
contract MyProtocol is SFTSequenceEnforcer {

    uint256 constant OP_ACTION_A = 0;
    uint256 constant OP_ACTION_B = 1;
    uint256 constant OP_ACTION_C = 2;

    constructor(address gov)
        SFTSequenceEnforcer(3, 3, gov)  // k=3, n=3
    {}

    function _classifyOperation() internal view override returns (uint256) {
        if (msg.sig == this.actionA.selector) return OP_ACTION_A;
        if (msg.sig == this.actionB.selector) return OP_ACTION_B;
        if (msg.sig == this.actionC.selector) return OP_ACTION_C;
        revert("Unknown operation");
    }

    function actionA() external perAddrIntraTxGuard {
        // ...
    }

    function actionB() external perAddrIntraTxGuard perAddrCrossTxGuard {
        // ...
    }

    function actionC() external globalIntraTxGuard {
        // ...
    }
}
```

When choosing which modifiers to apply to each function, consider: does the attack pattern this function participates in execute within a single transaction (use intra-tx), across multiple transactions from the same address (use per-address cross-tx), or across multiple addresses within a single transaction (use global intra-tx)? Multiple modifiers can be composed on the same function when multiple threat models apply.

---

## Limitations

These are inherent to the approach, not implementation bugs. They are documented in Section 6 of the spec.

### Address Splitting

Per-address enforcement is evaded by using different addresses for each step of the attack. The frontrun comes from address A, the backrun from address B. Neither address's rolling state shows a forbidden n-gram. Global enforcement partially addresses this but introduces false positives from unrelated users' operations coincidentally forming a forbidden pattern.

### Pattern Mutation

The forbidden bitmap is on-chain state, so attackers can read it and insert no-op operations (dust transfers, zero-amount adds) between attack steps to break the n-gram. Mitigation: design the alphabet so that no-op operations either don't update the rolling state or are collapsed into a neutral symbol. The `_classifyOperation()` function is the right place to handle this.

### False Positives

Any legitimate operation sequence that happens to match a forbidden n-gram will be reverted. The severity depends on how the alphabet and forbidden set are designed. This must be measured empirically against real transaction data before deployment. The Python analyzer includes the tooling for this analysis.

### Public Forbidden Set

Because the bitmap is on-chain, sophisticated attackers will read it and adapt. This mechanism is most effective against automated MEV bots that execute fixed patterns at scale, where even partial mitigation (forcing pattern mutation, increasing attack complexity) has economic value. It is not effective against manual, targeted attacks by sophisticated actors who can trivially restructure their execution.

### Governance Attack Surface

A compromised or malicious governance address can add legitimate operation patterns to the forbidden set, blocking normal usage. Timelocks on bitmap updates are strongly recommended. The base contract does not enforce timelocks because the appropriate timelock duration varies by protocol.

---

## Parameter Selection Guide

| k (alphabet) | n (lookback) | Bitmap bits | Storage slots | Good for |
|---|---|---|---|---|
| 4 | 2 | 16 | 1 | Simple protocols, reentrancy-like guards |
| 4 | 3 | 64 | 1 | Basic DeFi with few operation types |
| 6 | 3 | 216 | 1 | AMMs with flash loans (the reference config) |
| 6 | 4 | 1,296 | 6 | Complex AMMs needing deeper pattern detection |
| 8 | 3 | 512 | 2 | Lending protocols with many operation types |
| 8 | 4 | 4,096 | 16 | Maximum viable complexity |

Stay at `k <= 6, n <= 3` unless you have a specific attack pattern that requires more. Every increase in `k` or `n` increases the bitmap size exponentially and makes false-positive analysis harder.

---

## Files

| File | Purpose |
|------|---------|
| `SFTSequenceEnforcer.sol` | Abstract base contract. All enforcement logic, bitmap storage, governance, modifiers. |
| `SFTProtectedAMM.sol` | Reference AMM integration with constant-product math, flash loans, and the default forbidden set. |
| `SFTCapacityAnalyzer.py` | Off-chain policy design, capacity computation, bitmap generation, false-positive analysis. |

---

## Requirements

**Solidity** >= 0.8.24 (for EIP-1153 transient storage opcodes TLOAD/TSTORE, available since Dencun upgrade, March 2024).

**Python** >= 3.10 with `numpy` and `scipy` for the off-chain analyzer.

---

## License

MIT
