# Forbidden-Sequence Policy Enforcement via Shift-of-Finite-Type Constraints

## Full Technical Specification for On-Chain Implementation

---

## 1. Mathematical Foundations

### 1.1 The Shift of Finite Type

A **shift of finite type** (SFT) is a symbolic dynamical system defined by a finite set of forbidden words. Let $\Sigma = \{0, 1, \ldots, k-1\}$ be a finite alphabet of cardinality $k$. Let $F \subset \Sigma^n$ be a finite set of **forbidden $n$-grams** (words of length $n$ over $\Sigma$). The shift of finite type $X_F$ is the set of all bi-infinite sequences $x \in \Sigma^{\mathbb{Z}}$ such that no contiguous substring of $x$ of length $n$ belongs to $F$. Equivalently, $X_F$ is the complement of the set of sequences that contain a forbidden $n$-gram.

The parameter $n$ is the **memory** or **lookback depth** of the constraint. The key structural property is that verifying whether a new symbol $a$ extends a valid sequence requires examining only the most recent $n-1$ symbols. If the current state is the $(n-1)$-gram $\sigma = (a_1, a_2, \ldots, a_{n-1})$, and the candidate next symbol is $a$, then the transition is valid if and only if the $n$-gram $(\sigma, a) = (a_1, a_2, \ldots, a_{n-1}, a)$ does not belong to $F$. This is a constant-time check (a single bitmap lookup) regardless of the history of the sequence.

### 1.2 Connection to the de Bruijn Graph

The de Bruijn graph $G(k, n)$ has vertex set $\Sigma^{n-1}$ and edge set $\Sigma^n$, where each $n$-gram $w = a_1 \cdots a_n$ defines an edge from vertex $a_1 \cdots a_{n-1}$ to vertex $a_2 \cdots a_n$. The full de Bruijn graph encodes all possible transitions. An SFT is obtained by **removing** the edges corresponding to forbidden $n$-grams from $G(k, n)$. The remaining graph, $G_F = G(k, n) \setminus F$, defines the allowed transition structure.

A sequence of operations is valid under the policy if and only if it corresponds to a walk in $G_F$. The key insight for on-chain enforcement is that this walk can be verified incrementally: at each step, the contract checks that the current edge (the $n$-gram formed by the rolling state and the new operation) has not been removed. This check does not require constructing or storing the graph. It requires only a bitmap of forbidden edges and the rolling state.

### 1.3 Capacity of the Constrained System

The **topological entropy** (or **capacity**) of the SFT $X_F$ measures the growth rate of the number of allowed sequences of length $L$ as $L \to \infty$. It is given by $h(X_F) = \log_k \lambda$, where $\lambda$ is the spectral radius (largest eigenvalue) of the adjacency matrix $A_F$ of the graph $G_F$. When $F = \emptyset$ (no forbidden patterns), $\lambda = k$ and $h = 1$ (maximum entropy). As forbidden patterns are added, $\lambda$ decreases and $h < 1$, meaning the constraint reduces the set of valid sequences.

This capacity computation is relevant off-chain: it tells protocol designers what fraction of the full operation space remains available after imposing the forbidden-sequence policy. If the capacity is close to 1, the policy is permissive (few legitimate operations are blocked). If the capacity is much less than 1, the policy may be too restrictive, blocking a large fraction of legitimate operation sequences.

For the parameter regimes relevant to DeFi protocols ($k \leq 8$ operation types, $n \leq 4$ lookback depth), the adjacency matrix $A_F$ is at most $k^{n-1} \times k^{n-1}$ (e.g., $8^3 = 512 \times 512$), which is trivially diagonalizable on any modern computer. The capacity computation is a one-time off-chain calculation.

### 1.4 Why "Shift of Finite Type" and Not Just "Blacklist"

The SFT framework provides three things that a naive blacklist does not. First, it comes with a rigorous mathematical characterization of exactly what the constraint costs: the capacity formula quantifies the reduction in the valid operation space, enabling principled policy design. Second, the theory guarantees that the constraint is **Markovian**: enforcing it requires examining only the last $n-1$ operations, not the full history. This is what makes the on-chain cost bounded and predictable. Third, the de Bruijn graph structure provides a natural language for composing and analyzing multiple constraints. Two SFTs defined on the same alphabet can be intersected (both constraints apply simultaneously) by taking the product of their adjacency matrices, and the combined capacity is computable from the product's spectral radius.

---

## 2. Mechanism Design

### 2.1 System Architecture

The forbidden-sequence enforcement mechanism has three components.

**Component 1 (off-chain): Policy definition and analysis.** The protocol's designers or governance process defines the operation alphabet $\Sigma$, the lookback depth $n$, and the forbidden set $F$. The off-chain analysis computes the capacity of the resulting SFT and evaluates whether the constraint is too permissive (misses attack patterns) or too restrictive (blocks legitimate sequences). This is done once per policy update.

**Component 2 (on-chain, persistent state): Forbidden bitmap and rolling state.** The contract stores two pieces of persistent state: (a) a bitmap $B$ of $k^n$ bits indicating which $n$-grams are forbidden, packed into $\lceil k^n / 256 \rceil$ storage slots, and (b) a rolling state variable $\sigma$ storing the most recent $n-1$ operation types, packed into a single storage slot.

**Component 3 (on-chain, runtime): Per-operation enforcement.** On every operation, the contract computes the $n$-gram formed by the rolling state and the new operation, checks the corresponding bit in the forbidden bitmap, reverts if it is set, and updates the rolling state. This executes in the EVM during real transactions, reads and writes on-chain state, and is composable (other contracts can query the forbidden bitmap and rolling state).

### 2.2 Operation Alphabet Design

The operation alphabet $\Sigma$ must be defined carefully. Each symbol represents a distinct operation type within the protocol. The alphabet should be:

**Coarse enough** that $k$ remains small (ideally $k \leq 8$), keeping the bitmap size manageable ($k^n \leq 4096$ bits = 16 storage slots for $k = 8, n = 4$, or a single storage slot for $k = 4, n = 4$ since $4^4 = 256$ bits).

**Fine enough** that attack patterns are distinguishable from legitimate patterns. If the alphabet is too coarse (e.g., collapsing all swaps into a single symbol), attack patterns and legitimate patterns may become indistinguishable, leading to false positives or missed attacks.

**Stable across protocol upgrades.** Adding a new operation type changes $k$ and invalidates the existing bitmap. The alphabet should be designed with headroom for future operations.

For a typical AMM protocol, a reasonable alphabet might be:

| Symbol | Operation | Notes |
|---|---|---|
| 0 | `swap_A_to_B` | Swap token A for token B |
| 1 | `swap_B_to_A` | Swap token B for token A |
| 2 | `add_liquidity` | Add liquidity to the pool |
| 3 | `remove_liquidity` | Remove liquidity from the pool |
| 4 | `flash_loan` | Borrow via flash loan |
| 5 | `flash_repay` | Repay flash loan |

This gives $k = 6$. With lookback depth $n = 3$: $6^3 = 216$ possible 3-grams, fitting in a single 256-bit storage slot (216 bits used, 40 bits unused). With $n = 4$: $6^4 = 1296$ possible 4-grams, requiring $\lceil 1296 / 256 \rceil = 6$ storage slots.

### 2.3 Rolling State Encoding

The rolling state $\sigma$ stores the most recent $n-1$ operation types. Each operation type requires $\lceil \log_2 k \rceil$ bits. For $k = 6$: 3 bits per operation. For $n = 3$ (rolling state stores 2 operations): 6 bits total. For $n = 4$ (rolling state stores 3 operations): 9 bits total. This fits trivially in a single storage slot.

The rolling state is updated by shifting out the oldest operation and appending the new one:

$$\sigma_{\text{new}} = (\sigma_{\text{old}} \bmod k^{n-2}) \cdot k + a_{\text{new}}$$

In EVM arithmetic (using bit operations for power-of-2 alphabets, or MUL/MOD for general $k$), this costs approximately 15-20 gas.

### 2.4 $n$-gram Index Computation

The $n$-gram index is the position of the $n$-gram in the lexicographic ordering of $\Sigma^n$, computed as:

$$i(w) = \sigma \cdot k + a_{\text{new}}$$

where $\sigma$ is the current rolling state interpreted as a base-$k$ number (it already stores the $(n-1)$-gram in this encoding), and $a_{\text{new}}$ is the new operation symbol. This is a single MUL + ADD: approximately 8 gas.

### 2.5 Bitmap Lookup

The bitmap $B$ is stored as one or more `uint256` storage slots. The $n$-gram index $i$ maps to storage slot $\lfloor i / 256 \rfloor$ and bit position $i \bmod 256$ within that slot. For the single-slot case ($k^n \leq 256$), the lookup is:

```
bit = (B >> i) & 1
```

This costs: SLOAD (100 gas warm) + SHR (3 gas) + AND (3 gas) = 106 gas.

For the multi-slot case, the slot index must be computed and used with a mapping or array, adding approximately 30 gas for the slot index computation and an additional SLOAD.

### 2.6 Intra-Transaction vs. Cross-Transaction Enforcement

The mechanism has two distinct modes, each with different storage strategies and cost profiles.

**Cross-transaction enforcement** detects patterns that span multiple transactions. For example, a governance manipulation pattern (delegate in tx1, vote in tx2, undelegate in tx3) spans three transactions. Cross-transaction enforcement requires persistent storage (SSTORE/SLOAD) for the rolling state, because the state must survive across transactions. The rolling state is keyed by `msg.sender` (or some other identity), so each address has its own operation history. Cost per operation: 100 gas (SLOAD rolling state, warm) + 106 gas (SLOAD bitmap + check) + 5,000 gas (SSTORE rolling state, warm dirty) = approximately 5,206 gas.

**Intra-transaction enforcement** detects patterns that occur within a single transaction. For example, a flash loan attack (borrow, manipulate, profit) executes entirely within one transaction. Intra-transaction enforcement can use transient storage (TSTORE/TLOAD, 100 gas each, introduced in EIP-1153, deployed in Dencun, March 2024), which is dramatically cheaper than persistent storage. Cost per operation: 100 gas (TLOAD rolling state) + 106 gas (SLOAD bitmap + check) + 100 gas (TSTORE rolling state) = approximately 306 gas. The bitmap itself remains in persistent storage because it is a policy parameter, not per-transaction state.

The 306-gas intra-transaction mode is the more practical deployment path. Most high-frequency MEV attacks (sandwiches, flash loan exploits) execute within a single transaction. The 5,206-gas cross-transaction mode is viable only for lower-frequency operations where the overhead is a smaller fraction of total gas.

### 2.7 Per-Address vs. Global Enforcement

The rolling state can be scoped in two ways.

**Per-address rolling state** tracks each address's operation history independently. This is appropriate for detecting patterns attributed to a single actor (e.g., one address performing buy-then-sell around a victim's swap). The storage key for the rolling state is `keccak256(msg.sender, ROLLING_STATE_SLOT)`.

**Global rolling state** tracks the protocol's operation history across all callers. This is appropriate for detecting patterns that involve multiple actors but share a common structure (e.g., any buy followed by any external event followed by any sell, regardless of who performed each step). The storage key is a fixed slot.

Per-address enforcement is more precise (fewer false positives) but can be evaded by splitting an attack across multiple addresses. Global enforcement captures more attack patterns but has a higher false positive rate (legitimate sequences from different users may form a "forbidden" $n$-gram coincidentally). A hybrid approach, where some forbidden $n$-grams are enforced per-address and others globally, is possible by maintaining two rolling states.

---

## 3. Attack Pattern Encoding

### 3.1 Sandwich Attacks

A sandwich attack on an AMM consists of three operations: (1) the attacker buys token B with token A (frontrun), (2) the victim swaps A for B at a worse price, (3) the attacker sells token B for token A (backrun). Using the alphabet from Section 2.2:

The attacker's sequence is: `swap_A_to_B` (symbol 0), then some operations by others, then `swap_B_to_A` (symbol 1). The challenge is that the victim's transaction is interleaved between the attacker's frontrun and backrun.

**Intra-transaction encoding (attacker's callback or bundle).** If the attacker executes the frontrun and backrun within the same call stack (e.g., via a callback from the pool), the per-address intra-transaction rolling state will observe the 2-gram `(swap_A_to_B, swap_B_to_A)` = `(0, 1)` or the 3-gram `(swap_A_to_B, *, swap_B_to_A)` where `*` is any intervening operation. For $n = 2$, the forbidden 2-gram `(0, 1)` would block any direct buy-then-sell sequence. This is too restrictive: it also blocks legitimate round-trip trades. For $n = 3$, the forbidden 3-gram `(0, external_callback, 1)` would require encoding the intermediate callback as a distinct operation type, which is more precise but requires expanding the alphabet.

**Cross-transaction encoding.** If the frontrun and backrun are separate transactions (the typical case on Ethereum L1), per-address cross-transaction enforcement with rolling state would detect the pattern `(swap_A_to_B, swap_B_to_A)` from the same address within consecutive operations. However, the victim's transaction is from a different address and would not appear in the attacker's rolling state. The attacker's per-address history would show `(swap_A_to_B, swap_B_to_A)` as consecutive operations, which is the 2-gram `(0, 1)`. This is detectable with $n = 2$.

**Limitation.** The attacker can evade per-address detection by using two different addresses for the frontrun and backrun. This is the fundamental limitation of per-address enforcement. Global enforcement would detect the protocol-level pattern `(swap_A_to_B_by_anyone, swap_A_to_B_by_victim, swap_B_to_A_by_anyone)`, but this requires an alphabet that distinguishes "by attacker" from "by victim," which is not knowable at execution time. The policy can only operate on observable attributes (operation type, direction), not on the intent behind the operation.

### 3.2 Flash Loan Attacks

Flash loan attacks execute entirely within a single transaction. The typical pattern is: borrow via flash loan, perform some price manipulation (swaps, liquidity changes), then repay the flash loan and extract profit. Using the alphabet:

The 3-gram `(flash_loan, swap_A_to_B, remove_liquidity)` = `(4, 0, 3)` would capture a specific manipulation pattern. The 3-gram `(flash_loan, remove_liquidity, swap_B_to_A)` = `(4, 3, 1)` would capture another. A more general approach is to forbid any 3-gram of the form `(flash_loan, *, remove_liquidity)` for all $* \in \Sigma$, which is a set of $k$ forbidden 3-grams.

Intra-transaction enforcement with transient storage is the natural fit here: the entire attack occurs within one transaction, and the 306-gas overhead per step is acceptable.

### 3.3 Governance Manipulation

The pattern (delegate, vote, undelegate) executed by the same address within a short period is a governance attack that inflates voting power temporarily. With an appropriate alphabet:

| Symbol | Operation |
|---|---|
| 0 | `delegate` |
| 1 | `vote` |
| 2 | `undelegate` |
| 3 | `propose` |
| 4 | `other` |

The forbidden 3-gram `(delegate, vote, undelegate)` = `(0, 1, 2)` captures this pattern. Cross-transaction enforcement is required (these are separate transactions). With $k = 5, n = 3$: $5^3 = 125$ possible 3-grams, fitting in a single storage slot.

### 3.4 Designing Forbidden Sets in Practice

The process for designing a forbidden set is:

**Step 1.** Define the operation alphabet $\Sigma$ for the specific protocol, covering all externally callable state-changing functions.

**Step 2.** Analyze historical MEV data (from sources like Flashbots MEV-Explore, EigenPhi, or ZeroMEV) to identify the most common attack patterns expressed as $n$-grams over $\Sigma$.

**Step 3.** For each candidate forbidden $n$-gram, assess the false positive rate: what fraction of legitimate operation sequences would be blocked? This requires analyzing legitimate usage data from the same sources.

**Step 4.** Compute the capacity $h(X_F)$ of the resulting SFT to quantify the overall restrictiveness of the policy.

**Step 5.** Deploy with governance-updatable bitmap, so the forbidden set can be adjusted as new attack patterns emerge or false positives are discovered.

---

## 4. Gas Cost Analysis

### 4.1 Deployment Costs

Deploying the forbidden bitmap requires writing $\lceil k^n / 256 \rceil$ storage slots. For the single-slot case ($k^n \leq 256$): one SSTORE at 20,000 gas (cold, zero-to-nonzero). For 6 slots ($k = 6, n = 4$): 120,000 gas. This is a one-time cost.

### 4.2 Per-Operation Costs

| Mode | LOAD rolling state | Bitmap check | STORE rolling state | Total |
|---|---|---|---|---|
| Intra-tx (transient) | 100 gas (TLOAD) | 106 gas (SLOAD + bit extraction) | 100 gas (TSTORE) | **306 gas** |
| Cross-tx (persistent, warm) | 100 gas (SLOAD) | 106 gas (SLOAD + bit extraction) | 5,000 gas (SSTORE dirty) | **5,206 gas** |
| Cross-tx (persistent, cold first access) | 2,100 gas (SLOAD) | 2,100 gas (SLOAD) | 20,000 gas (SSTORE) | **24,200 gas** |

The cold first-access cost (24,200 gas) occurs once per transaction for each unique address accessing the contract. Subsequent operations within the same transaction benefit from warm pricing.

### 4.3 Overhead as Fraction of Typical Operations

| Protocol operation | Typical gas cost | Intra-tx overhead | Cross-tx overhead (warm) |
|---|---|---|---|
| Uniswap v3 swap | 120,000 - 150,000 | 0.20% - 0.26% | 3.5% - 4.3% |
| Uniswap v2 swap | 60,000 - 80,000 | 0.38% - 0.51% | 6.5% - 8.7% |
| Aave borrow | 200,000 - 300,000 | 0.10% - 0.15% | 1.7% - 2.6% |
| ERC-20 transfer | 21,000 - 50,000 | 0.61% - 1.5% | 10.4% - 24.8% |

The intra-transaction mode is viable for all operations. The cross-transaction mode is acceptable for high-gas operations (swaps, borrows) but imposes significant overhead on simple transfers.

### 4.4 Bitmap Update Cost (Governance)

Updating the forbidden bitmap (adding or removing forbidden patterns) requires one SSTORE per affected 256-bit slot. Adding a single forbidden $n$-gram to an existing bitmap costs: SLOAD (100 gas warm) + bit manipulation (15 gas) + SSTORE (5,000 gas warm dirty) = 5,115 gas. This is a governance operation, not a per-user cost.

---

## 5. Design Space and Parameter Selection

### 5.1 The $(k, n)$ Trade-off

Increasing $k$ (larger alphabet, finer-grained operation types) improves pattern discrimination (fewer false positives, more precise attack matching) but increases bitmap size exponentially ($k^n$ bits). Increasing $n$ (longer lookback) captures more complex multi-step attack patterns but also increases bitmap size and may increase false positive rates (longer legitimate sequences are more likely to coincidentally match a forbidden pattern).

The practical sweet spot for most DeFi protocols is $k \leq 6$ and $n \leq 4$, yielding bitmaps of at most $6^4 = 1296$ bits (6 storage slots). This is because: most known MEV attack patterns involve 2-4 steps, most protocols have fewer than 8 distinct operation types, and the gas overhead of maintaining more than a handful of storage slots for the bitmap starts to matter.

### 5.2 Hierarchical Policies

For protocols with many operation types, a two-level hierarchy can keep the bitmap small. The first level classifies operations into broad categories (e.g., "swap," "liquidity," "governance," "lending"). The second level, applied only when the first level flags a suspicious category sequence, checks a finer-grained alphabet. This is implementable as two separate modifier checks: the first uses a small bitmap ($k_1^{n_1}$ bits, where $k_1$ is the number of categories), and the second is only invoked if the first level detects a category sequence that could be part of an attack.

### 5.3 Wildcard Patterns

A common need is to forbid patterns of the form "operation A, then anything, then operation B" (the wildcard $n$-gram). With a strict $n$-gram model, this requires enumerating all $k$ possible values for the wildcard position, creating $k$ forbidden $n$-grams. For $n = 3$ and $k = 6$, the wildcard pattern `(A, *, B)` generates 6 forbidden 3-grams. This is manageable. For higher $n$ with multiple wildcards, the enumeration can grow, but for practical parameter ranges, it remains tractable.

---

## 6. Limitations and Adversarial Analysis

### 6.1 Evasion by Address Splitting

The most straightforward evasion of per-address enforcement is for the attacker to use a different address for each step of the attack. The frontrun comes from address $A_1$, the backrun from address $A_2$. Neither address's rolling state shows a forbidden $n$-gram. Global enforcement partially addresses this (it observes all operations regardless of sender) but introduces false positives from unrelated users' operations coincidentally forming a forbidden pattern.

This is a fundamental limitation. The policy enforces sequential constraints on observable operation types, not on economic intent. Any attack that can be decomposed into individually innocuous operations from different addresses is invisible to this mechanism.

### 6.2 Evasion by Pattern Mutation

If the forbidden set is public (which it must be, since on-chain state is public), the attacker can examine it and modify their attack to avoid forbidden patterns. For example, if the 3-gram `(swap_A_to_B, swap_A_to_B, swap_B_to_A)` is forbidden, the attacker can insert a no-op operation (e.g., a dust transfer) between steps to break the pattern: `(swap_A_to_B, transfer, swap_B_to_A)`, which produces a different 3-gram not in the forbidden set.

Mitigation: the alphabet should be designed so that "no-op" or "dust" operations are either excluded from the alphabet (they don't update the rolling state) or are collapsed into a neutral symbol that doesn't break attack patterns. This requires careful alphabet design.

### 6.3 False Positives

A false positive occurs when a legitimate sequence of operations matches a forbidden $n$-gram. For example, if `(swap_A_to_B, swap_B_to_A)` is forbidden (targeting sandwich attackers), a legitimate user who buys token B and then changes their mind and sells it back would be blocked.

The severity of false positives depends on the protocol. For an AMM where round-trips are rare and usually indicate wash trading or attack behavior, the false positive rate may be acceptably low. For a lending protocol where users frequently deposit and withdraw, false positives from forbidden `(deposit, withdraw)` patterns would be unacceptable.

False positive analysis must be performed empirically on real transaction data before deploying a forbidden set. No theoretical argument can substitute for this measurement.

### 6.4 Governance Attack Surface

The forbidden bitmap is governance-updatable. This means the governance mechanism can be used to maliciously block legitimate operations by adding their patterns to the forbidden set. This is not unique to this mechanism (any parameter-governance system has this attack surface), but the specificity of the forbidden set (it targets operation sequences, not amounts or addresses) makes the attack subtle and potentially hard to detect.

Mitigation: timelocks on bitmap updates, requiring a minimum delay between a governance proposal to update the forbidden set and its execution. During the delay, users and auditors can review the proposed changes.

---

## 7. Comparison with Existing MEV Defenses

### 7.1 Private Mempools (Flashbots Protect, MEV Blocker)

Private mempools prevent attackers from observing pending transactions, eliminating the information asymmetry that sandwich attacks require. They are effective against public mempool-based sandwich attacks but introduce trust assumptions (the private mempool operator could itself be an attacker) and do not prevent sandwich attacks by block builders or validators who see private transactions. Recent research (referenced in Phase 3 searches) documents that sandwich attacks persist even through private channels, with 2,932 private sandwich attacks recorded in November-December 2024 alone.

The forbidden-sequence policy is complementary: it operates at the execution layer, not the transaction ordering layer. Even if an attacker obtains privileged ordering (through private channels, builder cooperation, or validator collusion), the execution-layer check can still block the forbidden pattern if it occurs within the contract's call stack.

### 7.2 Reentrancy Guards

Reentrancy guards (including EIP-1153 transient storage guards) prevent a contract from being re-entered during execution. They are a specific case of intra-transaction sequence enforcement: they forbid the 2-gram `(enter, enter)` for the same contract. The forbidden-sequence policy generalizes reentrancy guards to arbitrary $n$-grams over arbitrary operation alphabets. A reentrancy guard is a forbidden-sequence policy with $k = 2$ (enter/exit), $n = 2$, and $F = \{(enter, enter)\}$.

### 7.3 Time-Weighted Average Prices (TWAP Oracles)

TWAP oracles mitigate price manipulation by averaging prices over time, making single-block manipulation less effective. They address the economic impact of attacks, not the attack structure. A forbidden-sequence policy addresses the attack structure, not its economic impact. They are complementary.

### 7.4 Slippage Limits

Slippage limits cap the maximum price deviation a user will accept. They reduce the profitability of sandwich attacks but do not prevent them. A sandwich attack that stays within the slippage tolerance still succeeds. The forbidden-sequence policy would prevent the attack pattern regardless of slippage tolerance, but only if the pattern is in the forbidden set.

### 7.5 Summary

| Defense | Layer | What it prevents | What it misses |
|---|---|---|---|
| Private mempool | Transaction ordering | Public mempool snooping | Builder/validator collusion |
| Reentrancy guard | Execution (binary) | Self-reentrancy | Multi-step non-reentrant attacks |
| TWAP oracle | Economic | Single-block price manipulation | Multi-block manipulation |
| Slippage limit | Economic | Excessive price impact | Attacks within tolerance |
| **Forbidden-sequence** | **Execution (general)** | **Known sequential patterns** | **Novel patterns, address splitting** |

The forbidden-sequence policy fills a gap: execution-layer enforcement of general sequential patterns. No existing mechanism provides this capability.

---

## 8. Empirical Validation Plan

### 8.1 Data Requirements

To validate the mechanism, the following data is needed:

**MEV attack data.** Source: ZeroMEV, EigenPhi, Flashbots MEV-Explore. Required fields: attack type, block number, transaction indices, operation types (swap direction, liquidity add/remove, flash loan), attacker addresses, victim addresses.

**Legitimate usage data.** Source: Same DEX/lending protocol transaction logs. Required fields: all operations by all users, with the same operation type classification used for the attack data.

### 8.2 Validation Protocol

**Step 1.** Select a target protocol (e.g., Uniswap v2 or v3) and define the operation alphabet.

**Step 2.** Extract 6 months of historical transaction data (all operations on the protocol, classified by type).

**Step 3.** Extract all MEV attacks on the same protocol over the same period (from ZeroMEV or EigenPhi).

**Step 4.** For each MEV attack, compute the $n$-gram sequence at the attacker's per-address level and at the global protocol level. Determine whether any forbidden $n$-gram would have caught the attack.

**Step 5.** For the legitimate usage data, compute all $n$-gram sequences for all users. Determine how many legitimate sequences would have been blocked by the same forbidden set.

**Step 6.** Report: attack detection rate (true positive rate), false positive rate, and capacity of the SFT.

### 8.3 Success Criteria

The mechanism is worth deploying if:
- The true positive rate exceeds 50% for the most common attack type (sandwich attacks)
- The false positive rate is below 0.1% (fewer than 1 in 1,000 legitimate operations blocked)
- The capacity of the SFT exceeds 0.9 (the constraint removes fewer than 10% of the valid operation space)

These thresholds are judgments, not mathematical requirements. The protocol's governance should set its own thresholds based on its risk tolerance.

### 8.4 What Would Constitute Failure

The mechanism fails if:
- The false positive rate exceeds 1%, indicating the forbidden set is too aggressive
- The true positive rate is below 20%, indicating attackers trivially evade the forbidden patterns
- The gas overhead exceeds 10% of the protected operation's cost, indicating the defense is too expensive relative to its value

---

## 9. Implementation Notes

The Solidity implementation is provided in a separate artifact. Key implementation decisions:

**The rolling state and enforcement logic are implemented as a Solidity abstract contract** with virtual functions for operation type classification. Concrete protocols inherit from this contract and implement the `_classifyOperation` function to map their specific function selectors to operation type symbols.

**The forbidden bitmap is stored in a dedicated storage slot** computed from a constant salt, avoiding collision with other storage variables. For the multi-slot case, consecutive slots are used.

**Both intra-transaction (transient storage) and cross-transaction (persistent storage) modes are supported.** The intra-transaction mode uses EIP-1153 TSTORE/TLOAD. The cross-transaction mode uses standard SSTORE/SLOAD with per-address keying.

**The bitmap is updatable via a governance function** protected by an `onlyGovernance` modifier. A timelock is recommended but not enforced at the library level (it should be implemented by the inheriting contract's governance system).

**The enforcement is implemented as a modifier** (`sequenceGuard`) that can be applied to any external function. The modifier calls `_classifyOperation` to determine the operation type, performs the check, and updates the rolling state.
