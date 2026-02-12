// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SFTSequenceEnforcer
 * @author Derived from "Forbidden-Sequence Policy Enforcement via Shift-of-Finite-Type Constraints"
 * @notice Abstract contract implementing forbidden-sequence policy enforcement via
 *         Shift-of-Finite-Type (SFT) constraints on the de Bruijn graph G(k, n).
 *
 * @dev Core mechanism (Sections 1.1-1.2 of the spec):
 *
 *      Given a finite alphabet Sigma = {0, 1, ..., k-1} and a forbidden set F of
 *      n-grams, the SFT X_F is the set of all sequences such that no contiguous
 *      substring of length n belongs to F. Enforcement is Markovian: checking
 *      whether a new symbol `a` extends a valid sequence requires examining only
 *      the most recent n-1 symbols (the rolling state sigma).
 *
 *      The n-gram formed by (sigma, a) = (a_1, ..., a_{n-1}, a) is valid iff it
 *      does not belong to F. This is a constant-time bitmap lookup regardless of
 *      history length.
 *
 *      On-chain state (Section 2.1):
 *        Component 2a: Forbidden bitmap B of k^n bits, packed into ceil(k^n / 256)
 *                       storage slots. Bit i is set iff the n-gram with lexicographic
 *                       index i is forbidden.
 *        Component 2b: Rolling state variable sigma storing the most recent n-1
 *                       operation types, packed into a single storage slot.
 *
 *      Per-operation enforcement (Section 2.1, Component 3):
 *        1. Compute n-gram index: i(w) = sigma * k + a_new  (Section 2.4)
 *        2. Check bitmap bit i: forbidden = (B[i/256] >> (i%256)) & 1  (Section 2.5)
 *        3. Revert if forbidden.
 *        4. Update rolling state: sigma_new = (sigma_old mod k^{n-2}) * k + a_new  (Section 2.3)
 *
 *      Enforcement modes (Section 2.6):
 *        - Intra-transaction: TLOAD/TSTORE (EIP-1153) for rolling state. ~306 gas/op.
 *        - Cross-transaction: SLOAD/SSTORE for rolling state. ~5,206 gas/op (warm).
 *
 *      Enforcement scopes (Section 2.7):
 *        - Per-address: rolling state keyed by keccak256(msg.sender, salt). Tracks each
 *          actor's operation history independently.
 *        - Global: rolling state at fixed slot. Tracks protocol-wide operation sequence
 *          across all callers. Higher false-positive rate, captures cross-address patterns.
 *
 *      Inheriting contracts MUST implement _classifyOperation() to map function selectors
 *      to operation type symbols in [0, k). The contract uses msg.sig directly per
 *      Section 9: "a pure mapping from function selectors to symbols, with no side effects."
 *
 * @dev Parameter constraints (Section 5.1):
 *      Practical sweet spot is k <= 8, n <= 4. This yields bitmaps of at most
 *      8^4 = 4096 bits (16 storage slots). Most known MEV patterns involve 2-4 steps,
 *      and most protocols have fewer than 8 distinct operation types.
 */
abstract contract SFTSequenceEnforcer {

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────

    /// @dev Reverted when the n-gram formed by (rolling state, new op) is in the forbidden set.
    error ForbiddenSequence(uint256 ngramIndex);

    /// @dev Reverted when _classifyOperation returns a value >= k.
    error InvalidOperationType(uint256 opType, uint256 alphabetSize);

    /// @dev Reverted when an n-gram index exceeds k^n.
    error InvalidNgramIndex(uint256 index, uint256 maxIndex);

    /// @dev Reverted when constructor receives k > MAX_K.
    error AlphabetSizeTooLarge(uint256 k, uint256 maxK);

    /// @dev Reverted when constructor receives n > MAX_N or n < 2.
    error LookbackDepthInvalid(uint256 n, uint256 maxN);

    /// @dev Reverted when caller is not the governance address.
    error Unauthorized();

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event ForbiddenBitmapSlotUpdated(uint256 indexed slotIndex, uint256 newValue);
    event NgramForbidden(uint256 indexed ngramIndex);
    event NgramAllowed(uint256 indexed ngramIndex);
    event GovernanceTransferred(address indexed previous, address indexed next);

    // ──────────────────────────────────────────────
    //  Constants & Immutables
    // ──────────────────────────────────────────────

    /// @dev Upper bound on alphabet size. k=8, n=4 -> 4096-bit bitmap (16 slots).
    uint256 internal constant MAX_K = 8;

    /// @dev Upper bound on lookback depth.
    uint256 internal constant MAX_N = 4;

    /// @notice Alphabet cardinality: number of distinct operation types.
    uint256 public immutable k;

    /// @notice Lookback depth: n-gram length.
    uint256 public immutable n;

    /// @notice Total number of possible n-grams: k^n.
    uint256 public immutable totalNgrams;

    /// @notice k^{n-1}. Used in n-gram index computation: i = sigma * k + a.
    ///         Also the number of vertices in the de Bruijn graph G(k, n).
    uint256 public immutable kToNMinus1;

    /// @notice k^{n-2}. Used in rolling state update: sigma_new = (sigma_old % kToNMinus2) * k + a.
    ///         Drops the oldest symbol from the (n-1)-gram.
    uint256 public immutable kToNMinus2;

    /// @notice Number of uint256 storage slots required for the forbidden bitmap.
    uint256 public immutable bitmapSlotCount;

    // ──────────────────────────────────────────────
    //  Storage Layout
    //  All slots are derived from constant salts to avoid collision with
    //  inheriting contracts (Section 9: "dedicated storage slot computed
    //  from a constant salt").
    // ──────────────────────────────────────────────

    /// @dev Base slot for the forbidden bitmap array. Bitmap occupies
    ///      [BITMAP_BASE, BITMAP_BASE + bitmapSlotCount).
    bytes32 internal constant BITMAP_BASE =
        keccak256("SFTSequenceEnforcer.bitmap.v1");

    /// @dev Salt for per-address cross-transaction rolling state.
    ///      Actual slot = keccak256(abi.encode(account, CROSS_TX_SALT)).
    bytes32 internal constant CROSS_TX_SALT =
        keccak256("SFTSequenceEnforcer.crossTx.state.v1");

    /// @dev Salt for per-address intra-transaction rolling state (transient).
    ///      Actual slot = keccak256(abi.encode(account, INTRA_TX_SALT)).
    bytes32 internal constant INTRA_TX_SALT =
        keccak256("SFTSequenceEnforcer.intraTx.perAddr.v1");

    /// @dev Fixed transient slot for global intra-transaction rolling state.
    bytes32 internal constant GLOBAL_INTRA_TX_SLOT =
        keccak256("SFTSequenceEnforcer.intraTx.global.v1");

    /// @dev Governance address slot.
    bytes32 internal constant GOVERNANCE_SLOT =
        keccak256("SFTSequenceEnforcer.governance.v1");

    // ──────────────────────────────────────────────
    //  Packed State Layout
    //
    //  Both transient and persistent rolling states use the same packing:
    //
    //    [255]       : initialized flag (1 = has at least one recorded op)
    //    [254:248]   : opCount — number of operations recorded, saturates at n-1.
    //                  The bitmap check activates only when opCount == n-1,
    //                  meaning a full (n-1)-gram is available.
    //    [247:0]     : rolling state sigma, base-k encoded integer in [0, k^{n-1}).
    //
    //  For max params (k=8, n=4), sigma max = 8^3 = 512 (10 bits). The 248-bit
    //  field is far more than sufficient.
    // ──────────────────────────────────────────────

    uint256 internal constant INIT_BIT = 1 << 255;
    uint256 internal constant COUNT_SHIFT = 248;
    uint256 internal constant COUNT_MASK = 0x7F; // 7 bits, max 127
    uint256 internal constant STATE_MASK = (1 << 248) - 1;

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    /**
     * @param _k Alphabet cardinality. Must be in [2, MAX_K].
     * @param _n Lookback depth. Must be in [2, MAX_N].
     * @param _governance Address authorized to update the forbidden bitmap.
     */
    constructor(uint256 _k, uint256 _n, address _governance) {
        if (_k < 2 || _k > MAX_K) revert AlphabetSizeTooLarge(_k, MAX_K);
        if (_n < 2 || _n > MAX_N) revert LookbackDepthInvalid(_n, MAX_N);

        k = _k;
        n = _n;
        totalNgrams = _pow(_k, _n);
        kToNMinus1 = _pow(_k, _n - 1);
        kToNMinus2 = _pow(_k, _n - 2);
        bitmapSlotCount = (totalNgrams + 255) / 256;

        _setGovernance(_governance);
    }

    // ──────────────────────────────────────────────
    //  Governance
    // ──────────────────────────────────────────────

    modifier onlyGovernance() {
        if (msg.sender != governance()) revert Unauthorized();
        _;
    }

    function governance() public view returns (address gov) {
        bytes32 s = GOVERNANCE_SLOT;
        assembly { gov := sload(s) }
    }

    /**
     * @notice Transfer governance to a new address. The inheriting contract
     *         should implement a timelock around this (Section 6.4).
     */
    function transferGovernance(address newGov) external onlyGovernance {
        emit GovernanceTransferred(governance(), newGov);
        _setGovernance(newGov);
    }

    // ──────────────────────────────────────────────
    //  Forbidden Bitmap — Governance Writes
    // ──────────────────────────────────────────────

    /**
     * @notice Mark a single n-gram as forbidden.
     * @dev Gas: ~5,115 (SLOAD + bit op + SSTORE warm dirty). Section 4.4.
     */
    function forbidNgram(uint256 idx) external onlyGovernance {
        _requireValidIndex(idx);
        _writeBitmapBit(idx, true);
        emit NgramForbidden(idx);
    }

    /// @notice Remove a single n-gram from the forbidden set.
    function allowNgram(uint256 idx) external onlyGovernance {
        _requireValidIndex(idx);
        _writeBitmapBit(idx, false);
        emit NgramAllowed(idx);
    }

    /// @notice Batch-forbid multiple n-grams. Useful for wildcard expansion (Section 5.3).
    function forbidNgrams(uint256[] calldata indices) external onlyGovernance {
        uint256 len = indices.length;
        for (uint256 i; i < len;) {
            uint256 idx = indices[i];
            _requireValidIndex(idx);
            _writeBitmapBit(idx, true);
            emit NgramForbidden(idx);
            unchecked { ++i; }
        }
    }

    /// @notice Batch-allow multiple n-grams.
    function allowNgrams(uint256[] calldata indices) external onlyGovernance {
        uint256 len = indices.length;
        for (uint256 i; i < len;) {
            uint256 idx = indices[i];
            _requireValidIndex(idx);
            _writeBitmapBit(idx, false);
            emit NgramAllowed(idx);
            unchecked { ++i; }
        }
    }

    /**
     * @notice Write a full 256-bit bitmap slot directly. Used for initial
     *         deployment or bulk governance updates.
     * @dev Deployment cost: 20,000 gas per slot (cold, zero-to-nonzero). Section 4.1.
     * @param slotIndex Index in [0, bitmapSlotCount).
     * @param value The 256-bit word to write.
     */
    function writeBitmapSlot(uint256 slotIndex, uint256 value) external onlyGovernance {
        if (slotIndex >= bitmapSlotCount) revert InvalidNgramIndex(slotIndex, bitmapSlotCount);
        bytes32 s = _bitmapStorageSlot(slotIndex);
        assembly { sstore(s, value) }
        emit ForbiddenBitmapSlotUpdated(slotIndex, value);
    }

    /**
     * @notice Write multiple consecutive bitmap slots in a single call.
     *         Most gas-efficient path for initial deployment.
     * @param startSlot Starting slot index.
     * @param values Array of 256-bit words, one per slot.
     */
    function writeBitmapSlots(uint256 startSlot, uint256[] calldata values) external onlyGovernance {
        uint256 len = values.length;
        if (startSlot + len > bitmapSlotCount) {
            revert InvalidNgramIndex(startSlot + len, bitmapSlotCount);
        }
        for (uint256 i; i < len;) {
            bytes32 s = _bitmapStorageSlot(startSlot + i);
            uint256 v = values[i];
            assembly { sstore(s, v) }
            emit ForbiddenBitmapSlotUpdated(startSlot + i, v);
            unchecked { ++i; }
        }
    }

    // ──────────────────────────────────────────────
    //  Enforcement Modifiers
    //
    //  Each modifier implements the three-step per-operation enforcement
    //  from Section 2.1 Component 3:
    //    1. Compute i(w) = sigma * k + a_new
    //    2. Check bitmap bit i
    //    3. Update sigma_new = (sigma_old % k^{n-2}) * k + a_new
    //
    //  The check at step 2 is only performed when the rolling state contains
    //  a complete (n-1)-gram (opCount >= n-1). Before that, we accumulate
    //  the initial state without checking.
    // ──────────────────────────────────────────────

    /**
     * @dev Per-address intra-transaction sequence guard.
     *      Uses EIP-1153 transient storage (TLOAD/TSTORE) for the rolling state.
     *      State resets automatically at end of transaction.
     *      Gas: ~306 per guarded call. Section 2.6.
     */
    modifier perAddrIntraTxGuard() {
        uint256 opType = _classifyOperation();
        _requireValidOpType(opType);
        bytes32 slot = _intraTxSlot(msg.sender);
        uint256 packed;
        assembly { packed := tload(slot) }
        packed = _enforceAndUpdate(packed, opType);
        assembly { tstore(slot, packed) }
        _;
    }

    /**
     * @dev Per-address cross-transaction sequence guard.
     *      Uses persistent storage (SLOAD/SSTORE) for the rolling state,
     *      keyed by keccak256(msg.sender, salt). Section 2.7.
     *      Gas: ~5,206 per call (warm), ~24,200 (cold first access). Section 4.2.
     */
    modifier perAddrCrossTxGuard() {
        uint256 opType = _classifyOperation();
        _requireValidOpType(opType);
        bytes32 slot = _crossTxSlot(msg.sender);
        uint256 packed;
        assembly { packed := sload(slot) }
        packed = _enforceAndUpdate(packed, opType);
        assembly { sstore(slot, packed) }
        _;
    }

    /**
     * @dev Global intra-transaction sequence guard.
     *      Tracks operations across all callers within a single transaction
     *      using a single fixed transient slot. Section 2.7.
     *      Higher false-positive rate, captures cross-address attack patterns.
     *      Gas: ~306 per call. Section 2.6.
     */
    modifier globalIntraTxGuard() {
        uint256 opType = _classifyOperation();
        _requireValidOpType(opType);
        bytes32 slot = GLOBAL_INTRA_TX_SLOT;
        uint256 packed;
        assembly { packed := tload(slot) }
        packed = _enforceAndUpdate(packed, opType);
        assembly { tstore(slot, packed) }
        _;
    }

    // ──────────────────────────────────────────────
    //  View / Pure Helpers
    // ──────────────────────────────────────────────

    /**
     * @notice Encode an n-gram from its component symbols to its lexicographic
     *         index. The index is the position in the lexicographic ordering of
     *         Sigma^n, computed as a base-k number.
     * @param ops Array of operation types, length must equal n.
     * @return idx Lexicographic index in [0, k^n).
     */
    function encodeNgram(uint256[] calldata ops) external view returns (uint256 idx) {
        require(ops.length == n, "Length must equal n");
        uint256 _k = k;
        for (uint256 i; i < ops.length;) {
            if (ops[i] >= _k) revert InvalidOperationType(ops[i], _k);
            idx = idx * _k + ops[i];
            unchecked { ++i; }
        }
    }

    /**
     * @notice Decode an n-gram index to its component operation types.
     * @param idx Lexicographic index in [0, k^n).
     * @return ops Array of n operation type symbols.
     */
    function decodeNgram(uint256 idx) external view returns (uint256[] memory ops) {
        _requireValidIndex(idx);
        uint256 _n = n;
        uint256 _k = k;
        ops = new uint256[](_n);
        uint256 rem = idx;
        for (uint256 i = _n; i > 0;) {
            unchecked { --i; }
            ops[i] = rem % _k;
            rem /= _k;
        }
    }

    /// @notice Check whether a specific n-gram is in the forbidden set.
    function isForbidden(uint256 idx) external view returns (bool) {
        _requireValidIndex(idx);
        return _readBitmapBit(idx);
    }

    /// @notice Read a full 256-bit bitmap slot.
    function readBitmapSlot(uint256 slotIndex) external view returns (uint256 value) {
        if (slotIndex >= bitmapSlotCount) revert InvalidNgramIndex(slotIndex, bitmapSlotCount);
        bytes32 s = _bitmapStorageSlot(slotIndex);
        assembly { value := sload(s) }
    }

    /**
     * @notice Read the cross-tx rolling state for an address.
     * @return initialized True if at least one operation has been recorded.
     * @return opCount Number of operations recorded (saturates at n-1).
     * @return sigma The rolling state: base-k encoded (n-1)-gram.
     */
    function getCrossTxState(address account)
        external
        view
        returns (bool initialized, uint256 opCount, uint256 sigma)
    {
        bytes32 slot = _crossTxSlot(account);
        uint256 packed;
        assembly { packed := sload(slot) }
        initialized = (packed & INIT_BIT) != 0;
        opCount = (packed >> COUNT_SHIFT) & COUNT_MASK;
        sigma = packed & STATE_MASK;
    }

    /**
     * @notice Simulate whether appending opType to a given rolling state
     *         would trigger a forbidden sequence. Pure off-chain pre-flight check.
     * @param sigma Current (n-1)-gram rolling state (base-k encoded).
     * @param opType Candidate next operation symbol.
     * @return forbidden True if the resulting n-gram is in the forbidden set.
     * @return ngramIdx The computed n-gram index: sigma * k + opType.
     */
    function simulateCheck(uint256 sigma, uint256 opType)
        external
        view
        returns (bool forbidden, uint256 ngramIdx)
    {
        _requireValidOpType(opType);
        ngramIdx = sigma * k + opType;
        _requireValidIndex(ngramIdx);
        forbidden = _readBitmapBit(ngramIdx);
    }

    /**
     * @notice Reset cross-tx rolling state for an address.
     *         Governance-only; intended for clearing false-positive blocks
     *         (Section 6.3).
     */
    function resetCrossTxState(address account) external onlyGovernance {
        bytes32 slot = _crossTxSlot(account);
        assembly { sstore(slot, 0) }
    }

    // ──────────────────────────────────────────────
    //  Abstract: Operation Classification
    // ──────────────────────────────────────────────

    /**
     * @dev Must be implemented by the inheriting contract. Maps the current
     *      call context to an operation type symbol in [0, k).
     *
     *      Per Section 9: "a pure mapping from function selectors to symbols,
     *      with no side effects." The implementation should inspect msg.sig
     *      and return the corresponding symbol.
     */
    function _classifyOperation() internal view virtual returns (uint256 opType);

    // ──────────────────────────────────────────────
    //  Internal: Core Enforcement Logic
    // ──────────────────────────────────────────────

    /**
     * @dev Unified enforce-and-update logic used by all modifiers.
     *      Implements the exact formulas from Sections 2.3 and 2.4:
     *
     *        n-gram index:    i = sigma * k + a_new           (Section 2.4)
     *        state update:    sigma_new = (sigma_old % k^{n-2}) * k + a_new  (Section 2.3)
     *
     *      The bitmap check is performed only when the rolling state holds a
     *      complete (n-1)-gram (opCount >= n-1).
     *
     * @param packed The current packed rolling state word.
     * @param opType The incoming operation symbol.
     * @return The updated packed rolling state word.
     */
    function _enforceAndUpdate(uint256 packed, uint256 opType) internal view returns (uint256) {
        uint256 _k = k;
        uint256 _nMinus1 = n - 1;
        uint256 _kToNMinus2 = kToNMinus2;

        bool initialized = (packed & INIT_BIT) != 0;
        uint256 opCount = (packed >> COUNT_SHIFT) & COUNT_MASK;
        uint256 sigma = packed & STATE_MASK;

        if (initialized && opCount >= _nMinus1) {
            // Full (n-1)-gram available. Compute and check the n-gram index.
            // i(w) = sigma * k + a_new  (Section 2.4, ~8 gas: MUL + ADD)
            uint256 ngramIdx = sigma * _k + opType;

            // Bitmap lookup (Section 2.5, ~106 gas: SLOAD + SHR + AND)
            if (_readBitmapBit(ngramIdx)) {
                revert ForbiddenSequence(ngramIdx);
            }

            // Rolling state update (Section 2.3):
            // sigma_new = (sigma_old mod k^{n-2}) * k + a_new
            // This drops the oldest symbol and appends the new one.
            sigma = (sigma % _kToNMinus2) * _k + opType;
        } else if (initialized) {
            // Still accumulating the initial (n-1)-gram. Append without checking.
            // sigma = sigma * k + opType builds up the base-k number.
            sigma = sigma * _k + opType;
            unchecked { ++opCount; }
        } else {
            // First operation ever for this scope. Initialize.
            sigma = opType;
            opCount = 1;
        }

        // Pack: [init flag | opCount | sigma]
        return INIT_BIT | (opCount << COUNT_SHIFT) | sigma;
    }

    // ──────────────────────────────────────────────
    //  Internal: Bitmap Read/Write
    // ──────────────────────────────────────────────

    /// @dev Compute the storage slot for bitmap word at `slotIndex`.
    ///      Uses consecutive slots starting from BITMAP_BASE.
    function _bitmapStorageSlot(uint256 slotIndex) internal pure returns (bytes32) {
        return bytes32(uint256(BITMAP_BASE) + slotIndex);
    }

    /**
     * @dev Read bit `bitIndex` from the forbidden bitmap.
     *      Section 2.5: slot = floor(i / 256), bit = i mod 256.
     *      Gas: SLOAD (100 warm) + SHR (3) + AND (3) = 106 gas.
     */
    function _readBitmapBit(uint256 bitIndex) internal view returns (bool) {
        bytes32 s = _bitmapStorageSlot(bitIndex >> 8); // bitIndex / 256
        uint256 word;
        assembly { word := sload(s) }
        return ((word >> (bitIndex & 0xFF)) & 1) == 1; // bitIndex % 256
    }

    /**
     * @dev Write a single bit in the forbidden bitmap.
     *      Gas: ~5,115 (SLOAD + bit op + SSTORE warm dirty). Section 4.4.
     */
    function _writeBitmapBit(uint256 bitIndex, bool value) internal {
        uint256 slotIndex = bitIndex >> 8;
        uint256 bitOffset = bitIndex & 0xFF;
        bytes32 s = _bitmapStorageSlot(slotIndex);
        uint256 word;
        assembly { word := sload(s) }

        if (value) {
            word = word | (1 << bitOffset);
        } else {
            word = word & ~(1 << bitOffset);
        }

        assembly { sstore(s, word) }
        emit ForbiddenBitmapSlotUpdated(slotIndex, word);
    }

    // ──────────────────────────────────────────────
    //  Internal: Slot Computation
    // ──────────────────────────────────────────────

    /// @dev Per-address cross-tx state slot: keccak256(account, CROSS_TX_SALT).
    function _crossTxSlot(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, CROSS_TX_SALT));
    }

    /// @dev Per-address intra-tx transient slot: keccak256(account, INTRA_TX_SALT).
    function _intraTxSlot(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, INTRA_TX_SALT));
    }

    // ──────────────────────────────────────────────
    //  Internal: Validation
    // ──────────────────────────────────────────────

    function _requireValidIndex(uint256 idx) internal view {
        if (idx >= totalNgrams) revert InvalidNgramIndex(idx, totalNgrams);
    }

    function _requireValidOpType(uint256 opType) internal view {
        if (opType >= k) revert InvalidOperationType(opType, k);
    }

    function _setGovernance(address gov) internal {
        bytes32 s = GOVERNANCE_SLOT;
        assembly { sstore(s, gov) }
    }

    // ──────────────────────────────────────────────
    //  Internal: Math
    // ──────────────────────────────────────────────

    /// @dev Integer exponentiation. Safe for the parameter range k <= 8, n <= 4.
    function _pow(uint256 base, uint256 exp) internal pure returns (uint256 result) {
        result = 1;
        for (uint256 i; i < exp;) {
            result *= base;
            unchecked { ++i; }
        }
    }
}
