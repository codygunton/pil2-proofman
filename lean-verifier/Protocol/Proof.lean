/-
  STARK proof data structures and binary deserialization.

  Translates: executable-spec/protocol/proof.py

  Binary format: flat array of little-endian uint64 values, structured in sections:
  1. airgroupValues (n_airgroup_values * 3 uint64s)
  2. airValues (n_air_values * 3 uint64s)
  3. roots ((n_stages + 1) * 4 uint64s)
  4. evals (n_evals * 3 uint64s)
  5-7. const tree query proofs (values, merkle paths, last levels)
  8. custom commit query proofs
  9. stage tree query proofs (cm1..cmQ)
  10. FRI step roots
  11. FRI step query proofs
  12. finalPol
  13. nonce (1 uint64)
-/
import Protocol.StarkInfo

namespace Protocol.Proof

open Protocol.StarkInfo (HASH_SIZE FIELD_EXTENSION_DEGREE StarkStruct StarkInfo
  FriFoldStep lookupSection)

-- ============================================================================
-- Type Aliases
-- ============================================================================

/-- Poseidon hash output: 4 uint64 field elements. -/
abbrev Hash := Array UInt64

/-- Extension field element: 3 uint64 coefficients [c0, c1, c2]. -/
abbrev FF3Val := Array UInt64

-- ============================================================================
-- Proof Data Structures
-- ============================================================================

/-- Merkle authentication path: leaf values and sibling hashes.

    Translates: proof.py:21-24 MerkleProof

    - `v`: Leaf values. Each entry is a single-element array wrapping one column value.
    - `mp`: Sibling hashes per Merkle tree level. Each entry is an array of
            (arity - 1) * HASH_SIZE sibling hash elements. -/
structure MerkleProof where
  v : Array (Array UInt64) := #[]
  mp : Array (Array UInt64) := #[]
  deriving Repr, BEq, Inhabited

/-- Merkle tree commitment with query proofs.

    Translates: proof.py:28-32 ProofTree

    - `root`: Merkle root hash (HASH_SIZE elements).
    - `lastLevels`: Pre-verified Merkle nodes for last_level_verification optimization.
    - `polQueries`: Query proofs indexed as polQueries[query_idx][tree_idx]. -/
structure ProofTree where
  root : Hash := #[]
  lastLevels : Array (Array UInt64) := #[]
  polQueries : Array (Array MerkleProof) := #[]
  deriving Repr, BEq, Inhabited

/-- FRI opening proof: folding trees and final polynomial.

    Translates: proof.py:36-40 FriProof

    - `trees`: Main commitment tree with per-query Merkle proofs.
    - `treesFri`: One ProofTree per FRI folding step (excluding the last).
    - `pol`: Final polynomial coefficients, each as [c0, c1, c2]. -/
structure FriProof where
  trees : ProofTree := {}
  treesFri : Array ProofTree := #[]
  pol : Array FF3Val := #[]
  deriving Repr, BEq, Inhabited

/-- Complete STARK proof for a single AIR.

    Translates: proof.py:44-72 STARKProof

    Contains all components needed to verify that a prover knows a valid
    execution trace satisfying the AIR constraints.

    - `roots`: Merkle roots for each stage commitment (stages 1 to n_stages+1).
               roots[0] is stage 1 (witness), roots[-1] is quotient polynomial.
    - `lastLevels`: Pre-verified Merkle nodes for last_level_verification.
                    Indexed by tree: [stage_0, ..., stage_n, const_tree].
    - `evals`: Polynomial evaluations at challenge point xi. Each entry is
               [c0, c1, c2] coefficients of an FF3 extension field element.
    - `airgroupValues`: Values shared across all AIRs in an airgroup.
    - `airValues`: Values specific to this individual AIR instance.
    - `customCommits`: Names of custom commitment schemes used (if any).
    - `fri`: FRI protocol data.
    - `nonce`: Proof-of-work nonce satisfying the grinding constraint. -/
structure STARKProof where
  roots : Array Hash := #[]
  lastLevels : Array (Array (Array UInt64)) := #[]
  evals : Array FF3Val := #[]
  airgroupValues : Array FF3Val := #[]
  airValues : Array FF3Val := #[]
  customCommits : Array String := #[]
  fri : FriProof := {}
  nonce : UInt64 := 0
  deriving Repr, BEq, Inhabited

-- ============================================================================
-- Binary Parsing Helpers
-- ============================================================================

/-- Read a UInt64 from ByteArray at byte offset (little-endian).

    Reads 8 bytes starting at `offset` and assembles them into a UInt64
    in little-endian order: byte[0] is LSB, byte[7] is MSB. -/
def readUInt64LE (data : ByteArray) (offset : Nat) : UInt64 :=
  let b0 := data.get! offset       |>.toUInt64
  let b1 := data.get! (offset + 1) |>.toUInt64
  let b2 := data.get! (offset + 2) |>.toUInt64
  let b3 := data.get! (offset + 3) |>.toUInt64
  let b4 := data.get! (offset + 4) |>.toUInt64
  let b5 := data.get! (offset + 5) |>.toUInt64
  let b6 := data.get! (offset + 6) |>.toUInt64
  let b7 := data.get! (offset + 7) |>.toUInt64
  b0 ||| (b1 <<< 8) ||| (b2 <<< 16) ||| (b3 <<< 24) |||
  (b4 <<< 32) ||| (b5 <<< 40) ||| (b6 <<< 48) ||| (b7 <<< 56)

/-- Read n consecutive UInt64s starting at byte offset (little-endian).

    Each UInt64 occupies 8 bytes, so reads bytes [offset, offset + 8*count). -/
def readUInt64Array (data : ByteArray) (offset : Nat) (count : Nat) : Array UInt64 :=
  Id.run do
    let mut result : Array UInt64 := Array.mkEmpty count
    for i in [:count] do
      result := result.push (readUInt64LE data (offset + i * 8))
    result

/-- Decode all UInt64 values from a ByteArray.

    Interprets the entire ByteArray as a flat array of little-endian UInt64s.
    This mirrors Python's struct.unpack('<{n}Q', data) pattern. -/
def decodeAllUInt64 (data : ByteArray) : Array UInt64 :=
  let nVals := data.size / 8
  readUInt64Array data 0 nVals

-- ============================================================================
-- Binary Proof Deserialization
-- ============================================================================

/-- Compute ceiling(a / b) for positive b. -/
private def ceilDiv (a b : Nat) : Nat :=
  (a + b - 1) / b

/-- Compute floor(log2(n)) for n >= 1. -/
private def log2Nat (n : Nat) : Nat :=
  if n <= 1 then 0
  else 1 + log2Nat (n / 2)

/-- Parse a binary proof file into a STARKProof structure.

    Translates: proof.py:180-373 from_bytes_full()

    The binary format is a flat array of little-endian uint64 values produced by
    the C++ proof2pointer() function. This parser deserializes it into the
    structured STARKProof dataclass.

    The `starkInfo` parameter provides all configuration needed to interpret
    the binary layout: number of stages, query count, Merkle tree parameters,
    FRI fold steps, and section widths. -/
def STARKProof.fromBytes (data : ByteArray) (starkInfo : StarkInfo) : STARKProof :=
  let values := decodeAllUInt64 data
  let nVals := values.size

  -- Configuration from StarkInfo
  let nQueries := starkInfo.starkStruct.nQueries
  let nStages := starkInfo.nStages
  let nConstants := starkInfo.constPolsMap.size
  let merkleArity := starkInfo.starkStruct.merkleTreeArity
  let lastLevelVerification := starkInfo.starkStruct.lastLevelVerification
  let nBitsExt := starkInfo.starkStruct.nBitsExt
  let logArity := log2Nat merkleArity
  let nSiblings := if logArity > 0 then
    ceilDiv nBitsExt logArity - lastLevelVerification
  else 0
  let nSiblingsPerLevel := (merkleArity - 1) * HASH_SIZE

  -- Helper to read a slice from values array
  let readSlice (start count : Nat) : Array UInt64 :=
    Id.run do
      let mut result : Array UInt64 := Array.mkEmpty count
      for i in [:count] do
        if start + i < nVals then
          result := result.push values[start + i]!
        else
          result := result.push 0
      result

  -- Use StateM-like index threading via Id.run with mutable state
  Id.run do
    let mut idx : Nat := 0
    let mut proof : STARKProof := {}

    -- Section 1: airgroupValues (proof.py:203-206)
    let nAirgroupValues := starkInfo.airgroupValuesMap.size
    let mut airgroupValues : Array FF3Val := Array.mkEmpty nAirgroupValues
    for _ in [:nAirgroupValues] do
      airgroupValues := airgroupValues.push (readSlice idx FIELD_EXTENSION_DEGREE)
      idx := idx + FIELD_EXTENSION_DEGREE
    proof := { proof with airgroupValues }

    -- Section 2: airValues (proof.py:209-211)
    let nAirValues := starkInfo.airValuesMap.size
    let mut airValues : Array FF3Val := Array.mkEmpty nAirValues
    for _ in [:nAirValues] do
      airValues := airValues.push (readSlice idx FIELD_EXTENSION_DEGREE)
      idx := idx + FIELD_EXTENSION_DEGREE
    proof := { proof with airValues }

    -- Section 3: roots (proof.py:214-216)
    let mut roots : Array Hash := Array.mkEmpty (nStages + 1)
    for _ in [:(nStages + 1)] do
      roots := roots.push (readSlice idx HASH_SIZE)
      idx := idx + HASH_SIZE
    proof := { proof with roots }

    -- Section 4: evals (proof.py:219-222)
    let nEvals := starkInfo.evMap.size
    let mut evals : Array FF3Val := Array.mkEmpty nEvals
    for _ in [:nEvals] do
      evals := evals.push (readSlice idx FIELD_EXTENSION_DEGREE)
      idx := idx + FIELD_EXTENSION_DEGREE
    proof := { proof with evals }

    -- Initialize FRI trees structure (proof.py:227-229)
    let nCustom := starkInfo.customCommits.size
    let nTrees := nStages + 2 + nCustom
    let emptyMerkleProof : MerkleProof := {}
    let mut polQueries : Array (Array MerkleProof) := Array.mkEmpty nQueries
    for _ in [:nQueries] do
      polQueries := polQueries.push (Array.replicate nTrees emptyMerkleProof)

    -- Pre-allocate lastLevels (proof.py:232-233)
    let mut lastLevels : Array (Array (Array UInt64)) :=
      Array.replicate nTrees #[]
    let constTreeIdx := nStages + 1

    -- Sections 5-7: const tree query proofs (proof.py:236-259)
    if nConstants > 0 then
      -- Values (proof.py:238-241)
      for q in [:nQueries] do
        let mut vEntries : Array (Array UInt64) := Array.mkEmpty nConstants
        for i in [:nConstants] do
          vEntries := vEntries.push #[values[idx + i]!]
        idx := idx + nConstants
        let mp := polQueries[q]![constTreeIdx]!
        let updatedMp : MerkleProof := { mp with v := vEntries }
        let row := polQueries[q]!.set! constTreeIdx updatedMp
        polQueries := polQueries.set! q row

      -- Merkle paths (proof.py:245-249)
      for q in [:nQueries] do
        let mut mpEntries : Array (Array UInt64) :=
          polQueries[q]![constTreeIdx]!.mp
        for _ in [:nSiblings] do
          mpEntries := mpEntries.push (readSlice idx nSiblingsPerLevel)
          idx := idx + nSiblingsPerLevel
        let currentMp := polQueries[q]![constTreeIdx]!
        let updatedMp : MerkleProof := { currentMp with mp := mpEntries }
        let row := polQueries[q]!.set! constTreeIdx updatedMp
        polQueries := polQueries.set! q row

      -- Last levels (proof.py:253-259)
      if lastLevelVerification != 0 then
        let numNodes := merkleArity ^ lastLevelVerification
        let mut constLastLevels : Array (Array UInt64) := Array.mkEmpty numNodes
        for _ in [:numNodes] do
          constLastLevels := constLastLevels.push (readSlice idx HASH_SIZE)
          idx := idx + HASH_SIZE
        lastLevels := lastLevels.set! constTreeIdx constLastLevels

    -- Section 8: custom commits (proof.py:262-288)
    for c in [:nCustom] do
      let customCommitName := starkInfo.customCommits[c]!.name
      let nCustomCols := lookupSection starkInfo.mapSectionsN (customCommitName ++ "0")
      let treeIdx := nStages + 2 + c

      -- Values (proof.py:267-270)
      for q in [:nQueries] do
        let mut vEntries : Array (Array UInt64) := Array.mkEmpty nCustomCols
        for i in [:nCustomCols] do
          vEntries := vEntries.push #[values[idx + i]!]
        idx := idx + nCustomCols
        let mp := polQueries[q]![treeIdx]!
        let updatedMp : MerkleProof := { mp with v := vEntries }
        let row := polQueries[q]!.set! treeIdx updatedMp
        polQueries := polQueries.set! q row

      -- Merkle paths (proof.py:274-279)
      for q in [:nQueries] do
        let mut mpEntries : Array (Array UInt64) :=
          polQueries[q]![treeIdx]!.mp
        for _ in [:nSiblings] do
          mpEntries := mpEntries.push (readSlice idx nSiblingsPerLevel)
          idx := idx + nSiblingsPerLevel
        let currentMp := polQueries[q]![treeIdx]!
        let updatedMp : MerkleProof := { currentMp with mp := mpEntries }
        let row := polQueries[q]!.set! treeIdx updatedMp
        polQueries := polQueries.set! q row

      -- Last levels (proof.py:282-288)
      if lastLevelVerification != 0 then
        let numNodes := merkleArity ^ lastLevelVerification
        let mut customLastLevels : Array (Array UInt64) := Array.mkEmpty numNodes
        for _ in [:numNodes] do
          customLastLevels := customLastLevels.push (readSlice idx HASH_SIZE)
          idx := idx + HASH_SIZE
        lastLevels := lastLevels.set! treeIdx customLastLevels

    -- Section 9: stage tree proofs cm1..cmQ (proof.py:292-318)
    for stageNum in [1:(nStages + 2)] do
      let treeIdx := stageNum - 1
      let nStageCols := lookupSection starkInfo.mapSectionsN s!"cm{stageNum}"

      -- Values (proof.py:297-300)
      for q in [:nQueries] do
        let mut vEntries : Array (Array UInt64) := Array.mkEmpty nStageCols
        for i in [:nStageCols] do
          vEntries := vEntries.push #[values[idx + i]!]
        idx := idx + nStageCols
        let mp := polQueries[q]![treeIdx]!
        let updatedMp : MerkleProof := { mp with v := vEntries }
        let row := polQueries[q]!.set! treeIdx updatedMp
        polQueries := polQueries.set! q row

      -- Merkle paths (proof.py:303-309)
      for q in [:nQueries] do
        let mut mpEntries : Array (Array UInt64) :=
          polQueries[q]![treeIdx]!.mp
        for _ in [:nSiblings] do
          mpEntries := mpEntries.push (readSlice idx nSiblingsPerLevel)
          idx := idx + nSiblingsPerLevel
        let currentMp := polQueries[q]![treeIdx]!
        let updatedMp : MerkleProof := { currentMp with mp := mpEntries }
        let row := polQueries[q]!.set! treeIdx updatedMp
        polQueries := polQueries.set! q row

      -- Last levels (proof.py:312-318)
      if lastLevelVerification != 0 then
        let numNodes := merkleArity ^ lastLevelVerification
        let mut stageLastLevels : Array (Array UInt64) := Array.mkEmpty numNodes
        for _ in [:numNodes] do
          stageLastLevels := stageLastLevels.push (readSlice idx HASH_SIZE)
          idx := idx + HASH_SIZE
        lastLevels := lastLevels.set! treeIdx stageLastLevels

    -- Assemble main FRI trees with polQueries
    let friTrees : ProofTree := { polQueries }

    -- Section 10: FRI step roots (proof.py:321-327)
    let nFriRoundLogSizes := starkInfo.starkStruct.friFoldSteps.size - 1
    let mut treesFri : Array ProofTree := Array.mkEmpty nFriRoundLogSizes
    for _ in [:nFriRoundLogSizes] do
      let friRoot := readSlice idx HASH_SIZE
      idx := idx + HASH_SIZE
      let mut friPolQueries : Array (Array MerkleProof) := Array.mkEmpty nQueries
      for _ in [:nQueries] do
        friPolQueries := friPolQueries.push #[emptyMerkleProof]
      treesFri := treesFri.push { root := friRoot, polQueries := friPolQueries }

    -- Section 11: FRI step query proofs (proof.py:330-358)
    for stepIdx in [:nFriRoundLogSizes] do
      let prevBits := starkInfo.starkStruct.friFoldSteps[stepIdx]!.domainBits
      let currBits := starkInfo.starkStruct.friFoldSteps[stepIdx + 1]!.domainBits
      let nFriCols := (1 <<< (prevBits - currBits)) * FIELD_EXTENSION_DEGREE

      -- Values (proof.py:336-339)
      for q in [:nQueries] do
        let mut vEntries : Array (Array UInt64) := Array.mkEmpty nFriCols
        for i in [:nFriCols] do
          vEntries := vEntries.push #[values[idx + i]!]
        idx := idx + nFriCols
        let currentTree := treesFri[stepIdx]!
        let currentMp := currentTree.polQueries[q]![0]!
        let updatedMp : MerkleProof := { currentMp with v := vEntries }
        let updatedRow := currentTree.polQueries[q]!.set! 0 updatedMp
        let updatedPQ := currentTree.polQueries.set! q updatedRow
        treesFri := treesFri.set! stepIdx { currentTree with polQueries := updatedPQ }

      -- Merkle paths (proof.py:343-349)
      let nSiblingsFri := if logArity > 0 then
        ceilDiv currBits logArity - lastLevelVerification
      else 0
      for q in [:nQueries] do
        let currentTree := treesFri[stepIdx]!
        let mut mpEntries : Array (Array UInt64) :=
          currentTree.polQueries[q]![0]!.mp
        for _ in [:nSiblingsFri] do
          mpEntries := mpEntries.push (readSlice idx nSiblingsPerLevel)
          idx := idx + nSiblingsPerLevel
        let currentMp := currentTree.polQueries[q]![0]!
        let updatedMp : MerkleProof := { currentMp with mp := mpEntries }
        let updatedRow := currentTree.polQueries[q]!.set! 0 updatedMp
        let updatedPQ := currentTree.polQueries.set! q updatedRow
        treesFri := treesFri.set! stepIdx { currentTree with polQueries := updatedPQ }

      -- Last levels (proof.py:352-358)
      if lastLevelVerification != 0 then
        let numNodes := merkleArity ^ lastLevelVerification
        let mut friLastLevels : Array (Array UInt64) := Array.mkEmpty numNodes
        for _ in [:numNodes] do
          friLastLevels := friLastLevels.push (readSlice idx HASH_SIZE)
          idx := idx + HASH_SIZE
        let currentTree := treesFri[stepIdx]!
        treesFri := treesFri.set! stepIdx { currentTree with lastLevels := friLastLevels }

    -- Section 12: finalPol (proof.py:361-364)
    let lastStep := starkInfo.starkStruct.friFoldSteps[starkInfo.starkStruct.friFoldSteps.size - 1]!
    let finalPolSize := 1 <<< lastStep.domainBits
    let mut finalPol : Array FF3Val := Array.mkEmpty finalPolSize
    for _ in [:finalPolSize] do
      finalPol := finalPol.push (readSlice idx FIELD_EXTENSION_DEGREE)
      idx := idx + FIELD_EXTENSION_DEGREE

    -- Section 13: nonce (proof.py:367-368)
    let nonce := if idx < nVals then values[idx]! else 0
    -- idx := idx + 1  -- (consumed; not needed after this)

    proof := { proof with
      lastLevels
      fri := { trees := friTrees, treesFri, pol := finalPol }
      nonce
    }

    proof

-- ============================================================================
-- VADCOP Final Proof Deserialization
-- ============================================================================

/-- Parse a VadcopFinal proof binary with embedded publics header.

    Translates: proof.py:161-177 from_vadcop_final_bytes()

    VadcopFinal proofs prepend [n_publics: u64] [publics: n_publics * u64]
    before the standard proof body. -/
def STARKProof.fromVadcopFinalBytes (data : ByteArray) (starkInfo : StarkInfo) :
    STARKProof × Array UInt64 :=
  let nPublics := (readUInt64LE data 0).toNat
  let headerSize := 8 + nPublics * 8
  let publics := readUInt64Array data 8 nPublics
  -- Extract the proof body after the header
  let proofData := data.extract headerSize data.size
  let proof := STARKProof.fromBytes proofData starkInfo
  (proof, publics)

-- ============================================================================
-- Proof Validation
-- ============================================================================

/-- Validate that proof structure matches STARK configuration.

    Translates: proof.py:746-783 validate_proof_structure()

    Returns a list of error messages. Empty list means the proof is valid. -/
def validateProofStructure (proof : STARKProof) (starkInfo : StarkInfo) : Array String :=
  Id.run do
    let mut errors : Array String := #[]

    -- Check stage root count
    let expectedStages := starkInfo.nStages + 1
    if proof.roots.size != expectedStages then
      errors := errors.push
        s!"Expected {expectedStages} stage roots, got {proof.roots.size}"

    -- Check evaluation count
    if proof.evals.size != starkInfo.evMap.size then
      errors := errors.push
        s!"Expected {starkInfo.evMap.size} evaluations, got {proof.evals.size}"

    -- Check evaluation dimensions
    for i in [:proof.evals.size] do
      if proof.evals[i]!.size != FIELD_EXTENSION_DEGREE then
        errors := errors.push
          s!"Evaluation {i} has dimension {proof.evals[i]!.size}, expected {FIELD_EXTENSION_DEGREE}"

    -- Check airgroup values count
    if proof.airgroupValues.size != starkInfo.airgroupValuesMap.size then
      errors := errors.push
        s!"Expected {starkInfo.airgroupValuesMap.size} airgroup values, got {proof.airgroupValues.size}"

    -- Check air values count
    if proof.airValues.size != starkInfo.airValuesMap.size then
      errors := errors.push
        s!"Expected {starkInfo.airValuesMap.size} air values, got {proof.airValues.size}"

    -- Check FRI trees count
    let expectedFriRoundLogSizes := starkInfo.starkStruct.friFoldSteps.size - 1
    if proof.fri.treesFri.size != expectedFriRoundLogSizes then
      errors := errors.push
        s!"Expected {expectedFriRoundLogSizes} FRI trees, got {proof.fri.treesFri.size}"

    -- Check final polynomial degree
    if proof.fri.pol.size > 0 then
      let lastStep := starkInfo.starkStruct.friFoldSteps[starkInfo.starkStruct.friFoldSteps.size - 1]!
      let expectedDegree := 1 <<< lastStep.domainBits
      if proof.fri.pol.size != expectedDegree then
        errors := errors.push
          s!"Final polynomial degree {proof.fri.pol.size}, expected {expectedDegree}"

    errors

end Protocol.Proof
