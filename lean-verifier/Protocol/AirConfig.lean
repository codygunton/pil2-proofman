/-
  AIR configuration bundle for STARK verification.

  Translates: executable-spec/protocol/air_config.py:259-309 (AirConfig)

  AirConfig packages the read-only configuration needed to verify a STARK proof
  for a specific AIR (Algebraic Intermediate Representation):

  - starkinfo_path: Path to starkinfo.json (AIR specification)
  - global_info_path: Optional path to pilout.globalInfo.json (VADCOP mode)
  - airgroup_id / air_id: Indices identifying this AIR within a multi-AIR setup

  Note: StarkInfo is loaded separately by the verifier. This structure stores
  paths and identifiers rather than parsed StarkInfo to avoid compile-time
  coupling with the StarkInfo module (built in parallel).
-/
namespace Protocol.AirConfig

-- ============================================================================
-- AirConfig
-- ============================================================================

/-- Configuration bundle for STARK verification.

    Translates: air_config.py:259-309 AirConfig

    Packages all read-only configuration needed to verify a STARK proof.
    The verifier uses this to locate starkinfo.json and identify the AIR
    within a multi-AIR VADCOP setup.

    Attributes:
    - `starkinfo_path`: Path to starkinfo.json (AIR specification)
    - `global_info_path`: Optional path to pilout.globalInfo.json (VADCOP)
    - `airgroup_id`: Airgroup index in multi-AIR setups (default 0)
    - `air_id`: AIR index within the airgroup (default 0) -/
structure AirConfig where
  starkinfo_path : System.FilePath
  global_info_path : Option System.FilePath := none
  airgroup_id : Nat := 0
  air_id : Nat := 0
  deriving Repr, Inhabited

instance : ToString AirConfig where
  toString c :=
    let gip := match c.global_info_path with
      | some p => s!", global_info={p}"
      | none => ""
    s!"AirConfig(starkinfo={c.starkinfo_path}{gip}, " ++
    s!"airgroup={c.airgroup_id}, air={c.air_id})"

-- ============================================================================
-- Factory Methods
-- ============================================================================

/-- Create AirConfig from a starkinfo.json path.

    Translates: air_config.py:284-304 AirConfig.from_starkinfo()

    This is the primary entry point for creating an AirConfig. The verifier
    will load and parse starkinfo.json separately using Protocol.StarkInfo.

    Args:
      path: Path to starkinfo.json
      global_info_path: Optional path to pilout.globalInfo.json (for VADCOP)
      airgroup_id: Airgroup index (default 0)
      air_id: AIR index within the airgroup (default 0) -/
def AirConfig.from_starkinfo
    (path : System.FilePath)
    (global_info_path : Option System.FilePath := none)
    (airgroup_id : Nat := 0)
    (air_id : Nat := 0) : AirConfig :=
  { starkinfo_path := path
    global_info_path
    airgroup_id
    air_id }

end Protocol.AirConfig
