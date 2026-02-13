//! Minimal StarkInfo JSON parser for constraint evaluation.
//!
//! Only parses the fields needed by the verifier-mode bytecode evaluator:
//! n_stages, c_exp_id, ev_map, cm_pols_map, const_pols_map, opening_points,
//! n_bits, custom_commits, challenges_map.
//!
//! Translates: executable-spec/protocol/stark_info.py (subset)

use serde::Deserialize;

/// Top-level StarkInfo structure (only fields we need).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StarkInfo {
    pub n_stages: usize,
    pub c_exp_id: u32,
    pub ev_map: Vec<EvMapEntry>,
    pub cm_pols_map: Vec<PolsMapEntry>,
    pub const_pols_map: Vec<PolsMapEntry>,
    pub opening_points: Vec<i32>,
    pub stark_struct: StarkStruct,
    #[serde(default)]
    pub custom_commits: Vec<CustomCommit>,
    #[serde(default)]
    pub challenges_map: Vec<ChallengeMapEntry>,
    #[serde(default)]
    pub air_values_map: Vec<AirValueMapEntry>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StarkStruct {
    pub n_bits: u32,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EvMapEntry {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: usize,
    /// Row offset (called "prime" in JSON)
    #[serde(default)]
    pub prime: i32,
    #[serde(default)]
    pub opening_pos: usize,
    /// Custom commit index (only for type="custom")
    #[serde(default)]
    pub commit_id: usize,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PolsMapEntry {
    pub stage: usize,
    pub name: String,
    #[serde(default = "default_dim")]
    pub dim: usize,
    #[serde(default)]
    pub stage_pos: usize,
    #[serde(default)]
    pub stage_id: usize,
}

fn default_dim() -> usize {
    1
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CustomCommit {
    pub name: String,
    #[serde(default)]
    pub stage: usize,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeMapEntry {
    pub name: String,
    pub stage: usize,
    #[serde(default = "default_dim")]
    pub dim: usize,
    #[serde(default)]
    pub stage_id: usize,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AirValueMapEntry {
    pub name: String,
    #[serde(default = "default_dim")]
    pub dim: usize,
    #[serde(default)]
    pub stage: usize,
    #[serde(default)]
    pub air_id: usize,
}

impl StarkInfo {
    /// Load from a starkinfo.json file.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {path}: {e}"))?;
        let mut si: Self =
            serde_json::from_str(&data).map_err(|e| format!("JSON parse error: {e}"))?;

        // For const pols, JSON has no `stagePos` field — Python uses `stageId` instead
        // (see stark_info.py line 269: stage_pos=const_data["stageId"]).
        for p in &mut si.const_pols_map {
            p.stage_pos = p.stage_id;
        }

        Ok(si)
    }

    /// Find the challenge index for "std_xi".
    pub fn xi_challenge_index(&self) -> Option<usize> {
        self.challenges_map
            .iter()
            .position(|c| c.name == "std_xi")
    }
}
