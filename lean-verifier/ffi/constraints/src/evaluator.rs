//! Verifier-mode bytecode expression evaluator.
//!
//! Evaluates constraint expressions at a single point (xi) for STARK verification.
//! In verify mode: domain_size=1, all polynomial values come from the evals buffer
//! (looked up via ev_map), not from polynomial evaluation domains.
//!
//! Translates: executable-spec/primitives/expression_bytecode/expression_evaluator.py
//! (ExpressionsPack.calculate_expressions, verify=True, domain_size=1)

use std::collections::HashMap;

use crate::expressions_bin::ExpressionsBin;
use crate::field::{self, FF3};
use crate::starkinfo::StarkInfo;

/// Scalar parameter buffer type offsets beyond committed polynomial slots.
/// Matches C++ expressions_bin.hpp layout.
const PUBLIC_INPUTS_OFFSET: usize = 2;
const NUMBERS_OFFSET: usize = 3;
const AIR_VALUES_OFFSET: usize = 4;
const PROOF_VALUES_OFFSET: usize = 5;
const AIRGROUP_VALUES_OFFSET: usize = 6;
const CHALLENGES_OFFSET: usize = 7;
const EVALS_OFFSET: usize = 8;

const FIELD_EXTENSION_DEGREE: usize = 3;

/// Evaluate constraint expression c_exp_id in verifier mode.
///
/// Returns Q(xi) as an FF3 element (the constraint quotient at the evaluation point).
///
/// Parameters:
/// - `si`: Parsed StarkInfo
/// - `expr_bin`: Parsed expression bytecode
/// - `evals`: Polynomial evaluations at xi (interleaved FF3)
/// - `challenges`: Fiat-Shamir challenges (interleaved FF3)
/// - `publics`: Public inputs (base field)
/// - `airgroup_values`: Airgroup accumulated values (interleaved FF3)
/// - `air_values`: AIR-specific values (mixed dim layout)
/// - `proof_values`: Proof-specific values (base field)
pub fn evaluate_constraint_verifier(
    si: &StarkInfo,
    expr_bin: &ExpressionsBin,
    evals: &[u64],
    challenges: &[u64],
    publics: &[u64],
    airgroup_values: &[u64],
    air_values: &[u64],
    proof_values: &[u64],
) -> FF3 {
    let c_exp_id = si.c_exp_id;
    let params = expr_bin
        .expressions_info
        .get(&c_exp_id)
        .unwrap_or_else(|| panic!("c_exp_id {c_exp_id} not found in expressions_info"));

    // Compute ProverHelpers values from xi challenge
    let xi_idx = si.xi_challenge_index().expect("std_xi challenge not found");
    let xi_base = xi_idx * FIELD_EXTENSION_DEGREE;
    let xi = FF3::from_interleaved(challenges, xi_base);

    let n = 1u64 << si.stark_struct.n_bits;
    let x_n = xi.pow(n); // xi^N

    // Compute zi = 1/(xi_k^N - 1) for each boundary/opening point
    let zi = compute_zi(si, &xi, n);

    // buffer_commits_size = 1 + n_stages + 3 + n_custom_commits
    let buffer_commits_size = 1 + si.n_stages + 3 + si.custom_commits.len();

    // Build scalar parameter lookup
    let scalar_params: HashMap<usize, &[u64]> = [
        (buffer_commits_size + PUBLIC_INPUTS_OFFSET, publics),
        (
            buffer_commits_size + NUMBERS_OFFSET,
            expr_bin.expressions_args.numbers.as_slice(),
        ),
        (buffer_commits_size + AIR_VALUES_OFFSET, air_values),
        (buffer_commits_size + PROOF_VALUES_OFFSET, proof_values),
        (buffer_commits_size + AIRGROUP_VALUES_OFFSET, airgroup_values),
        (buffer_commits_size + CHALLENGES_OFFSET, challenges),
        (buffer_commits_size + EVALS_OFFSET, evals),
    ]
    .into_iter()
    .collect();

    // Temp registers: both store FF3 because in verify mode all polynomial
    // evaluations are in the extension field, even for "base field" ops.
    let mut tmp1: HashMap<u16, FF3> = HashMap::new();
    let mut tmp3: HashMap<u16, FF3> = HashMap::new();

    let ops = &expr_bin.expressions_args.ops;
    let args = &expr_bin.expressions_args.args;

    let ops_start = params.ops_offset as usize;
    let args_start = params.args_offset as usize;
    let mut i_args = args_start;

    let mut result = FF3::ZERO;

    for op_idx in 0..params.n_ops as usize {
        let op_type = ops[ops_start + op_idx];
        let is_last = op_idx == (params.n_ops as usize - 1);
        let arith_op = args[i_args];
        let dest_slot = args[i_args + 1];

        let dim_a = if op_type >= 1 { FIELD_EXTENSION_DEGREE } else { 1 };
        let dim_b = if op_type == 2 { FIELD_EXTENSION_DEGREE } else { 1 };

        let a = load_operand(
            si,
            &scalar_params,
            &tmp1,
            &tmp3,
            args,
            evals,
            buffer_commits_size,
            i_args + 2,
            dim_a,
            &x_n,
            &zi,
        );

        let b = load_operand(
            si,
            &scalar_params,
            &tmp1,
            &tmp3,
            args,
            evals,
            buffer_commits_size,
            i_args + 5,
            dim_b,
            &x_n,
            &zi,
        );

        let res = apply_op(arith_op, a, b);

        if is_last {
            result = res;
        } else if op_type == 0 {
            tmp1.insert(dest_slot, res);
        } else {
            tmp3.insert(dest_slot, res);
        }

        i_args += 8;
    }

    result
}

/// Compute zi = 1/(xi_k^N - 1) for each boundary.
/// boundary 0 = x_n (not a zi), boundaries 1+ = inverse vanishing polynomials.
fn compute_zi(si: &StarkInfo, xi: &FF3, n: u64) -> Vec<FF3> {
    let mut zi_values = Vec::new();
    let n_openings = si.opening_points.len();

    for i in 0..n_openings {
        let opening = si.opening_points[i];
        // xi_k = xi * omega^opening where omega = root of unity
        // For verifier mode at a single point, the opening point offset
        // is handled by using different ev_map entries.
        // zi[i] = 1 / (xi_k^N - 1)
        // When opening == 0: xi_k = xi, so zi = 1/(xi^N - 1)
        // When opening != 0: xi_k = xi * W[n_bits]^opening
        let omega_n_bits = crate::field::pow(
            get_root_of_unity(si.stark_struct.n_bits as usize),
            opening.unsigned_abs() as u64,
        );
        let xi_k = if opening == 0 {
            *xi
        } else if opening > 0 {
            xi.mul(FF3::from_base(omega_n_bits))
        } else {
            // negative opening: use inverse root
            let omega_inv = crate::field::inv(omega_n_bits);
            xi.mul(FF3::from_base(omega_inv))
        };

        let xi_k_n = xi_k.pow(n);
        // Z_H(xi_k) = xi_k^N - 1
        let zh = FF3::new(
            field::sub(xi_k_n.c0, 1),
            xi_k_n.c1,
            xi_k_n.c2,
        );
        zi_values.push(zh.inv());
    }

    zi_values
}

/// Load an operand from the bytecode-specified source in verify mode.
fn load_operand(
    si: &StarkInfo,
    scalar_params: &HashMap<usize, &[u64]>,
    tmp1: &HashMap<u16, FF3>,
    tmp3: &HashMap<u16, FF3>,
    args: &[u16],
    evals: &[u64],
    buffer_commits_size: usize,
    i_args: usize,
    dim: usize,
    x_n: &FF3,
    zi: &[FF3],
) -> FF3 {
    let type_arg = args[i_args] as usize;
    let id = args[i_args + 1] as usize;
    let opening_idx = args[i_args + 2] as usize;

    // Type 0: Constant polynomials
    if type_arg == 0 {
        let stage_pos = id;
        return load_const_from_evals(si, evals, stage_pos, opening_idx);
    }

    // Types 1..n_stages+1: Committed polynomials
    if type_arg <= si.n_stages + 1 {
        let stage = type_arg;
        let stage_pos = id;
        return load_cm_from_evals(si, evals, stage, stage_pos, opening_idx);
    }

    // Type n_stages+2: Boundary values (x_n, zi)
    if type_arg == si.n_stages + 2 {
        let boundary = id;
        if boundary == 0 {
            return *x_n;
        }
        return zi[boundary - 1];
    }

    // Type n_stages+3: x/(x-xi) — not used for c_exp_id evaluation
    if type_arg == si.n_stages + 3 {
        panic!("xDivXSubXi operand not supported in constraint evaluation");
    }

    // Custom commits
    if type_arg >= si.n_stages + 4
        && type_arg < si.custom_commits.len() + si.n_stages + 4
    {
        let commit_index = type_arg - (si.n_stages + 4);
        let stage_pos = id;
        return load_custom_from_evals(si, evals, commit_index, stage_pos, opening_idx);
    }

    // Temp registers (base field — but in verify mode stores full FF3)
    if type_arg == buffer_commits_size {
        return tmp1.get(&(id as u16)).copied().unwrap_or(FF3::ZERO);
    }

    // Temp registers (extension field)
    if type_arg == buffer_commits_size + 1 {
        return tmp3.get(&(id as u16)).copied().unwrap_or(FF3::ZERO);
    }

    // Scalar values (publics, numbers, challenges, evals, etc.)
    if let Some(arr) = scalar_params.get(&type_arg) {
        if dim == 1 {
            return FF3::from_base(arr[id]);
        }
        return FF3::from_interleaved(arr, id);
    }

    panic!("Unknown operand type: {type_arg}");
}

/// Look up a constant polynomial evaluation from the evals buffer via ev_map.
fn load_const_from_evals(
    si: &StarkInfo,
    evals: &[u64],
    stage_pos: usize,
    opening_idx: usize,
) -> FF3 {
    // Find pol_id in const_pols_map
    let pol_id = si
        .const_pols_map
        .iter()
        .position(|p| p.stage_pos == stage_pos)
        .unwrap_or_else(|| panic!("const pol with stage_pos={stage_pos} not found"));

    // Find ev_map entry
    for (idx, e) in si.ev_map.iter().enumerate() {
        if e.type_ == "const" && e.id == pol_id && e.opening_pos == opening_idx {
            let base = idx * FIELD_EXTENSION_DEGREE;
            return FF3::from_interleaved(evals, base);
        }
    }

    panic!("ev_map entry not found for const pol_id={pol_id}, opening_idx={opening_idx}");
}

/// Look up a committed polynomial evaluation from the evals buffer via ev_map.
fn load_cm_from_evals(
    si: &StarkInfo,
    evals: &[u64],
    stage: usize,
    stage_pos: usize,
    opening_idx: usize,
) -> FF3 {
    // Find pol_id in cm_pols_map
    let pol_id = si
        .cm_pols_map
        .iter()
        .position(|p| p.stage == stage && p.stage_pos == stage_pos)
        .unwrap_or_else(|| {
            panic!("cm pol with stage={stage}, stage_pos={stage_pos} not found")
        });

    // Find ev_map entry
    for (idx, e) in si.ev_map.iter().enumerate() {
        if e.type_ == "cm" && e.id == pol_id && e.opening_pos == opening_idx {
            let base = idx * FIELD_EXTENSION_DEGREE;
            return FF3::from_interleaved(evals, base);
        }
    }

    panic!(
        "ev_map entry not found for cm pol_id={pol_id}, stage={stage}, opening_idx={opening_idx}"
    );
}

/// Look up a custom commit polynomial evaluation from the evals buffer via ev_map.
fn load_custom_from_evals(
    si: &StarkInfo,
    evals: &[u64],
    commit_index: usize,
    stage_pos: usize,
    opening_idx: usize,
) -> FF3 {
    for (idx, e) in si.ev_map.iter().enumerate() {
        if e.type_ == "custom"
            && e.id == stage_pos
            && e.opening_pos == opening_idx
            && e.commit_id == commit_index
        {
            let base = idx * FIELD_EXTENSION_DEGREE;
            return FF3::from_interleaved(evals, base);
        }
    }

    panic!(
        "ev_map entry not found for custom commit_index={commit_index}, stage_pos={stage_pos}"
    );
}

/// Apply arithmetic operation, promoting to FF3 if needed.
fn apply_op(op: u16, a: FF3, b: FF3) -> FF3 {
    match op {
        0 => a.add(b),       // ADD
        1 => a.sub(b),       // SUB
        2 => a.mul(b),       // MUL
        3 => b.sub(a),       // SUB_SWAP (b - a)
        _ => panic!("Unknown arithmetic op: {op}"),
    }
}

/// Get root of unity for domain of size 2^n_bits.
/// These are precomputed constants for Goldilocks field.
fn get_root_of_unity(n_bits: usize) -> u64 {
    const W: [u64; 33] = [
        1,
        18446744069414584320,
        281474976710656,
        18446744069397807105,
        17293822564807737345,
        70368744161280,
        549755813888,
        17870292113338400769,
        13797081185216407910,
        1803076106186727246,
        11353340290879379826,
        455906449640507599,
        17492915097719143606,
        1532612707718625687,
        16207902636198568418,
        17776499369601055404,
        6115771955107415310,
        12380578893860276750,
        9306717745644682924,
        18146160046829613826,
        3511170319078647661,
        17654865857378133588,
        5416168637041100469,
        16905767614792059275,
        9713644485405565297,
        5456943929260765144,
        17096174751763063430,
        1213594585890690845,
        6414415596519834757,
        16116352524544190054,
        9123114210336311365,
        4614640910117430873,
        1753635133440165772,
    ];
    W[n_bits]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expressions_bin::ExpressionsBin;
    use crate::starkinfo::StarkInfo;

    /// Exact test data from the Python verifier for SimpleLeft AIR.
    /// Expected Q(xi) = (3948594841981948916, 8867015489366039774, 978296951733334400)
    #[test]
    fn test_simple_left_constraint_evaluation() {
        let si = StarkInfo::from_file(
            "../../Tests/test-data/SimpleLeft.starkinfo.json",
        )
        .expect("Failed to parse starkinfo");
        let expr_bin = ExpressionsBin::from_file(
            "../../Tests/test-data/SimpleLeft.bin",
        )
        .expect("Failed to parse bytecode");

        // Exact evals from the C++ proof (interleaved FF3, 27 entries * 3 = 81 u64s)
        let evals: Vec<u64> = vec![
            14708208684446493519, 7777295877489359129, 3805323469446950077,
            9120011796906819093, 11176592848267157982, 2606014684954863824,
            7337513290634636195, 11097189300741246713, 12892826002917690935,
            80783743792319443, 9071654429904489725, 300184196795686460,
            12744832530220540864, 9380238868408918801, 5103274407608056257,
            6258191980441401552, 16299002527499730905, 14626770517956037126,
            200, 0, 0,
            201, 0, 0,
            13375619070016833480, 17592197624135685468, 8440730762296779916,
            5071124999397750848, 854546445278898853, 10006013307117804405,
            11409034621748181151, 12801104549170393246, 12854130149218907930,
            11816623083914531143, 2396405431504649876, 56053266593470523,
            11411580605552669334, 4813240290623048305, 232512289555469647,
            4268062021319421381, 13553334062896376693, 2271587692175749366,
            4810032115632732396, 11919487871655766575, 4926646491724172689,
            5942215447561497005, 16924983868669363044, 17848081412985240347,
            6957883310393121647, 16325044006374900864, 6544614857567896382,
            1429924755930094658, 12552588256897740715, 7177940153246497500,
            7284425632202162409, 10904789932080254997, 12785526431943481504,
            15867528244010326930, 6588194849693846326, 7188420105206062233,
            878073969256766758, 17937631742912203975, 1749246406111473365,
            3539805661801071, 4684259238933945818, 10244391023015150537,
            2563955911702349557, 7459182649423010499, 6150872496626811417,
            2411542765009835542, 2919645062594955543, 11279483224938829701,
            952379721407096185, 4690671178390076070, 9923890898232343511,
            7774897444090513433, 8932873962225809553, 364439629361540523,
            11861575133931201726, 10536181743092914519, 2996249451604970096,
        ];

        // Exact challenges (6 challenges * 3 = 18 u64s)
        let challenges: Vec<u64> = vec![
            10522569855850028606, 17509714464342549106, 9920312028938830972,  // std_alpha
            4441364294883569372, 3051863983745118048, 10173956607218352363,   // std_gamma
            16334203687750224618, 4294612768427165451, 3149686312137359433,   // std_vc
            14944002217527217563, 9739806307393641731, 7591735412576678922,   // std_xi
            17811847442631983652, 519937810141364897, 9761448015474649324,    // std_vf1
            2575228976132428782, 16172687718039523914, 3939334835537612240,   // std_vf2
        ];

        let publics: Vec<u64> = vec![];
        let airgroup_values: Vec<u64> = vec![
            13594840203748605127, 14550057880619064475, 17418608154175219049,
        ];
        let air_values: Vec<u64> = vec![];
        let proof_values: Vec<u64> = vec![];

        println!("c_exp_id: {}", si.c_exp_id);
        println!("n_stages: {}", si.n_stages);
        println!("n_bits: {}", si.stark_struct.n_bits);
        println!("ev_map count: {}", si.ev_map.len());
        println!("xi_challenge_index: {}", si.xi_challenge_index().unwrap());

        let result = evaluate_constraint_verifier(
            &si, &expr_bin, &evals, &challenges,
            &publics, &airgroup_values, &air_values, &proof_values,
        );

        println!("Result: ({}, {}, {})", result.c0, result.c1, result.c2);

        // Expected Q(xi) from Python verifier
        let expected = FF3::new(
            3948594841981948916,
            8867015489366039774,
            978296951733334400,
        );
        assert_eq!(result, expected,
            "C(xi) mismatch: got ({}, {}, {}), expected ({}, {}, {})",
            result.c0, result.c1, result.c2,
            expected.c0, expected.c1, expected.c2);
    }
}
