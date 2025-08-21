use crate::{nexus_orchestrator::TaskType, verifier};
use anyhow::{Result, anyhow};
use base64::engine::Engine; // 引入Engine trait
use base64::engine::general_purpose::STANDARD as BASE64;
use hex;
use nexus_sdk::{
    KnownExitCodes, Local, Prover, Viewable,
    stwo::seq::{Proof, Stwo},
};
use prost_types::NullValue;
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::convert::TryInto;
// 添加这个以支持 bincode 的反序列化

#[derive(Serialize, Deserialize)]
pub struct ProverResult {
    pub proof: Option<Proof>,
    pub combined_hash: String,
    pub proof_hashes: Vec<String>,
}

#[derive(Debug)]
pub struct Task {
    pub task_id: String,
    pub program_id: String,
    pub public_inputs: Vec<u8>,

    /// Multiple public inputs for the task (new field)
    pub public_inputs_list: Vec<Vec<u8>>,
    /// The type of task (proof required or only hash)
    pub task_type: crate::nexus_orchestrator::TaskType,
}
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProverError {
    #[error("Stwo prover error: {0}")]
    Stwo(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("Malformed task: {0}")]
    MalformedTask(String),

    #[error("Guest Program error: {0}")]
    GuestProgram(String),
}

// 在模块顶部
static FIB_INPUT: &[u8] = include_bytes!("../assets/fib_input");
static FIB_INPUT_INITIAL: &[u8] = include_bytes!("../assets/fib_input_initial");

// impl From<i32> for TaskType {
//     fn from(value: i32) -> Self {
//         match value {
//             0 => TaskType::ProofRequired,
//             1 => TaskType::ProofHash,
//             2 => TaskType::AllProofHashes,
//             _ => TaskType::ProofHash,
//         }
//     }
// }

impl From<super::TaskRequest> for Task {
    fn from(req: super::TaskRequest) -> Self {
        // 1. 解码 public_inputs_list（按逗号分割后逐个解码）
        let public_inputs_list: Vec<Vec<u8>> = req
            .public_inputs_list
            .split(',')
            .map(|s| BASE64.decode(s).unwrap_or_default())
            .collect();

        // 2. public_inputs 取 public_inputs_list 的第一个元素，如果没有则用空 Vec
        let public_inputs = public_inputs_list.first().cloned().unwrap_or_default();

        // 或带默认值的处理
        let task_type = TaskType::try_from(req.task_type).unwrap_or_else(|_| {
            log::warn!("Invalid TaskType, defaulting to ProofRequired");
            TaskType::ProofHash
        });

        Self {
            task_id: req.task_id,
            program_id: req.program_id,
            public_inputs,
            public_inputs_list,
            task_type,
        }
    }
}

pub fn prove_task(task: Task) -> Result<ProverResult> {
    // let proof = match task.program_id.as_str() {
    //     "fib_input_initial" => prove_fib_initial(&task)?,
    //     "fast-fib" => prove_fast_fib(&task)?,
    //     _ => return Err(anyhow!("Unsupported program ID: {}", task.program_id)),
    // };

    let all_inputs = task.public_inputs_list.clone();

    let mut proof_hashes = Vec::new();
    let mut final_proof = None;

    for (input_index, input_data) in all_inputs.iter().enumerate() {
        // Step 1: Parse and validate input
        let inputs = parse_triple_input(input_data)?;

        // Step 2: Generate and verify proof
        let proof = prove_and_validate(&inputs).map_err(|e| {
            // Track verification failure
            e
        })?;

        // Step 3: Generate proof hash
        let proof_hash = generate_proof_hash(&proof);
        proof_hashes.push(proof_hash);
        final_proof = Some(proof);
    }

    let final_proof_hash = combine_proof_hashes(&task, &proof_hashes);

    Ok(ProverResult {
        proof: Some(final_proof.unwrap()),
        combined_hash: final_proof_hash,
        proof_hashes,
    })
}

pub fn prove_task2(task: Task, max_threads: Option<usize>) -> Result<ProverResult> {
    let all_inputs = task.public_inputs_list.clone();

    // 特殊处理空输入的情况
    if all_inputs.is_empty() {
        return Ok(ProverResult {
            proof: None,
            combined_hash: combine_proof_hashes(&task, &[]),
            proof_hashes: vec![],
        });
    }

    // 创建带有线程限制的线程池
    let pool = ThreadPoolBuilder::new()
        .num_threads(max_threads.unwrap_or_else(|| {
            let cores = num_cpus::get();
            cores.min(16)
        }))
        .build()
        .map_err(|e| anyhow!("Failed to create thread pool: {}", e))?;

    // 并行处理所有输入并保持顺序
    let mut results = pool.install(|| {
        all_inputs
            .par_iter()
            .enumerate()
            .map(|(input_index, input_data)| {
                let inputs = parse_triple_input(input_data)?;
                let proof = prove_and_validate(&inputs)?;

                // 立即释放不再需要的大内存对象
                drop(inputs); // 显式释放输入数据

                // 返回最小必要数据
                Ok((input_index, proof))
            })
            .collect::<Result<Vec<_>>>()
    })?;

    // 按原始输入顺序排序
    results.sort_by_key(|(idx, _)| *idx);

    // 生成proof_hashes
    let mut proof_hashes = Vec::with_capacity(results.len());

    // 提前提取最终证明并释放其他证明
    let final_proof = if let Some((_, last_proof)) = results.pop() {
        // 处理除最后一个证明外的所有证明
        for (_, proof) in results.drain(..) {
            let hash = generate_proof_hash(&proof);
            proof_hashes.push(hash);

            // 显式释放证明对象
            drop(proof);
        }

        // 单独处理最后一个证明
        let hash = generate_proof_hash(&last_proof);


        proof_hashes.push(hash);

        Some(last_proof)
    } else {
        None
    };

    // 显式释放结果列表（此时已为空）
    drop(results);

    let combined_hash = combine_proof_hashes(&task, &proof_hashes);

    // 返回结果前显式释放大对象
    let result = ProverResult {
        proof: final_proof,
        combined_hash,
        proof_hashes,
    };

    Ok(result)
}
/// Combine multiple proof hashes based on task type
fn combine_proof_hashes(task: &Task, proof_hashes: &[String]) -> String {
    match task.task_type {
        crate::nexus_orchestrator::TaskType::AllProofHashes
        | crate::nexus_orchestrator::TaskType::ProofHash => task_combine_proof_hashes(proof_hashes),
        _ => proof_hashes.first().cloned().unwrap_or_default(),
    }
}

pub fn task_combine_proof_hashes(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return String::new();
    }

    // Concatenate all hash strings
    let all_bytes: Vec<u8> = hashes
        .iter()
        .flat_map(|input| input.as_bytes())
        .copied()
        .collect();

    // Hash the combined string using Keccak-256
    let hash = Keccak256::digest(&all_bytes);

    format!("{:x}", hash)
}
fn generate_proof_hash(proof: &Proof) -> String {
    let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
    format!("{:x}", Keccak256::digest(&proof_bytes))
}
/// Parse triple public input from byte data (n, init_a, init_b)
pub fn parse_triple_input(input_data: &[u8]) -> Result<(u32, u32, u32), ProverError> {
    if input_data.len() < (u32::BITS / 8 * 3) as usize {
        return Err(ProverError::MalformedTask(
            "Public inputs buffer too small, expected at least 12 bytes for three u32 values"
                .to_string(),
        ));
    }

    let mut bytes = [0u8; 4];

    bytes.copy_from_slice(&input_data[0..4]);
    let n = u32::from_le_bytes(bytes);

    bytes.copy_from_slice(&input_data[4..8]);
    let init_a = u32::from_le_bytes(bytes);

    bytes.copy_from_slice(&input_data[8..12]);
    let init_b = u32::from_le_bytes(bytes);

    Ok((n, init_a, init_b))
}

/// Generate proof for given inputs using the fibonacci program
/// Returns the proof and a validation function for the view
pub fn prove_and_validate(inputs: &(u32, u32, u32)) -> Result<Proof, ProverError> {
    let prover = create_initial_prover()?;
    let (view, proof) = prover
        .prove_with_input::<(), (u32, u32, u32)>(&(), inputs)
        .map_err(|e| {
            ProverError::Stwo(format!(
                "Failed to generate proof for inputs {:?}: {}",
                inputs, e
            ))
        })?;

    verifier::ProofVerifier::check_exit_code(&view).unwrap();

    // Verify proof immediately (create fresh prover for verification)
    let verify_prover = create_initial_prover()?;
    verifier::ProofVerifier::verify_proof(&proof, inputs, &verify_prover).unwrap();
    Ok(proof)
}

fn prove_fast_fib(task: &Task) -> Result<Proof> {
    let input = parse_single_input(task)?;
    let prover = create_default_prover()?;

    let (view, proof) = prover
        .prove_with_input::<(), u32>(&(), &input)
        .map_err(|e| anyhow!("fast-fib prover failed: {}", e))?;

    check_exit_code(&view)?;
    Ok(proof)
}

fn parse_single_input(task: &Task) -> Result<u32> {
    if task.public_inputs.is_empty() {
        return Err(anyhow!("Public inputs are empty"));
    }
    Ok(task.public_inputs[0] as u32)
}
fn create_default_prover() -> Result<Stwo<Local>> {
    Stwo::<Local>::new_from_bytes(FIB_INPUT).map_err(|e| anyhow!("Failed to load fib_input: {}", e))
}

fn create_initial_prover() -> Result<Stwo<Local>, ProverError> {
    Stwo::<Local>::new_from_bytes(FIB_INPUT_INITIAL).map_err(|e| {
        ProverError::Stwo(format!(
            "Failed to load fib_input_initial guest program: {}",
            e
        ))
    })
}

fn check_exit_code(view: &impl Viewable) -> Result<()> {
    let exit_code = view
        .exit_code()
        .map_err(|e| anyhow!("Failed to deserialize exit code: {}", e))?;

    if exit_code != KnownExitCodes::ExitSuccess as u32 {
        return Err(anyhow!(
            "Prover exited with non-zero exit code: {}",
            exit_code
        ));
    }
    Ok(())
}
