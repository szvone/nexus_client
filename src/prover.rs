use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::Engine; // 引入Engine trait
use hex;
use nexus_sdk::{
    stwo::seq::{Proof, Stwo},
    KnownExitCodes, Local, Prover, Viewable,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::convert::TryInto;
// 添加这个以支持 bincode 的反序列化

#[derive(Serialize, Deserialize,Debug)]
pub struct ProveResult {
    pub proof_hash: String,
    pub proof_bytes:Vec<u8>,
}

#[derive(Debug)]
pub struct Task {
    pub task_id: String,
    pub program_id: String,
    pub public_inputs: Vec<u8>,
}
// 在模块顶部
static FIB_INPUT: &[u8] = include_bytes!("../assets/fib_input");
static FIB_INPUT_INITIAL: &[u8] = include_bytes!("../assets/fib_input_initial");



impl From<super::TaskRequest> for Task {
    fn from(req: super::TaskRequest) -> Self {
        let public_inputs = BASE64.decode(&req.public_inputs).unwrap_or_default();

        Self {
            task_id:req.task_id,
            program_id: req.program_id,
            public_inputs,
        }
    }
}

pub fn prove_task(task: Task) -> Result<ProveResult> {

    let proof = match task.program_id.as_str() {
        "fib_input_initial" => prove_fib_initial(&task)?,
        "fast-fib" => prove_fast_fib(&task)?,
        _ => return Err(anyhow!("Unsupported program ID: {}", task.program_id)),
    };

    // 序列化证明并计算哈希
    let proof_bytes = postcard::to_allocvec(&proof)?;
    let proof_hash = format!("{:x}", Keccak256::digest(&proof_bytes));
    // let proof_base64 = BASE64.encode(&proof_bytes);

    let result = ProveResult {
        proof_hash,
        proof_bytes,
    };

    // Save to cache before returning
    // save_cache(&cache_path, &result)?;

    Ok(result)
}

fn prove_fib_initial(task: &Task) -> Result<Proof> {
    let (n, init_a, init_b) = parse_triple_input(task)?;
    let prover = create_initial_prover()?;

    let (view, proof) = prover
        .prove_with_input::<(), (u32, u32, u32)>(&(), &(n, init_a, init_b))
        .map_err(|e| anyhow!("fib_input_initial prover failed: {}", e))?;

    check_exit_code(&view)?;
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

fn parse_triple_input(task: &Task) -> Result<(u32, u32, u32)> {
    if task.public_inputs.len() < 12 {
        return Err(anyhow!(
            "Public inputs too small (need 12 bytes), got {} bytes",
            task.public_inputs.len()
        ));
    }

    let n = u32::from_le_bytes(
        task.public_inputs[0..4]
            .try_into()
            .map_err(|_| anyhow!("Failed to parse n"))?,
    );

    let init_a = u32::from_le_bytes(
        task.public_inputs[4..8]
            .try_into()
            .map_err(|_| anyhow!("Failed to parse init_a"))?,
    );

    let init_b = u32::from_le_bytes(
        task.public_inputs[8..12]
            .try_into()
            .map_err(|_| anyhow!("Failed to parse init_b"))?,
    );

    Ok((n, init_a, init_b))
}

fn create_default_prover() -> Result<Stwo<Local>> {
    Stwo::<Local>::new_from_bytes(FIB_INPUT).map_err(|e| anyhow!("Failed to load fib_input: {}", e))
}

fn create_initial_prover() -> Result<Stwo<Local>> {
    Stwo::<Local>::new_from_bytes(FIB_INPUT_INITIAL)
        .map_err(|e| anyhow!("Failed to load fib_input_initial: {}", e))
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
