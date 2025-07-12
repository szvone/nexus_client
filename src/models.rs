use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct TaskRequest {
    pub program_id: String,
    pub public_inputs: String, // base64编码的字符串
    pub task_id: String,
}

#[derive(Serialize)]
pub struct ProveResponse {
    pub proof_hash: String,
    pub proof_bytes: String, // base64编码的proof
}