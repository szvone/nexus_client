mod environment;
mod nexus_orchestrator;
mod orchestrator;
mod prover;
pub mod system;
mod task;

use crate::environment::Environment;
use crate::orchestrator::{Orchestrator, OrchestratorClient};
use crate::prover::ProveResult;
use ed25519_dalek::SigningKey;
use reqwest::{Client, Error as ReqwestError};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

use std::time::Duration;
use tokio::time::sleep;

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Deserialize, Clone)]
struct TaskRequest {
    #[serde(rename = "taskId")]
    task_id: String,
    #[serde(rename = "programId")]
    program_id: String,
    #[serde(rename = "publicInputs")]
    public_inputs: String,
    #[serde(rename = "signKey")]
    sign_key: String,
}

#[derive(Debug, Serialize)]
struct Api2Response {
    #[serde(rename = "taskId")]
    task_id: String,
    #[serde(rename = "result")]
    result: String,
    #[serde(rename = "credits")]
    credits: i32,
}
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    host: String,
    port: u16,
}
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();


    // 文件读取处理
    let contents = match std::fs::read_to_string("./nexus_client.txt") {
        Ok(c) => c,
        Err(e) => {
            log::error!("配置文件读取失败: {}", e);
            log::warn!("请检查文件路径或权限设置");
            wait_for_enter();
            return;
        }
    };

    // YAML解析处理
    let config: Config = match serde_yaml::from_str(&contents) {
        Ok(c) => c,
        Err(e) => {
            log::error!("YAML解析失败: {}", e);
            log::warn!("请检查配置文件格式是否正确");
            wait_for_enter();
            return;
        }
    };

    // 使用配置
    log::info!("服务端地址: {}", config.host);
    log::info!("服务端端口: {}", config.port);

    log::info!("分布式计算节点启动！");
    let pick_url = format!("http://{}:{}/tasks/pick", config.host, config.port);
    let submit_url = format!("http://{}:{}/tasks/submit", config.host, config.port);

    let http_client = Client::new();

    loop {
        match fetch_task(&http_client, pick_url.clone()).await {
            Ok(Some(payload)) => {
                log::info!("读取到计算任务: {:?}", payload.task_id);

                let task = prover::Task::from(payload.clone());
                let result = prover::prove_task(task);

                let response = match result {
                    Ok(proof) => {
                        log::info!("计算成功: {:?}", payload.task_id);
                        handle_proof(&payload, &proof).await
                    }
                    Err(err) => {
                        log::info!("计算失败: {:?}", err);
                        let error = format!("Proof generation failed: {}", err);
                        Api2Response {
                            task_id: payload.task_id.clone(),
                            result: error,
                            credits: 0,
                        }
                    }
                };

                log::info!("回传结果: {:?}", response.result);

                // Send result to API2
                if let Err(e) = http_client.post(submit_url.clone()).json(&response).send().await {
                    // eprintln!("Failed to send results to API2: {}", e);
                    log::info!("与任务分发服务器通讯失败，请检查配置文件的端口和IP是否正确！ {:?}", e);
                }
            }
            Ok(None) => {
                log::info!("没有计算任务，等待5秒...");
                sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                log::info!("与任务分发服务器通讯失败，请检查配置文件的端口和IP是否正确！ {:?}", e);

                // log::info!("与任务分发服务器通讯失败，等待10秒...");
                // eprintln!("Error fetching task: {}. Retrying...", e);
                sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

// 等待用户按回车键的函数
fn wait_for_enter() {
    use std::io::{self, Write};
    
    let mut input = String::new();
    print!("\n发生错误，按回车键退出...");
    io::stdout().flush().expect("刷新输出失败");
    io::stdin()
        .read_line(&mut input)
        .expect("读取输入失败");
}

async fn fetch_task(client: &Client, url: String) -> Result<Option<TaskRequest>, ReqwestError> {
    let response = client.get(url).send().await?;

    if response.status().is_success() {
        let payload: TaskRequest = response.json().await?;
        Ok(Some(payload))
    } else if response.status().as_u16() == 404 {
        Ok(None)
    } else {
        Err(response.error_for_status().unwrap_err())
    }
}

async fn handle_proof(task: &TaskRequest, proof: &ProveResult) -> Api2Response {
    // Convert sign key
    let bytes = match hex::decode(&task.sign_key) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Api2Response {
                task_id: task.task_id.clone(),
                credits: 0,
                result: format!("Sign key decoding failed: {}", e),
            };
        }
    };

    let mut array = [0u8; 64];
    if bytes.len() != 64 {
        return Api2Response {
            task_id: task.task_id.clone(),
            credits: 0,
            result: "Invalid sign key length".to_string(),
        };
    }
    array.copy_from_slice(&bytes);

    // Submit to orchestrator
    let signing_key = match SigningKey::from_keypair_bytes(&array) {
        Ok(key) => key,
        Err(e) => {
            return Api2Response {
                task_id: task.task_id.clone(),
                credits: 0,
                result: format!("Key pair creation failed: {}", e),
            };
        }
    };

    let client = OrchestratorClient::new(Environment::Beta);
    match client
        .submit_proof(
            &task.task_id,
            &proof.proof_hash,
            proof.proof_bytes.clone(),
            signing_key.clone(),
            5,
        )
        .await
    {
        Ok(node_point) => Api2Response {
            task_id: task.task_id.clone(),
            credits: node_point,
            result: "success".to_owned(),
        },
        Err(e) => {
            log::info!("任务结果提交失败 {:?}", e);
            log::info!("尝试重新提交...");

            match client
                .submit_proof(
                    &task.task_id,
                    &proof.proof_hash,
                    proof.proof_bytes.clone(),
                    signing_key.clone(),
                    5,
                )
                .await
            {
                Ok(node_point) => Api2Response {
                    task_id: task.task_id.clone(),
                    credits: node_point,
                    result: "success".to_owned(),
                },
                Err(e) => Api2Response {
                    task_id: task.task_id.clone(),
                    credits: 0,
                    result: format!("{}", e),
                },
            }
        }
    }
}
