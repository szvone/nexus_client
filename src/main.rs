mod environment;
mod nexus_orchestrator;
mod orchestrator;
mod prover;
pub mod system;
mod task;

use crate::environment::Environment;
use crate::orchestrator::error::OrchestratorError;
use crate::orchestrator::{Orchestrator, OrchestratorClient};
use crate::prover::ProveResult;
use ed25519_dalek::SigningKey;
use mac_address::get_mac_address;
use reqwest::{Client, Error as ReqwestError, blocking::Client as blockingClient};
use serde::{Deserialize, Serialize};
use std::thread;
use systemstat::{Platform, System};
use uuid::Uuid;
use std::time::{Instant, Duration};
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

#[derive(Serialize)]
struct HeartbeatData {
    client_uuid: String,
    client_key: String,
    cpu: u32,
    memory: u32,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 文件读取处理
    let contents = match std::fs::read_to_string("./nexus_client.txt") {
        Ok(c) => c,
        Err(e) => {
            log::error!("配置文件读取失败: {}", e);
            log::warn!("请检查文件 nexus_client.txt 是否存在或权限设置");
            wait_for_enter();
            return;
        }
    };

    // YAML解析处理
    let config: Config = match serde_yaml::from_str(&contents) {
        Ok(c) => c,
        Err(e) => {
            log::error!("YAML解析失败: {}", e);
            log::warn!("请检查配置文件 nexus_client.txt 格式是否正确");
            wait_for_enter();
            return;
        }
    };

    // 生成随机UUID
    let uuid = Uuid::new_v4().to_string();
    log::info!("客户端编号: {}", uuid);

    // 获取MAC地址
    let mac_address = get_mac_address()
        .expect("Failed to get MAC address")
        .map(|addr| addr.to_string().to_uppercase())
        .unwrap_or_else(|| "UNKNOWN-MAC".to_string());

    log::info!("客户端标识: {}", mac_address);

    // 使用配置
    log::info!("服务端地址: {}", config.host);
    log::info!("服务端端口: {}", config.port);

    let pick_url = format!("http://{}:{}/tasks/pick", config.host, config.port);
    let submit_url = format!("http://{}:{}/tasks/submit", config.host, config.port);
    let heart_url = format!("http://{}:{}/tasks/clientHeart", config.host, config.port);
    // 启动心跳线程
    thread::spawn(move || {
        heartbeat_loop(heart_url.clone(), uuid.clone(), mac_address.clone());
    });
    log::info!("客户端启动: 初始化完成，计算节点启动！");

    let http_client = Client::new();

    loop {
        log::info!("-------------------------------------------");

        match fetch_task(&http_client, pick_url.clone()).await {
            Ok(Some(payload)) => {
                log::info!("获取计算任务: {}", payload.task_id);
                let start_time = Instant::now();

                let task = prover::Task::from(payload.clone());
                let result = prover::prove_task(task);

                let response = match result {
                    Ok(proof) => {
                        let elapsed_ms = start_time.elapsed().as_millis();
                        log::info!("任务计算成功: 计算耗时 {} 毫秒 ", elapsed_ms);
                        handle_proof(&payload, &proof).await
                    }
                    Err(err) => {
                        let error = format!("Proof generation failed: {}", err);
                        log::info!("任务计算失败: {}", error);
                        Api2Response {
                            task_id: payload.task_id.clone(),
                            result: error,
                            credits: 0,
                        }
                    }
                };

                // Send result to API2
                if let Err(e) = http_client
                    .post(submit_url.clone())
                    .json(&response)
                    .send()
                    .await
                {
                    log::info!("回传任务结果: 失败-> {:?}", e);
                } else {
                    log::info!("回传任务结果: 回传数据成功！");
                }
            }
            Ok(None) => {
                log::info!("获取计算任务: 没有计算任务，等待5秒！");
                sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                
                log::info!("获取计算任务: 失败，请检查IP端口是否正确，服务端是否运行!");

                sleep(Duration::from_secs(10)).await;
            }
        }
        log::info!("-------------------------------------------");
    }
}

// 等待用户按回车键的函数
fn wait_for_enter() {
    use std::io::{self, Write};

    let mut input = String::new();
    print!("\n发生错误，按回车键退出...");
    io::stdout().flush().expect("刷新输出失败");
    io::stdin().read_line(&mut input).expect("读取输入失败");
}

async fn fetch_task(client: &Client, url: String) -> Result<Option<TaskRequest>, ReqwestError> {
    let response: reqwest::Response = client.get(url).send().await?;

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
        Ok(node_point) => {
            log::info!("任务提交结果: 提交成功");

            return Api2Response {
                task_id: task.task_id.clone(),
                credits: node_point,
                result: "success".to_owned(),
            };
        }
        Err(e) => {
            if let Some(msg) = e.http_message() {
                if msg.contains("Task not found") {
                    log::info!("任务提交结果: 任务不存在，可能入库太久已失效！");
                    return Api2Response {
                        task_id: task.task_id.clone(),
                        credits: 0,
                        result: format!("{}", e),
                    };
                } else if msg.contains(":429}") {
                    log::info!("任务提交结果: 提交频繁，回传后将重新分配！");
                    return Api2Response {
                        task_id: task.task_id.clone(),
                        credits: 0,
                        result: format!("{}", e),
                    };
                }
            }

            // 检查是否是 Reqwest 超时错误
            if let OrchestratorError::Reqwest(ref reqwest_err) = e {
                if reqwest_err.is_timeout() {
                    log::info!("任务提交结果: 提交失败，请求超时！");
                } else {
                    log::info!("任务提交结果: 失败-> {:?}", e);
                }
            } else {
                log::info!("任务提交结果: 失败-> {:?}", e);
            }
            log::info!("尝试重新提交: 提交中...");

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
                Ok(node_point) => {
                    log::info!("任务提交结果: 提交成功");

                    return Api2Response {
                        task_id: task.task_id.clone(),
                        credits: node_point,
                        result: "success".to_owned(),
                    };
                }
                Err(e) => {
                    if let Some(msg) = e.http_message() {
                        if msg.contains("Task not found") {
                            log::info!("重新提交失败: 任务不存在，可能入库太久已失效！");
                            return Api2Response {
                                task_id: task.task_id.clone(),
                                credits: 0,
                                result: format!("{}", e),
                            };
                        } else if msg.contains(":429}") {
                            log::info!("重新提交失败: 提交频繁，回传后将重新分配！");
                            return Api2Response {
                                task_id: task.task_id.clone(),
                                credits: 0,
                                result: format!("{}", e),
                            };
                        }
                    }
                    // 检查是否是 Reqwest 超时错误
                    if let OrchestratorError::Reqwest(ref reqwest_err) = e {
                        if reqwest_err.is_timeout() {
                            log::info!("重新提交失败: 提交失败，请求超时！");
                            return Api2Response {
                                task_id: task.task_id.clone(),
                                credits: 0,
                                result: format!("{}", e),
                            };
                        } else {
                            log::info!("重新提交失败: 失败-> {:?}", e);
                        }
                    } else {
                        log::info!("重新提交失败: 失败-> {:?}", e);
                    }

                    return Api2Response {
                        task_id: task.task_id.clone(),
                        credits: 0,
                        result: format!("{}", e),
                    };
                }
            }
        }
    }
}

fn heartbeat_loop(api: String, client_uuid: String, client_key: String) {
    let http_client = blockingClient::new();
    let sys = System::new();

    loop {
        // 获取系统资源使用情况并转换为整数
        let cpu_usage = get_cpu_usage(&sys).unwrap_or(0);
        let mem_usage = get_memory_usage(&sys).unwrap_or(0);

        // println!(
        //     "Uploading: CPU {}%, Mem {}%",
        //     cpu_usage, mem_usage
        // );

        // 准备心跳数据
        let data = HeartbeatData {
            client_uuid: client_uuid.clone(),
            client_key: client_key.clone(),
            cpu: cpu_usage,
            memory: mem_usage,
        };

        // 发送心跳请求
        if let Err(e) = send_heartbeat(api.clone(), &http_client, &data) {
            log::info!("心跳请求与服务端通讯失败，请检查IP端口！");
            // eprintln!("Error sending heartbeat: {}", e);
        }

        // 等待30秒
        thread::sleep(Duration::from_secs(5));
    }
}

fn get_cpu_usage(sys: &System) -> Result<u32, String> {
    let sample = sys
        .cpu_load()
        .map_err(|e| format!("Failed to get CPU load: {}", e))?;

    // 等待1秒获取准确的CPU使用率
    thread::sleep(Duration::from_secs(1));

    let usage = sample
        .done()
        .map_err(|e| format!("Failed to calculate CPU usage: {}", e))?;

    let mut total_usage = 0.0;
    for cpu in &usage {
        total_usage += (1.0 - cpu.idle) as f64;
    }

    // 计算平均CPU使用率并转为整数
    let avg_usage = (total_usage / usage.len() as f64) * 100.0;
    Ok(avg_usage.round() as u32)
}

fn get_memory_usage(sys: &System) -> Result<u32, String> {
    let mem = sys
        .memory()
        .map_err(|e| format!("Failed to get memory info: {}", e))?;

    let used = (mem.total.as_u64() - mem.free.as_u64()) as f64;
    let total = mem.total.as_u64() as f64;

    // 计算内存使用率并转为整数
    let usage_percentage = (used / total) * 100.0;
    Ok(usage_percentage.round() as u32)
}
fn send_heartbeat(
    api: String,
    http_client: &blockingClient,
    data: &HeartbeatData,
) -> Result<(), String> {
    let response = http_client.post(api).json(data).send();

    match response {
        Ok(res) => {
            let status = res.status(); // 先获取状态码
            if status.is_success() {
                Ok(())
            } else {
                match res.text() {
                    Ok(body) => Err(format!(
                        "Server returned error status: {}\nResponse body: {}",
                        status, body
                    )),
                    Err(e) => Err(format!(
                        "Server returned error status: {} but failed to read response body: {}",
                        status, e
                    )),
                }
            }
        }
        Err(e) => Err(format!("HTTP request failed: {}", e)),
    }
}
