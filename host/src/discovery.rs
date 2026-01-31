use crate::logging::{log_error, log_info};
use anyhow::Result;
use futures_util::SinkExt;
use local_ip_address::local_ip;
use serde_json::to_string;
use shared::DiscoveryMessage;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

const DISCOVERY_URL: &str = "ws://192.168.1.238:5600";

pub async fn start_discovery_service() {
    // This function now just calls the infinite loop, used for spawning
    maintain_discovery_connection().await;
}

pub async fn ensure_initial_registration() -> Result<()> {
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "Unknown".to_string());
    let user = whoami::fallible::username().unwrap_or_else(|_| "Unknown".to_string());
    let os = format!("{} {}", whoami::platform(), whoami::distro());
    let host_id = format!("HOST_{}", hostname);
    
    // Try to connect once
    log_info(&format!("Initial connection attempt to discovery server at {}...", DISCOVERY_URL));
    
    let mut ws_stream = loop {
        match connect_to_server().await {
            Ok(s) => break s,
            Err(e) => {
                log_error(&format!("Initial connection failed: {}. Retrying in 5s...", e));
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    log_info("Connected to discovery server. Registering...");

    // Register
    let ip = local_ip().map(|ip| ip.to_string()).unwrap_or_else(|_| "0.0.0.0".to_string());
    let register_msg = DiscoveryMessage::RegisterHost {
        host_id: host_id.clone(),
        hostname: hostname.clone(),
        ip,
        user: user.clone(),
        os: os.clone(),
    };

    send_msg(&mut ws_stream, register_msg).await.map_err(|e| anyhow::anyhow!(e))?;
    log_info(&format!("Successfully registered as {}", host_id));
    
    Ok(())
}

async fn maintain_discovery_connection() {
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "Unknown".to_string());
    let user = whoami::fallible::username().unwrap_or_else(|_| "Unknown".to_string());
    let os = format!("{} {}", whoami::platform(), whoami::distro());
    let host_id = format!("HOST_{}", hostname);

    loop {
        log_info(&format!("Connecting to discovery server (maintenance) at {}...", DISCOVERY_URL));
        match connect_to_server().await {
            Ok(mut ws_stream) => {
                log_info("Connected to discovery server.");
                
                // 1. Register
                let ip = local_ip().map(|ip| ip.to_string()).unwrap_or_else(|_| "0.0.0.0".to_string());
                
                let register_msg = DiscoveryMessage::RegisterHost {
                    host_id: host_id.clone(),
                    hostname: hostname.clone(),
                    ip,
                    user: user.clone(),
                    os: os.clone(),
                };

                if let Err(e) = send_msg(&mut ws_stream, register_msg).await {
                    log_error(&format!("Failed to register: {}", e));
                    continue; 
                }
                log_info(&format!("Registered as {}", host_id));

                // 2. Heartbeat Loop
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    let heartbeat = DiscoveryMessage::Heartbeat {
                        host_id: host_id.clone(),
                    };
                    
                    if let Err(e) = send_msg(&mut ws_stream, heartbeat).await {
                        log_info(&format!("Heartbeat failed (disconnected): {}. Reconnecting...", e));
                        break; 
                    }
                }
            }
            Err(e) => {
                log_error(&format!("Connection to discovery failed: {}", e));
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn connect_to_server() -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let url = Url::parse(DISCOVERY_URL)?;
    let (ws_stream, _) = connect_async(url).await?;
    Ok(ws_stream)
}

async fn send_msg(
    ws_stream: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    msg: DiscoveryMessage,
) -> Result<()> {
    let json = to_string(&msg)?;
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(json)).await?;
    Ok(())
}
