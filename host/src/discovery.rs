use crate::logging::{log_error, log_info};
use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use local_ip_address::local_ip;
use serde_json::to_string;
use shared::{DiscoveryMessage, DISCOVERY_WS_URL};
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

use crate::shmem_utils;

pub async fn start_discovery_service(
    pipe: Arc<tokio::sync::Mutex<NamedPipeServer>>,
    shmem: Arc<Mutex<shmem_utils::Shmem>>,
) {
    maintain_discovery_connection(pipe, shmem).await;
}

pub async fn ensure_initial_registration() -> Result<()> {
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "Unknown".to_string());
    let user = whoami::fallible::username().unwrap_or_else(|_| "Unknown".to_string());
    let os = format!("{} {}", whoami::platform(), whoami::distro());
    let host_id = format!("HOST_{}", hostname);
    
    // Try to connect once
    log_info(&format!("Initial connection attempt to discovery server at {}...", DISCOVERY_WS_URL));
    
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
    let ip = select_local_ip();
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

async fn maintain_discovery_connection(
    pipe: Arc<tokio::sync::Mutex<NamedPipeServer>>,
    shmem: Arc<Mutex<shmem_utils::Shmem>>,
) {
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "Unknown".to_string());
    let user = whoami::fallible::username().unwrap_or_else(|_| "Unknown".to_string());
    let os = format!("{} {}", whoami::platform(), whoami::distro());
    let host_id = format!("HOST_{}", hostname);

    loop {
        log_info(&format!("Connecting to discovery server (maintenance) at {}...", DISCOVERY_WS_URL));
        match connect_to_server().await {
            Ok(ws_stream) => {
                log_info("Connected to discovery server.");
                
                let (mut write, mut read) = ws_stream.split();

                // 1. Register
                let ip = select_local_ip();
                
                let register_msg = DiscoveryMessage::RegisterHost {
                    host_id: host_id.clone(),
                    hostname: hostname.clone(),
                    ip,
                    user: user.clone(),
                    os: os.clone(),
                };

                // Manually serialize and send because split() gives us a SplitSink that takes tungstenite::Message
                let msg_str = serde_json::to_string(&register_msg).unwrap();
                if let Err(e) = write.send(tokio_tungstenite::tungstenite::Message::Text(msg_str)).await {
                    log_error(&format!("Failed to register: {}", e));
                    continue; 
                }
                log_info(&format!("Registered as {}", host_id));

                // 2. Heartbeat & Read Loop
                let mut interval = tokio::time::interval(Duration::from_secs(15));

                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let heartbeat = DiscoveryMessage::Heartbeat {
                                host_id: host_id.clone(),
                            };
                            let msg_str = serde_json::to_string(&heartbeat).unwrap();
                            if let Err(e) = write.send(tokio_tungstenite::tungstenite::Message::Text(msg_str)).await {
                                log_info(&format!("Heartbeat failed (disconnected): {}. Reconnecting...", e));
                                break; 
                            }
                        }
                        msg = read.next() => {
                            match msg {
                                Some(Ok(m)) => {
                                    if let Ok(text) = m.to_text() {
                                        if let Ok(parsed) = serde_json::from_str::<DiscoveryMessage>(text) {
                                            match parsed {
                                                DiscoveryMessage::ReverseConnect { viewer_ip, viewer_port, viewer_id } => {
                                                    log_info(&format!("Received Reverse Connect request from viewer {} at {}:{}", viewer_id, viewer_ip, viewer_port));
                                                    let pipe = pipe.clone();
                                                    let shmem = shmem.clone();
                                                    let viewer_addr = format!("{}:{}", viewer_ip, viewer_port);
                                                    
                                                    tokio::spawn(async move {
                                                        log_info(&format!("Initiating reverse connection to {}", viewer_addr));
                                                        match TcpStream::connect(&viewer_addr).await {
                                                            Ok(socket) => {
                                                                log_info(&format!("Reverse connection established to {}", viewer_addr));
                                                                if let Err(e) = crate::handle_client(socket, pipe, shmem).await {
                                                                    log_error(&format!("Error in reverse connection session: {}", e));
                                                                } else {
                                                                    log_info("Reverse connection session ended.");
                                                                }
                                                            }
                                                            Err(e) => {
                                                                log_error(&format!("Failed to connect to viewer {}: {}", viewer_addr, e));
                                                            }
                                                        }
                                                    });
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                Some(Err(e)) => {
                                    log_error(&format!("WebSocket read error: {}", e));
                                    break;
                                }
                                None => {
                                    log_info("WebSocket connection closed.");
                                    break;
                                }
                            }
                        }
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
    let url = Url::parse(DISCOVERY_WS_URL)?;
    let (ws_stream, _) = connect_async(url).await?;
    Ok(ws_stream)
}

fn select_local_ip() -> String {
    if let Ok(url) = Url::parse(DISCOVERY_WS_URL) {
        if let Some(host) = url.host_str() {
            let port = url.port_or_known_default().unwrap_or(5600);
            let target = format!("{}:{}", host, port);
            if let Ok(mut addrs) = target.to_socket_addrs() {
                while let Some(addr) = addrs.next() {
                    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                        if sock.connect(addr).is_ok() {
                            if let Ok(local_addr) = sock.local_addr() {
                                let ip = local_addr.ip();
                                if is_valid_ip(ip) {
                                    log_info(&format!("Selected local IP via route: {}", ip));
                                    return ip.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let ip = local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string());
    log_info(&format!("Selected local IP via fallback: {}", ip));
    ip
}

fn is_valid_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}

async fn send_msg(
    ws_stream: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    msg: DiscoveryMessage,
) -> Result<()> {
    let json = to_string(&msg)?;
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(json)).await?;
    Ok(())
}
