use futures_util::{SinkExt, StreamExt};
use serde_json::{from_str, to_string};
use shared::{DiscoveryMessage, HostInfo};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

const DISCOVERY_URL: &str = "ws://192.168.1.238:5600";

pub struct DiscoveryClient {
    hosts: Arc<Mutex<Vec<HostInfo>>>,
    connection_status: Arc<Mutex<String>>,
}

impl DiscoveryClient {
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(Mutex::new(Vec::new())),
            connection_status: Arc::new(Mutex::new("Disconnected".to_string())),
        }
    }

    pub fn get_hosts(&self) -> Vec<HostInfo> {
        self.hosts.lock().unwrap().clone()
    }

    pub fn get_status(&self) -> String {
        self.connection_status.lock().unwrap().clone()
    }

    pub fn start(&self) {
        let hosts_clone = self.hosts.clone();
        let status_clone = self.connection_status.clone();

        tokio::spawn(async move {
            loop {
                *status_clone.lock().unwrap() = "Connecting...".to_string();
                match connect_async(Url::parse(DISCOVERY_URL).unwrap()).await {
                    Ok((mut ws_stream, _)) => {
                        *status_clone.lock().unwrap() = "Connected".to_string();
                        
                        // Initial fetch
                        let list_req = DiscoveryMessage::ListHosts { viewer_id: Some("Viewer".to_string()) }; // TODO: Unique ID
                        if let Err(e) = send_msg(&mut ws_stream, list_req).await {
                             eprintln!("Error sending list request: {}", e);
                             continue;
                        }

                        // Loop for refresh and messages
                        let mut interval = tokio::time::interval(Duration::from_secs(10));
                        loop {
                            tokio::select! {
                                _ = interval.tick() => {
                                     let list_req = DiscoveryMessage::ListHosts { viewer_id: Some("Viewer".to_string()) };
                                     if let Err(e) = send_msg(&mut ws_stream, list_req).await {
                                         eprintln!("Error sending list request (tick): {}", e);
                                         break;
                                     }
                                }
                                msg = ws_stream.next() => {
                                    match msg {
                                        Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                                            if let Ok(parsed) = from_str::<DiscoveryMessage>(&text) {
                                                match parsed {
                                                    DiscoveryMessage::HostList { hosts } => {
                                                        *hosts_clone.lock().unwrap() = hosts;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => {
                                            break;
                                        }
                                        Some(Err(e)) => {
                                            eprintln!("WS Error: {}", e);
                                            break;
                                        }
                                        None => break,
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        *status_clone.lock().unwrap() = format!("Error: {}", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    pub async fn request_connection(&self, host_id: String) -> Result<(String, u16), String> {
        // We create a temporary one-off connection or use the main loop?
        // Using main loop requires channel communication which I didn't set up.
        // For simplicity, let's open a new short-lived connection or improve the architecture.
        // Given the constraints, I will open a new connection for the request.
        
        match connect_async(Url::parse(DISCOVERY_URL).unwrap()).await {
            Ok((mut ws_stream, _)) => {
                let req = DiscoveryMessage::ConnectRequest {
                    viewer_id: "Viewer".to_string(),
                    host_id,
                };
                send_msg(&mut ws_stream, req).await.map_err(|e| e.to_string())?;
                
                // Wait for response
                while let Some(msg) = ws_stream.next().await {
                    match msg {
                        Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                             if let Ok(parsed) = from_str::<DiscoveryMessage>(&text) {
                                 if let DiscoveryMessage::ConnectResponse { success, host_ip, host_port, error } = parsed {
                                     if success {
                                         return Ok((host_ip.unwrap(), host_port.unwrap()));
                                     } else {
                                         return Err(error.unwrap_or("Unknown error".to_string()));
                                     }
                                 }
                             }
                        }
                        _ => {}
                    }
                }
                Err("No response".to_string())
            }
            Err(e) => Err(e.to_string())
        }
    }
}

async fn send_msg(
    ws_stream: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    msg: DiscoveryMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = to_string(&msg)?;
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(json)).await?;
    Ok(())
}
