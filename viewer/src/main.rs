use eframe::egui;
use eframe::egui::{ColorImage, TextureHandle};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use shared::{Crypto, InputEvent, MouseButton, NetworkMessage, RemoteKey};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpListener};
use std::net::UdpSocket;

mod discovery;
use discovery::DiscoveryClient;

fn get_local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

const PSK: &str = "mysecretpassword";
const KEY_BYTES: [u8; 32] = [0x42; 32];

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Rust Remote Viewer",
        options,
        Box::new(|cc| Box::new(ViewerApp::new(cc))),
    )
}

struct ViewerApp {
    host_ip: String,
    status: String,
    texture: Option<TextureHandle>,
    latest_image: Arc<Mutex<Option<ColorImage>>>,
    tx_input: Option<tokio::sync::mpsc::Sender<InputEvent>>,
    connection_state: Arc<Mutex<String>>,
    held_buttons: std::collections::HashSet<MouseButton>,
    discovery: DiscoveryClient,
    conn_req_rx: Option<std::sync::mpsc::Receiver<(String, u16, Option<TcpListener>)>>,
}

impl ViewerApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let discovery = DiscoveryClient::new();
        discovery.start();
        
        Self {
            host_ip: "".to_owned(),
            status: "Disconnected".to_owned(),
            texture: None,
            latest_image: Arc::new(Mutex::new(None)),
            tx_input: None,
            connection_state: Arc::new(Mutex::new("disconnected".to_string())),
            held_buttons: std::collections::HashSet::new(),
            discovery,
            conn_req_rx: None,
        }
    }

    fn connect(&mut self, ctx: egui::Context, listener: Option<TcpListener>) {
        let ip = self.host_ip.clone();
        let image_store = self.latest_image.clone();
        let conn_state = self.connection_state.clone();

        // We create a channel, but to support reconnects we should really keep the sender in the App struct
        // and just create a new receiver for each connection if possible?
        // No, receiver must be created with sender.
        // For simplicity in this quick fix: We recreate the channel.
        let (tx_input, mut rx_input) = tokio::sync::mpsc::channel::<InputEvent>(100);
        self.tx_input = Some(tx_input);

        self.status = "Connecting...".to_owned();
        *conn_state.lock().unwrap() = "connecting".to_string();

        let listen_info = if let Some(l) = &listener {
            l.local_addr().ok().map(|a| format!(" (Reverse listening on {})", a)).unwrap_or_default()
        } else {
            String::new()
        };
        let status_msg = format!("Connecting to {}{}...", ip, listen_info);
        self.status = status_msg.clone();

        tokio::spawn(async move {
            println!("{}", status_msg);
            let result = async {
                let mut socket = if let Some(l) = listener {
                    tokio::select! {
                        res = TcpStream::connect(&ip) => {
                            match res {
                                Ok(s) => s,
                                Err(e) => {
                                    println!("Direct connection failed ({}), waiting for reverse connection...", e);
                                    let (s, _) = l.accept().await?;
                                    println!("Accepted reverse connection!");
                                    s
                                }
                            }
                        },
                        res = l.accept() => {
                            let (s, _) = res?;
                            println!("Accepted reverse connection!");
                            s
                        }
                    }
                } else {
                    TcpStream::connect(&ip).await?
                };
                socket.set_nodelay(true)?;

                let crypto = Crypto::new(&KEY_BYTES);

                // Handshake
                let handshake = NetworkMessage::Handshake {
                    psk: PSK.to_string(),
                };
                send_message(&mut socket, &crypto, &handshake)
                    .await
                    .map_err(|e| anyhow::anyhow!("Handshake send: {}", e))?;

                match read_message(&mut socket, &crypto)
                    .await
                    .map_err(|e| anyhow::anyhow!("Handshake read: {}", e))?
                {
                    NetworkMessage::HandshakeAck { success } => {
                        if !success {
                            return Err(anyhow::anyhow!("Authentication failed"));
                        }
                    }
                    _ => return Err(anyhow::anyhow!("Invalid handshake response")),
                }

                println!("Connected!");
                *conn_state.lock().unwrap() = "connected".to_string();

                let (mut reader, mut writer) = socket.into_split();
                let crypto_read = Arc::new(crypto);
                let crypto_write = crypto_read.clone();

                // Reader Task
                let image_store_clone = image_store.clone();
                let ctx_clone = ctx.clone();
                let read_handle: tokio::task::JoinHandle<anyhow::Result<()>> =
                    tokio::spawn(async move {
                        let mut decoder = Decoder::new()?;
                        loop {
                            match read_message_raw(&mut reader, &crypto_read).await {
                                Ok(NetworkMessage::VideoFrame { data, keyframe: _ }) => {
                                    // Decode H264
                                    if let Ok(Some(yuv)) = decoder.decode(&data) {
                                        let (width, height) = yuv.dimensions();
                                        let mut rgb_data = vec![0u8; width * height * 3]; // RGB8
                                        yuv.write_rgb8(&mut rgb_data);

                                        // Convert RGB8 to ColorImage (which expects RGBA or RGB?)
                                        // egui ColorImage expects [u8] pixels. from_rgb expects 3 bytes per pixel.

                                        let size = [width, height];
                                        let color_image = ColorImage::from_rgb(size, &rgb_data);
                                        *image_store_clone.lock().unwrap() = Some(color_image);
                                        ctx_clone.request_repaint();
                                    }
                                }
                                Ok(_) => {}
                                Err(e) => return Err(anyhow::anyhow!("Read error: {}", e)),
                            }
                        }
                    });

                // Writer Task
                let write_handle: tokio::task::JoinHandle<anyhow::Result<()>> =
                    tokio::spawn(async move {
                        while let Some(event) = rx_input.recv().await {
                            let msg = NetworkMessage::Input(event);
                            if let Err(e) = send_message_raw(&mut writer, &crypto_write, &msg).await
                            {
                                return Err(anyhow::anyhow!("Send error: {}", e));
                            }
                        }
                        Ok(())
                    });

                let _ = tokio::try_join!(read_handle, write_handle);
                Ok::<(), anyhow::Error>(())
            }
            .await;

            if let Err(e) = result {
                eprintln!("Connection error: {}", e);
                *conn_state.lock().unwrap() = format!("error: {}", e);
            } else {
                *conn_state.lock().unwrap() = "disconnected".to_string();
            }
            // Pequeno delay para o usuário ver a mensagem de erro antes de voltar
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            *conn_state.lock().unwrap() = "disconnected".to_string();
        });
    }
}

impl eframe::App for ViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let current_state = self.connection_state.lock().unwrap().clone();
        let is_connected = current_state == "connecting" || current_state == "connected";

        if current_state == "disconnected" || current_state.starts_with("error:") {
            // Limpar texture e input sender quando desconectar
            if self.texture.is_some() || self.tx_input.is_some() {
                self.texture = None;
                self.tx_input = None;
                *self.latest_image.lock().unwrap() = None;
                self.held_buttons.clear();
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if !is_connected {
                if current_state.starts_with("error:") {
                    ui.colored_label(egui::Color32::RED, &current_state);
                    ui.add_space(5.0);
                } else if current_state == "connecting" {
                    ui.colored_label(egui::Color32::YELLOW, "Connecting...");
                    ui.add_space(5.0);
                }

                ui.heading("Available Hosts");
                ui.label(format!("Status: {}", self.discovery.get_status()));
                
                let hosts = self.discovery.get_hosts();
                
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Hostname").strong());
                        ui.add_space(20.0);
                        ui.label(egui::RichText::new("Status").strong());
                        ui.add_space(20.0);
                        ui.label(egui::RichText::new("Action").strong());
                    });
                    ui.separator();

                    for host in hosts {
                        ui.horizontal(|ui| {
                            ui.label(&host.hostname);
                            ui.add_space(20.0);
                            
                            let color = if host.status == "online" { egui::Color32::GREEN } else { egui::Color32::RED };
                            ui.colored_label(color, &host.status);
                            ui.add_space(20.0);

                            if host.status == "online" {
                                if ui.button("Connect").clicked() {
                                    let host_id = host.host_id.clone();
                                    self.status = format!("Requesting connection to {}...", host.hostname);
                                    
                                    let (tx, rx) = std::sync::mpsc::channel();
                                    self.conn_req_rx = Some(rx);
                                    
                                    tokio::spawn(async move {
                                        // Start listener for reverse connection
                                        let (listener, viewer_port) = match TcpListener::bind("0.0.0.0:0").await {
                                            Ok(l) => {
                                                if let Ok(addr) = l.local_addr() {
                                                    (Some(l), Some(addr.port()))
                                                } else {
                                                    (None, None)
                                                }
                                            },
                                            Err(_) => (None, None)
                                        };

                                        let viewer_ip = get_local_ip();

                                        let client = DiscoveryClient::new();
                                        match client.request_connection(host_id, viewer_ip, viewer_port).await {
                                            Ok((ip, port)) => {
                                                let _ = tx.send((ip, port, listener));
                                            }
                                            Err(e) => {
                                                eprintln!("Connection request failed: {}", e);
                                            }
                                        }
                                    });
                                }
                            }
                        });
                    }
                });

                // Check for connection response
                if let Some(rx) = &self.conn_req_rx {
                    if let Ok((ip, port, listener)) = rx.try_recv() {
                        self.host_ip = format!("{}:{}", ip, port);
                        self.conn_req_rx = None; // Clear receiver
                        self.connect(ctx.clone(), listener);
                    }
                }
                 
             } else {
                // Update texture if new image available
                if let Ok(mut guard) = self.latest_image.try_lock() {
                    if let Some(img) = guard.take() {
                        self.texture =
                            Some(ctx.load_texture("screen", img, egui::TextureOptions::LINEAR));
                    }
                }

                if let Some(texture) = &self.texture {
                    // Show image and capture input
                    // We need to scale the image to fit the window while maintaining aspect ratio
                    let available_size = ui.available_size();
                    let texture_size = texture.size_vec2();
                    
                    let scale_x = available_size.x / texture_size.x;
                    let scale_y = available_size.y / texture_size.y;
                    let scale = scale_x.min(scale_y); // Fit within window
                    
                    let final_size = texture_size * scale;
                    
                    // Center the image
                    let x_offset = (available_size.x - final_size.x) / 2.0;
                    let y_offset = (available_size.y - final_size.y) / 2.0;
                    
                    // Centering hack:
                    ui.vertical(|ui| {
                        ui.add_space(y_offset);
                        ui.horizontal(|ui| {
                            ui.add_space(x_offset);
                            let response = ui.add(egui::Image::new(texture).fit_to_exact_size(final_size));
                            
                            // Input Handling
                            if let Some(tx) = &self.tx_input {
                                // Mouse Movement
                                if response.hovered() || !self.held_buttons.is_empty() {
                                    if let Some(pos) = ui.input(|i| i.pointer.interact_pos()) {
                                        // Calculate relative position within the image rect
                                        let relative_x = pos.x - response.rect.min.x;
                                        let relative_y = pos.y - response.rect.min.y;
                                        
                                        // Scale back to original texture coordinates
                                        let final_x = (relative_x / scale) as i32;
                                        let final_y = (relative_y / scale) as i32;
        
                                        let _ = tx.try_send(InputEvent::MouseMove {
                                            x: final_x,
                                            y: final_y,
                                        });
                                    }
                                }
        
                                // Mouse Buttons (Drag Support)
                                let pointer_state = ui.input(|i| i.pointer.clone());
        
                                let mut check_button =
                                    |egui_btn: egui::PointerButton, remote_btn: MouseButton| {
                                        if pointer_state.button_down(egui_btn) {
                                            if !self.held_buttons.contains(&remote_btn) {
                                                // Only start click if we are hovering the image
                                                if response.hovered() {
                                                    let _ = tx.try_send(InputEvent::MouseDown {
                                                        button: remote_btn.clone(),
                                                    });
                                                    self.held_buttons.insert(remote_btn);
                                                }
                                            }
                                        } else {
                                            if self.held_buttons.contains(&remote_btn) {
                                                let _ = tx.try_send(InputEvent::MouseUp {
                                                    button: remote_btn.clone(),
                                                });
                                                self.held_buttons.remove(&remote_btn);
                                            }
                                        }
                                    };
        
                                check_button(egui::PointerButton::Primary, MouseButton::Left);
                                check_button(egui::PointerButton::Secondary, MouseButton::Right);
                                check_button(egui::PointerButton::Middle, MouseButton::Middle);
                            }
                        });
                    });

                        // Keyboard (Advanced)
                        // Process raw key events
                        if let Some(tx) = &self.tx_input {
                        for event in &ui.input(|i| i.events.clone()) {
                            match event {
                                egui::Event::Key {
                                    key,
                                    pressed,
                                    repeat,
                                    ..
                                } => {
                                    if *repeat {
                                        continue;
                                    } // Ignore repeats for now or handle them
                                    if let Some(remote_key) = map_egui_key(*key) {
                                        let input_event = if *pressed {
                                            InputEvent::KeyDown { key: remote_key }
                                        } else {
                                            InputEvent::KeyUp { key: remote_key }
                                        };
                                        let _ = tx.try_send(input_event);
                                    }
                                }
                                egui::Event::Text(_text) => {
                                    // Handle text input if needed
                                }
                                _ => {}
                            }
                        }
                        }
                } else {
                    ui.label("Waiting for video...");
                }
            }
        });
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

fn map_egui_key(key: egui::Key) -> Option<RemoteKey> {
    match key {
        egui::Key::ArrowDown => Some(RemoteKey::Down),
        egui::Key::ArrowLeft => Some(RemoteKey::Left),
        egui::Key::ArrowRight => Some(RemoteKey::Right),
        egui::Key::ArrowUp => Some(RemoteKey::Up),
        egui::Key::Escape => Some(RemoteKey::Escape),
        egui::Key::Tab => Some(RemoteKey::Tab),
        egui::Key::Backspace => Some(RemoteKey::Backspace),
        egui::Key::Enter => Some(RemoteKey::Enter),
        egui::Key::Space => Some(RemoteKey::Space),
        egui::Key::Delete => Some(RemoteKey::Delete),
        egui::Key::Home => Some(RemoteKey::Home),
        egui::Key::End => Some(RemoteKey::End),
        egui::Key::PageUp => Some(RemoteKey::PageUp),
        egui::Key::PageDown => Some(RemoteKey::PageDown),
        egui::Key::Q => Some(RemoteKey::Char('q')),
        egui::Key::A => Some(RemoteKey::Char('a')),
        egui::Key::B => Some(RemoteKey::Char('b')),
        egui::Key::C => Some(RemoteKey::Char('c')),
        egui::Key::D => Some(RemoteKey::Char('d')),
        egui::Key::E => Some(RemoteKey::Char('e')),
        egui::Key::F => Some(RemoteKey::Char('f')),
        egui::Key::G => Some(RemoteKey::Char('g')),
        egui::Key::H => Some(RemoteKey::Char('h')),
        egui::Key::I => Some(RemoteKey::Char('i')),
        egui::Key::J => Some(RemoteKey::Char('j')),
        egui::Key::K => Some(RemoteKey::Char('k')),
        egui::Key::L => Some(RemoteKey::Char('l')),
        egui::Key::M => Some(RemoteKey::Char('m')),
        egui::Key::N => Some(RemoteKey::Char('n')),
        egui::Key::O => Some(RemoteKey::Char('o')),
        egui::Key::P => Some(RemoteKey::Char('p')),
        egui::Key::R => Some(RemoteKey::Char('r')),
        egui::Key::S => Some(RemoteKey::Char('s')),
        egui::Key::T => Some(RemoteKey::Char('t')),
        egui::Key::U => Some(RemoteKey::Char('u')),
        egui::Key::V => Some(RemoteKey::Char('v')),
        egui::Key::W => Some(RemoteKey::Char('w')),
        egui::Key::X => Some(RemoteKey::Char('x')),
        egui::Key::Y => Some(RemoteKey::Char('y')),
        egui::Key::Z => Some(RemoteKey::Char('z')),
        egui::Key::Num0 => Some(RemoteKey::Char('0')),
        egui::Key::Num1 => Some(RemoteKey::Char('1')),
        egui::Key::Num2 => Some(RemoteKey::Char('2')),
        egui::Key::Num3 => Some(RemoteKey::Char('3')),
        egui::Key::Num4 => Some(RemoteKey::Char('4')),
        egui::Key::Num5 => Some(RemoteKey::Char('5')),
        egui::Key::Num6 => Some(RemoteKey::Char('6')),
        egui::Key::Num7 => Some(RemoteKey::Char('7')),
        egui::Key::Num8 => Some(RemoteKey::Char('8')),
        egui::Key::Num9 => Some(RemoteKey::Char('9')),
        egui::Key::F1 => Some(RemoteKey::F1),
        egui::Key::F2 => Some(RemoteKey::F2),
        egui::Key::F3 => Some(RemoteKey::F3),
        egui::Key::F4 => Some(RemoteKey::F4),
        egui::Key::F5 => Some(RemoteKey::F5),
        egui::Key::F6 => Some(RemoteKey::F6),
        egui::Key::F7 => Some(RemoteKey::F7),
        egui::Key::F8 => Some(RemoteKey::F8),
        egui::Key::F9 => Some(RemoteKey::F9),
        egui::Key::F10 => Some(RemoteKey::F10),
        egui::Key::F11 => Some(RemoteKey::F11),
        egui::Key::F12 => Some(RemoteKey::F12),
        _ => None,
    }
}

async fn send_message(
    socket: &mut TcpStream,
    crypto: &Crypto,
    msg: &NetworkMessage,
) -> anyhow::Result<()> {
    let data = bincode::serialize(msg)?;
    let encrypted = crypto.encrypt(&data)?;
    let len = encrypted.len() as u32;
    socket.write_all(&len.to_be_bytes()).await?;
    socket.write_all(&encrypted).await?;
    Ok(())
}

async fn send_message_raw(
    socket: &mut tokio::net::tcp::OwnedWriteHalf,
    crypto: &Crypto,
    msg: &NetworkMessage,
) -> anyhow::Result<()> {
    let data = bincode::serialize(msg)?;
    let encrypted = crypto.encrypt(&data)?;
    let len = encrypted.len() as u32;
    socket.write_all(&len.to_be_bytes()).await?;
    socket.write_all(&encrypted).await?;
    Ok(())
}

async fn read_message(socket: &mut TcpStream, crypto: &Crypto) -> anyhow::Result<NetworkMessage> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await?;

    let decrypted = crypto.decrypt(&buf)?;
    let msg = bincode::deserialize(&decrypted)?;
    Ok(msg)
}

async fn read_message_raw(
    socket: &mut tokio::net::tcp::OwnedReadHalf,
    crypto: &Crypto,
) -> anyhow::Result<NetworkMessage> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await?;

    let decrypted = crypto.decrypt(&buf)?;
    let msg = bincode::deserialize(&decrypted)?;
    Ok(msg)
}
