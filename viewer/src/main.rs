use eframe::egui;
use eframe::egui::{ColorImage, TextureHandle};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use shared::{Crypto, InputEvent, MouseButton, NetworkMessage, RemoteKey};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    is_connected: bool,
    held_buttons: std::collections::HashSet<MouseButton>,
}

impl ViewerApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            host_ip: "127.0.0.1:5599".to_owned(),
            status: "Disconnected".to_owned(),
            texture: None,
            latest_image: Arc::new(Mutex::new(None)),
            tx_input: None,
            is_connected: false,
            held_buttons: std::collections::HashSet::new(),
        }
    }

    fn connect(&mut self, ctx: egui::Context) {
        let ip = self.host_ip.clone();
        let image_store = self.latest_image.clone();

        // We create a channel, but to support reconnects we should really keep the sender in the App struct
        // and just create a new receiver for each connection if possible?
        // No, receiver must be created with sender.
        // For simplicity in this quick fix: We recreate the channel.
        let (tx_input, mut rx_input) = tokio::sync::mpsc::channel::<InputEvent>(100);
        self.tx_input = Some(tx_input);

        self.status = "Connecting...".to_owned();
        self.is_connected = true;

        tokio::spawn(async move {
            println!("Connecting to {}...", ip);
            let result = async {
                let mut socket = TcpStream::connect(&ip).await?;
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
            }
            // On exit, set status to disconnected?
            // We can't easily update `self.is_connected` from here because `self` is not available.
            // But the UI will show "Connecting..." or stale image.
            // We should probably send a message back to UI thread or use Arc<Mutex<State>>.
        });
    }
}

impl eframe::App for ViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if !self.is_connected {
                ui.horizontal(|ui| {
                    ui.label("Host IP:");
                    ui.text_edit_singleline(&mut self.host_ip);
                    if ui.button("Connect").clicked() {
                        self.connect(ctx.clone());
                    }
                });
                ui.label(&self.status);
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
                    let response = ui.add(egui::Image::new(texture));

                    // Input Handling
                    if let Some(tx) = &self.tx_input {
                        // Mouse Movement
                        if response.hovered() || !self.held_buttons.is_empty() {
                            if let Some(pos) = ui.input(|i| i.pointer.interact_pos()) {
                                let relative_x = pos.x - response.rect.min.x;
                                let relative_y = pos.y - response.rect.min.y;

                                let texture_size = texture.size();
                                let scale_x = texture_size[0] as f32 / response.rect.width();
                                let scale_y = texture_size[1] as f32 / response.rect.height();

                                let final_x = (relative_x * scale_x) as i32;
                                let final_y = (relative_y * scale_y) as i32;

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

                        // Keyboard (Advanced)
                        // Process raw key events
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
