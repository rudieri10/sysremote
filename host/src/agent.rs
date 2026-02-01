use anyhow::Result;
use enigo::{Enigo, Key, Keyboard, Mouse, Settings, Coordinate, Direction, Axis, Button};
use screenshots::Screen;
use shared::{InputEvent, IpcMessage, IPC_PIPE_NAME, IPC_SHMEM_NAME, IPC_SHMEM_SIZE, RemoteKey, MouseButton};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;
use xcap::Monitor;
use crate::logging::{log_error, log_info};
use std::time::Instant;

pub async fn run_agent() -> Result<()> {
    log_info(&format!(
        "Agent starting: pid={} pipe={} shmem={} shmem_size={}",
        std::process::id(),
        IPC_PIPE_NAME,
        IPC_SHMEM_NAME,
        IPC_SHMEM_SIZE
    ));
    // Retry connection loop
    let mut last_pipe_log = Instant::now();
    let mut client = loop {
        match ClientOptions::new().open(IPC_PIPE_NAME) {
            Ok(c) => break c,
            Err(_) => {
                if last_pipe_log.elapsed() >= Duration::from_secs(5) {
                    log_info("Waiting for IPC pipe...");
                    last_pipe_log = Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    log_info("Agent connected to IPC pipe.");

    // Open Shared Memory
    // Retry loop for ShMem as Service might take a moment to create it
    let mut last_shmem_log = Instant::now();
    let shmem = loop {
        match crate::shmem_utils::Shmem::open(IPC_SHMEM_NAME, IPC_SHMEM_SIZE) {
            Ok(m) => break m,
            Err(e) => {
                if last_shmem_log.elapsed() >= Duration::from_secs(5) {
                    log_error(&format!("Waiting for Shared Memory: {}", e));
                    last_shmem_log = Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };
    log_info("Agent connected to Shared Memory.");
    
    // Unsafe pointer to shared memory
    let shmem_ptr = shmem.as_ptr();

    // Setup Capture
    let mut enigo = Enigo::new(&Settings::default()).unwrap();
    let mut monitor: Option<Monitor> = None;
    let mut screen: Option<Screen> = None;
    let mut width = 0;
    let mut height = 0;
    let mut use_fallback = false;
    let mut dxgi_error_count = 0;
    let mut capture_error_count = 0u32;
    const MAX_DXGI_ERRORS: u32 = 10;
    
    // Initialize COM
    unsafe {
        let _ = winapi::um::objbase::CoInitialize(std::ptr::null_mut());
    }

    // Buffer for IPC reading
    let mut buf = vec![0u8; 4096];

    loop {
        // Read length (4 bytes)
        match client.read_u32().await {
            Ok(len) => {
                if len as usize > buf.len() {
                    buf.resize(len as usize, 0);
                }
                match client.read_exact(&mut buf[..len as usize]).await {
                    Ok(_) => {
                        let msg: IpcMessage = serde_json::from_slice(&buf[..len as usize])?;
                        match msg {
                            IpcMessage::CaptureRequest => {
                                // Monitor/Screen Discovery
                                if !use_fallback && monitor.is_none() {
                                    match Monitor::all() {
                                        Ok(monitors) => {
                                            if let Some(m) = monitors.into_iter().next() {
                                                width = m.width().unwrap_or(1920) as usize;
                                                height = m.height().unwrap_or(1080) as usize;
                                                monitor = Some(m);
                                                log_info(&format!("DXGI monitor selected: {}x{}", width, height));
                                            } else {
                                                dxgi_error_count += 1;
                                            }
                                        }
                                        Err(_) => {
                                            dxgi_error_count += 1;
                                            if dxgi_error_count > MAX_DXGI_ERRORS {
                                                use_fallback = true;
                                            }
                                        }
                                    }
                                }

                                if use_fallback && screen.is_none() {
                                    match Screen::all() {
                                        Ok(screens) => {
                                            if let Some(s) = screens.into_iter().next() {
                                                width = s.display_info.width as usize;
                                                height = s.display_info.height as usize;
                                                screen = Some(s);
                                                log_info(&format!("Fallback screen selected: {}x{}", width, height));
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                }

                                // Capture
                                let capture_result = if use_fallback {
                                    if let Some(ref s) = screen {
                                        s.capture().map(|img| (img.width(), img.height(), img.into_raw())).map_err(|e| anyhow::anyhow!(e))
                                    } else {
                                        Err(anyhow::anyhow!("No screen"))
                                    }
                                } else {
                                    if let Some(ref m) = monitor {
                                        m.capture_image().map(|img| (img.width(), img.height(), img.into_raw())).map_err(|e| anyhow::anyhow!(e))
                                    } else {
                                        Err(anyhow::anyhow!("No monitor"))
                                    }
                                };

                                match capture_result {
                                    Ok((w, h, pixels)) => {
                                        capture_error_count = 0;
                                        // Update width/height if changed
                                        if w as usize != width || h as usize != height {
                                            width = w as usize;
                                            height = h as usize;
                                            log_info(&format!("Capture size updated: {}x{}", width, height));
                                        }

                                        // Send raw pixels via ShMem
                                        let size = pixels.len();
                                        if size <= IPC_SHMEM_SIZE {
                                            unsafe {
                                                let src = pixels.as_ptr();
                                                let dst = shmem_ptr;
                                                std::ptr::copy_nonoverlapping(src, dst, size);
                                            }
                                            
                                            let response = IpcMessage::FrameReady {
                                                size,
                                                width: w,
                                                height: h,
                                                keyframe: false,
                                            };
                                            let resp_bytes = serde_json::to_vec(&response)?;
                                            client.write_u32(resp_bytes.len() as u32).await?;
                                            client.write_all(&resp_bytes).await?;
                                        }
                                    }
                                    Err(_) => {
                                        capture_error_count += 1;
                                        if capture_error_count % 30 == 0 {
                                            log_error(&format!("Capture error (count={})", capture_error_count));
                                        }
                                        if !use_fallback {
                                             dxgi_error_count += 1;
                                            if dxgi_error_count > MAX_DXGI_ERRORS {
                                                use_fallback = true;
                                                log_error("DXGI capture failed repeatedly, switching to fallback");
                                            }
                                        }
                                    }
                                }
                            }
                            IpcMessage::Input(event) => {
                                match event {
                                    InputEvent::MouseMove { x, y } => {
                                        let _ = enigo.move_mouse(x, y, Coordinate::Abs);
                                    }
                                    InputEvent::MouseDown { button } => {
                                        let b = match button {
                                            MouseButton::Left => Button::Left,
                                            MouseButton::Right => Button::Right,
                                            MouseButton::Middle => Button::Middle,
                                            _ => Button::Left,
                                        };
                                        let _ = enigo.button(b, Direction::Press);
                                    }
                                    InputEvent::MouseUp { button } => {
                                        let b = match button {
                                            MouseButton::Left => Button::Left,
                                            MouseButton::Right => Button::Right,
                                            MouseButton::Middle => Button::Middle,
                                            _ => Button::Left,
                                        };
                                        let _ = enigo.button(b, Direction::Release);
                                    }
                                    InputEvent::KeyDown { key } => {
                                        let _ = enigo.key(convert_key(key), Direction::Press);
                                    }
                                    InputEvent::KeyUp { key } => {
                                        let _ = enigo.key(convert_key(key), Direction::Release);
                                    }
                                    InputEvent::Scroll { delta_x: _, delta_y } => {
                                        let _ = enigo.scroll(delta_y, Axis::Vertical);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
            Err(_) => break, // Connection closed
        }
    }
    Ok(())
}

fn convert_key(k: RemoteKey) -> Key {
    match k {
        RemoteKey::Char(c) => Key::Unicode(c),
        RemoteKey::Space => Key::Space,
        RemoteKey::Enter => Key::Return,
        RemoteKey::Backspace => Key::Backspace,
        RemoteKey::Tab => Key::Tab,
        RemoteKey::Escape => Key::Escape,
        RemoteKey::Shift => Key::Shift,
        RemoteKey::Control => Key::Control,
        RemoteKey::Alt => Key::Alt,
        RemoteKey::Delete => Key::Delete,
        RemoteKey::Home => Key::Home,
        RemoteKey::End => Key::End,
        RemoteKey::PageUp => Key::PageUp,
        RemoteKey::PageDown => Key::PageDown,
        RemoteKey::Up => Key::UpArrow,
        RemoteKey::Down => Key::DownArrow,
        RemoteKey::Left => Key::LeftArrow,
        RemoteKey::Right => Key::RightArrow,
        RemoteKey::F1 => Key::F1,
        RemoteKey::F2 => Key::F2,
        RemoteKey::F3 => Key::F3,
        RemoteKey::F4 => Key::F4,
        RemoteKey::F5 => Key::F5,
        RemoteKey::F6 => Key::F6,
        RemoteKey::F7 => Key::F7,
        RemoteKey::F8 => Key::F8,
        RemoteKey::F9 => Key::F9,
        RemoteKey::F10 => Key::F10,
        RemoteKey::F11 => Key::F11,
        RemoteKey::F12 => Key::F12,
        RemoteKey::Windows => Key::Meta,
    }
}
