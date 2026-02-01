use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_PORT: u16 = 5599;

pub const DISCOVERY_HOST: &str = "192.168.1.238";
pub const DISCOVERY_PORT: u16 = 5600;
pub const DISCOVERY_WS_URL: &str = "ws://192.168.1.238:5600";


// --- Discovery Protocol Structs ---

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum DiscoveryMessage {
    #[serde(rename = "register_host")]
    RegisterHost {
        host_id: String,
        hostname: String,
        ip: String,
        user: String,
        os: String,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat {
        host_id: String,
    },
    #[serde(rename = "list_hosts")]
    ListHosts {
        #[serde(skip_serializing_if = "Option::is_none")]
        viewer_id: Option<String>,
    },
    #[serde(rename = "host_list")]
    HostList {
        hosts: Vec<HostInfo>,
    },
    #[serde(rename = "connect_request")]
    ConnectRequest {
        viewer_id: String,
        host_id: String,
    },
    #[serde(rename = "connect_response")]
    ConnectResponse {
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        host_ip: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host_port: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostInfo {
    pub host_id: String,
    pub hostname: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

// --- End Discovery Protocol Structs ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    Handshake { psk: String },
    HandshakeAck { success: bool },
    VideoFrame { data: Vec<u8>, keyframe: bool },
    Input(InputEvent),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum InputEvent {
    MouseMove { x: i32, y: i32 },
    MouseDown { button: MouseButton },
    MouseUp { button: MouseButton },
    KeyDown { key: RemoteKey },
    KeyUp { key: RemoteKey },
    Scroll { delta_x: i32, delta_y: i32 },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RemoteKey {
    Char(char),
    Space,
    Enter,
    Backspace,
    Tab,
    Escape,
    Shift,
    Control,
    Alt,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    Up,
    Down,
    Left,
    Right,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    Windows,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Other(u8),
}

// --- IPC Protocol Structs ---

pub const IPC_PIPE_NAME: &str = r"\\.\pipe\SysRemotePipe";
pub const IPC_SHMEM_NAME: &str = "Global\\SysRemoteShm";
// Buffer size: Enough for 4K RGBA (3840*2160*4 = ~33MB). 
// Let's allocate 64MB to be safe and allow double buffering if needed.
pub const IPC_SHMEM_SIZE: usize = 64 * 1024 * 1024; 

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum IpcMessage {
    CaptureRequest,
    FrameReady {
        size: usize,
        width: u32,
        height: u32,
        keyframe: bool,
    },
    Input(InputEvent),
    Pong,
}

// --- End IPC Protocol Structs ---

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed")]
    Encryption,
    #[error("Decryption failed")]
    Decryption,
}

pub struct Crypto {
    cipher: ChaCha20Poly1305,
}

impl Crypto {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        Self { cipher }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|_| CryptoError::Encryption)?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 12 {
            return Err(CryptoError::Decryption);
        }

        let nonce = Nonce::from_slice(&data[0..12]);
        let ciphertext = &data[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::Decryption)
    }
}
