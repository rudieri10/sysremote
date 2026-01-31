use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_PORT: u16 = 5599;

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
