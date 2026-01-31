# SysRemote (Rust)

Sistema de acesso remoto escrito em Rust, focado em performance e segurança.

## Arquitetura

O projeto é dividido em 3 crates:
- `host`: O servidor que roda na máquina a ser controlada. Captura a tela e recebe inputs.
- `viewer`: O cliente que visualiza a tela remota e envia inputs.
- `shared`: Biblioteca compartilhada com definições de protocolo e criptografia.

## Funcionalidades Implementadas

- **Protocolo Personalizado**: TCP com criptografia ChaCha20Poly1305.
- **Captura de Tela**: Usa `xcap` (baseado em DXGI no Windows) para alta performance.
- **Codec de Vídeo**: Substituição de JPEG por **H.264** (via OpenH264) para streaming em tempo real com baixa latência e banda.
- **Input Remoto**: Mouse e Teclado (via `enigo`).
- **Recuperação de Erros**: Tratamento de bloqueio de tela (UAC/Lock Screen) e mudanças de resolução.

## Requisitos

- **Windows 10/11** (para captura DXGI).
- **OpenH264 DLL**: O binário `openh264-*.dll` deve estar presente no diretório do executável (host e viewer). O crate `openh264` tenta baixar automaticamente, mas para distribuição, inclua a DLL.

## Como Compilar e Executar

1. **Compilar (Release)**:
   ```powershell
   cargo build --release --workspace
   ```

2. **Executar Host**:
   ```powershell
   ./target/release/host.exe
   ```
   *Nota: Execute como Administrador para permitir input em janelas elevadas.*

3. **Executar Viewer**:
   ```powershell
   ./target/release/viewer.exe
   ```
   *Nota: O viewer conecta automaticamente em localhost (para testes).*

## Notas de Segurança

- A chave de criptografia (PSK) está hardcoded como "mysecretpassword" para este MVP. Em produção, deve ser trocada ou negociada.
- O handshake valida a PSK antes de permitir controle.
