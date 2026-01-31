# Regras de Build do Instalador - SysRemote

O instalador oficial do projeto é **UNIFICADO**, contendo tanto o **Host** (Serviço) quanto o **Viewer** (Cliente) em um único executável.

## Script de Origem
O arquivo de configuração do Inno Setup é:
`installers\SysRemoteUnified.iss`

## Saída (Output)
O executável gerado deve ser salvo obrigatoriamente em:
`installers\Output\SysRemote_Setup.exe`

## Conteúdo do Instalador
O instalador permite selecionar o tipo de instalação:
1. **Full (Padrão)**: Instala Host e Viewer.
2. **Host Only**: Apenas o serviço.
3. **Viewer Only**: Apenas o cliente.
4. **Custom**: Seleção manual.

## Como Gerar (Build)
1. Compile os binários Rust em modo Release:
   ```cmd
   cd ..
   cargo build --release --bin host
   cargo build --release --bin viewer
   cd installers
   ```
2. Compile o script ISS usando o Inno Setup Compiler (ISCC):
   ```cmd
   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" SysRemoteUnified.iss
   ```

**Nota:** Não utilize os scripts antigos (`host.iss`, `viewer.iss`) para distribuição final. Use sempre o `SysRemoteUnified.iss`.
