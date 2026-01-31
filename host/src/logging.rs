use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static LOG_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

pub fn log_path() -> PathBuf {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    program_data.join("SysRemote").join("host.log")
}

pub fn init_log() {
    if LOG_FILE.get().is_some() {
        return;
    }
    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    
    // Try to open file, but don't crash if fails (e.g. permission denied)
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path) 
    {
        let _ = LOG_FILE.set(Mutex::new(file));
    }
}

fn log_write(level: &str, msg: &str) {
    init_log();
    let line = format!(
        "[{}] {} {}\r\n",
        level,
        chrono_like_timestamp(),
        msg.replace('\n', " ")
    );
    
    // Always print to stdout/stderr as well
    if level == "ERROR" {
        eprint!("{}", line);
    } else {
        print!("{}", line);
    }

    if let Some(lock) = LOG_FILE.get() {
        if let Ok(mut f) = lock.lock() {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }
}

pub fn log_info(msg: &str) {
    log_write("INFO", msg);
}

pub fn log_error(msg: &str) {
    log_write("ERROR", msg);
}

fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", now)
}
