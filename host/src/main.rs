#![windows_subsystem = "windows"]

use anyhow::Result;
use openh264::encoder::Encoder;
use openh264::formats::YUVBuffer;
use shared::{Crypto, NetworkMessage, DEFAULT_PORT};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};

mod discovery;
mod logging;
mod gui;
mod agent;
mod shmem_utils;

use logging::{init_log, log_error, log_info, log_path};
use std::time::{Duration, Instant};
use std::io::Read;
use std::os::windows::io::FromRawHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::windows::named_pipe::{ServerOptions, NamedPipeServer};
use shared::{IpcMessage, IPC_PIPE_NAME, IPC_SHMEM_NAME, IPC_SHMEM_SIZE};

use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType, SessionChangeReason,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

define_windows_service!(ffi_service_main, my_service_main);

static STOP_SERVICE: AtomicBool = AtomicBool::new(false);
static SESSION_CHANGED: AtomicBool = AtomicBool::new(false);
static AGENT_PROCESS_PID: OnceLock<Mutex<Option<u32>>> = OnceLock::new();

fn my_service_main(arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service(arguments) {
        log_error(&format!("Service error: {}", e));
    }
}

fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                STOP_SERVICE.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::SessionChange(change) => {
                log_info(&format!("Session Change detected: {:?} (Session ID: {:?})", change.reason, change.notification.session_id));
                match change.reason {
                    SessionChangeReason::ConsoleConnect
                    | SessionChangeReason::SessionLogon
                    | SessionChangeReason::RemoteConnect => {
                        SESSION_CHANGED.store(true, Ordering::SeqCst);
                    }
                    _ => {}
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register("SysRemoteHost", event_handler)?;

    init_log();
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
    let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "unknown".to_string());
    log_info(&format!(
        "Service init: exe={} pid={} user={}\\{} log={}",
        exe_path,
        std::process::id(),
        domain,
        username,
        log_path().display()
    ));
    let next_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SESSION_CHANGE,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    status_handle.set_service_status(next_status)?;

    // Create Runtime for Discovery
    let rt = tokio::runtime::Runtime::new().map_err(|e| anyhow::anyhow!("Failed to create runtime: {}", e))?;

    // Initialize IPC
    let (shmem, pipe) = match rt.block_on(async { init_ipc().await }) {
        Ok(res) => res,
        Err(e) => {
             log_error(&format!("Failed to initialize IPC: {}", e));
             return Err(e);
        }
    };

    // Blocking Discovery Registration (must happen before main loop)
    log_info("Attempting to connect to discovery server...");
    if let Err(e) = rt.block_on(discovery::ensure_initial_registration()) {
        log_error(&format!("Discovery registration failed: {}", e));
        // Exit service if registration fails
        return Err(anyhow::anyhow!(e));
    }
    log_info("Discovery registration successful.");

    // Start Discovery Service (Maintenance in background)
    let p1 = pipe.clone();
    let s1 = shmem.clone();
    rt.spawn(async move {
        discovery::start_discovery_service(p1, s1).await;
    });

    // Start Host Server
    let p2 = pipe.clone();
    let s2 = shmem.clone();
    rt.spawn(async move {
        if let Err(e) = run_server(p2, s2).await {
            log_error(&format!("Host server error: {}", e));
        }
    });

    log_info("Service started. Launching agent in active user session...");
    match spawn_agent_in_active_session() {
        Ok(pid) => {
            let _ = AGENT_PROCESS_PID.set(Mutex::new(Some(pid)));
            log_info(&format!("Agent started. pid={}", pid));
        }
        Err(e) => {
            log_error(&format!(
                "Failed to launch agent. Video capture will not work in Session 0. {}",
                e
            ));
        }
    }

    while !STOP_SERVICE.load(Ordering::SeqCst) {
        if let Some(lock) = AGENT_PROCESS_PID.get() {
            let mut guard = lock.lock().unwrap();

            // Check if session changed
            if SESSION_CHANGED.swap(false, Ordering::SeqCst) {
                if let Some(pid) = *guard {
                    log_info(&format!("Session changed. Killing old agent pid={}", pid));
                    kill_process(pid);
                    *guard = None;
                }
            }

            let needs_restart = match *guard {
                None => true,
                Some(pid) => !is_pid_running(pid),
            };

            if needs_restart {
                if let Some(pid) = *guard {
                    log_error(&format!("Agent pid {} is not running. Restarting...", pid));
                } else {
                    log_info("Agent not running. Starting...");
                }

                match spawn_agent_in_active_session() {
                    Ok(pid) => {
                        *guard = Some(pid);
                        log_info(&format!("Agent started. pid={}", pid));
                    }
                    Err(e) => {
                        log_error(&format!("Failed to start agent: {}", e));
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    if let Some(lock) = AGENT_PROCESS_PID.get() {
        if let Some(pid) = lock.lock().unwrap().take() {
            kill_process(pid);
        }
    }

    let stop_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(stop_status)?;

    Ok(())
}

fn is_elevated() -> bool {
    use std::ptr;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::OpenProcessToken;
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY};

    unsafe {
        let mut handle: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            TOKEN_QUERY,
            &mut handle,
        ) == 0
        {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let result = GetTokenInformation(
            handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );
        CloseHandle(handle);

        result != 0 && elevation.TokenIsElevated != 0
    }
}
const PSK: &str = "mysecretpassword"; // Hardcoded for simplicity as requested "senha fixa"
const KEY_BYTES: [u8; 32] = [0x42; 32]; // Fixed key for encryption for now (should derive from PSK in real app)

fn ensure_console() {
    unsafe {
        if winapi::um::wincon::GetConsoleWindow().is_null() {
            let _ = winapi::um::consoleapi::AllocConsole();
        }
    }
}

fn tail_logs_blocking() -> Result<()> {
    ensure_console();
    init_log();

    let path = log_path();
    println!("Log: {}", path.display());
    let mut file = std::fs::OpenOptions::new().read(true).open(&path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(64 * 1024);
    use std::io::Seek;
    use std::io::SeekFrom;
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    if !buf.is_empty() {
        print!("{}", String::from_utf8_lossy(&buf));
    }
    let mut pos = len;
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let new_len = std::fs::metadata(&path)?.len();
        if new_len > pos {
            let mut f = std::fs::OpenOptions::new().read(true).open(&path)?;
            f.seek(SeekFrom::Start(pos))?;
            let mut b = Vec::new();
            f.read_to_end(&mut b)?;
            if !b.is_empty() {
                print!("{}", String::from_utf8_lossy(&b));
            }
            pos = new_len;
        }
    }
}

fn kill_process(pid: u32) {
    unsafe {
        let proc = winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_TERMINATE,
            0,
            pid,
        );
        if !proc.is_null() {
            let _ = winapi::um::processthreadsapi::TerminateProcess(proc, 0);
            winapi::um::handleapi::CloseHandle(proc);
        }
    }
}

fn spawn_agent_in_active_session() -> Result<u32> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    unsafe {
        enable_privileges_for_create_process_as_user()?;

        let session_id = get_best_active_session_id()
            .unwrap_or_else(|| winapi::um::winbase::WTSGetActiveConsoleSessionId());
        if session_id == 0xFFFFFFFF {
            anyhow::bail!("No active console session found (WTSGetActiveConsoleSessionId returned -1)");
        }
        log_info(&format!(
            "Attempting to spawn agent in Session {} (local_system={})",
            session_id,
            is_running_as_local_system()
        ));

        let mut user_token: winapi::um::winnt::HANDLE = std::ptr::null_mut();
        let mut retry_count = 0;
        let max_retries = 5;

        if is_running_as_local_system() {
            while winapi::um::wtsapi32::WTSQueryUserToken(session_id, &mut user_token) == 0 {
                let err = winapi::um::errhandlingapi::GetLastError();
                retry_count += 1;
                log_error(&format!(
                    "WTSQueryUserToken failed for session {} (Attempt {}/{}): {}",
                    session_id, retry_count, max_retries, err
                ));

                if retry_count >= max_retries {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        if user_token.is_null() {
            log_info("Attempting Fallback: Duplicating token from a process in target session...");
            if let Some(token) = get_token_from_session_process(session_id) {
                user_token = token;
                log_info("Fallback Successful: Obtained token from process.");
            } else {
                anyhow::bail!("Failed to obtain a user token for session {}", session_id);
            }
        }

        let mut primary_token: winapi::um::winnt::HANDLE = std::ptr::null_mut();
        let ok = winapi::um::securitybaseapi::DuplicateTokenEx(
            user_token,
            winapi::um::winnt::TOKEN_ALL_ACCESS,
            std::ptr::null_mut(),
            winapi::um::winnt::SecurityImpersonation,
            winapi::um::winnt::TokenPrimary,
            &mut primary_token,
        );
        winapi::um::handleapi::CloseHandle(user_token);
        if ok == 0 {
            anyhow::bail!(
                "DuplicateTokenEx failed (err={})",
                winapi::um::errhandlingapi::GetLastError()
            );
        }

        let mut env: winapi::shared::minwindef::LPVOID = std::ptr::null_mut();
        let env_ok = winapi::um::userenv::CreateEnvironmentBlock(&mut env, primary_token, 0);
        if env_ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            log_error(&format!("CreateEnvironmentBlock failed (err={})", err));
        }

        let exe = std::env::current_exe()?;
        let exe_w: Vec<u16> = OsStr::new(exe.as_os_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let cmd = format!("\"{}\" --agent", exe.display());
        log_info(&format!("Agent command line: {}", cmd));
        let mut cmd_w: Vec<u16> = OsStr::new(&cmd)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut desktop = wide_string("winsta0\\default");
        let mut si: winapi::um::processthreadsapi::STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<winapi::um::processthreadsapi::STARTUPINFOW>() as u32;
        si.lpDesktop = desktop.as_mut_ptr();

        let mut pi: winapi::um::processthreadsapi::PROCESS_INFORMATION = std::mem::zeroed();

        let flags =
            winapi::um::winbase::CREATE_UNICODE_ENVIRONMENT | winapi::um::winbase::CREATE_NO_WINDOW;

        let created = winapi::um::processthreadsapi::CreateProcessAsUserW(
            primary_token,
            exe_w.as_ptr(),
            cmd_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            flags,
            if env_ok != 0 {
                env
            } else {
                std::ptr::null_mut()
            },
            std::ptr::null(),
            &mut si,
            &mut pi,
        );

        let created = if created == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            log_error(&format!("CreateProcessAsUserW failed (err={}). Trying CreateProcessWithTokenW...", err));

            let created2 = winapi::um::winbase::CreateProcessWithTokenW(
                primary_token,
                winapi::um::winbase::LOGON_WITH_PROFILE,
                exe_w.as_ptr(),
                cmd_w.as_mut_ptr(),
                flags,
                if env_ok != 0 {
                    env
                } else {
                    std::ptr::null_mut()
                },
                std::ptr::null(),
                &mut si,
                &mut pi,
            );
            if created2 == 0 {
                let err2 = winapi::um::errhandlingapi::GetLastError();
                anyhow::bail!("CreateProcessAsUserW err={} and CreateProcessWithTokenW failed (err={})", err, err2);
            }
            created2
        } else {
            created
        };

        if env_ok != 0 {
            let _ = winapi::um::userenv::DestroyEnvironmentBlock(env);
        }
        winapi::um::handleapi::CloseHandle(primary_token);

        if created == 0 {
            anyhow::bail!(
                "CreateProcessAsUserW failed (err={})",
                winapi::um::errhandlingapi::GetLastError()
            );
        }

        winapi::um::handleapi::CloseHandle(pi.hThread);
        winapi::um::handleapi::CloseHandle(pi.hProcess);
        log_info(&format!("Agent process created (pid={})", pi.dwProcessId));
        Ok(pi.dwProcessId)
    }
}

unsafe fn is_running_as_local_system() -> bool {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::{GetTokenInformation, IsWellKnownSid};
    use winapi::um::winnt::{TokenUser, TOKEN_QUERY, TOKEN_USER, WinLocalSystemSid};

    let mut token: winapi::um::winnt::HANDLE = std::ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
        return false;
    }

    let mut size: u32 = 0;
    let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
    if size == 0 {
        CloseHandle(token);
        return false;
    }

    let mut buf = vec![0u8; size as usize];
    let ok = GetTokenInformation(
        token,
        TokenUser,
        buf.as_mut_ptr() as *mut _,
        size,
        &mut size,
    );
    CloseHandle(token);
    if ok == 0 {
        return false;
    }

    let tu = buf.as_ptr() as *const TOKEN_USER;
    let sid = (*tu).User.Sid;
    IsWellKnownSid(sid as *mut _, WinLocalSystemSid) != 0
}

unsafe fn get_best_active_session_id() -> Option<u32> {
    use winapi::shared::minwindef::DWORD;
    use winapi::shared::ntdef::HANDLE;
    use winapi::shared::ntdef::PVOID;
    use winapi::shared::minwindef::BOOL;

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct WTS_SESSION_INFOW {
        session_id: DWORD,
        p_win_station_name: *mut u16,
        state: DWORD,
    }

    const WTS_CURRENT_SERVER_HANDLE: HANDLE = std::ptr::null_mut();
    const WTS_INFO_CLASS_WTSUSER_NAME: DWORD = 5;
    const WTS_CONNECTSTATE_WTSACTIVE: DWORD = 0;

    #[link(name = "Wtsapi32")]
    extern "system" {
        fn WTSEnumerateSessionsW(
            hServer: HANDLE,
            Reserved: DWORD,
            Version: DWORD,
            ppSessionInfo: *mut *mut WTS_SESSION_INFOW,
            pCount: *mut DWORD,
        ) -> BOOL;
        fn WTSQuerySessionInformationW(
            hServer: HANDLE,
            SessionId: DWORD,
            WTSInfoClass: DWORD,
            ppBuffer: *mut *mut u16,
            pBytesReturned: *mut DWORD,
        ) -> BOOL;
        fn WTSFreeMemory(pMemory: PVOID);
    }

    let mut sessions_ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: DWORD = 0;
    let ok = WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &mut sessions_ptr,
        &mut count,
    );
    if ok == 0 || sessions_ptr.is_null() || count == 0 {
        return None;
    }

    let mut best_active: Option<u32> = None;
    let mut best_with_user: Option<u32> = None;

    for i in 0..count as usize {
        let s = *sessions_ptr.add(i);
        if s.session_id == 0 {
            continue;
        }
        if s.state != WTS_CONNECTSTATE_WTSACTIVE {
            continue;
        }

        best_active = Some(s.session_id);

        let mut buf: *mut u16 = std::ptr::null_mut();
        let mut bytes: DWORD = 0;
        let ok_user = WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            s.session_id,
            WTS_INFO_CLASS_WTSUSER_NAME,
            &mut buf,
            &mut bytes,
        );
        if ok_user != 0 && !buf.is_null() && bytes >= 2 {
            let slice = std::slice::from_raw_parts(buf, (bytes as usize / 2).saturating_sub(1));
            let username = String::from_utf16_lossy(slice).trim().to_string();
            WTSFreeMemory(buf as PVOID);
            if !username.is_empty() {
                best_with_user = Some(s.session_id);
                break;
            }
        } else if !buf.is_null() {
            WTSFreeMemory(buf as PVOID);
        }
    }

    WTSFreeMemory(sessions_ptr as PVOID);

    best_with_user.or(best_active)
}

unsafe fn get_token_from_session_process(session_id: u32) -> Option<winapi::um::winnt::HANDLE> {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::processthreadsapi::OpenProcessToken;
    use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_DUPLICATE, TOKEN_QUERY};
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        return None;
    }
    
    let mut entry: PROCESSENTRY32W = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    
    if Process32FirstW(snapshot, &mut entry) == 0 {
        CloseHandle(snapshot);
        return None;
    }
    
    loop {
        let mut process_session: u32 = 0;
        if winapi::um::processthreadsapi::ProcessIdToSessionId(entry.th32ProcessID, &mut process_session) != 0 {
            if process_session == session_id {
                let name = String::from_utf16_lossy(&entry.szExeFile);
                let name = name.trim_matches('\0').to_lowercase();
                
                if name == "explorer.exe"
                    || name == "winlogon.exe"
                    || name == "userinit.exe"
                    || name == "dwm.exe"
                {
                    let mut process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
                    if process_handle.is_null() {
                        process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, entry.th32ProcessID);
                    }
                    if !process_handle.is_null() {
                        let mut token_handle: winapi::um::winnt::HANDLE = std::ptr::null_mut();
                        if OpenProcessToken(process_handle, TOKEN_DUPLICATE | TOKEN_QUERY, &mut token_handle) != 0 {
                            CloseHandle(process_handle);
                            CloseHandle(snapshot);
                            return Some(token_handle);
                        }
                        CloseHandle(process_handle);
                    }
                }
            }
        }
        
        if Process32NextW(snapshot, &mut entry) == 0 {
            break;
        }
    }
    
    CloseHandle(snapshot);
    None
}

unsafe fn enable_privileges_for_create_process_as_user() -> Result<()> {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::winbase::LookupPrivilegeValueW;
    use winapi::um::winnt::{
        TokenPrivileges, HANDLE, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    };

    let mut token: HANDLE = std::ptr::null_mut();
    let ok = OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut token,
    );
    if ok == 0 {
        anyhow::bail!(
            "OpenProcessToken failed (err={})",
            winapi::um::errhandlingapi::GetLastError()
        );
    }

    let result = (|| -> Result<()> {
        for name in [
            "SeIncreaseQuotaPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeTcbPrivilege",
            "SeDebugPrivilege",
        ] {
            let name_w = wide_string(name);
            let mut luid: winapi::um::winnt::LUID = std::mem::zeroed();
            let ok = LookupPrivilegeValueW(std::ptr::null(), name_w.as_ptr(), &mut luid);
            if ok == 0 {
                anyhow::bail!(
                    "LookupPrivilegeValueW({}) failed (err={})",
                    name,
                    winapi::um::errhandlingapi::GetLastError()
                );
            }

            let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
            tp.PrivilegeCount = 1;
            tp.Privileges[0] = LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            };

            let ok = winapi::um::securitybaseapi::AdjustTokenPrivileges(
                token,
                0,
                &mut tp,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if ok == 0 {
                anyhow::bail!(
                    "AdjustTokenPrivileges({}) failed (err={})",
                    name,
                    winapi::um::errhandlingapi::GetLastError()
                );
            }
        }
        Ok(())
    })();

    CloseHandle(token);
    result
}

fn is_pid_running(pid: u32) -> bool {
    unsafe {
        let proc = winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if proc.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = winapi::um::processthreadsapi::GetExitCodeProcess(proc, &mut code);
        winapi::um::handleapi::CloseHandle(proc);
        ok != 0 && code == winapi::um::minwinbase::STILL_ACTIVE
    }
}

fn query_service_state(name: &str) -> Option<u32> {
    unsafe {
        let scm = winapi::um::winsvc::OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            winapi::um::winsvc::SC_MANAGER_CONNECT,
        );
        if scm.is_null() {
            return None;
        }

        let name_w = wide_string(name);
        let svc = winapi::um::winsvc::OpenServiceW(
            scm,
            name_w.as_ptr(),
            winapi::um::winsvc::SERVICE_QUERY_STATUS,
        );
        if svc.is_null() {
            winapi::um::winsvc::CloseServiceHandle(scm);
            return None;
        }

        let mut status: winapi::um::winsvc::SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut bytes_needed: u32 = 0;
        let ok = winapi::um::winsvc::QueryServiceStatusEx(
            svc,
            winapi::um::winsvc::SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            std::mem::size_of::<winapi::um::winsvc::SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        );

        winapi::um::winsvc::CloseServiceHandle(svc);
        winapi::um::winsvc::CloseServiceHandle(scm);

        if ok == 0 {
            None
        } else {
            Some(status.dwCurrentState)
        }
    }
}

fn try_start_service(name: &str) -> Result<()> {
    unsafe {
        let scm = winapi::um::winsvc::OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            winapi::um::winsvc::SC_MANAGER_CONNECT,
        );
        if scm.is_null() {
            anyhow::bail!("OpenSCManagerW failed");
        }

        let name_w = wide_string(name);
        let svc = winapi::um::winsvc::OpenServiceW(
            scm,
            name_w.as_ptr(),
            winapi::um::winsvc::SERVICE_START | winapi::um::winsvc::SERVICE_QUERY_STATUS,
        );
        if svc.is_null() {
            winapi::um::winsvc::CloseServiceHandle(scm);
            anyhow::bail!("OpenServiceW failed");
        }

        let ok = winapi::um::winsvc::StartServiceW(svc, 0, std::ptr::null_mut());
        if ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            winapi::um::winsvc::CloseServiceHandle(svc);
            winapi::um::winsvc::CloseServiceHandle(scm);
            anyhow::bail!("StartServiceW failed (err={})", err);
        }

        winapi::um::winsvc::CloseServiceHandle(svc);
        winapi::um::winsvc::CloseServiceHandle(scm);
        Ok(())
    }
}

fn rgba_to_yuv420(rgba: &[u8], width: usize, height: usize) -> Vec<u8> {
    let y_size = width * height;
    let uv_width = width / 2;
    let uv_height = height / 2;
    let uv_size = uv_width * uv_height;

    let mut yuv = vec![0u8; y_size + uv_size * 2];
    let (y_plane, rest) = yuv.split_at_mut(y_size);
    let (u_plane, v_plane) = rest.split_at_mut(uv_size);

    for r in 0..height {
        for c in 0..width {
            let rgba_idx = (r * width + c) * 4;
            let r_val = rgba[rgba_idx] as f32;
            let g_val = rgba[rgba_idx + 1] as f32;
            let b_val = rgba[rgba_idx + 2] as f32;

            // BT.601
            let y_val = 0.257 * r_val + 0.504 * g_val + 0.098 * b_val + 16.0;
            y_plane[r * width + c] = y_val as u8;

            if r % 2 == 0 && c % 2 == 0 {
                let u_val = -0.148 * r_val - 0.291 * g_val + 0.439 * b_val + 128.0;
                let v_val = 0.439 * r_val - 0.368 * g_val - 0.071 * b_val + 128.0;

                let uv_idx = (r / 2) * uv_width + (c / 2);
                u_plane[uv_idx] = u_val as u8;
                v_plane[uv_idx] = v_val as u8;
            }
        }
    }
    yuv
}

fn main() -> Result<()> {
    init_log();
    let args: Vec<String> = std::env::args().collect();
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    log_info(&format!(
        "Host starting: exe={} pid={} args={:?} log={}",
        exe_path,
        std::process::id(),
        args,
        log_path().display()
    ));
    if args.iter().any(|a| a == "--logs") {
        let _ = tail_logs_blocking();
        return Ok(());
    }
    if args.iter().any(|a| a == "--agent") {
        init_log();
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(agent::run_agent());
    }

    // Tenta rodar como serviço
    let service_result = service_dispatcher::start("SysRemoteHost", ffi_service_main);

    match service_result {
        Ok(_) => Ok(()),
        Err(e) => {
            init_log();
            // ensure_console(); // No longer needed as we use GUI
            log_info(&format!("Nao iniciado como servico: {}", e));
            log_info("Running in GUI/Console Mode...");

            match query_service_state("SysRemoteHost") {
                Some(winapi::um::winsvc::SERVICE_RUNNING) => {
                    log_info("Servico SysRemoteHost esta rodando. Abrindo GUI de controle...");
                    // Instead of tail_logs_blocking, launch GUI
                    if let Err(e) = gui::run_gui() {
                         log_error(&format!("GUI failed: {}", e));
                    }
                    return Ok(());
                }
                Some(winapi::um::winsvc::SERVICE_STOPPED) => {
                    log_error("Servico SysRemoteHost esta instalado, mas PARADO.");
                    if is_elevated() {
                        if try_start_service("SysRemoteHost").is_ok() {
                            log_info("Servico iniciado. Abrindo GUI de controle...");
                             if let Err(e) = gui::run_gui() {
                                 log_error(&format!("GUI failed: {}", e));
                            }
                            return Ok(());
                        }
                    }
                }
                Some(state) => {
                    log_info(&format!(
                        "Servico SysRemoteHost esta instalado. Estado={}",
                        state
                    ));
                }
                None => {
                    log_error("Servico SysRemoteHost NAO esta instalado.");
                    log_info("No instalador, escolha o componente Host (Servidor/Servico).");
                }
            }

            // Se chegou aqui, porta está livre -> Rodar servidor Console
            // But user wants a "program open".
            // So we should probably show the GUI anyway, and warn user.
            
            // Check if we can bind to port. If yes, maybe we are running in portable mode?
            // But the GUI expects to read logs from a file.
            
            println!("---------------------------------------------------");
            println!("SysRemote Host - GUI Mode");
            println!("---------------------------------------------------");
            
            // Launch GUI
             if let Err(e) = gui::run_gui() {
                 log_error(&format!("GUI failed: {}", e));
            }
            Ok(())
        }
    }
}

fn wide_string(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

async fn init_ipc() -> Result<(Arc<Mutex<shmem_utils::Shmem>>, Arc<tokio::sync::Mutex<NamedPipeServer>>)> {
    log_info("Initializing IPC (Shared Memory & Pipe)...");
    log_info(&format!(
        "IPC names: pipe={} shmem={} shmem_size={}",
        IPC_PIPE_NAME, IPC_SHMEM_NAME, IPC_SHMEM_SIZE
    ));
    
    // Create Shared Memory
    // We try to open or create. Service creates.
    let shmem = match shmem_utils::Shmem::create(IPC_SHMEM_NAME, IPC_SHMEM_SIZE) {
        Ok(m) => m,
        Err(e) => {
            log_error(&format!("Failed to create Shared Memory: {}", e));
            return Err(e.into());
        }
    };
    let shmem = Arc::new(Mutex::new(shmem));

    // Create Named Pipe Server with security descriptor allowing user sessions
    let pipe_server = {
        use std::os::windows::ffi::OsStrExt;
        
         let sddl: Vec<u16> = std::ffi::OsStr::new("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut sd: winapi::um::winnt::PSECURITY_DESCRIPTOR = std::ptr::null_mut();

        unsafe {
            let res = winapi::shared::sddl::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                winapi::shared::sddl::SDDL_REVISION_1 as u32,
                &mut sd,
                std::ptr::null_mut(),
            );
            if res == 0 {
                let err = winapi::um::errhandlingapi::GetLastError();
                log_error(&format!("Failed to create security descriptor for pipe: {}", err));
                return Err(anyhow::anyhow!("Pipe security descriptor failed: {}", err));
            }
        }

        let mut sa: winapi::um::minwinbase::SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };
        sa.nLength = std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32;
        sa.lpSecurityDescriptor = sd;
        sa.bInheritHandle = 0;

        let pipe_name_w: Vec<u16> = std::ffi::OsStr::new(IPC_PIPE_NAME)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            winapi::um::namedpipeapi::CreateNamedPipeW(
                pipe_name_w.as_ptr(),
                winapi::um::winbase::PIPE_ACCESS_DUPLEX | winapi::um::winbase::FILE_FLAG_OVERLAPPED,
                winapi::um::winbase::PIPE_TYPE_BYTE | winapi::um::winbase::PIPE_READMODE_BYTE | winapi::um::winbase::PIPE_WAIT,
                1,      // max instances
                65536,  // out buffer size
                65536,  // in buffer size
                0,      // default timeout
                &mut sa,
            )
        };

        unsafe { winapi::um::winbase::LocalFree(sd as *mut _); }

        if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            log_error(&format!("Failed to create IPC pipe {}: win32 error {}", IPC_PIPE_NAME, err));
            return Err(anyhow::anyhow!("CreateNamedPipeW failed: {}", err));
        }

        log_info(&format!("Created IPC pipe {} with Everyone access", IPC_PIPE_NAME));
        unsafe { NamedPipeServer::from_raw_handle(handle as std::os::windows::io::RawHandle) }.map_err(|e| anyhow::anyhow!("from_raw_handle failed: {}", e))
    }?;

    let pipe_server = Arc::new(tokio::sync::Mutex::new(pipe_server));
    Ok((shmem, pipe_server))
}

async fn run_server(
    pipe_server: Arc<tokio::sync::Mutex<NamedPipeServer>>,
    shmem: Arc<Mutex<shmem_utils::Shmem>>,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", DEFAULT_PORT);
    log_info(&format!("Host trying to bind on {}", addr));
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            log_info(&format!("Host successfully bound to {}", addr));
            if let Ok(actual) = l.local_addr() {
                log_info(&format!("Host listening on {}", actual));
            }
            l
        }
        Err(e) => {
            log_error(&format!("Failed to bind to {}: {}", addr, e));
            return Err(e.into());
        }
    };

    // IPC is passed in
    
    log_info("Waiting for Agent to connect on IPC pipe...");
    // Wait for agent
    {
        let mut pipe = pipe_server.lock().await;
        match tokio::time::timeout(Duration::from_secs(30), pipe.connect()).await {
            Ok(res) => {
                if let Err(e) = res {
                    log_error(&format!("Agent failed to connect to pipe: {}", e));
                } else {
                    log_info("Agent connected to IPC!");
                }
            }
            Err(_) => {
                log_error("Timeout waiting for Agent connection.");
            }
        }
    }
    
    let pipe = pipe_server;

    log_info(&format!("Host listening loop started on {}", addr));

    loop {
        match listener.accept().await {
            Ok((socket, remote_addr)) => {
                log_info(&format!("ACCEPTED connection from {}", remote_addr));
                
                let pipe_clone = pipe.clone();
                let shmem_clone = shmem.clone();

                tokio::spawn(async move {
                    log_info(&format!("Spawning handler for {}", remote_addr));
                    if let Err(e) = handle_client(socket, pipe_clone, shmem_clone).await {
                        log_error(&format!("Error handling client {}: {}", remote_addr, e));
                    } else {
                        log_info(&format!("Client {} disconnected gracefully", remote_addr));
                    }
                });
            }
            Err(e) => {
                log_error(&format!("Error accepting connection: {}", e));
            }
        }
    }
}

pub(crate) async fn handle_client(
    mut socket: TcpStream,
    pipe: Arc<tokio::sync::Mutex<NamedPipeServer>>,
    shmem: Arc<Mutex<shmem_utils::Shmem>>,
) -> Result<()> {
    let peer_addr = socket
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    log_info(&format!("[{}] Starting handshake...", peer_addr));

    let crypto = Crypto::new(&KEY_BYTES);

    // 1. Handshake
    log_info(&format!("[{}] Waiting for handshake message...", peer_addr));
    let handshake_msg = match read_message(&mut socket, &crypto).await {
        Ok(msg) => msg,
        Err(e) => {
            let e_str = e.to_string().to_lowercase();
            if e_str.contains("early eof") || e_str.contains("unexpected end of file") {
                log_info(&format!(
                    "[{}] Client disconnected during handshake (Connection Probe/Check).",
                    peer_addr
                ));
                return Ok(());
            } else {
                log_error(&format!("[{}] Handshake read failed: {}", peer_addr, e));
            }
            return Err(e);
        }
    };

    if let NetworkMessage::Handshake { psk } = handshake_msg {
        log_info(&format!(
            "[{}] Received handshake PSK: {} (expected: {})",
            peer_addr, psk, PSK
        ));
        if psk != PSK {
            log_error(&format!("[{}] Invalid PSK received", peer_addr));
            let response = NetworkMessage::HandshakeAck { success: false };
            send_message(&mut socket, &crypto, &response).await?;
            return Ok(());
        }
    } else {
        log_error(&format!(
            "[{}] Unexpected message during handshake: {:?}",
            peer_addr, handshake_msg
        ));
        return Ok(());
    }

    log_info(&format!(
        "[{}] Handshake successful. Sending ACK...",
        peer_addr
    ));
    let response = NetworkMessage::HandshakeAck { success: true };
    send_message(&mut socket, &crypto, &response).await?;
    log_info(&format!("[{}] ACK sent. Splitting socket...", peer_addr));

    let (mut reader, mut writer) = socket.into_split();
    let crypto_read = Arc::new(crypto);
    let crypto_write = crypto_read.clone();

    // Channels
    let (tx_frame, mut rx_frame) = tokio::sync::mpsc::channel::<(Vec<u8>, bool)>(5);

    // Capture Requester Task (Service -> Agent -> Service)
    let pipe_clone = pipe.clone();
    let shmem_clone = shmem.clone();

    tokio::spawn(async move {
        let mut encoder: Option<Encoder> = None;
        let mut frame_count = 0;
        let mut width = 1920;
        let mut height = 1080;

        // Initialize Encoder
        match Encoder::new() {
            Ok(enc) => encoder = Some(enc),
            Err(e) => log_error(&format!("Failed to create encoder: {}", e)),
        }

        loop {
            let start = Instant::now();

            // 1. Send Capture Request
            let req = IpcMessage::CaptureRequest;
            let req_bytes = serde_json::to_vec(&req).unwrap();

            // Scope for Write Request
            let write_result = {
                let mut p = pipe_clone.lock().await;
                async {
                    p.write_u32(req_bytes.len() as u32).await?;
                    p.write_all(&req_bytes).await?;
                    Ok::<(), std::io::Error>(())
                }
                .await
            };

            if let Err(e) = write_result {
                log_error(&format!("IPC Write Error: {}", e));
                break;
            }

            // Scope for Read Response
            let frame_info = {
                let mut p = pipe_clone.lock().await;
                async {
                    let len = p.read_u32().await?;
                    let mut buf = vec![0u8; len as usize];
                    p.read_exact(&mut buf).await?;
                    Ok::<Vec<u8>, std::io::Error>(buf)
                }
                .await
            };

            match frame_info {
                Ok(buf) => match serde_json::from_slice::<IpcMessage>(&buf) {
                    Ok(msg) => {
                        if let IpcMessage::FrameReady {
                            size,
                            width: w,
                            height: h,
                            keyframe: _,
                        } = msg
                        {
                            // Update dimensions
                            if w as usize != width || h as usize != height {
                                log_info(&format!(
                                    "Frame size changed: {}x{} -> {}x{}",
                                    width, height, w, h
                                ));
                                width = w as usize;
                                height = h as usize;
                                encoder = None; // Reset encoder
                                match Encoder::new() {
                                    Ok(enc) => encoder = Some(enc),
                                    Err(e) => log_error(&format!("Failed to create encoder: {}", e)),
                                }
                            }

                            // Read Pixels from ShMem
                            let mut pixels = vec![0u8; size];
                            {
                                // Handle PoisonError by using into_inner() or unwrap()
                                let shmem = match shmem_clone.lock() {
                                    Ok(guard) => guard,
                                    Err(poisoned) => poisoned.into_inner(),
                                };
                                let src = shmem.as_ptr();
                                unsafe {
                                    std::ptr::copy_nonoverlapping(src, pixels.as_mut_ptr(), size);
                                }
                            }

                            // Convert to YUV
                            let yuv = rgba_to_yuv420(&pixels, width, height);
                            let yuv_buffer = YUVBuffer::from_vec(yuv, width, height);

                            // Encode
                            let mut encoded_packet: Option<(Vec<u8>, bool)> = None;
                            if let Some(ref mut enc) = encoder {
                                match enc.encode(&yuv_buffer) {
                                    Ok(bitstream) => {
                                        let mut data = Vec::new();
                                        bitstream.write_vec(&mut data);
                                        let is_keyframe = frame_count % 60 == 0;
                                        encoded_packet = Some((data, is_keyframe));
                                    }
                                    Err(e) => log_error(&format!("H264 encoding error: {}", e)),
                                }
                                frame_count += 1;
                            }
                            
                            if let Some(packet) = encoded_packet {
                                if tx_frame.send(packet).await.is_err() {
                                    log_error("Failed to enqueue frame for network send");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log_error(&format!("IPC Deserialize Error: {}", e));
                        break;
                    }
                },
                Err(e) => {
                    log_error(&format!("IPC Read Error: {}", e));
                    break;
                }
            }

            // Pacing (60 FPS)
            let elapsed = start.elapsed();
            if elapsed < Duration::from_millis(16) {
                tokio::time::sleep(Duration::from_millis(16) - elapsed).await;
            }
        }
    });

    // Sender Task (Network)
    let writer_task = tokio::spawn(async move {
        while let Some((data, keyframe)) = rx_frame.recv().await {
            let msg = NetworkMessage::VideoFrame { data, keyframe };
            if let Err(e) = send_message_raw(&mut writer, &crypto_write, &msg).await {
                // Log and break
                let e_str = e.to_string().to_lowercase();
                if !e_str.contains("broken pipe")
                    && !e_str.contains("connection reset")
                {
                    log_error(&format!("Failed to send frame: {}", e));
                }
                break;
            }
        }
    });

    // Input Receiver Task (Network -> IPC)
    let pipe_input = pipe.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            match read_message_raw(&mut reader, &crypto_read).await {
                Ok(msg) => match msg {
                    NetworkMessage::Input(event) => {
                        // Forward to Agent via IPC
                        let ipc_msg = IpcMessage::Input(event);
                        if let Ok(bytes) = serde_json::to_vec(&ipc_msg) {
                            let mut p = pipe_input.lock().await;
                            // Just write, no response expected
                            if let Err(e) = p.write_u32(bytes.len() as u32).await {
                                log_error(&format!("IPC Input write length failed: {}", e));
                                break;
                            }
                            if let Err(e) = p.write_all(&bytes).await {
                                log_error(&format!("IPC Input write failed: {}", e));
                                break;
                            }
                        }
                    }
                    _ => {}
                },
                Err(e) => {
                    log_error(&format!("Network input read error: {}", e));
                    break;
                }
            }
        }
    });

    let _ = tokio::join!(writer_task, reader_task);

    Ok(())
}

async fn send_message(socket: &mut TcpStream, crypto: &Crypto, msg: &NetworkMessage) -> Result<()> {
    // Implementation needed
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
) -> Result<()> {
    let data = bincode::serialize(msg)?;
    let encrypted = crypto.encrypt(&data)?;
    let len = encrypted.len() as u32;
    socket.write_all(&len.to_be_bytes()).await?;
    socket.write_all(&encrypted).await?;
    Ok(())
}

async fn read_message(socket: &mut TcpStream, crypto: &Crypto) -> Result<NetworkMessage> {
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
) -> Result<NetworkMessage> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await?;

    let decrypted = crypto.decrypt(&buf)?;
    let msg = bincode::deserialize(&decrypted)?;
    Ok(msg)
}
