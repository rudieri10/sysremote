use eframe::egui;
use std::sync::mpsc::Sender;
use std::time::Duration;
use crate::logging::log_path;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use shared::{DISCOVERY_HOST, DISCOVERY_PORT};

pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 400.0])
            .with_title("SysRemote Host Control Panel"),
        ..Default::default()
    };
    eframe::run_native(
        "SysRemote Host",
        options,
        Box::new(|cc| Box::new(HostApp::new(cc))),
    )
}

struct HostApp {
    log_content: String,
    last_log_size: u64,
    connection_status: String,
    is_checking: bool,
    service_status: String,
}

impl HostApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            log_content: String::new(),
            last_log_size: 0,
            connection_status: "Unknown".to_owned(),
            is_checking: false,
            service_status: "Checking...".to_owned(),
        }
    }

    fn update_logs(&mut self) {
        if let Ok(path) = std::env::current_exe() {
            // Log path logic matches logging.rs roughly (assuming standard ProgramData location or relative)
            let log_file = log_path(); 
            
            if let Ok(metadata) = std::fs::metadata(&log_file) {
                let len = metadata.len();
                if len > self.last_log_size {
                    if let Ok(mut file) = std::fs::OpenOptions::new().read(true).open(&log_file) {
                        if self.last_log_size == 0 {
                            // First read: read last 4KB
                             let start = len.saturating_sub(4096);
                             let _ = file.seek(SeekFrom::Start(start));
                        } else {
                            let _ = file.seek(SeekFrom::Start(self.last_log_size));
                        }
                        
                        let mut new_content = String::new();
                        if file.read_to_string(&mut new_content).is_ok() {
                            self.log_content.push_str(&new_content);
                            // Keep log buffer reasonable
                            if self.log_content.len() > 20000 {
                                let split = self.log_content.len() - 10000;
                                self.log_content = self.log_content.split_off(split);
                            }
                        }
                        self.last_log_size = len;
                    }
                }
            }
        }
    }

    fn check_connection(&mut self) {
        self.is_checking = true;
        self.connection_status = "Checking connectivity...".to_owned();
        
        // This should ideally be async, but for simple GUI button click blocking briefly is "okay" or spawn thread
        let (tx, rx) = std::sync::mpsc::channel();
        
        std::thread::spawn(move || {
            // Check 1: Can we reach Google? (Internet Check)
            let internet = std::net::TcpStream::connect("8.8.8.8:53").is_ok();
            
            // Check 2: Can we reach Discovery Server?
            // Assuming Discovery is at 34.135.23.167:3000 (from shared lib or config)
            // But let's use the actual discovery logic if possible, or just a TCP connect
            let discovery = std::net::TcpStream::connect(format!("{}:{}", DISCOVERY_HOST, DISCOVERY_PORT)).is_ok();
            
            // Check 3: Is Local Port Open? (Service running)
            let local = std::net::TcpStream::connect("127.0.0.1:5599").is_ok();
            
            tx.send((internet, discovery, local)).unwrap();
        });
        
        // We can't block here easily in immediate mode without freezing UI.
        // For this simple implementation, we'll just wait for next frame to poll a channel if we stored it in struct.
        // But to keep it simple, let's just use a thread and update status later? 
        // No, `self` is borrowed.
        // Let's just do a quick blocking check for now, or use a channel in the struct.
    }
}

impl eframe::App for HostApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll logs every frame (or every second)
        self.update_logs();
        
        // Update Service Status
        if let Some(state) = crate::query_service_state("SysRemoteHost") {
             let state_str = match state {
                 1 => "STOPPED",
                 2 => "START_PENDING",
                 3 => "STOP_PENDING",
                 4 => "RUNNING",
                 _ => "UNKNOWN",
             };
             self.service_status = format!("Installed (State: {})", state_str);
        } else {
             self.service_status = "Not Installed".to_owned();
        }

        // Apply a dark theme or style if desired, but default eframe is usually dark
        
        egui::CentralPanel::default().show(ctx, |ui| {
            // Header
            ui.vertical_centered(|ui| {
                ui.heading(egui::RichText::new("SysRemote Host").size(24.0).strong());
                ui.label("Control Panel & Diagnostics");
            });
            ui.separator();
            
            // Service Status Section
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Service Status:").strong());
                    
                    let color = if self.service_status.contains("RUNNING") {
                        egui::Color32::GREEN
                    } else if self.service_status.contains("STOPPED") {
                        egui::Color32::RED
                    } else {
                        egui::Color32::YELLOW
                    };
                    
                    ui.colored_label(color, &self.service_status);
                });
            });
            
            ui.add_space(10.0);
            
            // Diagnostics Section
            ui.group(|ui| {
                ui.vertical_centered(|ui| {
                    if ui.button(egui::RichText::new("🔍 Run Connection Diagnostics").size(16.0)).clicked() {
                        // Perform checks
                        let internet = std::net::TcpStream::connect_timeout(&"8.8.8.8:53".parse().unwrap(), Duration::from_secs(2)).is_ok();
                        let discovery = std::net::TcpStream::connect_timeout(&format!("{}:{}", DISCOVERY_HOST, DISCOVERY_PORT).parse().unwrap(), Duration::from_secs(2)).is_ok();
                        let local = std::net::TcpStream::connect_timeout(&"127.0.0.1:5599".parse().unwrap(), Duration::from_secs(1)).is_ok();
                        
                        let mut status = String::new();
                        status.push_str("Diagnostic Results:\n");
                        status.push_str("-------------------\n");
                        status.push_str(&format!(" [1] Internet Access:   {}\n", if internet { "✅ OK" } else { "❌ FAILED" }));
                        status.push_str(&format!(" [2] Discovery Server:  {}\n", if discovery { "✅ OK" } else { "❌ FAILED" }));
                        status.push_str(&format!(" [3] Local Service:     {}\n", if local { "✅ RUNNING" } else { "❌ STOPPED/BLOCKED" }));
                        
                        if internet && discovery && local {
                            status.push_str("\n>> STATUS: READY TO RECEIVE CONNECTIONS <<");
                        } else {
                            status.push_str("\n>> STATUS: CONNECTION ISSUES DETECTED <<");
                        }
                        
                        self.connection_status = status;
                    }
                });
                
                ui.add_space(5.0);
                if !self.connection_status.is_empty() {
                    ui.label(egui::RichText::new(&self.connection_status).monospace());
                } else {
                    ui.label("Click the button above to check connectivity.");
                }
            });

            ui.add_space(10.0);
            ui.separator();
            ui.label(egui::RichText::new("Real-time Logs").strong());
            
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.log_content)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .lock_focus(false) // Don't steal focus
                    );
                });
        });
        
        // Repaint periodically to update logs even if no mouse movement
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}
