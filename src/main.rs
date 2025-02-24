use std::fs;
use std::io;
use std::path::PathBuf;
use std::ptr;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;
use log::{info, warn};
use winapi::shared::minwindef::DWORD;
use winapi::shared::windef::{HWINEVENTHOOK, HWND};
use winapi::shared::ntdef::LONG;
use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenProcess};
use winapi::um::winuser::*;
use winapi::um::psapi::GetModuleBaseNameW;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
use winapi::um::wincon::GetConsoleWindow;
use winapi::um::dwmapi::*;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct SafeHWND(HWND);

unsafe impl Send for SafeHWND {}
unsafe impl Sync for SafeHWND {}

lazy_static::lazy_static! {
    static ref STYLE_CACHE: Mutex<HashMap<SafeHWND, u32>> = Mutex::new(HashMap::with_capacity(100));
    static ref PROCESS_CACHE: Mutex<HashMap<DWORD, Option<String>>> = Mutex::new(HashMap::with_capacity(50));
    static ref EXCLUDED_PROCESSES: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

const GWL_STYLE: i32 = -16;
//const STYLE_TO_REMOVE: u32 = WS_CAPTION;
const DWMWA_WINDOW_CORNER_PREFERENCE: DWORD = 33;
const DWMWCP_ROUND: DWORD = 2;

static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Serialize, Deserialize, Default)]
struct Config {
    excluded_processes: Vec<String>,
}

fn get_config_path() -> PathBuf {
    let mut config_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    config_dir.push(".config");
    config_dir.push("winnodeco");
    fs::create_dir_all(&config_dir).unwrap_or_default();
    config_dir.push("config.json");
    config_dir
}

fn read_excluded_processes() -> io::Result<Vec<String>> {
    let config_path = get_config_path();
    
    if !config_path.exists() {
        let default_config = Config::default();
        fs::write(&config_path, serde_json::to_string_pretty(&default_config)?)?;
        return Ok(Vec::new());
    }
    
    let config_str = fs::read_to_string(config_path)?;
    let config: Config = serde_json::from_str(&config_str).unwrap_or_default();
    Ok(config.excluded_processes)
}

// Get process name from window handle with caching
fn get_process_name(hwnd: HWND) -> Option<String> {
    unsafe {
        let mut process_id: DWORD = 0;
        GetWindowThreadProcessId(hwnd, &mut process_id);
        
        if process_id == 0 || process_id == GetCurrentProcessId() {
            return None;
        }
        
        // Check process cache first
        let mut process_cache = PROCESS_CACHE.lock().unwrap();
        if let Some(cached_name) = process_cache.get(&process_id) {
            return cached_name.clone();
        }
        
        // If not in cache, get the process name
        let process_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | winapi::um::winnt::PROCESS_VM_READ,
            0,
            process_id
        );
        
        if process_handle.is_null() {
            process_cache.insert(process_id, None);
            return None;
        }
        
        struct HandleGuard(winapi::um::winnt::HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                unsafe { winapi::um::handleapi::CloseHandle(self.0); }
            }
        }
        let _guard = HandleGuard(process_handle);
        
        let mut name_buf = [0u16; 260];
        let len = GetModuleBaseNameW(
            process_handle,
            ptr::null_mut(),
            name_buf.as_mut_ptr(),
            name_buf.len() as DWORD
        );
        
        let result = if len == 0 {
            None
        } else {
            Some(String::from_utf16_lossy(&name_buf[..len as usize]))
        };
        
        process_cache.insert(process_id, result.clone());
        result
    }
}

// Window event callback
unsafe extern "system" fn win_event_proc(
    _h_win_event_hook: HWINEVENTHOOK,
    _event: DWORD,
    _hwnd: HWND,
    _id_object: LONG,
    _id_child: LONG,
    _id_event_thread: DWORD,
    _dwms_event_time: DWORD,
) {
    unsafe {
        let foreground_window = GetForegroundWindow();
        if foreground_window.is_null() { 
            return; 
        }

        if let Some(process_name) = get_process_name(foreground_window) {
            info!("Detected foreground window change: {}", process_name);
            
            // Check excluded processes
            let excluded = EXCLUDED_PROCESSES.lock().unwrap();
            let process_name_lower = process_name.to_lowercase();
            if excluded.iter().any(|p| {
                let p_lower = p.to_lowercase();
                let p_no_exe = p_lower.trim_end_matches(".exe");
                let proc_no_exe = process_name_lower.trim_end_matches(".exe");
                p_no_exe == proc_no_exe
            }) {
                info!("Process {} is in exclusion list, skipping", process_name);
                return;
            }
            
            let current_style = GetWindowLongW(foreground_window, GWL_STYLE) as u32;
            let new_style = current_style;
            //& !STYLE_TO_REMOVE;
            
            // Check style cache
            let mut cache = STYLE_CACHE.lock().unwrap();
            let safe_hwnd = SafeHWND(foreground_window);
            if let Some(&cached_style) = cache.get(&safe_hwnd) {
                if cached_style == new_style { 
                    info!("Window style already modified for {}", process_name);
                    return; 
                }
            }
            
            // Update style if different
            if current_style != new_style {
                info!("Modifying window decoration for {} (style: 0x{:x} -> 0x{:x})", 
                      process_name, current_style, new_style);
                let result = SetWindowLongW(foreground_window, GWL_STYLE, new_style as i32);
                if result != 0 {
                    cache.insert(safe_hwnd, new_style);
                    
                    // Set DWM window corner preference to maintain rounded corners
                    DwmSetWindowAttribute(
                        foreground_window,
                        DWMWA_WINDOW_CORNER_PREFERENCE,
                        &(DWMWCP_ROUND as i32) as *const _ as *const _,
                        std::mem::size_of::<i32>() as u32
                    );
                    
                    SetWindowPos(
                        foreground_window,
                        ptr::null_mut(),
                        0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
                    );
                    info!("Successfully modified window decoration for {}", process_name);
                } else {
                    warn!("Failed to modify window decoration for {}", process_name);
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let debug_mode = args.iter().any(|arg| arg == "--debug");

    unsafe {
        // Hide console window if not in debug mode
        if !debug_mode {
            let window = GetConsoleWindow();
            if !window.is_null() {
                ShowWindow(window, SW_HIDE);
            }
        }
    }

    if debug_mode {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
        env_logger::init();
        info!("Starting window decoration remover in debug mode...");
    }

    // Initialize excluded processes
    if let Ok(processes) = read_excluded_processes() {
        let mut excluded = EXCLUDED_PROCESSES.lock().unwrap();
        *excluded = processes.clone();
        if debug_mode {
            info!("Loaded excluded processes: {:?}", processes);
        }
    } else if debug_mode {
        warn!("Failed to load excluded processes");    
    }
    
    unsafe {
        let hook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            ptr::null_mut(),
            Some(win_event_proc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        );
        
        if hook.is_null() {
            eprintln!("Failed to set window event hook");
            return;
        }
        
        if debug_mode {
            println!("Window decoration remover is running in debug mode... Press Ctrl+C to exit");
        } else {
            println!("Window decoration remover is running... Press Ctrl+C to exit");
        }
        
        let mut msg: MSG = std::mem::zeroed();
        while RUNNING.load(Ordering::SeqCst) {
            if GetMessageA(&mut msg, ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }
        }
        
        UnhookWinEvent(hook);
    }
}
