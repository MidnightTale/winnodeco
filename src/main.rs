use std::fs;
use std::path::PathBuf;
use std::ptr;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;
use log::info;
use winapi::shared::minwindef::DWORD;
use winapi::shared::windef::{HWINEVENTHOOK, HWND};
use winapi::shared::ntdef::LONG;
use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenProcess};
use winapi::um::winuser::*;
use winapi::um::psapi::GetModuleBaseNameW;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
use winapi::um::wincon::GetConsoleWindow;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct SafeHWND(HWND);

unsafe impl Send for SafeHWND {}
unsafe impl Sync for SafeHWND {}

lazy_static::lazy_static! {
    static ref STYLE_CACHE: Mutex<HashMap<SafeHWND, u32>> = Mutex::new(HashMap::with_capacity(100));
    static ref PROCESS_CACHE: Mutex<HashMap<DWORD, Option<String>>> = Mutex::new(HashMap::with_capacity(50));
    static ref CONFIG: Mutex<Config> = Mutex::new(Config::default());
}

const GWL_STYLE: i32 = -16;
const STYLE_TO_REMOVE: u32 = WS_CAPTION | WS_THICKFRAME;


static RUNNING: AtomicBool = AtomicBool::new(true);



#[derive(Serialize, Deserialize, Debug, Clone)]
struct WindowDecorationSettings {
    title_bar: bool,
    window_buttons: bool,
}

impl Default for WindowDecorationSettings {
    fn default() -> Self {
        Self {
            title_bar: false,
            window_buttons: false,
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Config {
    ignore_patterns: IgnorePatterns,
    override_settings: HashMap<String, WindowDecorationSettings>,
    default_settings: WindowDecorationSettings,
}

#[derive(Serialize, Deserialize, Default)]
struct IgnorePatterns {
    process_names: Vec<String>,
    window_classes: Vec<String>,
}

fn get_config_path() -> PathBuf {
    let mut config_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    config_dir.push(".config");
    config_dir.push("winnodeco");
    fs::create_dir_all(&config_dir).unwrap_or_default();
    config_dir.push("config.json");
    config_dir
}

fn load_config() -> Config {
    let config_path = get_config_path();
    info!("Loading config from path: {}", config_path.display());
    
    if let Ok(config_str) = fs::read_to_string(&config_path) {
        info!("Raw config content: {}", config_str);
        if let Ok(config) = serde_json::from_str::<Config>(&config_str) {
            info!("Parsed config: override_settings_count={}, default_settings={:?}", 
                  config.override_settings.len(), config.default_settings);
            return config;
        }
    }
    Config::default()
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

        // Get window class name
        let mut class_name = [0u16; 256];
        if GetClassNameW(foreground_window, class_name.as_mut_ptr(), class_name.len() as i32) == 0 {
            return;
        }
        let window_class = String::from_utf16_lossy(&class_name[..class_name.iter().position(|&x| x == 0).unwrap_or(class_name.len())]);

        if let Some(process_name) = get_process_name(foreground_window) {
            info!("Detected foreground window change: {} (class: {})", process_name, window_class);
            
            let config = CONFIG.lock().unwrap();
            let process_name_lower = process_name.to_lowercase();
            let proc_no_exe = process_name_lower.trim_end_matches(".exe");
            
            info!("Process name matching: original='{}', lower='{}', no_exe='{}'", 
                  process_name, process_name_lower, proc_no_exe);

            // First check: ignore patterns
            let should_ignore = config.ignore_patterns.process_names.iter()
                .any(|p| p.to_lowercase().trim_end_matches(".exe") == proc_no_exe) ||
                config.ignore_patterns.window_classes.iter()
                .any(|c| c.to_lowercase() == window_class.to_lowercase());

            if should_ignore {
                info!("Window ignored due to ignore patterns: {} ({})", process_name, window_class);
                return;
            }
            
            // Second check: override settings
            let settings = if let Some(override_settings) = config.override_settings.get(proc_no_exe) {
                info!("Using override settings for {}", process_name);
                override_settings
            } else {
                // Third check: default settings
                info!("Using default settings for {}", process_name);
                &config.default_settings
            };
    
            let current_style = GetWindowLongW(foreground_window, GWL_STYLE) as u32;
            let mut new_style = current_style;

            // Apply title bar and window button settings
            if !settings.title_bar || !settings.window_buttons {
                new_style &= !STYLE_TO_REMOVE;
            }

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
                
                // Apply style changes multiple times with small delays to ensure they stick
                for _ in 0..3 {
                    let result = SetWindowLongW(foreground_window, GWL_STYLE, new_style as i32);
                    if result != 0 {
                        cache.insert(safe_hwnd, new_style);
                        

                        
                        SetWindowPos(
                            foreground_window,
                            ptr::null_mut(),
                            0, 0, 0, 0,
                            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
                        );
                        
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
                info!("Successfully modified window decoration for {}", process_name);
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
    
    // Load config at startup
    *CONFIG.lock().unwrap() = load_config();
    
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
