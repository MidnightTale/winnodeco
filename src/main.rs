use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;
use winapi::shared::minwindef::DWORD;
use winapi::shared::windef::{HWINEVENTHOOK, HWND};
use winapi::shared::ntdef::LONG;
use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenProcess};
use winapi::um::winuser::*;
use winapi::um::psapi::GetModuleBaseNameW;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;

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
const STYLE_TO_REMOVE: u32 = WS_CAPTION | WS_THICKFRAME;

static RUNNING: AtomicBool = AtomicBool::new(true);

// Read excluded processes from file
fn read_excluded_processes() -> io::Result<Vec<String>> {
    let path = Path::new("ExcludedProcesses.txt");
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut processes = Vec::new();
    
    for line in reader.lines() {
        if let Ok(process) = line {
            processes.push(process.trim().to_string());
        }
    }
    
    Ok(processes)
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
        if foreground_window.is_null() { return; }

        if let Some(process_name) = get_process_name(foreground_window) {
            // Check excluded processes
            let excluded = EXCLUDED_PROCESSES.lock().unwrap();
            if excluded.iter().any(|p| p == &process_name) { return; }
            
            let current_style = GetWindowLongW(foreground_window, GWL_STYLE) as u32;
            let new_style = current_style & !STYLE_TO_REMOVE;
            
            // Check style cache
            let mut cache = STYLE_CACHE.lock().unwrap();
            let safe_hwnd = SafeHWND(foreground_window);
            if let Some(&cached_style) = cache.get(&safe_hwnd) {
                if cached_style == new_style { return; }
            }
            
            // Update style if different
            if current_style != new_style {
                let result = SetWindowLongW(foreground_window, GWL_STYLE, new_style as i32);
                if result != 0 {
                    cache.insert(safe_hwnd, new_style);
                    SetWindowPos(
                        foreground_window,
                        ptr::null_mut(),
                        0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
                    );
                }
            }
        }
    }
}

fn main() {
    // Initialize excluded processes
    if let Ok(processes) = read_excluded_processes() {
        let mut excluded = EXCLUDED_PROCESSES.lock().unwrap();
        *excluded = processes;
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
        
        println!("Window decoration remover is running... Press Ctrl+C to exit");
        
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
