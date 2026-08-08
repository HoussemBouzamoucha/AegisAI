// File: src/core/file_system/realtime.rs
//
// Real-Time File Protection — watches configured directories for file-system
// events (create / modify / rename-in) and scans each new or changed file.
//
// Architecture:
//   • One OS watcher thread per watched directory, using Windows
//     `ReadDirectoryChangesW` with overlapped I/O + a per-thread stop event.
//   • One scanner thread drains an `mpsc` channel of file paths; calls
//     `FileSystemScanner::scan_file()` on each; pushes `ThreatEvent`s to a
//     shared poll-able queue on Suspicious/Malicious results; auto-quarantines
//     Malicious files when `auto_quarantine = true`.
//   • The daemon polls the queue every 2 s via the `realtime-status` command.
//
// Stopping:
//   `RealTimeWatcher::stop()` signals every watcher thread via its stop event,
//   then joins all threads.  Closing the directory handle inside the thread
//   unblocks any in-flight `ReadDirectoryChangesW`.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::types::ThreatLevel;

// ─── Public types ─────────────────────────────────────────────────────────────

/// A threat detected during real-time file monitoring.
#[derive(Debug, Clone)]
pub struct ThreatEvent {
    pub path:           PathBuf,
    pub level:          ThreatLevel,
    pub reason:         String,
    pub hash:           Option<String>,
    pub timestamp_secs: u64,
    /// True when the file was automatically quarantined.
    pub quarantined:    bool,
}

// ─── Internal watcher thread handle ──────────────────────────────────────────

struct WatcherThread {
    #[cfg(windows)]
    stop_event: windows::Win32::Foundation::HANDLE,
    join:       Option<std::thread::JoinHandle<()>>,
}

// SAFETY: HANDLE is a kernel object handle; the underlying synchronisation
// object is thread-safe.  We only call SetEvent / CloseHandle on it.
#[cfg(windows)]
unsafe impl Send for WatcherThread {}
#[cfg(windows)]
unsafe impl Sync for WatcherThread {}

// ─── RealTimeWatcher ─────────────────────────────────────────────────────────

pub struct RealTimeWatcher {
    auto_quarantine: bool,
    running:         Arc<AtomicBool>,
    threat_queue:    Arc<Mutex<VecDeque<ThreatEvent>>>,
    watched_dirs:    Vec<PathBuf>,
    threads:         Vec<WatcherThread>,
}

impl RealTimeWatcher {
    pub fn new(auto_quarantine: bool) -> Self {
        Self {
            auto_quarantine,
            running:      Arc::new(AtomicBool::new(false)),
            threat_queue: Arc::new(Mutex::new(VecDeque::new())),
            watched_dirs: Vec::new(),
            threads:      Vec::new(),
        }
    }

    /// Currently watched directories (empty when stopped).
    pub fn watched_dirs(&self) -> &[PathBuf] { &self.watched_dirs }

    /// True while the watcher is actively running.
    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }

    /// Drain all pending threat events from the queue (clears the queue).
    pub fn drain_threats(&self) -> Vec<ThreatEvent> {
        self.threat_queue.lock().unwrap().drain(..).collect()
    }

    /// Number of threats waiting in the queue without draining.
    #[allow(dead_code)]
    pub fn threat_count(&self) -> usize {
        self.threat_queue.lock().unwrap().len()
    }

    /// Start watching `dirs`.  No-op if already running.
    ///
    /// Spawns one OS watcher thread per directory and one shared scanner thread.
    pub fn start(&mut self, dirs: Vec<PathBuf>) -> anyhow::Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.watched_dirs = dirs.clone();
        self.running.store(true, Ordering::SeqCst);

        // One mpsc channel: all watcher threads → scanner thread.
        let (path_tx, path_rx) = mpsc::channel::<PathBuf>();

        // Spawn one watcher thread per directory.
        for dir in dirs {
            if !dir.is_dir() {
                eprintln!("[realtime] skipping non-directory: {}", dir.display());
                continue;
            }
            let tx      = path_tx.clone();
            let running = Arc::clone(&self.running);
            let wt      = spawn_watcher_thread(dir, tx, running);
            self.threads.push(wt);
        }
        // Drop the producer clone held here so the channel closes when all
        // watcher threads exit.
        drop(path_tx);

        // Spawn the single scanner thread.
        let queue   = Arc::clone(&self.threat_queue);
        let auto_q  = self.auto_quarantine;
        std::thread::spawn(move || scanner_thread_body(path_rx, queue, auto_q));

        Ok(())
    }

    /// Stop all watcher threads and reset internal state.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);

        #[cfg(windows)]
        for wt in &self.threads {
            unsafe {
                let _ = windows::Win32::System::Threading::SetEvent(wt.stop_event);
            }
        }

        for wt in &mut self.threads {
            if let Some(jh) = wt.join.take() {
                let _ = jh.join();
            }
            #[cfg(windows)]
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(wt.stop_event);
            }
        }
        self.threads.clear();
        self.watched_dirs.clear();
    }
}

impl Drop for RealTimeWatcher {
    fn drop(&mut self) { self.stop(); }
}

// ─── Scanner thread ───────────────────────────────────────────────────────────

fn scanner_thread_body(
    path_rx:    mpsc::Receiver<PathBuf>,
    queue:      Arc<Mutex<VecDeque<ThreatEvent>>>,
    auto_quart: bool,
) {
    // One fresh FileSystemScanner per scanner thread — owns its YARA engine.
    use crate::core::file_system::scanner::FileSystemScanner;
    let scanner = FileSystemScanner::new();

    for path in path_rx {
        // Skip very small / tmp files that are still being written.
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() == 0 { continue; }
        }

        let result = match scanner.scan_file(&path) {
            Ok(r)  => r,
            Err(e) => {
                eprintln!("[realtime] scan error for {}: {}", path.display(), e);
                continue;
            }
        };

        if result.level == ThreatLevel::Clean { continue; }

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut quarantined = false;
        if auto_quart && result.level == ThreatLevel::Malicious {
            let path_str = path.to_string_lossy();
            let qr = crate::core::action::quarantine_file(&path_str);
            if qr.success {
                quarantined = true;
                eprintln!("[realtime] auto-quarantined: {}", path.display());
            } else {
                eprintln!("[realtime] quarantine failed: {:?}", qr.error);
            }
        }

        let event = ThreatEvent {
            path,
            level:          result.level,
            reason:         result.reason,
            hash:           result.hash,
            timestamp_secs: ts,
            quarantined,
        };

        queue.lock().unwrap().push_back(event);
    }
}

// ─── Watcher thread (Windows implementation) ──────────────────────────────────

#[cfg(windows)]
fn spawn_watcher_thread(
    dir:     PathBuf,
    path_tx: mpsc::Sender<PathBuf>,
    running: Arc<AtomicBool>,
) -> WatcherThread {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::ptr::addr_of;

    use windows::Win32::Foundation::{
        CloseHandle, HANDLE, INVALID_HANDLE_VALUE, BOOL, TRUE, FALSE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadDirectoryChangesW,
        FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_NEW_NAME,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
        FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_FILE_NAME,
        FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
        FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
    use windows::Win32::System::Threading::{
        CreateEventW, WaitForMultipleObjects, INFINITE,
    };
    use windows::core::PCWSTR;

    // Create the stop event (manual-reset, initially not signalled).
    let stop_event = unsafe {
        CreateEventW(None, TRUE, FALSE, PCWSTR::null())
            .expect("[realtime] CreateEventW for stop_event failed")
    };

    // HANDLE is not Send in windows 0.58, so transmit the raw pointer value.
    let stop_event_raw = stop_event.0 as usize;

    let jh = std::thread::spawn(move || {
        let stop_event = HANDLE(stop_event_raw as *mut std::ffi::c_void);
        // Open the directory for change notifications.
        let dir_wide: Vec<u16> = {
            use std::os::windows::ffi::OsStrExt;
            dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
        };

        let dir_handle = unsafe {
            CreateFileW(
                PCWSTR(dir_wide.as_ptr()),
                FILE_LIST_DIRECTORY.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                HANDLE::default(),
            )
        };
        let dir_handle = match dir_handle {
            Ok(h) if h != INVALID_HANDLE_VALUE => h,
            _ => {
                eprintln!("[realtime] cannot open directory: {}", dir.display());
                return;
            }
        };

        // Completion event (auto-reset, initially not signalled).
        let comp_event = unsafe {
            CreateEventW(None, FALSE, FALSE, PCWSTR::null())
                .expect("[realtime] CreateEventW for comp_event failed")
        };

        const BUF_SIZE: usize = 64 * 1024;
        let mut buf = vec![0u8; BUF_SIZE];

        while running.load(Ordering::Relaxed) {
            // Zero the overlapped struct and set our completion event.
            let mut overlapped = OVERLAPPED::default();
            overlapped.hEvent = comp_event;
            let mut bytes_returned: u32 = 0;

            let start_ok = unsafe {
                ReadDirectoryChangesW(
                    dir_handle,
                    buf.as_mut_ptr().cast(),
                    BUF_SIZE as u32,
                    TRUE,   // watch subtree
                    FILE_NOTIFY_CHANGE_FILE_NAME
                        | FILE_NOTIFY_CHANGE_LAST_WRITE
                        | FILE_NOTIFY_CHANGE_SIZE,
                    Some(&mut bytes_returned),
                    Some(&mut overlapped),
                    None,  // no completion routine
                )
            };

            if start_ok.is_err() {
                eprintln!("[realtime] ReadDirectoryChangesW failed for {}", dir.display());
                break;
            }

            // Wait for: [0] completion event  [1] stop event
            let handles = [comp_event, stop_event];
            let wait_result = unsafe {
                WaitForMultipleObjects(&handles, BOOL(0), INFINITE)
            };

            if wait_result.0 != 0 {
                // Stop event fired (or error) — exit the loop.
                break;
            }

            // Completion event fired — retrieve result.
            let mut transferred: u32 = 0;
            let got = unsafe {
                GetOverlappedResult(dir_handle, &overlapped, &mut transferred, BOOL(0))
            };
            if got.is_err() || transferred == 0 {
                continue;
            }

            // Parse FILE_NOTIFY_INFORMATION entries from the buffer.
            let mut offset = 0usize;
            loop {
                let remaining = transferred as usize;
                if offset + std::mem::size_of::<FILE_NOTIFY_INFORMATION>() > remaining {
                    break;
                }

                let fni = unsafe {
                    &*(buf.as_ptr().add(offset) as *const FILE_NOTIFY_INFORMATION)
                };

                let action     = fni.Action;
                let name_bytes = fni.FileNameLength as usize;

                if name_bytes > 0 {
                    let name_ptr = addr_of!((*fni).FileName) as *const u16;
                    let name_len = name_bytes / 2;
                    let name_slice = unsafe {
                        std::slice::from_raw_parts(name_ptr, name_len)
                    };
                    let file_name = OsString::from_wide(name_slice);
                    let full_path = dir.join(file_name);

                    let relevant = action == FILE_ACTION_ADDED
                        || action == FILE_ACTION_MODIFIED
                        || action == FILE_ACTION_RENAMED_NEW_NAME;

                    if relevant && full_path.is_file() {
                        // Small pause so the file-write can complete.
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        let _ = path_tx.send(full_path);
                    }
                }

                if fni.NextEntryOffset == 0 {
                    break;
                }
                offset += fni.NextEntryOffset as usize;
            }
        }

        // Cleanup: close handles.  Closing dir_handle cancels any pending I/O.
        unsafe {
            let _ = CloseHandle(comp_event);
            let _ = CloseHandle(dir_handle);
        }
    });

    WatcherThread { stop_event, join: Some(jh) }
}

// ─── Non-Windows stub ─────────────────────────────────────────────────────────

#[cfg(not(windows))]
fn spawn_watcher_thread(
    dir:     PathBuf,
    _tx:     mpsc::Sender<PathBuf>,
    _running: Arc<AtomicBool>,
) -> WatcherThread {
    eprintln!("[realtime] directory watching is Windows-only (skipping {})", dir.display());
    WatcherThread { join: None }
}

#[cfg(not(windows))]
struct WatcherThread {
    join: Option<std::thread::JoinHandle<()>>,
}
