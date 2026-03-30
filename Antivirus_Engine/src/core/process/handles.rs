// File: src/core/process_scanner/handles.rs
// Stage 2: Handle enumeration per process via NtQuerySystemInformation.
//
// Enumerates all system handles and filters by PID. For each handle:
//   - Handle value (numeric)
//   - Object type name  (File, Mutant, Event, Key, Section, Thread, Process...)
//   - Object name       (best-effort — many handles have no queryable name)
//
// Why NtQuerySystemInformation and not a public API?
//   There is no public Win32 API for enumerating another process's handles.
//   NtQuerySystemInformation(SystemHandleInformation) is the undocumented
//   syscall used by every major security tool (Process Hacker, Sysinternals).
//
// Cargo.toml additions (already gated behind cfg(windows)):
//   [target.'cfg(windows)'.dependencies]
//   windows = { version = "0.58", features = [
//     "Win32_Foundation",
//     "Win32_System_Threading",
//     "Win32_System_WindowsProgramming",
//     "Wdk_Foundation",
//     "Wdk_System_SystemInformation",
//     "Wdk_System_SystemServices",
//     "Win32_Security",
//   ]}

use crate::core::process::types::HandleInfo;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Enumerate all open handles belonging to `pid`.
/// Returns an empty Vec on non-Windows platforms or if enumeration fails.
pub fn enumerate_handles(pid: u32) -> Vec<HandleInfo> {
    #[cfg(windows)]
    {
        match windows_impl::enumerate_handles_for_pid(pid) {
            Ok(handles) => handles,
            Err(e) => {
                // Change #1: silence expected Windows access errors to reduce log noise.
                // "Access is denied" and "parameter is incorrect" are normal for
                // protected processes — only log genuinely unexpected failures.
                let msg = e.to_string().to_lowercase();
                if !msg.contains("access is denied") &&
                   !msg.contains("parameter is incorrect") {
                    eprintln!("WARN [handles] PID {}: {}", pid, e);
                }
                vec![]
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        vec![]
    }
}

/// Quick count — avoids returning the full Vec when the caller only needs
/// the number for threat scoring.
pub fn handle_count_for_pid(pid: u32) -> u32 {
    enumerate_handles(pid).len() as u32
}

// ─── Windows implementation ───────────────────────────────────────────────────

#[cfg(windows)]
mod windows_impl {
    use crate::core::process::types::HandleInfo;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    use windows::Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE,
        STATUS_INFO_LENGTH_MISMATCH,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE,
    };
    use windows::Win32::System::WindowsProgramming::PUBLIC_OBJECT_TYPE_INFORMATION;

    use windows::Wdk::System::SystemInformation::{
        NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS,
    };

    use windows::Wdk::Foundation::{
        NtQueryObject, ObjectTypeInformation,
    };

    const SYSTEM_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(16i32);

    use windows::Wdk::Foundation::OBJECT_INFORMATION_CLASS;
    const OBJECT_NAME_INFORMATION_CLASS: OBJECT_INFORMATION_CLASS =
        OBJECT_INFORMATION_CLASS(1i32);

    #[repr(C)]
    struct SystemHandleEntry {
        process_id:               u16,
        creator_back_trace_index: u16,
        object_type_index:        u8,
        handle_attributes:        u8,
        handle_value:             u16,
        object:                   *mut std::ffi::c_void,
        granted_access:           u32,
    }

    #[repr(C)]
    struct RawSystemHandleInformation {
        number_of_handles: u32,
        handles:           [SystemHandleEntry; 1],
    }

    pub fn enumerate_handles_for_pid(target_pid: u32) -> anyhow::Result<Vec<HandleInfo>> {
        // ── 1. Call NtQuerySystemInformation with a growing buffer ────────────
        let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024); // 1 MB start
        let mut return_length: u32 = 0;

        loop {
            let cap = buffer.capacity();
            unsafe { buffer.set_len(cap) };

            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_HANDLE_INFORMATION,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut return_length,
                )
            };

            if status == STATUS_INFO_LENGTH_MISMATCH {
                let new_cap = (return_length as usize).max(cap * 2) + 65536;
                buffer = Vec::with_capacity(new_cap);
                continue;
            }

            if status.is_err() {
                return Err(anyhow::anyhow!(
                    "NtQuerySystemInformation failed: {:?}", status
                ));
            }

            break;
        }

        // ── 2. Parse raw handle entries ───────────────────────────────────────
        let info_ptr = buffer.as_ptr() as *const RawSystemHandleInformation;
        let count    = unsafe { (*info_ptr).number_of_handles } as usize;
        let handles_ptr = unsafe {
            std::ptr::addr_of!((*info_ptr).handles) as *const SystemHandleEntry
        };

        // ── 3. Open the target process for DuplicateHandle ───────────────────
        let target_proc = unsafe {
            OpenProcess(PROCESS_DUP_HANDLE, false, target_pid)
        }.map_err(|e| anyhow::anyhow!("OpenProcess({}) failed: {}", target_pid, e))?;

        let current_proc = unsafe { GetCurrentProcess() };

        let mut type_cache: HashMap<u8, String> = HashMap::new();
        let mut results: Vec<HandleInfo>         = Vec::new();

        for i in 0..count {
            let entry = unsafe { &*handles_ptr.add(i) };

            if entry.process_id as u32 != target_pid {
                continue;
            }

            let handle_value = entry.handle_value as u64;

            // ── 4. Duplicate the handle into our process ──────────────────────
            let raw_handle = HANDLE(entry.handle_value as usize as *mut std::ffi::c_void);
            let mut dup = HANDLE::default();
            let duped = unsafe {
                DuplicateHandle(
                    target_proc,
                    raw_handle,
                    current_proc,
                    &mut dup,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            }.is_ok();

            if !duped {
                results.push(HandleInfo {
                    handle_value,
                    object_type: type_from_cache(
                        entry.object_type_index, &mut type_cache, None,
                    ),
                    name: None,
                });
                continue;
            }

            // ── 5. Resolve type name ──────────────────────────────────────────
            let type_name = type_from_cache(
                entry.object_type_index, &mut type_cache, Some(dup),
            );

            // ── 6. Resolve object name (best-effort) ─────────────────────────
            // File handles are skipped — querying their names on synchronous
            // handles blocks indefinitely.
            let object_name = if type_name != "File" {
                query_object_name(dup)
            } else {
                None
            };

            unsafe { let _ = CloseHandle(dup); };

            results.push(HandleInfo { handle_value, object_type: type_name, name: object_name });
        }

        unsafe { let _ = CloseHandle(target_proc); };

        Ok(results)
    }

    // ── Type name helpers ─────────────────────────────────────────────────────

    fn type_from_cache(
        index: u8,
        cache: &mut HashMap<u8, String>,
        handle: Option<HANDLE>,
    ) -> String {
        if let Some(n) = cache.get(&index) {
            return n.clone();
        }
        let name = handle
            .and_then(query_object_type)
            .unwrap_or_else(|| format!("Type_{}", index));
        cache.insert(index, name.clone());
        name
    }

    fn query_object_type(handle: HANDLE) -> Option<String> {
        let mut buf = vec![0u8; 1024];
        let mut ret_len: u32 = 0;

        let status = unsafe {
            NtQueryObject(
                handle,
                ObjectTypeInformation,
                Some(buf.as_mut_ptr() as *mut _),
                buf.len() as u32,
                Some(&mut ret_len),
            )
        };
        if status.is_err() { return None; }

        let info  = buf.as_ptr() as *const PUBLIC_OBJECT_TYPE_INFORMATION;
        let us    = unsafe { (*info).TypeName };
        if us.Length == 0 { return None; }

        let slice = unsafe {
            std::slice::from_raw_parts(us.Buffer.0, us.Length as usize / 2)
        };
        Some(OsString::from_wide(slice).to_string_lossy().into_owned())
    }

    // ── Object name ──────────────────────────────────────────────────────────

    fn query_object_name(handle: HANDLE) -> Option<String> {
        let mut buf = vec![0u8; 512];
        let mut ret_len: u32 = 0;

        let status = unsafe {
            NtQueryObject(
                handle,
                OBJECT_NAME_INFORMATION_CLASS,
                Some(buf.as_mut_ptr() as *mut _),
                buf.len() as u32,
                Some(&mut ret_len),
            )
        };

        let status = if status == STATUS_INFO_LENGTH_MISMATCH {
            buf = vec![0u8; ret_len as usize + 64];
            unsafe {
                NtQueryObject(
                    handle,
                    OBJECT_NAME_INFORMATION_CLASS,
                    Some(buf.as_mut_ptr() as *mut _),
                    buf.len() as u32,
                    Some(&mut ret_len),
                )
            }
        } else {
            status
        };

        if status.is_err() { return None; }

        #[repr(C)]
        struct UnicodeString {
            length:          u16,
            maximum_length:  u16,
            _pad:            u32,
            buffer:          *const u16,
        }

        let us = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
        if us.length == 0 || us.buffer.is_null() { return None; }

        let buf_start = buf.as_ptr() as usize;
        let buf_end   = buf_start + buf.len();
        let str_start = us.buffer as usize;
        let str_end   = str_start + us.length as usize;

        if str_start < buf_start || str_end > buf_end { return None; }

        let slice = unsafe {
            std::slice::from_raw_parts(us.buffer, us.length as usize / 2)
        };
        let s = OsString::from_wide(slice).to_string_lossy().into_owned();
        if s.is_empty() { None } else { Some(s) }
    }
}

// ─── Heuristic helpers (consumed by the threat scorer in future stages) ───────

/// True if the handle list contains a Mutant (mutex) with a name pattern
/// associated with single-instance malware tricks.
pub fn has_suspicious_mutex(handles: &[HandleInfo]) -> bool {
    handles.iter().any(|h| {
        if h.object_type != "Mutant" { return false; }
        let Some(name) = &h.name else { return false; };
        let n = name.to_lowercase();
        n.contains("global\\") && (
            n.len() < 8
            || n.contains("mutex_")
            || n.contains("_mutex")
            || n.contains("lock_")
        )
    })
}

/// Count of open File handles — high counts can indicate ransomware
/// iterating through the filesystem.
pub fn open_file_handle_count(handles: &[HandleInfo]) -> usize {
    handles.iter().filter(|h| h.object_type == "File").count()
}

/// True if the process holds a handle to another process object — a common
/// indicator of code injection (PROCESS_VM_READ / PROCESS_VM_WRITE access).
pub fn has_cross_process_handle(handles: &[HandleInfo]) -> bool {
    handles.iter().any(|h| h.object_type == "Process")
}