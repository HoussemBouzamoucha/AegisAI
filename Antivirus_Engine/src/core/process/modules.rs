// File: src/core/process_scanner/modules.rs
// Stage 3: Loaded DLL / module enumeration per process.

use super::types::ModuleInfo;

#[cfg(target_os = "windows")]
use windows::{
    Win32::Foundation::{CloseHandle, HANDLE, HMODULE, MAX_PATH},
    Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
    },
    Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
};

/// Enumerate all loaded modules (DLLs) for a given process.
pub fn enumerate_modules(pid: u32) -> Vec<ModuleInfo> {
    #[cfg(target_os = "windows")]
    {
        enumerate_modules_windows(pid)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        vec![]
    }
}

#[cfg(target_os = "windows")]
fn enumerate_modules_windows(pid: u32) -> Vec<ModuleInfo> {
    use std::mem;
    use std::ptr;

    let mut modules = Vec::new();

    unsafe {
        // Open process with query and read permissions.
        let process_handle = match OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        ) {
            Ok(handle) => handle,
            Err(_) => return modules,
        };

        // RAII guard — ensures the handle is always closed.
        let _guard = HandleGuard(process_handle);

        // ── First call: get required buffer size ───────────────────────────
        let mut bytes_needed: u32 = 0;
        let _ = EnumProcessModules(
            process_handle,
            ptr::null_mut(),
            0,
            &mut bytes_needed,
        );

        if bytes_needed == 0 {
            return modules;
        }

        let module_count = bytes_needed as usize / mem::size_of::<HMODULE>();

        // Allocate buffer safely (no uninitialized UB)
        let mut module_handles: Vec<HMODULE> = vec![HMODULE::default(); module_count];

        // ── Second call: fill buffer ───────────────────────────────────────
        if EnumProcessModules(
            process_handle,
            module_handles.as_mut_ptr(),
            bytes_needed,
            &mut bytes_needed,
        )
        .is_err()
        {
            return modules;
        }

        // Recompute count (Windows can return fewer modules)
        let actual_count = (bytes_needed as usize / mem::size_of::<HMODULE>())
            .min(module_handles.len());

        for &module_handle in module_handles.iter().take(actual_count) {
            // ── Get module path ───────────────────────────────────────────
            let mut path_buffer = [0u16; MAX_PATH as usize];

            let path_len = GetModuleFileNameExW(
                process_handle,   // ✅ FIXED
                module_handle,    // ✅ FIXED
                &mut path_buffer,
            );

            if path_len == 0 {
                continue;
            }

            let path =
                String::from_utf16_lossy(&path_buffer[..path_len as usize]);

            // ── Get module info ───────────────────────────────────────────
            let mut mod_info: MODULEINFO = mem::zeroed();

            if GetModuleInformation(
                process_handle,
                module_handle,
                &mut mod_info,
                mem::size_of::<MODULEINFO>() as u32,
            )
            .is_err()
            {
                continue;
            }

            // ── Extract filename ──────────────────────────────────────────
            let name = path
                .rsplit('\\')
                .next()
                .unwrap_or(&path)
                .to_string();

            let is_suspicious = is_module_suspicious(&path, &name);

            modules.push(ModuleInfo {
                name,
                path: Some(path),
                base_address: mod_info.lpBaseOfDll as u64,
                size: mod_info.SizeOfImage as u64,
                is_suspicious,
            });
        }
    }

    modules
}

/// Determine whether a module looks suspicious based on its path and name.
#[cfg(target_os = "windows")]
fn is_module_suspicious(path: &str, name: &str) -> bool {
    let path_lower = path.to_lowercase();
    let name_lower = name.to_lowercase();

    // Known-safe system directory prefixes.
    let system_paths = [
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\program files",
        "c:\\program files (x86)",
    ];

    let in_system_path = system_paths
        .iter()
        .any(|sys_path| path_lower.starts_with(sys_path));

    let suspicious_indicators = [
        // Temporary / writable directories.
        path_lower.contains("\\temp\\"),
        path_lower.contains("\\tmp\\"),
        path_lower.contains("\\appdata\\local\\temp"),
        path_lower.contains("\\downloads\\"),
        path_lower.contains("\\desktop\\"),

        // Recycle bin / explicitly hidden paths.
        path_lower.contains("\\$recycle.bin"),
        // Fix #7: only flag the double-dot traversal pattern, not every `\.`
        // (which would match versioned paths like `\v1.2\`).
        path_lower.contains("\\..\\"),

        // Suspicious DLL name keywords.
        name_lower.contains("inject"),
        name_lower.contains("hook"),
        name_lower.contains("patch"),
        name_lower.contains("crack"),
        name_lower.contains("keygen"),

        // Heuristic: random-looking name.
        is_random_looking_name(&name_lower),
    ];

    let suspicious_count = suspicious_indicators.iter().filter(|&&x| x).count();

    (!in_system_path && suspicious_count > 0) || suspicious_count >= 2
}

/// Heuristic: returns true if the DLL name looks randomly generated.
///
/// A name is considered random-looking when either:
/// - More than half of its (non-extension) characters are digits, or
/// - It is longer than 8 characters but contains fewer than 4 alphabetic chars.
// Fix #6: gate with #[cfg(windows)] so it compiles only where it is used.
#[cfg(target_os = "windows")]
fn is_random_looking_name(name: &str) -> bool {
    if name.len() < 8 {
        return false;
    }

    let stem = name.trim_end_matches(".dll");
    let total = stem.len();
    let digits = stem.chars().filter(|c| c.is_ascii_digit()).count();
    let alphas = stem.chars().filter(|c| c.is_ascii_alphabetic()).count();

    digits > total / 2 || (alphas < 4 && total > 8)
}

/// RAII guard — closes a Windows HANDLE on drop.
#[cfg(target_os = "windows")]
struct HandleGuard(HANDLE);

#[cfg(target_os = "windows")]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            // Fix #3: only close if the handle is valid.
            if !self.0.is_invalid() {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_suspicious_name_detection() {
        assert!(is_random_looking_name("a1b2c3d4e5f6.dll"));
        assert!(is_random_looking_name("12345678.dll"));
        assert!(!is_random_looking_name("kernel32.dll"));
        assert!(!is_random_looking_name("user32.dll"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_module_suspicious_paths() {
        assert!(!is_module_suspicious(
            "C:\\Windows\\System32\\kernel32.dll",
            "kernel32.dll"
        ));
        assert!(is_module_suspicious(
            "C:\\Users\\Test\\AppData\\Local\\Temp\\malware.dll",
            "malware.dll"
        ));
        assert!(is_module_suspicious(
            "C:\\Users\\Test\\Downloads\\suspicious.dll",
            "suspicious.dll"
        ));
        assert!(is_module_suspicious(
            "C:\\SomeDir\\inject_helper.dll",
            "inject_helper.dll"
        ));
        // Fix #7 regression: versioned paths must NOT be flagged.
        assert!(!is_module_suspicious(
            "C:\\Program Files\\MyApp\\v1.2\\mylib.dll",
            "mylib.dll"
        ));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_enumerate_current_process() {
        use std::process;

        let pid = process::id();
        let modules = enumerate_modules(pid);

        assert!(!modules.is_empty());

        let has_system_dll = modules.iter().any(|m| {
            m.name.to_lowercase().contains("kernel32")
                || m.name.to_lowercase().contains("ntdll")
        });
        assert!(has_system_dll);

        // Every entry must have a path (the Windows impl always sets Some).
        assert!(modules.iter().all(|m| m.path.is_some()));
    }
}