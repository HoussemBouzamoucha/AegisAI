// File: src/core/process/api_parameters.rs
//
// Static knowledge base for Windows API calls:
//   - Semantic category for histogram features
//   - Graph edge signal each call implies (MemoryInjection, NetworkOwner, …)
//   - Parameter schema (names + "target" index)
//   - Runtime target-entity resolution: ApiCall → ParsedTarget
//
// This module is intentionally self-contained — it carries its own `ApiCall`
// and `ApiParam` types so that `ApiFeatureExtractor` can import from here
// without creating a circular dependency.

use std::collections::HashMap;

// ─── API semantic category ────────────────────────────────────────────────────

/// Semantic bucket used for category-count histogram features fed to the GRU.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ApiCategory {
    ProcessAccess,  // OpenProcess, NtOpenProcess, Read/WriteProcessMemory
    MemoryAllocate, // VirtualAllocEx, NtAllocateVirtualMemory
    MemoryWrite,    // WriteProcessMemory, NtWriteVirtualMemory
    MemoryProtect,  // VirtualProtectEx, NtProtectVirtualMemory
    RemoteThread,   // CreateRemoteThread, NtCreateThreadEx, NtQueueApcThread
    ProcessCreate,  // CreateProcess*, NtCreateProcess*
    FileExecute,    // ShellExecute*, WinExec  (execute file as new process)
    ProcessEnum,    // CreateToolhelp32Snapshot, NtQuerySystemInformation
    FileRead,       // CreateFile (R), ReadFile, NtCreateFile
    FileWrite,      // WriteFile, DeleteFile, MoveFileEx, CopyFile
    NetworkConnect, // connect, WSAConnect, InternetConnect*, socket init
    NetworkSend,    // send, WSASend, HttpSendRequest*
    NetworkReceive, // recv, WSARecv
    NetworkLookup,  // gethostbyname, GetAddrInfoW, DnsQuery_A
    TokenAccess,    // OpenProcessToken, AdjustTokenPrivileges, ImpersonateLoggedOnUser
    ServiceControl, // CreateService, ControlService
    Cryptography,   // CryptEncrypt/Decrypt, BCryptEncrypt/Decrypt
    RegistryRead,   // RegOpenKeyEx, RegQueryValueEx
    RegistryWrite,  // RegSetValueEx, RegDeleteValue
    Unknown,
}

// ─── Edge signal ──────────────────────────────────────────────────────────────

/// The threat-graph relationship this API call implies when used cross-process.
///
/// Variants mirror `graph::types::EdgeType`; use `EdgeSignal::to_str()` to
/// convert to the graph layer string key without importing the graph crate.
#[derive(Debug, Clone, PartialEq)]
pub enum EdgeSignal {
    /// RWX allocation + write into another process  — weight ×1.50
    MemoryInjection,
    /// This process owns a C2 network connection    — weight ×1.40
    NetworkOwner,
    /// Multiple processes reach the same C2 IP      — weight ×1.30
    SharedC2,
    /// This process opened a flagged file           — weight ×1.20
    ProcessOpenedFile,
    /// This process spawned another process         — weight ×1.10
    ParentChild,
    /// Two entities share the same OS PID           — weight ×1.00
    SameProcess,
    /// Two processes loaded the same file hash      — weight ×0.90
    SharedFileHash,
    /// No direct edge implied by this call
    None,
}

impl EdgeSignal {
    pub fn multiplier(&self) -> f32 {
        match self {
            Self::MemoryInjection   => 1.50,
            Self::NetworkOwner      => 1.40,
            Self::SharedC2          => 1.30,
            Self::ProcessOpenedFile => 1.20,
            Self::ParentChild       => 1.10,
            Self::SameProcess       => 1.00,
            Self::SharedFileHash    => 0.90,
            Self::None              => 0.00,
        }
    }

    /// String key matching `EdgeType::as_str()` in `graph/types.rs`.
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::MemoryInjection   => "memory_injection",
            Self::NetworkOwner      => "network_owner",
            Self::SharedC2          => "shared_c2",
            Self::ProcessOpenedFile => "process_opened_file",
            Self::ParentChild       => "parent_child",
            Self::SameProcess       => "same_process",
            Self::SharedFileHash    => "shared_file_hash",
            Self::None              => "none",
        }
    }
}

// ─── Runtime API call representation ─────────────────────────────────────────

/// A typed value captured from a live Windows API call parameter.
///
/// ETW providers and user-mode hooks serialize parameters differently; callers
/// convert raw data into the best-matching variant before passing it here.
#[derive(Debug, Clone)]
pub enum ApiParam {
    /// A resolved process identifier (e.g. dwProcessId, or ClientId.UniqueProcess).
    Pid(u32),
    /// An opaque Windows kernel handle.
    Handle(u64),
    /// A virtual memory address (allocation base, remote buffer pointer, …).
    Address(u64),
    /// A byte count or region size.
    Size(u64),
    /// A resolved filesystem path (from ObjectAttributes.ObjectName or raw LPSTR).
    Path(String),
    /// A resolved IP address string ("1.2.3.4" or "::1").
    Ip(String),
    /// A TCP/UDP port number (from sockaddr or nServerPort).
    Port(u16),
    /// A bit-flag integer (access rights, page-protection flags, …).
    Flags(u32),
    /// Unresolved 64-bit value (handle that hasn't been mapped to PID yet).
    Raw(u64),
}

/// A single Windows API call observed on a monitored process.
#[derive(Debug, Clone)]
pub struct ApiCall {
    /// API function name exactly as it appears in ntdll/kernel32 exports.
    pub name: String,
    /// PID of the process that made the call.
    pub pid: u32,
    /// Monotonic timestamp in milliseconds since engine start.
    pub timestamp_ms: u64,
    /// Positional parameters, typed.  Index corresponds to `ApiParameterSchema::params`.
    pub params: Vec<ApiParam>,
    /// NT / Win32 return value (0 / STATUS_SUCCESS = success; negative = error).
    pub return_value: Option<i64>,
}

// ─── Target entity resolution ─────────────────────────────────────────────────

/// The primary entity that a call targets — extracted from its parameters.
///
/// Used by `GraphBuilder` to create directed edges between the calling process
/// and the entity it interacts with.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedTarget {
    /// A specific OS process (target of injection, token theft, …).
    ProcessId(u32),
    /// A filesystem path (executable, dropped file, opened document).
    FilePath(String),
    /// A network endpoint (C2 server, DNS name, …).
    NetworkEndpoint { ip: String, port: u16 },
    /// A raw virtual memory address (when the handle can't be resolved to a PID).
    MemoryAddress(u64),
    /// Target cannot be determined from the available parameters.
    None,
}

// ─── Static per-API schema ────────────────────────────────────────────────────

/// Compile-time metadata for one Windows API.
#[derive(Debug, Clone)]
pub struct ApiParameterSchema {
    /// Semantic category for histogram features.
    pub category: ApiCategory,
    /// Graph edge this call implies when observed cross-process.
    pub edge_signal: EdgeSignal,
    /// Parameter names in declaration order (for display / documentation).
    pub params: &'static [&'static str],
    /// Index of the "target entity" parameter inside `ApiCall::params`.
    /// None when the target cannot be inferred from parameters alone.
    pub target_param_index: Option<usize>,
    /// Per-call threat contribution in [0, 1].
    /// Aggregated over the sequence to build the heuristic injection score.
    pub threat_weight: f32,
}

// ─── Knowledge base ───────────────────────────────────────────────────────────

/// Complete static registry of monitored Windows APIs.
pub struct ApiKnowledgeBase {
    entries: HashMap<&'static str, ApiParameterSchema>,
}

impl Default for ApiKnowledgeBase {
    fn default() -> Self { Self::new() }
}

impl ApiKnowledgeBase {
    pub fn new() -> Self {
        let mut m: HashMap<&'static str, ApiParameterSchema> = HashMap::with_capacity(80);

        macro_rules! reg {
            ($name:expr, $cat:expr, $sig:expr, $params:expr, $tgt:expr, $w:expr) => {
                m.insert($name, ApiParameterSchema {
                    category: $cat,
                    edge_signal: $sig,
                    params: $params,
                    target_param_index: $tgt,
                    threat_weight: $w,
                });
            };
        }

        // ── Process access ─────────────────────────────────────────────────
        reg!("OpenProcess",
            ApiCategory::ProcessAccess, EdgeSignal::MemoryInjection,
            &["dwDesiredAccess", "bInheritHandle", "dwProcessId"],
            Some(2), 0.60);
        reg!("NtOpenProcess",
            ApiCategory::ProcessAccess, EdgeSignal::MemoryInjection,
            &["ProcessHandle", "DesiredAccess", "ObjectAttributes", "ClientId"],
            Some(3), 0.70);
        reg!("ReadProcessMemory",
            ApiCategory::ProcessAccess, EdgeSignal::MemoryInjection,
            &["hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesRead"],
            Some(0), 0.60);
        reg!("NtReadVirtualMemory",
            ApiCategory::ProcessAccess, EdgeSignal::MemoryInjection,
            &["ProcessHandle", "BaseAddress", "Buffer", "NumberOfBytesToRead", "NumberOfBytesRead"],
            Some(0), 0.60);

        // ── Memory allocation ──────────────────────────────────────────────
        reg!("VirtualAllocEx",
            ApiCategory::MemoryAllocate, EdgeSignal::MemoryInjection,
            &["hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"],
            Some(0), 0.80);
        reg!("NtAllocateVirtualMemory",
            ApiCategory::MemoryAllocate, EdgeSignal::MemoryInjection,
            &["ProcessHandle", "BaseAddress", "ZeroBits", "RegionSize", "AllocationType", "Protect"],
            Some(0), 0.80);

        // ── Memory write ───────────────────────────────────────────────────
        reg!("WriteProcessMemory",
            ApiCategory::MemoryWrite, EdgeSignal::MemoryInjection,
            &["hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesWritten"],
            Some(0), 0.90);
        reg!("NtWriteVirtualMemory",
            ApiCategory::MemoryWrite, EdgeSignal::MemoryInjection,
            &["ProcessHandle", "BaseAddress", "Buffer", "NumberOfBytesToWrite", "NumberOfBytesWritten"],
            Some(0), 0.90);

        // ── Memory protection ──────────────────────────────────────────────
        reg!("VirtualProtectEx",
            ApiCategory::MemoryProtect, EdgeSignal::MemoryInjection,
            &["hProcess", "lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"],
            Some(0), 0.70);
        reg!("NtProtectVirtualMemory",
            ApiCategory::MemoryProtect, EdgeSignal::MemoryInjection,
            &["ProcessHandle", "BaseAddress", "RegionSize", "NewProtect", "OldProtect"],
            Some(0), 0.70);

        // ── Remote thread creation ─────────────────────────────────────────
        reg!("CreateRemoteThread",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["hProcess", "lpThreadAttributes", "dwStackSize", "lpStartAddress",
              "lpParameter", "dwCreationFlags", "lpThreadId"],
            Some(0), 1.00);
        reg!("NtCreateThreadEx",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["ThreadHandle", "DesiredAccess", "ObjectAttributes", "ProcessHandle",
              "StartRoutine", "Argument", "CreateFlags", "ZeroBits",
              "StackSize", "MaximumStackSize", "AttributeList"],
            Some(3), 1.00);
        reg!("RtlCreateUserThread",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["Process", "SecurityDescriptor", "CreateSuspended", "StackZeroBits",
              "StackReserved", "StackCommit", "StartAddress", "StartParameter",
              "ThreadHandle", "ClientId"],
            Some(0), 1.00);
        reg!("NtQueueApcThread",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["ThreadHandle", "ApcRoutine", "ApcArgument1", "ApcArgument2", "ApcArgument3"],
            Some(0), 0.85);
        reg!("SetThreadContext",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["hThread", "lpContext"],
            Some(0), 0.80);
        reg!("GetThreadContext",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["hThread", "lpContext"],
            Some(0), 0.50);
        reg!("SuspendThread",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["hThread"],
            Some(0), 0.50);
        reg!("ResumeThread",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["hThread"],
            Some(0), 0.50);
        reg!("NtResumeThread",
            ApiCategory::RemoteThread, EdgeSignal::MemoryInjection,
            &["ThreadHandle", "PreviousSuspendCount"],
            Some(0), 0.50);

        // ── Process creation ───────────────────────────────────────────────
        reg!("CreateProcessA",
            ApiCategory::ProcessCreate, EdgeSignal::ParentChild,
            &["lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes",
              "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory",
              "lpStartupInfo", "lpProcessInformation"],
            Some(0), 0.70);
        reg!("CreateProcessW",
            ApiCategory::ProcessCreate, EdgeSignal::ParentChild,
            &["lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes",
              "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory",
              "lpStartupInfo", "lpProcessInformation"],
            Some(0), 0.70);
        reg!("CreateProcessWithLogonW",
            ApiCategory::ProcessCreate, EdgeSignal::ParentChild,
            &["lpUsername", "lpDomain", "lpPassword", "dwLogonFlags", "lpApplicationName",
              "lpCommandLine", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory",
              "lpStartupInfo", "lpProcessInformation"],
            Some(4), 0.85);
        reg!("CreateProcessWithTokenW",
            ApiCategory::ProcessCreate, EdgeSignal::ParentChild,
            &["hToken", "dwLogonFlags", "lpApplicationName", "lpCommandLine",
              "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory",
              "lpStartupInfo", "lpProcessInformation"],
            Some(2), 0.85);
        reg!("NtCreateProcess",
            ApiCategory::ProcessCreate, EdgeSignal::ParentChild,
            &["ProcessHandle", "DesiredAccess", "ObjectAttributes", "ParentProcess",
              "InheritObjectTable", "SectionHandle", "DebugPort", "ExceptionPort"],
            Some(3), 0.70);
        reg!("NtCreateProcessEx",
            ApiCategory::ProcessCreate, EdgeSignal::ParentChild,
            &["ProcessHandle", "DesiredAccess", "ObjectAttributes", "ParentProcess",
              "Flags", "SectionHandle", "DebugPort", "ExceptionPort", "JobMemberLevel"],
            Some(3), 0.70);
        reg!("ShellExecuteA",
            ApiCategory::FileExecute, EdgeSignal::ParentChild,
            &["hwnd", "lpOperation", "lpFile", "lpParameters", "lpDirectory", "nShowCmd"],
            Some(2), 0.70);
        reg!("ShellExecuteW",
            ApiCategory::FileExecute, EdgeSignal::ParentChild,
            &["hwnd", "lpOperation", "lpFile", "lpParameters", "lpDirectory", "nShowCmd"],
            Some(2), 0.70);
        reg!("WinExec",
            ApiCategory::FileExecute, EdgeSignal::ParentChild,
            &["lpCmdLine", "uCmdShow"],
            Some(0), 0.80);

        // ── Process enumeration / reconnaissance ──────────────────────────
        reg!("CreateToolhelp32Snapshot",
            ApiCategory::ProcessEnum, EdgeSignal::SameProcess,
            &["dwFlags", "th32ProcessID"],
            Some(1), 0.30);
        reg!("Process32FirstW",
            ApiCategory::ProcessEnum, EdgeSignal::SameProcess,
            &["hSnapshot", "lppe"],
            None, 0.30);
        reg!("Process32NextW",
            ApiCategory::ProcessEnum, EdgeSignal::SameProcess,
            &["hSnapshot", "lppe"],
            None, 0.30);
        reg!("NtQuerySystemInformation",
            ApiCategory::ProcessEnum, EdgeSignal::SameProcess,
            &["SystemInformationClass", "SystemInformation", "SystemInformationLength", "ReturnLength"],
            None, 0.20);
        reg!("NtQueryInformationProcess",
            ApiCategory::ProcessEnum, EdgeSignal::SameProcess,
            &["ProcessHandle", "ProcessInformationClass", "ProcessInformation",
              "ProcessInformationLength", "ReturnLength"],
            Some(0), 0.30);

        // ── File I/O ───────────────────────────────────────────────────────
        reg!("CreateFileA",
            ApiCategory::FileRead, EdgeSignal::ProcessOpenedFile,
            &["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes",
              "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile"],
            Some(0), 0.40);
        reg!("CreateFileW",
            ApiCategory::FileRead, EdgeSignal::ProcessOpenedFile,
            &["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes",
              "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile"],
            Some(0), 0.40);
        reg!("NtCreateFile",
            ApiCategory::FileRead, EdgeSignal::ProcessOpenedFile,
            &["FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock",
              "AllocationSize", "FileAttributes", "ShareAccess", "CreateDisposition",
              "CreateOptions", "EaBuffer", "EaLength"],
            Some(2), 0.40);
        reg!("ReadFile",
            ApiCategory::FileRead, EdgeSignal::ProcessOpenedFile,
            &["hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "lpOverlapped"],
            None, 0.30);
        reg!("WriteFile",
            ApiCategory::FileWrite, EdgeSignal::ProcessOpenedFile,
            &["hFile", "lpBuffer", "nNumberOfBytesToWrite", "lpNumberOfBytesWritten", "lpOverlapped"],
            None, 0.50);
        reg!("NtWriteFile",
            ApiCategory::FileWrite, EdgeSignal::ProcessOpenedFile,
            &["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock",
              "Buffer", "Length", "ByteOffset", "Key"],
            None, 0.50);
        reg!("DeleteFileA",
            ApiCategory::FileWrite, EdgeSignal::ProcessOpenedFile,
            &["lpFileName"], Some(0), 0.60);
        reg!("DeleteFileW",
            ApiCategory::FileWrite, EdgeSignal::ProcessOpenedFile,
            &["lpFileName"], Some(0), 0.60);
        reg!("MoveFileExA",
            ApiCategory::FileWrite, EdgeSignal::ProcessOpenedFile,
            &["lpExistingFileName", "lpNewFileName", "dwFlags"],
            Some(0), 0.50);
        reg!("MoveFileExW",
            ApiCategory::FileWrite, EdgeSignal::ProcessOpenedFile,
            &["lpExistingFileName", "lpNewFileName", "dwFlags"],
            Some(0), 0.50);
        reg!("CopyFileA",
            ApiCategory::FileWrite, EdgeSignal::ProcessOpenedFile,
            &["lpExistingFileName", "lpNewFileName", "bFailIfExists"],
            Some(0), 0.40);
        reg!("CopyFileW",
            ApiCategory::FileWrite, EdgeSignal::ProcessOpenedFile,
            &["lpExistingFileName", "lpNewFileName", "bFailIfExists"],
            Some(0), 0.40);

        // ── Network / C2 ───────────────────────────────────────────────────
        reg!("connect",
            ApiCategory::NetworkConnect, EdgeSignal::NetworkOwner,
            &["s", "name", "namelen"],
            Some(1), 0.70);
        reg!("WSAConnect",
            ApiCategory::NetworkConnect, EdgeSignal::NetworkOwner,
            &["s", "name", "namelen", "lpCallerData", "lpCalleeData", "lpSQOS", "lpGQOS"],
            Some(1), 0.70);
        reg!("InternetConnectA",
            ApiCategory::NetworkConnect, EdgeSignal::NetworkOwner,
            &["hInternet", "lpszServerName", "nServerPort", "lpszUserName",
              "lpszPassword", "dwService", "dwFlags", "dwContext"],
            Some(1), 0.70);
        reg!("InternetConnectW",
            ApiCategory::NetworkConnect, EdgeSignal::NetworkOwner,
            &["hInternet", "lpszServerName", "nServerPort", "lpszUserName",
              "lpszPassword", "dwService", "dwFlags", "dwContext"],
            Some(1), 0.70);
        reg!("InternetOpenA",
            ApiCategory::NetworkConnect, EdgeSignal::NetworkOwner,
            &["lpszAgent", "dwAccessType", "lpszProxy", "lpszProxyBypass", "dwFlags"],
            None, 0.50);
        reg!("InternetOpenW",
            ApiCategory::NetworkConnect, EdgeSignal::NetworkOwner,
            &["lpszAgent", "dwAccessType", "lpszProxy", "lpszProxyBypass", "dwFlags"],
            None, 0.50);
        reg!("send",
            ApiCategory::NetworkSend, EdgeSignal::NetworkOwner,
            &["s", "buf", "len", "flags"],
            None, 0.50);
        reg!("WSASend",
            ApiCategory::NetworkSend, EdgeSignal::NetworkOwner,
            &["s", "lpBuffers", "dwBufferCount", "lpNumberOfBytesSent",
              "dwFlags", "lpOverlapped", "lpCompletionRoutine"],
            None, 0.50);
        reg!("HttpSendRequestA",
            ApiCategory::NetworkSend, EdgeSignal::NetworkOwner,
            &["hRequest", "lpszHeaders", "dwHeadersLength", "lpOptional", "dwOptionalLength"],
            None, 0.50);
        reg!("HttpSendRequestW",
            ApiCategory::NetworkSend, EdgeSignal::NetworkOwner,
            &["hRequest", "lpszHeaders", "dwHeadersLength", "lpOptional", "dwOptionalLength"],
            None, 0.50);
        reg!("recv",
            ApiCategory::NetworkReceive, EdgeSignal::NetworkOwner,
            &["s", "buf", "len", "flags"],
            None, 0.40);
        reg!("WSARecv",
            ApiCategory::NetworkReceive, EdgeSignal::NetworkOwner,
            &["s", "lpBuffers", "dwBufferCount", "lpNumberOfBytesRecvd",
              "lpFlags", "lpOverlapped", "lpCompletionRoutine"],
            None, 0.40);
        reg!("gethostbyname",
            ApiCategory::NetworkLookup, EdgeSignal::NetworkOwner,
            &["name"], Some(0), 0.40);
        reg!("GetAddrInfoW",
            ApiCategory::NetworkLookup, EdgeSignal::NetworkOwner,
            &["pNodeName", "pServiceName", "pHints", "ppResult"],
            Some(0), 0.40);
        reg!("DnsQuery_A",
            ApiCategory::NetworkLookup, EdgeSignal::NetworkOwner,
            &["pszName", "wType", "Options", "pExtra", "ppQueryResults", "pReserved"],
            Some(0), 0.40);

        // ── Token / privilege escalation ───────────────────────────────────
        reg!("OpenProcessToken",
            ApiCategory::TokenAccess, EdgeSignal::MemoryInjection,
            &["ProcessHandle", "DesiredAccess", "TokenHandle"],
            Some(0), 0.60);
        reg!("AdjustTokenPrivileges",
            ApiCategory::TokenAccess, EdgeSignal::MemoryInjection,
            &["TokenHandle", "DisableAllPrivileges", "NewState",
              "BufferLength", "PreviousState", "ReturnLength"],
            None, 0.70);
        reg!("ImpersonateLoggedOnUser",
            ApiCategory::TokenAccess, EdgeSignal::MemoryInjection,
            &["hToken"], None, 0.80);
        reg!("DuplicateTokenEx",
            ApiCategory::TokenAccess, EdgeSignal::MemoryInjection,
            &["hExistingToken", "dwDesiredAccess", "lpTokenAttributes",
              "ImpersonationLevel", "TokenType", "phNewToken"],
            None, 0.70);

        // ── Registry ───────────────────────────────────────────────────────
        reg!("RegOpenKeyExA",
            ApiCategory::RegistryRead, EdgeSignal::None,
            &["hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult"],
            Some(1), 0.20);
        reg!("RegOpenKeyExW",
            ApiCategory::RegistryRead, EdgeSignal::None,
            &["hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult"],
            Some(1), 0.20);
        reg!("RegSetValueExA",
            ApiCategory::RegistryWrite, EdgeSignal::None,
            &["hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData"],
            Some(1), 0.50);
        reg!("RegSetValueExW",
            ApiCategory::RegistryWrite, EdgeSignal::None,
            &["hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData"],
            Some(1), 0.50);
        reg!("RegQueryValueExA",
            ApiCategory::RegistryRead, EdgeSignal::None,
            &["hKey", "lpValueName", "lpReserved", "lpType", "lpData", "lpcbData"],
            Some(1), 0.20);
        reg!("RegQueryValueExW",
            ApiCategory::RegistryRead, EdgeSignal::None,
            &["hKey", "lpValueName", "lpReserved", "lpType", "lpData", "lpcbData"],
            Some(1), 0.20);

        // ── Services / persistence ─────────────────────────────────────────
        reg!("CreateServiceA",
            ApiCategory::ServiceControl, EdgeSignal::None,
            &["hSCManager", "lpServiceName", "lpDisplayName", "dwDesiredAccess",
              "dwServiceType", "dwStartType", "dwErrorControl", "lpBinaryPathName",
              "lpLoadOrderGroup", "lpdwTagId", "lpDependencies",
              "lpServiceStartName", "lpPassword"],
            Some(7), 0.80);
        reg!("CreateServiceW",
            ApiCategory::ServiceControl, EdgeSignal::None,
            &["hSCManager", "lpServiceName", "lpDisplayName", "dwDesiredAccess",
              "dwServiceType", "dwStartType", "dwErrorControl", "lpBinaryPathName",
              "lpLoadOrderGroup", "lpdwTagId", "lpDependencies",
              "lpServiceStartName", "lpPassword"],
            Some(7), 0.80);
        reg!("ControlService",
            ApiCategory::ServiceControl, EdgeSignal::None,
            &["hService", "dwControl", "lpServiceStatus"],
            Some(0), 0.50);

        // ── Cryptography ───────────────────────────────────────────────────
        reg!("CryptEncrypt",
            ApiCategory::Cryptography, EdgeSignal::None,
            &["hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen", "dwBufLen"],
            None, 0.60);
        reg!("BCryptEncrypt",
            ApiCategory::Cryptography, EdgeSignal::None,
            &["hKey", "pbInput", "cbInput", "pPaddingInfo", "pbIV", "cbIV",
              "pbOutput", "cbOutput", "pcbResult", "dwFlags"],
            None, 0.60);
        reg!("CryptDecrypt",
            ApiCategory::Cryptography, EdgeSignal::None,
            &["hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen"],
            None, 0.40);
        reg!("BCryptDecrypt",
            ApiCategory::Cryptography, EdgeSignal::None,
            &["hKey", "pbInput", "cbInput", "pPaddingInfo", "pbIV", "cbIV",
              "pbOutput", "cbOutput", "pcbResult", "dwFlags"],
            None, 0.40);

        Self { entries: m }
    }

    // ── Query methods ──────────────────────────────────────────────────────────

    /// Schema for a named API, or `None` if not in the registry.
    pub fn get(&self, api_name: &str) -> Option<&ApiParameterSchema> {
        self.entries.get(api_name)
    }

    /// Edge signal implied by this API call.
    pub fn edge_signal_for(&self, api_name: &str) -> EdgeSignal {
        self.entries
            .get(api_name)
            .map(|s| s.edge_signal.clone())
            .unwrap_or(EdgeSignal::None)
    }

    /// Per-call threat weight for this API.
    pub fn threat_weight_for(&self, api_name: &str) -> f32 {
        self.entries
            .get(api_name)
            .map(|s| s.threat_weight)
            .unwrap_or(0.0)
    }

    /// All registered API names that emit a specific edge signal.
    pub fn apis_for_signal(&self, signal: &EdgeSignal) -> Vec<&'static str> {
        self.entries
            .iter()
            .filter(|(_, s)| &s.edge_signal == signal)
            .map(|(name, _)| *name)
            .collect()
    }

    // ── Target resolution ──────────────────────────────────────────────────────

    /// Resolve the primary target entity from a captured API call.
    ///
    /// Uses `ApiParameterSchema::target_param_index` to pick the relevant
    /// parameter from `call.params`, then interprets it by category.
    ///
    /// # Example
    /// ```
    /// // OpenProcess(PROCESS_ALL_ACCESS, false, 1234)
    /// //   → ParsedTarget::ProcessId(1234)
    /// //
    /// // CreateFileW("C:\\malware.exe", …)
    /// //   → ParsedTarget::FilePath("C:\\malware.exe")
    /// //
    /// // InternetConnectW(_, "192.168.1.100", 4444, …)
    /// //   → ParsedTarget::NetworkEndpoint { ip: "192.168.1.100", port: 0 }
    /// ```
    pub fn resolve_target(&self, call: &ApiCall) -> ParsedTarget {
        let schema = match self.entries.get(call.name.as_str()) {
            Some(s) => s,
            None => return ParsedTarget::None,
        };
        let idx = match schema.target_param_index {
            Some(i) => i,
            None => return ParsedTarget::None,
        };
        let param = match call.params.get(idx) {
            Some(p) => p,
            None => return ParsedTarget::None,
        };

        match schema.category {
            // Cross-process memory/thread ops → target is always a process
            ApiCategory::ProcessAccess
            | ApiCategory::MemoryAllocate
            | ApiCategory::MemoryWrite
            | ApiCategory::MemoryProtect
            | ApiCategory::RemoteThread
            | ApiCategory::TokenAccess => match param {
                ApiParam::Pid(pid)      => ParsedTarget::ProcessId(*pid),
                ApiParam::Handle(h)     => ParsedTarget::MemoryAddress(*h),
                _                       => ParsedTarget::None,
            },

            // File/execution/registry/service ops → target is a filesystem path
            ApiCategory::ProcessCreate
            | ApiCategory::FileExecute
            | ApiCategory::FileRead
            | ApiCategory::FileWrite
            | ApiCategory::RegistryRead
            | ApiCategory::RegistryWrite
            | ApiCategory::ServiceControl => match param {
                ApiParam::Path(p) => ParsedTarget::FilePath(p.clone()),
                _                 => ParsedTarget::None,
            },

            // Network ops → target is a remote endpoint
            ApiCategory::NetworkConnect
            | ApiCategory::NetworkSend
            | ApiCategory::NetworkLookup => match param {
                ApiParam::Ip(ip)     => ParsedTarget::NetworkEndpoint { ip: ip.clone(), port: 0 },
                ApiParam::Path(host) => ParsedTarget::NetworkEndpoint { ip: host.clone(), port: 0 },
                _                    => ParsedTarget::None,
            },

            _ => ParsedTarget::None,
        }
    }
}
