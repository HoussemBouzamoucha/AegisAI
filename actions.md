# AegisAI — Post-Verdict Response Actions

Defines what must happen after the graph outputs a **Malicious** or **Critical** verdict.
Actions are grouped by severity tier, then by attack pattern.
Implementation status is marked for each action.

---

## Trigger Conditions

| Verdict severity | Trigger |
|---|---|
| `Clean` | No action. |
| `Suspicious` | Investigate only — no containment yet. |
| `Malicious` | Containment actions apply. Requires user confirmation unless autonomous mode is on. |
| `Critical` | Same as Malicious but escalated urgency. Critical path score ≥ 0.80 or MultiStageAttack detected. |

---

## Severity-Based Response Tiers

### Tier 1 — Suspicious
Investigation only. Do not terminate or quarantine.

1. Log the full graph verdict JSON (chains, critical path, node scores) to the history store.
2. Flag the involved entities in the UI with a "Under investigation" badge.
3. Schedule a re-correlation in 60 seconds to detect score drift.
4. Surface pivot suggestions (see per-pattern section below).

### Tier 2 — Malicious
Containment required. Default: user must confirm each action in the UI.

1. **Terminate** all processes on the critical path (via `kill-process` daemon command).
2. **Quarantine** any file entity with `has_malicious_file = true` (move to isolated quarantine folder, rename extension).
3. **Log** full graph state + all involved entity IDs + timestamp to incident history.
4. Re-correlate with `include_memory: true` after termination to confirm the chain is broken.

### Tier 3 — Critical
Same as Tier 2 plus:

1. **Isolate host** from the network (disable active network interfaces — requires elevated privilege).
2. **Dump memory** of all involved processes before termination (for forensic preservation).
3. **Alert** the user immediately (system notification + UI banner).
4. **Do not automatically clean up** — preserve all artifacts until the user reviews.

---

## Per-Pattern Actions

### ProcessInjection (T1055)
Triggered when: `node.has_malicious_memory == true`

1. Terminate the injected process (`kill-process {pid}`).
2. Dump the process memory before termination if Critical tier.
3. Scan the parent process for injection source: `scan-memory {parent_pid}`.
4. Pivot: check if the parent has a `SharedFileHash` or `ParentChild` edge to another threat entity.
5. Look for common injection tools in `%TEMP%`, `%APPDATA%`, `%SYSTEMROOT%\Temp`.

### C2Communication (T1071)
Triggered when: `node.has_malicious_network == true`

1. Block all outbound connections from the process (`kill-process {pid}` if no legitimate use).
2. Record the remote IP and port from the network entity's `remote_address` field.
3. Add the remote IP to the local Windows Firewall blocklist (outbound rule).
4. Run `scan-network` again after blocking to confirm no surviving C2 connection.
5. Pivot: check if any other process is connecting to the same remote IP (`SharedC2` edge detection).

### MalwareExecution (T1204)
Triggered when: `node.has_malicious_file == true`

1. Terminate the process running the malicious file.
2. Quarantine the file: move to `%SYSTEMROOT%\AegisAI\quarantine\` with `.quarantined` extension.
3. Record SHA-256 hash for IOC feed submission.
4. Scan the parent directory of the file: `scan-dir {parent_path}`.
5. Check for persistence: scan `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` and common registry run keys.

### LateralMovement (T1021)
Triggered when: `ParentChild` edge + `child.has_malicious_network == true`

1. Terminate child process first (`kill-process {child_pid}`), then parent.
2. Scan all sibling processes (same parent PID) for similar network signals.
3. Check if the parent process has written any files recently (pivot: `scan-dir` on parent's working directory).
4. Investigate destination IPs — flag internal IPs (RFC 1918 ranges) as potential lateral spread targets.
5. Re-correlate with `include_memory: true` to detect if injection was used to cross process boundaries.

### SuspiciousSpawn (T1059)
Triggered when: `ParentChild` edge + both parent and child are threat-level

1. Terminate child process first to stop propagation.
2. Terminate parent process if it has no legitimate identity (i.e., not a known system binary).
3. If parent is a trusted binary (e.g., `explorer.exe`, `svchost.exe`): mark as **ExploitedTrustedProcess** instead — do not terminate the trusted process, only the child.
4. Scan the child's executable: `scan-file {child_exe_path}`.
5. Pivot: look for additional children with the same parent PID.

### MultiStageAttack (TA0002)
Triggered when: BFS over threat entities finds ≥ 3 linked threat nodes

1. Escalate immediately to Critical tier regardless of individual chain scores.
2. Terminate all processes on the attack chain, in reverse topological order (leaves first).
3. Quarantine all files associated with threat entities.
4. Dump memory for all involved processes.
5. After termination: full re-correlation to verify no surviving branches.
6. Log a structured incident report (attack chain map, MITRE tactics, all PIDs, file hashes, remote IPs).

### ExploitedTrustedProcess (T1059 / T1204)
Triggered when: parent is Clean + child is Malicious (`is_vector = true` on parent node)

1. **Do not terminate the trusted parent** (e.g., `powershell.exe`, `wscript.exe`, `mshta.exe` running legitimately).
2. Terminate the malicious child process only.
3. Quarantine the child's executable.
4. Scan the command-line arguments used to spawn the child (if available from process scan).
5. Check for LOLBin patterns: if the trusted parent is in the LOLBins list, flag it as a living-off-the-land delivery vector.
6. Re-scan the parent's memory for injected shellcode after child termination.

---

## Investigation Pivots (All Patterns)

These pivots are run after the verdict to gather additional evidence before containment.
The AI agent (when implemented) will emit these as targeted scan requests.

| Signal | Pivot action |
|---|---|
| Process has `has_malicious_network` | `scan-network {pid}` — confirm active connections |
| Process has `has_malicious_memory` | `scan-memory {pid}` — deep dive into malicious regions |
| File entity found | `scan-dir {parent_directory}` — look for sibling payloads |
| Parent process is vector (`is_vector`) | Re-correlate with `include_memory: true` |
| `SharedC2` edge between two entities | Cross-check all processes connecting to that remote IP |
| Critical path score ≥ 0.80 | Full re-correlate after containment to confirm chain is broken |
| MultiStageAttack detected | `scan-dir %TEMP%`, `%APPDATA%`, `%SYSTEMROOT%\Temp` |

---

## Currently Supported Actions (Daemon API)

| Action | Daemon command | Status |
|---|---|---|
| Kill a process | `kill-process {pid}` | ✅ Implemented |
| Targeted memory scan | `scan-memory {pid}` | ✅ Implemented |
| Targeted network scan | `scan-network {pid}` | ✅ Implemented |
| Targeted file scan | `scan-file {path}` | ✅ Implemented |
| Directory scan | `scan-dir {path}` | ✅ Implemented |
| Full re-correlation | `correlate {include_memory}` | ✅ Implemented |

---

## Actions Not Yet Implemented (Planned)

| Action | What needs to be built |
|---|---|
| File quarantine | Move file to isolated folder, rename to `.quarantined`, log hash |
| Network block (firewall rule) | Call Windows Firewall API to add outbound deny rule for remote IP |
| Host network isolation | Disable all network interfaces via WinAPI or `netsh` |
| Memory dump | `MiniDumpWriteDump` on target PID before termination |
| Persistence check | Scan registry run keys + scheduled tasks + startup folder |
| LOLBin detection | Maintain list of common living-off-the-land binaries; flag when they appear as vector nodes |
| Incident report export | Serialize graph verdict + actions taken to a structured JSON/PDF report |
| Autonomous mode | User-opt-in flag that skips confirmation dialogs for Malicious-tier actions |

---

## Decision Flowchart

```
Graph outputs verdict
        │
        ▼
  severity == Clean? ──────────────────────► No action. Done.
        │ no
        ▼
  severity == Suspicious? ─────────────────► Log + re-correlate in 60s. Surface pivots. Done.
        │ no (Malicious or Critical)
        ▼
  Is autonomous mode ON?
        │ yes                    │ no
        ▼                        ▼
  Execute actions          Show confirmation dialog
  immediately              User approves → execute
                           User rejects → log only
        │
        ▼
  Terminate processes (critical path first, leaves first)
        │
        ▼
  Quarantine malicious files
        │
        ▼
  Block C2 IPs (if C2Communication chain present)
        │
        ▼
  severity == Critical?
        │ yes                    │ no
        ▼                        ▼
  Dump memory             Skip memory dump
  Isolate host
        │
        ▼
  Re-correlate (include_memory: true)
        │
        ▼
  Any surviving chains?
        │ yes                    │ no
        ▼                        ▼
  Repeat containment       Log incident report. Investigation closed.
```

---

## Preservation Rules

Before any destructive action (process termination, file deletion):

1. Record PID, process name, exe path, command line, parent PID.
2. Record all network connections (remote IPs, ports, protocols).
3. Record the graph verdict JSON at the moment of the decision.
4. If Critical tier: dump process memory before termination.
5. Never delete quarantined files — only move and rename. Deletion requires explicit user action.

---

## Implementation Details

How each action is built: the layer it lives in, the API or tool it calls, and the logic it follows.

---

### Kill a Process
**Already implemented** via the `kill-process` daemon command.

**Layer:** Rust daemon → `Antivirus_Engine/src/main.rs`

**How it works:**
1. The UI calls `invoke('kill_process', { pid })` over Tauri IPC.
2. Tauri sends `{ "cmd": "kill-process", "pid": N }` to the daemon over stdin JSON-RPC.
3. The daemon calls `OpenProcess(PROCESS_TERMINATE, false, pid)` then `TerminateProcess(handle, 1)` using the `windows` crate.
4. Returns `{ "status": "ok" }` or an error string.

**Privilege note:** requires the daemon to be running with sufficient rights. For system-level processes (e.g., injected into `svchost.exe`) the daemon may need to call `AdjustTokenPrivileges` to enable `SeDebugPrivilege` first.

---

### File Quarantine
**Not yet implemented.**

**New daemon command:** `quarantine-file { path: String }`

**Layer:** Rust daemon → new handler in `main.rs`, file I/O via `std::fs`

**How it works:**
1. UI calls `invoke('quarantine_file', { path })`.
2. Tauri forwards to daemon as `{ "cmd": "quarantine-file", "path": "..." }`.
3. Daemon handler:
   a. Reads the file and computes SHA-256 (reuse the existing hasher in `file_system/` scanner).
   b. Creates the quarantine directory if missing: `%PROGRAMDATA%\AegisAI\quarantine\` (writable without elevation on most configurations; falls back to `%TEMP%\AegisAI\quarantine\`).
   c. Destination filename: `{sha256_hex}.quarantined` — the extension change alone prevents accidental execution.
   d. Calls `std::fs::rename(src, dst)`. If src and dst are on different drives (rename crosses volume boundaries), falls back to `std::fs::copy` + `std::fs::remove_file`.
   e. Writes a sidecar metadata file `{sha256_hex}.meta.json`: `{ original_path, sha256, quarantined_at, reason, verdict_id }`.
4. Returns `{ "status": "ok", "quarantine_path": "...", "sha256": "..." }` to the UI.
5. UI marks the file entity as "Quarantined" in the entity panel.

**Why rename instead of delete:** preserves the binary for forensic analysis and future hash lookup. Deletion is irreversible and loses evidence.

---

### Network Block (Firewall Rule)
**Not yet implemented.**

**New daemon command:** `block-ip { remote_ip: String, direction: "out" | "both" }`

**Layer:** Rust daemon → `std::process::Command` calling `netsh`

**How it works:**
1. UI calls `invoke('block_ip', { remote_ip, direction })`.
2. Daemon generates a unique rule name: `AegisAI-Block-{remote_ip}-{timestamp}`.
3. Runs:
   ```
   netsh advfirewall firewall add rule
     name="AegisAI-Block-{ip}"
     dir=out
     action=block
     remoteip={ip}
     enable=yes
     profile=any
   ```
   For `direction = "both"`, the same command is run twice with `dir=in` and `dir=out`.
4. Checks exit code — non-zero means insufficient privilege or malformed IP; returns error.
5. Appends the rule name to `%PROGRAMDATA%\AegisAI\firewall_rules.json` so blocked IPs can be listed and rolled back.
6. Returns `{ "status": "ok", "rule_name": "..." }`.

**Why `netsh` instead of the COM firewall API (`INetFwPolicy2`):** `netsh` is available on all Windows versions we target, requires no COM interop in Rust, and the command is human-readable and auditable. The COM path would require the `windows` crate's `Win32::NetworkManagement::WindowsFirewall` feature — viable but adds complexity without benefit.

**Rollback:** a `remove-block-ip { rule_name }` command runs `netsh advfirewall firewall delete rule name="{rule_name}"`.

---

### Host Network Isolation
**Not yet implemented.**

**New daemon command:** `isolate-network`

**Layer:** Rust daemon → `std::process::Command` calling `netsh` per adapter

**How it works:**
1. Enumerate all active network interfaces:
   ```
   netsh interface show interface
   ```
   Parse output to collect adapter names with state `Connected`.
2. For each adapter:
   ```
   netsh interface set interface "{name}" admin=disable
   ```
3. Save the list of disabled adapters to `%PROGRAMDATA%\AegisAI\isolated_interfaces.json` so recovery can re-enable exactly those adapters.
4. Returns `{ "status": "ok", "disabled_interfaces": [...] }`.

**Recovery command:** `restore-network` — reads `isolated_interfaces.json` and runs `netsh interface set interface "{name}" admin=enable` for each entry.

**Privilege note:** disabling a network interface requires administrator rights. The daemon already runs with elevation for memory scanning; this reuses the same privilege level.

**Why not use `GetAdaptersInfo` / `DeviceIoControl` directly:** `netsh` gives us adapter names directly without parsing raw WinAPI structs, and is scriptable and auditable. The direct API path (via `windows` crate `Win32::NetworkManagement::IpHelper`) is more robust but significantly more code for the same outcome.

---

### Memory Dump
**Not yet implemented.**

**New daemon command:** `dump-memory { pid: u32 }`

**Layer:** Rust daemon → `windows` crate → `dbghelp.dll`

**How it works:**
1. UI calls `invoke('dump_memory', { pid })`.
2. Daemon:
   a. Enables `SeDebugPrivilege` on its own token (required for cross-process full-memory access).
   b. Opens the target process: `OpenProcess(PROCESS_ALL_ACCESS, false, pid)`.
   c. Creates a dump file at `%PROGRAMDATA%\AegisAI\dumps\{pid}_{timestamp_unix}.dmp`.
   d. Calls `MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, null, null, null)` from `dbghelp.dll`.
      - `MiniDumpWithFullMemory` captures all accessible memory pages — the most complete dump type.
   e. Closes handles. Returns `{ "status": "ok", "dump_path": "..." }`.
3. UI shows a "Memory dump saved" notification with the path and a copy button.

**Rust binding:** use `windows::Win32::System::Diagnostics::Debug::MiniDumpWriteDump` from the `windows` crate (feature `Win32_System_Diagnostics_Debug`).

**Why full memory dump:** we already have `VirtualQueryEx` region analysis from the memory scanner. The dump is for external forensic tools (WinDbg, Volatility) — they need the full image, not just our scanner's summary.

---

### Persistence Check
**Not yet implemented.**

**New daemon command:** `check-persistence { pid?: u32 }`

**Layer:** Rust daemon — registry queries via `windows` crate + `std::process::Command` for scheduled tasks + `std::fs::read_dir` for startup folder

**How it works:**

The check runs three sub-scans in parallel and merges results:

**1. Registry run keys**
Query the four standard autorun locations using `RegOpenKeyEx` + `RegEnumValueEx`:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (check `Userinit` and `Shell` values for tampering)

For each value, extract the executable path and cross-reference with:
- The malicious file hashes from the current verdict
- The exe paths of terminated PIDs

**2. Scheduled tasks**
Run `schtasks /query /fo CSV /v` via `std::process::Command`, parse the CSV output.
Extract task name, next run time, and the action path (the executable the task runs).
Cross-reference action paths with malicious file hashes and terminated exe paths.

**3. Startup folder**
`std::fs::read_dir` on:
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

For each `.lnk` or `.exe` found, extract the target path (resolve shortcuts) and cross-reference.

**Output:** returns a list of `PersistenceEntry { kind, name, path, sha256?, matched_verdict_entity }`. Entries that match a verdict entity are flagged `suspicious: true`.

**UI:** displayed as a new "Persistence" section in the verdict panel, with remove buttons for each flagged entry (which call `remove-persistence { kind, name }` on the daemon).

---

### LOLBin Detection
**Not yet implemented — logic addition to existing graph analyzer.**

**Layer:** Rust — `graph/analyzer.rs` + `graph/types.rs` + UI `types/index.ts`

**How it works:**

A static list of known living-off-the-land binaries is embedded in `analyzer.rs`:

```rust
const LOLBINS: &[&str] = &[
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe", "schtasks.exe",
    "regasm.exe", "installutil.exe", "msbuild.exe", "cmstp.exe",
    "forfiles.exe", "pcalua.exe", "syncappvpublishingserver.exe",
];
```

During `find_attack_chains_aggregated()`, when a `ParentChild` edge is found where the parent node is Clean (`threat_level == Clean`) and the child is Malicious:
1. The existing `ExploitedTrustedProcess` pattern fires.
2. Additionally, if `parent_label.to_lowercase()` matches any entry in `LOLBINS`, set `is_lolbin: true` on the parent `GraphNode`.
3. The `is_lolbin` flag is serialized to JSON and typed in `GraphNodeData`.
4. UI renders a "LOLBin" badge on that node in the ThreatGraph and Verdict panels.

**Why a static list instead of a dynamic feed:** LOLBins change slowly. A static list in code is auditable, version-controlled, and does not require a network call at verdict time. The list can be updated as new LOLBins are discovered (LOLBAS project is the reference: lolbas-project.github.io).

---

### Incident Report Export
**Not yet implemented.**

**New Tauri command:** `export_incident_report { output_path?: String }`

**Layer:** Tauri backend (`UI/src-tauri/src/main.rs`) — pure serialization, no daemon call needed

**How it works:**
1. The Tauri command receives the current `CorrelateResult` from the store (passed from the UI) plus an action log (list of actions taken this session with timestamps).
2. Builds a structured report object:
   ```json
   {
     "report_id": "uuid",
     "generated_at": "ISO8601 timestamp",
     "severity": "Malicious",
     "attack_chains": [...],
     "critical_path": {...},
     "entities": [...],
     "actions_taken": [
       { "action": "kill-process", "pid": 4821, "at": "...", "result": "ok" },
       { "action": "quarantine-file", "path": "...", "sha256": "...", "at": "..." }
     ],
     "graph_snapshot": { "nodes": [...], "edges": [...] }
   }
   ```
3. Serializes to JSON with `serde_json::to_string_pretty`.
4. If `output_path` is provided, writes there. Otherwise writes to `%USERPROFILE%\Documents\AegisAI\incident_{timestamp}.json`.
5. Returns the final path to the UI, which shows a "Report saved" toast with an "Open folder" button (via Tauri's `shell::open`).

**PDF export (future):** the JSON report can be loaded into the UI and rendered via `window.print()` with a dedicated print stylesheet — no Rust PDF crate needed. This avoids a heavy dependency for a non-critical feature.

---

### Autonomous Mode
**Not yet implemented.**

**Layer:** UI store (`UI/src/store/index.ts`) + Tauri settings

**How it works:**

A boolean flag `autonomousMode` is added to the Zustand store, defaulting to `false`.

**Confirmation dialog path (default, `autonomousMode = false`):**
- Every destructive action (kill, quarantine, block, isolate) opens a modal: "This will terminate PID 4821 (chrome.exe). Confirm?"
- User clicks Confirm → Tauri IPC call fires.
- User clicks Cancel → action is logged as "declined" but no system change is made.

**Autonomous path (`autonomousMode = true`):**
- The same Tauri IPC call fires immediately without showing the modal.
- A non-blocking toast notification informs the user: "Terminated chrome.exe (PID 4821) automatically."
- All actions are still logged to the incident report.

**Persistence:** `autonomousMode` is stored in Tauri's `app.store` (a persisted key-value store backed by a local JSON file). It resets to `false` on each app startup — autonomous mode is never silently active across restarts.

**UI control:** a toggle in the Settings panel with a prominent red warning: "Autonomous mode — containment actions execute without confirmation. Use only in active incident response."

---

### Re-Correlation After Containment
**Already implemented** — reuses the existing `correlate` daemon command.

**How it works:**
After all containment actions complete, the UI automatically calls `correlateEntities(true)` (with `include_memory: true`).

The new correlation rebuilds the entity graph from scratch against the current system state. Since terminated processes are gone and quarantined files no longer execute:
- Nodes for terminated PIDs will be absent (the process scanner won't see them).
- File entities for quarantined files will no longer match running processes.
- If any attack chains survive in the new verdict, the response loop repeats.

The UI compares the new verdict severity against the pre-containment severity and surfaces a diff: "2 of 3 chains resolved. 1 chain remains active."
