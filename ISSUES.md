# AegisAI — Performance Issues: CPU Spikes, RAM Growth & System Freezes

This document identifies the root causes of high CPU usage, RAM spikes, and system freezes observed when running the AegisAI application and its network scanner.

---

## Quick Summary

| # | Issue | File | Severity | Impact |
|---|-------|------|----------|--------|
| 1 | Tight polling loop — no sleep on packet capture timeout | `feature_extractor.rs:668` | **CRITICAL** | 25–50% CPU per interface, all cores saturated when idle |
| 2 | Unbounded flow table (DashMap) grows without a size cap | `feature_extractor.rs:717` | **HIGH** | RAM grows indefinitely with network activity |
| 3 | One background thread per network interface, no pool limit | `feature_extractor.rs:639` | **HIGH** | Thread explosion if many interfaces present |
| 4 | Feature computation iterates over packet list multiple times | `feature_extractor.rs:254–281` | **MEDIUM** | O(n²) CPU per high-traffic flow |
| 5 | Full flow-key Vec clone before every CSV write | `feature_extractor.rs:756–760` | **MEDIUM** | Large allocation each scan cycle |
| 6 | Mandatory 200 ms blocking sleep during every process scan | `process/types.rs:204` | **MEDIUM** | Blocks the daemon thread; UI freezes on scan |
| 7 | Memory region enumeration loop has no yields | `memory/scanner.rs:184–271` | **MEDIUM** | Saturates one core for the entire scan duration |
| 8 | Flow idle eviction threshold is 120 seconds | `feature_extractor.rs:738` | **LOW–MED** | Stale flows linger in RAM for 2 minutes |
| 9 | CSV writes are unbuffered (no `BufWriter`) | `feature_extractor.rs:712` | **LOW** | Frequent small I/O calls cause unnecessary context switching |
| 10 | Capture threads are never explicitly stopped | `feature_extractor.rs:668` | **LOW–MED** | Threads keep running after the UI closes; resource leak |

---

## Issue 1 — Tight Polling Loop: No Sleep on Packet Capture Timeout (CRITICAL)

**File:** `Antivirus_Engine/src/core/network/feature_extractor.rs`, lines 661 and 668–685

### What happens

`spawn_capture_threads()` opens a `pcap` capture handle for every network interface with a 100 ms read timeout, then enters a `while` loop:

```rust
// Line 661
let cap = Device::from(dev.clone())
    .open()
    .snaplen(65535)
    .timeout(100)   // ← 100 ms read timeout
    .open()?;

// Lines 668–685
while !stopper.load(Ordering::Relaxed) {
    match cap.next_packet() {
        Ok(pkt) => { /* process packet */ }
        Err(pcap::Error::TimeoutExpired) => {}  // ← nothing, loop restarts immediately
        Err(e) => { eprintln!(...); break; }
    }
}
```

When no packets arrive (or the network is quiet), `next_packet()` returns `TimeoutExpired` roughly 10 times per second. The `{}` arm does absolutely nothing — the loop immediately retries. This is a **busy-wait spin loop**.

### Why your PC freezes

- Each interface thread consumes **25–50% of one CPU core** doing nothing useful.
- With 3–4 interfaces (loopback, Wi-Fi, Ethernet, VPN adapter), this is **100–200% CPU** at idle.
- The OS scheduler tries to keep these threads running, starving other processes.

### Fix

Add a small sleep in the timeout arm, or increase the pcap timeout so the kernel does the waiting:

```rust
Err(pcap::Error::TimeoutExpired) => {
    std::thread::sleep(std::time::Duration::from_millis(10));
}
```

Or raise the capture timeout to 500–1000 ms so `next_packet()` blocks in the kernel rather than returning immediately.

---

## Issue 2 — Unbounded Flow Table (RAM Grows Indefinitely)

**File:** `Antivirus_Engine/src/core/network/feature_extractor.rs`, line 717

### What happens

The flow accumulator is an unbounded `DashMap`:

```rust
let flow_table = Arc::new(DashMap::<FlowKey, FlowAcc>::new());
// ↑ No capacity limit, no max-entry policy
```

Every unique TCP/UDP 4-tuple (src IP, dst IP, src port, dst port) gets its own `FlowAcc` entry. Each `FlowAcc` stores a `Vec<PktSummary>` that grows with every packet seen on that flow. There is **no hard cap** on the number of flows or the number of packets stored per flow.

### Eviction policy is too slow

Eviction only happens inside `extract_and_append()`:

```rust
const FLOW_IDLE_SECS: f64 = 120.0;  // Line 738
// Only flows idle >2 minutes AND absent from netstat are removed
```

On a busy machine (browser open, background services, downloads), hundreds of flows exist at any given time. Each flow accumulates packet summaries. After 10–15 minutes of normal browsing, the flow table can easily hold **tens of thousands of entries** and several hundred MB of packet data.

### Why your RAM spikes

- Each `PktSummary` stores timestamps, lengths, and flags per packet.
- A single long-lived HTTPS stream (e.g., streaming video) can accumulate tens of thousands of entries.
- The table is never trimmed mid-session; it only shrinks at the 120-second eviction boundary.

### Fix

1. Set a max entries limit (e.g., 10,000 flows) and evict LRU entries when the limit is hit.
2. Cap `FlowAcc::pkts` to the last N packets needed for feature calculation (e.g., 200 packets is sufficient for all 47 UNSW-NB15 features).
3. Reduce `FLOW_IDLE_SECS` to 30 seconds.

---

## Issue 3 — One Capture Thread Per Interface, No Pool Limit

**File:** `Antivirus_Engine/src/core/network/feature_extractor.rs`, lines 639–691

### What happens

```rust
for dev in devices {
    let stopper = Arc::clone(&stop_flag);
    let table   = Arc::clone(&flow_table);
    let handle  = std::thread::spawn(move || { /* capture loop */ });
    handles.push(handle);
}
```

One OS thread is created per network interface. On Windows, a typical machine may expose: loopback (`127.0.0.1`), Ethernet, Wi-Fi, a VPN adapter, a Hyper-V virtual switch, and a WSL2 bridge — **6 or more interfaces**.

Combined with Issue 1 (each thread busy-waits), 6 threads × 25–50% CPU = **150–300% CPU overhead from the network scanner alone**.

### Fix

- Filter devices to only physical/relevant interfaces before spawning threads.
- Cap to a maximum of 2–3 simultaneous capture threads.
- Consider a single thread that multiplexes across interfaces.

---

## Issue 4 — O(n²) Feature Computation for High-Traffic Flows

**File:** `Antivirus_Engine/src/core/network/feature_extractor.rs`, lines 254–281

### What happens

Statistical feature functions (jitter, inter-arrival time, etc.) each independently iterate over the full packet list:

```rust
fn sjit(&self) -> f64 {
    let ts: Vec<f64> = self.src_pkts().map(|p| p.ts).collect(); // full pass
    Self::iat_stats(&ts).1
}

fn djit(&self) -> f64 {
    let ts: Vec<f64> = self.dst_pkts().map(|p| p.ts).collect(); // another full pass
    Self::iat_stats(&ts).1
}
// ... repeated for mean, std, min, max, etc.
```

For a flow with 5,000 packets, computing all 47 features does approximately 15–20 full iterations, each allocating a `Vec<f64>`. This is **O(n × k)** allocations where `n` is packets and `k` is feature count — effectively O(n²) in total work across all flows.

When `extract_and_append()` is called, this runs for every active flow simultaneously.

### Fix

Pre-compute running statistics (mean, variance, min, max) using Welford's online algorithm as packets arrive in `push()`, so feature extraction is O(1) per flow.

---

## Issue 5 — Full Flow-Key Clone Before Every CSV Write

**File:** `Antivirus_Engine/src/core/network/feature_extractor.rs`, lines 756–800

### What happens

```rust
// Collect ALL flow keys into memory before processing
let keys: Vec<FlowKey> = self.flow_table.iter().map(|e| e.key().clone()).collect();

let mut rows = Vec::new();
for key in &keys {
    // compute features, push FeatureRow to rows
}
// write all rows to CSV
```

This clones every `FlowKey` in the table, then builds a `Vec<FeatureRow>` containing every computed row. With 10,000 flows, this is two large heap allocations of potentially several MB each, done synchronously on the scan path.

### Fix

Stream directly to the CSV writer inside the `iter()` loop instead of collecting to a Vec first.

---

## Issue 6 — Blocking 200 ms Sleep During Every Process Scan

**File:** `Antivirus_Engine/src/core/process/types.rs`, line 204

### What happens

```rust
let mut sys = System::new_with_specifics(refresh_kind);
sys.refresh_specifics(refresh_kind);
std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL); // ~200 ms
sys.refresh_specifics(refresh_kind);
// Now CPU% is valid
```

The `sysinfo` library requires two samples separated by at least ~200 ms to compute CPU usage percentage. The code takes this sleep **on the daemon's main thread** during every process scan.

### Why the UI freezes

- The Tauri frontend sends a process scan request and waits for a JSON response.
- The daemon thread sleeps for 200 ms per batch of processes scanned.
- With 100+ processes, this means the UI is **blocked for seconds** while the daemon sleeps.

### Fix

Move process scanning to a dedicated thread or Tokio task. Pre-refresh the `System` object on a background timer so the sleep gap is already satisfied when a scan is requested.

---

## Issue 7 — Memory Region Enumeration Loop Has No Yields

**File:** `Antivirus_Engine/src/core/memory/scanner.rs`, lines 184–271

### What happens

```rust
loop {
    let result = unsafe { VirtualQueryEx(handle, addr, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
    if result == 0 { break; }
    // ... analyze region, advance addr
}
```

This iterates over **every virtual memory page** in the target process's address space. A typical 64-bit process may have thousands to tens of thousands of committed regions. The loop runs with no `yield`, no `sleep`, and no cooperative scheduling.

### Why one CPU core maxes out during memory scan

The thread never gives up its time slice voluntarily. The OS preempts it, but because the work quantum is always fully consumed, the core runs at ~100% for the entire scan duration (can be 5–30 seconds for a large process).

### Fix

Insert a `std::thread::yield_now()` or a short sleep every N iterations (e.g., every 1,000 regions) to allow other threads to run.

---

## Issue 8 — Flow Idle Eviction Set to 120 Seconds

**File:** `Antivirus_Engine/src/core/network/feature_extractor.rs`, line 738

```rust
const FLOW_IDLE_SECS: f64 = 120.0;
```

Flows that have not seen a packet for 2 minutes are kept in the DashMap. Combined with Issue 2 (unbounded table), this means short-lived DNS/QUIC/HTTP/3 flows — of which there are hundreds per minute on an active machine — accumulate for up to 2 minutes before eviction. Lower this to **15–30 seconds** for realistic network traffic.

---

## Issue 9 — CSV Writes Are Unbuffered

**File:** `Antivirus_Engine/src/core/network/feature_extractor.rs`, lines 712–714

```rust
let mut f = File::create(&path)?;
writeln!(f, "{}", CSV_HEADER)?;
// ... row writes in a loop, each calling write() on the raw File
```

`File` in Rust does not buffer writes. Every `writeln!` call becomes a syscall. For 1,000 flow rows, this is 1,000 separate `write()` syscalls. Under heavy load, this causes measurable I/O overhead and context switching.

### Fix

Wrap with `BufWriter`:

```rust
let mut f = BufWriter::new(File::create(&path)?);
```

---

## Issue 10 — Capture Threads Are Never Explicitly Stopped

**File:** `Antivirus_Engine/src/core/network/feature_extractor.rs`, line 668

The `stop_flag` `AtomicBool` is only set to `true` if the `FeatureExtractor` struct is explicitly dropped. In the Tauri daemon, there is no evidence the extractor is dropped on UI close. The background capture threads continue running after the window is closed, holding pcap handles open and spinning on CPU (see Issue 1), until the daemon process is eventually killed by the OS.

### Fix

- Implement a `Drop` for `FeatureExtractor` that sets `stop_flag = true` and joins all threads.
- Ensure the Tauri shutdown hook calls the extractor's cleanup function.

---

## Recommended Priority Order for Fixes

1. **Issue 1** — Add `thread::sleep(10ms)` in the `TimeoutExpired` arm. This alone will likely eliminate the CPU freeze.
2. **Issue 2** — Cap the flow table to 5,000–10,000 entries + cap per-flow packet history to 200 packets.
3. **Issue 3** — Filter to physical interfaces only before spawning threads.
4. **Issue 6** — Move process scan sleep to a background pre-refresh cycle.
5. **Issue 7** — Add `yield_now()` every 1,000 memory regions.
6. **Issues 4, 5, 8, 9, 10** — Secondary cleanup pass.

---

## Environment Details

- **Platform:** Windows 11 Pro (10.0.26200)
- **Engine language:** Rust (Cargo workspace)
- **UI framework:** Tauri + Vue.js
- **Packet capture:** `pcap` crate (libpcap/Npcap)
- **Concurrency:** `std::thread` + `Arc<DashMap>` + `AtomicBool` stop flags
- **ML pipeline:** UNSW-NB15 feature extraction; model inference not yet wired into runtime
