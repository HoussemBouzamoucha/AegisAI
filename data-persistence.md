# AegisAI — Data Persistence & Community Intelligence

Remote database strategy for cross-session behavioral baselines, community
anomaly detection, and real-world ML training dataset collection.

---

## What This Unlocks

This directly addresses the two deferred steps from `upgrades.md` that are
currently blocked on real-world data:

- **Step 2** (ML calibration on real data) — a community dataset of consenting
  users provides labeled real-world traffic, process behavior, and memory
  profiles that the models need for `CalibratedClassifierCV`.
- **Step 3** (uncertainty propagation) — only meaningful once models are
  retrained on real data; this infrastructure makes that possible.

It also gives **Step 7** (behavioral baseline) a community dimension: instead
of each user building their own profile from scratch over weeks, a new install
immediately inherits population-level knowledge of what `chrome.exe`,
`svchost.exe`, and `powershell.exe` normally look like across all consenting
machines.

---

## Two Separate Use Cases

### Use Case 1 — Community Behavioral Baseline

**Goal:** For each common process name, know its typical score distribution
across all users so anomaly detection works from day one, before the local
baseline has accumulated enough observations.

**What to collect:**

| Field | Collect? | Reason |
|---|---|---|
| Process name (`chrome.exe`) | Yes | The grouping key — not PII |
| Memory / network / process / file sub-scores | Yes | The signal |
| ML score per domain | Yes | Needed for calibration analysis |
| Combined score | Yes | Population distribution |
| Heuristic score | Yes | Per-domain normalization analysis |
| `is_threat` (was it flagged?) | Yes | Separates normal from anomalous observations |
| OS build number | Yes | Stratification — Win11 26200 vs Win10 19045 behave differently |
| Command line arguments | **No** | Can contain passwords, usernames, secrets |
| File paths | **No** | Contains username (`C:\Users\houss\...`) |
| Raw memory contents | **No** | Never |
| Remote IPs (raw) | **No** | PII — use `/24` prefix or SHA-256 hash instead |
| Remote port number | Yes | Port alone is not PII |

**What the server computes from these observations:** for each `(process_name,
domain)` pair — `mean`, `std_dev`, `p5`, `p95` of the score distribution. These
population statistics are what get sent back to clients as their starting
baseline. Clients use them to seed the `BaselineStore` in `EntityManager` before
any local observations exist.

---

### Use Case 2 — ML Training Dataset

**Goal:** Collect labeled feature vectors to retrain the three domain models on
real-world data, replacing the current synthetic/UNSW-NB15-only training sets.

**What to collect per domain:**

| Domain | Feature vector | Label source |
|---|---|---|
| Network | 47 UNSW-NB15 features already written to `OnePace.csv` | User confirms alert as malicious/benign in UI |
| Process | API call sequence (already captured by GRU preprocessor) | User confirmation |
| Memory | Region characteristics: size, permissions, entropy, PE-header present, RWX flag | User confirmation |
| File | SHA-256, section entropy, section count, import count, has-resources | YARA match + user confirmation |

**Label collection:** when the UI surfaces a verdict and the user acts on it
(confirms a kill = malicious, dismisses as false positive = clean), that
decision becomes the label. This is implicit labeling from user behavior —
standard practice in production ML systems. An explicit "Was this a false
positive?" prompt is shown after any user dismissal to capture clean labels
cleanly.

---

## Architecture

### Backend: Supabase (PostgreSQL)

Supabase is the right choice:
- Hosted PostgreSQL — supports complex aggregation queries for computing
  population statistics.
- Built-in Row Level Security (RLS) — each device's data is isolated; the anon
  key shipped in the app can only insert into the telemetry tables and read
  its own rows, nothing else.
- REST API — callable from Rust via `reqwest` + `serde_json`, no new heavy
  client library needed.
- Generous free tier for early stage (500 MB database, 2 GB bandwidth/month).
- `pg_cron` extension available for scheduled aggregation jobs.

### Client: Tauri backend (`UI/src-tauri/src/`)

A `telemetry.rs` module handles all upload logic. It runs in a background
`tokio::spawn` task after `correlate_entities` resolves — never blocking the
UI or the detection pipeline.

---

## Database Schema

```sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Use Case 1: Behavioral baseline observations
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE process_observations (
  id             BIGSERIAL PRIMARY KEY,
  device_id      UUID        NOT NULL,   -- anonymous, generated on first opt-in
  process_name   TEXT        NOT NULL,   -- "chrome.exe"
  memory_score   REAL,
  network_score  REAL,
  process_score  REAL,
  file_score     REAL,
  ml_score       REAL,
  combined_score REAL        NOT NULL,
  is_threat      BOOLEAN     NOT NULL,   -- true = was flagged at verdict time
  graph_boost    REAL,                   -- post-feedback score boost from graph
  os_build       TEXT,                   -- "26200"
  observed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for aggregation queries (p5/p95 per process name)
CREATE INDEX idx_obs_process ON process_observations (process_name, is_threat);

-- ─────────────────────────────────────────────────────────────────────────────
-- Use Case 2: ML training samples
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE training_samples (
  id             BIGSERIAL   PRIMARY KEY,
  device_id      UUID        NOT NULL,
  domain         TEXT        NOT NULL CHECK (domain IN ('network','process','memory','file')),
  feature_vector JSONB       NOT NULL,   -- sanitized feature vector
  label          SMALLINT    CHECK (label IN (0, 1)),  -- 0=clean, 1=malicious, NULL=unlabeled
  label_source   TEXT,                   -- 'user_confirmed' | 'yara_match' | 'hash_db' | 'gru_inference'
  confidence     REAL,                   -- chain confidence at time of labeling (from step 6)
  collected_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_samples_domain_label ON training_samples (domain, label);

-- ─────────────────────────────────────────────────────────────────────────────
-- Use Case 3: Hash reputation feed
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE file_reputation (
  sha256         CHAR(64)    PRIMARY KEY,
  malicious_votes INT        NOT NULL DEFAULT 0,
  clean_votes     INT        NOT NULL DEFAULT 0,
  first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
  yara_rules      TEXT[],                -- which YARA rules matched (rule names only, not content)
  verdict         TEXT GENERATED ALWAYS AS (
    CASE
      WHEN malicious_votes >= 3 AND malicious_votes > clean_votes * 2 THEN 'malicious'
      WHEN clean_votes >= 10 AND clean_votes > malicious_votes * 5    THEN 'clean'
      ELSE 'unknown'
    END
  ) STORED
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Materialized view: population baseline (refreshed by pg_cron every hour)
-- ─────────────────────────────────────────────────────────────────────────────

CREATE MATERIALIZED VIEW baseline_statistics AS
SELECT
  process_name,
  is_threat,
  COUNT(*)                                        AS observation_count,
  AVG(combined_score)                             AS mean_combined,
  STDDEV(combined_score)                          AS std_combined,
  PERCENTILE_CONT(0.05) WITHIN GROUP (ORDER BY combined_score) AS p5_combined,
  PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY combined_score) AS p95_combined,
  AVG(memory_score)                               AS mean_memory,
  AVG(network_score)                              AS mean_network,
  AVG(process_score)                              AS mean_process,
  AVG(file_score)                                 AS mean_file
FROM process_observations
WHERE observed_at > NOW() - INTERVAL '90 days'   -- rolling 90-day window
GROUP BY process_name, is_threat
HAVING COUNT(*) >= 10;                            -- only publish stats with enough data

-- Refresh every hour via pg_cron
SELECT cron.schedule('refresh-baseline', '0 * * * *',
  'REFRESH MATERIALIZED VIEW CONCURRENTLY baseline_statistics');
```

---

## Row Level Security Policies

The anon key shipped inside the app binary can only do two things:
1. Insert rows into `process_observations`, `training_samples`, `file_reputation`.
2. Read rows in `baseline_statistics` (the materialized view — aggregated, no raw rows).

It cannot read any other device's raw `process_observations` or `training_samples`.

```sql
-- Enable RLS on all raw tables
ALTER TABLE process_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE training_samples     ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_reputation      ENABLE ROW LEVEL SECURITY;

-- Devices can insert their own rows
CREATE POLICY "insert own observations"
  ON process_observations FOR INSERT
  TO anon
  WITH CHECK (true);

-- Devices can read only their own rows
CREATE POLICY "read own observations"
  ON process_observations FOR SELECT
  TO anon
  USING (device_id = current_setting('request.jwt.claims', true)::jsonb->>'device_id');

-- Same for training_samples
CREATE POLICY "insert own samples" ON training_samples FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "read own samples"   ON training_samples FOR SELECT TO anon
  USING (device_id = current_setting('request.jwt.claims', true)::jsonb->>'device_id');

-- File reputation: anyone can insert votes, anyone can read
CREATE POLICY "insert reputation" ON file_reputation FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "read reputation"   ON file_reputation FOR SELECT TO anon USING (true);

-- Baseline statistics view: world-readable (aggregated, no raw data)
GRANT SELECT ON baseline_statistics TO anon;

-- Delete own data (GDPR right to erasure)
CREATE POLICY "delete own data" ON process_observations FOR DELETE TO anon
  USING (device_id = current_setting('request.jwt.claims', true)::jsonb->>'device_id');
CREATE POLICY "delete own samples" ON training_samples FOR DELETE TO anon
  USING (device_id = current_setting('request.jwt.claims', true)::jsonb->>'device_id');
```

---

## Privacy Model

1. **Opt-in only.** Consent is explicit, off by default. Shown on first launch
   as a modal with a plain-language breakdown of every field that will be sent.
   No dark patterns — the "no thanks" button is the same size as "yes".

2. **Device ID is anonymous.** Generated locally as a random UUIDv4 on first
   opt-in. Stored in Tauri's persisted app store. Never linked to a user
   account, email, or machine name.

3. **PII stripping before upload.** A `sanitize()` pass runs locally in Rust
   before any data leaves the machine. File paths, command lines, raw IPs, and
   usernames are removed or hashed. The sanitized payload is what the user sees
   in the "preview what will be sent" panel.

4. **Right to erasure.** A "Delete my data" button in Settings calls a Tauri
   command that issues `DELETE FROM process_observations WHERE device_id = $1`
   and the equivalent for `training_samples`. The device ID is then
   regenerated so the device is effectively unlinkable from that point forward.

5. **No third-party analytics.** Supabase is self-hosted-capable; if privacy
   requirements tighten, the backend can be migrated to a self-hosted Supabase
   instance with zero client-side changes.

---

## Implementation: Rust / Tauri Side

### New dependency

Add to `UI/src-tauri/Cargo.toml`:

```toml
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
uuid    = { version = "1", features = ["v4"] }
```

`reqwest` with `rustls-tls` avoids a dependency on the system OpenSSL — important
on Windows where OpenSSL is not bundled.

---

### `UI/src-tauri/src/telemetry.rs`

```rust
use reqwest::Client;
use serde::Serialize;
use uuid::Uuid;

const SUPABASE_URL: &str = "https://<project>.supabase.co";
const SUPABASE_ANON_KEY: &str = "<anon-key>";   // safe to ship — RLS restricts it

// ── Sanitized observation (no PII) ───────────────────────────────────────────

#[derive(Serialize)]
pub struct ProcessObservation {
    pub device_id:     Uuid,
    pub process_name:  String,   // "chrome.exe" — not PII
    pub memory_score:  Option<f32>,
    pub network_score: Option<f32>,
    pub process_score: Option<f32>,
    pub file_score:    Option<f32>,
    pub ml_score:      Option<f32>,
    pub combined_score: f32,
    pub is_threat:     bool,
    pub graph_boost:   Option<f32>,
    pub os_build:      Option<String>,
}

#[derive(Serialize)]
pub struct TrainingSample {
    pub device_id:      Uuid,
    pub domain:         String,
    pub feature_vector: serde_json::Value,  // sanitized features
    pub label:          Option<i16>,        // 0 or 1; None = unlabeled
    pub label_source:   Option<String>,
    pub confidence:     Option<f32>,
}

#[derive(Serialize)]
pub struct ReputationVote {
    pub sha256:        String,
    pub malicious_votes: i32,
    pub clean_votes:     i32,
    pub yara_rules:    Vec<String>,
}

// ── Sanitize helpers ──────────────────────────────────────────────────────────

/// Hash a raw IP address to a non-reversible token.
/// The /24 subnet is preserved in the hash input so clustering still works,
/// but the exact IP is not recoverable.
pub fn hash_ip(ip: &str) -> String {
    use sha2::{Sha256, Digest};
    let subnet = ip.rsplitn(2, '.').last().unwrap_or(ip); // keep /24 prefix
    let mut h = Sha256::new();
    h.update(b"aegisai-ip-salt-v1");
    h.update(subnet.as_bytes());
    hex::encode(h.finalize())[..16].to_string()  // 16-char prefix, not full hash
}

/// Strip a file path to just the filename, dropping the directory (username).
pub fn strip_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_string()
}

// ── Uploader ──────────────────────────────────────────────────────────────────

pub struct TelemetryUploader {
    client:    Client,
    device_id: Uuid,
}

impl TelemetryUploader {
    pub fn new(device_id: Uuid) -> Self {
        Self {
            client: Client::new(),
            device_id,
        }
    }

    /// POST a batch of observations to Supabase.
    /// Called in a background tokio task after correlate completes.
    pub async fn upload_observations(&self, rows: Vec<ProcessObservation>)
        -> anyhow::Result<()>
    {
        self.client
            .post(format!("{SUPABASE_URL}/rest/v1/process_observations"))
            .header("apikey", SUPABASE_ANON_KEY)
            .header("Authorization", format!("Bearer {SUPABASE_ANON_KEY}"))
            .header("Content-Type", "application/json")
            .header("Prefer", "return=minimal")   // don't return inserted rows
            .json(&rows)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn upload_samples(&self, rows: Vec<TrainingSample>)
        -> anyhow::Result<()>
    {
        self.client
            .post(format!("{SUPABASE_URL}/rest/v1/training_samples"))
            .header("apikey", SUPABASE_ANON_KEY)
            .header("Authorization", format!("Bearer {SUPABASE_ANON_KEY}"))
            .header("Content-Type", "application/json")
            .header("Prefer", "return=minimal")
            .json(&rows)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn vote_reputation(&self, vote: ReputationVote)
        -> anyhow::Result<()>
    {
        // Upsert: increment vote counters atomically via a Postgres function
        // (defined as a Supabase RPC to avoid a read-modify-write race).
        self.client
            .post(format!("{SUPABASE_URL}/rest/v1/rpc/cast_reputation_vote"))
            .header("apikey", SUPABASE_ANON_KEY)
            .header("Authorization", format!("Bearer {SUPABASE_ANON_KEY}"))
            .header("Content-Type", "application/json")
            .json(&vote)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Fetch the materialized baseline statistics for a list of process names.
    /// Called once at daemon startup to seed the local BaselineStore.
    pub async fn fetch_baseline(&self, process_names: &[&str])
        -> anyhow::Result<Vec<BaselineRow>>
    {
        let names_csv = process_names
            .iter()
            .map(|n| format!("\"{}\"", n))
            .collect::<Vec<_>>()
            .join(",");

        let url = format!(
            "{SUPABASE_URL}/rest/v1/baseline_statistics\
             ?process_name=in.({names_csv})\
             &is_threat=eq.false\
             &select=process_name,mean_combined,std_combined,p5_combined,p95_combined,\
                     mean_memory,mean_network,mean_process,mean_file,observation_count"
        );

        let rows: Vec<BaselineRow> = self.client
            .get(url)
            .header("apikey", SUPABASE_ANON_KEY)
            .header("Authorization", format!("Bearer {SUPABASE_ANON_KEY}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(rows)
    }
}

#[derive(serde::Deserialize)]
pub struct BaselineRow {
    pub process_name:       String,
    pub mean_combined:      f64,
    pub std_combined:       f64,
    pub p5_combined:        f64,
    pub p95_combined:       f64,
    pub mean_memory:        Option<f64>,
    pub mean_network:       Option<f64>,
    pub mean_process:       Option<f64>,
    pub mean_file:          Option<f64>,
    pub observation_count:  i64,
}
```

---

### `UI/src-tauri/src/main.rs` — wiring it in

```rust
// After correlate_entities resolves and the result is returned to the UI,
// fire the telemetry upload in a background task so it never blocks the UI.

#[tauri::command]
async fn correlate_entities(
    include_memory: bool,
    state: tauri::State<'_, AppState>,
) -> Result<CorrelateResult, String> {
    let result = run_correlate(&state, include_memory).await?;

    // Fire-and-forget telemetry upload
    if state.telemetry_consent.load(Ordering::Relaxed) {
        let uploader = state.uploader.clone();
        let observations = build_observations(&result, &state.device_id);
        tokio::spawn(async move {
            if let Err(e) = uploader.upload_observations(observations).await {
                eprintln!("[telemetry] upload failed: {e}");
                // Non-fatal — detection pipeline is unaffected
            }
        });
    }

    Ok(result)
}
```

---

### `UI/src-tauri/src/main.rs` — delete my data command

```rust
#[tauri::command]
async fn delete_my_data(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let uploader = &state.uploader;
    let device_id = state.device_id;

    // Delete all rows for this device
    uploader.delete_device_data(device_id).await
        .map_err(|e| e.to_string())?;

    // Regenerate device ID so the device is unlinkable from this point
    let new_id = Uuid::new_v4();
    state.store.set("device_id", new_id.to_string());
    state.device_id.store(new_id);

    Ok(())
}
```

---

## Where the Baseline Feeds Back into the Engine

The community baseline is fetched once at daemon startup (or on first
`correlate` call) and used to seed the `BaselineStore` in `EntityManager`.

### New struct: `BaselineStore` in `entity/manager.rs`

```rust
/// Per-process population statistics fetched from the community database.
/// Used to seed the local rolling baseline before any local observations exist.
#[derive(Default)]
pub struct BaselineStore {
    /// process_name → population stats (clean observations only)
    pub stats: HashMap<String, PopulationStats>,
}

#[derive(Clone)]
pub struct PopulationStats {
    pub mean_combined: f32,
    pub std_combined:  f32,
    pub p5:            f32,
    pub p95:           f32,
    pub mean_memory:   Option<f32>,
    pub mean_network:  Option<f32>,
    pub mean_process:  Option<f32>,
    pub mean_file:     Option<f32>,
    pub n:             u64,         // how many community observations back this
}

impl BaselineStore {
    /// Compute how many standard deviations above the population mean
    /// this entity's score sits. Returns None if no community data exists.
    pub fn z_score(&self, process_name: &str, combined_score: f32) -> Option<f32> {
        let stats = self.stats.get(process_name)?;
        if stats.std_combined < 1e-6 { return None; }
        Some((combined_score - stats.mean_combined) / stats.std_combined)
    }

    /// True if the score is above the population p95 for this process.
    /// A chrome.exe scoring above its p95 is genuinely anomalous.
    pub fn is_anomalous(&self, process_name: &str, combined_score: f32) -> bool {
        self.stats
            .get(process_name)
            .map(|s| combined_score > s.p95)
            .unwrap_or(false)  // no community data → fall back to absolute scoring
    }
}
```

### Integration in `EntityManager::combined_score()`

After computing `combined_score = H × 0.4 + ML × 0.6`, apply a delta
adjustment if a community baseline exists:

```rust
// In assemble_entity() / combined_score() in manager.rs

let base_score = heuristic_norm * 0.4 + ml_score * 0.6;

// Delta adjustment: if community baseline exists and this score is within
// the normal range for this process, dampen it toward the population mean.
// If it's above p95, amplify it slightly to make the anomaly stand out.
let adjusted_score = if let Some(stats) = baseline.stats.get(&process_name) {
    if base_score <= stats.p95 {
        // Score is within normal range — dampen toward mean
        // Weight: 70% current score, 30% population mean
        base_score * 0.7 + stats.mean_combined * 0.3
    } else {
        // Score exceeds population p95 — genuine anomaly, amplify slightly
        (base_score * 1.1).min(1.0)
    }
} else {
    base_score  // no community data — use absolute score unchanged
};
```

This means a JVM process that always scores 0.35 in memory (large anonymous
exec regions) gets dampened toward its population mean of 0.35 and never
triggers an alert. A process that normally scores 0.12 and suddenly scores
0.78 gets amplified and fires.

---

## Hash Reputation Feed

The simplest and highest-value feature. A SHA-256 hash reveals nothing about
the user but a hash seen as malicious by 50 users is very strong signal.

### Supabase RPC for atomic vote upsert

```sql
CREATE OR REPLACE FUNCTION cast_reputation_vote(
  p_sha256         CHAR(64),
  p_malicious_votes INT,
  p_clean_votes     INT,
  p_yara_rules     TEXT[]
) RETURNS VOID AS $$
BEGIN
  INSERT INTO file_reputation (sha256, malicious_votes, clean_votes, yara_rules, last_seen)
  VALUES (p_sha256, p_malicious_votes, p_clean_votes, p_yara_rules, now())
  ON CONFLICT (sha256) DO UPDATE SET
    malicious_votes = file_reputation.malicious_votes + EXCLUDED.malicious_votes,
    clean_votes     = file_reputation.clean_votes     + EXCLUDED.clean_votes,
    yara_rules      = ARRAY(
      SELECT DISTINCT unnest(file_reputation.yara_rules || EXCLUDED.yara_rules)
    ),
    last_seen = now();
END;
$$ LANGUAGE plpgsql;
```

### Query at scan time

Before the local file scanner runs its heuristics, query the reputation feed:

```rust
pub async fn lookup_reputation(
    uploader: &TelemetryUploader,
    sha256: &str,
) -> Option<&'static str> {   // "malicious" | "clean" | None
    let url = format!(
        "{SUPABASE_URL}/rest/v1/file_reputation\
         ?sha256=eq.{sha256}\
         &select=verdict"
    );
    // parse "verdict" field from response
    // "malicious" → skip heuristics, return Malicious immediately
    // "clean"     → dampen heuristic score
    // no row      → no community data, run full scan
}
```

A file with `verdict = malicious` from the community database gets flagged
without needing a local YARA match. A file with `verdict = clean` from 1000+
machines gets its heuristic score dampened even if local heuristics fire weakly.

---

## Data Flow in the Full Pipeline

```
App starts
  │
  ├── consent = true?
  │     └── fetch baseline_statistics for top-100 process names
  │               → seed BaselineStore in EntityManager
  │
correlate_entities called
  │
  ├── Scanners run (unchanged)
  │
  ├── File scanner: lookup_reputation(sha256) for each file
  │     → early Malicious if community verdict = malicious
  │
  ├── EntityManager.assemble_entity()
  │     → combined_score with delta adjustment from BaselineStore
  │
  ├── GraphBuilder → GraphAnalyzer → Verdict
  │
  ├── Verdict shown to UI  ◄─── user interaction happens here
  │
  └── (background, consent = true)
        ├── build sanitized ProcessObservation[] from graph nodes
        ├── upload_observations()
        ├── if user confirms kill → vote reputation (malicious)
        ├── if user dismisses as FP → vote reputation (clean)
        │     + upload TrainingSample with label=0
        └── if malicious file found → cast_reputation_vote()
```

---

## Label Collection in the UI

In `UI/src/components/GraphVerdict.tsx`, after the user takes a containment
action (kill, quarantine), show a one-question prompt:

```
"Was this a real threat or a false alarm?"
  [ ✓ Real threat — malicious ]   [ ✗ False alarm — safe ]   [ Skip ]
```

The answer is stored in the Zustand store as `verdictFeedback: 'malicious' | 'clean' | null`.

When the background uploader fires, it reads `verdictFeedback` and sets
`label` on the `TrainingSample` accordingly. If the user skips, `label = null`
(unlabeled — still useful for unsupervised analysis).

For **network samples** specifically: the 47-feature vector from `OnePace.csv`
is already on disk. The uploader reads the CSV path from the correlate result,
strips any identifying rows (those matching the device's own IPs), and uploads
the remaining rows as network training samples.

---

## Retraining Pipeline (Offline, Server-Side)

Once enough labeled samples accumulate, retraining runs server-side (GitHub
Actions, a scheduled job, or manually):

```
Supabase → export training_samples WHERE domain='network' AND label IS NOT NULL
         → preprocessing_pipeline.py --retrain --data community_network.csv
         → CalibratedClassifierCV wraps the new XGBoost model
         → ids_network_calibrated.pkl uploaded to a versioned model registry
         → clients pull new model on next startup (if model version > local version)
```

The same flow applies to the GRU (process domain) and memory classifier.

Minimum sample targets before retraining is meaningful:

| Domain | Minimum labeled samples | Rationale |
|---|---|---|
| Network | 2,000 (balanced) | XGBoost needs enough real traffic to generalize |
| Process | 500 sequences | GRU sequences are long; fewer needed |
| Memory | 1,000 | Memory features are low-dimensional |

---

## What Needs to Be Built (Implementation Checklist)

| Component | File | Status |
|---|---|---|
| `reqwest` + `uuid` dependencies | `UI/src-tauri/Cargo.toml` | Not started |
| `telemetry.rs` — uploader, sanitizer, baseline fetch | `UI/src-tauri/src/telemetry.rs` | Not started |
| `AppState` gains `uploader`, `device_id`, `telemetry_consent` | `UI/src-tauri/src/main.rs` | Not started |
| `BaselineStore` + `PopulationStats` structs | `Antivirus_Engine/src/core/entity/manager.rs` | Not started |
| Delta adjustment in `assemble_entity()` | `Antivirus_Engine/src/core/entity/manager.rs` | Not started |
| `lookup_reputation()` in file scanner | `Antivirus_Engine/src/core/file_system/` | Not started |
| Consent modal | `UI/src/components/ConsentModal.tsx` | Not started |
| `verdictFeedback` in Zustand store | `UI/src/store/index.ts` | Not started |
| "Was this a false alarm?" prompt | `UI/src/components/GraphVerdict.tsx` | Not started |
| "Delete my data" button in Settings | `UI/src/components/Settings.tsx` | Not started |
| Supabase project setup | Cloud | Not started |
| `cast_reputation_vote` RPC | Supabase SQL editor | Not started |
| `baseline_statistics` materialized view + `pg_cron` | Supabase SQL editor | Not started |
| RLS policies | Supabase SQL editor | Not started |
| Retraining pipeline script | `scripts/retrain.py` | Not started |
| Model version check on startup | `UI/src-tauri/src/main.rs` | Not started |

---

## Milestones

| Users / Time | What becomes possible |
|---|---|
| 50 users · 2 weeks | Baseline statistics for top 20 most common Windows processes (chrome, svchost, explorer, …) |
| 100 users · 1 month | Hash reputation feed has enough coverage to catch common malware families |
| 500 users · 3 months | Enough labeled network samples to retrain XGBoost on real traffic → unblocks step 2 |
| 1,000 users · 6 months | GRU and memory model retraining; step 3 (uncertainty propagation) becomes meaningful |
| Ongoing | Community baseline tightens; false positive rate drops as population p95 per process is known |
