# AegisAI — Multi-Layer Windows Antivirus & IDS

AegisAI is a desktop security suite combining a Rust scanning engine, Python ML models, and a Tauri/React UI. This guide walks you through every installation step needed to run it from a clean Windows machine.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Install Core Toolchains](#2-install-core-toolchains)
   - [2.1 Rust](#21-rust)
   - [2.2 Node.js](#22-nodejs)
   - [2.3 Python](#23-python)
   - [2.4 Visual Studio Build Tools (C++ compiler)](#24-visual-studio-build-tools-c-compiler)
   - [2.5 WebView2 Runtime](#25-webview2-runtime)
   - [2.6 Npcap (network packet capture)](#26-npcap-network-packet-capture)
3. [Clone / Locate the Project](#3-clone--locate-the-project)
4. [Build the Rust Scanning Engine](#4-build-the-rust-scanning-engine)
5. [Set Up Python ML Models](#5-set-up-python-ml-models)
6. [Install UI Dependencies](#6-install-ui-dependencies)
7. [Run the Application](#7-run-the-application)
8. [Optional: Run Individual Components](#8-optional-run-individual-components)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. System Requirements

| Requirement | Minimum |
|---|---|
| OS | Windows 10 / 11 (64-bit) |
| RAM | 8 GB (16 GB recommended) |
| Disk | 5 GB free |
| CPU | x86-64, any modern processor |
| Privileges | Administrator (required for process/network/memory scanning) |

---

## 2. Install Core Toolchains

Open **PowerShell as Administrator** for all installation steps below.

---

### 2.1 Rust

Rust is used to build both the antivirus scanning engine and the Tauri backend.

1. Download and run the official Rust installer:

   ```powershell
   winget install -e --id Rustlang.Rustup
   ```

   Or download `rustup-init.exe` from https://rustup.rs and run it.

2. When prompted, choose **option 1** (default installation).

3. Close and reopen PowerShell, then verify:

   ```powershell
   rustc --version
   cargo --version
   ```

   Expected output: `rustc 1.75.0` or higher.

4. Add the MSVC target (required on Windows):

   ```powershell
   rustup target add x86_64-pc-windows-msvc
   ```

---

### 2.2 Node.js

Node.js is required to build and run the React/Tauri UI.

1. Install via winget:

   ```powershell
   winget install -e --id OpenJS.NodeJS.LTS
   ```

   Or download the LTS installer from https://nodejs.org (v18 or higher).

2. Reopen PowerShell and verify:

   ```powershell
   node --version
   npm --version
   ```

   Expected: `node v18.x.x` or higher, `npm 9.x.x` or higher.

---

### 2.3 Python

Python is required to run the ML inference pipelines (network XGBoost, process GRU, memory classifier).

1. Install Python 3.11 (recommended):

   ```powershell
   winget install -e --id Python.Python.3.11
   ```

   Or download from https://www.python.org/downloads/ — make sure to check **"Add Python to PATH"** during installation.

2. Verify:

   ```powershell
   python --version
   pip --version
   ```

   Expected: `Python 3.10.x` or higher.

3. Install all required Python packages. From the project root:

   ```powershell
   pip install numpy pandas scikit-learn xgboost joblib torch
   ```

   > **Note:** `torch` (PyTorch) is needed for the process GRU model. If you only want the network/memory models and want a lighter install, you can skip `torch` — the engine degrades gracefully.

   For the AI agent component (optional):

   ```powershell
   pip install -r C:\Users\houss\Desktop\AegisAI\ai_agent\requirements.txt
   ```

---

### 2.4 Visual Studio Build Tools (C++ compiler)

The Rust compiler on Windows requires the MSVC C++ linker and Windows SDK.

1. Install Visual Studio Build Tools 2022:

   ```powershell
   winget install -e --id Microsoft.VisualStudio.2022.BuildTools
   ```

   Or download from https://visualstudio.microsoft.com/visual-cpp-build-tools/

2. In the Visual Studio Installer, select the **"Desktop development with C++"** workload. This installs:
   - MSVC compiler toolchain
   - Windows 10/11 SDK
   - CMake tools

3. Restart PowerShell after installation completes.

---

### 2.5 WebView2 Runtime

Tauri uses the Microsoft WebView2 runtime to render the UI. It is pre-installed on Windows 11. On Windows 10, install it manually:

```powershell
winget install -e --id Microsoft.EdgeWebView2Runtime
```

Or download the Evergreen Bootstrapper from https://developer.microsoft.com/microsoft-edge/webview2/

---

### 2.6 Npcap (network packet capture)

The network scanner uses raw packet capture. Npcap provides the Windows driver.

1. Download Npcap from https://npcap.com/#download (the free installer).

2. Run the installer. On the options screen, check:
   - **"Install Npcap in WinPcap API-compatible Mode"**

3. Restart your machine after installation.

> **Important:** The Npcap driver requires Administrator privileges at runtime. Always launch AegisAI as Administrator when using network scanning.

---

## 3. Clone / Locate the Project

If you received the project as a folder, skip to step 4. To clone from Git:

```powershell
git clone <repository-url> C:\Users\houss\Desktop\AegisAI
cd C:\Users\houss\Desktop\AegisAI
```

The project structure is:

```
AegisAI/
├── Antivirus_Engine/      # Rust scanning engine (cargo project)
│   ├── src/
│   ├── models/            # Pre-trained ML model files (.pkl, .joblib)
│   ├── yara_rules/        # YARA rule definitions
│   └── Cargo.toml
├── UI/                    # Tauri + React desktop app
│   ├── src/               # React/TypeScript frontend
│   ├── src-tauri/         # Tauri Rust backend
│   └── package.json
└── ai_agent/              # Optional AI reasoning agent (stub)
```

---

## 4. Build the Rust Scanning Engine

The scanning engine is a standalone Rust binary that the Tauri app spawns as a daemon.

1. Navigate to the engine directory:

   ```powershell
   cd C:\Users\houss\Desktop\AegisAI\Antivirus_Engine
   ```

2. Build in release mode:

   ```powershell
   cargo build --release
   ```

   This compiles all four scanner domains (file, process, network, memory), the entity/graph pipeline, and all post-verdict action modules. First build will take several minutes while dependencies download.

3. Verify the binary was produced:

   ```powershell
   ls .\target\release\antivirus_engine.exe
   ```

4. (Optional) Run the test suite to confirm everything works:

   ```powershell
   cargo test --release
   ```

   All tests should pass, including `test_extension_arrays_sorted`.

---

## 5. Set Up Python ML Models

The ML inference pipelines run as child processes spawned by the Rust engine. No separate server is needed — they are called on demand.

### 5.1 Verify model files exist

The pre-trained model files should already be present:

```powershell
ls C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\models\network\
```

Expected files:
- `ids_network_model.pkl` — XGBoost network IDS model
- `ids_network_calibrated.pkl` — calibrated wrapper
- `ordinal_encoder.joblib` — categorical encoder
- Frequency map files (`.json`)

If any model file is missing, you need to train it first (see section 8).

### 5.2 Test the network inference pipeline

```powershell
cd C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\src\core\network\Feature_extractor\ML_IDS
python preprocessing_pipeline.py --help
```

### 5.3 Test the process GRU pipeline

```powershell
cd C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\src\core\process\Sys_API
python preprocessing_pipeline.py --help
```

If both commands print a usage message without errors, the Python environment is correctly set up.

---

## 6. Install UI Dependencies

1. Navigate to the UI directory:

   ```powershell
   cd C:\Users\houss\Desktop\AegisAI\UI
   ```

2. Install Node.js dependencies:

   ```powershell
   npm install
   ```

3. Install the Tauri CLI (if not already installed globally):

   ```powershell
   npm install -g @tauri-apps/cli
   ```

4. Verify TypeScript compiles without errors:

   ```powershell
   npx tsc --noEmit
   ```

---

## 7. Run the Application

> **Administrator privileges are required** for process inspection, network packet capture, memory scanning, and firewall actions.

### Option A — Development mode (hot reload)

Open **PowerShell as Administrator**, then:

```powershell
cd C:\Users\houss\Desktop\AegisAI\UI
npm run tauri dev
```

This will:
1. Compile the Rust Tauri backend
2. Start the Vite dev server for the React frontend
3. Launch the AegisAI desktop window

Changes to `UI/src/` are reflected live in the window. Rust backend changes require a restart.

### Option B — Production build

Build a standalone installable package:

```powershell
cd C:\Users\houss\Desktop\AegisAI\UI
npm run tauri build
```

The installer is output to:

```
UI\src-tauri\target\release\bundle\msi\AegisAI_x.x.x_x64_en-US.msi
```

Run the MSI installer, then launch AegisAI from the Start Menu. Right-click the shortcut and choose **"Run as administrator"** for full functionality.

---

## 8. Optional: Run Individual Components

### Run the scanning engine directly (CLI mode)

The engine binary accepts JSON-RPC commands on stdin. For quick testing:

```powershell
# As Administrator
cd C:\Users\houss\Desktop\AegisAI\Antivirus_Engine
echo '{"id":"1","cmd":"ping"}' | .\target\release\antivirus_engine.exe
# Expected: {"status":"pong"}

echo '{"id":"2","cmd":"scan-file","path":"C:\\Windows\\System32\\notepad.exe"}' | .\target\release\antivirus_engine.exe
```

### Train the network ML model from scratch

If `models/network/` is empty or you want to retrain:

```powershell
cd C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\src\core\network\Feature_extractor\ML_IDS
python preprocessing_pipeline.py
```

This trains the XGBoost IDS on UNSW-NB15 data and saves model files to `models/network/`.

### Train the process GRU model from scratch

```powershell
cd C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\src\core\process\Sys_API
python preprocessing_pipeline.py
```

### Train the memory classifier

```powershell
cd C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\src\core\memory\ML_models\Deep_dive
python preprocessing_pipeline.py
```

### Run the smoke test

```powershell
cd C:\Users\houss\Desktop\AegisAI
python diagnostic_test.py
```

---

## 9. Troubleshooting

### `cargo build` fails with "linker not found"

The MSVC C++ toolchain is not on PATH. Fix:

```powershell
# Verify Visual Studio Build Tools are installed
where cl.exe

# If not found, launch the VS Developer PowerShell from Start Menu,
# or run the VS environment setup script:
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

---

### `error: failed to run custom build command for yara-x`

YARA-X needs a C compiler. Ensure Visual Studio Build Tools (section 2.4) are installed with the "Desktop development with C++" workload.

---

### Tauri dev window does not open / WebView2 error

WebView2 is missing. Install it per section 2.5, then restart.

---

### Network scan returns no results / packet capture fails

- Npcap is not installed (section 2.6) — install it with WinPcap compatibility mode.
- The app is not running as Administrator — restart PowerShell as Admin.
- Check available interfaces:
  ```powershell
  Get-NetAdapter | Select-Object Name, Status
  ```

---

### Python ML pipeline import error (`ModuleNotFoundError`)

Install the missing package:

```powershell
pip install <package-name>
```

Common packages needed: `numpy`, `pandas`, `scikit-learn`, `xgboost`, `joblib`, `torch`.

---

### `npm run tauri dev` is very slow on first run

Cargo compiles the Tauri Rust backend from scratch on the first run. This is normal and takes 3–8 minutes. Subsequent runs are much faster.

---

### Port conflict / Vite dev server fails to start

Default port is 1420. If it is in use:

```powershell
netstat -ano | findstr :1420
# Kill the conflicting process or change the port in UI/vite.config.ts
```

---

### Process/memory scanner requires elevation

Any command that inspects other processes (`scan-processes`, `scan-memory`, `kill-process`, `dump-memory`) requires the engine to run as Administrator. Always launch AegisAI with **"Run as administrator"**.

---

## Quick Reference — All Commands

```powershell
# Build engine
cd AegisAI\Antivirus_Engine && cargo build --release

# Run engine tests
cargo test --release

# Install UI deps
cd AegisAI\UI && npm install

# Type-check UI only (no build)
npx tsc --noEmit

# Dev mode (hot reload) — run as Administrator
cd AegisAI\UI && npm run tauri dev

# Production build
cd AegisAI\UI && npm run tauri build

# Train network ML model
cd AegisAI\Antivirus_Engine\src\core\network\Feature_extractor\ML_IDS
python preprocessing_pipeline.py

# Train process GRU model
cd AegisAI\Antivirus_Engine\src\core\process\Sys_API
python preprocessing_pipeline.py

# Train memory model
cd AegisAI\Antivirus_Engine\src\core\memory\ML_models\Deep_dive
python preprocessing_pipeline.py

# Smoke test
cd AegisAI && python diagnostic_test.py
```
