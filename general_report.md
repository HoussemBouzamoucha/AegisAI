\documentclass[12pt,a4paper]{report}

% ── Packages ──────────────────────────────────────────────────────────────────
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{lmodern}
\usepackage[margin=2.5cm]{geometry}
\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{amsmath,amssymb}
\usepackage{listings}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{hyperref}
\usepackage{fancyhdr}
\usepackage{titlesec}
\usepackage{enumitem}
\usepackage{mdframed}
\usepackage{tikz}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\usetikzlibrary{shapes,arrows,positioning,fit,backgrounds}

% ── Colors ────────────────────────────────────────────────────────────────────
\definecolor{aegisblue}{RGB}{30,80,162}
\definecolor{aegiscyan}{RGB}{0,172,193}
\definecolor{aegisdark}{RGB}{20,20,35}
\definecolor{malicious}{RGB}{200,40,40}
\definecolor{suspicious}{RGB}{220,140,0}
\definecolor{clean}{RGB}{30,150,70}
\definecolor{codegray}{RGB}{245,245,245}
\definecolor{codegreen}{RGB}{0,128,0}
\definecolor{codepurple}{RGB}{128,0,128}

% ── Code listings style ───────────────────────────────────────────────────────
\lstdefinestyle{rust}{
  backgroundcolor=\color{codegray},
  commentstyle=\color{codegreen}\itshape,
  keywordstyle=\color{aegisblue}\bfseries,
  stringstyle=\color{codepurple},
  basicstyle=\ttfamily\footnotesize,
  breakatwhitespace=false,
  breaklines=true,
  captionpos=b,
  keepspaces=true,
  numberstyle=\tiny\color{gray},
  numbers=left,
  numbersep=5pt,
  showspaces=false,
  showstringspaces=false,
  showtabs=false,
  tabsize=2,
  frame=single,
  rulecolor=\color{aegisblue!40},
}

\lstdefinestyle{python}{
  backgroundcolor=\color{codegray},
  commentstyle=\color{codegreen}\itshape,
  keywordstyle=\color{aegisblue}\bfseries,
  stringstyle=\color{codepurple},
  basicstyle=\ttfamily\footnotesize,
  breaklines=true,
  captionpos=b,
  numbers=left,
  numberstyle=\tiny\color{gray},
  numbersep=5pt,
  frame=single,
  rulecolor=\color{aegisblue!40},
}

\lstdefinestyle{json}{
  backgroundcolor=\color{codegray},
  basicstyle=\ttfamily\footnotesize,
  breaklines=true,
  frame=single,
  rulecolor=\color{aegisblue!40},
  morestring=[b]",
  stringstyle=\color{codepurple},
}

% ── Hyperref config ───────────────────────────────────────────────────────────
\hypersetup{
  colorlinks=true,
  linkcolor=aegisblue,
  urlcolor=aegiscyan,
  citecolor=aegisblue,
  pdftitle={AegisAI -- Comprehensive Technical Report},
  pdfauthor={Houssem Bouzamoucha},
}

% ── Header / Footer ───────────────────────────────────────────────────────────
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\textcolor{aegisblue}{\textbf{AegisAI}}}
\fancyhead[R]{\textcolor{gray}{\leftmark}}
\fancyfoot[C]{\thepage}
\renewcommand{\headrulewidth}{0.4pt}

% ── Section formatting ────────────────────────────────────────────────────────
\titleformat{\chapter}[hang]
  {\normalfont\huge\bfseries\color{aegisblue}}
  {\thechapter}{1em}{}
\titleformat{\section}[hang]
  {\normalfont\Large\bfseries\color{aegisblue!80}}
  {\thesection}{1em}{}
\titleformat{\subsection}[hang]
  {\normalfont\large\bfseries\color{aegisblue!60}}
  {\thesubsection}{1em}{}

% ── Custom commands ───────────────────────────────────────────────────────────
\newcommand{\threat}[1]{\textcolor{malicious}{\textbf{#1}}}
\newcommand{\suspicious}[1]{\textcolor{suspicious}{\textbf{#1}}}
\newcommand{\clean}[1]{\textcolor{clean}{\textbf{#1}}}
\newcommand{\code}[1]{\texttt{\small #1}}
\newcommand{\file}[1]{\texttt{\small\color{aegisblue}#1}}

\newmdenv[
  backgroundcolor=aegisblue!5,
  linecolor=aegisblue,
  linewidth=1pt,
  roundcorner=3pt,
]{infobox}

% =============================================================================
% DOCUMENT
% =============================================================================

\begin{document}

% ── Title Page ────────────────────────────────────────────────────────────────
\begin{titlepage}
  \centering
  \vspace*{2cm}

  {\Huge\bfseries\color{aegisblue} AegisAI}\\[0.4cm]
  {\large\color{gray} Multi-Layer Windows Antivirus \& Intrusion Detection System}\\[2cm]

  \rule{\linewidth}{1pt}\\[0.5cm]
  {\LARGE\bfseries Comprehensive Technical Report}\\[0.5cm]
  \rule{\linewidth}{1pt}\\[2cm]

  \begin{tabular}{ll}
    \textbf{Author:}       & Houssem Bouzamoucha \\[0.3cm]
    \textbf{Email:}        & houssem.bouzamoucha@gmail.com \\[0.3cm]
    \textbf{Date:}         & May 18, 2026 \\[0.3cm]
    \textbf{Version:}      & 1.0 \\[0.3cm]
    \textbf{Platform:}     & Windows 10/11 (x86-64) \\[0.3cm]
    \textbf{Language:}     & Rust (engine), Python (ML), TypeScript/React (UI) \\
  \end{tabular}

  \vfill

  \begin{infobox}
    \textbf{Abstract.} AegisAI is a research-grade, multi-layer endpoint security
    system for Windows. It combines four independent scanning domains---file system,
    process behaviour, network traffic, and memory forensics---under a unified entity
    correlation engine that reconstructs cross-domain attack chains using graph
    analysis. Three machine-learning pipelines (EMBER2024 gradient-boosted trees for
    PE files, a GRU sequence model for Windows API call traces, and an XGBoost
    network intrusion-detection model trained on UNSW-NB15) augment the classical
    heuristic layer. All components communicate through a daemon-mode Rust backend
    exposed via a Tauri IPC bridge to a React/TypeScript desktop frontend.
  \end{infobox}
\end{titlepage}

\tableofcontents
\newpage
\listoftables
\newpage

% =============================================================================
\chapter{System Overview}
% =============================================================================

\section{Introduction and Goals}

AegisAI addresses the limitations of signature-only antivirus engines by combining
five independent detection layers that collaborate through a shared entity model.
The system aims to:

\begin{enumerate}
  \item Detect malware at rest (file scanner), in execution (process scanner), during
        network communication (IDS), and after injection (memory scanner).
  \item Correlate cross-domain signals into a \emph{threat graph} that surfaces
        attack chains a single scanner would miss.
  \item Provide actionable containment---quarantine, firewall rules, memory dumps,
        network isolation---triggered from the same UI that surfaced the threat.
  \item Keep heuristics and ML loosely coupled so either layer degrades gracefully
        if the other is unavailable.
\end{enumerate}

\section{High-Level Architecture}

The system consists of three tiers:

\begin{description}
  \item[Tier 1 -- Scanning Engine] A Rust binary compiled in release mode. Runs as
    a persistent daemon process. Implements four scanner domains plus the entity
    correlation and graph pipeline. Communicates over \texttt{stdin}/\texttt{stdout}
    using line-delimited JSON-RPC.

  \item[Tier 2 -- ML Pipelines] Python subprocesses (one per domain). Long-lived
    server processes loaded once at daemon startup to amortise cold-start cost.
    Models: EMBER2024 (LightGBM), GRU (PyTorch), XGBoost (scikit-learn/xgboost).

  \item[Tier 3 -- Tauri Desktop Application] A Tauri v2 application bundling a
    React 18 / TypeScript frontend. The Tauri Rust backend spawns the daemon and
    forwards IPC invocations. State is managed with Zustand; the threat graph is
    rendered with D3.js.
\end{description}

\subsection{Full Data Flow}

\begin{center}
\begin{tikzpicture}[
  node distance=0.8cm and 1.6cm,
  box/.style={rectangle, draw=aegisblue, fill=aegisblue!8, rounded corners=3pt,
              text width=3.2cm, align=center, minimum height=0.85cm, font=\small},
  mlbox/.style={rectangle, draw=suspicious!70, fill=suspicious!10, rounded corners=3pt,
               text width=3.2cm, align=center, minimum height=0.85cm, font=\small},
  arrow/.style={->, thick, color=aegisblue!70},
  mlArrow/.style={->, thick, color=suspicious!70, dashed},
]

\node[box] (ui)     {React / Tauri UI\\(8 views)};
\node[box, below=of ui] (tauri)  {Tauri Rust Backend\\(IPC router)};
\node[box, below=of tauri] (daemon) {Antivirus Daemon\\(JSON-RPC loop)};

\node[box, below left=1cm and 2.5cm of daemon]  (fs)  {File System\\Scanner};
\node[box, below left=1cm and 0.6cm of daemon]  (proc){Process\\Scanner};
\node[box, below right=1cm and 0.6cm of daemon] (net) {Network\\Scanner};
\node[box, below right=1cm and 2.5cm of daemon] (mem) {Memory\\Scanner};

\node[box, below=1.4cm of daemon]  (em)  {Entity Manager\\(10-min window)};
\node[box, below=of em]  (corr){Entity Correlator\\+ Aggregator};
\node[box, below=of corr] (gb)  {Graph Builder\\(O(n) join-key)};
\node[box, below=of gb]   (ga)  {Graph Analyzer\\(7 attack patterns)};

\node[mlbox, right=2.2cm of fs]   (ember){EMBER2024\\(LightGBM)};
\node[mlbox, right=2.2cm of proc] (gru)  {GRU Process\\(PyTorch)};
\node[mlbox, right=2.2cm of net]  (xgb)  {XGBoost IDS\\(UNSW-NB15)};

\draw[arrow] (ui) -- (tauri);
\draw[arrow] (tauri) -- (daemon);
\draw[arrow] (daemon) -- (fs);
\draw[arrow] (daemon) -- (proc);
\draw[arrow] (daemon) -- (net);
\draw[arrow] (daemon) -- (mem);
\draw[arrow] (fs)   |- (em);
\draw[arrow] (proc) |- (em);
\draw[arrow] (net)  |- (em);
\draw[arrow] (mem)  |- (em);
\draw[arrow] (em)   -- (corr);
\draw[arrow] (corr) -- (gb);
\draw[arrow] (gb)   -- (ga);

\draw[mlArrow] (fs)   -- (ember);
\draw[mlArrow] (proc) -- (gru);
\draw[mlArrow] (net)  -- (xgb);
\draw[mlArrow] (ember) |- (em);
\draw[mlArrow] (gru)   |- (em);
\draw[mlArrow] (xgb)   |- (em);

\end{tikzpicture}
\end{center}

\section{Repository Structure}

\begin{verbatim}
AegisAI/
├── Antivirus_Engine/
│   ├── src/
│   │   ├── main.rs                  # Daemon entry point, JSON-RPC loop
│   │   └── core/
│   │       ├── types.rs             # Shared Rust types
│   │       ├── utils.rs             # SHA-256, entropy, PE detection
│   │       ├── file_system/         # YARA + heuristics + scan_all
│   │       ├── process/             # sysinfo-based process scanner
│   │       ├── network/             # IP-helper enumeration + ML bridge
│   │       ├── memory/              # VirtualQuery scanner
│   │       ├── entity/              # EntityManager, correlator, aggregator
│   │       ├── graph/               # ThreatGraph, analyzer, builder
│   │       └── action/              # Post-verdict containment actions
│   ├── yara_rules/                  # 1,000+ YARA rules
│   └── Cargo.toml
├── UI/
│   ├── src-tauri/src/main.rs        # Tauri IPC commands, daemon lifecycle
│   └── src/
│       ├── store/index.ts           # Zustand state store
│       ├── types/index.ts           # TypeScript type definitions
│       ├── lib/entityUtils.ts       # Client-side entity aggregation
│       └── components/              # React views
└── ai_agent/                        # Python ML environment (.venv)
\end{verbatim}

% =============================================================================
\chapter{Daemon and IPC Protocol}
% =============================================================================

\section{Daemon Architecture}

The scanning engine runs as a long-lived child process of the Tauri backend,
spawned once at application startup. This design allows expensive initialisation
operations---YARA rule compilation, ML model loading---to be amortised across all
subsequent requests.

\begin{infobox}
  \textbf{Startup sequence.} The daemon prints \texttt{\{"status":"ready"\}} to
  stdout once all YARA rules have been compiled and scanner singletons initialised.
  The Tauri backend waits for this message before accepting any UI commands.
\end{infobox}

The daemon reads one JSON line from \texttt{stdin} per request and writes one JSON
line to \texttt{stdout} per response. A UUID \code{id} field ties each response
back to the originating request, enabling the Tauri backend to multiplex concurrent
UI invocations over the single stdin/stdout channel.

\section{JSON-RPC Command Table}

\begin{longtable}{@{}lll@{}}
  \toprule
  \textbf{Command} & \textbf{Extra Arguments} & \textbf{Response Shape} \\
  \midrule
  \endhead
  \code{ping}             & --                        & \code{\{status:"pong"\}} \\
  \code{scan-file}        & \code{path}               & \code{ScanResult} \\
  \code{scan-dir}         & \code{path}               & \code{\{files[], statistics\}} \\
  \code{scan-all}         & --                        & \code{\{files[], statistics, cached\_hits\}} \\
  \code{scan-processes}   & --                        & \code{\{processes[], statistics\}} \\
  \code{scan-network}     & \code{pid?}               & \code{\{connections[], statistics\}} \\
  \code{scan-memory}      & \code{pid?}               & \code{\{regions[], statistics\}} \\
  \code{kill-process}     & \code{pid}                & \code{\{success, message?\}} \\
  \code{correlate}        & \code{include\_memory}    & \code{CorrelateResult} \\
  \code{quarantine-file}  & \code{path}               & \code{QuarantineResult} \\
  \code{block-ip}         & \code{remote\_ip, direction} & \code{BlockIpResult} \\
  \code{remove-block-ip}  & \code{rule\_name}         & \code{\{success\}} \\
  \code{dump-memory}      & \code{pid}                & \code{DumpResult} \\
  \code{check-persistence}& \code{suspicious\_paths[]}& \code{PersistenceResult} \\
  \code{isolate-network}  & --                        & \code{IsolationResult} \\
  \code{restore-network}  & --                        & \code{\{success\}} \\
  \bottomrule
  \caption{Full JSON-RPC command set supported by the daemon.}
\end{longtable}

\section{Example Exchange}

\begin{lstlisting}[style=json, caption={Scan-file request and response}]
// Request (Tauri → daemon, via stdin)
{
  "id":   "b3f2a1-...",
  "cmd":  "scan-file",
  "path": "C:\\Users\\user\\Downloads\\suspicious.exe"
}

// Response (daemon → Tauri, via stdout)
{
  "id":             "b3f2a1-...",
  "success":        true,
  "path":           "C:\\Users\\user\\Downloads\\suspicious.exe",
  "level":          "Malicious",
  "reason":         "Dynamic analysis (score: 14): Very high entropy (7.82) -- packed/crypted; PE executable; Suspicious strings in PE binary: iex(, frombase64string",
  "hash":           "e3b0c44298fc1c149afb...",
  "confidence_score": 0.93,
  "detection_signals": [
    { "source": "entropy",  "description": "Very high entropy (7.82)", "score": 3 },
    { "source": "structure","description": "PE executable",            "score": 1 },
    { "source": "keyword",  "description": "Suspicious strings: iex(", "score": 6 }
  ]
}
\end{lstlisting}

% =============================================================================
\chapter{File System Scanner}
% =============================================================================

\section{Scanner Architecture}

The file system domain comprises four cooperating components:

\begin{description}
  \item[\file{scanner.rs}] \code{FileSystemScanner} -- single-file entry point;
    calls signature lookup, YARA matching, and the heuristic analyser in sequence.
  \item[\file{heuristics.rs}] \code{HeuristicAnalyzer} -- the main scoring engine,
    described in detail below.
  \item[\file{scan\_all.rs}] \code{SystemScanner} + \code{ScanScheduler} -- parallel
    system-wide scanner with mtime/size cache and priority ordering.
  \item[\file{yara\_engine.rs}] YARA-X wrapper with wasmtime JIT; rules compiled
    once at daemon startup.
\end{description}

\section{Heuristic Engine (\texttt{HeuristicAnalyzer})}

\subsection{Single-Read Optimisation}

The engine reads each file into a \code{Vec<u8>} buffer (capped at 10~MiB) exactly
once. All downstream checks---magic bytes, Shannon entropy, content keyword scan,
Base64 detection, crypto address detection, and SHA-256 hashing---share this buffer.
Files larger than 10~MiB receive only metadata-level checks (filename, extension,
timestamp) plus streaming SHA-256.

\subsection{Two-Pass Triage}

For full-system scans a fast pre-score runs first:

\begin{lstlisting}[style=rust, caption={Fast triage score (excerpt from heuristics.rs)}]
pub fn fast_score(path: &Path, file_size: u64, bytes: &[u8]) -> i32 {
    let ext = ...; // lowercased once
    let mut score: i32 = 0;
    if let Some(c) = check_zero_byte(ext, file_size)        { score += c.score; }
    if let Some(c) = check_filename(path, ext, is_exec)     { score += c.score; }
    if let Some(c) = check_extension(path, ext, is_doc)     { score += c.score; }
    if bytes.len() >= 2 {
        if let Some(c) = check_magic_bytes(bytes, ext, is_doc) { score += c.score; }
    }
    if is_exec && file_size > 100 && !bytes.is_empty() {
        if let Some(c) = check_entropy(bytes)               { score += c.score; }
    }
    score  // expensive content scan + YARA only when score >= SUSPICIOUS_THRESHOLD
}
\end{lstlisting}

Files scoring below \texttt{SUSPICIOUS\_THRESHOLD} (5) skip the full content
scan and YARA pass, running at approximately 5\,000 files per second per thread.

\subsection{Scoring Rules}

\begin{longtable}{@{}p{5cm}rp{6.8cm}@{}}
  \toprule
  \textbf{Rule} & \textbf{Score} & \textbf{Condition} \\
  \midrule
  \endhead
  Zero-byte executable            & $+8$  & File size $= 0$, extension in exec set \\
  Tiny dropper                    & $+4$  & $0 <$ size $< 512\,\text{B}$, \code{.exe} only \\
  Ransomware note filename        & $+7$  & Compound patterns in \code{.txt/.html/.hta} names \\
  Malware filename pattern        & $+5$  & Substrings in exec filenames (e.g.\ \emph{payload}, \emph{keylogger}) \\
  Ransomware extension            & $+8$  & Known extensions: \code{.locky}, \code{.cerber}, \code{.ryuk}, \ldots \\
  Double extension trick          & $+4$  & \code{document.pdf.exe} pattern \\
  PE content in document ext      & $+3$  & File type mismatch (MZ header in \code{.docx}) \\
  Valid PE header                 & $+1$  & Matching extension (\code{.exe/.dll/.sys}) \\
  High entropy $> 7.2$ (exec)    & $+2$  & Shannon entropy on executable bytes \\
  Very high entropy $> 7.7$       & $+3$  & Any file type; threshold raised from 7.5 \\
  Ransomware content phrase       & $+5$/hit, $\leq +20$ & Full phrases: ``pay bitcoin'', ``all your files have been'' \\
  Crypto wallet address           & $+5$  & Bitcoin/Ethereum; entropy-gated to suppress false positives \\
  Script keyword hit              & $+3$/hit, $\leq +12$ & Live code: \code{iex(}, \code{downloadstring}, \code{writeprocessmemory}, \ldots \\
  PE binary obfuscation keyword   & $+2$/hit, $\leq +6$  & String-table: \code{-encodedcommand}, \code{frombase64string}, \ldots \\
  PowerShell obfuscation          & $+4$  & $\geq 2$ obfuscation patterns co-occur \\
  Base64 payload (script $> 400\,\text{B}$) & $+1$ & Long base64 line in script file \\
  Timestamp: modified $<$ created & $+1$  & Common on copied files -- low weight \\
  Suspicious future timestamp     & $+2$  & Modification time $>$ now + 1 year \\
  \bottomrule
  \caption{Complete heuristic scoring table (\texttt{heuristics.rs}).}
  \label{tab:heuristics}
\end{longtable}

\subsection{Verdict Thresholds and Confidence Mapping}

\begin{equation}
  \text{level} =
  \begin{cases}
    \threat{Malicious}    & \text{if } s \geq 10 \\
    \suspicious{Suspicious} & \text{if } 5 \leq s < 10 \\
    \clean{Clean}           & \text{if } s < 5
  \end{cases}
\end{equation}

\begin{equation}
  \text{confidence} =
  \begin{cases}
    1.0                                              & \text{Clean} \\
    0.55 + \min\!\left(\tfrac{s}{40},\,0.25\right)  & \text{Suspicious} \\
    0.70 + \min\!\left(\tfrac{s}{60},\,0.25\right)  & \text{Malicious}
  \end{cases}
\end{equation}

\subsection{Path Trust Tiers}

To reduce false positives on legitimate Windows system files, the engine applies
path-based score capping:

\begin{longtable}{@{}lll@{}}
  \toprule
  \textbf{Tier} & \textbf{Paths} & \textbf{Effect} \\
  \midrule
  \endhead
  \code{TrustedSystem}  & \code{Windows\textbackslash System32}, \code{SysWOW64} & Cap score at $9$ (below Malicious) \\
  \code{TrustedInstall} & \code{WinSxS}, \code{Installer}, \code{node\_modules},
                          \code{.nuget}, Program Files, Cargo registry & Cap score at $9$ \\
  \code{Unknown}        & All other paths & Full scoring applies \\
  \bottomrule
  \caption{Path trust tier definitions.}
\end{longtable}

\subsection{Binary-Safe Content Analysis}

The content scanner uses \code{from\_utf8\_lossy} on the shared byte buffer instead
of \code{read\_to\_string}. This ensures binary executables are not silently skipped
during keyword and phrase matching. All comparisons operate on a pre-lowercased byte
slice (\code{to\_ascii\_lowercase}) using a custom \code{memmem} byte-window search,
avoiding heap allocation per comparison.

\subsection{Extension Tables and Binary Search}

Three static, sorted ASCII arrays (\code{DOCUMENT\_EXTENSIONS},
\code{EXECUTABLE\_EXTENSIONS}, \code{SCRIPT\_EXTENSIONS}) enable O($\log n$)
extension classification. A compile-time test (\code{test\_extension\_arrays\_sorted})
asserts sort order.

\subsection{Entropy-Gated Crypto Address Detection}

A na\"{i}ve Bitcoin/Ethereum address detector would flag TLS library DLLs whose
DER byte sequences resemble wallet addresses. AegisAI gates each candidate address
match against the local Shannon entropy of a $\pm 128$-byte window:

\begin{equation}
  \text{flag} = \text{address\_match} \;\wedge\; H_{\text{local}} \leq 6.5\,\text{bits/byte}
\end{equation}

Dense binary or cryptographic data exceeds this threshold and is suppressed.

\section{YARA Integration}

The engine uses \textbf{yara-x 1.13} with a \textbf{wasmtime} JIT backend.
Over 1,000 rules are compiled \emph{once} at daemon startup into a single
\code{YaraEngine} singleton. The rule set is organised into thematic index files:

\begin{itemize}
  \item \code{malware\_index.yar} -- generic malware families
  \item \code{cve\_rules\_index.yar} -- known CVE exploit patterns
  \item \code{capabilities\_index.yar} -- capability-based detection (keylogger, screen capture)
  \item \code{crypto\_index.yar} -- cryptocurrency miner patterns
  \item \code{exploit\_kits\_index.yar} -- exploit kit landing pages
  \item \code{webshells\_index.yar} -- web shell variants
\end{itemize}

YARA is disabled during full system scans to prevent wasmtime JIT deadlocks under
high concurrency; single-file manual scans use full YARA matching.

\section{System-Wide Scanner (\texttt{scan\_all.rs})}

The \code{SystemScanner} performs a full-disk scan with the following features:

\begin{description}
  \item[Incremental caching] Each file's modification time and size are hashed
    into a cache key. Unchanged files from prior scans are skipped in O(1).
  \item[Priority ordering] A \code{ScanPrioritizer} assigns risk scores based on
    extension, location (temp directories, user profile), and filename patterns.
    High-risk files are queued first so the most suspicious results appear quickly.
  \item[Thread pool] Up to 16 worker threads each holding one
    \code{Arc<Mutex<FileSystemScanner>>} instance.
  \item[\code{ScanScheduler}] Optional background thread that re-triggers
    system scans on a configurable interval.
\end{description}

% =============================================================================
\chapter{Process Scanner}
% =============================================================================

\section{Data Collection}

The process scanner uses the \textbf{sysinfo} crate to enumerate all running
processes. For each process it collects:

\begin{itemize}
  \item PID, parent PID, process name, executable path, command-line arguments
  \item CPU usage (\%), committed memory (bytes), thread count
  \item Loaded DLL/module list (via Windows \code{EnumProcessModules})
  \item Open handle inspection (file, registry, named-pipe handles)
\end{itemize}

\section{Heuristic Scoring}

\begin{longtable}{@{}p{5.5cm}rp{6.5cm}@{}}
  \toprule
  \textbf{Rule} & \textbf{Score} & \textbf{Condition} \\
  \midrule
  \endhead
  No executable path (non-system) & $+5$  & Process hollowing indicator \\
  Executable outside standard paths & $+4$ & Not in Program Files, Windows, Users \\
  System process in wrong location  & $+8$ & e.g.\ \code{svchost.exe} not in \code{System32} \\
  Known malware process name        & $+10$& \code{mimikatz}, \code{meterpreter}, \ldots \\
  Suspicious name pattern           & $+5$ & \code{svch0st}, \code{wininit32}, \ldots \\
  Zero thread count                 & $+6$ & Process hollowing / zombie process \\
  CPU usage $> 90\%$                & $+3$ & Cryptocurrency miner indicator \\
  Memory $> 1\,\text{GB}$          & $+2$ & Data stealer / memory bomb \\
  Suspicious command-line argument  & $+3$/hit, $\leq +9$ & \code{-enc}, \code{IEX}, \code{bypass}, \ldots \\
  \midrule
  \textit{Dev-tool halving}         & score $\div 2$ & \code{rust-analyzer}, \code{cargo}, \code{node}, \code{python} \\
  \bottomrule
  \caption{Process scanner heuristic rules.}
\end{longtable}

\subsection{Verdict Thresholds}

\begin{equation}
  \text{level} =
  \begin{cases}
    \threat{Critical}       & s \geq 15 \\
    \threat{Malicious}      & 10 \leq s < 15 \\
    \suspicious{Suspicious} & 4 \leq s < 10 \\
    \clean{Safe}            & s < 4
  \end{cases}
\end{equation}

% =============================================================================
\chapter{Network Scanner and IDS}
% =============================================================================

\section{Data Collection}

The network scanner uses the Windows IP Helper API
(\code{GetExtendedTcpTable} / \code{GetExtendedUdpTable}) to enumerate all active
TCP and UDP connections. Per-connection data includes:

\begin{itemize}
  \item Protocol, local address:port, remote address:port, connection state
  \item Owning process PID (mapped to process name via the process scanner)
\end{itemize}

\section{Machine Learning: XGBoost Network IDS}

\subsection{Dataset}

The IDS model is trained on \textbf{UNSW-NB15}, a publicly available network
intrusion dataset containing approximately 100\,000 flow records across nine attack
categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance,
Shellcode, and Worms, plus a benign class.

\subsection{Feature Engineering Pipeline}

The preprocessing script (\file{ML\_IDS/preprocessing\_pipeline.py}) transforms
47 raw UNSW-NB15 features into 56 model-ready features:

\begin{longtable}{@{}lp{9cm}@{}}
  \toprule
  \textbf{Feature Group} & \textbf{Features} \\
  \midrule
  \endhead
  Flow timing (8)          & \code{dur, Stime, Ltime, Sintpkt, Dintpkt, tcprtt, synack, ackdat} \\
  Packet bytes (6)         & \code{sbytes, dbytes, Sload, Dload, smeansz, dmeansz} \\
  Packet count (6)         & \code{Spkts, Dpkts, swin, dwin, sloss, dloss} \\
  TTL (2)                  & \code{sttl, dttl} \\
  TCP handshake (3)        & \code{stcpb, dtcpb, trans\_depth} \\
  HTTP/FTP context (5)     & \code{res\_bdy\_len, ct\_flw\_http\_mthd, is\_ftp\_login, ct\_ftp\_cmd, ct\_srv\_src} \\
  Connection context (7)   & \code{ct\_state\_ttl, ct\_srv\_dst, ct\_dst\_ltm, ct\_src\_ltm, ct\_src\_dport\_ltm, ct\_dst\_sport\_ltm, ct\_dst\_src\_ltm} \\
  Categorical encoded (3)  & \code{proto, state, service} via \code{OrdinalEncoder} \\
  IP classification (8)    & \code{src/dst is\_private, is\_global, is\_multicast, version} \\
  Subnet encoding (2)      & \code{src\_subnet, dst\_subnet} (/24 subnet IDs) \\
  Frequency maps (2)       & \code{src\_freq, dst\_freq} (historical flow counts) \\
  Jitter (2)               & \code{Sjit, Djit} \\
  Port fields (2)          & \code{sport, dsport} \\
  \bottomrule
  \caption{56-feature model input derived from 47 UNSW-NB15 raw features.}
\end{longtable}

\subsection{Clean-IP Filtering}

Flows to or from well-known CDN/cloud infrastructure are filtered \emph{before}
the model to suppress structural false positives. The filter covers prefixes for
Google, Microsoft/Azure, Cloudflare, Apple, and Amazon AWS:

\begin{lstlisting}[style=python, caption={Clean-IP prefix filter (excerpt)}]
CLEAN_PREFIXES = [
    '8.8.', '8.34.', '34.', '35.',          # Google
    '13.64.', '20.', '40.', '52.',           # Microsoft / Azure
    '1.1.1.', '104.16.',                     # Cloudflare
    '17.',                                   # Apple
    '54.', '18.', '3.',                      # Amazon / AWS
]

def _is_clean_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in CLEAN_PREFIXES)
\end{lstlisting}

\subsection{Inference Thresholds}

\begin{equation}
  \text{level} =
  \begin{cases}
    \threat{Malicious}      & P(\text{intrusion}) \geq 0.80 \\
    \suspicious{Suspicious} & 0.55 \leq P < 0.80 \\
    \clean{Clean}           & P < 0.55
  \end{cases}
\end{equation}

\subsection{Model Calibration}

The primary model is a \code{CalibratedClassifierCV}-wrapped XGBoost classifier
for well-calibrated probability outputs. A raw (uncalibrated) XGBoost model
serves as fallback if calibration artefacts are absent.

% =============================================================================
\chapter{Memory Scanner}
% =============================================================================

\section{Data Collection}

The memory scanner uses the Windows \code{VirtualQueryEx} API to enumerate all
committed memory regions in a target process. For each region it records:

\begin{itemize}
  \item Base address, region size, memory protection flags (read/write/execute)
  \item Allocation type (private, mapped, image)
  \item First 512 bytes of region content (sampled for pattern analysis)
\end{itemize}

\section{Heuristic Rules}

\begin{longtable}{@{}p{5.5cm}rp{6.5cm}@{}}
  \toprule
  \textbf{Rule} & \textbf{Score} & \textbf{Condition} \\
  \midrule
  \endhead
  RWX protection             & $+15$ & Region is simultaneously writable and executable \\
  Private + writable + high entropy & $+8$ & Likely injected payload \\
  PE header in non-image region & $+10$ & DLL injection / manual mapping \\
  YARA shellcode pattern     & $+12$ & Known shellcode byte sequences \\
  Entropy $> 7.5$ in region  & $+6$  & Packed/encrypted in-memory code \\
  \midrule
  \textit{Thresholds} & & \\
  $\geq 20$ & & \threat{Malicious} \\
  $\geq 10$ & & \suspicious{Suspicious} \\
  $< 10$   & & \clean{Clean} \\
  \bottomrule
  \caption{Memory scanner heuristic rules and thresholds.}
\end{longtable}

\section{Trust Model (False-Positive Reduction)}

A three-tier trust model reduces false positives from JIT-compiled runtimes:

\begin{description}
  \item[\code{SystemOs}] Core Windows system processes.
  \item[\code{JitRuntime}] Approximately 90 known JIT processes (Chrome, Node.js,
    the CLR, Java HotSpot, Firefox SpiderMonkey, V8). These legitimately allocate
    RWX regions; shellcode thresholds are raised.
  \item[\code{TrustedInstall}] Installer processes; NOP/INT3 thresholds tightened.
  \item[\code{Unknown}] All other processes -- full scoring applies.
\end{description}

% =============================================================================
\chapter{Machine Learning Pipelines}
% =============================================================================

\section{Dual-Layer Scoring Philosophy}

AegisAI uses a \emph{hybrid scoring} strategy: classical heuristics provide an
always-available synchronous verdict; ML models provide asynchronous refinement
that can promote or demote that verdict.

\begin{equation}
  \text{combined\_score} =
  \begin{cases}
    \min\!\left(H \times 0.4 + \text{ML} \times 0.6,\; 1.0\right)
      & \text{if ML score available} \\
    H & \text{otherwise}
  \end{cases}
\end{equation}

where $H$ is the normalised heuristic score in $[0,1]$ and ML is the model
probability. The 40/60 weighting reflects the empirical finding that the ML models
are more accurate on known malware families, while heuristics catch novel variants
and model-evasion attempts.

\section{EMBER2024 File Classification}

\subsection{Architecture}

EMBER2024 uses \textbf{LightGBM} gradient-boosted decision trees trained on the
EMBER (Endgame Malware Benchmark for Research) dataset, extended with 2024 samples.

\begin{description}
  \item[Input] 2,381 features extracted from Windows PE headers:
    section entropy, import table richness, string characteristics, header flags,
    and section layout statistics.
  \item[Models] Five domain-specific models: Win32, Win64, .NET (DotNet),
    PDF, and a universal model.
  \item[Routing] Magic-byte detection routes each file to its domain model:
    \code{MZ} header (PE), \code{\%PDF} prefix, \code{MZ} with .NET metadata.
\end{description}

\subsection{Integration}

The Tauri backend spawns a long-lived Python subprocess (\code{bridge.py}) that
loads all five EMBER models once at startup (approximately 120\,s cold-start).
Subsequent batch inference requests take $< 5$\,s.

\subsection{Verdict Escalation}

\begin{equation}
  \text{escalation} =
  \begin{cases}
    \text{Suspicious} \to \threat{Malicious} & \text{EMBER score} \geq 0.80 \\
    \text{keep Suspicious}                   & 0.60 \leq \text{score} < 0.80 \\
    \text{Suspicious} \to \clean{Clean}      & \text{score} < 0.60
  \end{cases}
\end{equation}

EMBER only runs on files already marked \suspicious{Suspicious} by the heuristic
layer, keeping inference cost proportional to alert volume.

\section{GRU Process Behaviour Model}

\subsection{Architecture}

A \textbf{Gated Recurrent Unit (GRU)} model classifies processes based on their
Windows API call sequences.

\begin{description}
  \item[Input] Sequence of Windows API names (\code{OpenProcess},
    \code{WriteProcessMemory}, \code{CreateRemoteThread}, etc.) collected via
    module handle analysis and call trace logging.
  \item[Architecture] Single-layer GRU with hidden dimension from \code{config.json};
    maximum sequence length \texttt{MAX\_LEN = 177}.
  \item[Training] Binary classification: benign API trace vs.\ malware API trace.
\end{description}

\subsection{Preprocessing Pipeline}

\begin{lstlisting}[style=python, caption={GRU sequence preprocessing (preprocessing\_pipeline.py)}]
PAD_TOKEN = "PAD"
PAD_IDX   = 0
MIN_VALID_LEN = 5     # reject sequences too short to be meaningful
MAX_LEN       = 177   # fixed input length (matches model config.json)
STRIDE        = 100   # sliding-window stride for long sequences

def prepare_for_inference(api_sequence, vocab):
    # 1. Strip empty / None entries
    calls = [c for c in api_sequence if c and c.strip()]
    # 2. Validate syntax: ^[A-Za-z_][A-Za-z0-9_]*$
    calls = [c if is_valid_api(c) else PAD_TOKEN for c in calls]
    # 3. Keep only vocab-known calls
    calls = [c for c in calls if c in vocab and c != PAD_TOKEN]
    if len(calls) < MIN_VALID_LEN:
        return None  # "TOO_SHORT"
    # 4. Encode to integer IDs
    ids = [vocab.get(c, 0) for c in calls]
    # 5. For long sequences: sliding window chunks (stride=100)
    if len(ids) > MAX_LEN:
        chunks = []
        for start in range(0, len(ids) - MAX_LEN + 1, STRIDE):
            chunks.append(ids[start:start + MAX_LEN])
        return chunks  # scored independently; max score wins
    # 6. Pad right to MAX_LEN
    ids += [PAD_IDX] * (MAX_LEN - len(ids))
    return [ids]
\end{lstlisting}

\subsection{Thresholds}

\begin{equation}
  \text{escalation} =
  \begin{cases}
    \to \threat{Malicious} & P(\text{malicious}) \geq 0.75 \\
    \text{keep Suspicious} & 0.50 \leq P < 0.75 \\
    \to \clean{Safe}       & P < 0.50
  \end{cases}
\end{equation}

\section{Combined Score Formula (Entity Layer)}

When entities are aggregated into \code{AggregatedEntity} objects, per-domain
scores are normalised and combined:

\begin{align}
  \text{proc\_score}    &= \min\!\left(\frac{T_{\text{proc}}}{30},\; 1\right) \\[4pt]
  \text{network\_score} &= \max_{c \in \text{owned connections}}\!\min\!\left(\frac{T_c}{40},\;1\right) \\[4pt]
  \text{memory\_score}  &= \max_{r \in \text{owned regions}}\!\min\!\left(\frac{T_r}{40},\;1\right) \\[4pt]
  \text{file\_score}    &= \max_{f \in \text{owned files}} \text{confidence}(f) \\[4pt]
  H &= \max(\text{proc\_score},\; \text{network\_score},\; \text{memory\_score},\; \text{file\_score}) \\[4pt]
  \text{combined} &=
    \begin{cases}
      \min(H \times 0.4 + \text{ML} \times 0.6,\; 1.0) & \text{if ML available} \\
      H & \text{otherwise}
    \end{cases}
\end{align}

% =============================================================================
\chapter{Entity Correlation Engine}
% =============================================================================

\section{EntityNode}

Every scanner output is converted to an \code{EntityNode} before entering the
correlation pipeline. The node carries:

\begin{itemize}
  \item \code{entity\_id} -- typed unique identifier (e.g.\ \code{proc:1234:svchost.exe})
  \item \code{entity\_type} -- \code{Process | File | NetworkConnection | MemoryRegion}
  \item \code{heuristic\_score}, \code{ml\_score} (optional), \code{combined\_score}
  \item \code{threat\_level} -- \code{UnifiedThreatLevel} (\code{Clean | Suspicious | Malicious | Critical})
  \item \code{JoinKeys} -- structural correlation anchors
  \item \code{EntityAttributes} -- type-specific metadata
\end{itemize}

\section{JoinKeys}

\begin{lstlisting}[style=rust, caption={JoinKeys struct (entity/types.rs)}]
pub struct JoinKeys {
    pub pid:         Option<u32>,    // Process <-> Network <-> Memory
    pub parent_pid:  Option<u32>,    // Parent -> Child process chain
    pub file_path:   Option<String>, // Process exe_path <-> File path
    pub file_hash:   Option<String>, // File <-> File (same binary)
    pub remote_ip:   Option<String>, // Network <-> Network (shared C2)
    pub remote_port: Option<u16>,
}
\end{lstlisting}

\section{Sliding Time Window}

The \code{EntityManager} holds a \code{DashMap<String, EntityNode>} for lock-free
concurrent access. Nodes carry a \code{last\_seen} Unix timestamp. The
\code{prune\_expired()} method removes nodes older than the configured window
(default: 600\,s / 10 minutes), bounding memory usage in long-running sessions.

\section{Parent-Context Boost}

When a parent process is confirmed as a threat, all of its child processes receive
a score boost proportional to the parent's combined score:

\begin{equation}
  \text{child\_score} \mathrel{+}= \alpha \times \text{parent\_combined}
  \quad \text{where } \alpha = 0.15
\end{equation}

\section{Aggregation (\texttt{aggregate()})}

The \code{aggregate()} method groups flat \code{EntityNode} objects into
\code{AggregatedEntity} composites -- one per process PID. Each composite embeds:

\begin{itemize}
  \item The root \code{ProcessAttributes} for that PID.
  \item All owned \code{NetworkConnection} entities (same PID via join key).
  \item All owned \code{MemoryRegion} entities (same PID).
  \item All owned \code{File} entities (exe\_path match).
  \item Intra-entity threat flags: \code{has\_malicious\_memory},
    \code{has\_malicious\_network}, \code{has\_malicious\_file}.
  \item Per-domain sub-scores: \code{process\_score}, \code{network\_score},
    \code{memory\_score}, \code{file\_score}.
\end{itemize}

Orphan network connections (no owning process found) and standalone malicious files
become their own \code{AggregatedEntity} entries.

\section{Entity Correlator (UI View)}

A second aggregation path, \code{EntityCorrelator}, groups flat nodes into
\code{CorrelatedCluster} objects for the EntityManager UI view. This is a
client-side grouping separate from the graph pipeline, using the same join keys
to form per-actor clusters displayed in the entity list table.

% =============================================================================
\chapter{Threat Graph Pipeline}
% =============================================================================

\section{Graph Builder (\texttt{build\_from\_aggregated})}

The graph builder constructs a \code{ThreatGraph} (nodes + directed edges) from
the slice of \code{AggregatedEntity} objects produced by the EntityManager.

\subsection{O(n) Algorithm}

\begin{enumerate}
  \item \textbf{Build 5 join-key index HashMaps} in a single O(n) pass:
    \code{by\_pid}, \code{by\_parent\_pid}, \code{by\_file\_path},
    \code{by\_file\_hash}, \code{by\_remote\_ip}.
  \item \textbf{Emit edges}: for each entity, look up peers in each index.
    Use a \code{HashSet<(String,String)>} to deduplicate undirected edges.
  \item \textbf{Assign weights}: $w = \text{avg}(\text{score}_A, \text{score}_B)
    \times m_{\text{edge type}}$.
\end{enumerate}

\subsection{Edge Type Multipliers}

\begin{longtable}{@{}llr@{}}
  \toprule
  \textbf{Edge Type} & \textbf{Meaning} & \textbf{Multiplier} \\
  \midrule
  \endhead
  \code{SharedC2}           & Two entities share a C2 IP        & $\times 1.50$ \\
  \code{MemoryInjection}    & Process has injected memory region & $\times 1.35$ \\
  \code{NetworkOwner}       & Process owns malicious connection  & $\times 1.25$ \\
  \code{ParentChild}        & Parent spawned child process       & $\times 1.20$ \\
  \code{ProcessOpenedFile}  & Process loaded a malicious file    & $\times 1.10$ \\
  \code{SameProcess}        & Structural PID grouping            & $\times 1.00$ \\
  \code{SharedFileHash}     & Same binary at different path      & $\times 0.90$ \\
  \bottomrule
  \caption{Edge type weights in the ThreatGraph.}
\end{longtable}

\section{Graph Analyzer: Attack Pattern Detection}

\subsection{Overview}

The \code{GraphAnalyzer} implements seven attack pattern detectors, each mapped to
a MITRE ATT\&CK technique:

\begin{longtable}{@{}llp{5cm}l@{}}
  \toprule
  \textbf{\#} & \textbf{Pattern} & \textbf{Detection Method} & \textbf{MITRE} \\
  \midrule
  \endhead
  1 & ProcessInjection       & \code{node.has\_malicious\_memory}                       & T1055 \\
  2 & C2Communication        & \code{node.has\_malicious\_network}                      & T1071 \\
  3 & MalwareExecution       & \code{node.has\_malicious\_file}                         & T1204 \\
  4 & LateralMovement        & ParentChild edge + child has malicious network           & T1021 \\
  5 & SuspiciousSpawn        & ParentChild edge + both nodes are non-Clean              & T1059 \\
  6 & ExploitedTrustedProcess& Clean parent + Malicious child; checks LOLBin list       & T1059/T1204 \\
  7 & MultiStageAttack       & BFS connected component $\geq 3$ threat nodes            & TA0002 \\
  \bottomrule
  \caption{Attack pattern detectors and MITRE ATT\&CK mappings.}
\end{longtable}

\subsection{Confidence Formulas}

\begin{align}
  c_{\text{ProcessInjection}}  &= \text{memory\_score} + 0.15 \times \text{ml\_score} \\
  c_{\text{C2Communication}}   &= \text{network\_score} + 0.20 \times \text{ml\_score} \\
  c_{\text{MalwareExecution}}  &= \text{file\_score} \\
  c_{\text{LateralMovement}}   &= 0.50 \times \overline{\text{score}}_{\text{nodes}} + 0.50 \times \text{child.network\_score} \\
  c_{\text{SuspiciousSpawn}}   &= \min(\text{parent.score},\, \text{child.score}) + \begin{cases}0.15 & \text{both Malicious}\\ 0 & \text{otherwise}\end{cases} \\
  c_{\text{MultiStageAttack}}  &= \overline{\text{score}}_{\text{component}} \times \min\!\left(\frac{|\text{scanner types}|}{3},\;1\right)
\end{align}

\subsection{Chain Sorting and Deduplication}

Chains are sorted by $\text{chain\_score} \times \text{confidence}$ descending.
\code{MultiStageAttack} chains whose node sets are fully covered by more specific
chains (patterns 1--6) are suppressed during deduplication.

\section{Critical Path Analysis}

The critical path algorithm finds the maximum-weight simple path through the
threat graph using a depth-bounded DFS (depth limit 10):

\begin{enumerate}
  \item Collect all non-Clean (threat) node IDs.
  \item Trace ParentChild edges backwards from each threat node to find clean
    ancestor processes (delivery chain, up to depth 8).
  \item Seed DFS from process-tree roots and all threat nodes.
  \item At each step select the highest-weight unvisited neighbour first.
  \item Guard: the winning path must contain at least one threat node.
\end{enumerate}

The resulting path is accompanied by a plain-English narrative constructed by
mapping each edge type to a verb phrase:

\begin{center}
\begin{tabular}{ll}
  \toprule
  \textbf{Edge} & \textbf{Verb phrase} \\
  \midrule
  \code{parent\_child}      & ``spawned'' \\
  \code{network\_owner}     & ``connected to'' \\
  \code{process\_opened\_file} & ``loaded'' / ``was loaded by'' \\
  \code{shared\_c2}         & ``shares C2 infrastructure with'' \\
  \code{memory\_injection}  & ``has a suspicious memory region at'' \\
  \bottomrule
\end{tabular}
\end{center}

Example narrative: \textit{``malicious.docx was loaded by word.exe, which spawned
powershell.exe, which connected to TCP~\texttt{185.x.x.x:443}''}

\section{Graph Feedback Pass}

After attack-chain detection, \code{apply\_graph\_feedback} refines node scores
with three structural boosts:

\begin{description}
  \item[Critical-path boost] Nodes on the critical path receive up to $+0.15$,
    proportional to their edge-weight contribution to the path total score.
  \item[Centrality boost] Threat nodes with above-average degree (many cross-entity
    edges) receive up to $+0.10$, scaled by $\text{degree}/\text{max\_degree}$.
  \item[Vector flag] A clean parent that directly spawned a Malicious/Critical child
    is marked \code{is\_vector = true} and receives $+0.08$ (positional indicator
    only; threat level is not escalated).
\end{description}

\section{LOLBin Detection}

When a clean parent is flagged as \code{is\_vector}, its label is checked against
a static list of 36 \textbf{Living-Off-the-Land Binaries} from the LOLBAS project:

\begin{center}
\begin{tabular}{llll}
  \code{powershell.exe} & \code{cmd.exe}      & \code{wscript.exe}  & \code{cscript.exe} \\
  \code{mshta.exe}      & \code{regsvr32.exe} & \code{rundll32.exe} & \code{certutil.exe} \\
  \code{bitsadmin.exe}  & \code{msiexec.exe}  & \code{wmic.exe}     & \code{schtasks.exe} \\
  \code{regasm.exe}     & \code{installutil.exe} & \code{msbuild.exe} & \code{bash.exe} \\
  \code{explorer.exe}   & \code{expand.exe}   & \code{forfiles.exe} & \code{mavinject.exe} \\
  \ldots (36 total)     &                     &                     &
\end{tabular}
\end{center}

Matching nodes receive \code{is\_lolbin = true}, which the UI renders as a
``LOLBin'' badge in the threat graph detail panel.

% =============================================================================
\chapter{Post-Verdict Containment Actions}
% =============================================================================

All containment logic is implemented in \file{action/executor.rs}. Actions are
triggered from the UI after a threat is confirmed and return typed result structs
serialised to JSON by the daemon.

\begin{longtable}{@{}lp{4.5cm}p{5.5cm}@{}}
  \toprule
  \textbf{Action} & \textbf{Mechanism} & \textbf{Artefacts Written} \\
  \midrule
  \endhead
  File Quarantine
    & SHA-256 hash file; rename to \code{.quarantined}; write \code{.meta.json} sidecar.
      Cross-volume: copy + delete.
    & \code{\%PROGRAMDATA\%\textbackslash AegisAI\textbackslash quarantine\textbackslash \{sha256\}.quarantined} \\[6pt]
  Firewall IP Block
    & \code{netsh advfirewall firewall add rule} (auditable; no COM).
      Rule name: \code{AegisAI-\{ts\}-\{ip\}}.
    & \code{firewall\_rules.json} (per-rule registry) \\[6pt]
  Firewall Rule Rollback
    & \code{netsh advfirewall firewall delete rule name=...}
    & Removes entry from \code{firewall\_rules.json} \\[6pt]
  Memory Dump
    & \code{MiniDumpWriteDump} with \code{MiniDumpWithFullMemory} flag. Compatible with WinDbg and Volatility.
    & \code{dumps\textbackslash\{pid\}\_\{timestamp\}.dmp} \\[6pt]
  Persistence Check
    & Enumerates HKCU/HKLM Run keys, scheduled tasks, startup folders. Cross-references \code{suspicious\_paths}.
    & Read-only; returns \code{PersistenceEntry[]} \\[6pt]
  Network Isolation
    & \code{netsh interface set interface disable} on all connected adapters.
    & \code{isolated\_interfaces.json} for rollback \\[6pt]
  Network Restore
    & Re-enables adapters from \code{isolated\_interfaces.json}.
    & Removes \code{isolated\_interfaces.json} \\[6pt]
  Incident Report
    & Tauri-side only (no daemon round-trip). Serialises scan results + actions taken to JSON.
    & \code{\%USERPROFILE\%\textbackslash Documents\textbackslash AegisAI\textbackslash incident\_\{ts\}.json} \\
  \bottomrule
  \caption{Post-verdict containment actions and their side effects.}
\end{longtable}

% =============================================================================
\chapter{Tauri Desktop Application}
% =============================================================================

\section{Architecture}

The UI layer is a \textbf{Tauri v2} application:

\begin{description}
  \item[Frontend] React 18 with TypeScript, built by Vite.
  \item[State] Zustand store (\file{store/index.ts}) holds all scan results,
    ML results, correlation data, agent verdicts, and history.
  \item[IPC] \code{invoke()} calls from React components to Tauri Rust commands.
    The Tauri backend translates each invoke into a JSON-RPC message to the daemon.
  \item[Graph visualisation] D3.js force-directed graph rendered in
    \file{ThreatGraph.tsx}.
\end{description}

\section{Views}

\begin{longtable}{@{}ll@{}}
  \toprule
  \textbf{View} & \textbf{Function} \\
  \midrule
  \endhead
  Dashboard       & Threat summary counters; recent alert feed \\
  Scanner         & File/directory/all-system scan; live elapsed timer; ML result panel \\
  ProcessMonitor  & Sortable process table; kill button; GRU ML results \\
  NetworkMonitor  & Active connections; per-PID filter; IP block action \\
  MemoryMonitor   & Memory regions per process; RWX highlight \\
  EntityManager   & Aggregated entity list with per-domain sub-scores \\
  ThreatGraph     & Interactive D3.js graph; attack chain sidebar; critical path highlight \\
  History         & Scan history timeline \\
  \bottomrule
  \caption{Application views and their primary functions.}
\end{longtable}

\section{Key TypeScript Types}

\begin{lstlisting}[style=python, caption={Core TypeScript types (types/index.ts, abbreviated)}]
type ThreatLevel     = 'Clean' | 'Suspicious' | 'Malicious';
type UnifiedThreat   = 'Clean' | 'Suspicious' | 'Malicious' | 'Critical';
type AttackPatternName =
  | 'ProcessInjection' | 'C2Communication' | 'MalwareExecution'
  | 'LateralMovement'  | 'SuspiciousSpawn' | 'ExploitedTrustedProcess'
  | 'MultiStageAttack';

interface GraphNodeData {
  entity_id:           string;
  entity_type:         string;
  threat_level:        UnifiedThreat;
  combined_score:      number;        // [0, 1]
  label:               string;
  process_score:       number;
  network_score:       number;
  memory_score:        number;
  file_score:          number;
  has_malicious_network: boolean;
  has_malicious_memory:  boolean;
  has_malicious_file:    boolean;
  is_lolbin:           boolean;
}

interface AttackChain {
  chain_id:     string;
  pattern:      AttackPatternName;
  node_ids:     string[];
  chain_score:  number;
  severity:     UnifiedThreat;
  description:  string;
  mitre_tactic: string;
  confidence:   number;
}
\end{lstlisting}

\section{Zustand Store Structure}

The store (\file{store/index.ts}) exposes the following major slices:

\begin{longtable}{@{}lp{8.5cm}@{}}
  \toprule
  \textbf{Slice} & \textbf{State and Actions} \\
  \midrule
  \endhead
  Scanning        & \code{scanning}, \code{scanResults[]}, \code{scanAll()}, \code{quickScan()} \\
  EMBER ML        & \code{emberMlRunning}, \code{emberMlResults[]}, \code{applyEmberMl()} \\
  Process ML      & \code{processEmberRunning}, \code{processEmberResults[]}, \code{applyProcessMl()} \\
  Process scan    & \code{processes[]}, \code{processStats}, \code{killProcess(pid)} \\
  Network scan    & \code{networkConnections[]}, \code{networkStats}, \code{scanNetwork()} \\
  Memory scan     & \code{memoryRegions[]}, \code{memoryStats}, \code{scanMemory()} \\
  Correlation     & \code{correlateResult}, \code{correlating}, \code{correlateEntities()} \\
  Agent (round 1) & \code{agentVerdict}, \code{agentLoading}, \code{runAgentAnalysis()} \\
  Agent (round 2+)& \code{currentRound}, \code{actionsTaken[]}, \code{runAgentReassessment()} \\
  History         & \code{history[]}, \code{addHistory()} \\
  \bottomrule
  \caption{Zustand store slices.}
\end{longtable}

% =============================================================================
\chapter{Performance Characteristics}
% =============================================================================

\section{Algorithmic Complexity}

\begin{longtable}{@{}lll@{}}
  \toprule
  \textbf{Component} & \textbf{Complexity} & \textbf{Notes} \\
  \midrule
  \endhead
  Single file scan      & $O(|F|)$         & $|F|$ = file size; one read pass \\
  Directory scan        & $O(n \log n)$    & $n$ = file count; sort by priority \\
  System scan           & $O(n)$           & Multi-threaded with mtime cache \\
  Process scan          & $O(p \cdot m)$   & $p$ = process count, $m$ = modules/process \\
  Network scan          & $O(c)$           & $c$ = connection count \\
  Memory scan           & $O(R)$           & $R$ = total memory regions \\
  Entity ingestion      & $O(n)$           & DashMap insert is amortised O(1) \\
  Graph construction    & $O(n + e)$       & via pre-built join-key indexes \\
  Attack chain detection& $O(n + e)$       & Pattern DFS over adjacency list \\
  Critical path DFS     & $O((n+e) \cdot d)$ & $d$ = depth limit (10) \\
  \bottomrule
  \caption{Algorithmic complexity of major pipeline components.}
\end{longtable}

\section{Timeout Budget}

\begin{longtable}{@{}lr@{}}
  \toprule
  \textbf{Operation} & \textbf{Timeout} \\
  \midrule
  \endhead
  Single file scan (YARA + heuristics)      & 30\,s \\
  EMBER ML (cold start)                     & 120\,s \\
  EMBER ML (warm -- models loaded)          & $< 5$\,s / batch \\
  GRU process model (cold start)            & 120\,s \\
  GRU process model (warm)                  & $< 2$\,s / process \\
  Network XGBoost inference                 & 30\,s \\
  Full memory scan                          & 60\,s \\
  Full correlate (process + network + graph)& 900\,s \\
  \bottomrule
  \caption{Timeout budget for each major operation.}
\end{longtable}

\section{Runtime Dependencies}

\begin{longtable}{@{}lll@{}}
  \toprule
  \textbf{Crate / Package} & \textbf{Version} & \textbf{Purpose} \\
  \midrule
  \endhead
  \multicolumn{3}{l}{\textit{Rust (Cargo.toml)}} \\
  \code{sysinfo}          & latest  & Process enumeration \\
  \code{yara-x}           & 1.13    & YARA rule engine \\
  \code{sha2}             & latest  & SHA-256 hashing \\
  \code{dashmap}          & latest  & Concurrent HashMap \\
  \code{windows}          & 0.58    & Win32 API (memory, process, security) \\
  \code{windows-sys}      & 0.61    & Low-level networking (IP Helper, WinSock) \\
  \code{serde\_json}      & latest  & JSON serialisation \\
  \code{walkdir}          & latest  & Recursive directory traversal \\
  \code{anyhow}           & latest  & Error handling \\
  \midrule
  \multicolumn{3}{l}{\textit{Python (ai\_agent/.venv)}} \\
  \code{xgboost}          & latest  & Network IDS model \\
  \code{torch}            & latest  & GRU process model \\
  \code{scikit-learn}     & latest  & OrdinalEncoder, CalibratedClassifierCV \\
  \code{lightgbm}         & latest  & EMBER2024 file model \\
  \code{joblib}           & latest  & Model serialisation \\
  \code{pandas}, \code{numpy} & latest & Feature engineering \\
  \midrule
  \multicolumn{3}{l}{\textit{Node.js (package.json)}} \\
  \code{react}            & 18      & UI framework \\
  \code{@tauri-apps/api}  & v2      & Tauri IPC bridge \\
  \code{zustand}          & latest  & State management \\
  \code{d3}               & latest  & Graph visualisation \\
  \code{lucide-react}     & latest  & Icon library \\
  \code{vite}             & latest  & Build tool \\
  \bottomrule
  \caption{Key runtime dependencies.}
\end{longtable}

% =============================================================================
\chapter{Security Analysis}
% =============================================================================

\section{Strengths}

\begin{enumerate}
  \item \textbf{Multi-layer independence}: Four scanner domains run independently.
    An adversary must evade all four simultaneously to avoid detection.
  \item \textbf{Cross-domain correlation}: The entity graph correlates weak signals
    from multiple domains into high-confidence attack chains that no single scanner
    could surface.
  \item \textbf{Heuristic + ML dual layer}: Classical heuristics catch novel
    variants and model-evasion attempts; ML models improve precision on known
    families.
  \item \textbf{LOLBin awareness}: Trusted Windows binaries used as delivery
    vectors are flagged and badged without generating false process alerts.
  \item \textbf{Forensic-quality containment}: Memory dumps use
    \code{MiniDumpWithFullMemory}, compatible with WinDbg and Volatility for
    post-incident analysis.
  \item \textbf{Auditable firewall rules}: \code{netsh} is used instead of COM
    API, producing a human-readable Windows Firewall rule with a named
    \code{AegisAI-*} prefix.
  \item \textbf{Daemon architecture}: YARA compilation and ML model loading happen
    once, not per-request. No cold-start penalty after the initial startup.
\end{enumerate}

\section{Limitations and Known Gaps}

\begin{enumerate}
  \item \textbf{Windows-only}: The memory scanner (VirtualQuery), network scanner
    (IP Helper), and process scanner (sysinfo Windows back-end) are Windows-specific.
    Porting to Linux/macOS requires significant rework.
  \item \textbf{No dynamic execution / sandboxing}: The system analyses static
    properties and runtime observations. Malware that only activates under specific
    conditions (delayed execution, environment checks) may evade detection.
  \item \textbf{ML model staleness}: The EMBER2024, GRU, and XGBoost models are
    trained on historical datasets. Adversarially crafted samples that exploit
    model blind spots can evade ML scoring while still being caught by heuristics.
  \item \textbf{Network IDS requires calibration}: The XGBoost model was trained
    on UNSW-NB15 synthetic traffic; performance on real enterprise traffic requires
    retraining with mixed real-world + benchmark data.
  \item \textbf{Memory scan performance}: \code{VirtualQueryEx} enumeration over
    all process regions is O(total regions) and can be slow on processes with
    fragmented address spaces (browsers, JVMs).
  \item \textbf{Pending UI wiring}: The React components for quarantine management,
    settings, and post-incident report export are not yet implemented. The Tauri
    IPC commands are registered but the UI surfaces do not yet call them.
  \item \textbf{AI agent stubs}: The \file{ai\_agent/} reasoning and action-planner
    modules (\code{reasoning.py}, \code{main.py}) are empty stubs pending
    implementation.
\end{enumerate}

% =============================================================================
\chapter{Summary and Conclusions}
% =============================================================================

AegisAI demonstrates a research-grade approach to endpoint security that goes
beyond conventional antivirus by combining:

\begin{itemize}
  \item \textbf{Four independent detection domains} (file, process, network, memory)
    each with tuned heuristics and ML augmentation.
  \item \textbf{A unified entity model} that correlates cross-domain signals using
    structural join keys (PID, parent PID, file path, file hash, remote IP).
  \item \textbf{A graph-based attack-chain pipeline} implementing seven
    MITRE-mapped patterns, LOLBin detection, and a narrative critical-path finder.
  \item \textbf{Forensic-quality containment} (quarantine, firewall, memory dump,
    network isolation) accessible from the same UI surface that surfaced the threat.
  \item \textbf{A daemon architecture} that amortises expensive initialisation
    (YARA compilation, ML model loading) across all requests.
\end{itemize}

The scoring formula $\text{combined} = H \times 0.4 + \text{ML} \times 0.6$
intentionally favours ML precision over heuristic recall, while preserving
heuristic coverage as a fallback when models are unavailable. The 10-minute sliding
time window bounds memory usage in long-running sessions without sacrificing
correlation depth for typical attack sequences.

The primary areas for future work are: retraining the network IDS on real traffic,
completing the UI wiring for containment actions, implementing the AI agent
reasoning layer, and extending the scanner to support macOS and Linux platforms.

% =============================================================================
% Bibliography (if any)
% =============================================================================
\begin{thebibliography}{9}

\bibitem{unswnb15}
  N.\ Moustafa and J.\ Slay,
  \textit{UNSW-NB15: a comprehensive data set for network intrusion detection systems},
  Military Communications and Information Systems Conference (MilCIS), 2015.

\bibitem{ember}
  H.\ Anderson and P.\ Roth,
  \textit{EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models},
  arXiv:1804.04637, 2018.

\bibitem{lolbas}
  LOLBAS Project,
  \textit{Living Off The Land Binaries, Scripts and Libraries},
  \url{https://lolbas-project.github.io/}, accessed 2026.

\bibitem{yarax}
  VirusTotal,
  \textit{YARA-X: A rewrite of YARA in Rust},
  \url{https://github.com/VirusTotal/yara-x}, 2024.

\bibitem{mitre}
  MITRE Corporation,
  \textit{ATT\&CK: Adversarial Tactics, Techniques, and Common Knowledge},
  \url{https://attack.mitre.org/}, 2026.

\bibitem{tauri}
  Tauri Contributors,
  \textit{Tauri: Build an optimized, secure, and frontend-independent application
  for multi-platform deployment},
  \url{https://tauri.app/}, 2024.

\end{thebibliography}

\end{document}
