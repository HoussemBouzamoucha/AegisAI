
```latex
\documentclass[12pt,a4paper]{report}

% ─── Packages ────────────────────────────────────────────────────────────────
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[english]{babel}
\usepackage{geometry}
\geometry{margin=2.5cm}

\usepackage{lmodern}
\usepackage{microtype}
\usepackage{setspace}
\onehalfspacing

\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{amsmath, amssymb}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{tabularx}
\usepackage{multirow}
\usepackage{enumitem}
\usepackage{listings}
\usepackage{caption}
\usepackage{subcaption}
\usepackage{float}
\usepackage{hyperref}
\usepackage{fancyhdr}
\usepackage{titlesec}
\usepackage{tocloft}
\usepackage{mdframed}
\usepackage{tikz}
\usetikzlibrary{shapes.geometric, arrows.meta, positioning, fit, backgrounds, calc}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\usepackage{algorithm}
\usepackage{algpseudocode}
\usepackage{forest}
\usepackage{fontawesome5}

% ─── Colours ─────────────────────────────────────────────────────────────────
\definecolor{aegisblue}{RGB}{30, 80, 160}
\definecolor{aegisdark}{RGB}{15, 30, 60}
\definecolor{aegisred}{RGB}{200, 40, 40}
\definecolor{aegisgreen}{RGB}{34, 139, 34}
\definecolor{aegisgray}{RGB}{100, 100, 100}
\definecolor{codebg}{RGB}{245, 245, 250}
\definecolor{codekw}{RGB}{0, 0, 180}
\definecolor{codestr}{RGB}{160, 32, 240}
\definecolor{codecomment}{RGB}{100, 149, 237}
\definecolor{warnorange}{RGB}{220, 120, 0}

% ─── Hyperref ────────────────────────────────────────────────────────────────
\hypersetup{
  colorlinks=true,
  linkcolor=aegisblue,
  citecolor=aegisblue,
  urlcolor=aegisblue,
  pdftitle={AegisAI -- Comprehensive Technical Report},
  pdfauthor={Houssem Bouzamoucha},
  pdfsubject={Multi-Layer AI Antivirus and Intrusion Detection System}
}

% ─── Code listings ───────────────────────────────────────────────────────────
\lstset{
  backgroundcolor=\color{codebg},
  basicstyle=\ttfamily\small,
  keywordstyle=\color{codekw}\bfseries,
  stringstyle=\color{codestr},
  commentstyle=\color{codecomment}\itshape,
  breaklines=true,
  frame=single,
  rulecolor=\color{aegisblue!30},
  captionpos=b,
  numbers=left,
  numberstyle=\tiny\color{aegisgray},
  tabsize=2,
  showstringspaces=false
}

% ─── Headers / Footers ───────────────────────────────────────────────────────
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\textcolor{aegisblue}{\small\textit{AegisAI -- Technical Report}}}
\fancyhead[R]{\textcolor{aegisgray}{\small\thepage}}
\fancyfoot[C]{\textcolor{aegisgray}{\small\textit{Confidential -- Houssem Bouzamoucha}}}
\renewcommand{\headrulewidth}{0.4pt}
\renewcommand{\footrulewidth}{0.2pt}

% ─── Section formatting ───────────────────────────────────────────────────────
\titleformat{\chapter}[display]
  {\normalfont\huge\bfseries\color{aegisblue}}
  {\chaptertitlename\ \thechapter}{20pt}{\Huge}
\titleformat{\section}
  {\normalfont\Large\bfseries\color{aegisdark}}
  {\thesection}{1em}{}
\titleformat{\subsection}
  {\normalfont\large\bfseries\color{aegisblue!80}}
  {\thesubsection}{1em}{}
\titleformat{\subsubsection}
  {\normalfont\normalsize\bfseries\color{aegisgray}}
  {\thesubsubsection}{1em}{}

% ─── Custom environments ──────────────────────────────────────────────────────
\newmdenv[
  backgroundcolor=aegisblue!8,
  linecolor=aegisblue,
  linewidth=1.5pt,
  roundcorner=4pt,
  skipabove=8pt,
  skipbelow=8pt
]{infobox}

\newmdenv[
  backgroundcolor=aegisred!8,
  linecolor=aegisred,
  linewidth=1.5pt,
  roundcorner=4pt,
  skipabove=8pt,
  skipbelow=8pt
]{warnbox}

% ─────────────────────────────────────────────────────────────────────────────
%  DOCUMENT
% ─────────────────────────────────────────────────────────────────────────────
\begin{document}

% ============================================================
%  TITLE PAGE
% ============================================================
\begin{titlepage}
  \centering
  \vspace*{1cm}

  {\color{aegisblue}\rule{\linewidth}{3pt}}
  \vspace{0.5cm}

  {\fontsize{48}{56}\selectfont\bfseries\color{aegisdark} \textsc{AegisAI}}\\[0.4cm]
  {\LARGE\color{aegisblue} Multi-Layer AI-Powered Antivirus \& Intrusion Detection System}\\[0.3cm]
  {\large\color{aegisgray} Comprehensive Technical Report}

  \vspace{0.5cm}
  {\color{aegisblue}\rule{\linewidth}{1pt}}

  \vspace{1.5cm}

  \begin{center}
  \begin{tikzpicture}[node distance=1.4cm, auto,
    block/.style={rectangle, draw=aegisblue, fill=aegisblue!10, rounded corners, minimum width=3.2cm, minimum height=0.8cm, font=\small\bfseries},
    arrow/.style={-{Stealth}, thick, color=aegisblue}]

    \node[block] (ui)   {React / Tauri UI};
    \node[block, below of=ui] (ipc) {JSON-RPC Daemon};
    \node[block, below left=0.9cm and 1.5cm of ipc]  (fs)  {File Scanner};
    \node[block, below left=0.9cm and -0.4cm of ipc] (proc){Process Scanner};
    \node[block, below right=0.9cm and -0.4cm of ipc](net) {Network Scanner};
    \node[block, below right=0.9cm and 1.5cm of ipc] (mem) {Memory Scanner};
    \node[block, below=2.8cm of ipc] (ent) {Entity Graph Pipeline};
    \node[block, below of=ent] (agent) {AI Agent (LangChain + LLM)};

    \draw[arrow] (ui) -- (ipc);
    \draw[arrow] (ipc) -- (fs);
    \draw[arrow] (ipc) -- (proc);
    \draw[arrow] (ipc) -- (net);
    \draw[arrow] (ipc) -- (mem);
    \draw[arrow] (fs)   -- (ent);
    \draw[arrow] (proc) -- (ent);
    \draw[arrow] (net)  -- (ent);
    \draw[arrow] (mem)  -- (ent);
    \draw[arrow] (ent) -- (agent);
  \end{tikzpicture}
  \end{center}

  \vspace{1.5cm}

  \begin{tabular}{rl}
    \textbf{Author:}   & Houssem Bouzamoucha \\
    \textbf{Email:}    & houssem.bouzamoucha@gmail.com \\
    \textbf{Date:}     & May 2026 \\
    \textbf{Version:}  & 1.0 \\
    \textbf{Platform:} & Windows 11 (x86\_64) \\
  \end{tabular}

  \vfill
  {\color{aegisblue}\rule{\linewidth}{3pt}}
\end{titlepage}

% ============================================================
%  ABSTRACT
% ============================================================
\chapter*{Abstract}
\addcontentsline{toc}{chapter}{Abstract}

\textbf{AegisAI} is a comprehensive, multi-layered, AI-driven endpoint security platform designed for Windows systems.
It combines a high-performance Rust scanning engine, domain-specific machine-learning models, a graph-based threat
correlation pipeline, and an autonomous LLM-powered analyst agent -- all exposed through a modern React/Tauri desktop
application.

The system operates across four detection domains: \textit{file system}, \textit{process behaviour}, \textit{network
traffic}, and \textit{memory forensics}. Each domain employs independent heuristic scorers that feed a unified entity
model. Entities are correlated into a directed \textit{ThreatGraph} whose nodes represent aggregated process-anchored
entities and whose edges encode parent--child spawning, shared C2 infrastructure, and shared malicious file hashes.
Six MITRE ATT\&CK--aligned attack patterns are detected automatically within this graph.

A conversational AI agent (powered by a large language model via LangChain and OpenRouter) ingests the graph, reasons
about the most impactful containment actions, and iteratively re-assesses as the analyst executes recommendations.
All containment primitives -- file quarantine, firewall rules, memory dumps, persistence audits, and full network
isolation -- are reversible and implemented natively in the Rust engine.

This report documents every layer of the architecture, all ML models and their training/inference pipelines, the
entity graph data structures and algorithms, the AI agent design, the Tauri IPC protocol, and all security design
decisions.

\bigskip
\noindent\textbf{Keywords:} antivirus, intrusion detection, machine learning, XGBoost, GRU, EMBER2024, LightGBM,
entity graph, attack chain detection, MITRE ATT\&CK, LangChain, LLM, Tauri, Rust, YARA.

% ============================================================
%  TABLE OF CONTENTS
% ============================================================
\tableofcontents
\listoffigures
\listoftables

% ============================================================
%  CHAPTER 1 -- INTRODUCTION
% ============================================================
\chapter{Introduction}

\section{Motivation}

Modern endpoint threats have evolved far beyond static, signature-only malware. Advanced persistent threats (APTs),
living-off-the-land binaries (LOLBins), file-less attacks injected directly into trusted processes, and
multi-stage ransomware campaigns routinely bypass conventional antivirus products that rely on a single detection
layer.

AegisAI was designed to address this gap by combining four independent detection layers with a cross-domain
correlation engine that reasons at the \textit{behavioural graph} level rather than at the individual file or
process level. A machine-learning-powered reasoning agent then acts as a virtual threat analyst, prioritising
remediation actions and iterating as the human analyst responds.

\section{Scope of this Report}

This document provides a complete technical description of:

\begin{itemize}[leftmargin=*]
  \item The Rust antivirus daemon and its four scanning modules.
  \item The machine-learning models used per domain (EMBER2024 file models, XGBoost network IDS, GRU process
        inference, memory classifier).
  \item The steganography detection sub-module.
  \item The entity graph pipeline: ingestion, aggregation, correlation, graph construction, attack-chain detection,
        and critical-path analysis.
  \item The AI agent: prompt design, LangChain chains, Pydantic schema, and multi-round reasoning.
  \item The Tauri IPC layer and React/TypeScript front-end.
  \item Post-verdict containment actions (quarantine, firewall, isolation, dumps, persistence audit).
  \item YARA rule organisation and scoring.
  \item Key design decisions, threat thresholds, and security properties.
\end{itemize}

\section{Document Conventions}

\begin{itemize}[leftmargin=*]
  \item \texttt{monospace} denotes file paths, command names, type names, and code snippets.
  \item \textbf{Bold} marks the first occurrence of important terms.
  \item Numbers in square brackets (e.g., [T1055]) refer to MITRE ATT\&CK technique identifiers.
\end{itemize}

% ============================================================
%  CHAPTER 2 -- SYSTEM ARCHITECTURE
% ============================================================
\chapter{System Architecture}

\section{High-Level Overview}

AegisAI comprises three major runtime components that communicate over well-defined boundaries:

\begin{enumerate}
  \item \textbf{Antivirus Engine} -- a Rust binary that operates as a persistent \textit{daemon} receiving
        JSON-RPC commands on \texttt{stdin} and streaming results on \texttt{stdout}.
  \item \textbf{Python ML Pipelines} -- per-domain Python scripts that load pre-trained models and perform
        inference; they are spawned as sub-processes by the Rust engine.
  \item \textbf{Tauri Desktop Application} -- a Rust/React application whose Rust backend spawns and manages
        the daemon, translates Tauri IPC \texttt{invoke()} calls into JSON-RPC commands, and serves the
        React UI.
\end{enumerate}

\begin{figure}[H]
\centering
\begin{tikzpicture}[
  box/.style={draw=aegisblue, fill=aegisblue!8, rounded corners=4pt, minimum width=4cm,
              minimum height=1cm, align=center, font=\small\bfseries},
  sbox/.style={draw=aegisgray, fill=gray!6, rounded corners=3pt, minimum width=3.2cm,
               minimum height=0.7cm, align=center, font=\footnotesize},
  arr/.style={-{Stealth[length=6pt]}, thick, color=aegisblue},
  darr/.style={-{Stealth[length=6pt]}, thick, color=aegisgreen, dashed}
]

% UI Layer
\node[box, fill=aegisblue!15] (ui) at (6,9) {React / TypeScript\\UI};
\node[box, fill=aegisblue!10] (tauri) at (6,7.2) {Tauri Rust Backend\\(IPC Bridge)};

% Daemon
\node[box, fill=aegisblue!20] (daemon) at (6,5.2) {AegisAI Daemon\\(Rust, JSON-RPC)};

% Scanners
\node[sbox] (fs)   at (0.5, 3)  {File System\\Scanner};
\node[sbox] (proc) at (3.5, 3)  {Process\\Scanner};
\node[sbox] (net)  at (6.5, 3)  {Network\\Scanner};
\node[sbox] (mem)  at (9.5, 3)  {Memory\\Scanner};

% ML layer
\node[sbox, fill=warnorange!10, draw=warnorange] (ember)  at (0.5, 1.4) {EMBER2024\\LightGBM};
\node[sbox, fill=warnorange!10, draw=warnorange] (gru)    at (3.5, 1.4) {GRU\\API Sequences};
\node[sbox, fill=warnorange!10, draw=warnorange] (xgb)    at (6.5, 1.4) {XGBoost\\IDS (UNSW-NB15)};
\node[sbox, fill=warnorange!10, draw=warnorange] (memml)  at (9.5, 1.4) {Memory\\ML Classifier};

% Entity pipeline
\node[box, fill=aegisgreen!10, draw=aegisgreen] (ent) at (5, -0.2) {Entity Manager \& Correlator};
\node[box, fill=aegisgreen!10, draw=aegisgreen] (graph) at (5, -1.7) {Graph Builder \& Analyzer};

% AI Agent
\node[box, fill=aegisred!10, draw=aegisred] (agent) at (5, -3.2) {AI Agent (LangChain + LLM)};

% Arrows
\draw[arr] (ui) -- (tauri);
\draw[arr] (tauri) -- node[right,font=\tiny]{JSON-RPC} (daemon);
\draw[arr] (daemon) -- (fs);
\draw[arr] (daemon) -- (proc);
\draw[arr] (daemon) -- (net);
\draw[arr] (daemon) -- (mem);
\draw[darr] (fs)   -- (ember);
\draw[darr] (proc) -- (gru);
\draw[darr] (net)  -- (xgb);
\draw[darr] (mem)  -- (memml);
\draw[arr] (fs)   -- (ent);
\draw[arr] (proc) -- (ent);
\draw[arr] (net)  -- (ent);
\draw[arr] (mem)  -- (ent);
\draw[arr] (ent)  -- (graph);
\draw[arr] (graph) -- (agent);
\draw[arr, bend right=35] (agent) to (tauri);

\end{tikzpicture}
\caption{AegisAI full-stack architecture. Dashed arrows indicate optional ML sub-processes.}
\label{fig:arch}
\end{figure}

\section{Daemon JSON-RPC Protocol}

The daemon reads one JSON line from \texttt{stdin} and writes one JSON line to \texttt{stdout} per
request. Every request carries a unique \texttt{id} field that is echoed in the response for
correlation.

\textbf{Request format:}
\begin{lstlisting}[language=json, caption={JSON-RPC request envelope}]
{ "id": "<uuid>", "cmd": "<command>", ...additional_fields }
\end{lstlisting}

\begin{table}[H]
\centering
\caption{Daemon command catalogue}
\label{tab:daemon-cmds}
\begin{tabularx}{\linewidth}{lXl}
\toprule
\textbf{Command} & \textbf{Extra fields} & \textbf{Notes} \\
\midrule
\texttt{scan-file}       & \texttt{path}                          & Single file \\
\texttt{scan-dir}        & \texttt{path}                          & Recursive directory \\
\texttt{scan-processes}  & ---                                    & All running processes \\
\texttt{scan-network}    & \texttt{pid?}                          & All connections or per PID \\
\texttt{scan-memory}     & \texttt{pid?}                          & All or targeted \\
\texttt{correlate}       & \texttt{include\_memory: bool}         & Full entity/graph pipeline \\
\texttt{kill-process}    & \texttt{pid}                           & SIGKILL \\
\texttt{quarantine-file} & \texttt{path}                          & Move + rename \\
\texttt{block-ip}        & \texttt{remote\_ip, direction}         & Windows Firewall rule \\
\texttt{remove-block-ip} & \texttt{rule\_name}                    & Rollback firewall rule \\
\texttt{dump-memory}     & \texttt{pid}                           & MiniDumpWithFullMemory \\
\texttt{check-persistence} & \texttt{suspicious\_paths}           & Registry / tasks audit \\
\texttt{isolate-network} & ---                                    & Disable all adapters \\
\texttt{restore-network} & ---                                    & Re-enable saved adapters \\
\texttt{ping}            & ---                                    & Returns \texttt{\{status:"pong"\}} \\
\bottomrule
\end{tabularx}
\end{table}

\textbf{Startup handshake:} the daemon prints \texttt{\{"status":"ready"\}} before entering the
request loop, allowing the Tauri backend to wait for the engine to become available.

\section{Data Flow Pipeline}

The full data flow from a user-initiated scan to an agent verdict follows these stages:

\begin{enumerate}
  \item \textbf{Invocation} -- React UI calls \texttt{invoke()} via the Tauri JS bridge.
  \item \textbf{IPC routing} -- Tauri Rust backend serialises the call into a JSON-RPC command
        sent to the daemon's \texttt{stdin}.
  \item \textbf{Scanning} -- the relevant domain scanner(s) run and produce \texttt{EntityNode}
        records with heuristic scores and detection signals.
  \item \textbf{ML scoring} -- Python sub-processes apply trained models and patch ML scores back
        onto entities via \texttt{EntityManager::update\_ml\_score()}.
  \item \textbf{Entity aggregation} -- \texttt{EntityManager::aggregate()} groups flat entity
        nodes into composite \texttt{AggregatedEntity} objects, one per process PID.
  \item \textbf{Correlation} -- \texttt{EntityCorrelator} groups nodes into
        \texttt{CorrelatedCluster} objects by shared PID, parent PID, remote IP, or file hash.
  \item \textbf{Graph construction} -- \texttt{GraphBuilder::build\_from\_aggregated()} builds a
        \texttt{ThreatGraph} with three inter-entity edge types.
  \item \textbf{Attack-chain detection} -- \texttt{GraphAnalyzer} identifies six MITRE-mapped
        patterns and computes the critical path.
  \item \textbf{Agent analysis} -- the LangChain agent ingests the full
        \texttt{CorrelateResult} and returns a ranked \texttt{AgentVerdict}.
  \item \textbf{Analyst loop} -- the human executes containment actions; the agent
        re-assesses with the updated context until \texttt{investigation\_closed = true}.
\end{enumerate}

% ============================================================
%  CHAPTER 3 -- RUST ANTIVIRUS ENGINE
% ============================================================
\chapter{Rust Antivirus Engine}

\section{Technology Choices}

The engine is written in \textbf{Rust} (edition 2021) and compiled with aggressive release
optimisations (\texttt{opt-level=3}, LTO, single codegen unit, stripped binaries). Key crate
dependencies include:

\begin{itemize}[leftmargin=*]
  \item \texttt{yara-x 1.13} -- WebAssembly JIT-compiled YARA rules via \textit{wasmtime}.
  \item \texttt{sysinfo 0.38} -- cross-platform process/system information.
  \item \texttt{windows-sys 0.61} / \texttt{windows 0.58} -- raw Windows API bindings.
  \item \texttt{pcap 2.4} / \texttt{etherparse 0.19} -- live packet capture and parsing.
  \item \texttt{dashmap 6} -- concurrent hash-map for the entity manager's entity store.
  \item \texttt{sha2}, \texttt{hex} -- SHA-256 hashing.
  \item \texttt{serde\_json} -- all serialisation/deserialisation.
\end{itemize}

\section{File System Scanner}

\subsection{Detection Stack}

The file scanner applies four techniques in deterministic escalation order:

\begin{enumerate}
  \item \textbf{SHA-256 signature database} -- exact hash lookup; returns an immediate
        \textit{Malicious} verdict if found.  The hash computation uses
        \texttt{utils::compute\_sha256\_from\_bytes} for files $\leq$10\,MiB (sharing the
        already-read buffer) and \texttt{compute\_sha256} with streaming for larger files.
  \item \textbf{YARA-X rules} -- $\approx$300 rules compiled once at daemon startup.  Each
        matching named rule family adds $+10$ to the threat score; generic/network-pattern
        matches add $+1$ each.
  \item \textbf{Heuristics} -- entropy analysis, magic-byte detection, content scanning for
        ransomware/malware phrases, extension and header cross-checks.  Scores accumulate
        additively.
  \item \textbf{Context analysis} -- directory-level context flags (e.g.,
        \texttt{RansomNoteNearby}, \texttt{MassModificationDetected}) apply per-directory and
        never leak across subdirectory boundaries.
\end{enumerate}

\textbf{Threat-level thresholds:}
\[
  \text{score} \in [0,3] \Rightarrow \text{Clean}, \quad
  [4,9] \Rightarrow \text{Suspicious}, \quad
  [10, \infty) \Rightarrow \text{Malicious}
\]

\subsection{Single-Read Optimisation}

The \texttt{HeuristicAnalyzer::analyze()} method reads each file \textit{exactly once} into a
\texttt{Vec<u8>} (capped at 10\,MiB).  Magic-byte detection, Shannon entropy,
content analysis, and SHA-256 all derive from the same in-memory buffer, eliminating three
redundant file opens per scan on the common case.

Files larger than 10\,MiB receive filename/extension/timestamp checks only; SHA-256 is
streamed separately.

\subsection{YARA Integration}

YARA rules are organised into subdirectories:

\begin{table}[H]
\centering
\caption{YARA rule categories}
\begin{tabular}{ll}
\toprule
\textbf{Directory} & \textbf{Content} \\
\midrule
\texttt{antidebug\_antivm/}  & Anti-analysis and VM-evasion techniques \\
\texttt{capabilities/}       & Code injection, persistence, cryptographic operations \\
\texttt{crypto\_rules/}      & Use of encryption primitives (RC4, AES, XOR) \\
\texttt{cve\_rules/}         & 300+ known CVE exploit signatures \\
\texttt{deprecated/}         & Legacy rules (Android, old formats) \\
\bottomrule
\end{tabular}
\end{table}

A representative rule illustrating the injection family:

\begin{lstlisting}[language=c, caption={YARA rule: inject\_thread}]
rule inject_thread {
  meta:
    author      = "x0r"
    description = "CreateRemoteThread code injection"
  strings:
    $c1 = "OpenProcess"
    $c2 = "VirtualAllocEx"
    $c3 = "NtWriteVirtualMemory"
    $c4 = "WriteProcessMemory"
    $c5 = "CreateRemoteThread"
  condition:
    $c1 and $c2 and ($c3 or $c4) and $c5
}
\end{lstlisting}

\subsection{Context Flags}

Context flags represent ransomware-specific indicators derived from directory-level analysis:

\begin{itemize}[leftmargin=*]
  \item \texttt{RansomNoteNearby} / \texttt{MultipleRansomNotes} -- text files matching
        ransomware note patterns present in the same directory.
  \item \texttt{RansomwareExtension} / \texttt{HighRansomwareExtensionRatio} -- extensions
        from a known ransomware-extension set (e.g., \texttt{.locked}, \texttt{.encrypted}).
  \item \texttt{MassModificationDetected} -- many files modified in a very short time window.
  \item \texttt{EncryptedCopyDetected} -- an encrypted copy of a known file was found
        alongside the original.
  \item \texttt{YaraRansomwareCorrelated} / \texttt{YaraFilenameCorrelated} -- cross-correlation
        between YARA hits and file-name patterns.
\end{itemize}

\subsection{Full-System Scanner (scan\_all.rs)}

The \texttt{SystemScanner} performs an incremental, prioritised, parallel scan of the entire
local filesystem.

\textbf{ScanPrioritizer scoring axes:}

\begin{table}[H]
\centering
\caption{File priority scoring}
\begin{tabular}{lll}
\toprule
\textbf{Axis} & \textbf{Example} & \textbf{Points} \\
\midrule
Location risk & \texttt{Temp}, \texttt{Downloads} & 30 \\
Location risk & \texttt{System32} & 15 \\
Extension risk & PE executables (\texttt{.exe,.dll}) & 20 \\
Extension risk & Scripts (\texttt{.ps1,.bat,.vbs}) & 15 \\
Extension risk & Archives (\texttt{.zip,.7z}) & 10 \\
Filename keyword & ``payload'', ``dropper'', ``exploit'' & 15 \\
Magic bytes & PE header (\texttt{MZ}) present & 10 \\
\bottomrule
\end{tabular}
\end{table}

\textbf{Incremental caching:} files whose \texttt{(mtime, size)} pair matches the cache are
skipped, providing near-instant re-scans after the initial cold run.

\textbf{Thread pool:} 1--16 worker threads, each holding an independent \texttt{FileSystemScanner}
instance behind an \texttt{Arc<Mutex<Receiver>>} channel.

\textbf{Skip rules:} large media files (video, audio, raw images), Windows internal directories
(\texttt{WinSxS}, \texttt{Installer}, Recycle Bin), and files exceeding 256\,MB are excluded.

\section{Process Scanner}

\subsection{Three-Stage Pipeline}

\subsubsection{Stage 1 -- Heuristic Scoring}

Per-process heuristic scoring considers:
\begin{itemize}[leftmargin=*]
  \item \textbf{Path analysis} -- executable in \texttt{Temp}, \texttt{AppData}, or a
        user-writable location raises the score.
  \item \textbf{Name analysis} -- processes matching known developer-tool patterns (IDEs,
        compilers, debuggers) receive a score halving to suppress false positives.
  \item \textbf{Command-line analysis} -- encoded PowerShell payloads
        (\texttt{-EncodedCommand}), long base64 blobs, or LOLBin invocations contribute
        positively.
  \item \textbf{Resource analysis} -- unusually high CPU or memory usage relative to process
        type.
  \item \textbf{Parent-context boost} -- children of processes already flagged as threats
        receive an amplified score.
\end{itemize}

\subsubsection{Stage 2 -- Handle Enumeration}

The engine enumerates all open handles for each suspicious process:
\begin{itemize}[leftmargin=*]
  \item Cross-process handles (targeting other processes): $+10$ per handle
        (reduced from $+25$ to accommodate legitimate multi-process applications).
  \item Single-instance mutexes commonly used by malware: $+20$.
  \item High file-handle counts (ransomware iterating over user files): $+15$.
\end{itemize}

\subsubsection{Stage 3 -- Loaded Module Analysis}

Loaded DLLs are compared against a whitelist of known system modules.  Anomalous or
unsigned modules contribute $+10$ each, capped at 5 modules ($+50$ maximum) to prevent
score inflation from legitimate software.  Anomaly details are stored in
\texttt{anomaly\_flags} for downstream ML feature extraction.

\textbf{Process threat-level thresholds:}

\begin{table}[H]
\centering
\caption{Process heuristic thresholds}
\begin{tabular}{lll}
\toprule
\textbf{Score range} & \textbf{Threat level} & \textbf{Action} \\
\midrule
0 -- 19   & Safe       & No action \\
20 -- 49  & Suspicious & Log + ML inference \\
50 -- 79  & Malicious  & Alert \\
80+       & Critical   & Alert + immediate recommendation \\
\bottomrule
\end{tabular}
\end{table}

\section{Network Scanner}

\subsection{Heuristic Layer}

The network heuristic module inspects each active connection's:
\begin{itemize}[leftmargin=*]
  \item \textbf{IP reputation} -- known C2 IP ranges, Tor exit nodes, bullet-proof hosting
        ASNs.
  \item \textbf{Port analysis} -- uncommon outbound ports, IRC/P2P patterns, beaconing
        intervals.
  \item \textbf{Connection state} -- established vs.\ half-open (SYN-sent) counts.
\end{itemize}

\subsection{Selective Deep Packet Inspection (DPI)}

DPI is only triggered when the heuristic score exceeds 14 \textbf{or} the ML probability
exceeds 0.5.  This design ensures zero overhead on clean traffic.  When triggered, the
payload is inspected for:
\begin{itemize}[leftmargin=*]
  \item Known malware command strings (shell metacharacters, SQL injection fragments).
  \item Shellcode byte patterns (NOP sleds, short-jump sequences).
  \item Anomalous protocol framing (HTTP in a non-HTTP port, TLS on port 80).
\end{itemize}
DPI signals \textit{bypass} the process-whitelist score cap because payload evidence is
considered definitive.

\subsection{Feature Extraction}

The \texttt{feature\_extractor.rs} module captures 47 UNSW-NB15 features from live packet
streams and writes them to \texttt{OnePace.csv}.  Key features include:

\begin{multicols}{2}
\begin{itemize}[leftmargin=*, itemsep=0pt]
  \item Flow duration
  \item Total bytes (src/dst)
  \item Mean packet size
  \item TCP RTT (min/max/mean)
  \item TCP window size
  \item Jitter
  \item Service type (port-derived)
  \item Connection state
  \item Protocol (TCP/UDP/ICMP)
  \item Source/destination port
  \item Inter-packet arrival time
\end{itemize}
\end{multicols}

\textbf{Network threat thresholds:}
\[
  \text{heuristic} \leq 14 \Rightarrow \text{Clean}, \quad
  [15, 34] \Rightarrow \text{Suspicious}, \quad
  \geq 35 \Rightarrow \text{Malicious}
\]

\section{Memory Scanner}

The memory scanner calls \texttt{VirtualQueryEx} to enumerate all virtual memory regions of
target processes and applies the following heuristics:

\begin{itemize}[leftmargin=*]
  \item \textbf{RWX regions} -- a region with \texttt{PAGE\_EXECUTE\_READWRITE} protection
        receives the highest base score ($+40$).
  \item \textbf{PE header in unexpected region} -- a committed, private region beginning
        with the ``\texttt{MZ}'' magic bytes outside of a mapped image indicates process
        hollowing or manual PE mapping.
  \item \textbf{Suspicious protection transitions} -- \texttt{PAGE\_NOACCESS} followed by
        \texttt{PAGE\_EXECUTE} indicates reflective DLL loading.
  \item \textbf{Content sampling} -- a 512-byte sample from each flagged region is extracted
        for further heuristic analysis (shellcode NOP sled detection, encoded payload
        signatures).
\end{itemize}

\textbf{3-Tier trust model:}
\begin{enumerate}
  \item \textit{SystemOs} -- Windows system processes; significantly reduced false-positive
        scores.
  \item \textit{JitRuntime} -- processes in an expanded list of $\approx$90 known JIT
        runtimes (.NET CLR, V8, SpiderMonkey, Java JVM) that legitimately create executable
        memory.
  \item \textit{Unknown} -- full scoring applied.
\end{enumerate}

% ============================================================
%  CHAPTER 4 -- MACHINE LEARNING MODELS
% ============================================================
\chapter{Machine Learning Models}

\section{File Domain -- EMBER2024 (LightGBM)}

\subsection{Dataset}

EMBER2024 (Endgame Malware BEnchmark for Research) is a large-scale dataset of Windows PE
features extracted from benign and malicious samples.  The dataset provides pre-computed
feature vectors so that raw PE files need not be distributed.

\subsection{Model Architecture}

Five LightGBM gradient-boosting classifiers are trained on EMBER2024, each specialised for
a PE sub-type detected via magic bytes:

\begin{table}[H]
\centering
\caption{EMBER2024 model routing}
\begin{tabular}{lll}
\toprule
\textbf{Model} & \textbf{Target format} & \textbf{Routing signal} \\
\midrule
\texttt{Win32}    & 32-bit Windows PE  & \texttt{MZ} + PE machine = \texttt{0x014C} \\
\texttt{Win64}    & 64-bit Windows PE  & \texttt{MZ} + PE machine = \texttt{0x8664} \\
\texttt{DotNet}   & .NET managed PE    & CLR directory present \\
\texttt{PDF}      & PDF documents      & \texttt{\%PDF} magic bytes \\
\texttt{All}      & Generic fallback   & Anything else \\
\bottomrule
\end{tabular}
\end{table}

\subsection{Inference Pipeline}

The Rust engine invokes a persistent Python server process (\texttt{ember\_bridge.py
--server}) that keeps all five models loaded in memory.  Per-file inference is handled via
an in-process call without sub-process spawning overhead.  The cold-start time (model load)
is absorbed once at daemon startup.

\textbf{Output:} a malicious probability $p \in [0, 1]$ mapped to a threat verdict using the
same $\geq 0.5 \Rightarrow$ Suspicious, $\geq 0.75 \Rightarrow$ Malicious thresholds as the
heuristic scoring.

\section{Network Domain -- XGBoost IDS}

\subsection{Dataset}

The network IDS is trained on the \textbf{UNSW-NB15} dataset, which contains 49 features
extracted from real network traffic augmented with synthetic attack scenarios across nine
attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance,
Shellcode, and Worms.

\subsection{Preprocessing Pipeline}

The script \texttt{preprocessing\_pipeline.py} performs the following steps:

\begin{enumerate}
  \item \textbf{Clean-IP filtering} -- connections to known-clean infrastructure (Google DNS
        8.8.8.8, Cloudflare 1.1.1.1, major Azure/AWS prefixes) are removed from inference
        to reduce noise.
  \item \textbf{Ordinal encoding} -- categorical columns (\texttt{proto}, \texttt{state},
        \texttt{service}) are encoded using a pre-fitted \texttt{OrdinalEncoder} persisted
        as \texttt{ordinal\_encoder.joblib}.
  \item \textbf{IP feature engineering} -- source and destination IPs are decomposed into:
        IPv4 vs.\ IPv6 flag, private/global/multicast classification, and a subnet index
        (16 possible /24 subnets).
  \item \textbf{Frequency features} -- \texttt{src\_freq} (count of flows from this source
        IP) and \texttt{dst\_freq} (count of flows to this destination IP) are appended
        using pre-computed frequency dictionaries.
  \item \textbf{Model selection} -- either \texttt{ids\_network\_calibrated.pkl} (preferred)
        or \texttt{ids\_network\_model.pkl} is loaded from \texttt{models/network/}.
\end{enumerate}

\subsection{Decision Thresholds}

\[
  p \geq 0.80 \Rightarrow \text{Malicious}, \quad
  p \in [0.55, 0.80) \Rightarrow \text{Suspicious}, \quad
  p < 0.55 \Rightarrow \text{Clean}
\]

The model outputs are enriched with human-readable labels: common IPs are resolved to
hostnames (e.g., ``google-dns'', ``cloudflare-dns'') and destination ports are mapped to
service names.

\section{Process Domain -- GRU on API Call Sequences}

\subsection{Architecture}

A \textbf{Gated Recurrent Unit (GRU)} network is trained to classify Windows processes as
malicious or benign based on sequences of Win32 API calls.  The model configuration is
stored in \texttt{config.json}:

\begin{itemize}[leftmargin=*]
  \item \textbf{Vocabulary size:} $\sim$500 unique API names.
  \item \textbf{Maximum sequence length:} 177 API calls.
  \item \textbf{Sliding window stride:} 100 (overlapping windows for long traces).
  \item \textbf{Minimum sequence length:} 5 API calls (shorter traces are discarded).
\end{itemize}

\subsection{Inference from PE Imports}

Because dynamic API traces are not available without sandboxing, the inference pipeline uses
a \textit{static approximation}: the PE import table is parsed to extract the list of
imported function names.  Unknown imports are silently discarded.  The remaining API names
are fed to \texttt{predict\_process()} as a static sequence.

\textbf{Output JSON:}
\begin{lstlisting}[language=python, caption={GRU inference output}]
{
  "exe_path":      "/path/to/process.exe",
  "probability":   0.73,
  "verdict":       "malicious",
  "label":         1,
  "top_api_calls": [["CreateRemoteThread", 0.89],
                    ["VirtualAllocEx",     0.76]],
  "trigger_chunk": 5,
  "api_count":     23,
  "source":        "pe_imports"
}
\end{lstlisting}

\begin{warnbox}
\textbf{Caveat:} PE import-based inference indicates ``capabilities consistent with malware''
rather than observed runtime behaviour.  A process that imports
\texttt{CreateRemoteThread} may be a legitimate injector (e.g., some anticheat software).
The ML probability is therefore blended with heuristic evidence rather than used standalone.
\end{warnbox}

\subsection{Deployment Mode}

The bridge script supports two modes:
\begin{itemize}[leftmargin=*]
  \item \texttt{--server}: persistent mode; keeps the PyTorch model loaded, services
        requests over JSON lines on \texttt{stdin/stdout}.  120\,s cold-start timeout.
  \item \texttt{--batch}: one-shot inference for a list of paths.  30\,s per-file timeout.
\end{itemize}

\section{Memory Domain -- Sklearn/XGBoost/ONNX Classifier}

\subsection{Architecture}

The memory ML model ingests feature vectors extracted from forensic memory snapshots.  The
inference module (\texttt{Deep\_dive/inference.py}) uses a \textit{format-agnostic loader}:

\begin{itemize}[leftmargin=*]
  \item \textbf{Joblib format} -- \texttt{sklearn}, \texttt{XGBoost}, or \texttt{LightGBM}
        estimators loaded via \texttt{joblib.load()}.
  \item \textbf{ONNX format} -- loaded via \texttt{onnxruntime.InferenceSession} for
        cross-platform deployment.
\end{itemize}

\subsection{Output}

\begin{lstlisting}[language=python, caption={Memory ML output}]
{
  "label":      1,
  "proba":      0.87,
  "verdict":    "MALWARE",
  "confidence": "HIGH",   # HIGH > 0.85, MEDIUM > 0.65, LOW otherwise
  "threshold":  0.5
}
\end{lstlisting}

The \texttt{MalMemPreprocessor} (\texttt{preprocess.py}) normalises raw memory-region feature
vectors before inference, applying the same scaler fitted during training.

\subsection{Diagnostic Pipeline}

The \texttt{Deep\_dive/preprocessing\_pipeline.py} script includes end-to-end checks for
data leakage (train/test feature overlap), class imbalance, and overfitting detection
(\textit{train accuracy} vs.\ \textit{test accuracy} gap $> 5\%$ triggers a warning).

\section{Steganography Detection}

AegisAI includes a multi-instance learning (MIL) steganography detector
(\texttt{MIL\_Steganography/}) that identifies hidden data concealed in image files using
Least Significant Bit (LSB) techniques.

\begin{itemize}[leftmargin=*]
  \item \textbf{Signal:} \texttt{stegProb} $\in [0,1]$ (probability of steganographic
        content), \texttt{isStego} (boolean verdict), \texttt{lsbOnesRatio} (should be
        $\approx 0.5$ for clean images; deviations indicate LSB manipulation).
  \item \textbf{Architecture:} a MIL framework treats image patches as a ``bag''; the bag
        label (stego/clean) is inferred from patch-level features.
  \item \textbf{Use case:} detecting exfiltration channels where malware conceals C2
        commands or stolen data in innocuous-looking image files.
\end{itemize}

% ============================================================
%  CHAPTER 5 -- ENTITY GRAPH PIPELINE
% ============================================================
\chapter{Entity Graph Pipeline}

\section{Overview}

The entity graph pipeline transforms flat, domain-specific scan results into a structured
threat graph that reveals \textit{relationships} between suspicious artefacts.  It consists
of four sequential stages: ingestion, aggregation, correlation, and graph analysis.

\section{Entity Manager (manager.rs)}

\subsection{Ingestion and Scoring}

The \texttt{EntityManager} receives \texttt{EntityNode} records from all four domain
scanners.  Each node carries a heuristic score and an optional ML score.  The
\textbf{combined score} is computed as:

\[
  \text{combined\_score} = \frac{H}{H_{\max}} \times 0.4 + \text{ML} \times 0.6
\]

where $H$ is the raw heuristic score, $H_{\max}$ is the domain-specific normalisation
constant (40 for most domains), and ML $\in [0,1]$ is the model probability.

\subsection{Sliding-Window Pruning}

The entity manager maintains a \textbf{10-minute sliding window}: entities older than
10\,min that are below the Suspicious threshold are automatically pruned to bound memory
usage.  This prevents long-running daemon sessions from accumulating stale data.

\subsection{Parent Context Boost}

When a process entity is flagged as a threat, its child processes receive a score boost via
\texttt{apply\_parent\_context\_boost()}.  This propagates threat context up the process
tree, reducing the probability that child processes of a malicious parent are dismissed as
clean.

\subsection{Entity ID Formats}

\begin{table}[H]
\centering
\caption{Flat EntityNode ID formats}
\begin{tabular}{ll}
\toprule
\textbf{Entity type} & \textbf{ID format} \\
\midrule
Process & \texttt{proc:\{pid\}:\{name\}} \\
Network & \texttt{net:\{proto\}:\{local\_addr\}:\{remote\_addr\}} \\
Memory  & \texttt{mem:\{pid\}:\{region\_start\_hex\}} \\
File    & \texttt{file:\{sha256\}} or \texttt{file:\{path\}} \\
\bottomrule
\end{tabular}
\end{table}

\subsection{Aggregation}

\texttt{EntityManager::aggregate()} transforms the flat node list into a set of
\texttt{AggregatedEntity} objects:

\begin{itemize}[leftmargin=*]
  \item \textbf{Process-anchored entities} (ID: \texttt{entity:\{pid\}}) -- one per PID,
        embedding all owned network, memory, and file sub-entities with per-domain
        sub-scores and boolean threat flags (\texttt{has\_malicious\_network},
        \texttt{has\_malicious\_memory}, \texttt{has\_malicious\_file}).
  \item \textbf{Orphan network entities} (ID: \texttt{entity-net:\{net\_entity\_id\}}) --
        network connections whose PID does not correspond to any known process.
  \item \textbf{Standalone file entities} (ID: \texttt{entity-file:\{file\_entity\_id\}}) --
        malicious files not linked to any running process.
\end{itemize}

\section{Entity Correlator (correlator.rs)}

The correlator groups flat \texttt{EntityNode} records into \texttt{CorrelatedCluster}
objects used by the \textit{EntityManager UI view} (distinct from the ThreatGraph).

\textbf{Join keys:}
\begin{itemize}[leftmargin=*]
  \item \texttt{pid} -- all entities belonging to the same process.
  \item \texttt{parent\_pid} -- parent--child spawn chains.
  \item \texttt{file\_hash} -- SHA-256: same binary at multiple paths.
  \item \texttt{remote\_ip} -- multiple connections to the same C2 infrastructure.
\end{itemize}

Process PIDs referenced in memory or network signals but not observed in the process scanner
are \textbf{backfilled}: the engine queries \texttt{sysinfo} to create a structural stub
node, maintaining graph continuity.

\section{Graph Builder (graph/builder.rs)}

\texttt{GraphBuilder::build\_from\_aggregated()} constructs a \texttt{ThreatGraph} from the
\texttt{AggregatedEntity} slice.  Nodes are one-to-one with aggregated entities.

\textbf{Three inter-entity edge types:}

\begin{table}[H]
\centering
\caption{ThreatGraph edge types and weights}
\begin{tabular}{lll}
\toprule
\textbf{Edge type} & \textbf{Detection criterion} & \textbf{Weight multiplier} \\
\midrule
\texttt{SharedC2}       & Two entities share the same remote IP  & $\times 1.50$ \\
\texttt{ParentChild}    & \texttt{parent\_pid} link               & $\times 1.20$ \\
\texttt{SharedFileHash} & Same SHA-256 at different paths         & $\times 0.90$ \\
\bottomrule
\end{tabular}
\end{table}

\section{Graph Analyzer (graph/analyzer.rs)}

\subsection{Attack Chain Detection}

Six attack patterns are detected, all mapped to MITRE ATT\&CK:

\begin{table}[H]
\centering
\caption{Attack chain patterns}
\label{tab:patterns}
\begin{tabularx}{\linewidth}{llXl}
\toprule
\textbf{Pattern} & \textbf{MITRE} & \textbf{Detection criterion} & \textbf{Scope} \\
\midrule
ProcessInjection     & T1055 & \texttt{has\_malicious\_memory == true}            & Intra-entity \\
C2Communication      & T1071 & \texttt{has\_malicious\_network == true}           & Intra-entity \\
MalwareExecution     & T1204 & \texttt{has\_malicious\_file == true}              & Intra-entity \\
LateralMovement      & T1021 & ParentChild edge + child has malicious network      & Inter-entity \\
SuspiciousSpawn      & T1059 & ParentChild edge + both nodes are threats           & Inter-entity \\
MultiStageAttack     & TA0002 & BFS over threat entities ($\geq$3 members)         & Inter-entity \\
\bottomrule
\end{tabularx}
\end{table}

After detection, chains are \textbf{deduplicated}: overlapping chains with lower
$\text{score} \times \text{confidence}$ products are removed.

\subsubsection{Confidence Scoring per Pattern}

Each pattern uses a domain-weighted confidence formula:

\begin{align}
  c_{\text{ProcessInjection}}  &= \text{memory\_score} + 0.15 \times \text{ml\_score} \\
  c_{\text{C2Communication}}   &= \text{network\_score} + 0.20 \times \text{ml\_score} \\
  c_{\text{MalwareExecution}}  &= \text{file\_score} \\
  c_{\text{LateralMovement}}   &= 0.5 \times \overline{\text{score}} + 0.5 \times \text{child.network\_score} \\
  c_{\text{SuspiciousSpawn}}   &= \min(\text{parent, child scores}) + 0.15 \cdot \mathbf{1}[\text{both Malicious}] \\
  c_{\text{MultiStageAttack}}  &= \overline{\text{score}}_{\text{chain nodes}}
\end{align}

\subsection{Critical Path}

\texttt{find\_critical\_path()} executes a DFS over the threat graph, selecting edges that
maximise the cumulative weight:

\[
  \text{path}^* = \arg\max_{\pi} \sum_{(u,v) \in \pi} w(u,v) \cdot s(v)
\]

where $w(u,v)$ is the edge weight and $s(v)$ is the combined score of node $v$.  The result
includes a plain-English narrative of the attack chain (e.g., \textit{``svchost.exe
[entity:1234] → C2 via 185.x.x.x → child cmd.exe [entity:5678] → file-based payload
[entity-file:abc]''}).

\subsection{LOLBin Detection}

The graph feedback pass (\texttt{apply\_graph\_feedback}) checks whether a clean parent node
is marked \texttt{is\_vector = true} (a trusted process exploited as an attack vector).  If
the parent's label matches any entry in the \texttt{LOLBINS} list ($\approx$35 entries from
the LOLBAS project, including \texttt{powershell.exe}, \texttt{cmd.exe},
\texttt{rundll32.exe}, \texttt{wscript.exe}, \texttt{mshta.exe}, \texttt{regsvr32.exe},
etc.), the node is additionally marked \texttt{is\_lolbin = true}.

% ============================================================
%  CHAPTER 6 -- AI AGENT
% ============================================================
\chapter{AI Agent}

\section{Overview}

The AI agent (\texttt{ai\_agent/}) acts as an autonomous virtual threat analyst.  It ingests
the full \texttt{CorrelateResult} produced by the graph pipeline and returns a structured
\texttt{AgentVerdict} with ranked containment actions, a risk assessment, and follow-up
investigation suggestions.

\begin{figure}[H]
\centering
\begin{tikzpicture}[
  box/.style={draw=aegisred!70, fill=aegisred!8, rounded corners, minimum width=3.8cm,
              minimum height=0.8cm, align=center, font=\small},
  arr/.style={-{Stealth}, thick, color=aegisred!80}
]
  \node[box] (ctx)  {Build Prompt Context\\(\texttt{build\_prompt\_context()})};
  \node[box, right=1.8cm of ctx] (llm)  {LLM Call\\(OpenRouter)};
  \node[box, right=1.8cm of llm] (parse) {Parse \& Validate\\(Pydantic)};
  \node[box, below=1cm of ctx] (re_ctx) {Reassess Context\\(\texttt{build\_reassess\_context()})};
  \node[box, right=1.8cm of re_ctx] (re_llm) {LLM Call\\(OpenRouter)};
  \node[box, right=1.8cm of re_llm] (re_parse) {Parse \& Validate\\(Pydantic)};

  \draw[arr] (ctx) -- node[above,font=\tiny]{system+human\\prompt} (llm);
  \draw[arr] (llm) -- node[above,font=\tiny]{JSON} (parse);
  \draw[arr] (re_ctx) -- (re_llm);
  \draw[arr] (re_llm) -- (re_parse);

  \draw[arr, dashed, bend left=30] (parse) to node[right, font=\tiny]{if not closed \& action taken} (re_ctx);

  \node[font=\footnotesize, color=aegisgray] at (4.5, -2.2) {Round 2+};
  \node[font=\footnotesize, color=aegisgray] at (4.5, 0.9)  {Round 1};
\end{tikzpicture}
\caption{AI agent reasoning loop.}
\label{fig:agent}
\end{figure}

\section{LLM and Framework}

\begin{itemize}[leftmargin=*]
  \item \textbf{LLM:} \texttt{poolside/laguna-xs.2:free} served via OpenRouter
        (OpenAI-compatible endpoint).
  \item \textbf{Framework:} LangChain (\texttt{ChatOpenAI} + \texttt{ChatPromptTemplate}
        chains).
  \item \textbf{Protocol:} JSON-RPC over \texttt{stdin}/\texttt{stdout}; the agent is
        spawned as an async sub-process by the Tauri backend.
\end{itemize}

\section{Pydantic Schema}

\subsection{RankedAction}

\begin{lstlisting}[language=python, caption={RankedAction Pydantic model}]
class RankedAction(BaseModel):
    action:        Literal["kill_process","quarantine_file","block_ip",
                           "dump_memory","check_persistence",
                           "isolate_network","remove_block_ip"]
    target:        str   # human-readable: "svchost.exe (PID 1234)"
    entity_id:     str   # references a ThreatGraph node
    justification: str   # one sentence from the model
    reversible:    bool  # derived from action name
    min_score_met: bool  # combined_score >= threshold
    confirm_required: bool  # kill_process, isolate_network require confirm
\end{lstlisting}

\subsection{AgentVerdict}

\begin{lstlisting}[language=python, caption={AgentVerdict Pydantic model}]
class AgentVerdict(BaseModel):
    ranked_actions:        List[RankedAction]  # 0-5 actions
    rationale:             str                 # 2-4 sentence analysis
    risk_level:            Literal["Low","Medium","High","Critical"]
    confidence:            float               # [0, 1]
    pivot_suggestions:     List[str]           # 0-3 follow-up scans
    warnings:              List[str]           # empty unless loop-capped
    investigation_closed:  bool
    close_reason:          Optional[Literal["resolved","no_improvement",
                                            "max_rounds_reached"]]
    round_num:             int                 # 1 = initial
\end{lstlisting}

\section{Prompt Engineering}

\subsection{System Prompt}

The system prompt defines the agent as a \textit{``Tier-3 Threat Analyst''} with
instructions to:

\begin{enumerate}
  \item Analyse the attack graph, chains, and critical path.
  \item Prioritise actions from \textit{most reversible} to \textit{least reversible}
        (never recommend network isolation before simpler containment).
  \item Justify each action by referencing specific attack chains and node IDs.
  \item Suggest 0--3 targeted follow-up scans (e.g., ``scan memory of PID 4821'',
        ``check persistence for path C:\textbackslash Temp\textbackslash dropper.exe'').
  \item Assign a \texttt{risk\_level} and \texttt{confidence} calibrated to the available
        evidence.
  \item Return valid JSON matching the \texttt{AgentVerdict} schema.
\end{enumerate}

\subsection{Human Prompt}

The human prompt is built by \texttt{build\_prompt\_context()} and includes:

\begin{itemize}[leftmargin=*]
  \item Formatted attack-chain summaries: pattern name, MITRE tactic, severity, confidence,
        and affected entity IDs.
  \item Per-node data: \texttt{threat\_level}, \texttt{combined\_score}, sub-scores
        (\texttt{process/network/memory/file\_score}), \texttt{anomaly\_flags}.
  \item Critical-path narrative (plain-English text generated by the graph analyzer).
  \item Entity statistics (total entities, threat count, per-domain counts).
\end{itemize}

\subsection{Re-assessment Prompt}

Starting from round 2, \texttt{build\_reassess\_context()} appends an
\textit{``Actions Already Taken''} block to the human prompt:

\begin{itemize}[leftmargin=*]
  \item Each executed action is listed with its type, target, timestamp, and result.
  \item The model is instructed to never recommend an action that has already been executed.
  \item If the threat level has dropped or no malicious chains remain, the model must
        set \texttt{investigation\_closed = true} with
        \texttt{close\_reason = "resolved"}.
  \item After 5 rounds with no improvement, the model sets
        \texttt{close\_reason = "no\_improvement"}.
\end{itemize}

% ============================================================
%  CHAPTER 7 -- TAURI UI
% ============================================================
\chapter{Tauri Desktop Application}

\section{Technology Stack}

\begin{table}[H]
\centering
\caption{UI technology stack}
\begin{tabular}{ll}
\toprule
\textbf{Component} & \textbf{Technology} \\
\midrule
Desktop shell       & Tauri 2 (Rust backend + WebView2) \\
UI framework        & React 18.2 \\
State management    & Zustand 4.5 \\
Charts              & Recharts 3.7 \\
Icons               & Lucide React \\
Type system         & TypeScript 5.3 \\
Build tool          & Vite 5 \\
\bottomrule
\end{tabular}
\end{table}

\section{Tauri IPC Command Catalogue}

The Tauri Rust backend registers the following \texttt{invoke()} commands:

\begin{table}[H]
\centering
\caption{Tauri invoke command catalogue}
\begin{tabularx}{\linewidth}{lX}
\toprule
\textbf{Command} & \textbf{Description} \\
\midrule
\texttt{scan\_file}           & Scan a single file path \\
\texttt{scan\_directory}      & Recursive directory scan \\
\texttt{scan\_processes}      & Enumerate and score all running processes \\
\texttt{scan\_network}        & Scan all or one process's network connections \\
\texttt{scan\_memory}         & Scan all or one process's memory regions \\
\texttt{correlate\_entities}  & Full entity/graph pipeline (includes memory if requested) \\
\texttt{run\_ml\_ids}         & Run network XGBoost IDS on an optional CSV path \\
\texttt{kill\_process}        & Terminate a process by PID \\
\texttt{quarantine\_file}     & Move a file to quarantine \\
\texttt{block\_ip}            & Add Windows Firewall outbound deny rule \\
\texttt{remove\_block\_ip}    & Remove a named AegisAI firewall rule \\
\texttt{dump\_memory}         & Write a full memory dump for a PID \\
\texttt{check\_persistence}   & Audit autorun locations \\
\texttt{isolate\_network}     & Disable all network adapters \\
\texttt{restore\_network}     & Re-enable saved adapters \\
\texttt{export\_incident\_report} & Write structured JSON incident report \\
\texttt{get\_engine\_status}  & Return daemon health \\
\bottomrule
\end{tabularx}
\end{table}

\section{React Component Architecture}

\subsection{Navigation and Layout}

\begin{itemize}[leftmargin=*]
  \item \textbf{App.tsx} -- top-level router across 8 views:
        \texttt{dashboard | scanner | processes | network | memory | history | entities | graph}.
  \item \textbf{TitleBar} -- frameless window controls (minimise, maximise, close) and
        real-time engine status indicator.
  \item \textbf{Sidebar} -- icon-based tab navigation with active-tab highlighting.
\end{itemize}

\subsection{Scanner View}

\begin{itemize}[leftmargin=*]
  \item Path input (file or directory) with a native OS file picker.
  \item Scan-All button that triggers a full-system scan; a \texttt{setInterval} live timer
        shows elapsed seconds while scanning; a duration badge shows the final time.
  \item Results table filterable by threat level with per-result detail panel (detection
        signals, context flags, confidence score).
\end{itemize}

\subsection{Process / Network / Memory Monitors}

Each domain view presents a tabular list of scan results with:
\begin{itemize}[leftmargin=*, itemsep=0pt]
  \item Colour-coded threat level badges (green / yellow / red / dark-red).
  \item Score bars (0--100 heuristic, 0.0--1.0 ML).
  \item Detection signal chips (e.g., ``hollow'', ``packed'', ``temp\_dir'', ``dpi'').
  \item Contextual action buttons (Kill, Block, Dump) that invoke the Tauri IPC layer.
\end{itemize}

\subsection{ThreatGraph}

The graph view renders the \texttt{ThreatGraph} as an interactive node-link diagram:
\begin{itemize}[leftmargin=*]
  \item Nodes are coloured by threat level; node icons are chosen by dominant sub-score
        (CPU icon for process-heavy, network for C2-heavy, etc.).
  \item Edges are labelled by type; \texttt{SharedC2} edges are rendered with a distinctive
        dashed red style.
  \item A detail panel on node click shows all sub-scores (\texttt{PROC/NET/MEM/FILE}
        chips), attack-chain membership, and graph-feedback badges
        (\texttt{is\_vector}, \texttt{is\_lolbin}).
  \item The attack-chain list shows each detected pattern, MITRE tactic, severity, and
        affected nodes.
  \item The critical-path narrative is displayed at the top of the panel.
\end{itemize}

\subsection{GraphVerdict View}

The verdict view presents the \texttt{AgentVerdict} returned by the AI agent:
\begin{itemize}[leftmargin=*]
  \item Ranked action cards with confidence scores, justifications, and execute buttons.
  \item Risk level badge (colour-coded Low/Medium/High/Critical).
  \item Pivot-suggestion chips for follow-up scans.
  \item Round counter and ``investigation closed'' banner when
        \texttt{investigation\_closed = true}.
\end{itemize}

\section{Zustand State Store}

The \texttt{store/index.ts} file maintains all async UI state:

\begin{itemize}[leftmargin=*]
  \item Loading flags: \texttt{scanning}, \texttt{processScanning}, \texttt{networkScanning},
        \texttt{memoryScanning}, \texttt{correlating}.
  \item Result arrays: \texttt{scanResults}, \texttt{processes}, \texttt{networkConnections},
        \texttt{memoryRegions}.
  \item \texttt{correlateResult} -- full \texttt{CorrelateResult} including graph and
        attack chains.
  \item \texttt{agentVerdict} -- latest \texttt{AgentVerdict} from the LLM agent.
  \item \texttt{actionsTaken} -- ordered list of \texttt{ExecutedAction} objects for
        re-assessment context.
  \item \texttt{currentRound} -- iteration counter for multi-round agent analysis.
  \item \texttt{history} -- scan history entries with timestamps, statistics, and duration.
  \item \texttt{lastScanDurationMs} -- duration of the most recent full-system scan.
\end{itemize}

% ============================================================
%  CHAPTER 8 -- POST-VERDICT CONTAINMENT ACTIONS
% ============================================================
\chapter{Post-Verdict Containment Actions}

\section{Design Principles}

All containment actions are designed around three principles:

\begin{enumerate}
  \item \textbf{Reversibility first} -- every action except \texttt{kill\_process} can be
        undone.  Firewall rules are named and logged; quarantined files are moved, never
        deleted; isolated adapters are saved for restore.
  \item \textbf{Least-privilege scope} -- actions target specific PIDs, IPs, or file paths;
        no action affects the entire system without explicit confirmation.
  \item \textbf{Forensic preservation} -- memory dumps and metadata sidecars ensure
        evidence is available for post-incident analysis.
\end{enumerate}

\section{Action Implementations}

\subsection{File Quarantine}

\texttt{quarantine\_file(path)} in \texttt{executor.rs}:
\begin{enumerate}
  \item Computes SHA-256 of the target file.
  \item Moves the file to \texttt{\%PROGRAMDATA\%\textbackslash AegisAI\textbackslash quarantine\textbackslash\{sha256\}.quarantined}.
  \item Writes a JSON metadata sidecar:
        \texttt{\{sha256\}.meta.json} containing original path, timestamp, threat level.
\end{enumerate}

\subsection{Firewall Block}

\texttt{block\_ip(remote\_ip, direction)}:
\begin{enumerate}
  \item Constructs a rule name: \texttt{AegisAI\_\{unix\_timestamp\}}.
  \item Executes: \texttt{netsh advfirewall firewall add rule name="AegisAI\_..." dir=out
        action=block remoteip=\{ip\} protocol=tcp}.
  \item Appends the rule to
        \texttt{\%PROGRAMDATA\%\textbackslash AegisAI\textbackslash firewall\_rules.json}
        for audit and rollback.
\end{enumerate}

\texttt{remove\_block\_ip(rule\_name)} reverses the above with \texttt{netsh ... delete rule}.

\subsection{Memory Dump}

\texttt{dump\_memory(pid)}:
\begin{enumerate}
  \item Calls \texttt{MiniDumpWriteDump} with the
        \texttt{MiniDumpWithFullMemory} flag via the Windows API.
  \item Saves to \texttt{\%PROGRAMDATA\%\textbackslash AegisAI\textbackslash dumps\textbackslash\{pid\}\_\{timestamp\}.dmp}.
  \item Compatible with WinDbg (\texttt{.dump} inspection) and Volatility 3 forensic
        framework.
\end{enumerate}

\subsection{Persistence Audit}

\texttt{check\_persistence(suspicious\_paths)}:
\begin{enumerate}
  \item Enumerates Windows Registry run keys:
        \texttt{HKLM/HKCU\textbackslash Software\textbackslash Microsoft\textbackslash Windows\textbackslash CurrentVersion\textbackslash Run[Once]}.
  \item Inspects scheduled tasks in
        \texttt{C:\textbackslash Windows\textbackslash System32\textbackslash Tasks\textbackslash*}.
  \item Checks startup folders:
        \texttt{\%APPDATA\%\textbackslash Microsoft\textbackslash Windows\textbackslash Start Menu\textbackslash Programs\textbackslash Startup}.
  \item Cross-references found entries against the provided \texttt{suspicious\_paths} list.
  \item Returns a list of \texttt{PersistenceEntry} records (read-only, no modifications).
\end{enumerate}

\subsection{Network Isolation / Restore}

\texttt{isolate\_network()}:
\begin{enumerate}
  \item Enumerates all connected network adapters via \texttt{GetAdaptersInfo} / WMI.
  \item Saves the adapter list to
        \texttt{\%PROGRAMDATA\%\textbackslash AegisAI\textbackslash isolated\_interfaces.json}.
  \item Disables all adapters via \texttt{netsh interface set interface ... disable}.
\end{enumerate}

\texttt{restore\_network()} reverses the above using the saved list.

\begin{infobox}
\textbf{Network isolation is the most impactful reversible action.}  It should only be
recommended by the agent when evidence of active C2 communication is present and less
disruptive options (firewall rules) have already been applied.  The confirm-gate in the UI
enforces this by requiring explicit user acknowledgement before execution.
\end{infobox}

\section{Action Result Types}

\begin{table}[H]
\centering
\caption{Containment action result structs}
\begin{tabularx}{\linewidth}{llX}
\toprule
\textbf{Struct} & \textbf{Action} & \textbf{Fields} \\
\midrule
\texttt{QuarantineResult} & \texttt{quarantine\_file} & \texttt{success, quarantine\_path?, sha256?, error?} \\
\texttt{BlockIpResult}    & \texttt{block\_ip}        & \texttt{success, rule\_name?, error?} \\
\texttt{DumpResult}       & \texttt{dump\_memory}     & \texttt{success, dump\_path?, error?} \\
\texttt{PersistenceResult}& \texttt{check\_persistence}& \texttt{success, entries: Vec<PersistenceEntry>, error?} \\
\texttt{IsolationResult}  & \texttt{isolate\_network} & \texttt{success, disabled\_interfaces: Vec<String>, error?} \\
\bottomrule
\end{tabularx}
\end{table}

% ============================================================
%  CHAPTER 9 -- CORE DATA TYPES
% ============================================================
\chapter{Core Data Types and Type System}

\section{Rust Types}

\subsection{Shared Types (core/types.rs)}

\begin{lstlisting}[language=rust, caption={Core Rust types}]
pub enum ThreatLevel { Clean, Suspicious, Malicious }

pub enum FileCategory {
    Executable, Script, Document,
    Archive, MacroEnabled, Unknown
}

pub struct DetectionSignal {
    pub source:      String,   // "path", "name", "cmdline", "handle", "dpi"
    pub description: String,
    pub score:       i32,
}

pub struct ScanResult {
    pub path:             String,
    pub threat_level:     ThreatLevel,
    pub reason:           String,
    pub hash:             Option<String>,   // SHA-256
    pub signature:        Option<String>,   // YARA rule name
    pub confidence_score: f64,
    pub detection_signals: Vec<DetectionSignal>,
    pub file_category:    Option<FileCategory>,
    pub context_flags:    Vec<ContextFlag>,
}
\end{lstlisting}

\subsection{Entity Types (entity/types.rs)}

\begin{lstlisting}[language=rust, caption={Entity and AggregatedEntity types}]
pub enum UnifiedThreatLevel { Clean, Suspicious, Malicious, Critical }

pub struct EntityNode {
    pub entity_id:        String,
    pub entity_type:      EntityType,  // Process | Network | Memory | File
    pub combined_score:   f64,
    pub heuristic_score:  f64,
    pub ml_score:         Option<f64>,
    pub threat_level:     UnifiedThreatLevel,
    pub detection_signals: Vec<DetectionSignal>,
    pub join_keys:        JoinKeys,
    pub timestamp:        Instant,
}

pub struct AggregatedEntity {
    pub entity_id:       String,      // "entity:{pid}" or "entity-net:..." 
    pub process_score:   Option<f64>,
    pub network_score:   Option<f64>,
    pub memory_score:    Option<f64>,
    pub file_score:      Option<f64>,
    pub combined_score:  f64,
    pub threat_level:    UnifiedThreatLevel,
    pub has_malicious_network: bool,
    pub has_malicious_memory:  bool,
    pub has_malicious_file:    bool,
    pub pid:             Option<u32>,
    pub parent_pid:      Option<u32>,
    pub sub_entities:    Vec<EntityNode>,
}
\end{lstlisting}

\subsection{Graph Types (graph/types.rs)}

\begin{lstlisting}[language=rust, caption={ThreatGraph, GraphNode, and GraphEdge}]
pub struct ThreatGraph {
    pub nodes:         Vec<GraphNode>,
    pub edges:         Vec<GraphEdge>,
    pub attack_chains: Vec<AttackChain>,
    pub critical_path: Option<CriticalPath>,
}

pub struct GraphNode {
    pub entity_id:      String,
    pub label:          String,
    pub threat_level:   UnifiedThreatLevel,
    pub combined_score: f64,
    pub process_score:  Option<f64>,
    pub network_score:  Option<f64>,
    pub memory_score:   Option<f64>,
    pub file_score:     Option<f64>,
    pub has_malicious_network: bool,
    pub has_malicious_memory:  bool,
    pub has_malicious_file:    bool,
    pub pid:            Option<u32>,
    pub parent_pid:     Option<u32>,
    pub graph_boost:    f64,
    pub is_vector:      bool,
    pub is_lolbin:      bool,
}

pub struct GraphEdge {
    pub from:      String,
    pub to:        String,
    pub edge_type: EdgeType,  // ParentChild | SharedC2 | SharedFileHash
    pub weight:    f64,
}

pub struct AttackChain {
    pub chain_id:    String,
    pub pattern:     AttackPattern,
    pub node_ids:    Vec<String>,
    pub chain_score: f64,
    pub severity:    Severity,
    pub description: String,
    pub mitre_tactic: String,
    pub confidence:  f64,
}
\end{lstlisting}

\section{TypeScript Types}

The TypeScript type system in \texttt{UI/src/types/index.ts} mirrors the Rust types and
adds UI-specific fields:

\begin{lstlisting}[language=javascript, caption={Key TypeScript interfaces (abbreviated)}]
interface GraphNodeData {
  entity_id: string;
  entity_type: string;
  threat_level: UnifiedThreat;
  combined_score: number;
  process_score?: number;
  network_score?: number;
  memory_score?: number;
  file_score?: number;
  has_malicious_network?: boolean;
  has_malicious_memory?: boolean;
  has_malicious_file?: boolean;
  pid?: number;
  parent_pid?: number;
  graph_boost?: number;
  is_vector?: boolean;
  is_lolbin?: boolean;
}

interface AgentVerdict {
  ranked_actions: RankedAction[];
  rationale: string;
  risk_level: "Low" | "Medium" | "High" | "Critical";
  confidence: number;
  pivot_suggestions: string[];
  warnings: string[];
  investigation_closed: boolean;
  close_reason?: "resolved" | "no_improvement" | "max_rounds_reached";
  round_num: number;
}
\end{lstlisting}

% ============================================================
%  CHAPTER 10 -- SECURITY DESIGN
% ============================================================
\chapter{Security Design and Key Decisions}

\section{Defence-in-Depth Architecture}

AegisAI is designed around the principle of \textbf{defence-in-depth}: each detection layer
operates independently and can catch threats that the others miss.

\begin{table}[H]
\centering
\caption{Detection layer coverage matrix}
\begin{tabular}{lllll}
\toprule
\textbf{Threat type} & \textbf{File} & \textbf{Process} & \textbf{Network} & \textbf{Memory} \\
\midrule
Known malware family       & \faCheck & \faCheck &           &           \\
Ransomware                 & \faCheck & \faCheck &           & \faCheck  \\
Code injection / process hollowing & & \faCheck &           & \faCheck  \\
C2 beaconing               &           &           & \faCheck  &           \\
Fileless malware           &           & \faCheck  & \faCheck  & \faCheck  \\
LOLBin abuse               &           & \faCheck  &           &           \\
Lateral movement           &           & \faCheck  & \faCheck  &           \\
Persistence                &           & \faCheck  &           &           \\
Steganographic exfil       & \faCheck  &           & \faCheck  &           \\
\bottomrule
\end{tabular}
\end{table}

\section{False-Positive Reduction}

\begin{itemize}[leftmargin=*]
  \item \textbf{Developer-tool halving:} known IDE, compiler, and debugger processes have
        their heuristic scores halved (twice if needed) to prevent security tools from
        flagging developer workstations.
  \item \textbf{JIT runtime trust:} $\approx$90 known JIT runtimes are in a trust list
        that relaxes memory-region scoring.
  \item \textbf{Context isolation:} directory-level ransomware flags do not propagate to
        parent or sibling directories.
  \item \textbf{Clean-IP filtering:} connections to major CDN/DNS providers are excluded
        from network ML inference.
  \item \textbf{Graph feedback:} LOLBin and vector flags are only set after
        parent--child edge analysis, preventing noise from isolated process scans.
  \item \textbf{DPI selectivity:} deep packet inspection is only triggered above defined
        score thresholds, eliminating overhead and false positives on clean traffic.
\end{itemize}

\section{ML Robustness}

The \textbf{dual-scoring formula} ($H \times 0.4 + \text{ML} \times 0.6$) is designed to
ensure that neither layer alone can determine the final verdict:

\begin{itemize}[leftmargin=*]
  \item A high ML score on a clean-heuristic process is flagged as Suspicious, not
        Malicious, until heuristic evidence corroborates.
  \item A high heuristic score on a clean-ML process (e.g., an obfuscated but known-safe
        binary) similarly results in a Suspicious rather than Malicious verdict.
  \item ML is \textit{optional}: if Python is unavailable or the model fails to load, the
        engine silently falls back to heuristic-only scoring without crashing.
\end{itemize}

\section{Reversibility and Forensics}

\begin{itemize}[leftmargin=*]
  \item Files are \textit{moved and renamed}, never deleted.  The SHA-256-named quarantine
        format makes deduplication and restore trivial.
  \item Firewall rules carry an ``AegisAI\_'' prefix and a timestamp, making them easy to
        identify and remove without disrupting pre-existing rules.
  \item Network isolation stores the adapter state to a JSON file before disabling; restore
        is a single command.
  \item Memory dumps use \texttt{MiniDumpWithFullMemory}, the most complete dump type,
        ensuring all pages are captured for forensic analysis.
\end{itemize}

\section{Scoring Thresholds Summary}

\begin{table}[H]
\centering
\caption{Complete threshold reference}
\begin{tabular}{lllll}
\toprule
\textbf{Domain} & \textbf{Metric} & \textbf{Clean} & \textbf{Suspicious} & \textbf{Malicious} \\
\midrule
File        & Composite score    & $[0, 3]$   & $[4, 9]$   & $\geq 10$   \\
Process     & Heuristic score    & $[0, 19]$  & $[20, 49]$ & $\geq 50$ ($\geq 80$ = Critical) \\
Network     & Heuristic score    & $[0, 14]$  & $[15, 34]$ & $\geq 35$   \\
Network ML  & XGBoost probability& $< 0.55$   & $[0.55, 0.80)$ & $\geq 0.80$ \\
File ML     & EMBER probability  & $< 0.50$   & $[0.50, 0.75)$ & $\geq 0.75$ \\
Process ML  & GRU probability    & $< 0.40$   & $[0.40, 0.65)$ & $\geq 0.65$ \\
Entity      & Combined score     & $[0, 0.30]$& $(0.30, 0.65]$ & $(0.65, 1.0]$ \\
\bottomrule
\end{tabular}
\end{table}

% ============================================================
%  CHAPTER 11 -- PERFORMANCE
% ============================================================
\chapter{Performance Characteristics}

\section{Engine Startup}

\begin{itemize}[leftmargin=*]
  \item YARA rule compilation: $\sim$2--5\,s for $\approx$300 rules (one-time, at daemon
        start; rules are reused across all scan requests).
  \item EMBER2024 model load: $\sim$5--10\,s (five LightGBM models loaded into the
        \texttt{EmberServer} process).
  \item After startup, all subsequent scan requests have zero ML cold-start overhead.
\end{itemize}

\section{Full-System Scan}

Scan performance depends heavily on filesystem size and content.  Key optimisations:
\begin{itemize}[leftmargin=*]
  \item \textbf{Incremental cache:} on repeat scans, files whose \texttt{(mtime, size)}
        matches the cache are skipped immediately.  A warm-cache re-scan of a 100\,k-file
        system can complete in under 10\,s.
  \item \textbf{Priority ordering:} high-risk files (Temp, Downloads, suspicious
        extensions) are scanned first, so early results are the most actionable.
  \item \textbf{Thread pool:} 8--16 parallel workers exploit multi-core CPUs; the
        \texttt{Arc<Mutex<Receiver>>} pattern ensures work-stealing without per-file
        locking overhead.
  \item \textbf{Size cap:} files $>$ 256\,MB receive a fast-path (metadata + extension
        checks only), preventing scan stalls on large media files.
\end{itemize}

\section{Network ML Latency}

\begin{itemize}[leftmargin=*]
  \item Feature extraction (\texttt{OnePace.csv} generation): live, inline with packet
        capture.
  \item XGBoost inference (Python sub-process): $\sim$50--200\,ms for a batch of
        connections.
  \item DPI is triggered selectively; on clean traffic, overhead is effectively zero.
\end{itemize}

% ============================================================
%  CHAPTER 12 -- PENDING WORK AND ROADMAP
% ============================================================
\chapter{Pending Work and Roadmap}

The following features are designed and partially scaffolded but not yet fully implemented:

\begin{table}[H]
\centering
\caption{Known pending work}
\begin{tabularx}{\linewidth}{lX}
\toprule
\textbf{Area} & \textbf{Description} \\
\midrule
UI: containment actions & \texttt{GraphVerdict.tsx}, \texttt{QuarantineManager.tsx},
                           \texttt{Settings.tsx} components for calling quarantine, firewall,
                           dump, persistence, isolation from the React UI are not yet built. \\
UI: LOLBin badge        & \texttt{is\_lolbin} field in \texttt{GraphNodeData} (TypeScript) needs
                           to be added; \texttt{ThreatGraph.tsx} can then render the badge on
                           vector nodes. \\
UI: autonomous mode     & \texttt{autonomousMode} Zustand flag + Settings toggle not yet
                           implemented. \\
Network model           & Recalibrate \texttt{CalibratedClassifierCV} on real traffic; retrain
                           with mixed real-world + UNSW-NB15 data. \\
AI agent stubs          & \texttt{ai\_agent/agent/reasoning.py} and \texttt{main.py} are empty
                           stubs; full LangChain chain is in \texttt{analyst.py} but the
                           orchestration entrypoint needs wiring. \\
File ML model           & No dedicated ML model for the file domain yet (YARA + heuristics
                           only); EMBER2024 integration is implemented but the file scanner
                           does not call it inline. \\
\bottomrule
\end{tabularx}
\end{table}

% ============================================================
%  CHAPTER 13 -- CONCLUSION
% ============================================================
\chapter{Conclusion}

AegisAI represents a comprehensive, production-oriented approach to endpoint threat detection
that combines the best attributes of traditional antivirus (signature databases, YARA rules,
heuristics) with modern machine learning (EMBER2024 LightGBM, XGBoost network IDS, GRU
process inference) and autonomous AI reasoning (LangChain-powered threat analyst agent).

The \textbf{entity graph pipeline} is the system's most novel contribution: by lifting
detection from the individual-artefact level to the \textit{relationship graph} level, the
engine can identify multi-stage attack scenarios -- process injection followed by C2
communication followed by lateral movement -- that no single-layer detector could catch in
isolation.

The \textbf{multi-round agent reasoning loop} closes the gap between automated detection and
human-in-the-loop incident response: the analyst executes containment actions and the agent
re-assesses, iterating until the investigation is closed.  All containment actions are
reversible and forensically sound.

Together, these layers form a \textbf{defence-in-depth} architecture suited for detecting
and containing sophisticated endpoint threats on Windows systems, while providing the
analyst with the transparency and control necessary for responsible automated response.

% ============================================================
%  APPENDICES
% ============================================================
\appendix

\chapter{Directory Structure}

\begin{lstlisting}[caption={Top-level project layout}]
AegisAI/
├── Antivirus_Engine/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs             # CLI entry + daemon loop
│   │   ├── lib.rs
│   │   └── core/
│   │       ├── types.rs        # Shared types
│   │       ├── utils.rs        # SHA-256, entropy, is_pe_file
│   │       ├── file_system/    # scanner, heuristics, yara_engine,
│   │       │                   # scan_all, context
│   │       ├── process/        # scanner, heuristics, handles,
│   │       │                   # modules, API_feature_extractor
│   │       ├── network/        # scanner, heuristics, dpi,
│   │       │                   # feature_extractor
│   │       ├── memory/         # scanner, ML_models/
│   │       ├── entity/         # manager, correlator, types
│   │       ├── graph/          # builder, analyzer, types
│   │       ├── action/         # executor (all containment actions)
│   │       └── MIL_Steganography/
│   ├── models/
│   │   └── network/            # XGBoost model + encoders
│   └── yara_rules/             # 300+ rules in subdirectories
├── UI/
│   ├── package.json
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/         # All React components
│   │   ├── store/index.ts      # Zustand store
│   │   ├── types/index.ts      # TypeScript interfaces
│   │   └── lib/entityUtils.ts  # Client-side entity aggregation
│   └── src-tauri/src/main.rs   # Tauri IPC commands
├── ai_agent/
│   ├── main.py                 # Entry point (stub)
│   └── agent/
│       ├── analyst.py          # LangChain chain
│       ├── reasoning.py        # Stub
│       ├── prompt.py           # System + human prompts
│       └── schema.py           # Pydantic models
└── CLAUDE.md                   # Project instructions
\end{lstlisting}

\chapter{MITRE ATT\&CK Mapping}

\begin{table}[H]
\centering
\caption{Full MITRE ATT\&CK coverage}
\begin{tabular}{lll}
\toprule
\textbf{Technique ID} & \textbf{Name} & \textbf{AegisAI detection} \\
\midrule
T1055  & Process Injection      & Memory scanner RWX + entity flag \\
T1071  & C2 Application Layer   & Network ML + DPI \\
T1204  & User Execution         & File scanner malicious verdict \\
T1021  & Remote Services        & Network lateral movement edge \\
T1059  & Command/Scripting      & Process heuristics + graph edge \\
TA0002 & Execution (multi-stage)& BFS attack chain ($\geq$3 nodes) \\
T1027  & Obfuscated Files       & Entropy heuristics + YARA \\
T1053  & Scheduled Task/Job     & Persistence checker \\
T1547  & Boot/Logon Autostart   & Persistence checker (registry) \\
T1562  & Impair Defences        & YARA antidebug\_antivm rules \\
T1048  & Exfiltration Over Alt.\ Channel & Steganography detector \\
\bottomrule
\end{tabular}
\end{table}

\chapter{Glossary}

\begin{description}[leftmargin=3cm, style=nextline]
  \item[APT] Advanced Persistent Threat -- a prolonged, targeted cyberattack campaign.
  \item[C2] Command and Control -- the infrastructure used by an attacker to direct malware.
  \item[DPI] Deep Packet Inspection -- payload-level analysis of network traffic.
  \item[EMBER2024] Endgame Malware BEnchmark for Research, 2024 edition -- PE feature dataset.
  \item[GRU] Gated Recurrent Unit -- a type of recurrent neural network.
  \item[IDS] Intrusion Detection System.
  \item[IPC] Inter-Process Communication.
  \item[LOLBin] Living-Off-the-Land Binary -- a legitimate system binary abused by attackers.
  \item[LSB] Least Significant Bit -- used in steganographic techniques.
  \item[MIL] Multiple Instance Learning -- a machine-learning paradigm for bag-level labels.
  \item[MITRE ATT\&CK] A knowledge base of adversary tactics and techniques.
  \item[RWX] Read-Write-Execute -- a memory protection flag indicating an executable heap.
  \item[SHA-256] Secure Hash Algorithm 256-bit -- used for file identification.
  \item[UNSW-NB15] A network intrusion dataset from the University of New South Wales.
  \item[YARA] Yet Another Recursive Acronym -- a pattern-matching language for malware.
  \item[XGBoost] Extreme Gradient Boosting -- an ensemble machine-learning algorithm.
\end{description}

\end{document}
```
