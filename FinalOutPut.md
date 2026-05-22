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
\usepackage{tcolorbox}
\usepackage{multicol}
\usepackage{tabularx}
\usepackage{caption}
\usepackage{float}
\usepackage{pifont}
\usepackage{fontawesome5}
\pgfplotsset{compat=1.18}
\usetikzlibrary{shapes,arrows,arrows.meta,positioning,fit,backgrounds,decorations.pathreplacing,calc}
\tcbuselibrary{skins,breakable}

% ── Colors ────────────────────────────────────────────────────────────────────
\definecolor{aegisblue}{RGB}{30,80,162}
\definecolor{aegiscyan}{RGB}{0,172,193}
\definecolor{aegisdark}{RGB}{20,20,35}
\definecolor{malicious}{RGB}{200,40,40}
\definecolor{suspicious}{RGB}{220,140,0}
\definecolor{clean}{RGB}{30,150,70}
\definecolor{codegray}{RGB}{248,248,248}
\definecolor{codegreen}{RGB}{0,128,0}
\definecolor{codepurple}{RGB}{128,0,128}
\definecolor{codebrown}{RGB}{160,82,45}
\definecolor{lightblue}{RGB}{220,235,255}
\definecolor{lightyellow}{RGB}{255,253,220}
\definecolor{lightred}{RGB}{255,230,230}
\definecolor{lightgreen}{RGB}{220,255,220}
\definecolor{titlegray}{RGB}{60,60,80}
\definecolor{sectionblue}{RGB}{20,60,140}
\definecolor{tableheadblue}{RGB}{30,80,162}

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
  keywordstyle=\color{codebrown}\bfseries,
  stringstyle=\color{codepurple},
  basicstyle=\ttfamily\footnotesize,
  breakatwhitespace=false,
  breaklines=true,
  captionpos=b,
  keepspaces=true,
  numbers=left,
  numberstyle=\tiny\color{gray},
  numbersep=5pt,
  showspaces=false,
  showstringspaces=false,
  showtabs=false,
  tabsize=2,
  frame=single,
  rulecolor=\color{codebrown!40},
}

\lstdefinestyle{json}{
  backgroundcolor=\color{codegray},
  basicstyle=\ttfamily\footnotesize,
  breaklines=true,
  frame=single,
  rulecolor=\color{gray!40},
}

% ── tcolorbox styles ──────────────────────────────────────────────────────────
\tcbset{
  aegisbox/.style={
    enhanced,colback=lightblue,colframe=aegisblue,
    fonttitle=\bfseries\color{white},
    attach boxed title to top left={yshift=-2mm,xshift=4mm},
    boxed title style={colback=aegisblue},
    breakable,
  },
  warnbox/.style={
    enhanced,colback=lightyellow,colframe=suspicious,
    fonttitle=\bfseries,
    breakable,
  },
  dangerbox/.style={
    enhanced,colback=lightred,colframe=malicious,
    fonttitle=\bfseries\color{white},
    attach boxed title to top left={yshift=-2mm,xshift=4mm},
    boxed title style={colback=malicious},
    breakable,
  },
  successbox/.style={
    enhanced,colback=lightgreen,colframe=clean,
    fonttitle=\bfseries\color{white},
    attach boxed title to top left={yshift=-2mm,xshift=4mm},
    boxed title style={colback=clean},
    breakable,
  },
}

% ── Page style ────────────────────────────────────────────────────────────────
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\textcolor{aegisblue}{\textbf{AegisAI}}}
\fancyhead[R]{\textcolor{titlegray}{\small\leftmark}}
\fancyfoot[C]{\textcolor{titlegray}{\thepage}}
\renewcommand{\headrulewidth}{0.4pt}
\renewcommand{\headrule}{\hbox to\headwidth{\color{aegisblue}\leaders\hrule height \headrulewidth\hfill}}

% ── Section formatting ────────────────────────────────────────────────────────
\titleformat{\chapter}[display]
  {\normalfont\huge\bfseries\color{sectionblue}}
  {\chaptertitlename\ \thechapter}{20pt}{\Huge}
\titleformat{\section}
  {\normalfont\Large\bfseries\color{sectionblue}}
  {\thesection}{1em}{}
\titleformat{\subsection}
  {\normalfont\large\bfseries\color{aegisblue}}
  {\thesubsection}{1em}{}
\titleformat{\subsubsection}
  {\normalfont\normalsize\bfseries\color{titlegray}}
  {\thesubsubsection}{1em}{}

% ── Hyperref setup ────────────────────────────────────────────────────────────
\hypersetup{
  colorlinks=true,
  linkcolor=aegisblue,
  citecolor=aegisblue,
  urlcolor=aegiscyan,
  pdftitle={AegisAI -- Technical Architecture Report},
  pdfauthor={Houssem Eddine Bouzamoucha, Abdelmajid Tabessi, Ahmed Ameur Lejmi},
}

% ── Utility commands ──────────────────────────────────────────────────────────
\newcommand{\mitre}[1]{\textcolor{malicious}{\textbf{[#1]}}}
\newcommand{\code}[1]{\texttt{\small#1}}
\newcommand{\file}[1]{\texttt{\small\textcolor{aegisblue}{#1}}}
\newcommand{\badge}[2]{\colorbox{#1}{\textcolor{white}{\footnotesize\textbf{#2}}}}

% ═════════════════════════════════════════════════════════════════════════════
\begin{document}

% ── Title Page ────────────────────────────────────────────────────────────────
\begin{titlepage}
\pagecolor{aegisdark}
\color{white}
\centering
\vspace*{2cm}

\begin{tikzpicture}[scale=1.2]
  % Outer shield
  \filldraw[fill=aegisblue!80, draw=aegiscyan, line width=2pt]
    (0,2.5) -- (2.2,1.5) -- (2.2,-1.2) -- (0,-2.8) -- (-2.2,-1.2) -- (-2.2,1.5) -- cycle;
  % Inner shield highlight
  \filldraw[fill=aegisblue!50, draw=aegiscyan!60, line width=1pt]
    (0,2.0) -- (1.7,1.2) -- (1.7,-0.9) -- (0,-2.2) -- (-1.7,-0.9) -- (-1.7,1.2) -- cycle;
  % AI symbol
  \node[text=white, font=\bfseries\LARGE] at (0,0.1) {AI};
  % Scan lines
  \draw[aegiscyan, opacity=0.5, line width=0.4pt] (-1.4,0.8) -- (1.4,0.8);
  \draw[aegiscyan, opacity=0.5, line width=0.4pt] (-1.4,0.3) -- (1.4,0.3);
  \draw[aegiscyan, opacity=0.5, line width=0.4pt] (-1.4,-0.2) -- (1.4,-0.2);
  \draw[aegiscyan, opacity=0.5, line width=0.4pt] (-1.4,-0.7) -- (1.4,-0.7);
\end{tikzpicture}

\vspace{1.2cm}
{\fontsize{52}{60}\selectfont\textbf{\textcolor{aegiscyan}{Aegis}\textcolor{white}{AI}}}

\vspace{0.4cm}
\textcolor{aegiscyan!80}{\rule{10cm}{0.6pt}}

\vspace{0.6cm}
{\Large\textbf{Comprehensive Technical Architecture Report}}

\vspace{0.3cm}
{\large\textcolor{aegiscyan!70}{Multi-Layer Windows Antivirus \& Intrusion Detection System}}

\vspace{1.5cm}
\begin{tcolorbox}[
  width=12cm,
  colback=aegisblue!30,
  colframe=aegiscyan,
  boxrule=0.8pt,
  arc=6pt,
]
\centering
\textcolor{aegiscyan}{\large\textbf{Project Authors}}\\[6pt]
\textcolor{white}{\large Houssem Eddine Bouzamoucha}\\[4pt]
\textcolor{white}{\large Abdelmajid Tabessi}\\[4pt]
\textcolor{white}{\large Ahmed Ameur Lejmi}
\end{tcolorbox}

\vfill

\begin{tcolorbox}[
  width=12cm,
  colback=aegisdark!60,
  colframe=aegiscyan!40,
  boxrule=0.5pt,
  arc=4pt,
]
\centering\small
\textcolor{aegiscyan!60}{Technology Stack} \\[4pt]
\textcolor{white!80}{Rust \textbullet\ Python \textbullet\ TypeScript \textbullet\ Tauri \textbullet\ React}\\
\textcolor{white!80}{YARA-X \textbullet\ LightGBM \textbullet\ XGBoost \textbullet\ Claude AI}\\[6pt]
\textcolor{aegiscyan!60}{Academic Year 2025--2026}
\end{tcolorbox}

\vspace{0.8cm}
\pagecolor{white}
\end{titlepage}

% ── Table of Contents ─────────────────────────────────────────────────────────
\tableofcontents
\newpage

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Introduction and Project Overview}
% ═════════════════════════════════════════════════════════════════════════════

\section{Motivation and Goals}

Modern endpoint threats have outgrown signature-only antivirus solutions. Polymorphic
malware, living-off-the-land (LOLBin) attacks, fileless exploits, and multi-stage APT
campaigns evade static detection by construction. A defender that only looks for known
bad patterns will always lag behind attackers who continuously mutate their tools.

\textbf{AegisAI} addresses this gap by combining four complementary detection modalities
into a single, correlated, scored threat picture:

\begin{itemize}[leftmargin=2cm]
  \item \textbf{Signature \& rule detection} --- YARA-X rules and SHA-256 hash databases
        catch known malware families instantly.
  \item \textbf{Heuristic analysis} --- 50+ rule-based checks over file content, process
        behaviour, network traffic, and memory layout catch unknown variants by behavioral
        pattern.
  \item \textbf{Machine learning} --- per-domain ML models (LightGBM, XGBoost, GRU) trained
        on public security datasets provide calibrated probability scores that catch statistical
        anomalies the rules miss.
  \item \textbf{Graph-based correlation} --- an entity graph engine correlates signals across
        all four domains, detects multi-entity attack chains mapped to MITRE ATT\&CK, and
        surfaces a ranked, explainable threat picture.
\end{itemize}

The system is designed as a \textbf{Windows endpoint agent} with a native desktop UI,
built for deployment in environments where an operator needs real-time visibility into
endpoint threat state without relying on a cloud backend.

\section{Repository Structure}

\begin{tcolorbox}[aegisbox, title=Repository Layout]
\begin{verbatim}
AegisAI/
├── Antivirus_Engine/          # Rust scanning engine + Python ML
│   ├── src/
│   │   ├── main.rs            # CLI entry-point + daemon loop
│   │   └── core/
│   │       ├── types.rs       # Shared Rust types
│   │       ├── utils.rs       # SHA-256, entropy, PE detection
│   │       ├── file_system/   # YARA, heuristics, scan_all, EMBER
│   │       ├── process/       # API sequence extraction, GRU
│   │       ├── network/       # pcap, UNSW-NB15 feature pipeline
│   │       ├── memory/        # VirtualQueryEx, shellcode heuristics
│   │       ├── entity/        # EntityManager + EntityCorrelator
│   │       ├── graph/         # ThreatGraph builder + analyzer
│   │       └── action/        # Post-verdict containment executor
│   └── models/                # Trained ML model files
├── UI/
│   ├── src/                   # React + TypeScript frontend
│   │   ├── App.tsx            # 8-view router
│   │   ├── store/index.ts     # Zustand state management
│   │   ├── types/index.ts     # TypeScript type contracts
│   │   ├── lib/entityUtils.ts # Client-side entity aggregation
│   │   └── components/        # Dashboard, Scanner, Graph, etc.
│   └── src-tauri/src/main.rs  # Tauri IPC bridge + daemon lifecycle
└── ai_agent/                  # Claude API reasoning layer
\end{verbatim}
\end{tcolorbox}

\section{Component Summary}

\begin{center}
\begin{tabularx}{\textwidth}{|l|l|X|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Component}} & \textcolor{white}{\textbf{Language}} & \textcolor{white}{\textbf{Role}} \\
\hline
Scanning engine & Rust & Four domain scanners, entity graph, action executor \\
\hline
ML models & Python & Domain-specific probability scoring (LightGBM, XGBoost, GRU) \\
\hline
Desktop UI & TypeScript / React & Visualization, user interaction, result display \\
\hline
IPC bridge & Rust (Tauri) & Connects UI to scanning daemon via JSON-RPC \\
\hline
AI agent & Rust + Claude API & Post-graph reasoning, ranked action recommendation \\
\hline
\end{tabularx}
\end{center}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{System Architecture}
% ═════════════════════════════════════════════════════════════════════════════

\section{High-Level Data Flow}

The end-to-end data flow through AegisAI proceeds in five major stages:

\begin{enumerate}
  \item \textbf{Trigger} --- the user initiates a scan via the React UI (file, directory,
        process list, network capture, or memory dump).
  \item \textbf{IPC dispatch} --- the Tauri desktop process receives the request and forwards
        it over a stdin/stdout JSON-RPC pipe to the scanning daemon.
  \item \textbf{Scanning} --- one or more of the four domain scanners run and produce
        \code{EntityNode} objects that are ingested into the \code{EntityManager}.
  \item \textbf{Correlation and graph build} --- on a ``correlate'' command, the
        \code{EntityCorrelator} groups entities into clusters, then \code{GraphBuilder}
        constructs a \code{ThreatGraph}, and \code{GraphAnalyzer} detects attack chains.
  \item \textbf{Presentation} --- the serialised result flows back through the IPC pipe,
        the Zustand store updates, and the React UI re-renders the threat picture.
\end{enumerate}

\begin{figure}[H]
\centering
\begin{tikzpicture}[
  node distance=0.7cm and 1.4cm,
  box/.style={rectangle, rounded corners=4pt, minimum width=3.2cm, minimum height=0.9cm,
              text centered, font=\small\bfseries, draw, thick},
  arrow/.style={-{Stealth[scale=1.2]}, thick, color=aegisblue},
  label/.style={font=\tiny\itshape, color=titlegray},
]

\node[box, fill=aegiscyan!20, draw=aegiscyan] (ui) {React UI\\(Scanner.tsx)};
\node[box, fill=aegisblue!15, draw=aegisblue, right=1.6cm of ui] (tauri) {Tauri Bridge\\(main.rs)};
\node[box, fill=aegisblue!25, draw=aegisblue, right=1.6cm of tauri] (daemon) {Rust Daemon\\(main.rs)};

\node[box, fill=orange!15, draw=orange!70, below=1.2cm of daemon] (scanners) {Domain Scanners\\File/Proc/Net/Mem};
\node[box, fill=purple!10, draw=purple!50, below=1.2cm of scanners] (entity) {EntityManager\\+ Correlator};
\node[box, fill=malicious!10, draw=malicious!50, below=1.2cm of entity] (graph) {ThreatGraph\\+ Analyzer};
\node[box, fill=aegiscyan!15, draw=aegiscyan, below=1.2cm of graph] (agent) {AI Agent\\(Claude API)};

\draw[arrow] (ui) -- node[above, label]{invoke()} (tauri);
\draw[arrow] (tauri) -- node[above, label]{JSON-RPC stdin} (daemon);
\draw[arrow] (daemon) -- node[right, label]{dispatch} (scanners);
\draw[arrow] (scanners) -- node[right, label]{EntityNode} (entity);
\draw[arrow] (entity) -- node[right, label]{AggregatedEntity} (graph);
\draw[arrow] (graph) -- node[right, label]{AttackChains} (agent);

\draw[arrow, color=clean!70, dashed] (agent.west) -- ++(-7.5,0) -- (ui.south)
  node[midway, above, label, color=clean!80]{JSON result $\rightarrow$ Zustand store $\rightarrow$ re-render};

\end{tikzpicture}
\caption{End-to-end data flow in AegisAI}
\end{figure}

\section{Daemon Architecture and JSON-RPC Protocol}

AegisAI's scanning engine runs as a \textbf{separate child process} (the ``daemon'') that
the Tauri desktop app spawns at startup. Communication is exclusively via newline-delimited
JSON over stdin/stdout pipes. This architecture provides three key benefits:

\begin{itemize}
  \item \textbf{Crash isolation} --- a panic in the Rust engine does not kill the UI.
  \item \textbf{Single initialisation} --- YARA rules compile once; the Python ML bridge
        loads models once; scanner objects are reused across all requests.
  \item \textbf{Process separation} --- the heavy scanning work runs in a separate OS
        process, keeping the UI responsive.
\end{itemize}

\subsection{Startup Handshake}

When the daemon starts, it compiles YARA rules, loads the hash database, starts the
persistent Python EMBER server, and then prints a single line to stdout:

\begin{lstlisting}[style=json]
{"status": "ready"}
\end{lstlisting}

The Tauri bridge waits for this line before accepting UI requests.

\subsection{Request / Response Format}

Every request is a single JSON line written to daemon stdin:

\begin{lstlisting}[style=json]
{ "id": "<uuid>", "cmd": "<command>", ...extra_args }
\end{lstlisting}

Every response is a single JSON line written to daemon stdout:

\begin{lstlisting}[style=json]
{ "id": "<uuid>", "success": true/false, ...result_fields }
\end{lstlisting}

\subsection{Full Command Reference}

\begin{longtable}{|p{3.5cm}|p{3.0cm}|p{7.5cm}|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Command}} & \textcolor{white}{\textbf{Extra Args}} & \textcolor{white}{\textbf{Description}} \\
\hline
\endhead
\code{ping} & --- & Returns \code{\{"status":"pong"\}}; health check \\
\hline
\code{scan-file} & \code{path} & Full 4-layer file scan (hash $\to$ YARA $\to$ heuristics $\to$ ML) \\
\hline
\code{scan-dir} & \code{path} & Recursive directory scan \\
\hline
\code{scan-processes} & --- & Enumerate and score all running processes \\
\hline
\code{scan-network} & \code{pid?} & Capture and analyse network connections \\
\hline
\code{scan-memory} & \code{pid?} & Enumerate and score memory regions via VirtualQueryEx \\
\hline
\code{correlate} & \code{include\_memory: bool} & Run all scanners, build entity graph, detect attack chains \\
\hline
\code{apply-ember-ml} & \code{paths: [String]} & Run EMBER2024 LightGBM models on a list of file paths \\
\hline
\code{kill-process} & \code{pid} & Terminate a process by PID \\
\hline
\code{quarantine-file} & \code{path} & Move file to AegisAI quarantine directory \\
\hline
\code{block-ip} & \code{remote\_ip, direction} & Add Windows Firewall deny rule \\
\hline
\code{remove-block-ip} & \code{rule\_name} & Remove a previously added firewall rule \\
\hline
\code{dump-memory} & \code{pid} & Write MiniDumpWithFullMemory to disk \\
\hline
\code{check-persistence} & \code{suspicious\_paths?} & Scan registry, scheduled tasks, startup folders \\
\hline
\code{isolate-network} & --- & Disable all connected network interfaces \\
\hline
\code{restore-network} & --- & Re-enable interfaces saved by \code{isolate-network} \\
\hline
\end{longtable}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{File System Scanner}
% ═════════════════════════════════════════════════════════════════════════════

\section{Overview: Four-Layer Detection Pipeline}

The file scanner applies four detection layers in sequence. Each layer adds to a cumulative
numeric score; the final verdict is derived from the total. The layers are ordered from
cheapest to most expensive, and each layer can short-circuit the scan if it produces a
conclusive result.

\begin{figure}[H]
\centering
\begin{tikzpicture}[
  layer/.style={rectangle, rounded corners=5pt, minimum width=9cm, minimum height=1.0cm,
                text centered, font=\bfseries\small, draw=aegisblue, thick},
  arrow/.style={-{Stealth}, thick, color=aegisblue},
]
\node[layer, fill=malicious!20] (l1) at (0,0) {Layer 3.1 --- Hash Signature Lookup (O(1))};
\node[layer, fill=suspicious!20] (l2) at (0,-1.5) {Layer 3.2 --- YARA-X Rules (score += 1--10 per rule)};
\node[layer, fill=aegisblue!15] (l3) at (0,-3.0) {Layer 3.3 --- Heuristic Analysis (50+ checks)};
\node[layer, fill=aegiscyan!20] (l4) at (0,-4.5) {Layer 3.4 --- EMBER2024 ML (gated: Suspicious/Malicious only)};

\draw[arrow] (l1) -- (l2) node[midway,right,font=\tiny\itshape,color=titlegray]{hash miss};
\draw[arrow] (l2) -- (l3) node[midway,right,font=\tiny\itshape,color=titlegray]{continue};
\draw[arrow] (l3) -- (l4) node[midway,right,font=\tiny\itshape,color=titlegray]{score $\geq 4$};

\node[right=1cm of l1, font=\small, color=malicious] {\textbf{known hash} $\Rightarrow$ Malicious};
\node[right=1cm of l4, font=\small, color=aegiscyan] {score $\geq 0.8$ $\Rightarrow$ escalate};
\end{tikzpicture}
\caption{File scanner detection layers}
\end{figure}

\section{Layer 3.1 --- Hash Signature Database}

The first check is a SHA-256 (or multi-hash: MD5 + SHA-512) lookup against a known-malware
hash database stored as an in-memory \code{HashSet}. Lookup is $O(1)$.

\begin{itemize}
  \item \textbf{Hit} --- returns \code{ThreatLevel::Malicious} with \code{confidence = 1.0}
        immediately. No further layers run.
  \item \textbf{Miss} --- proceeds to YARA.
\end{itemize}

This layer catches EICAR test files, known ransomware samples, and any binary that has been
previously catalogued by a threat intelligence feed.

\section{Layer 3.2 --- YARA-X Rules}

YARA rules are compiled once at daemon startup using the \textbf{YARA-X} engine (WebAssembly
JIT via \texttt{wasmtime}). Per-request rule compilation would add several seconds of latency;
daemon mode eliminates this entirely.

\subsection{YARA Execution Gates}

YARA only runs on:
\begin{itemize}
  \item Files with executable or script extensions:
        \code{.exe}, \code{.dll}, \code{.sys}, \code{.ps1}, \code{.bat}, \code{.py}, etc.
  \item Files $\leq$ 10~MiB in size.
\end{itemize}

Generic rules (e.g., \code{contains\_base64}) fire on enormous amounts of legitimate content
when applied to all file types. Restricting by extension reduces false positives significantly.

\subsection{Rule Scoring}

\begin{center}
\begin{tabular}{|l|c|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Rule Strength}} & \textcolor{white}{\textbf{Score Added}} \\
\hline
Strong (named malware family, e.g.\ \code{WannaCry\_Ransomware\_Generic}) & $+10$ \\
\hline
Weak (generic pattern, e.g.\ \code{contains\_base64}, \code{powershell}) & $+1$ \\
\hline
\end{tabular}
\end{center}

\section{Layer 3.3 --- Heuristic Analysis Engine}

The heuristic engine (\file{heuristics.rs}) reads the file \textbf{once} into a
\code{Vec<u8>} buffer (up to 10~MiB). All checks --- magic-byte detection, entropy
calculation, content analysis, and SHA-256 hashing --- operate on this shared buffer.
This design eliminates the 3--4 redundant file-open operations that a naive implementation
would perform.

For files $>$ 10~MiB, only filename, extension, and modification timestamp checks run;
SHA-256 is computed by streaming separately.

\subsection{Single-Read Optimisation}

\begin{tcolorbox}[warnbox, title=Design Decision: Single Read]
Files are opened exactly once per scan call. The buffer is passed by reference through all
heuristic subsystems. Magic-byte detection, Shannon entropy, content scanning (keyword
search), and SHA-256 all read from \code{\&[u8]} slices of the same allocation. This
halves I/O operations on SSDs and eliminates seek overhead on spinning disks.
\end{tcolorbox}

\subsection{Heuristic Scoring Table}

\begin{longtable}{|p{7cm}|p{3cm}|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Heuristic Check}} & \textcolor{white}{\textbf{Score Added}} \\
\hline
\endhead
Very high entropy $> 7.5$ (packed / encrypted binary) & $+4$ \\
\hline
High entropy $> 7.2$ (executable section only) & $+2$ \\
\hline
Suspicious keyword in content (each, capped at $+12$) & $+3$ \\
\hline
PowerShell obfuscation patterns detected & $+4$ \\
\hline
Ransomware content phrase (each, capped at $+20$) & $+5$ \\
\hline
Cryptocurrency wallet address detected & $+5$ \\
\hline
Ransomware filename match & $+7$ \\
\hline
Ransomware extension match & $+8$ \\
\hline
File type mismatch (e.g., PE header inside \code{.txt}) & $+3$ \\
\hline
Double-extension trick (\code{.pdf.exe}) & $+4$ \\
\hline
Zero-byte executable dropper & $+8$ \\
\hline
Tiny executable (under 1~KiB) suspicious dropper & $+6$ \\
\hline
\end{longtable}

\begin{tcolorbox}[successbox, title=False-Positive Suppression]
Files located under \code{System32}, \code{SysWOW64}, or \code{WinSxS} have their
heuristic score capped below the Malicious threshold. This prevents legitimate Windows
binaries (which legitimately have high entropy or unusual attributes) from being
flagged as threats.
\end{tcolorbox}

\subsection{Extension Lookup Optimisation}

Extension tables (\code{DOCUMENT\_EXTENSIONS}, \code{EXECUTABLE\_EXTENSIONS},
\code{SCRIPT\_EXTENSIONS}) are \textbf{sorted ASCII arrays}. All lookups use
\code{binary\_search}, giving $O(\log n)$ performance versus $O(n)$ for an unsorted
linear scan. A compile-time test \code{test\_extension\_arrays\_sorted} asserts the
sort order is maintained across all future code changes.

\subsection{Script Coverage}

Extensions \code{.py}, \code{.sh}, \code{.rb}, \code{.pl}, \code{.php}, and \code{.lua}
are included in ransomware-phrase checks and suspicious-keyword analysis. Previously
these were inadvertently excluded by an \code{is\_doc || is\_exec} gate; the fix ensures
scripts cannot hide ransomware functionality behind non-executable file categories.

\subsection{Binary-Safe Content Scanning}

Content scanning uses \code{from\_utf8\_lossy} on the shared byte buffer rather than
\code{read\_to\_string}. This means binary executables containing embedded UTF-8-hostile
sequences are scanned correctly instead of silently returning empty content.

\section{Layer 3.4 --- EMBER2024 ML Pipeline}

\subsection{Architecture Overview}

When heuristics or YARA have already flagged a file as Suspicious or Malicious, the EMBER
ML layer provides a second opinion from a model trained on the EMBER 2024 dataset
(1~million labelled PE files and PDFs).

The ML bridge is a \textbf{persistent Python process} (\code{bridge.py --server}) started
eagerly at daemon initialisation. All five LightGBM models load once; subsequent calls pay
only inference cost ($\approx$0.1--0.3\,s per file).

\begin{figure}[H]
\centering
\begin{tikzpicture}[
  box/.style={rectangle, rounded corners=4pt, minimum width=3.5cm, minimum height=0.8cm,
              text centered, font=\small, draw, thick},
  arrow/.style={-{Stealth}, thick, color=aegisblue},
]
\node[box, fill=aegiscyan!20, draw=aegiscyan] (ui) {User: Apply ML};
\node[box, fill=aegisblue!15, draw=aegisblue, right=1.5cm of ui] (store) {Zustand Store};
\node[box, fill=aegisblue!25, draw=aegisblue, right=1.5cm of store] (tauri) {Tauri IPC\\300\,s timeout};
\node[box, fill=orange!15, draw=orange!70, below=1.0cm of tauri] (daemon) {Daemon Handler};
\node[box, fill=purple!10, draw=purple!60, below=1.0cm of daemon] (server) {EmberServer\\(Rust handle)};
\node[box, fill=green!10, draw=green!50, below=1.0cm of server] (bridge) {bridge.py\\--server mode};
\node[box, fill=malicious!10, draw=malicious!40, below=1.0cm of bridge] (model) {LightGBM Model\\(Win32/Win64/DotNet/PDF/All)};

\draw[arrow] (ui) -- (store);
\draw[arrow] (store) -- (tauri);
\draw[arrow] (tauri) -- (daemon);
\draw[arrow] (daemon) -- node[right, font=\tiny\itshape]{path via stdin} (server);
\draw[arrow] (server) -- node[right, font=\tiny\itshape]{one-line protocol} (bridge);
\draw[arrow] (bridge) -- node[right, font=\tiny\itshape]{thrember features} (model);
\draw[arrow, dashed, color=clean!60] (model.east) -- ++(2,0) -- ++(0,5.5) -- (tauri.east)
  node[midway, right, font=\tiny\itshape, color=clean!80]{JSON score $\rightarrow$ UI badges};
\end{tikzpicture}
\caption{EMBER2024 ML inference pipeline}
\end{figure}

\subsection{File-Type Routing}

The ML bridge inspects magic bytes (not the file extension) to route each file to the
correct specialised model:

\begin{center}
\begin{tabularx}{\textwidth}{|l|X|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Magic Bytes / Condition}} & \textcolor{white}{\textbf{Model Selected}} \\
\hline
\code{MZ} + CLR directory present & \code{EMBER2024\_Dot\_Net.model} \\
\hline
\code{MZ} + 64-bit COFF machine code & \code{EMBER2024\_Win64.model} \\
\hline
\code{MZ} (default PE) & \code{EMBER2024\_Win32.model} \\
\hline
\code{\%PDF} & \code{EMBER2024\_PDF.model} \\
\hline
No recognised magic bytes & \code{EMBER2024\_all.model} (catch-all) \\
\hline
Empty file (0 bytes) & Short-circuited --- score 0.0, clean \\
\hline
File deleted / locked & Skipped --- \code{skip\_reason: file\_unavailable} \\
\hline
\end{tabularx}
\end{center}

Magic bytes always take priority over extension. A \code{.tmp} file that starts with
\code{MZ} (a common malware staging technique) is correctly routed to a PE model rather
than skipped.

\subsection{Score Interpretation}

\begin{center}
\begin{tabular}{|c|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Score Range}} & \textcolor{white}{\textbf{Meaning}} & \textcolor{white}{\textbf{UI Badge}} \\
\hline
$\geq 0.80$ & Malicious & \badge{malicious}{Malicious} \\
\hline
$0.50$--$0.79$ & Suspicious & \badge{suspicious}{Suspicious} \\
\hline
$< 0.50$ & Clean & \badge{clean}{Clean} \\
\hline
\end{tabular}
\end{center}

\subsection{Engineering Challenges and Fixes}

Five non-trivial engineering problems were encountered and resolved during EMBER integration:

\begin{enumerate}
  \item \textbf{Context-escalated files returning ``unsupported''} --- Files escalated by
        directory context (not raw score) were re-scanned and dropped back to Clean before
        reaching the ML gate. Fix: a dedicated \code{apply-ember-ml} daemon command bypasses
        the YARA/heuristics pipeline and calls the bridge directly.

  \item \textbf{Very slow inference ($N$ Python spawns)} --- Each file spawned a fresh Python
        process, paying 5--10\,s model load cost each time. Fix: persistent \code{--server}
        mode; models load once at daemon start.

  \item \textbf{Bootstrap \code{capture\_output=True} deadlock} --- The venv bootstrap
        re-launched \code{bridge.py} with \code{capture\_output=True}, which blocked forever
        in \code{--server} mode because the inner process never exits. Fix: detect
        \code{--server} in \code{sys.argv} and use plain \code{subprocess.run()} without
        capture.

  \item \textbf{Pipe buffer deadlock during model load} --- Writing all paths before reading
        any responses filled the OS pipe buffer ($\approx$64~KiB) while models were still
        loading, causing a write--write deadlock. Fix: strict sequential protocol
        (write one $\to$ wait for one response $\to$ repeat).

  \item \textbf{Model load counted against Tauri timeout} --- Lazy server start consumed
        5--15\,s of the command window. Fix: eager start at daemon init; Tauri timeout raised
        to 300\,s.
\end{enumerate}

\subsection{Timing Budget (After All Fixes)}

\begin{center}
\begin{tabular}{|l|c|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Phase}} & \textcolor{white}{\textbf{Time}} \\
\hline
Python startup + 5-model LightGBM load & 5--15\,s (background, during daemon idle) \\
\hline
First-file warmup timeout (safety net) & 120\,s \\
\hline
Per-file inference (Win32 / Win64 / DotNet) & $\approx$0.1--0.3\,s \\
\hline
Per-file inference (PDF / All) & $\approx$0.05--0.15\,s \\
\hline
Tauri command timeout & 300\,s \\
\hline
\end{tabular}
\end{center}

\section{Verdict Calculation}

\begin{align}
\text{total\_score} &\geq 10 \Rightarrow \textbf{Malicious} \notag \\
\text{total\_score} &\geq 4 \Rightarrow \textbf{Suspicious} \notag \\
\text{total\_score} &< 4 \Rightarrow \textbf{Clean} \notag
\end{align}

\begin{align}
\text{confidence}_{\text{Suspicious}} &= 0.55 + \min\!\left(\frac{\text{score}}{40}, 0.25\right) + \text{ember\_blend} \notag \\
\text{confidence}_{\text{Malicious}} &= 0.70 + \min\!\left(\frac{\text{score}}{60}, 0.25\right) + \text{ember\_blend} \notag
\end{align}

\section{System-Wide Scanner (\texttt{scan\_all})}

The \code{SystemScanner} and \code{ScanScheduler} (\file{scan\_all.rs}) provide a
background system-wide file scan capability.

\subsection{ScanPrioritizer}

Files are scored on a 100-point risk scale before scanning to prioritise high-risk
locations:

\begin{center}
\begin{tabular}{|l|c|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Risk Axis}} & \textcolor{white}{\textbf{Points}} \\
\hline
High-risk directory (\code{\%TEMP\%}, \code{\%APPDATA\%}, \code{Downloads}) & up to 40 \\
\hline
Executable / script extension & up to 30 \\
\hline
Recently modified (last 24\,h) & up to 20 \\
\hline
File size anomalies & up to 10 \\
\hline
\end{tabular}
\end{center}

\subsection{Incremental Scanning with FileStateCache}

The \code{FileStateCache} records the last-seen \code{mtime + size} of every scanned file.
On subsequent runs, unchanged files are skipped entirely. This allows a full-system rescan
to complete in seconds on a system where most files have not changed since the last pass.

\subsection{Thread Pool}

The \code{SystemScanner} uses a Rayon-style thread pool. Each worker thread holds its own
\code{Arc<Mutex<FileSystemScanner>>} instance (YARA context is not \code{Send}).
Files are distributed via a \code{Mutex<Receiver<PathBuf>>} channel. High-priority files
are placed at the head of the queue so they are processed first regardless of directory
traversal order.

\subsection{Smart Skip Rules}

The following directories are always skipped to avoid false positives and wasted I/O:

\begin{itemize}
  \item \code{C:\textbackslash Windows\textbackslash WinSxS} (component store, very large)
  \item \code{C:\textbackslash Windows\textbackslash Installer}
  \item \code{C:\textbackslash Windows\textbackslash SoftwareDistribution}
  \item \code{\$Recycle.Bin}, \code{System Volume Information}
\end{itemize}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Process Scanner}
% ═════════════════════════════════════════════════════════════════════════════

\section{Process Enumeration}

The process scanner uses the \texttt{sysinfo} crate and Windows API calls to enumerate all
running processes. For each process, it extracts:

\begin{itemize}
  \item PID, parent PID (PPID), process name, full executable path
  \item CPU usage percentage, memory consumption (bytes)
  \item Command-line arguments
  \item Thread count, start time
\end{itemize}

\section{Heuristic Scoring Rules}

The process heuristic engine applies a rule set covering known-malicious process ancestry
patterns, path anomalies, and resource consumption:

\begin{center}
\begin{tabular}{|p{8cm}|c|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Heuristic}} & \textcolor{white}{\textbf{Score}} \\
\hline
Process name matches system binary but runs outside \code{System32} & $+10$ \\
\hline
Executable in \code{\%TEMP\%} or \code{\%APPDATA\%} & $+8$ \\
\hline
Parent is a LOLBin (\code{mshta.exe}, \code{regsvr32.exe}, etc.) & $+7$ \\
\hline
Process name has high Shannon entropy (random-name dropper) & $+5$ \\
\hline
Known LOLBin with suspicious command-line arguments & $+6$ \\
\hline
Spawn depth $> 5$ in process tree & $+4$ \\
\hline
Abnormally high CPU usage ($> 90$th percentile) & $+3$ \\
\hline
Thread count anomaly (0 threads --- hollow process indicator) & $+8$ \\
\hline
\end{tabular}
\end{center}

\section{LOLBin Detection}

Living-off-the-land binaries (LOLBins) are legitimate Windows executables that attackers
abuse to execute malicious payloads without dropping a new binary. AegisAI maintains a
static list of approximately 35 common LOLBins sourced from the LOLBAS project, including:

\begin{multicols}{3}
\begin{itemize}[noitemsep]
  \item \code{mshta.exe}
  \item \code{regsvr32.exe}
  \item \code{certutil.exe}
  \item \code{wscript.exe}
  \item \code{cscript.exe}
  \item \code{rundll32.exe}
  \item \code{msiexec.exe}
  \item \code{wmic.exe}
  \item \code{powershell.exe}
  \item \code{cmd.exe}
  \item \code{bitsadmin.exe}
  \item \code{schtasks.exe}
\end{itemize}
\end{multicols}

When the graph feedback mechanism marks a clean parent process as a lateral-movement
vector (\code{is\_vector = true}), it additionally checks the node label against this list.
A match sets \code{is\_lolbin = true} on the \code{GraphNode}, which can be surfaced as a
visual badge in the UI.

\section{Windows API Call Sequence Extraction}

For processes flagged as Suspicious or Malicious, the process scanner can extract the
sequence of Windows API calls made by the process via \file{API\_feature\_extractor.rs}.
This sequence is then scored by the GRU ML model.

\subsection{GRU ML Model}

\begin{itemize}
  \item \textbf{Architecture}: Gated Recurrent Unit (GRU) neural network
  \item \textbf{Input}: API call sequences (minimum 5, maximum 177 calls, stride 100)
  \item \textbf{Vocabulary}: defined in \code{config.json} (\code{MAX\_LEN = 177})
  \item \textbf{Output}: malicious probability $\in [0.0, 1.0]$
  \item \textbf{Training data}: DAPT 2020 dataset (APT-style process execution chains)
  \item \textbf{Location}: \file{Antivirus\_Engine/src/core/process/Sys\_API/}
\end{itemize}

The GRU captures temporal patterns in API call sequences that are characteristic of specific
attack families (injection sequences, credential dumping patterns, persistence installation
patterns).

\section{Performance Optimisations}

\begin{tcolorbox}[aegisbox, title=WARM\_SYSTEM Singleton]
The \code{WARM\_SYSTEM} global (\code{OnceLock<Mutex<SystemInfo>>}) ensures the OS process
list is populated exactly once per scan call rather than waiting 200\,ms for system
warm-up on every invocation. This is critical when the process scanner runs as part of a
larger ``correlate'' pipeline.
\end{tcolorbox}

\begin{tcolorbox}[successbox, title=memory\_scan\_lock]
An \code{AtomicBool} CAS guard rejects concurrent memory scans before they stack up. Memory
scanning can take 30--120\,s; allowing two concurrent scans would double memory pressure and
produce confusing duplicate results.
\end{tcolorbox}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Network Scanner and IDS}
% ═════════════════════════════════════════════════════════════════════════════

\section{Packet Capture and Feature Extraction}

The network scanner captures live traffic using a Windows packet capture library and
extracts 47 UNSW-NB15 format features per connection. The raw pcap data is written to
\code{OnePace.csv} for ML processing.

\section{Network Heuristics}

The heuristic engine analyses each connection for:

\begin{itemize}
  \item Known C2 ports (4444, 1337, 8080, 8443, and other common Metasploit / Cobalt
        Strike defaults)
  \item DNS-over-HTTPS usage with non-CDN resolvers (potential DNS tunnelling)
  \item Beaconing patterns --- regular inter-packet timing with small packet sizes
  \item Outbound connections from unusual processes (browser spawning shells,
        \code{lsass.exe} making outbound connections)
  \item Port scanning patterns --- many SYN packets to sequential ports
\end{itemize}

\section{XGBoost Network IDS}

The trained XGBoost model operates on the UNSW-NB15 feature set. The inference pipeline
is invoked by \code{run\_ml\_and\_patch\_scores()}, which:

\begin{enumerate}
  \item Calls \code{preprocessing\_pipeline.py --infer --csv \$PATH}
  \item Waits for the Python process to complete
  \item Reads the output JSON containing per-entity ML scores
  \item Calls \code{EntityManager::update\_ml\_score(entity\_id, ml\_score)} for each result
\end{enumerate}

\subsection{Feature Vector (UNSW-NB15, 43 Features)}

After preprocessing, the network feature vector contains:

\begin{itemize}
  \item \textbf{Port/protocol}: \code{is\_known\_c2\_port}, \code{dst\_port\_norm},
        one-hot protocol (\code{tcp/udp/icmp}), connection state
  \item \textbf{Volume}: log-scaled bytes/packets sent and received, mean packet sizes,
        load metrics
  \item \textbf{Timing}: log-scaled duration, inter-packet intervals, jitter,
        beaconing regularity score
  \item \textbf{TCP internals}: window sizes, RTT, SYN-ACK timing
  \item \textbf{IP metadata}: private/global address flags, source/destination
        frequency counters
  \item \textbf{Connection frequency}: per-service, per-destination, time-window
        connection counts
\end{itemize}

Fields discarded from UNSW-NB15 include raw IP addresses (machine-specific), absolute
timestamps (meaningless across deployments), and protocol-specific fields with near-zero
variance in modern environments.

\subsection{Training Protocol Summary}

\begin{itemize}
  \item \textbf{Class imbalance}: handled via \code{scale\_pos\_weight = neg/pos}
  \item \textbf{Metric}: \code{aucpr} (AUC-PR, honest for imbalanced data)
  \item \textbf{Calibration}: \code{CalibratedClassifierCV} with isotonic regression,
        \code{cv="prefit"} to prevent information leakage
  \item \textbf{Threshold}: tuned for recall $\geq 0.95$ at model level; false positives
        are suppressed by the graph layer
\end{itemize}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Memory Scanner}
% ═════════════════════════════════════════════════════════════════════════════

\section{Region Enumeration}

The memory scanner calls \code{VirtualQueryEx} for each running process to enumerate all
memory regions. For each region it records:

\begin{itemize}
  \item Base address, region size, protection flags (\code{PAGE\_EXECUTE\_READWRITE}, etc.)
  \item Allocation type (private anonymous, mapped file, image)
  \item A 512-byte content sample from the start of the region
\end{itemize}

\section{Three-Tier Trust Model}

To suppress false positives, the memory scanner implements a three-tier process trust model:

\begin{center}
\begin{tabular}{|l|l|p{6cm}|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Tier}} & \textcolor{white}{\textbf{Examples}} & \textcolor{white}{\textbf{Treatment}} \\
\hline
\textbf{SystemOs} & \code{lsass.exe}, \code{csrss.exe}, \code{winlogon.exe} & RWX regions tolerated; only flag extreme patterns \\
\hline
\textbf{JitRuntime} & \code{node.exe}, \code{java.exe}, \code{chrome.exe}, $\approx$90 entries & JIT-generated RWX regions expected; raised shellcode thresholds \\
\hline
\textbf{TrustedInstall} / \textbf{Unknown} & All others & Standard shellcode detection rules applied \\
\hline
\end{tabular}
\end{center}

\section{Shellcode Detection Heuristics}

\begin{itemize}
  \item \textbf{RWX regions} --- \code{PAGE\_EXECUTE\_READWRITE} in non-JIT processes is the
        primary shellcode indicator
  \item \textbf{NOP/INT3 thresholds} --- sequences of \code{0x90} (NOP) or \code{0xCC}
        (INT3) above tuned thresholds indicate shellcode sleds or breakpoints
  \item \textbf{PE header in non-image region} --- \code{MZ} magic in a private anonymous
        region indicates a reflectively-loaded PE (process hollowing, process injection)
  \item \textbf{Shellcode sequence patterns} --- known shellcode prologues and API hash
        resolution sequences
  \item \textbf{Suspicious region ratio} --- if more than $N\%$ of a process's regions
        are flagged, all regions receive a combined-score boost
\end{itemize}

\section{ML Integration}

The memory ML model (\file{Antivirus\_Engine/src/core/memory/ML\_models/Deep\_dive/})
is trained on CIC-MalMem-2022 data. The feature vector includes:

\begin{itemize}
  \item Permission flags: \code{is\_executable}, \code{is\_writable}, \code{is\_rwx},
        \code{is\_copy\_on\_write}
  \item Allocation type one-hot: \code{alloc\_private}, \code{alloc\_mapped},
        \code{alloc\_image}
  \item Region size (log-scaled), shellcode size range indicator
  \item Alignment, PE header presence in region
  \item Process-level context: owning process threat status, network activity
  \item Session-level aggregates: RWX region count, suspicious region ratio per PID
\end{itemize}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{ML Architecture Deep Dive}
% ═════════════════════════════════════════════════════════════════════════════

\section{Design Philosophy: Four Specialists, One Attending}

AegisAI's ML architecture deliberately avoids a unified model that tries to reason across
all four domains simultaneously. Instead, it follows a ``specialist convergence'' pattern:

\begin{tcolorbox}[aegisbox, title=Core Principle]
Each ML model is a specialist trained on a single domain dataset. All four models share
only their output interface: a calibrated probability score $\in [0.0, 1.0]$ attached to
an \code{EntityNode}. The entity layer is the attending physician that combines these
four independent opinions into a unified threat level.
\end{tcolorbox}

The analogy is exact: a radiologist, cardiologist, neurologist, and pathologist each read
different instruments and produce probability reports. The attending physician combines
four numbers from four specialists without needing to understand radiology or pathology.
The entity layer is the attending; the four ML models are the specialists; the graph engine
is the clinical reasoning that catches patterns no single specialist would see.

\section{Dual-Signal Combined Score}

For every entity, the combined score formula is:

\begin{equation}
\text{combined\_score} = H \times 0.4 + \text{ML} \times 0.6
\end{equation}

where $H$ is the heuristic score normalised to $[0, 1]$ and ML is the calibrated model
output. ML receives 60\% weight because it has access to richer statistical context. The
heuristic component ensures that even if the ML model degrades due to distribution shift,
the rule-based signal still contributes 40\% of the final verdict.

\section{Why Not One Model Per Heuristic?}

The naive approach of pairing every heuristic with a dedicated classifier fails at scale:

\begin{center}
\begin{tabular}{|l|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Issue}} & \textcolor{white}{\textbf{Per-Heuristic Model}} & \textcolor{white}{\textbf{Per-Domain Model}} \\
\hline
Model count & $N$ (grows with feature set) & 4 (fixed) \\
\hline
Calibration & Each on different data slice & Each on full domain dataset \\
\hline
New heuristic & Must train a new model & Adds fields to feature vector \\
\hline
Score semantics & Inconsistent across models & Uniform: $P(\text{malicious})$ \\
\hline
Training effort & $N \times$ training sprint & 1 sprint per domain \\
\hline
\end{tabular}
\end{center}

\section{Calibration: Making Scores Comparable}

Without calibration, a score of 0.85 from the network model and 0.85 from the file model
carry no common meaning. After \code{CalibratedClassifierCV} with isotonic regression,
both scores represent a true probability: ``of events assigned a score near 0.85, approximately
85\% were actually malicious.'' Only calibrated scores can be meaningfully blended via
\code{combined\_score}.

\section{Training Datasets}

\begin{center}
\begin{tabular}{|l|l|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Domain}} & \textcolor{white}{\textbf{Primary Dataset}} & \textcolor{white}{\textbf{Algorithm}} & \textcolor{white}{\textbf{Features}} \\
\hline
Network & UNSW-NB15 (2.54M rows) & XGBoost + Calibration & 43 \\
\hline
File & EMBER 2024 (1M samples) & LightGBM (pre-trained) & $\approx$2000 \\
\hline
Process & DAPT 2020 (APT chains) & XGBoost + Calibration & $\sim$30 \\
\hline
Memory & CIC-MalMem-2022 & XGBoost + Calibration & $\sim$20 \\
\hline
\end{tabular}
\end{center}

\section{Distribution Shift Mitigation}

All public security datasets are frozen snapshots of a specific lab environment at a specific
point in time. AegisAI contains five layers of protection against distribution shift:

\begin{enumerate}
  \item \textbf{Heuristics as safety net} (40\% weight) --- rules do not depend on training
        data and fire correctly regardless of the year.
  \item \textbf{Graph structural reasoning} --- attack chain topology does not shift as fast
        as raw feature distributions.
  \item \textbf{Domain isolation} --- shift in one domain does not affect the other three.
  \item \textbf{False positive rate monitoring} --- rising FP rate is an early warning that
        deployment distribution has diverged from training.
  \item \textbf{\code{CLEAN\_PREFIXES} filtering} --- known-good CDN and resolver infrastructure
        is excluded from training to prevent the model learning those IPs as benign signals.
\end{enumerate}

\section{Heuristic Score as a Training-Compatible Feature}

The \code{heuristic\_score\_norm} field is always set to \code{0.0} in training data (the
heuristic engine does not run during offline preprocessing). The model therefore learns to
treat it as ``no information when zero.'' At inference time, when it carries a real value
(e.g., 0.45), it becomes an additional positive signal on top of the raw features.
\textbf{No retraining is required} to incorporate new heuristic signals --- the existing
model is already compatible by design.

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Entity Correlation Engine}
% ═════════════════════════════════════════════════════════════════════════════

\section{Three-Tier Architecture}

The entity correlation engine sits between the raw scanners and the threat graph. It
normalises heterogeneous scanner output into a common schema and groups related entities
into clusters.

\begin{figure}[H]
\centering
\begin{tikzpicture}[
  tier/.style={rectangle, rounded corners=6pt, minimum width=11cm, minimum height=1.1cm,
               text centered, font=\bfseries\small, draw=aegisblue, thick, fill=lightblue},
  arrow/.style={-{Stealth}, thick, color=aegisblue},
  label/.style={font=\tiny\itshape, color=titlegray},
]
\node[tier, fill=orange!15, draw=orange!60] (scanners) at (0,0)
  {Raw Scanners: ProcessScanner / FileScanner / NetworkScanner / MemoryScanner};
\node[tier, fill=aegisblue!15] (em) at (0,-1.8)
  {Tier 1 --- EntityManager (normalisation, dual-score, sliding window)};
\node[tier, fill=purple!10, draw=purple!50] (ec) at (0,-3.0)
  {Tier 1b --- EntityCorrelator (4 cluster strategies)};
\node[tier, fill=malicious!10, draw=malicious!40] (gb) at (0,-4.2)
  {Tier 2 --- GraphBuilder (O(n) via join-key indexes)};
\node[tier, fill=aegiscyan!15, draw=aegiscyan] (ga) at (0,-5.4)
  {Tier 2b --- GraphAnalyzer (6 MITRE-mapped attack patterns)};

\draw[arrow] (scanners) -- (em);
\draw[arrow] (em) -- (ec);
\draw[arrow] (ec) -- (gb);
\draw[arrow] (gb) -- (ga);
\end{tikzpicture}
\caption{Entity correlation three-tier architecture}
\end{figure}

\section{EntityNode --- The Normalisation Contract}

Every scanner maps its output to a single \code{EntityNode} before anything else. This is
the schema that makes the entire downstream pipeline scanner-agnostic:

\begin{center}
\begin{tabular}{|l|l|p{7cm}|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Field}} & \textcolor{white}{\textbf{Type}} & \textcolor{white}{\textbf{Description}} \\
\hline
\code{entity\_id} & \code{String} & Stable key: \code{proc:PID:name}, \code{file:SHA256}, \code{net:proto:local:remote}, \code{mem:PID:ADDR} \\
\hline
\code{entity\_type} & enum & \code{Process | File | NetworkConnection | MemoryRegion} \\
\hline
\code{heuristic\_score} & \code{i32} & Raw score from the scanner rule engine \\
\hline
\code{ml\_score} & \code{Option<f32>} & Calibrated probability from domain ML model \\
\hline
\code{combined\_score()} & \code{f32} & $H \times 0.4 + \text{ML} \times 0.6$ (or $H/40$ if no ML) \\
\hline
\code{threat\_level} & enum & \code{Clean | Suspicious | Malicious | Critical} \\
\hline
\code{join\_keys} & \code{JoinKeys} & Structural correlation handles: \code{pid}, \code{parent\_pid}, \code{file\_hash}, \code{remote\_ip} \\
\hline
\code{attributes} & \code{EntityAttributes} & Type-specific scanner output preserved \\
\hline
\end{tabular}
\end{center}

\subsection{Entity ID Formats}

\textbf{Flat \code{EntityNode} IDs} (used by EntityManager and EntityManager UI view):
\begin{itemize}[noitemsep]
  \item Process: \code{proc:\{pid\}:\{name\}}
  \item Network: \code{net:\{proto\}:\{local\_address\}:\{remote\_address\}}
  \item Memory: \code{mem:\{pid\}:\{region\_start\_hex\}}
  \item File: \code{file:\{sha256\}} or \code{file:\{path\}}
\end{itemize}

\textbf{\code{AggregatedEntity} IDs} (used by ThreatGraph):
\begin{itemize}[noitemsep]
  \item Process-anchored: \code{entity:\{pid\}}
  \item Orphan network: \code{entity-net:\{net\_entity\_id\}}
  \item Standalone file: \code{entity-file:\{file\_entity\_id\}}
\end{itemize}

\section{EntityManager --- Sliding Window and Concurrent Ingestion}

\code{EntityManager} wraps a \code{DashMap<String, EntityNode>} with a \code{window\_secs}
bound (default: 600\,s = 10\,min).

\begin{itemize}
  \item \textbf{DashMap} is used over \code{RwLock<HashMap>} because it shards the map into
        independent buckets, allowing concurrent reads and writes from multiple scanner threads
        without a global lock.
  \item \textbf{\code{prune\_expired()}} removes nodes older than the window, bounding memory
        growth during continuous monitoring.
  \item \textbf{\code{update\_ml\_score()}} patches in ML results asynchronously after heuristic
        ingestion. Threat level is only ever \emph{escalated} by this patch, never downgraded.
\end{itemize}

\section{EntityCorrelator --- Four Cluster Strategies}

\code{EntityCorrelator} is a read-only view over \code{EntityManager}. It groups entities
into \code{CorrelatedCluster} objects using four structural strategies:

\begin{center}
\begin{tabular}{|l|l|p{6cm}|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Strategy}} & \textcolor{white}{\textbf{Join Key}} & \textcolor{white}{\textbf{Detects}} \\
\hline
\code{SharedPid} & \code{pid} & Entities from different scanners belonging to the same OS process (requires $\geq 2$ distinct types) \\
\hline
\code{ParentChildChain} & \code{parent\_pid $\to$ pid} & A process spawned by another process where both appear in the window \\
\hline
\code{SharedRemoteIp} & \code{remote\_ip} & Multiple connections to the same external IP from $\geq 2$ distinct PIDs --- shared C2 infrastructure \\
\hline
\code{SharedFileHash} & \code{file\_hash} & The same binary (SHA-256) at $\geq 2$ different filesystem paths --- lateral copy or dropper \\
\hline
\end{tabular}
\end{center}

Each \code{CorrelatedCluster} carries:
\begin{itemize}[noitemsep]
  \item \code{cluster\_score}: maximum \code{combined\_score} across all members
  \item \code{has\_threat}: true if any member is non-Clean
  \item \code{max\_threat\_level()}: worst threat level among members
  \item \code{anchor\_id}: entity ID of the highest-scoring member
\end{itemize}

\section{AggregatedEntity --- Composite Process Nodes}

\code{manager.aggregate()} groups flat \code{EntityNode}s into \code{AggregatedEntity}
objects, one per process PID. Each \code{AggregatedEntity} embeds:

\begin{itemize}
  \item The root process entity with all its attributes
  \item All network connections owned by that PID as sub-entities
  \item All memory regions owned by that PID as sub-entities
  \item Any files associated with the process
  \item Per-domain sub-scores (\code{process\_score}, \code{network\_score},
        \code{memory\_score}, \code{file\_score})
  \item Threat flags (\code{has\_malicious\_memory}, \code{has\_malicious\_network},
        \code{has\_malicious\_file})
\end{itemize}

Orphan network connections (not owned by any flagged process) and standalone malicious
files each become their own top-level aggregated entity.

\section{Parent Context Boost}

\code{apply\_parent\_context\_boost()} scans the entity window for parent-child process
relationships. When a parent process is already classified as a threat, its children receive
a score boost proportional to the parent's combined score. This captures the common pattern
of a dropper spawning a clean-looking child process to evade per-process detection.

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Threat Graph Pipeline}
% ═════════════════════════════════════════════════════════════════════════════

\section{Graph Construction --- O(n) via Join-Key Indexes}

\code{GraphBuilder::build\_from\_aggregated()} converts the aggregated entity slice into
a directed, weighted \code{ThreatGraph}.

\subsection{The O(n) Optimisation}

Naïve edge discovery iterates all pairs: $O(n^2)$. Instead, \code{GraphBuilder} builds
five index maps in a single $O(n)$ pass:

\begin{lstlisting}[style=rust, caption={GraphBuilder join-key indexes}]
by_pid:       HashMap<u32, Vec<entity_id>>    // PID → all entities with that PID
by_parent:    HashMap<u32, Vec<entity_id>>    // parent_pid → all children
by_file_path: HashMap<String, Vec<entity_id>> // file path (lowercase) → entities
by_file_hash: HashMap<String, Vec<entity_id>> // SHA-256 → entities
by_remote_ip: HashMap<String, Vec<entity_id>> // remote IP → network entities
\end{lstlisting}

For each entity, its join keys are looked up against these maps in $O(1)$ per map. Total
edge discovery is $O(n \cdot \text{avg\_cluster\_size})$, which is $O(n)$ in the typical
case where clusters are small.

\textbf{Deduplication}: a \code{HashSet<(String, String)>} of canonical pairs
\code{(min(a,b), max(a,b))} ensures each undirected edge is emitted exactly once regardless
of traversal direction.

\section{Edge Types and Weights}

\begin{center}
\begin{tabularx}{\textwidth}{|l|c|X|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Edge Type}} & \textcolor{white}{\textbf{Multiplier}} & \textcolor{white}{\textbf{Meaning}} \\
\hline
\code{MemoryInjection} & $\times 1.50$ & RWX region in a flagged process --- primary injection indicator \\
\hline
\code{NetworkOwner} & $\times 1.40$ & C2 connection owned by flagged process \\
\hline
\code{SharedC2} & $\times 1.30$ & Multiple processes connecting to same flagged external IP \\
\hline
\code{ProcessOpenedFile} & $\times 1.20$ & Flagged process loaded a flagged file (dropper/loader) \\
\hline
\code{ParentChild} & $\times 1.10$ & Flagged process spawned another process (propagation) \\
\hline
\code{SameProcess} & $\times 1.00$ & Two entities both owned by the same process \\
\hline
\code{SharedFileHash} & $\times 0.90$ & Two processes loaded the same binary (weaker spread indicator) \\
\hline
\end{tabularx}
\end{center}

\begin{equation}
\text{edge\_weight} = \max(\text{score}_A, \text{score}_B) \times \text{multiplier}
\end{equation}

Using the maximum rather than the average prevents high-scoring entities from being diluted
by low-scoring partners.

\section{GraphNode Extended Fields}

Each \code{GraphNode} carries:

\begin{multicols}{2}
\begin{itemize}[noitemsep]
  \item \code{process\_score: f32}
  \item \code{network\_score: f32}
  \item \code{memory\_score: f32}
  \item \code{file\_score: f32}
  \item \code{has\_malicious\_memory: bool}
  \item \code{has\_malicious\_network: bool}
  \item \code{has\_malicious\_file: bool}
  \item \code{pid: Option<u32>}
  \item \code{parent\_pid: Option<u32>}
  \item \code{graph\_boost: f32}
  \item \code{is\_vector: bool}
  \item \code{is\_lolbin: bool}
\end{itemize}
\end{multicols}

\section{Attack Chain Detection --- Six MITRE-Mapped Patterns}

\code{GraphAnalyzer} runs six independent pattern detectors over the built graph. Each method
operates on the scored graph and produces \code{AttackChain} objects with MITRE ATT\&CK
tactic and technique identifiers.

\subsection{Pattern 1: ProcessInjection \mitre{T1055}}

\textbf{Trigger}: a \code{MemoryInjection} edge where the memory-region endpoint is non-Clean.

\textbf{Logic}: Scan all \code{MemoryInjection} edges. If the memory node is Suspicious or
Malicious, emit a chain linking the process and its memory region. Indicates shellcode or
injected code executing inside a legitimate process.

\subsection{Pattern 2: C2Communication \mitre{T1071}}

\textbf{Trigger}: a \code{NetworkOwner} edge where the network endpoint is non-Clean.

\textbf{Logic}: Scan all \code{NetworkOwner} edges. If the network node is flagged, emit a
chain. The ML model's 60\% weight makes this particularly sensitive to beaconing patterns
that heuristics alone would miss.

\subsection{Pattern 3: MalwareExecution \mitre{T1204}}

\textbf{Trigger}: a \code{ProcessOpenedFile} edge where the file endpoint is non-Clean.

\textbf{Logic}: Scan all \code{ProcessOpenedFile} edges. If the file from which the process
was spawned is malicious, emit a chain. Edge direction is file $\to$ process to reflect
execution causality.

\subsection{Pattern 4: LateralMovement \mitre{T1021}}

\textbf{Trigger}: a \code{ParentChild} edge followed by a \code{NetworkOwner} edge from the
child to a non-Clean network node.

\textbf{Logic}: A spawned process that immediately opens an outbound connection --- common
dropper or lateral movement behaviour.

\subsection{Pattern 5: SuspiciousSpawn \mitre{T1059}}

\textbf{Trigger}: a \code{ParentChild} edge where \textbf{both} parent and child are
threat-level entities.

\textbf{Logic}: Distinguishes from \code{LateralMovement} (which requires a downstream
network connection) by focusing on the propagation chain itself.

\subsection{Pattern 6: MultiStageAttack \mitre{TA0002}}

\textbf{Trigger}: BFS over an undirected view of the graph, seeded from unvisited threat nodes.

\textbf{Logic}: BFS only traverses edges between threat-level nodes (clean nodes act as
barriers). Any connected component with $\geq 3$ threat nodes is emitted as a multi-stage
chain. The description includes the count of distinct scanner types involved.

\textbf{Optimisation}: Each threat node is visited at most once across all BFS runs via a
shared \code{visited: HashSet}. Total BFS complexity is $O(V + E)$ where $V$ and $E$ are
the threat-node subgraph sizes.

\subsection{Summary Table}

\begin{center}
\begin{tabular}{|l|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Pattern}} & \textcolor{white}{\textbf{MITRE}} & \textcolor{white}{\textbf{Detection Method}} \\
\hline
ProcessInjection & T1055 & \code{has\_malicious\_memory == true} on node \\
\hline
C2Communication & T1071 & \code{has\_malicious\_network == true} on node \\
\hline
MalwareExecution & T1204 & \code{has\_malicious\_file == true} on node \\
\hline
LateralMovement & T1021 & ParentChild edge + child has malicious network \\
\hline
SuspiciousSpawn & T1059 & ParentChild edge + both nodes are threats \\
\hline
MultiStageAttack & TA0002 & BFS over threat entities $\geq 3$ nodes \\
\hline
\end{tabular}
\end{center}

\section{Critical Path Analysis}

\code{GraphAnalyzer::find\_critical\_path()} runs a DFS max-weight path algorithm over the
graph. The critical path is the sequence of nodes and edges with the highest cumulative edge
weight. It represents the most dangerous attack chain in the current threat picture and is
surfaced prominently in the UI as the top-priority finding.

\section{Graph Feedback and LOLBin Detection}

\code{apply\_graph\_feedback()} propagates threat information back through the graph. When a
node is identified as a lateral-movement vector (\code{is\_vector = true}), it also checks
the node label against the static \code{LOLBINS} list ($\approx$35 entries). A match sets
\code{is\_lolbin = true} on the \code{GraphNode}.

\section{correlate Command Response}

The full \code{correlate} daemon command response:

\begin{lstlisting}[style=json, caption={correlate response structure}]
{
  "id": "...",
  "success": true,
  "entities":  [ ...EntityNode... ],
  "clusters":  [ ...CorrelatedCluster... ],
  "graph": {
    "nodes":         [ ...GraphNode... ],
    "edges":         [ ...GraphEdge... ],
    "attack_chains": [ ...AttackChain... ]
  },
  "statistics": {
    "total_entities": 42,    "threat_entities": 7,
    "graph_nodes":    42,    "graph_edges":     18,
    "attack_chains_detected": 2,
    "scan_duration_ms": 3200
  }
}
\end{lstlisting}

\textbf{Timeout}: 60\,s without memory scan; 180\,s with \code{include\_memory: true}.

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Post-Verdict Response Actions}
% ═════════════════════════════════════════════════════════════════════════════

\section{Overview}

Once the threat graph has produced a verdict, AegisAI can take containment actions to
stop the attack. All containment logic lives in \file{Antivirus\_Engine/src/core/action/executor.rs}.
The daemon loop in \file{main.rs} calls these functions and serialises their typed result
structs to JSON.

\section{Action Reference}

\begin{longtable}{|l|l|p{4.5cm}|p{3cm}|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Action}} & \textcolor{white}{\textbf{Daemon Cmd}} & \textcolor{white}{\textbf{Runtime Data Written}} & \textcolor{white}{\textbf{Result Struct}} \\
\hline
\endhead
File quarantine & \code{quarantine-file} & \code{\%PROGRAMDATA\%\textbackslash AegisAI\textbackslash quarantine\textbackslash \{sha256\}.quarantined} + \code{.meta.json} & \code{QuarantineResult} \\
\hline
Firewall block & \code{block-ip} & \code{firewall\_rules.json} & \code{BlockIpResult} \\
\hline
Firewall rollback & \code{remove-block-ip} & removes entry from \code{firewall\_rules.json} & \code{BlockIpResult} \\
\hline
Memory dump & \code{dump-memory} & \code{\%PROGRAMDATA\%\textbackslash AegisAI\textbackslash dumps\textbackslash \{pid\}\_\{ts\}.dmp} & \code{DumpResult} \\
\hline
Persistence check & \code{check-persistence} & read-only; returns entries & \code{PersistenceResult} \\
\hline
Network isolation & \code{isolate-network} & \code{isolated\_interfaces.json} & \code{IsolationResult} \\
\hline
Network restore & \code{restore-network} & removes \code{isolated\_interfaces.json} & \code{IsolationResult} \\
\hline
Incident report & Tauri-only & \code{\%USERPROFILE\%\textbackslash Documents\textbackslash AegisAI\textbackslash incident\_\{ts\}.json} & inline JSON \\
\hline
\end{longtable}

\section{Result Type Schemas}

\begin{center}
\begin{tabular}{|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Struct}} & \textcolor{white}{\textbf{Fields}} \\
\hline
\code{QuarantineResult} & \code{success, quarantine\_path?, sha256?, error?} \\
\hline
\code{BlockIpResult} & \code{success, rule\_name?, error?} \\
\hline
\code{DumpResult} & \code{success, dump\_path?, error?} \\
\hline
\code{PersistenceEntry} & \code{kind, name, path, sha256?, suspicious} \\
\hline
\code{PersistenceResult} & \code{success, entries: Vec<PersistenceEntry>, error?} \\
\hline
\code{IsolationResult} & \code{success, disabled\_interfaces: Vec<String>, error?} \\
\hline
\end{tabular}
\end{center}

\section{Firewall Rule Management}

\code{block\_ip(ip, direction)} adds a Windows Firewall deny rule via the Windows Filtering
Platform API. The rule is recorded in \code{firewall\_rules.json} so it can be explicitly
removed by \code{remove\_block\_ip(rule\_name)} without requiring the operator to navigate
Windows Firewall manually. Direction may be \code{"out"} (block outbound C2) or
\code{"both"} (full isolation of the IP).

\section{Persistence Check}

\code{check\_persistence(suspicious\_paths)} scans three autorun locations:

\begin{itemize}
  \item \textbf{Registry}: \code{HKCU\textbackslash Software\textbackslash Microsoft\textbackslash
        Windows\textbackslash CurrentVersion\textbackslash Run} and related keys
  \item \textbf{Scheduled tasks}: \code{\%SystemRoot\%\textbackslash System32\textbackslash
        Tasks\textbackslash} directory tree
  \item \textbf{Startup folders}: per-user and all-users startup directories
\end{itemize}

Each entry is cross-referenced against the supplied suspicious path list. Matching entries
have \code{suspicious = true} in the result.

\section{Network Isolation}

\code{isolate\_network()} disables all connected network adapters via the Windows Device
Management API and records their names in \code{isolated\_interfaces.json}.
\code{restore\_network()} re-enables exactly those interfaces. This provides a
``break glass'' containment action for confirmed intrusions while preserving the ability
to restore connectivity without a reboot.

% ═════════════════════════════════════════════════════════════════════════════
\chapter{AI Agent --- Reasoning Layer}
% ═════════════════════════════════════════════════════════════════════════════

\section{Position in the Pipeline}

The graph is the \textbf{detection layer}. The AI agent is the \textbf{reasoning layer}.
They are sequential: the graph must finish before the agent starts. The agent can then loop
back and trigger new targeted scans, which rebuild the graph, which the agent re-analyses.

\begin{tcolorbox}[aegisbox, title=Why the Agent Cannot Run Before the Graph]
Without the graph, the agent would reason over raw scanner output: hundreds of processes,
thousands of network connections, memory regions. That is noise. The graph collapses that
noise into 3--5 structured, MITRE-mapped, scored findings. By the time the agent sees the
output, it is not looking at 300 processes --- it is looking at 3 attack chains with entity
IDs, scores, and tactics. That is a tractable reasoning problem.
\end{tcolorbox}

\section{Hunt Loop --- Round by Round}

\subsection{Round 1: Initial Graph Verdict}

The agent receives the \code{correlate} result (attack chains, critical path, graph nodes
and edges) and produces:

\begin{itemize}
  \item A human-readable explanation of the observed attack pattern
  \item A confidence level (e.g., ``high --- two corroborating patterns, both domains flagged'')
  \item 2--4 targeted pivot suggestions for Round 2 (specific paths, PIDs, flags)
\end{itemize}

\textbf{Example output} for \code{chrome.exe} spawning \code{cmd.exe} after C2 contact:

\begin{tcolorbox}[warnbox]
``Browser spawned cmd after C2 contact. Consistent with drive-by exploit $\to$ dropper
execution (T1071 + T1059). Confidence: high.

Next pivots:
1. Scan \code{\%TEMP\%} and \code{\%APPDATA\%} for binaries written after chrome started.
2. Re-correlate with \code{include\_memory = true}.
3. Check persistence: scheduled tasks, registry run keys.''
\end{tcolorbox}

\subsection{Round 2: Targeted File Scan}

The agent's pivot from Round 1 triggers a \code{scan-dir \%TEMP\%} command. A newly
discovered \code{payload.exe} is ingested, the graph rebuilds, and the agent receives an
updated correlate result. \code{CriticalPath} now extends to: \code{chrome $\to$ cmd $\to$
payload.exe}.

\subsection{Round 3: Full Correlate with Memory}

A \code{correlate(include\_memory: true)} command reveals process injection into
\code{cmd.exe} and child processes installing scheduled tasks. The agent closes the
investigation with a full kill-chain narrative and a ranked action plan.

\section{Action Prioritization Framework}

The agent collapses 20+ possible containment actions into a 3--5 item ranked plan using
three reasoning layers:

\subsubsection{1. Severity Gating}

Actions have minimum score thresholds. Network isolation should never fire below a combined
score of 0.85. Process termination may fire at 0.65.

\subsubsection{2. Pattern-to-Action Mapping}

\begin{center}
\begin{tabular}{|l|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Pattern}} & \textcolor{white}{\textbf{Primary Actions}} & \textcolor{white}{\textbf{Skip Unless Critical}} \\
\hline
ProcessInjection & \code{dump\_memory}, \code{kill\_process} & \code{isolate\_network} \\
\hline
C2Communication & \code{block\_ip}, \code{check\_persistence} & \code{isolate\_network} \\
\hline
MalwareExecution & \code{quarantine\_file}, \code{kill\_process} & \code{dump\_memory} \\
\hline
LateralMovement & \code{isolate\_network}, \code{check\_persistence} & --- \\
\hline
MultiStageAttack & all, sequenced & --- \\
\hline
\end{tabular}
\end{center}

\subsubsection{3. Risk Ranking (Reversibility Order)}

Actions are always ordered: reversible before destructive before disruptive.
\begin{center}
\code{block\_ip} $\to$ \code{quarantine\_file} $\to$ \code{kill\_process} $\to$ \code{isolate\_network}
\end{center}

\section{Agent Architecture}

The agent is implemented in \file{ai\_agent/} and wired to Tauri via an
\code{invoke\_ai\_agent} command. The Rust \code{agent.rs} module:

\begin{enumerate}
  \item \textbf{\code{build\_analyst\_prompt()}} --- constructs a 4-section briefing:
        system role (security analyst persona), graph context (serialised attack chains and
        critical path), action menu (available containment commands with threshold gates),
        and output schema (JSON with ranked actions and rationale).

  \item \textbf{\code{call\_claude()}} --- calls the Anthropic Claude API (model:
        \code{claude-sonnet-4-6}) with the structured prompt. The response is expected as
        a JSON object.

  \item \textbf{\code{parse\_agent\_response()}} --- deserialises the Claude response into
        a typed \code{AgentVerdict} struct with \code{RankedAction[]} and free-text rationale.
\end{enumerate}

\section{Key Design Constraints}

\begin{itemize}
  \item The agent \textbf{never runs a full scan unprompted}. Each pivot is specific:
        a path, a PID, an \code{include\_memory} flag.
  \item The graph \textbf{rebuilds from scratch each round}. All four scanners re-run (or
        a designated subset). The EntityManager starts fresh to reflect current system state.
  \item The agent \textbf{closes the loop or escalates}. After $N$ rounds with no new
        evidence, it produces a confidence statement and terminates the investigation.
  \item Actions are \textbf{never fired automatically} unless \code{autonomousMode} is
        explicitly enabled by the operator. All actions require UI confirmation.
  \item Irreversible actions (\code{kill\_process}, \code{isolate\_network}) require
        \code{confirm: true} in the agent response, which forces a confirmation prompt
        before execution.
\end{itemize}

\section{Prerequisites}

\begin{center}
\begin{tabular}{|l|p{8cm}|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Prerequisite}} & \textcolor{white}{\textbf{Why Needed}} \\
\hline
Agent can invoke daemon commands & The loop requires the agent to emit \code{scan-file}, \code{correlate} JSON-RPC calls \\
\hline
Persistence layer (SQLite) & The agent cannot ask ``when did this entity first appear?'' without history \\
\hline
Continuous monitoring mode & Rounds 2 and 3 need the daemon running continuously \\
\hline
IOC feed integration & Hash and IP lookups give external confirmation of findings \\
\hline
Behavioural baseline & Required before the agent can say ``this is anomalous for this process'' \\
\hline
\end{tabular}
\end{center}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Tauri Desktop Application}
% ═════════════════════════════════════════════════════════════════════════════

\section{Architecture Overview}

The desktop application is built with \textbf{Tauri 2.x}: a Rust backend (IPC bridge,
daemon lifecycle, file system operations) combined with a \textbf{React/TypeScript} frontend.
The two sides communicate via Tauri's \code{invoke()} bridge, which serialises JavaScript
calls into Rust function invocations.

\begin{figure}[H]
\centering
\begin{tikzpicture}[
  layer/.style={rectangle, rounded corners=5pt, minimum width=10cm, minimum height=0.9cm,
                text centered, font=\small\bfseries, draw, thick},
]
\node[layer, fill=aegiscyan!20, draw=aegiscyan] (react) at (0,0)
  {React Frontend (TypeScript)};
\node[layer, fill=aegisblue!15, draw=aegisblue] (zustand) at (0,-1.3)
  {Zustand Store (state management, async actions)};
\node[layer, fill=orange!15, draw=orange!60] (tauri) at (0,-2.6)
  {Tauri IPC Bridge (src-tauri/src/main.rs)};
\node[layer, fill=malicious!10, draw=malicious!40] (daemon) at (0,-3.9)
  {Rust Daemon (Antivirus\_Engine/src/main.rs)};
\end{tikzpicture}
\caption{Tauri application layered architecture}
\end{figure}

\section{Tauri IPC Commands}

\subsection{Scanning Commands}

\begin{center}
\begin{tabular}{|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Invoke Call}} & \textcolor{white}{\textbf{Description}} \\
\hline
\code{invoke('scan\_file', \{path\})} & Single file scan \\
\hline
\code{invoke('scan\_directory', \{path\})} & Recursive directory scan \\
\hline
\code{invoke('scan\_processes')} & Enumerate and score all processes \\
\hline
\code{invoke('scan\_network', \{pid?\})} & Capture and analyse network connections \\
\hline
\code{invoke('scan\_memory', \{pid?\})} & Enumerate and score memory regions \\
\hline
\code{invoke('scan\_all')} & System-wide incremental file scan \\
\hline
\end{tabular}
\end{center}

\subsection{Correlation and Graph}

\begin{center}
\begin{tabular}{|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Invoke Call}} & \textcolor{white}{\textbf{Description}} \\
\hline
\code{invoke('correlate\_entities', \{includeMemory\})} & Run full entity/graph pipeline \\
\hline
\code{invoke('run\_ml\_ids', \{csvPath?\})} & Run network XGBoost IDS \\
\hline
\code{invoke('get\_engine\_status')} & Daemon health check \\
\hline
\code{invoke('apply\_ember\_ml', \{paths\})} & Run EMBER ML on suspicious files \\
\hline
\end{tabular}
\end{center}

\subsection{Post-Verdict Containment}

\begin{center}
\begin{tabular}{|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Invoke Call}} & \textcolor{white}{\textbf{Description}} \\
\hline
\code{invoke('quarantine\_file', \{path\})} & Move malicious file to quarantine \\
\hline
\code{invoke('block\_ip', \{remote\_ip, direction?\})} & Add outbound firewall deny rule \\
\hline
\code{invoke('remove\_block\_ip', \{rule\_name\})} & Roll back a firewall rule \\
\hline
\code{invoke('dump\_memory', \{pid\})} & Write process memory dump to disk \\
\hline
\code{invoke('check\_persistence', \{suspicious\_paths?\})} & Scan autorun locations \\
\hline
\code{invoke('isolate\_network')} & Disable all connected network adapters \\
\hline
\code{invoke('restore\_network')} & Re-enable saved network adapters \\
\hline
\code{invoke('kill\_process', \{pid\})} & Terminate a process \\
\hline
\code{invoke('export\_incident\_report', \{...\})} & Write structured JSON incident report \\
\hline
\end{tabular}
\end{center}

\section{Eight-View Router}

\code{App.tsx} routes across eight views:

\begin{center}
\begin{tabular}{|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Route}} & \textcolor{white}{\textbf{Component}} \\
\hline
\code{dashboard} & System overview, threat summary, recent alerts \\
\hline
\code{scanner} & File/directory/system-wide scan with ML panel \\
\hline
\code{processes} & Process list with scores, kill actions \\
\hline
\code{network} & Network connection table, ML IDS panel \\
\hline
\code{memory} & Memory region browser, shellcode indicators \\
\hline
\code{entities} & EntityManager: flat/cluster/attack-chain views \\
\hline
\code{graph} & ThreatGraph: interactive force-directed graph \\
\hline
\code{history} & Scan history and past verdicts \\
\hline
\end{tabular}
\end{center}

\section{Zustand Store}

All async state and scanner calls are managed by a single Zustand store
(\file{UI/src/store/index.ts}). Key store slices include:

\begin{itemize}
  \item \code{scanResults}: current scan result list with normalised \code{ScanResult[]}
  \item \code{correlateResult}: full correlate payload (\code{CorrelateResult})
  \item \code{emberMlResults}: EMBER inference results per file path
  \item \code{lastScanDurationMs}: elapsed scan time for the duration badge
  \item \code{scanAll()}: triggers system-wide scan with live elapsed timer
  \item \code{applyEmberMl()}: collects suspicious paths and calls ML bridge
  \item \code{correlateEntities(includeMemory?)}: triggers entity/graph pipeline
  \item \code{clearCorrelate()}: resets backend result, returns to client-side mode
\end{itemize}

\section{ThreatGraph Component}

\code{ThreatGraph.tsx} renders the interactive force-directed entity graph using a
graph visualisation library. Features:

\begin{itemize}
  \item \textbf{Node icons} selected by dominant sub-score
        (\code{process/network/memory/file\_score})
  \item \textbf{Sub-chip row} in detail panel showing PROC/NET/MEM/FILE score breakdown
  \item \textbf{Edge colour} by type: \code{SharedC2} (red), \code{ParentChild} (orange),
        \code{SharedFileHash} (blue)
  \item \textbf{Fallback path}: if no \code{correlate} result is available, client-side
        \code{buildProcessEntities()} aggregates the current entity store into graph nodes
  \item \textbf{LOLBin badge}: displayed on vector nodes when \code{is\_lolbin = true}
\end{itemize}

\section{EntityManager Component}

Three view modes are available:

\begin{center}
\begin{tabular}{|l|l|p{5.5cm}|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Mode}} & \textcolor{white}{\textbf{Data Source}} & \textcolor{white}{\textbf{Description}} \\
\hline
Flat List & Client-side store & All entity types, filterable, sortable by score \\
\hline
Clusters & Backend or client fallback & Backend shows 4 cluster types; fallback shows PID clusters only \\
\hline
Attack Chains & Backend only & Requires CORRELATE; shows MITRE-tagged chains \\
\hline
\end{tabular}
\end{center}

\section{Scanner Component Features}

\begin{itemize}
  \item \textbf{Live elapsed timer}: a \code{setInterval} counter shows elapsed seconds
        while a scan is in progress
  \item \textbf{Duration badge}: shows the final scan time once complete
  \item \textbf{Scan All button}: triggers \code{scanAll()} in the store
  \item \textbf{ML Results panel}: scrollable EMBER inference results with score badges
  \item \textbf{Expandable result rows}: click to see confidence bar, detection signals,
        YARA rule names, and the EMBER ML signal with score and file type
\end{itemize}

\section{Client-Side Entity Aggregation (\texttt{entityUtils.ts})}

\file{UI/src/lib/entityUtils.ts} provides the client-side fallback aggregation path:

\begin{itemize}
  \item \code{buildProcessEntities()} --- groups flat entities from the Zustand store into
        aggregated process nodes (one per PID), matching the structure of the backend
        \code{aggregate()} function
  \item \code{buildProcessEdges()} --- creates inter-entity edges from the client-side
        entity list (only SharedC2, ParentChild, SharedFileHash --- the 3 inter-entity
        edge types)
  \item \code{orphanConnections()} --- network entities not claimed by any process entity
  \item \code{orphanFiles()} --- file entities not matched to any process executable
\end{itemize}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Performance Characteristics}
% ═════════════════════════════════════════════════════════════════════════════

\section{Per-Operation Timing Budget}

\begin{center}
\begin{tabular}{|l|c|c|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Operation}} & \textcolor{white}{\textbf{Typical}} & \textcolor{white}{\textbf{Worst Case}} \\
\hline
Hash DB lookup (single file) & $< 1$\,ms & $< 1$\,ms \\
\hline
YARA scan (10\,MiB executable) & $\approx$50\,ms & 5\,s (timeout) \\
\hline
Heuristics (single file, single read) & 5--20\,ms & 100\,ms \\
\hline
EMBER ML inference (warm server) & 100--300\,ms & 20\,s \\
\hline
Process scan (all running processes) & 500\,ms--2\,s & 5\,s \\
\hline
Network capture and feature extraction & 2--5\,s & 15\,s \\
\hline
Memory scan (single PID) & 200\,ms--2\,s & 10\,s \\
\hline
Full correlate (no memory) & 3--10\,s & 30\,s \\
\hline
Full correlate (with memory) & 30--90\,s & 180\,s \\
\hline
System-wide scan (incremental, warm cache) & 5--30\,s & minutes \\
\hline
\end{tabular}
\end{center}

\section{Key Optimisations Summary}

\begin{center}
\begin{tabular}{|l|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Component}} & \textcolor{white}{\textbf{Technique}} & \textcolor{white}{\textbf{Benefit}} \\
\hline
\code{EntityManager} & DashMap sharded concurrent map & No global lock during multi-scanner ingest \\
\hline
\code{EntityManager} & 10-min sliding window + prune & Bounded memory under continuous operation \\
\hline
\code{GraphBuilder} & 5 join-key index maps & $O(n)$ edge discovery vs.\ $O(n^2)$ naive \\
\hline
\code{GraphBuilder} & HashSet deduplication & Each undirected edge emitted exactly once \\
\hline
\code{GraphAnalyzer} & Shared BFS visited set & Each threat node visited once total, $O(V+E)$ \\
\hline
\code{HeuristicAnalyzer} & Single file read & Eliminates 3+ redundant I/O operations \\
\hline
\code{HeuristicAnalyzer} & Binary-search extension tables & $O(\log n)$ vs.\ $O(n)$ extension lookup \\
\hline
\code{SystemScanner} & FileStateCache (mtime+size) & Unchanged files skipped in rescans \\
\hline
\code{EmberServer} & Persistent Python process & Models load once; $\times 50$ inference speedup \\
\hline
\code{WARM\_SYSTEM} & OnceLock+Mutex singleton & No 200\,ms OS warm-up per process scan \\
\hline
\code{memory\_scan\_lock} & AtomicBool CAS & Rejects concurrent memory scans \\
\hline
\end{tabular}
\end{center}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Security Analysis}
% ═════════════════════════════════════════════════════════════════════════════

\section{Detection Strengths}

\begin{enumerate}
  \item \textbf{Multi-layer fusion}: no single detector is a single point of failure.
        YARA catches known families; heuristics catch structural anomalies; ML catches
        statistical outliers; the graph catches multi-entity chains.

  \item \textbf{Score-based rather than binary}: a file that scores $+3$ from heuristics
        (Suspicious) but $+0.92$ from EMBER is escalated to Malicious. No single layer
        can suppress the aggregate verdict.

  \item \textbf{Living-off-the-land coverage}: the LOLBin list and process ancestry
        heuristics specifically target techniques that evade signature-only solutions.

  \item \textbf{Attack chain visibility}: the graph surfaces multi-stage attacks that are
        invisible to per-process or per-file analysis (e.g., browser $\to$ cmd $\to$
        payload $\to$ schtasks kill chain).

  \item \textbf{Calibrated probabilities}: all ML outputs are calibrated, making the
        combined score meaningful for threshold-based alerting rather than requiring
        per-model threshold tuning.

  \item \textbf{Reversible containment}: all containment actions are logged and reversible.
        Network isolation can be rolled back with a single \code{restore\_network} call.
\end{enumerate}

\section{Known Limitations and Pending Work}

\begin{tcolorbox}[dangerbox, title=Known Limitations]
\begin{itemize}
  \item \textbf{File ML model not yet trained}: the file domain uses YARA + heuristics +
        EMBER only; a dedicated XGBoost model on EMBER features is pending.
  \item \textbf{Process and memory ML not yet wired into entity scoring}: GRU and memory
        models produce scores but are not yet patched into \code{EntityManager} via
        \code{update\_ml\_score()}.
  \item \textbf{Network model requires calibration}: the XGBoost network IDS should be
        recalibrated on real enterprise traffic to reduce distribution shift.
  \item \textbf{No IOC feed integration}: hash and IP reputation lookups rely on the local
        hash DB; external threat intelligence feeds are not yet wired in.
  \item \textbf{No persistence layer (SQLite)}: the agent cannot ask historical questions
        about entity score evolution over time.
  \item \textbf{UI wiring for action commands incomplete}: \code{quarantine\_file},
        \code{block\_ip}, \code{dump\_memory}, \code{check\_persistence},
        \code{isolate\_network} are registered in Tauri but the React components that
        invoke them are not yet fully built.
  \item \textbf{Autonomous mode not implemented}: the \code{autonomousMode} flag in the
        Zustand store and the Settings toggle that enables it are pending.
  \item \textbf{AI agent stubs}: \file{ai\_agent/agent/reasoning.py} and \file{main.py}
        are empty stubs; the Rust \code{agent.rs} Round 1 implementation is complete.
\end{itemize}
\end{tcolorbox}

\section{Threat Model}

AegisAI is designed to detect:

\begin{itemize}
  \item \textbf{Known malware}: via YARA rules and SHA-256 hash database
  \item \textbf{Polymorphic and packed malware}: via entropy analysis and PE structure anomalies
  \item \textbf{Fileless attacks}: via process behaviour and memory shellcode detection
  \item \textbf{Living-off-the-land attacks}: via LOLBin detection and process ancestry rules
  \item \textbf{C2 beaconing}: via network timing analysis and ML
  \item \textbf{Process injection}: via RWX region detection and MZ-in-private-region checks
  \item \textbf{Ransomware}: via content phrase detection, wallet address scanning,
        ransomware filename/extension matching
  \item \textbf{Multi-stage APT campaigns}: via graph-level attack chain correlation
\end{itemize}

Out of scope for the current implementation:
\begin{itemize}
  \item Kernel-mode rootkits (requires a kernel driver)
  \item Hardware-level attacks (firmware, UEFI persistence)
  \item Encrypted C2 traffic that is behaviourally indistinguishable from HTTPS
\end{itemize}

% ═════════════════════════════════════════════════════════════════════════════
\chapter{Conclusion}
% ═════════════════════════════════════════════════════════════════════════════

\section{Summary}

AegisAI is a production-quality endpoint detection and response system that fuses four
complementary detection modalities --- signatures, heuristics, machine learning, and graph
correlation --- into a unified, scored, explainable threat picture.

The architecture is layered by design:

\begin{center}
\begin{tabular}{|l|l|l|}
\hline
\rowcolor{tableheadblue}
\textcolor{white}{\textbf{Layer}} & \textcolor{white}{\textbf{Role}} & \textcolor{white}{\textbf{Survives Distribution Shift?}} \\
\hline
Heuristics & Rule-based first filter & Yes --- rules do not depend on training data \\
\hline
Feature space & Normalisation contract & Yes --- it is a specification, not a model \\
\hline
ML models & Domain probability estimators & Partially --- degrades gracefully \\
\hline
Entity layer & Signal convergence and join point & Yes --- join keys are structural \\
\hline
Graph engine & Attack chain reasoning & Yes --- topology shifts slower than raw features \\
\hline
AI agent & Ranked action recommendation & N/A --- LLM reasoning is environment-agnostic \\
\hline
\end{tabular}
\end{center}

\section{Key Technical Achievements}

\begin{itemize}
  \item \textbf{Single-read heuristic engine}: all file analysis (entropy, content,
        SHA-256, magic bytes) operates on one shared in-memory buffer.

  \item \textbf{O(n) graph construction}: five join-key index maps replace $O(n^2)$
        naive pair iteration.

  \item \textbf{Calibrated multi-domain ML}: four independent XGBoost/LightGBM models
        produce comparable probability scores via isotonic regression calibration.

  \item \textbf{Persistent ML server}: EMBER models load once at daemon start;
        subsequent calls pay only $\approx$200\,ms inference cost.

  \item \textbf{Layered attack chain detection}: six MITRE-mapped patterns covering
        injection, C2, execution, lateral movement, and multi-stage campaigns.

  \item \textbf{Reversible containment}: all post-verdict actions are logged and can
        be rolled back without system restart.
\end{itemize}

\section{Future Work}

\begin{enumerate}
  \item Train and wire in process (XGBoost on DAPT 2020) and memory (XGBoost on
        CIC-MalMem-2022) ML models.
  \item Complete the UI action components for quarantine, firewall, memory dump,
        persistence check, and network isolation.
  \item Add IOC feed integration (MISP, VirusTotal API) for hash and IP reputation.
  \item Implement the persistence layer (SQLite) for historical entity queries.
  \item Implement the autonomous mode flag and confirmation-gate mechanism.
  \item Calibrate the network model on real enterprise traffic samples.
  \item Complete the AI agent reasoning loop (Rounds 2--3, persistence check pivots).
  \item Add the \code{is\_lolbin} UI badge to the ThreatGraph component.
\end{enumerate}

\vspace{2cm}
\begin{center}
\textcolor{aegisblue}{\rule{10cm}{0.8pt}}\\[0.4cm]
{\large\textbf{AegisAI} --- Multi-Layer Windows Antivirus \& Intrusion Detection System}\\[0.2cm]
{\normalsize Houssem Eddine Bouzamoucha \quad Abdelmajid Tabessi \quad Ahmed Ameur Lejmi}\\[0.2cm]
{\small Academic Year 2025--2026}
\end{center}

\end{document}
