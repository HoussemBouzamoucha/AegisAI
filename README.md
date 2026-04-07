# AegisAI Network Feature Extractor

Extracts 47 UNSW-NB15 network flow features for intrusion detection and machine learning analysis.

## Quick Start

### Option 1: Using Pre-built Rust Binary (Fastest)

```powershell
# Navigate to project directory
cd C:\Users\[YOUR_USERNAME]\Desktop\AegisAI

# Run network scan
.\Antivirus_Engine\target\release\antivirus.exe scan-network

# Generate 47-feature CSV
PowerShell -ExecutionPolicy Bypass -File ".\extract_47_features.ps1"
```

### Option 2: Using MSYS2 (Full Build)

```powershell
# Install MSYS2 (if not already installed)
winget install -e --id MSYS2.MSYS2

# Launch MSYS2 UCRT64 shell
C:\msys64\ucrt64.exe

# Navigate and build
cd /c/Users/[YOUR_USERNAME]/Desktop/AegisAI/Antivirus_Engine/src/core/network/Feature_extractor
make clean && make

# Run live capture (30 seconds on Ethernet interface)
./flow_extractor -i Ethernet -o features.csv -d 30 -v
```

### Option 3: Using Docker (Cross-platform)

```powershell
# Build Docker image
docker-compose build rust_engine

# Run network monitor
docker-compose up rust_engine
```

## Prerequisites

### Windows Requirements
- **MSYS2** (recommended): `winget install -e --id MSYS2.MSYS2`
- **Docker Desktop** (alternative): Download from docker.com
- **PowerShell 5.1+** (built-in)

### Linux/Mac Requirements
- **Docker**: `sudo apt install docker.io` (Ubuntu/Debian)
- **GCC/Make**: Usually pre-installed

## Output Files

- `network_scan_output.csv` - Basic connection data
- `network_features_47.csv` - Full UNSW-NB15 47 features
- `features.csv` - Raw packet capture features (MSYS2 build)

## 47 UNSW-NB15 Features

| # | Feature | Type | Description |
|---|---------|------|-------------|
| 1 | srcip | object | Source IP address |
| 2 | sport | Int32 | Source port |
| 3 | dstip | object | Destination IP address |
| 4 | dsport | Int32 | Destination port |
| 5 | proto | object | Protocol (TCP/UDP) |
| 6 | state | object | Connection state |
| 7 | dur | float32 | Flow duration |
| 8 | sbytes | float32 | Source bytes |
| 9 | dbytes | float32 | Destination bytes |
| 10 | sttl | float32 | Source TTL |
| 11 | dttl | float32 | Destination TTL |
| 12 | sloss | float32 | Source packet loss |
| 13 | dloss | float32 | Destination packet loss |
| 14 | service | object | Service type (http, https, etc.) |
| 15 | Sload | float32 | Source load |
| 16 | Dload | float32 | Destination load |
| 17 | Spkts | float32 | Source packets |
| 18 | Dpkts | float32 | Destination packets |
| 19 | swin | float32 | Source window size |
| 20 | dwin | float32 | Destination window size |
| 21 | stcpb | float32 | Source TCP base sequence |
| 22 | dtcpb | float32 | Destination TCP base sequence |
| 23 | smeansz | float32 | Source mean packet size |
| 24 | dmeansz | float32 | Destination mean packet size |
| 25 | trans_depth | float32 | Transaction depth |
| 26 | res_bdy_len | float32 | Response body length |
| 27 | Sjit | float32 | Source jitter |
| 28 | Djit | float32 | Destination jitter |
| 29 | Stime | int64 | Start time |
| 30 | Ltime | int64 | Last time |
| 31 | Sintpkt | float32 | Source inter-packet time |
| 32 | Dintpkt | float32 | Destination inter-packet time |
| 33 | tcprtt | float32 | TCP round trip time |
| 34 | synack | float32 | SYN-ACK time |
| 35 | ackdat | float32 | ACK-data time |
| 36 | is_sm_ips_ports | float32 | Same IP/port flag |
| 37 | ct_state_ttl | float32 | State TTL count |
| 38 | ct_flw_http_mthd | float32 | HTTP method count |
| 39 | is_ftp_login | float32 | FTP login flag |
| 40 | ct_ftp_cmd | float32 | FTP command count |
| 41 | ct_srv_src | float32 | Service source count |
| 42 | ct_srv_dst | float32 | Service destination count |
| 43 | ct_dst_ltm | float32 | Destination lifetime count |
| 44 | ct_src_ltm | float32 | Source lifetime count |
| 45 | ct_src_dport_ltm | float32 | Source dport lifetime count |
| 46 | ct_dst_sport_ltm | float32 | Destination sport lifetime count |
| 47 | ct_dst_src_ltm | float32 | Destination source lifetime count |

## Troubleshooting

### MSYS2 Issues
```bash
# Update MSYS2 packages
pacman -Syu

# Install missing tools
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make mingw-w64-ucrt-x86_64-libpcap
```

### Docker Issues
```powershell
# Start Docker Desktop
&"${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"

# Check Docker status
docker ps
```

### Network Interface Issues
```powershell
# List available interfaces (Windows)
Get-NetAdapter | Select-Object Name, InterfaceDescription

# List available interfaces (Linux/Mac)
ip link show
```

### Permission Issues
```powershell
# Run PowerShell as Administrator
# Or use sudo in MSYS2/Linux
```

## Usage Examples

### Continuous Monitoring
```powershell
# Monitor every 60 seconds
while ($true) {
    .\antivirus.exe scan-network
    Start-Sleep 60
}
```

### Process-Specific Analysis
```powershell
# Monitor specific process (replace PID)
.\antivirus.exe scan-network-pid 1234
```

### Batch Processing
```powershell
# Process multiple PCAP files
foreach ($pcap in Get-ChildItem *.pcap) {
    .\flow_extractor -r $pcap.FullName -o "$($pcap.BaseName)_features.csv"
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with multiple interfaces
5. Submit a pull request

## License

See LICENSE file for details.