# Extract 47 UNSW-NB15 network flow features from scan output
$output = C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\target\release\antivirus.exe scan-network | ConvertFrom-Json

$features = @()
$timestamp = [int64](Get-Date -UFormat %s)

function Parse-Address($addr) {
    if ([string]::IsNullOrWhiteSpace($addr)) {
        return @{ ip = ''; port = 0 }
    }

    # IPv6 literal with port: [::1]:443
    if ($addr -match '^\[(.+)\]:(\d+|\*)$') {
        return @{ ip = $matches[1]; port = if ($matches[2] -match '^\d+$') { [int]$matches[2] } else { 0 } }
    }

    # Split at the last colon for IPv4 and non-bracketed addresses.
    $lastColon = $addr.LastIndexOf(':')
    if ($lastColon -ge 0) {
        $ipPart = $addr.Substring(0, $lastColon)
        $portPart = $addr.Substring($lastColon + 1)
        if ($portPart -match '^\d+$') {
            return @{ ip = $ipPart; port = [int]$portPart }
        }
        if ($portPart -eq '*') {
            return @{ ip = $ipPart; port = 0 }
        }
    }

    return @{ ip = $addr; port = 0 }
}

function Resolve-Service($sport, $dsport, $protocol) {
    $serviceMap = @{
        80 = 'http'
        443 = 'https'
        22 = 'ssh'
        21 = 'ftp'
        25 = 'smtp'
        53 = 'dns'
    }

    if ($dsport -and $serviceMap.ContainsKey($dsport)) {
        return $serviceMap[$dsport]
    }
    if ($sport -and $serviceMap.ContainsKey($sport)) {
        return $serviceMap[$sport]
    }
    return 'other'
}

foreach ($conn in $output.connections) {
    # Parse addresses safely and convert '*' ports to 0
    $srcAddr = Parse-Address $conn.local_address
    $dstAddr = Parse-Address $conn.remote_address

    $srcip = $srcAddr.ip -replace '\[\:\:\]', '::1'
    $sport = $srcAddr.port
    $dstip = $dstAddr.ip -replace '\[\:\:\]', '::1'
    $dsport = $dstAddr.port
    
    # Determine service by port, preferring destination port for client flows
    $service = Resolve-Service $sport $dsport $conn.protocol

    $feature = [PSCustomObject]@{
        srcip             = $srcip
        sport             = $sport
        dstip             = $dstip
        dsport            = $dsport
        proto             = $conn.protocol
        state             = $conn.state
        dur               = 0.0  # Duration unavailable in current socket snapshot
        sbytes            = 0.0  # Packet-level counters unavailable
        dbytes            = 0.0
        sttl              = 0.0
        dttl              = 0.0
        sloss             = 0.0
        dloss             = 0.0
        service           = $service
        Sload             = 0.0
        Dload             = 0.0
        Spkts             = 0.0
        Dpkts             = 0.0
        swin              = 0.0
        dwin              = 0.0
        stcpb             = 0.0
        dtcpb             = 0.0
        smeansz           = 0.0
        dmeansz           = 0.0
        trans_depth       = 0.0
        res_bdy_len       = 0.0
        Sjit              = 0.0
        Djit              = 0.0
        Stime             = $timestamp
        Ltime             = $timestamp
        Sintpkt           = 0.0
        Dintpkt           = 0.0
        tcprtt            = 0.0
        synack            = if ($conn.protocol -eq 'TCP') { 1.0 } else { 0.0 }
        ackdat            = if ($conn.state -eq 'ESTABLISHED') { 1.0 } else { 0.0 }
        is_sm_ips_ports   = if ($sport -eq $dsport) { 1.0 } else { 0.0 }
        ct_state_ttl      = 0.0
        ct_flw_http_mthd  = 0.0
        is_ftp_login      = if ($service -eq 'ftp') { 1.0 } else { 0.0 }
        ct_ftp_cmd        = if ($service -eq 'ftp') { 1.0 } else { 0.0 }
        ct_srv_src        = 0.0
        ct_srv_dst        = 0.0
        ct_dst_ltm        = 0.0
        ct_src_ltm        = 0.0
        ct_src_dport_ltm  = 0.0
        ct_dst_sport_ltm  = 0.0
        ct_dst_src_ltm    = 0.0
        process_name      = $conn.process_name
        threat_level      = $conn.threat_level
        threat_score      = $conn.threat_score
    }

    $features += $feature
}

# Calculate count-based connection tracking features from the current snapshot.
foreach ($feature in $features) {
    $feature.ct_srv_src      = ($features | Where-Object { $_.srcip -eq $feature.srcip -and $_.service -eq $feature.service }).Count - 1
    $feature.ct_srv_dst      = ($features | Where-Object { $_.dstip -eq $feature.dstip -and $_.service -eq $feature.service }).Count - 1
    $feature.ct_dst_ltm      = ($features | Where-Object { $_.dstip -eq $feature.dstip }).Count - 1
    $feature.ct_src_ltm      = ($features | Where-Object { $_.srcip -eq $feature.srcip }).Count - 1
    $feature.ct_src_dport_ltm= ($features | Where-Object { $_.srcip -eq $feature.srcip -and $_.dsport -eq $feature.dsport }).Count - 1
    $feature.ct_dst_sport_ltm= ($features | Where-Object { $_.dstip -eq $feature.dstip -and $_.sport -eq $feature.sport }).Count - 1
    $feature.ct_dst_src_ltm  = ($features | Where-Object { $_.dstip -eq $feature.dstip -and $_.srcip -eq $feature.srcip }).Count - 1
    if ($feature.service -eq 'http') {
        $feature.ct_flw_http_mthd = ($features | Where-Object { $_.srcip -eq $feature.srcip -and $_.service -eq 'http' }).Count - 1
    }
}

# Export to CSV with all 47 features
$features | Select-Object srcip, sport, dstip, dsport, proto, state, dur, sbytes, dbytes, sttl, dttl, sloss, dloss, service, Sload, Dload, Spkts, Dpkts, swin, dwin, stcpb, dtcpb, smeansz, dmeansz, trans_depth, res_bdy_len, Sjit, Djit, Stime, Ltime, Sintpkt, Dintpkt, tcprtt, synack, ackdat, is_sm_ips_ports, ct_state_ttl, ct_flw_http_mthd, is_ftp_login, ct_ftp_cmd, ct_srv_src, ct_srv_dst, ct_dst_ltm, ct_src_ltm, ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm | Export-Csv -Path "C:\Users\houss\Desktop\AegisAI\network_features_47.csv" -NoTypeInformation -Encoding UTF8

Write-Host "✓ 47-feature CSV created: network_features_47.csv"
$count = $features.Count
Write-Host "✓ Total flows: $count"
