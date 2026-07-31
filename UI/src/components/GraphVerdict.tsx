// File: UI/src/components/GraphVerdict.tsx
// Graph Verdict — humanized synthesis of the graph's attack-chain output.
//
// Layout:
//   Left panel  — verdict card + attack chains + critical path narrative
//   Right panel — sub-graph showing only verdict-relevant entities and edges
//
// ML placeholder policy:
//   If ml_score is undefined/null for a node, the display shows "N/A" and
//   notes that ML scoring was not available for that domain.  The combined
//   score shown is the heuristic-only value from the backend.  No fake score
//   is injected — the verdict text calls this out explicitly.

import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import { AlertTriangle, CheckCircle, Zap, GitMerge, ChevronDown, ChevronRight, Info, Clock, ShieldAlert, ShieldOff, Siren, Play, SkipForward, FileText } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from '../store';
import type {
  AttackChain, CriticalPath, GraphNodeData, UnifiedThreat,
} from '../types';

// ─── Colour tokens (mirror ThreatGraph) ──────────────────────────────────────

function threatColor(level: UnifiedThreat | string): string {
  if (level === 'Critical')   return '#ff3355';
  if (level === 'Malicious')  return '#ff3355';
  if (level === 'Suspicious') return '#ffb300';
  return '#00ff88';
}


// ─── Verdict generation ───────────────────────────────────────────────────────

type Severity = 'Clean' | 'Suspicious' | 'Malicious' | 'Critical';

const SEVERITY_ORDER: Record<Severity, number> = {
  Clean: 0, Suspicious: 1, Malicious: 2, Critical: 3,
};

function worstSeverity(chains: AttackChain[]): Severity {
  return chains.reduce<Severity>((worst, c) => {
    const s = c.severity as Severity;
    return SEVERITY_ORDER[s] > SEVERITY_ORDER[worst] ? s : worst;
  }, 'Clean');
}

interface PatternSentence {
  pattern: string;
  sentence: string;
  mitre: string;
}

function humanizePattern(chain: AttackChain, nodes: Record<string, GraphNodeData>): PatternSentence {
  const labels = chain.node_ids
    .map(id => nodes[id]?.label ?? id)
    .filter(Boolean);

  const actor = labels[0] ?? 'Unknown process';
  const target = labels[1] ?? null;

  const sentences: Record<string, string> = {
    ProcessInjection:
      `"${actor}" has a suspicious or malicious memory region — possible shellcode injected into its address space.`,
    C2Communication:
      `"${actor}" is actively connecting to a remote host that matches command-and-control indicators.`,
    MalwareExecution:
      `A malicious file on disk matches the executable path of "${actor}" — this process is running known malware.`,
    LateralMovement:
      target
        ? `"${actor}" spawned "${target}", which subsequently opened an external network connection — consistent with dropper or lateral-movement behaviour.`
        : `A process spawned a child that opened an external network connection — consistent with lateral-movement behaviour.`,
    SuspiciousSpawn:
      target
        ? `"${actor}" (already flagged as a threat) spawned "${target}", which is also flagged — possible propagation or privilege-escalation chain.`
        : `A threat-level process spawned another threat-level child — possible propagation chain.`,
    MultiStageAttack:
      `Three or more threat indicators across different scanners are structurally linked through ${actor}${target ? ` → ${target}` : ''} — consistent with a coordinated, multi-stage attack.`,
    ExploitedTrustedProcess:
      target
        ? `Trusted process "${actor}" spawned confirmed-malicious child "${target}" — classic living-off-the-land delivery or exploitation of a legitimate binary (T1059/T1204).`
        : `A trusted process spawned a confirmed-malicious child — living-off-the-land delivery or exploitation of a legitimate binary.`,
  };

  return {
    pattern: chain.pattern,
    sentence: sentences[chain.pattern] ?? chain.description,
    mitre: chain.mitre_tactic,
  };
}

// ─── Post-verdict action engine ───────────────────────────────────────────────

/** A single containment action suggested for a given attack chain. */
interface SuggestedAction {
  /** Stable key for React. */
  id: string;
  /** Short label shown on the confirm button, e.g. "Kill chrome.exe (PID 1234)". */
  label: string;
  /** One-line explanation shown in grey below the label. */
  description: string;
  /** Tauri command name, e.g. "kill_process". */
  cmd: string;
  /** Arguments object passed to invoke(). */
  args: Record<string, unknown>;
  /** Severity tier that gates this action: Suspicious = investigate; Malicious = disrupt; Critical = contain. */
  tier: 'Investigate' | 'Disrupt' | 'Contain';
}

type ActionStatus = 'idle' | 'running' | 'done' | 'error' | 'skipped';

/**
 * Build the list of suggested containment actions for a given attack chain.
 * Parameters are extracted from the chain's node data (PIDs, paths, IPs).
 */
/**
 * Build the list of suggested containment actions for a given attack chain.
 * Parameters are extracted from chain node data (PIDs, paths) and the live
 * network connection list (remote IPs for C2/Lateral patterns).
 *
 * @param netConnsByPid  Map of pid → remote_address strings, derived from
 *                       the NetworkConnection store slice.  Used to look up
 *                       C2 remote IPs that are not stored on GraphNode itself.
 */
function buildActions(
  chain:        AttackChain,
  nodeMap:      Record<string, GraphNodeData>,
  netConnsByPid: Map<number, string[]>,
): SuggestedAction[] {
  const nodes  = chain.node_ids.map(id => nodeMap[id]).filter(Boolean) as GraphNodeData[];
  // first / second by analyzer ordering (attacker → victim)
  const first  = nodes[0];
  const second = nodes[1];
  const actions: SuggestedAction[] = [];

  // Helper: collect remote IPs for a process PID from the live network store
  const remoteIpsForPid = (pid: number | undefined | null): string[] =>
    pid != null ? (netConnsByPid.get(pid) ?? []) : [];

  switch (chain.pattern) {

    // ── ProcessInjection ─────────────────────────────────────────────────────
    // Dump then kill the injected process + check persistence.
    case 'ProcessInjection': {
      if (first?.pid != null) {
        actions.push({
          id: `dump-${first.pid}`,
          label: `Dump memory of "${first.label}" (PID ${first.pid})`,
          description: 'Write a full MiniDump to %PROGRAMDATA%\\AegisAI\\dumps\\ first — preserves shellcode for forensics.',
          cmd: 'dump_memory', args: { pid: first.pid },
          tier: 'Investigate',
        });
        actions.push({
          id: `kill-${first.pid}`,
          label: `Kill "${first.label}" (PID ${first.pid})`,
          description: 'Terminate the process with a malicious memory region to halt shellcode execution.',
          cmd: 'kill_process', args: { pid: first.pid },
          tier: 'Disrupt',
        });
      }
      actions.push({
        id: `persist-check-${chain.chain_id}`,
        label: 'Check persistence entries',
        description: 'Scan registry run keys, scheduled tasks, and startup folders for the injected process.',
        cmd: 'check_persistence',
        args: { suspicious_paths: nodes.map(n => n.sub_label ?? n.label).filter(Boolean) },
        tier: 'Investigate',
      });
      break;
    }

    // ── C2Communication ──────────────────────────────────────────────────────
    // Kill the beaconing process + firewall-block the remote IPs it is using.
    // Remote IPs come from the live network connection store (not on GraphNode).
    case 'C2Communication': {
      if (first?.pid != null) {
        actions.push({
          id: `kill-${first.pid}`,
          label: `Kill "${first.label}" (PID ${first.pid})`,
          description: 'Terminate the process that is actively communicating with a C2 server.',
          cmd: 'kill_process', args: { pid: first.pid },
          tier: 'Disrupt',
        });
      }
      // Use live network store to find remote IPs for this pid
      const c2Ips = remoteIpsForPid(first?.pid);
      if (c2Ips.length > 0) {
        c2Ips.slice(0, 3).forEach(ip => {          // cap at 3 IPs
          actions.push({
            id: `block-out-${ip}`,
            label: `Block outbound to ${ip}`,
            description: 'Add a Windows Firewall deny rule blocking outbound traffic to this C2 address.',
            cmd: 'block_ip', args: { remote_ip: ip, direction: 'out' },
            tier: 'Disrupt',
          });
          actions.push({
            id: `block-in-${ip}`,
            label: `Block inbound from ${ip}`,
            description: 'Prevent the C2 server from re-connecting or pushing further payloads.',
            cmd: 'block_ip', args: { remote_ip: ip, direction: 'in' },
            tier: 'Contain',
          });
        });
      } else {
        // No live IP data — guide the user to the network monitor
        actions.push({
          id: `c2-no-ip-hint-${chain.chain_id}`,
          label: 'Open Network monitor to find C2 IP',
          description: 'No live network data found for this PID. Run a Network scan, then return here to block the remote address.',
          cmd: 'check_persistence',    // safe read-only cmd used as placeholder
          args: { suspicious_paths: [] },
          tier: 'Investigate',
        });
      }
      break;
    }

    // ── MalwareExecution ─────────────────────────────────────────────────────
    // Kill the process + quarantine the malicious executable on disk.
    case 'MalwareExecution': {
      if (first?.pid != null) {
        actions.push({
          id: `kill-${first.pid}`,
          label: `Kill "${first.label}" (PID ${first.pid})`,
          description: 'Terminate the running malware process.',
          cmd: 'kill_process', args: { pid: first.pid },
          tier: 'Disrupt',
        });
      }
      // sub_label on a process-anchored entity is the exe_path
      const exePath = first?.sub_label ?? null;
      if (exePath) {
        actions.push({
          id: `quarantine-${exePath}`,
          label: `Quarantine "${exePath.split(/[/\\]/).pop()}"`,
          description: `Move the malicious file to %PROGRAMDATA%\\AegisAI\\quarantine\\: ${exePath}`,
          cmd: 'quarantine_file', args: { path: exePath },
          tier: 'Contain',
        });
      }
      actions.push({
        id: `persist-mal-${chain.chain_id}`,
        label: 'Check persistence entries',
        description: 'Scan autorun locations to ensure the malware has not installed a re-launch mechanism.',
        cmd: 'check_persistence',
        args: { suspicious_paths: nodes.map(n => n.sub_label ?? n.label).filter(Boolean) },
        tier: 'Investigate',
      });
      break;
    }

    // ── LateralMovement ──────────────────────────────────────────────────────
    // Kill child then parent. Block child's outbound remote IPs.
    case 'LateralMovement': {
      // second node is the child that opened the network connection
      if (second?.pid != null) {
        actions.push({
          id: `kill-child-${second.pid}`,
          label: `Kill child "${second.label}" (PID ${second.pid})`,
          description: 'Terminate the laterally-moving child process first.',
          cmd: 'kill_process', args: { pid: second.pid },
          tier: 'Disrupt',
        });
      }
      if (first?.pid != null) {
        actions.push({
          id: `kill-parent-${first.pid}`,
          label: `Kill parent "${first.label}" (PID ${first.pid})`,
          description: 'Terminate the dropper/parent after the child is stopped.',
          cmd: 'kill_process', args: { pid: first.pid },
          tier: 'Disrupt',
        });
      }
      // Block IPs used by the child process
      const childIps = remoteIpsForPid(second?.pid);
      if (childIps.length > 0) {
        childIps.slice(0, 2).forEach(ip => {
          actions.push({
            id: `block-lateral-${ip}`,
            label: `Block child's remote IP ${ip}`,
            description: 'Firewall-block the lateral-movement destination.',
            cmd: 'block_ip', args: { remote_ip: ip, direction: 'out' },
            tier: 'Contain',
          });
        });
      }
      actions.push({
        id: `persist-lateral-${chain.chain_id}`,
        label: 'Check persistence for both processes',
        description: 'Scan registry and scheduled tasks for the parent and child processes.',
        cmd: 'check_persistence',
        args: { suspicious_paths: nodes.map(n => n.sub_label ?? n.label).filter(Boolean) },
        tier: 'Investigate',
      });
      break;
    }

    // ── SuspiciousSpawn ──────────────────────────────────────────────────────
    // Kill child first; kill parent too (both are flagged threats).
    case 'SuspiciousSpawn': {
      if (second?.pid != null) {
        actions.push({
          id: `kill-spawn-child-${second.pid}`,
          label: `Kill child "${second.label}" (PID ${second.pid})`,
          description: 'Terminate the spawned threat-level child process first.',
          cmd: 'kill_process', args: { pid: second.pid },
          tier: 'Disrupt',
        });
      }
      if (first?.pid != null) {
        actions.push({
          id: `kill-spawn-parent-${first.pid}`,
          label: `Kill parent "${first.label}" (PID ${first.pid})`,
          description: 'Terminate the threat-level parent that initiated the suspicious spawn.',
          cmd: 'kill_process', args: { pid: first.pid },
          tier: 'Disrupt',
        });
      }
      actions.push({
        id: `persist-spawn-${chain.chain_id}`,
        label: 'Check persistence for spawn chain',
        description: 'Scan registry autorun keys and scheduled tasks for both processes.',
        cmd: 'check_persistence',
        args: { suspicious_paths: nodes.map(n => n.sub_label ?? n.label).filter(Boolean) },
        tier: 'Investigate',
      });
      break;
    }

    // ── MultiStageAttack ─────────────────────────────────────────────────────
    // Kill all + dump all + quarantine files + isolate network.
    case 'MultiStageAttack': {
      nodes.forEach(n => {
        if (n.pid != null) {
          actions.push({
            id: `dump-multi-${n.pid}`,
            label: `Dump memory of "${n.label}" (PID ${n.pid})`,
            description: 'Capture full process memory before termination — preserves malware artifacts.',
            cmd: 'dump_memory', args: { pid: n.pid },
            tier: 'Investigate',
          });
        }
      });
      nodes.forEach(n => {
        if (n.pid != null) {
          actions.push({
            id: `kill-multi-${n.pid}`,
            label: `Kill "${n.label}" (PID ${n.pid})`,
            description: `Terminate stage process "${n.label}".`,
            cmd: 'kill_process', args: { pid: n.pid },
            tier: 'Disrupt',
          });
        }
      });
      const exePaths = [...new Set(nodes.map(n => n.sub_label).filter(Boolean) as string[])];
      exePaths.forEach(p => {
        actions.push({
          id: `quarantine-multi-${p}`,
          label: `Quarantine "${p.split(/[/\\]/).pop()}"`,
          description: `Move file to quarantine: ${p}`,
          cmd: 'quarantine_file', args: { path: p },
          tier: 'Contain',
        });
      });
      actions.push({
        id: `isolate-${chain.chain_id}`,
        label: 'Isolate all network adapters',
        description: 'Disable every connected interface to cut off C2 and stop lateral spread. Run restore_network to re-enable.',
        cmd: 'isolate_network', args: {},
        tier: 'Contain',
      });
      break;
    }

    // ── ExploitedTrustedProcess ──────────────────────────────────────────────
    // Kill child only (NOT the trusted parent). Quarantine child exe + check persistence.
    case 'ExploitedTrustedProcess': {
      // first = trusted parent (do NOT kill); second = malicious child
      if (second?.pid != null) {
        actions.push({
          id: `kill-exploited-child-${second.pid}`,
          label: `Kill malicious child "${second.label}" (PID ${second.pid})`,
          description: 'Terminate only the malicious child — the trusted parent is intentionally preserved.',
          cmd: 'kill_process', args: { pid: second.pid },
          tier: 'Disrupt',
        });
      }
      const childExe = second?.sub_label ?? null;
      if (childExe) {
        actions.push({
          id: `quarantine-exploited-${childExe}`,
          label: `Quarantine "${childExe.split(/[/\\]/).pop()}"`,
          description: `Quarantine the LOLBin-delivered payload: ${childExe}`,
          cmd: 'quarantine_file', args: { path: childExe },
          tier: 'Contain',
        });
      }
      actions.push({
        id: `persist-lolbin-${chain.chain_id}`,
        label: 'Check persistence for LOLBin delivery',
        description: 'Scan for scheduled tasks or registry entries that re-launch the payload via the trusted binary.',
        cmd: 'check_persistence',
        args: { suspicious_paths: [second?.sub_label, second?.label, first?.label].filter(Boolean) },
        tier: 'Investigate',
      });
      break;
    }

    default:
      break;
  }

  // Universal fallback — every pattern always shows at least a persistence check
  // so the ActionPanel is never empty and `return null` is never hit.
  if (actions.length === 0) {
    actions.push({
      id: `persist-fallback-${chain.chain_id}`,
      label: `Check persistence for "${nodes[0]?.label ?? chain.pattern}"`,
      description: 'Scan registry autorun keys, scheduled tasks, and startup folders for any entries related to this detection.',
      cmd: 'check_persistence',
      args: { suspicious_paths: nodes.map(n => n.sub_label ?? n.label).filter(Boolean) },
      tier: 'Investigate',
    });
  }

  return actions;
}

// ─── Tier badge colours ───────────────────────────────────────────────────────
const TIER_COLOR: Record<SuggestedAction['tier'], string> = {
  Investigate: '#818cf8',  // indigo
  Disrupt:     '#ffb300',  // amber
  Contain:     '#ff3355',  // red
};

// ─── Single action row ────────────────────────────────────────────────────────

function ActionRow({
  action,
  status,
  result,
  onConfirm,
  onSkip,
}: {
  action:    SuggestedAction;
  status:    ActionStatus;
  result:    string | null;
  onConfirm: () => void;
  onSkip:    () => void;
}) {
  const tierColor = TIER_COLOR[action.tier];
  const isDone    = status === 'done' || status === 'skipped';

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: 5,
      padding: '9px 12px',
      background: status === 'done'    ? 'rgba(0,255,136,0.05)'
                : status === 'error'   ? 'rgba(255,51,85,0.06)'
                : status === 'skipped' ? 'rgba(100,100,100,0.04)'
                : `${tierColor}08`,
      border: `1px solid ${
        status === 'done'    ? 'rgba(0,255,136,0.25)'
        : status === 'error' ? 'rgba(255,51,85,0.25)'
        : status === 'skipped' ? 'var(--border)'
        : `${tierColor}35`}`,
      borderRadius: 6,
      opacity: status === 'skipped' ? 0.5 : 1,
      transition: 'opacity 0.2s',
    }}>
      {/* Top row: tier badge + label */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 7, fontWeight: 700,
          color: tierColor, background: `${tierColor}20`,
          padding: '1px 5px', borderRadius: 2, flexShrink: 0,
          letterSpacing: '0.08em',
        }}>
          {action.tier.toUpperCase()}
        </span>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)',
          fontWeight: 600, flex: 1,
        }}>
          {action.label}
        </span>
        {/* Status indicator */}
        {status === 'running' && (
          <span style={{ fontSize: 10, color: '#ffb300', animation: 'pulse 1s infinite' }}>
            running…
          </span>
        )}
        {status === 'done' && (
          <CheckCircle size={13} color="#00ff88" />
        )}
        {status === 'error' && (
          <AlertTriangle size={13} color="#ff3355" />
        )}
        {status === 'skipped' && (
          <span style={{ fontSize: 9, color: 'var(--text-dim)' }}>skipped</span>
        )}
      </div>

      {/* Description */}
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
        lineHeight: 1.5,
      }}>
        {action.description}
      </div>

      {/* Result message */}
      {result && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9,
          color: status === 'error' ? '#ff3355' : '#00ff88',
          background: status === 'error' ? 'rgba(255,51,85,0.08)' : 'rgba(0,255,136,0.06)',
          padding: '4px 8px', borderRadius: 3,
          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}>
          {result}
        </div>
      )}

      {/* Confirm / Skip buttons — hide once resolved */}
      {!isDone && status !== 'running' && (
        <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
          <button
            onClick={onConfirm}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '4px 12px',
              background: tierColor, color: '#000',
              border: 'none', borderRadius: 4,
              fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
              cursor: 'pointer',
            }}>
            <Play size={9} /> Execute
          </button>
          <button
            onClick={onSkip}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '4px 12px',
              background: 'transparent', color: 'var(--text-dim)',
              border: '1px solid var(--border)', borderRadius: 4,
              fontFamily: 'var(--font-mono)', fontSize: 10,
              cursor: 'pointer',
            }}>
            <SkipForward size={9} /> Skip
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Action panel ─────────────────────────────────────────────────────────────

function ActionPanel({
  chain,
  nodeMap,
}: {
  chain:   AttackChain;
  nodeMap: Record<string, GraphNodeData>;
}) {
  // Pull live network connections so we can look up C2/lateral remote IPs by PID
  const { networkConnections, recordExecutedAction, runAgentReassessment, agentVerdict } = useStore();

  // Build pid → remote_address[] map from the live network store
  const netConnsByPid = useMemo(() => {
    const map = new Map<number, string[]>();
    for (const conn of networkConnections) {
      const pid = conn.pid;
      if (pid == null) continue;
      const ip = conn.remote_address?.split(':')?.[0];   // strip port
      if (!ip || ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '::1') continue;
      const existing = map.get(pid) ?? [];
      if (!existing.includes(ip)) existing.push(ip);
      map.set(pid, existing);
    }
    return map;
  }, [networkConnections]);

  const actions = useMemo(
    () => buildActions(chain, nodeMap, netConnsByPid),
    [chain, nodeMap, netConnsByPid],
  );
  const [statuses, setStatuses] = useState<Record<string, ActionStatus>>({});
  const [results,  setResults]  = useState<Record<string, string | null>>({});
  // Default open so actions are immediately visible when the chain card expands
  const [panelOpen, setPanelOpen] = useState(true);

  const getStatus = (id: string): ActionStatus => statuses[id] ?? 'idle';

  const handleConfirm = useCallback(async (action: SuggestedAction) => {
    setStatuses(s => ({ ...s, [action.id]: 'running' }));
    setResults(r  => ({ ...r, [action.id]: null }));
    const executedAt = new Date().toISOString();

    try {
      const res = await invoke(action.cmd, action.args);
      // Stringify the result for display (most results are JSON objects)
      const text = typeof res === 'string'
        ? res
        : JSON.stringify(res, null, 2);
      setResults(r  => ({ ...r, [action.id]: text }));
      setStatuses(s => ({ ...s, [action.id]: 'done' }));
      // Record the executed action for Round 2 re-assessment
      recordExecutedAction({
        action:      action.cmd,
        target:      String(action.args['path'] ?? action.args['remote_ip'] ?? action.args['pid'] ?? action.args['rule_name'] ?? ''),
        entity_id:   '',
        executed_at: executedAt,
        result:      'success',
        pid:         typeof action.args['pid'] === 'number' ? action.args['pid'] : null,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setResults(r  => ({ ...r, [action.id]: msg }));
      setStatuses(s => ({ ...s, [action.id]: 'error' }));
    }
  }, [recordExecutedAction]);

  const handleSkip = useCallback((id: string) => {
    setStatuses(s => ({ ...s, [id]: 'skipped' }));
  }, []);

  if (actions.length === 0) return null;

  // Determine the highest tier present so the panel header can show it
  const tiers = actions.map(a => a.tier);
  const topTier: SuggestedAction['tier'] =
    tiers.includes('Contain')     ? 'Contain'
    : tiers.includes('Disrupt')   ? 'Disrupt'
    : 'Investigate';
  const topColor = TIER_COLOR[topTier];

  const totalActions  = actions.length;
  const doneActions   = actions.filter(a => ['done', 'skipped'].includes(getStatus(a.id))).length;
  const allResolved   = doneActions === totalActions;

  return (
    <div style={{
      marginTop: 10,
      border: `1px solid ${topColor}30`,
      borderRadius: 7,
      overflow: 'hidden',
    }}>
      {/* Panel toggle header */}
      <button
        onClick={() => setPanelOpen(v => !v)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 12px',
          background: `${topColor}10`,
          border: 'none', cursor: 'pointer', textAlign: 'left',
        }}>
        {topTier === 'Contain'
          ? <ShieldOff size={13} color={topColor} />
          : topTier === 'Disrupt'
            ? <ShieldAlert size={13} color={topColor} />
            : <Siren size={13} color={topColor} />}
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
          color: topColor, letterSpacing: '0.1em', flex: 1,
        }}>
          SUGGESTED ACTIONS ({doneActions}/{totalActions} resolved)
        </span>
        {allResolved && <CheckCircle size={11} color="#00ff88" />}
        {panelOpen ? <ChevronDown size={11} color="var(--text-dim)" /> : <ChevronRight size={11} color="var(--text-dim)" />}
      </button>

      {panelOpen && (
        <div style={{
          padding: '8px 10px',
          display: 'flex', flexDirection: 'column', gap: 6,
          background: 'var(--void)',
        }}>
          {/* Tier legend */}
          <div style={{
            display: 'flex', gap: 10, fontSize: 8,
            fontFamily: 'var(--font-mono)', color: 'var(--text-dim)',
            marginBottom: 2,
          }}>
            {(['Investigate', 'Disrupt', 'Contain'] as const).map(t => (
              <span key={t} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{
                  width: 8, height: 8, borderRadius: '50%',
                  background: TIER_COLOR[t], display: 'inline-block',
                }} />
                {t}
              </span>
            ))}
          </div>

          {actions.map(action => (
            <ActionRow
              key={action.id}
              action={action}
              status={getStatus(action.id)}
              result={results[action.id] ?? null}
              onConfirm={() => handleConfirm(action)}
              onSkip={() => handleSkip(action.id)}
            />
          ))}

          {allResolved && (
            <div style={{
              marginTop: 4, display: 'flex', flexDirection: 'column', gap: 6,
              alignItems: 'center',
            }}>
              <div style={{
                fontSize: 9, color: '#00ff88',
                fontFamily: 'var(--font-mono)', opacity: 0.8,
              }}>
                All actions resolved.
              </div>
              {/* Re-assess button — only show if AI agent has an active verdict */}
              {agentVerdict && !agentVerdict.investigation_closed && (
                <button
                  onClick={runAgentReassessment}
                  style={{
                    padding: '5px 14px',
                    background: 'rgba(167,139,250,0.1)',
                    border: '1px solid rgba(167,139,250,0.4)',
                    borderRadius: 5,
                    color: '#a78bfa',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 9,
                    fontWeight: 700,
                    cursor: 'pointer',
                    letterSpacing: '0.06em',
                  }}
                >
                  Re-assess with AI →
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function mlCoverage(nodes: GraphNodeData[]): string {
  const total = nodes.length;
  const withMl = nodes.filter(n => n.ml_score != null).length;
  if (withMl === 0) return 'ML scoring was not available for any entity in this verdict — scores reflect heuristic analysis only.';
  if (withMl < total) return `ML scoring available for ${withMl} of ${total} entities. Remaining scores are heuristic-only.`;
  return '';
}

function overallSummary(
  severity: Severity,
  chains: AttackChain[],
  cp: CriticalPath | null | undefined,
  nodesInVerdict: GraphNodeData[],
): string {
  if (chains.length === 0) {
    return 'The graph found no attack patterns and no critical path. The system appears clean based on current scan data.';
  }

  const patternNames = [...new Set(chains.map(c => c.pattern))];
  const patternList = patternNames.length === 1
    ? patternNames[0]
    : patternNames.slice(0, -1).join(', ') + ' and ' + patternNames[patternNames.length - 1];

  const entityCount = nodesInVerdict.length;
  const entityWord = entityCount === 1 ? 'entity' : 'entities';

  let base = `The graph identified ${chains.length} attack chain${chains.length > 1 ? 's' : ''} `
    + `(${patternList}) across ${entityCount} ${entityWord}. `;

  if (severity === 'Critical') {
    base += 'Threat level is CRITICAL — immediate action is required.';
  } else if (severity === 'Malicious') {
    base += 'Threat level is MALICIOUS — confirmed malicious activity detected.';
  } else if (severity === 'Suspicious') {
    base += 'Threat level is SUSPICIOUS — further investigation is warranted.';
  }

  if (cp && cp.node_ids.length > 1) {
    base += ` The highest-weight path through the graph is: ${cp.narrative}`;
  }

  return base;
}

// ─── Critical path directed graph ────────────────────────────────────────────

// ─── Layout constants ─────────────────────────────────────────────────────────
const CPG_R    = 24;   // node circle radius
const CPG_STEP = 112;  // horizontal distance between node centres
const CPG_VH   = 300;  // SVG viewport height
const CPG_CY   = 150;  // centre-line Y (spine)
const CPG_VY   = 80;   // vertical offset for upper / lower rows

// Edge colour lookup (edge_type string → hex)
const EDGE_COLOR_MAP: Record<string, string> = {
  parent_child:     '#00d4ff',
  shared_c2:        '#facc15',
  shared_file_hash: '#34d399',
};
function edgeColor(t: string): string { return EDGE_COLOR_MAP[t] ?? '#00d4ff'; }

// All distinct hex colours used by arrows (for <marker> generation)
const ARROW_COLORS = ['#00d4ff', '#facc15', '#34d399', '#888888'];

// Node Y position:
//   index 0 and N-1  → spine (centre)
//   index 1, 3, 5 …  → upper row
//   index 2, 4, 6 …  → lower row  (i.e. same depth as ref image E→a→b→…→S)
function nodeY(i: number, N: number): number {
  if (i === 0 || i === N - 1) return CPG_CY;
  return i % 2 === 1 ? CPG_CY - CPG_VY : CPG_CY + CPG_VY;
}
function nodeX(i: number): number { return 54 + i * CPG_STEP; }

function CriticalPathGraph({
  criticalPath,
  nodeMap,
}: {
  criticalPath: CriticalPath | null | undefined;
  nodeMap: Record<string, GraphNodeData>;
}) {
  const [hovered, setHovered] = useState<string | null>(null);

  if (!criticalPath || criticalPath.node_ids.length === 0) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', height: '100%', gap: 10,
        color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 11,
      }}>
        <Info size={22} style={{ opacity: 0.35 }} />
        <span>No critical path — run a correlation scan first.</span>
      </div>
    );
  }

  const ids = criticalPath.node_ids;
  const N   = ids.length;
  const vW  = Math.max(nodeX(N - 1) + 60, 400);

  return (
    <div style={{ width: '100%', height: '100%', overflowX: 'auto', overflowY: 'hidden' }}>
      <svg width={vW} height={CPG_VH} viewBox={`0 0 ${vW} ${CPG_VH}`}
        style={{ display: 'block' }}>
        <defs>
          <filter id="glow-cp">
            <feGaussianBlur stdDeviation="2.5" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          {/* One arrowhead per colour */}
          {ARROW_COLORS.map(c => (
            <marker key={c} id={`ar-${c.slice(1)}`}
              markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L0,6 L8,3 z" fill={c}/>
            </marker>
          ))}
        </defs>

        {/* ── Edges ──────────────────────────────────────────────────────────── */}
        {ids.slice(0, -1).map((_, i) => {
          const ax = nodeX(i),     ay = nodeY(i, N);
          const bx = nodeX(i + 1), by = nodeY(i + 1, N);
          const etype = criticalPath.edge_types?.[i]   ?? 'parent_child';
          const w     = criticalPath.edge_weights?.[i] ?? 0;
          const col   = edgeColor(etype);
          const hex   = col.slice(1);

          // Arrow starts / ends at circle boundary
          const dx = bx - ax, dy = by - ay;
          const len = Math.sqrt(dx*dx + dy*dy) || 1;
          const ux = dx/len, uy = dy/len;
          const x1 = ax + ux * CPG_R, y1 = ay + uy * CPG_R;
          const x2 = bx - ux * (CPG_R + 9), y2 = by - uy * (CPG_R + 9);

          // Weight label: midpoint + small perpendicular offset (so it sits
          // beside the line, not on top of it — exactly like the reference image)
          const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
          // Perpendicular unit vector (rotated 90° CCW)
          const px = -uy, py = ux;
          const off = 14;  // px offset away from the line
          const lx = mx + px * off, ly = my + py * off;

          return (
            <g key={`e${i}`}>
              <line x1={x1} y1={y1} x2={x2} y2={y2}
                stroke={col} strokeWidth={1.5} strokeOpacity={0.9}
                markerEnd={`url(#ar-${hex})`}/>
              {/* Weight number — plain, like the reference image */}
              <text x={lx} y={ly} textAnchor="middle" dominantBaseline="middle"
                fill={col} fontSize={11} fontFamily="var(--font-mono)" fontWeight={700}>
                {w.toFixed(2)}
              </text>
              {/* Edge type — tiny, just below the weight */}
              <text x={lx} y={ly + 13} textAnchor="middle" dominantBaseline="middle"
                fill={col} fontSize={7} fontFamily="var(--font-mono)" opacity={0.65}>
                {etype.replace(/_/g, ' ')}
              </text>
            </g>
          );
        })}

        {/* ── Nodes ──────────────────────────────────────────────────────────── */}
        {ids.map((id, i) => {
          const x      = nodeX(i), y = nodeY(i, N);
          const node   = nodeMap[id];
          const isHov  = hovered === id;
          const col    = node ? threatColor(node.threat_level) : '#888';
          const score  = node?.combined_score ?? 0;
          const ml     = node?.ml_score;
          // Short label: strip .exe, keep ≤9 chars
          const raw    = node?.label ?? id.split(':')[1] ?? id;
          const label  = raw.replace(/\.exe$/i, '');
          const short  = label.length > 9 ? label.slice(0, 8) + '…' : label;
          const circ   = 2 * Math.PI * CPG_R;
          const isFirst = i === 0, isLast = i === N - 1;

          // Tooltip flips left for nodes near the right edge
          const flipTip = i >= N - 2;
          const tipX    = flipTip ? -(CPG_R + 162) : CPG_R + 8;

          return (
            <g key={id} transform={`translate(${x},${y})`}
              onMouseEnter={() => setHovered(id)}
              onMouseLeave={() => setHovered(null)}
              style={{ cursor: 'default' }}>

              {/* Origin / endpoint dashed ring — mirrors the reference's E and S */}
              {isFirst && (
                <circle r={CPG_R + 7} fill="none"
                  stroke="#00ff88" strokeWidth={1.5} strokeDasharray="4 3" opacity={0.55}/>
              )}
              {isLast && (
                <circle r={CPG_R + 7} fill="none"
                  stroke="#ff3355" strokeWidth={1.5} strokeDasharray="4 3" opacity={0.65}/>
              )}

              {/* Main circle */}
              <circle r={CPG_R} fill={`${col}1a`} stroke={col}
                strokeWidth={isHov ? 2.5 : 1.8}
                filter={isHov ? 'url(#glow-cp)' : undefined}/>

              {/* Score arc (thin, clockwise from top) */}
              <circle r={CPG_R} fill="none"
                stroke={col} strokeWidth={3.5} strokeOpacity={0.35}
                strokeDasharray={`${score * circ} ${circ}`}
                strokeLinecap="round"
                transform="rotate(-90)"/>

              {/* Short process name — centred inside the circle */}
              <text textAnchor="middle" dominantBaseline="middle" y={0}
                fill={col} fontSize={8} fontFamily="var(--font-mono)" fontWeight={700}>
                {short}
              </text>

              {/* ── Labels below the circle ── */}
              {/* Score % */}
              <text textAnchor="middle" y={CPG_R + 14}
                fill="var(--text)" fontSize={10} fontFamily="var(--font-mono)" fontWeight={700}>
                {(score * 100).toFixed(0)}%
              </text>
              {/* Threat level */}
              <text textAnchor="middle" y={CPG_R + 26}
                fill={col} fontSize={7} fontFamily="var(--font-mono)" fontWeight={700}>
                {node?.threat_level ?? ''}
              </text>
              {/* ML indicator */}
              <text textAnchor="middle" y={CPG_R + 37}
                fill={ml != null ? '#818cf8' : 'var(--text-dim)'}
                fontSize={7} fontFamily="var(--font-mono)">
                {ml != null ? `ML ${(ml * 100).toFixed(0)}%` : 'ML N/A'}
              </text>

              {/* Hover tooltip */}
              {isHov && node && (
                <g>
                  <rect x={tipX} y={-60} width={158} height={130}
                    rx={4} fill="var(--elevated)" stroke="var(--border)" strokeWidth={1}/>
                  {[
                    { t: node.label,                                   dy: -44, c: 'var(--text)', w: 700, s: 9 },
                    { t: `${node.threat_level} · ${(score*100).toFixed(0)}%`, dy: -31, c: col,           w: 400, s: 8 },
                    { t: ml != null ? `ML: ${(ml*100).toFixed(1)}%` : 'ML: not available', dy: -19, c: '#818cf8', w: 400, s: 7 },
                    { t: `PROC ${((node.process_score??0)*100).toFixed(0)}  NET ${((node.network_score??0)*100).toFixed(0)}  MEM ${((node.memory_score??0)*100).toFixed(0)}`, dy: -7, c: 'var(--text-dim)', w: 400, s: 7 },
                    { t: `FILE ${((node.file_score??0)*100).toFixed(0)}`,       dy:  5, c: 'var(--text-dim)', w: 400, s: 7 },
                    { t: `type: ${node.entity_type ?? '?'}  pid: ${node.pid ?? '—'}`, dy: 17, c: 'var(--text-dim)', w: 400, s: 7 },
                    { t: (node.sub_label ?? node.entity_id).slice(-24),           dy: 29, c: 'var(--text-dim)', w: 400, s: 7 },
                    { t: `step ${i + 1} / ${N}`,                                  dy: 55, c: 'var(--text-dim)', w: 400, s: 7 },
                  ].map(({ t, dy, c, w, s }) => (
                    <text key={dy} x={tipX + 8} y={dy}
                      fill={c} fontSize={s} fontFamily="var(--font-mono)" fontWeight={w}>
                      {t}
                    </text>
                  ))}
                </g>
              )}
            </g>
          );
        })}

        {/* Total score — bottom-right corner */}
        <text x={vW - 8} y={CPG_VH - 8} textAnchor="end"
          fill="var(--text-dim)" fontSize={8} fontFamily="var(--font-mono)" opacity={0.7}>
          total path score: {criticalPath.total_score.toFixed(3)}
        </text>
      </svg>
    </div>
  );
}

// ─── Chain card ───────────────────────────────────────────────────────────────

function ChainCard({
  chain, sentence, nodeMap,
}: {
  chain:    AttackChain;
  sentence: PatternSentence;
  nodeMap:  Record<string, GraphNodeData>;
}) {
  const [open, setOpen] = useState(false);
  const color = threatColor(chain.severity);

  return (
    <div style={{
      border: `1px solid ${color}40`,
      borderRadius: 8,
      background: `${color}08`,
      overflow: 'hidden',
      marginBottom: 8,
    }}>
      {/* Header row */}
      <button onClick={() => setOpen(v => !v)} style={{
        display: 'flex', alignItems: 'center', gap: 10,
        width: '100%', padding: '10px 14px',
        background: 'transparent', border: 'none', cursor: 'pointer',
        textAlign: 'left',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
          color, letterSpacing: '0.1em',
          background: `${color}20`, padding: '2px 6px', borderRadius: 3,
          flexShrink: 0,
        }}>
          {chain.severity.toUpperCase()}
        </span>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)',
          fontWeight: 600, flex: 1,
        }}>
          {chain.pattern}
        </span>
        {/* Score + confidence bars */}
        <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {/* Severity score */}
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{
              width: 52, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden',
            }}>
              <div style={{
                width: `${chain.chain_score * 100}%`, height: '100%',
                background: color, borderRadius: 2,
              }} />
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
              {(chain.chain_score * 100).toFixed(0)}%
            </span>
          </span>
          {/* Confidence */}
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{
              fontFamily: 'var(--font-mono)', fontSize: 7, color: 'var(--text-dim)',
              letterSpacing: '0.05em',
            }}>
              CONF
            </span>
            <div style={{
              width: 36, height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden',
            }}>
              <div style={{
                width: `${(chain.confidence ?? 0) * 100}%`, height: '100%',
                background: '#818cf8', borderRadius: 2,
              }} />
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#818cf8' }}>
              {((chain.confidence ?? 0) * 100).toFixed(0)}%
            </span>
          </span>
        </span>
        <span style={{ color: 'var(--text-dim)', marginLeft: 6 }}>
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </span>
      </button>

      {open && (
        <div style={{ padding: '0 14px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {/* Humanized sentence */}
          <p style={{
            fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)',
            lineHeight: 1.7, margin: 0,
          }}>
            {sentence.sentence}
          </p>

          {/* MITRE tag */}
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9, color: '#818cf8',
            background: 'rgba(129,140,248,0.1)', padding: '3px 8px', borderRadius: 3,
            alignSelf: 'flex-start',
          }}>
            {sentence.mitre}
          </div>

          {/* Involved entities */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 2 }}>
            {chain.node_ids.map(id => {
              const node = nodeMap[id];
              if (!node) return null;
              const nc = threatColor(node.threat_level);
              return (
                <span key={id} style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9,
                  color: nc, background: `${nc}15`,
                  border: `1px solid ${nc}40`,
                  padding: '2px 7px', borderRadius: 3,
                }}>
                  {node.label}
                  {node.is_lolbin && (
                    <span style={{
                      color: '#ff8c00', marginLeft: 4,
                      fontSize: 7, fontWeight: 700,
                    }}>LOLBin</span>
                  )}
                  {node.ml_score == null && (
                    <span style={{ color: 'var(--text-dim)', marginLeft: 4 }}>[ML:N/A]</span>
                  )}
                </span>
              );
            })}
          </div>

          {/* Per-chain action suggestions */}
          <ActionPanel chain={chain} nodeMap={nodeMap} />
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function GraphVerdict() {
  const {
    correlateResult, correlating, correlateError,
    correlateEntities, correlateFromStore, abortCorrelate,
    processes, networkConnections, memoryRegions, scanResults, mlIdsResult,
    actionsTaken,
  } = useStore();

  // ── Export incident report ─────────────────────────────────────────────────
  const [exporting,   setExporting]   = useState(false);
  const [exportDone,  setExportDone]  = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const handleExport = useCallback(async () => {
    if (!correlateResult) return;
    setExporting(true); setExportDone(false); setExportError(null);
    try {
      await invoke('export_incident_report', {
        correlateResult,
        actionsTaken: actionsTaken.map(a => ({ ...a })),
        outputPath:   undefined,
      });
      setExportDone(true);
      setTimeout(() => setExportDone(false), 3000);
    } catch (e: any) {
      setExportError(String(e));
    } finally {
      setExporting(false);
    }
  }, [correlateResult, actionsTaken]);

  // Whether there is enough store data to correlate without re-scanning
  const hasStoreData = processes.length > 0 || networkConnections.length > 0;

  // ── Derive verdict data ────────────────────────────────────────────────────
  const verdict = useMemo(() => {
    if (!correlateResult?.graph) return null;

    const { nodes: rawNodes, edges: rawEdges, attack_chains, critical_path } = correlateResult.graph;
    const nodeMap: Record<string, GraphNodeData> =
      Object.fromEntries(rawNodes.map(n => [n.entity_id, n]));

    // Collect all entity IDs referenced by any chain or the critical path
    const verdictIds = new Set<string>();
    attack_chains.forEach(c => c.node_ids.forEach(id => verdictIds.add(id)));
    if (critical_path) critical_path.node_ids.forEach(id => verdictIds.add(id));

    const criticalPathIds = new Set<string>(critical_path?.node_ids ?? []);

    // Filter nodes and edges to verdict participants only
    const verdictNodes = rawNodes.filter(n => verdictIds.has(n.entity_id));
    const verdictEdges = rawEdges.filter(
      e => verdictIds.has(e.from) && verdictIds.has(e.to),
    );

    const severity = worstSeverity(attack_chains);
    const sentences = attack_chains.map(c => humanizePattern(c, nodeMap));
    const summary   = overallSummary(severity, attack_chains, critical_path, verdictNodes);
    const mlNote    = mlCoverage(verdictNodes);

    return {
      severity, summary, mlNote,
      chains: attack_chains, sentences,
      criticalPath: critical_path ?? null,
      verdictNodes, verdictEdges,
      nodeMap, criticalPathIds,
      hasThreats: attack_chains.length > 0,
    };
  }, [correlateResult]);

  // ── Elapsed timer (resets when correlating starts) ────────────────────────
  const elapsedRef = useRef(0);
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!correlating) { elapsedRef.current = 0; setElapsed(0); return; }
    const start = Date.now();
    const interval = setInterval(() => {
      const s = Math.floor((Date.now() - start) / 1000);
      elapsedRef.current = s;
      setElapsed(s);
    }, 500);
    return () => clearInterval(interval);
  }, [correlating]);

  // ── Loading ────────────────────────────────────────────────────────────────
  if (correlating) {
    // Approximate stage windows (seconds). Process enum + exe scan is now fast
    // (only confirmed-malicious exes are file-scanned, capped at 5).
    // Network scan (pcap + threat scoring) is the new dominant step.
    const STEPS: { label: string; start: number; end: number; detail: string }[] = [
      { label: 'Process scan',    start: 0,   end: 30,  detail: 'Enumerating all running processes, handles, modules…' },
      { label: 'Exe file scan',   start: 5,   end: 60,  detail: 'YARA-scanning confirmed-malicious process executables (max 5)…' },
      { label: 'Network scan',    start: 15,  end: 180, detail: 'Capturing live connections, scoring, running ML IDS pipeline…' },
      { label: 'Entity pipeline', start: 60,  end: 270, detail: 'Aggregating entities, scoring, backfilling orphan PIDs…' },
      { label: 'Graph analysis',  start: 240, end: 300, detail: 'Building graph, detecting attack chains, critical path…' },
    ];

    function stepStatus(s: { start: number; end: number }) {
      if (elapsed > s.end) return 'done';
      if (elapsed >= s.start) return 'running';
      return 'pending';
    }

    const statusColor = { done: '#00ff88', running: '#ffb300', pending: 'var(--text-dim)' } as const;
    const statusLabel = { done: '✓', running: '▶', pending: '○' } as const;

    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', gap: 20,
      }}>
        <GitMerge size={36} style={{ opacity: 0.5 }} />

        {/* Elapsed clock */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text)' }}>
          <Clock size={14} style={{ opacity: 0.7 }} />
          <span>Correlating entities…</span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 14, color: '#ffb300',
            minWidth: 42, textAlign: 'right',
          }}>
            {elapsed}s
          </span>
        </div>

        {/* Step tracker */}
        <div style={{
          background: 'var(--base)',
          border: '1px solid var(--border)',
          borderRadius: 8, padding: '14px 20px',
          display: 'flex', flexDirection: 'column', gap: 12,
          minWidth: 380,
        }}>
          {STEPS.map(step => {
            const st = stepStatus(step);
            const col = statusColor[st];
            return (
              <div key={step.label} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {/* Status icon */}
                  <span style={{
                    width: 16, textAlign: 'center',
                    color: col, fontSize: 11, fontWeight: 700,
                  }}>
                    {statusLabel[st]}
                  </span>
                  {/* Step label */}
                  <span style={{
                    fontSize: 11, color: st === 'pending' ? 'var(--text-dim)' : 'var(--text)',
                    fontWeight: st === 'running' ? 700 : 400,
                    flex: 1,
                  }}>
                    {step.label}
                  </span>
                  {/* Time badge */}
                  <span style={{
                    fontSize: 9, color: col,
                    background: `${col}18`,
                    padding: '1px 6px', borderRadius: 3,
                  }}>
                    {st === 'done'    ? `~${step.end}s`
                    : st === 'running' ? `${elapsed}s / ~${step.end}s`
                    : `~${step.start}s`}
                  </span>
                </div>
                {/* Detail line when running */}
                {st === 'running' && (
                  <div style={{
                    marginLeft: 26, fontSize: 9, color: '#ffb300', opacity: 0.7, lineHeight: 1.5,
                  }}>
                    {step.detail}
                  </div>
                )}
              </div>
            );
          })}

          {/* Warning if taking longer than expected */}
          {elapsed > 300 && (
            <div style={{
              marginTop: 4, padding: '8px 10px',
              background: 'rgba(255,179,0,0.07)',
              border: '1px solid rgba(255,179,0,0.25)',
              borderRadius: 5, fontSize: 9,
              color: '#ffb300', lineHeight: 1.6,
            }}>
              ⚠ Taking longer than expected. Check the daemon stderr for per-step timings.
              Network scan (pcap) or ML pipeline may be the bottleneck.
              Timeout is 5 minutes.
            </div>
          )}
        </div>

        <button
          onClick={abortCorrelate}
          style={{
            padding: '6px 18px',
            background: 'transparent', color: 'var(--text-dim)',
            border: '1px solid var(--border)', borderRadius: 5,
            fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer',
          }}>
          CANCEL
        </button>
      </div>
    );
  }

  // ── Error state ────────────────────────────────────────────────────────────
  if (correlateError) {
    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', gap: 14,
      }}>
        <AlertTriangle size={36} color="#ff3355" style={{ opacity: 0.8 }} />
        <div style={{ fontSize: 13, color: '#ff3355' }}>Correlation failed</div>
        <div style={{
          fontSize: 10, color: 'var(--text-dim)', maxWidth: 420, textAlign: 'center',
          background: 'rgba(255,51,85,0.07)', border: '1px solid rgba(255,51,85,0.2)',
          borderRadius: 6, padding: '10px 16px', lineHeight: 1.7,
        }}>
          {correlateError}
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {hasStoreData && (
            <button onClick={correlateFromStore}
              style={{
                padding: '8px 20px',
                background: 'var(--green)', color: 'var(--void)',
                border: 'none', borderRadius: 5,
                fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                cursor: 'pointer',
              }}>
              ⚡ USE EXISTING DATA
            </button>
          )}
          <button onClick={() => correlateEntities(false)}
            style={{
              padding: '8px 20px',
              background: 'transparent', color: 'var(--text)',
              border: '1px solid var(--border)', borderRadius: 5,
              fontFamily: 'var(--font-mono)', fontSize: 11,
              cursor: 'pointer',
            }}>
            FULL RESCAN
          </button>
        </div>
      </div>
    );
  }

  // ── No result yet ──────────────────────────────────────────────────────────
  if (!correlateResult) {
    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', gap: 20,
      }}>
        <GitMerge size={40} style={{ opacity: 0.3 }} />
        <div style={{ fontSize: 13, color: 'var(--text)' }}>No correlation data available</div>

        {/* Available store data summary */}
        <div style={{
          display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'center',
          fontSize: 10,
        }}>
          {[
            { label: 'Processes',   count: processes.length,          color: processes.length > 0 ? 'var(--green)' : 'var(--text-dim)' },
            { label: 'Connections', count: networkConnections.length,  color: networkConnections.length > 0 ? '#00d4ff' : 'var(--text-dim)' },
            { label: 'Memory',      count: memoryRegions.length,       color: memoryRegions.length > 0 ? '#ffb300' : 'var(--text-dim)' },
            { label: 'Files',       count: scanResults.length,         color: scanResults.length > 0 ? '#34d399' : 'var(--text-dim)' },
            { label: 'ML flows',    count: mlIdsResult?.flows.length ?? 0, color: mlIdsResult ? '#818cf8' : 'var(--text-dim)' },
          ].map(({ label, count, color }) => (
            <span key={label} style={{
              padding: '3px 10px', borderRadius: 4,
              border: `1px solid ${count > 0 ? color + '60' : 'var(--border)'}`,
              color,
            }}>
              {count > 0 ? `${count}` : '—'} {label}
            </span>
          ))}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10, marginTop: 4 }}>
          {/* Fast path: use existing store data */}
          <button
            onClick={correlateFromStore}
            disabled={!hasStoreData}
            style={{
              padding: '9px 24px',
              background: hasStoreData ? 'var(--green)' : 'var(--border)',
              color: hasStoreData ? 'var(--void)' : 'var(--text-dim)',
              border: 'none', borderRadius: 5,
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              cursor: hasStoreData ? 'pointer' : 'not-allowed',
              opacity: hasStoreData ? 1 : 0.5,
            }}>
            ⚡ USE EXISTING SCAN DATA
          </button>
          <div style={{ fontSize: 9, color: 'var(--text-dim)' }}>
            {hasStoreData
              ? 'Builds the graph instantly from already-scanned data (with ML if run)'
              : 'Run the Process or Network scanner first'}
          </div>

          {/* Slow path: full re-scan via daemon */}
          <button
            onClick={() => correlateEntities(false)}
            style={{
              marginTop: 4, padding: '7px 20px',
              background: 'transparent', color: 'var(--text-dim)',
              border: '1px solid var(--border)', borderRadius: 5,
              fontFamily: 'var(--font-mono)', fontSize: 10,
              cursor: 'pointer',
            }}>
            FULL RESCAN (slow — runs all scanners)
          </button>
        </div>
      </div>
    );
  }

  // ── Result exists but graph payload is missing ─────────────────────────────
  if (!verdict) {
    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', gap: 14,
      }}>
        <Info size={32} style={{ opacity: 0.4 }} />
        <div style={{ fontSize: 13, color: 'var(--text)' }}>Graph data unavailable</div>
        <div style={{ fontSize: 10, maxWidth: 360, textAlign: 'center', lineHeight: 1.7 }}>
          The correlation completed but returned no graph payload.
          This usually means the engine daemon is not running or
          the correlate response was malformed.
        </div>
        <button onClick={() => correlateEntities(false)}
          style={{
            marginTop: 4, padding: '8px 20px',
            background: 'transparent', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: 5,
            fontFamily: 'var(--font-mono)', fontSize: 11, cursor: 'pointer',
          }}>
          RETRY
        </button>
      </div>
    );
  }

  const severityColor = threatColor(verdict.severity);
  const SeverityIcon = verdict.severity === 'Clean'
    ? CheckCircle
    : verdict.severity === 'Suspicious'
      ? AlertTriangle
      : Zap;

  return (
    <div style={{
      height: '100%', display: 'flex', overflow: 'hidden',
      fontFamily: 'var(--font-mono)',
      background: 'var(--void)',
    }}>

      {/* ── Left panel: verdict text ────────────────────────────────────────── */}
      <div style={{
        width: 480, flexShrink: 0,
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          padding: '18px 20px 14px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--base)',
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <SeverityIcon size={18} color={severityColor} />
            <span style={{ fontSize: 13, fontWeight: 700, color: severityColor, letterSpacing: '0.08em' }}>
              GRAPH VERDICT — {verdict.severity.toUpperCase()}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>
              {verdict.chains.length} attack chain{verdict.chains.length !== 1 ? 's' : ''} detected
              &nbsp;·&nbsp;
              {verdict.verdictNodes.length} entit{verdict.verdictNodes.length !== 1 ? 'ies' : 'y'} involved
            </span>

            {/* Export report button */}
            <button
              onClick={handleExport}
              disabled={exporting}
              title="Export structured incident report to Documents\AegisAI\"
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '3px 10px',
                background: exportDone
                  ? 'rgba(0,255,136,0.1)'
                  : 'rgba(129,140,248,0.08)',
                border: `1px solid ${exportDone ? 'rgba(0,255,136,0.35)' : 'rgba(129,140,248,0.3)'}`,
                borderRadius: 4,
                color: exportDone ? '#00ff88' : '#818cf8',
                fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 600,
                cursor: exporting ? 'wait' : 'pointer',
                opacity: exporting ? 0.6 : 1,
              }}>
              {exportDone
                ? <><CheckCircle size={10} /> Saved</>
                : <><FileText size={10} /> {exporting ? 'Exporting…' : 'Export Report'}</>}
            </button>

            {exportError && (
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: 8, color: '#ff3355',
              }}>
                {exportError}
              </span>
            )}
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 18 }}>

          {/* Overall summary */}
          <section>
            <div style={{ fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', marginBottom: 8 }}>
              SUMMARY
            </div>
            <p style={{
              margin: 0, fontSize: 12, color: 'var(--text)', lineHeight: 1.75,
              borderLeft: `2px solid ${severityColor}`,
              paddingLeft: 12,
            }}>
              {verdict.summary}
            </p>
          </section>

          {/* ML note */}
          {verdict.mlNote && (
            <div style={{
              display: 'flex', gap: 8, alignItems: 'flex-start',
              background: 'rgba(129,140,248,0.07)',
              border: '1px solid rgba(129,140,248,0.2)',
              borderRadius: 6, padding: '8px 12px',
            }}>
              <Info size={13} color="#818cf8" style={{ flexShrink: 0, marginTop: 1 }} />
              <span style={{ fontSize: 10, color: '#818cf8', lineHeight: 1.6 }}>
                {verdict.mlNote}
              </span>
            </div>
          )}

          {/* Attack chains */}
          {verdict.hasThreats && (
            <section>
              <div style={{ fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', marginBottom: 10 }}>
                DETECTED ATTACK CHAINS
              </div>
              {verdict.chains.map((chain, i) => (
                <ChainCard
                  key={chain.chain_id}
                  chain={chain}
                  sentence={verdict.sentences[i]}
                  nodeMap={verdict.nodeMap}
                />
              ))}
            </section>
          )}

          {/* No threats */}
          {!verdict.hasThreats && (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10,
              padding: '24px 0', color: '#00ff88',
            }}>
              <CheckCircle size={28} />
              <span style={{ fontSize: 12 }}>No attack patterns detected.</span>
              <span style={{ fontSize: 10, color: 'var(--text-dim)', textAlign: 'center' }}>
                The graph found no structural relationships between threat signals.<br />
                All entities are either clean or isolated.
              </span>
            </div>
          )}

          {/* Critical path */}
          {verdict.criticalPath && verdict.criticalPath.node_ids.length > 0 && (
            <section>
              <div style={{ fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', marginBottom: 8 }}>
                CRITICAL PATH
              </div>
              <div style={{
                border: '1px solid rgba(245,158,11,0.3)',
                borderRadius: 8, padding: '12px 14px',
                background: 'rgba(245,158,11,0.05)',
              }}>
                {/* Path hops */}
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 4, marginBottom: 10 }}>
                  {verdict.criticalPath.node_ids.map((id, i) => {
                    const node = verdict.nodeMap[id];
                    const label = node?.label ?? id;
                    const isLast = i === verdict.criticalPath!.node_ids.length - 1;
                    return (
                      <span key={id} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span style={{
                          fontFamily: 'var(--font-mono)', fontSize: 10,
                          color: '#f59e0b', fontWeight: 600,
                          background: 'rgba(245,158,11,0.12)',
                          padding: '2px 7px', borderRadius: 3,
                        }}>
                          {label}
                        </span>
                        {!isLast && (
                          <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>→</span>
                        )}
                      </span>
                    );
                  })}
                </div>

                {/* Narrative */}
                <p style={{
                  margin: 0, fontSize: 11, color: 'var(--text)', lineHeight: 1.7,
                  fontStyle: 'italic',
                }}>
                  "{verdict.criticalPath.narrative}"
                </p>

                {/* Total score */}
                <div style={{ marginTop: 8, fontSize: 9, color: 'var(--text-dim)' }}>
                  Path score: {verdict.criticalPath.total_score.toFixed(3)}
                </div>
              </div>
            </section>
          )}

          {/* Spacer */}
          <div style={{ height: 8 }} />
        </div>
      </div>

      {/* ── Right panel: critical path directed graph ──────────────────────── */}
      <div style={{
        flex: 1, display: 'flex', flexDirection: 'column',
        overflow: 'hidden', padding: '18px 20px',
      }}>
        {/* Panel header */}
        <div style={{
          fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', marginBottom: 14,
          display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <span>CRITICAL PATH</span>
          {verdict.criticalPath && verdict.criticalPath.node_ids.length > 0 && (
            <>
              <span style={{ color: 'var(--border)' }}>·</span>
              <span style={{ color: '#f59e0b' }}>
                {verdict.criticalPath.node_ids.length} node{verdict.criticalPath.node_ids.length !== 1 ? 's' : ''}
              </span>
              <span style={{ color: 'var(--border)' }}>·</span>
              <span>score {verdict.criticalPath.total_score.toFixed(3)}</span>
            </>
          )}
        </div>

        {/* Directed graph canvas */}
        <div style={{
          flex: 1, background: 'var(--base)',
          border: '1px solid var(--border)', borderRadius: 8,
          overflow: 'hidden', position: 'relative', minHeight: 220,
        }}>
          <CriticalPathGraph
            criticalPath={verdict.criticalPath}
            nodeMap={verdict.nodeMap}
          />
        </div>

        {/* Legend */}
        <div style={{
          display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap',
          fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
        }}>
          {[
            { label: 'Parent → child',  color: '#00d4ff' },
            { label: 'Shared C2',       color: '#facc15' },
            { label: 'Shared hash',     color: '#34d399' },
          ].map(({ label, color }) => (
            <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{
                width: 16, height: 2, background: color,
                display: 'inline-block', borderRadius: 1,
              }} />
              {label}
            </span>
          ))}
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{
              width: 10, height: 10, borderRadius: '50%',
              border: '1.5px dashed #00ff88', display: 'inline-block',
            }} />
            origin
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{
              width: 10, height: 10, borderRadius: '50%',
              border: '1.5px dashed #ff3355', display: 'inline-block',
            }} />
            endpoint
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ color: '#818cf8' }}>ML N/A</span>
            = model not run
          </span>
          <span style={{ marginLeft: 'auto', color: 'var(--text-dim)', fontStyle: 'italic' }}>
            w = hop weight · arc = combined score · scroll →
          </span>
        </div>
      </div>
    </div>
  );
}
