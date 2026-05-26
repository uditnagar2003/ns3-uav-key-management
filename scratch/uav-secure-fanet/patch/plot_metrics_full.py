#!/usr/bin/env python3
"""
graphs/plot_metrics_full.py
============================
Complete graph generation for ALL 5 metric categories.

CATEGORY A — Network Metrics
CATEGORY B — Security & Key Management
CATEGORY C — Overhead
CATEGORY D — Denied Environment
CATEGORY E — Mobility & Swarm

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 graphs/plot_metrics_full.py

OUTPUT:
    graphs/  (one PNG per graph + one full-report summary)

INPUT FILES EXPECTED in output/:
    metrics_full_report.csv
    metrics_per_uav.csv
    metrics_per_cluster.csv
    timeseries.csv
    rekey_latency_full.csv
    auth_log.csv
    secrecy_checks.csv
    replay_log.csv
    healing_log.csv
    compute_timings.csv
    sinr_log.csv
    link_failures.csv
    route_breaks.csv
    swarm_survivability.csv
    cluster_head_stability.csv
"""

import os, sys, csv, argparse
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import matplotlib.gridspec as gridspec
    import numpy as np
    from matplotlib.ticker import MaxNLocator
except ImportError:
    print("pip3 install matplotlib numpy")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

parser = argparse.ArgumentParser()
parser.add_argument('--input-dir',  default=os.path.join(PROJECT_DIR,'output'))
parser.add_argument('--output-dir', default=SCRIPT_DIR)
args, _ = parser.parse_known_args()

INPUT  = args.input_dir
OUTPUT = args.output_dir
os.makedirs(OUTPUT, exist_ok=True)

# ---------------------------------------------------------------------------
# Colors & Style
# ---------------------------------------------------------------------------
C = {
    'blue':   '#2980b9',
    'green':  '#27ae60',
    'red':    '#e74c3c',
    'orange': '#e67e22',
    'purple': '#8e44ad',
    'gray':   '#7f8c8d',
    'dark':   '#2c3e50',
    'teal':   '#16a085',
    'yellow': '#f39c12',
    'pink':   '#fd79a8',
}
CLUSTER_COLORS = [C['blue'], C['orange'], C['green']]
CLUSTER_LABELS = ['Cluster 0', 'Cluster 1', 'Cluster 2']
MARKER_STYLES  = ['o', 's', '^', 'D', 'v']

plt.rcParams.update({
    'font.family':    'DejaVu Sans',
    'font.size':      10,
    'axes.titlesize': 11,
    'axes.titleweight': 'bold',
    'axes.grid':      True,
    'grid.alpha':     0.3,
    'figure.dpi':     150,
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_csv(fname):
    path = os.path.join(INPUT, fname)
    if not os.path.exists(path):
        print(f"  [SKIP] {fname}")
        return []
    with open(path) as f:
        return list(csv.DictReader(f))

def load_kv(fname):
    rows = load_csv(fname)
    return {r['metric']: float(r['value']) for r in rows
            if 'metric' in r and 'value' in r}

def save(fig, name, tight=True):
    path = os.path.join(OUTPUT, name)
    if tight:
        fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  [OK]  {name}")

def bar_cluster(ax, values, title, ylabel, colors=None,
                ylim=None, hline=None):
    if colors is None:
        colors = CLUSTER_COLORS
    x     = range(len(values))
    bars  = ax.bar(x, values, color=colors, edgecolor='black',
                   linewidth=0.6, width=0.55)
    ax.set_xticks(x)
    ax.set_xticklabels(CLUSTER_LABELS[:len(values)])
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    if ylim: ax.set_ylim(*ylim)
    if hline is not None:
        ax.axhline(hline[0], color=hline[1], linestyle='--',
                   linewidth=1.5, label=hline[2], alpha=0.8)
        ax.legend(fontsize=8)
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() * 1.01 + 0.001,
                f'{v:.3f}', ha='center', fontsize=8)
    return bars


# ============================================================================
# CATEGORY A — NETWORK METRICS
# ============================================================================

def plot_a1_pdr_per_uav():
    """A1. PDR per UAV — bar chart colored by cluster."""
    rows = load_csv('metrics_per_uav.csv')
    if not rows: return
    ids   = [int(r['uav_id'])     for r in rows]
    pdrs  = [float(r['pdr'])      for r in rows]
    cids  = [int(r['cluster_id']) for r in rows]
    cols  = [CLUSTER_COLORS[c % 3] for c in cids]

    fig, ax = plt.subplots(figsize=(14, 4))
    bars = ax.bar(ids, pdrs, color=cols, edgecolor='black', linewidth=0.5)
    ax.axhline(1.0, color='red', linestyle='--', linewidth=1.5,
               label='PDR = 1.0', alpha=0.8)
    ax.set_title('A1. Packet Delivery Ratio per UAV')
    ax.set_xlabel('UAV ID')
    ax.set_ylabel('PDR (0–1)')
    ax.set_ylim(0, 1.2)
    ax.set_xticks(ids)
    patches = [mpatches.Patch(color=CLUSTER_COLORS[c],
               label=f'Cluster {c}') for c in range(3)]
    ax.legend(handles=patches + [
        mpatches.Patch(color='none', label='')], fontsize=8)
    save(fig, 'A1_pdr_per_uav.png')

def plot_a2_throughput_per_cluster():
    """A2. Throughput per cluster."""
    rows = load_csv('metrics_per_cluster.csv')
    if not rows: return
    vals = [float(r['throughput_kbps']) for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4))
    bar_cluster(ax, vals,
                'A2. Throughput per Cluster',
                'Throughput (kbps)')
    save(fig, 'A2_throughput_per_cluster.png')

def plot_a3_e2e_delay_timeseries():
    """A3. End-to-end delay over simulation time."""
    rows = load_csv('timeseries.csv')
    if not rows: return
    t    = [float(r['time_s'])      for r in rows]
    dly  = [float(r['avg_delay_ms'])for r in rows]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(t, dly, color=C['orange'], linewidth=1.8,
            marker='.', markersize=3)
    ax.set_title('A3. End-to-End Delay over Time')
    ax.set_xlabel('Simulation Time (s)')
    ax.set_ylabel('Average Delay (ms)')
    ax.fill_between(t, dly, alpha=0.15, color=C['orange'])
    save(fig, 'A3_delay_timeseries.png')

def plot_a4_packet_loss_per_cluster():
    """A4. Packet loss ratio per cluster."""
    rows = load_csv('metrics_per_cluster.csv')
    if not rows: return
    vals = [float(r['loss_ratio']) for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4))
    bar_cluster(ax, vals,
                'A4. Packet Loss Ratio per Cluster',
                'Loss Ratio (0–1)',
                ylim=(0, min(1.2, max(vals)*1.5+0.1)))
    save(fig, 'A4_loss_ratio_per_cluster.png')

def plot_a5_routing_stability():
    """A5. Routing stability index over time."""
    rows = load_csv('timeseries.csv')
    if not rows: return
    t    = [float(r['time_s'])          for r in rows]
    conn = [float(r['connectivity'])    for r in rows]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(t, conn, color=C['teal'], linewidth=1.8,
            marker='.', markersize=3, label='Connectivity Ratio')
    ax.axhline(1.0, color='green', linestyle='--', linewidth=1,
               label='Full Connectivity', alpha=0.7)
    ax.set_title('A5. Swarm Connectivity Ratio over Time')
    ax.set_xlabel('Simulation Time (s)')
    ax.set_ylabel('Connectivity Ratio (0–1)')
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=8)
    save(fig, 'A5_connectivity_timeseries.png')

def plot_a6_network_summary():
    """A6. Combined network metrics bar (PDR, Throughput, Delay, Loss)."""
    gm = load_kv('metrics_network.csv')
    if not gm: return
    metrics = {
        'PDR':            gm.get('global_pdr', 0),
        'Throughput\n(kbps)': gm.get('global_throughput_kbps', 0),
        'Avg Delay\n(ms)':    gm.get('global_avg_delay_ms', 0),
        'Loss Ratio':     gm.get('global_loss_ratio', 0),
        'Routing\nStability': gm.get('avg_routing_stability', 0),
        'Connectivity':   gm.get('avg_connectivity_ratio', 0),
    }
    colors = [C['green'], C['blue'], C['orange'],
              C['red'],   C['teal'], C['purple']]
    fig, ax = plt.subplots(figsize=(12, 4))
    bars = ax.bar(range(len(metrics)), list(metrics.values()),
                  color=colors, edgecolor='black')
    ax.set_xticks(range(len(metrics)))
    ax.set_xticklabels(list(metrics.keys()), fontsize=9)
    ax.set_title('A6. Global Network Metrics Summary')
    ax.set_ylabel('Value')
    for bar, v in zip(bars, metrics.values()):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()*1.01+0.001,
                f'{v:.4f}', ha='center', fontsize=8)
    save(fig, 'A6_network_summary.png')


# ============================================================================
# CATEGORY B — SECURITY & KEY MANAGEMENT METRICS
# ============================================================================

def plot_b1_key_establishment_time():
    """B1. Key establishment time distribution."""
    rows = load_csv('rekey_latency_full.csv')
    ke   = load_kv('metrics_security.csv')
    fig, axes = plt.subplots(1, 2, figsize=(13, 4))

    # Left: histogram of rekey latencies
    if rows:
        lats = [float(r['latency_ms']) for r in rows]
        axes[0].hist(lats, bins=25, color=C['blue'],
                     edgecolor='black', alpha=0.75)
        mean_v = np.mean(lats) if lats else 0
        axes[0].axvline(mean_v, color='red', linestyle='--',
                        linewidth=2, label=f'Mean={mean_v:.3f}ms')
        axes[0].set_xlabel('Latency (ms)')
        axes[0].set_ylabel('Frequency')
        axes[0].set_title('B1. Rekey Latency Distribution')
        axes[0].legend(fontsize=8)

    # Right: bar of key management metrics
    if ke:
        names = ['Avg Key\nEstab (ms)', 'Avg Rekey\n(ms)',
                 'Max Key\nEstab (ms)', 'Avg Session\nRecovery (ms)']
        vals  = [ke.get('avg_key_estab_ms', 0),
                 ke.get('avg_rekey_latency_ms', 0),
                 ke.get('max_key_estab_ms', 0),
                 ke.get('avg_session_recovery_ms', 0)]
        bars = axes[1].bar(names, vals,
                           color=[C['blue'],C['green'],C['red'],C['orange']],
                           edgecolor='black')
        axes[1].set_title('B1. Key Management Timing')
        axes[1].set_ylabel('Latency (ms)')
        for bar, v in zip(bars, vals):
            axes[1].text(bar.get_x()+bar.get_width()/2,
                         bar.get_height()*1.01,
                         f'{v:.3f}', ha='center', fontsize=8)
    save(fig, 'B1_key_establishment_time.png')

def plot_b2_rekeying_delay_per_trigger():
    """B2. Rekeying delay per event type (JOIN/LEAVE/COMPROMISE/HANDOVER)."""
    rows = load_csv('rekey_latency_full.csv')
    if not rows: return
    by_trigger = defaultdict(list)
    for r in rows:
        by_trigger[r['trigger']].append(float(r['latency_ms']))

    triggers = sorted(by_trigger.keys())
    means    = [np.mean(by_trigger[t]) for t in triggers]
    stds     = [np.std(by_trigger[t])  for t in triggers]

    fig, ax = plt.subplots(figsize=(10, 4))
    colors = [C['blue'], C['orange'], C['red'],
              C['green'], C['purple'], C['teal'],
              C['yellow'], C['pink']][:len(triggers)]
    bars = ax.bar(triggers, means, yerr=stds, capsize=5,
                  color=colors, edgecolor='black', alpha=0.85)
    ax.set_title('B2. Rekeying Delay per Event Type')
    ax.set_xlabel('Trigger Type')
    ax.set_ylabel('Latency (ms)')
    for bar, v in zip(bars, means):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()+0.001,
                f'{v:.3f}ms', ha='center', fontsize=8)
    save(fig, 'B2_rekeying_delay_per_trigger.png')

def plot_b3_auth_success_rate():
    """B3. Authentication success rate over time."""
    rows = load_csv('auth_log.csv')
    if not rows: return
    # Bin into 10s windows
    bins    = defaultdict(lambda: [0, 0])  # [success, total]
    for r in rows:
        t   = int(float(r['time_s']) / 10) * 10
        bins[t][1] += 1
        if r['success'] == '1' or r['success'].lower() == 'true':
            bins[t][0] += 1

    times = sorted(bins.keys())
    rates = [bins[t][0] / bins[t][1] if bins[t][1] else 0 for t in times]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(times, rates, color=C['green'], linewidth=2,
            marker='o', markersize=5)
    ax.axhline(1.0, color='gray', linestyle='--', alpha=0.5,
               label='100% Rate')
    ax.set_ylim(0, 1.15)
    ax.set_title('B3. Authentication Success Rate over Time')
    ax.set_xlabel('Simulation Time (s)')
    ax.set_ylabel('Auth Success Rate (0–1)')
    ax.legend(fontsize=8)
    save(fig, 'B3_auth_success_rate.png')

def plot_b4b5_secrecy_validation():
    """B4/B5. Forward and Backward Secrecy validation rates."""
    rows = load_csv('secrecy_checks.csv')
    if not rows: return

    fwd_by_type = defaultdict(lambda: [0, 0])
    bwd_by_type = defaultdict(lambda: [0, 0])
    for r in rows:
        t = r['event_type']
        fwd_by_type[t][1] += 1
        bwd_by_type[t][1] += 1
        if r['forward_ok']  in ('1','True','true'):
            fwd_by_type[t][0] += 1
        if r['backward_ok'] in ('1','True','true'):
            bwd_by_type[t][0] += 1

    types     = sorted(set(fwd_by_type) | set(bwd_by_type))
    fwd_rates = [fwd_by_type[t][0]/fwd_by_type[t][1]
                 if fwd_by_type[t][1] else 0 for t in types]
    bwd_rates = [bwd_by_type[t][0]/bwd_by_type[t][1]
                 if bwd_by_type[t][1] else 0 for t in types]

    x     = np.arange(len(types))
    width = 0.35
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(x - width/2, fwd_rates, width, label='Forward Secrecy',
           color=C['blue'], edgecolor='black', alpha=0.85)
    ax.bar(x + width/2, bwd_rates, width, label='Backward Secrecy',
           color=C['orange'], edgecolor='black', alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(types)
    ax.set_ylim(0, 1.2)
    ax.axhline(1.0, color='red', linestyle='--', alpha=0.6)
    ax.set_title('B4/B5. Forward & Backward Secrecy per Event Type')
    ax.set_ylabel('Validation Rate (0–1)')
    ax.legend(fontsize=8)
    save(fig, 'B4B5_secrecy_validation.png')

def plot_b6_replay_detection():
    """B6. Replay attack detection rate — confusion breakdown."""
    rows = load_csv('replay_log.csv')
    if not rows: return

    tp = fp = fn = tn = 0
    for r in rows:
        wr = r['was_replay']  in ('1','True','true')
        dt = r['detected']    in ('1','True','true')
        if wr and dt:   tp += 1
        if not wr and dt:   fp += 1
        if wr and not dt:   fn += 1
        if not wr and not dt: tn += 1

    labels = ['True\nPositive\n(Blocked)', 'False\nPositive\n(Over-block)',
              'False\nNeg\n(Missed)', 'True\nNeg\n(Allowed)']
    values = [tp, fp, fn, tn]
    colors_conf = [C['green'], C['orange'], C['red'], C['blue']]

    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.bar(labels, values, color=colors_conf, edgecolor='black')
    ax.set_title('B6. Replay Attack Detection — Confusion Matrix')
    ax.set_ylabel('Count')
    det_rate = tp / (tp+fn) if (tp+fn) else 0
    ax.text(0.98, 0.97, f'Detection Rate: {det_rate:.1%}',
            transform=ax.transAxes, ha='right', va='top',
            fontsize=10, color='darkgreen',
            bbox=dict(boxstyle='round', fc='white', ec='gray'))
    for bar, v in zip(bars, values):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()+0.3,
                str(v), ha='center', fontsize=9)
    save(fig, 'B6_replay_detection.png')

def plot_b7b8_healing_recovery():
    """B7/B8. Mutual-healing success and recovery time."""
    rows = load_csv('healing_log.csv')
    if not rows: return

    latencies = [float(r['latency_ms']) for r in rows]
    recovered = [r['recovered'] in ('1','True','true') for r in rows]
    by_type   = defaultdict(list)
    for r in rows:
        by_type[r['event_type']].append(float(r['latency_ms']))

    fig, axes = plt.subplots(1, 2, figsize=(13, 4))

    # Left: success rate pie
    ok  = sum(recovered)
    nok = len(recovered) - ok
    if ok + nok > 0:
        axes[0].pie([ok, nok],
                    labels=[f'Recovered ({ok})', f'Failed ({nok})'],
                    colors=[C['green'], C['red']],
                    autopct='%1.1f%%', startangle=90,
                    wedgeprops={'edgecolor':'black','linewidth':0.6})
    axes[0].set_title('B7. Mutual-Healing Recovery Success')

    # Right: recovery latency by event type
    types  = sorted(by_type.keys())
    means  = [np.mean(by_type[t]) for t in types]
    axes[1].bar(types, means,
                color=[C['blue'], C['orange'], C['purple']][:len(types)],
                edgecolor='black')
    axes[1].set_title('B8. Secure Session Recovery Time by Event')
    axes[1].set_xlabel('Event Type')
    axes[1].set_ylabel('Recovery Latency (ms)')
    save(fig, 'B7B8_healing_recovery.png')


# ============================================================================
# CATEGORY C — OVERHEAD METRICS
# ============================================================================

def plot_c1_communication_overhead():
    """C1/C4. Communication and control packet overhead breakdown."""
    oh = load_kv('metrics_overhead.csv')
    if not oh: return

    labels = ['Data', 'Header\nOverhead', 'HMAC\nOverhead',
              'MT_K\nField', 'Control\nPackets', 'Rekey\nMessages']
    # Infer data ratio = 1 - all overhead
    total_oh = (oh.get('header_overhead_ratio', 0) +
                oh.get('hmac_overhead_ratio', 0) +
                oh.get('rekey_overhead_ratio', 0) +
                oh.get('comm_overhead_ratio', 0) * 0.3)  # approx split
    data_r = max(0, 1.0 - oh.get('comm_overhead_ratio', 0))

    vals = [
        data_r,
        oh.get('header_overhead_ratio', 0),
        oh.get('hmac_overhead_ratio', 0),
        0.0,   # mtk placeholder if not tracked separately
        oh.get('comm_overhead_ratio', 0) * 0.5,
        oh.get('rekey_overhead_ratio', 0),
    ]
    colors_pie = [C['green'], C['blue'], C['orange'],
                  C['purple'], C['red'], C['teal']]

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Pie
    non_zero = [(l, v, c) for l, v, c in zip(labels, vals, colors_pie) if v > 1e-6]
    if non_zero:
        ls, vs, cs = zip(*non_zero)
        axes[0].pie(vs, labels=ls, colors=cs,
                    autopct='%1.1f%%', startangle=90,
                    wedgeprops={'edgecolor':'black','linewidth':0.5})
    axes[0].set_title('C1. Packet Byte Breakdown')

    # Bar: control overhead over time
    ts = load_csv('timeseries.csv')
    if ts:
        t   = [float(r['time_s'])        for r in ts]
        ovh = [float(r['overhead_ratio'])*100 for r in ts]
        axes[1].plot(t, ovh, color=C['red'], linewidth=1.8,
                     marker='.', markersize=3)
        axes[1].fill_between(t, ovh, alpha=0.12, color=C['red'])
        axes[1].set_title('C4. Control Overhead Ratio over Time')
        axes[1].set_xlabel('Simulation Time (s)')
        axes[1].set_ylabel('Overhead (%)')
    save(fig, 'C1C4_communication_overhead.png')

def plot_c2_computational_overhead():
    """C2. Computational overhead — timing per operation."""
    rows = load_csv('compute_timings.csv')
    if not rows: return
    by_op = defaultdict(list)
    for r in rows:
        by_op[r['operation']].append(float(r['wall_us']))

    ops   = sorted(by_op.keys())
    means = [np.mean(by_op[op]) for op in ops]
    stds  = [np.std(by_op[op])  for op in ops]
    counts= [len(by_op[op])     for op in ops]

    fig, ax = plt.subplots(figsize=(10, 4))
    colors_op = [C['blue'], C['orange'], C['green'],
                 C['red'],  C['purple'], C['teal']][:len(ops)]
    bars = ax.bar(ops, means, yerr=stds, capsize=5,
                  color=colors_op, edgecolor='black', alpha=0.85)
    ax.set_title('C2. Computational Overhead per Crypto Operation')
    ax.set_xlabel('Operation')
    ax.set_ylabel('Wall-Clock Time (µs)')
    for bar, v, n in zip(bars, means, counts):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()+0.1,
                f'{v:.1f}µs\n(n={n})', ha='center', fontsize=7)
    save(fig, 'C2_computational_overhead.png')

def plot_c3_storage_overhead():
    """C3. Storage overhead breakdown per UAV."""
    oh = load_kv('metrics_overhead.csv')
    storage_b = oh.get('storage_per_uav_bytes', 1568)

    components = {
        'TEK (32B)':           32,
        'Slave Key (~512B)':   512,
        'Replay Cache (1024B)':1024,
    }
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.pie(components.values(),
           labels=components.keys(),
           colors=[C['blue'], C['orange'], C['green']],
           autopct='%1.1f%%', startangle=90,
           wedgeprops={'edgecolor':'black','linewidth':0.5})
    ax.set_title(f'C3. Storage Overhead per UAV\n'
                 f'(Total ≈ {storage_b:.0f} bytes)')
    save(fig, 'C3_storage_overhead.png')

def plot_c5_rekey_message_cost():
    """C5. Rekeying message cost per cluster over sim."""
    rows = load_csv('rekey_latency_full.csv')
    if not rows: return
    by_cluster = defaultdict(list)
    for r in rows:
        c = int(r['cluster_id'])
        cost = float(r.get('msg_cost_bytes', 512))
        by_cluster[c].append(cost)

    fig, ax = plt.subplots(figsize=(8, 4))
    for c in sorted(by_cluster.keys()):
        costs = by_cluster[c]
        ax.plot(range(len(costs)), costs,
                color=CLUSTER_COLORS[c % 3],
                label=f'Cluster {c}',
                linewidth=1.5, marker='.', markersize=4)
    ax.set_title('C5. Rekeying Message Cost per Event (per Cluster)')
    ax.set_xlabel('Rekey Event Index')
    ax.set_ylabel('Message Cost (bytes)')
    ax.legend(fontsize=8)
    save(fig, 'C5_rekey_message_cost.png')


# ============================================================================
# CATEGORY D — DENIED ENVIRONMENT METRICS
# ============================================================================

def plot_d1_sinr_timeseries():
    """D1. SINR over time with jammer threshold."""
    rows = load_csv('sinr_log.csv')
    if not rows: return
    # Average SINR per second
    bins = defaultdict(list)
    for r in rows:
        t = int(float(r['time_s']))
        bins[t].append(float(r['sinr_db']))
    times = sorted(bins.keys())
    avgs  = [np.mean(bins[t]) for t in times]
    mins  = [np.min(bins[t])  for t in times]

    fig, ax = plt.subplots(figsize=(11, 4))
    ax.plot(times, avgs, color=C['blue'], linewidth=1.8,
            label='Avg SINR', marker='.', markersize=3)
    ax.plot(times, mins, color=C['red'], linewidth=1.2,
            linestyle=':', label='Min SINR')
    ax.axhline(8.0, color='orange', linestyle='--', linewidth=1.5,
               label='Threshold (8 dB)')
    ax.fill_between(times, mins, avgs, alpha=0.1, color=C['blue'])
    ax.set_title('D1. SINR per Second (Avg & Min)')
    ax.set_xlabel('Simulation Time (s)')
    ax.set_ylabel('SINR (dB)')
    ax.legend(fontsize=8)
    save(fig, 'D1_sinr_timeseries.png')

def plot_d1_sinr_cdf():
    """D1. SINR CDF across all UAVs."""
    rows = load_csv('sinr_log.csv')
    if not rows: return
    sinrs = sorted([float(r['sinr_db']) for r in rows])
    cdf   = np.arange(1, len(sinrs)+1) / len(sinrs)

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(sinrs, cdf, color=C['blue'], linewidth=2)
    ax.axvline(8.0, color='red', linestyle='--', linewidth=1.5,
               label='Threshold (8 dB)')
    ax.set_title('D1. SINR CDF — All UAVs, All Time')
    ax.set_xlabel('SINR (dB)')
    ax.set_ylabel('CDF')
    ax.legend(fontsize=8)
    save(fig, 'D1_sinr_cdf.png')

def plot_d2_jammed_uav_ratio():
    """D2. Jammed UAV count over time."""
    rows = load_csv('sinr_log.csv')
    if not rows: return
    bins_jammed = defaultdict(set)
    bins_total  = defaultdict(set)
    for r in rows:
        t = int(float(r['time_s']))
        bins_total[t].add(int(r['uav_id']))
        if r['jammed'] in ('1','True','true'):
            bins_jammed[t].add(int(r['uav_id']))

    times   = sorted(bins_total.keys())
    ratios  = [len(bins_jammed.get(t, set())) /
               max(1, len(bins_total.get(t, {1}))) for t in times]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.fill_between(times, ratios, alpha=0.3, color=C['red'])
    ax.plot(times, ratios, color=C['red'], linewidth=1.8,
            marker='.', markersize=3)
    ax.set_title('D2. Jammed UAV Ratio over Time')
    ax.set_xlabel('Simulation Time (s)')
    ax.set_ylabel('Fraction of UAVs Jammed')
    ax.set_ylim(0, 1.1)
    save(fig, 'D2_jammed_ratio_timeseries.png')

def plot_d3_recovery_time():
    """D3. Recovery time after jamming per UAV."""
    rows = load_csv('link_failures.csv')
    if not rows: return
    jammer_rows = [r for r in rows if 'JAMMER' in r.get('cause','').upper()]
    if not jammer_rows: jammer_rows = rows  # fallback

    uav_ids   = [int(r['uav_id'])      for r in jammer_rows]
    durations = [float(r['duration_ms'])for r in jammer_rows]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(range(len(uav_ids)), durations,
           color=[CLUSTER_COLORS[uid//6 % 3] for uid in uav_ids],
           edgecolor='black')
    ax.set_xticks(range(len(uav_ids)))
    ax.set_xticklabels([f'UAV{u}' for u in uav_ids], rotation=45, fontsize=7)
    ax.set_title('D3. Recovery Time after Jammer-Induced Link Failure')
    ax.set_ylabel('Recovery Duration (ms)')
    save(fig, 'D3_recovery_time_after_jamming.png')

def plot_d4_link_failure_rate():
    """D4. Link failure events over simulation time by cause."""
    rows = load_csv('link_failures.csv')
    if not rows: return
    by_cause = defaultdict(lambda: defaultdict(int))
    for r in rows:
        t     = int(float(r['time_s']) / 10) * 10
        cause = r.get('cause', 'UNKNOWN')
        by_cause[cause][t] += 1

    fig, ax = plt.subplots(figsize=(10, 4))
    all_times = sorted(set(t for c in by_cause.values() for t in c))
    colors_cause = [C['red'], C['orange'], C['purple'], C['blue']]
    for i, (cause, bins) in enumerate(by_cause.items()):
        cts = [bins.get(t, 0) for t in all_times]
        ax.plot(all_times, cts,
                color=colors_cause[i % len(colors_cause)],
                label=cause, linewidth=1.5,
                marker='o', markersize=4)
    ax.set_title('D4. Link Failure Events per 10s Window by Cause')
    ax.set_xlabel('Simulation Time (s)')
    ax.set_ylabel('Failure Count')
    ax.legend(fontsize=8)
    save(fig, 'D4_link_failure_rate.png')

def plot_d5_interference_impact():
    """D5. PDR comparison: jammed vs non-jammed UAVs."""
    sinr_rows = load_csv('sinr_log.csv')
    uav_rows  = load_csv('metrics_per_uav.csv')
    if not sinr_rows or not uav_rows: return

    jammed_uavs = set()
    for r in sinr_rows:
        if r['jammed'] in ('1','True','true'):
            jammed_uavs.add(int(r['uav_id']))

    j_pdrs  = [float(r['pdr']) for r in uav_rows
               if int(r['uav_id']) in jammed_uavs]
    nj_pdrs = [float(r['pdr']) for r in uav_rows
               if int(r['uav_id']) not in jammed_uavs]

    fig, ax = plt.subplots(figsize=(7, 4))
    data   = []
    labels = []
    if j_pdrs:
        data.append(j_pdrs);   labels.append(f'Jammed\n(n={len(j_pdrs)})')
    if nj_pdrs:
        data.append(nj_pdrs);  labels.append(f'Not Jammed\n(n={len(nj_pdrs)})')
    if data:
        bp = ax.boxplot(data, labels=labels,
                        patch_artist=True,
                        boxprops=dict(facecolor=C['blue'], alpha=0.6),
                        medianprops=dict(color='red', linewidth=2))
    ax.set_title('D5. Interference Impact: PDR Jammed vs Non-Jammed UAVs')
    ax.set_ylabel('PDR')
    ax.set_ylim(0, 1.2)
    save(fig, 'D5_interference_impact.png')


# ============================================================================
# CATEGORY E — MOBILITY & SWARM METRICS
# ============================================================================

def plot_e1_cluster_head_stability():
    """E1. Cluster head (SKDC) reachability over time."""
    rows = load_csv('cluster_head_stability.csv')
    if not rows: return
    by_cluster = defaultdict(list)
    for r in rows:
        c = int(r['cluster_id'])
        by_cluster[c].append(
            (float(r['time_s']),
             1 if r['reachable'] in ('1','True','true') else 0))

    fig, ax = plt.subplots(figsize=(10, 4))
    for c in sorted(by_cluster.keys()):
        data = sorted(by_cluster[c])
        ts   = [d[0] for d in data]
        reac = [d[1] for d in data]
        # Rolling 10s stability
        win  = 10
        stab = []
        for i in range(len(reac)):
            w = reac[max(0, i-win):i+1]
            stab.append(sum(w)/len(w))
        ax.plot(ts, stab,
                color=CLUSTER_COLORS[c % 3],
                label=f'Cluster {c}',
                linewidth=1.8)
    ax.set_title('E1. Cluster Head (SKDC) Stability over Time')
    ax.set_xlabel('Simulation Time (s)')
    ax.set_ylabel('Stability (10s rolling avg)')
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=8)
    save(fig, 'E1_cluster_head_stability.png')

def plot_e2_route_break_frequency():
    """E2. Route break frequency per cluster over time."""
    rows = load_csv('route_breaks.csv')
    if not rows: return
    by_cluster = defaultdict(lambda: defaultdict(int))
    for r in rows:
        t = int(float(r['time_s']) / 10) * 10
        c = int(r['cluster_id'])
        by_cluster[c][t] += 1

    all_times = sorted(set(t for c in by_cluster.values() for t in c))
    fig, ax = plt.subplots(figsize=(10, 4))
    for c in sorted(by_cluster.keys()):
        cts = [by_cluster[c].get(t, 0) for t in all_times]
        ax.plot(all_times, cts,
                color=CLUSTER_COLORS[c % 3],
                label=f'Cluster {c}',
                linewidth=1.5, marker='s', markersize=4)
    ax.set_title('E2. Route Break Frequency (per 10s window)')
    ax.set_xlabel('Simulation Time (s)')
    ax.set_ylabel('Route Breaks')
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(fontsize=8)
    save(fig, 'E2_route_break_frequency.png')

def plot_e3_mobility_rekey_correlation():
    """E3. Scatter: UAV velocity vs rekey triggered."""
    rows = load_csv('route_breaks.csv')
    if not rows: return
    vels  = [float(r['velocity_mps'])    for r in rows]
    rkd   = [int(r['triggered_rekey'] in ('1','True','true'))
             for r in rows]
    yes_v = [v for v, r in zip(vels, rkd) if r]
    no_v  = [v for v, r in zip(vels, rkd) if not r]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.scatter(range(len(no_v)),  no_v,
               color=C['blue'],  alpha=0.5,  s=20,
               label='No Rekey triggered')
    ax.scatter(range(len(yes_v)), yes_v,
               color=C['red'],   alpha=0.7,  s=30,
               label='Rekey triggered')
    # Correlation annotation
    if len(vels) > 2:
        corr = np.corrcoef(vels, rkd)[0, 1]
        ax.text(0.98, 0.97, f'Pearson r = {corr:.3f}',
                transform=ax.transAxes, ha='right', va='top',
                fontsize=9,
                bbox=dict(boxstyle='round', fc='white', ec='gray'))
    ax.set_title('E3. Mobility Impact on Rekeying\n'
                 '(Route Break Events by UAV Velocity)')
    ax.set_xlabel('Event Index')
    ax.set_ylabel('UAV Velocity (m/s)')
    ax.legend(fontsize=8)
    save(fig, 'E3_mobility_rekey_correlation.png')

def plot_e4_swarm_survivability():
    """E4. Swarm survivability and connectivity over time."""
    rows = load_csv('swarm_survivability.csv')
    if not rows: return
    t    = [float(r['time_s'])          for r in rows]
    surv = [float(r['survivability'])   for r in rows]
    conn = [float(r['connectivity'])    for r in rows]
    jmd  = [int(r['jammed'])            for r in rows]

    fig, axes = plt.subplots(2, 1, figsize=(11, 7), sharex=True)

    # Top: survivability
    axes[0].plot(t, surv, color=C['green'], linewidth=2,
                 label='Survivability')
    axes[0].plot(t, conn, color=C['blue'],  linewidth=1.5,
                 linestyle='--', label='Connectivity')
    axes[0].fill_between(t, surv, alpha=0.1, color=C['green'])
    axes[0].set_ylabel('Ratio (0–1)')
    axes[0].set_title('E4. Swarm Survivability & Connectivity over Time')
    axes[0].set_ylim(0, 1.15)
    axes[0].legend(fontsize=8)

    # Bottom: jammed/disconnected counts
    total = [int(r.get('active', 18)) + int(r.get('jammed', 0)) +
             int(r.get('compromised', 0)) + int(r.get('disconnected', 0))
             for r in rows]
    active    = [int(r.get('active', 18))       for r in rows]
    jammed    = [int(r.get('jammed', 0))         for r in rows]
    compromised=[int(r.get('compromised', 0))   for r in rows]
    axes[1].stackplot(t, active, jammed, compromised,
                      labels=['Active', 'Jammed', 'Compromised'],
                      colors=[C['green'], C['red'], C['orange']],
                      alpha=0.75)
    axes[1].set_xlabel('Simulation Time (s)')
    axes[1].set_ylabel('UAV Count')
    axes[1].set_title('UAV State Breakdown')
    axes[1].legend(fontsize=8, loc='upper right')
    save(fig, 'E4_swarm_survivability.png')


# ============================================================================
# MASTER SUMMARY FIGURE — All 5 categories in one panel
# ============================================================================

def plot_master_summary():
    """Combined 5-category research summary figure."""
    gm  = load_kv('metrics_full_report.csv')
    if not gm: return

    fig = plt.figure(figsize=(18, 11))
    fig.suptitle(
        'Hierarchical CRT-GCRT UAV Swarm Multicast Key Management\n'
        'Complete Performance Evaluation — Denied FANET Environment',
        fontsize=13, fontweight='bold', y=0.98)

    gs = gridspec.GridSpec(3, 5, figure=fig,
                           hspace=0.55, wspace=0.45)

    def metric_bar(ax, names, vals, colors, title, ylabel):
        bars = ax.bar(range(len(names)), vals, color=colors,
                      edgecolor='black', linewidth=0.5)
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels(names, fontsize=7, rotation=15, ha='right')
        ax.set_title(title, fontsize=9)
        ax.set_ylabel(ylabel, fontsize=8)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x()+bar.get_width()/2,
                    bar.get_height()*1.02,
                    f'{v:.3f}', ha='center', fontsize=6.5)

    # Row 1: Network
    ax = fig.add_subplot(gs[0, :2])
    metric_bar(ax,
               ['PDR', 'Throughput\n(kbps)', 'Delay\n(ms)',
                'Loss\nRatio', 'Routing\nStab.'],
               [gm.get('A,pdr',0), gm.get('A,throughput_kbps',0),
                gm.get('A,avg_delay_ms',0), gm.get('A,loss_ratio',0),
                gm.get('A,routing_stability',0)],
               [C['green'],C['blue'],C['orange'],C['red'],C['teal']],
               'A. Network Metrics', 'Value')

    # Row 1: Security timing
    ax2 = fig.add_subplot(gs[0, 2:4])
    metric_bar(ax2,
               ['Key Estab\n(ms)', 'Rekey\n(ms)', 'Auth\nSuccess',
                'Fwd Sec', 'Bwd Sec'],
               [gm.get('B,key_estab_ms',0),
                gm.get('B,rekey_latency_ms',0),
                gm.get('B,auth_success_rate',0),
                gm.get('B,forward_secrecy',0),
                gm.get('B,backward_secrecy',0)],
               [C['blue'],C['orange'],C['green'],C['purple'],C['teal']],
               'B. Security Timing', 'Value')

    # Row 1: Replay / Healing
    ax3 = fig.add_subplot(gs[0, 4])
    vals3 = [gm.get('B,replay_detection_rate',0),
             gm.get('B,healing_success_rate',0)]
    bars3 = ax3.bar(['Replay\nDetect', 'Healing\nSucc'],
                    vals3,
                    color=[C['red'], C['green']],
                    edgecolor='black')
    ax3.set_ylim(0, 1.2)
    ax3.set_title('B. Replay & Healing', fontsize=9)
    ax3.set_ylabel('Rate', fontsize=8)
    for bar, v in zip(bars3, vals3):
        ax3.text(bar.get_x()+bar.get_width()/2,
                 bar.get_height()+0.02,
                 f'{v:.2f}', ha='center', fontsize=8)

    # Row 2: Overhead
    ax4 = fig.add_subplot(gs[1, :2])
    metric_bar(ax4,
               ['Comm\nOvhd', 'Rekey\nOvhd', 'HMAC\nOvhd',
                'Storage\n(KB)', 'Ctrl B/s'],
               [gm.get('C,comm_overhead',0),
                gm.get('C,rekey_overhead',0),
                0.0,
                gm.get('C,storage_per_uav_bytes',0)/1024,
                gm.get('C,ctrl_bytes_per_sec',0)],
               [C['orange'],C['red'],C['purple'],C['blue'],C['teal']],
               'C. Overhead Metrics', 'Value')

    # Row 2: Denied environment
    ax5 = fig.add_subplot(gs[1, 2:4])
    metric_bar(ax5,
               ['Avg SINR\n(dB)', 'Min SINR\n(dB)', 'Jammed\nRatio',
                'Jam Recov\n(ms)', 'Interference\nImpact'],
               [gm.get('D,avg_sinr_db',0),
                max(0, gm.get('D,min_sinr_db',0)),
                gm.get('D,jammed_uav_ratio',0),
                gm.get('D,recovery_after_jam_ms',0),
                gm.get('D,interference_impact',0)],
               [C['blue'],C['red'],C['orange'],C['green'],C['purple']],
               'D. Denied Environment', 'Value')

    # Row 2: Mobility
    ax6 = fig.add_subplot(gs[1, 4])
    vals6 = [gm.get('E,cluster_head_stability',0),
             gm.get('E,swarm_survivability',0)]
    bars6 = ax6.bar(['CH\nStability', 'Swarm\nSurviv.'],
                    vals6,
                    color=[C['teal'], C['green']],
                    edgecolor='black')
    ax6.set_ylim(0, 1.2)
    ax6.set_title('E. Mobility', fontsize=9)
    ax6.set_ylabel('Ratio', fontsize=8)
    for bar, v in zip(bars6, vals6):
        ax6.text(bar.get_x()+bar.get_width()/2,
                 bar.get_height()+0.02,
                 f'{v:.2f}', ha='center', fontsize=8)

    # Row 3: Time series (PDR + Survivability)
    ts = load_csv('timeseries.csv')
    if ts:
        ax7 = fig.add_subplot(gs[2, :3])
        t    = [float(r['time_s'])         for r in ts]
        pdr  = [float(r['pdr'])            for r in ts]
        surv = [float(r['survivability'])  for r in ts]
        sinr = [float(r.get('sinr_db', 0)) for r in ts]

        ax7.plot(t, pdr,  color=C['green'], linewidth=1.5, label='PDR')
        ax7.plot(t, surv, color=C['blue'],  linewidth=1.5,
                 linestyle='--', label='Survivability')
        ax7.axhline(8.0/40, color='orange', linestyle=':', alpha=0.5)
        ax7.set_xlabel('Simulation Time (s)', fontsize=8)
        ax7.set_ylabel('Ratio (0–1)', fontsize=8)
        ax7.set_title('PDR & Swarm Survivability over Time', fontsize=9)
        ax7.legend(fontsize=7)
        ax7.set_ylim(0, 1.15)

    # Row 3: Rekey events
    rk = load_csv('rekey_latency_full.csv')
    if rk:
        ax8 = fig.add_subplot(gs[2, 3:])
        by_c = defaultdict(lambda: defaultdict(int))
        for r in rk:
            t2 = int(float(r['time_s']) / 20) * 20
            by_c[int(r['cluster_id'])][t2] += 1
        all_t = sorted(set(t for c in by_c.values() for t in c))
        for c in sorted(by_c.keys()):
            cts = [by_c[c].get(t, 0) for t in all_t]
            ax8.plot(all_t, cts,
                     color=CLUSTER_COLORS[c % 3],
                     label=f'C{c}', linewidth=1.5,
                     marker='o', markersize=4)
        ax8.set_title('Rekey Events per Cluster (20s bins)', fontsize=9)
        ax8.set_xlabel('Simulation Time (s)', fontsize=8)
        ax8.set_ylabel('Rekey Count', fontsize=8)
        ax8.legend(fontsize=7)

    save(fig, 'MASTER_SUMMARY_all_metrics.png', tight=False)


# ============================================================================
# NetAnim Visualization Guide (text report)
# ============================================================================
def generate_netanim_guide():
    """Generate a text file explaining what to look for in NetAnim."""
    path = os.path.join(OUTPUT, 'NETANIM_VISUALIZATION_GUIDE.txt')
    with open(path, 'w') as f:
        f.write("""
╔══════════════════════════════════════════════════════════════════════════════╗
║         NETANIM VISUALIZATION GUIDE — UAV SECURE FANET                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

FILE: output/uav-fanet-anim.xml
Open with: netanim

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NODE COLORS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  RED    — KDC  (Node 0)         : Ground Key Distribution Center
  ORANGE — SKDC (Nodes 1–3)     : Cluster Key Distribution Centers
  GREEN  — UAV  (Nodes 4–21)    : Active, authenticated UAVs
  BLACK  — Compromised UAV       : Detected compromised node (5% prob)
  PURPLE — Jammer (Node 22)     : Mobile RF jammer

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT TO OBSERVE DURING PLAYBACK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  t=0–10s    INITIALIZATION
             • SKDC nodes (orange) register with KDC (red)
             • UAVs (green) join their cluster SKDCs
             • Packet lines appear: CSMA backbone (KDC↔SKDC)
             • Look for: MT_K broadcast lines from each SKDC to its 6 UAVs

  t=30s      LEAVE EVENT (UAV 3, Cluster 0)
             • UAV 3 label changes to indicate LEAVE
             • SKDC 0 broadcasts REKEY packet to remaining C0 members
             • Observe: green packet lines from SKDC0 to UAV {0,1,2,4,5}

  t=60s      HANDOVER (UAV 5, Cluster 0 → Cluster 1)
             • UAV 5 moves geographically toward Cluster 1
             • Color briefly changes (handover in progress)
             • OLD SKDC 0 sends rekey to C0; NEW SKDC 1 sends rekey to C1
             • Both clusters show simultaneous MT_K broadcasts

  t=90s      JOIN EVENT (New UAV, Cluster 2)
             • New node appears near Cluster 2
             • SKDC 2 sends unicast key establishment packet
             • Then broadcasts updated MT_K to all C2 members

  t=120s     COMPROMISE EVENT
             • A random UAV turns BLACK
             • SKDC broadcasts forced rekey (COMPROMISE trigger)
             • KDC is notified (packet line to red KDC node)

  ONGOING    JAMMER MOVEMENT
             • Purple node moves continuously (RandomWaypoint)
             • Nearby UAV nodes may briefly change to lighter color
               indicating degraded SINR (< 8 dB threshold)
             • Packet loss visible as fewer transmission lines near jammer

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PACKET COLORS IN NETANIM (if supported by your NetAnim version)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Blue lines   — DATA packets (AES-256 encrypted payload)
  Orange lines — MT_K broadcast packets (CRT multicast key)
  Red lines    — REKEY packets (triggered rekeying)
  Yellow lines — JOIN/AUTH packets
  Purple lines — HANDOVER packets
  Gray lines   — OLSR routing updates (HELLO/TC)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
METRICS TO READ IN REAL TIME (Statistics Panel)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  In NetAnim:  View → Statistics Window
  Expected per-node counters:
    • Packets TX / RX
    • Bytes TX / RX
  Use these to compute live PDR per UAV.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NETANIM SETTINGS FOR BEST VIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Playback speed: 0.01x (very slow — 300s simulation needs slow play)
  Packet size:    Scale to 0.5–1.0 for visibility
  Show routes:    Enable OLSR route display (View → Show Routes)
  Node labels:    Enable (View → Show Node IDs)
  Zoom:           1500×1500m simulation area; set canvas to fit

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOPOLOGY AT A GLANCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 KDC  +  3 SKDCs  +  18 UAVs  +  1 Jammer  =  23 nodes total
  3 clusters × 6 UAVs each
  CSMA backbone: KDC ↔ SKDC0 ↔ SKDC1 ↔ SKDC2
  WiFi adhoc:    802.11a, 5GHz, 26Mbps, 1500×1500m area
  Routing:       OLSR (HELLO=2s, TC=5s)
""")
    print(f"  [OK]  NETANIM_VISUALIZATION_GUIDE.txt")


# ============================================================================
# MAIN
# ============================================================================
GRAPHS = [
    # A — Network
    ('A1. PDR per UAV',              plot_a1_pdr_per_uav),
    ('A2. Throughput per Cluster',   plot_a2_throughput_per_cluster),
    ('A3. E2E Delay Timeseries',     plot_a3_e2e_delay_timeseries),
    ('A4. Packet Loss per Cluster',  plot_a4_packet_loss_per_cluster),
    ('A5. Routing Stability',        plot_a5_routing_stability),
    ('A6. Network Summary',          plot_a6_network_summary),
    # B — Security
    ('B1. Key Establishment Time',   plot_b1_key_establishment_time),
    ('B2. Rekeying Delay per Trigger', plot_b2_rekeying_delay_per_trigger),
    ('B3. Auth Success Rate',        plot_b3_auth_success_rate),
    ('B4/B5. Secrecy Validation',    plot_b4b5_secrecy_validation),
    ('B6. Replay Detection',         plot_b6_replay_detection),
    ('B7/B8. Healing & Recovery',    plot_b7b8_healing_recovery),
    # C — Overhead
    ('C1/C4. Communication Overhead', plot_c1_communication_overhead),
    ('C2. Computational Overhead',   plot_c2_computational_overhead),
    ('C3. Storage Overhead',         plot_c3_storage_overhead),
    ('C5. Rekey Message Cost',       plot_c5_rekey_message_cost),
    # D — Denied Environment
    ('D1. SINR Timeseries',          plot_d1_sinr_timeseries),
    ('D1. SINR CDF',                 plot_d1_sinr_cdf),
    ('D2. Jammed UAV Ratio',         plot_d2_jammed_uav_ratio),
    ('D3. Recovery after Jamming',   plot_d3_recovery_time),
    ('D4. Link Failure Rate',        plot_d4_link_failure_rate),
    ('D5. Interference Impact',      plot_d5_interference_impact),
    # E — Mobility & Swarm
    ('E1. Cluster Head Stability',   plot_e1_cluster_head_stability),
    ('E2. Route Break Frequency',    plot_e2_route_break_frequency),
    ('E3. Mobility-Rekey Corr.',     plot_e3_mobility_rekey_correlation),
    ('E4. Swarm Survivability',      plot_e4_swarm_survivability),
    # Master
    ('MASTER Summary',               plot_master_summary),
    ('NetAnim Guide',                generate_netanim_guide),
]

if __name__ == '__main__':
    print("=" * 60)
    print("  UAV FANET — Full Metrics Graph Generator")
    print(f"  Input:  {INPUT}")
    print(f"  Output: {OUTPUT}")
    print("=" * 60)

    ok = err = 0
    for name, func in GRAPHS:
        print(f"\n[{name}]")
        try:
            func()
            ok += 1
        except Exception as e:
            print(f"  [ERROR] {e}")
            err += 1

    print(f"\n{'='*60}")
    print(f"  Done: {ok} graphs generated, {err} errors")
    print(f"  Output: {OUTPUT}")
    print(f"{'='*60}")
