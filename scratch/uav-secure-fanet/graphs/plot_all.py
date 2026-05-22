#!/usr/bin/env python3
"""
graphs/plot_all.py
Module 64 — Graph Generation Scripts

Generates all research graphs from simulation CSV outputs.

USAGE:
    python3 graphs/plot_all.py [--input-dir DIR] [--output-dir DIR]

GRAPHS GENERATED:
    1.  throughput_vs_uav.png
    2.  pdr_vs_uav.png
    3.  sinr_vs_uav.png
    4.  delay_vs_uav.png
    5.  drop_prob_vs_uav.png
    6.  cluster_throughput.png
    7.  cluster_pdr.png
    8.  rekey_latency_hist.png
    9.  rekey_per_cluster.png
    10. global_metrics_bar.png
    11. sinr_cdf.png
    12. routing_overhead.png
    13. scenario_handovers.png
    14. scenario_rekeys.png
"""

import os, sys, csv, argparse
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
except ImportError:
    print("pip3 install matplotlib numpy")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

parser = argparse.ArgumentParser()
parser.add_argument('--input-dir',
    default=os.path.join(PROJECT_DIR,'output'))
parser.add_argument('--output-dir', default=SCRIPT_DIR)
args = parser.parse_args()

INPUT_DIR  = args.input_dir
OUTPUT_DIR = args.output_dir
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Colors
C = {'green':'#2ecc71','red':'#e74c3c','blue':'#3498db',
     'orange':'#e67e22','purple':'#9b59b6','gray':'#95a5a6',
     'dark':'#2c3e50'}
CLUSTER_COLORS = [C['blue'], C['orange'], C['green']]

print(f"[Graph] Input:  {INPUT_DIR}")
print(f"[Graph] Output: {OUTPUT_DIR}\n")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_csv(filename):
    path = os.path.join(INPUT_DIR, filename)
    if not os.path.exists(path):
        print(f"  [SKIP] {filename} not found")
        return []
    with open(path) as f:
        return list(csv.DictReader(f))

def load_kv(filename='metrics_global.csv'):
    rows = load_csv(filename)
    return {r['metric']: float(r['value'])
            for r in rows if r.get('metric')}

def save(fig, name):
    path = os.path.join(OUTPUT_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  [OK] {name}")

def styled_bar(ax, x, y, colors, title, xlabel, ylabel,
               ylim=None, hline=None):
    bars = ax.bar(x if not isinstance(x[0], str)
                  else range(len(x)),
                  y, color=colors, edgecolor='black',
                  linewidth=0.5)
    ax.set_title(title, fontsize=12, fontweight='bold')
    ax.set_xlabel(xlabel); ax.set_ylabel(ylabel)
    if isinstance(x[0], str):
        ax.set_xticks(range(len(x)))
        ax.set_xticklabels(x)
    else:
        ax.set_xticks(x)
    if ylim: ax.set_ylim(*ylim)
    if hline is not None:
        ax.axhline(y=hline[0], color=hline[1],
                   linestyle='--', linewidth=1.5,
                   label=hline[2], alpha=0.8)
        ax.legend(fontsize=8)
    ax.grid(axis='y', alpha=0.3)
    return bars

# ---------------------------------------------------------------------------
# 1. Throughput per UAV
# ---------------------------------------------------------------------------
def plot_throughput_vs_uav():
    rows = load_csv('throughput.csv')
    if not rows: return
    ids   = [int(r['uav_id']) for r in rows]
    tput  = [float(r['throughput_kbps']) for r in rows]
    cols  = [CLUSTER_COLORS[int(r['cluster_id'])] for r in rows]
    fig, ax = plt.subplots(figsize=(13,4))
    styled_bar(ax, ids, tput, cols,
               'Per-UAV Throughput',
               'UAV ID', 'Throughput (kbps)')
    patches = [mpatches.Patch(color=CLUSTER_COLORS[c],
               label=f'Cluster {c}') for c in range(3)]
    ax.legend(handles=patches, fontsize=8)
    save(fig, 'throughput_vs_uav.png')

# ---------------------------------------------------------------------------
# 2. PDR per UAV
# ---------------------------------------------------------------------------
def plot_pdr_vs_uav():
    rows = load_csv('pdr.csv')
    if not rows: return
    ids  = [int(r['uav_id']) for r in rows]
    pdrs = [float(r['pdr']) for r in rows]
    cols = [CLUSTER_COLORS[int(r['cluster_id'])] for r in rows]
    fig, ax = plt.subplots(figsize=(13,4))
    styled_bar(ax, ids, pdrs, cols,
               'Per-UAV Packet Delivery Ratio',
               'UAV ID', 'PDR',
               ylim=(0,1.15),
               hline=(1.0,'red','PDR=1.0'))
    patches = [mpatches.Patch(color=CLUSTER_COLORS[c],
               label=f'Cluster {c}') for c in range(3)]
    ax.legend(handles=patches, fontsize=8)
    save(fig, 'pdr_vs_uav.png')

# ---------------------------------------------------------------------------
# 3. SINR per UAV
# ---------------------------------------------------------------------------
def plot_sinr_vs_uav():
    rows = load_csv('sinr.csv')
    if not rows: return
    ids   = [int(r['uav_id']) for r in rows]
    sinrs = [float(r['sinr_db']) for r in rows]
    cols  = [C['red'] if int(r['jammed']) else C['green']
             for r in rows]
    fig, ax = plt.subplots(figsize=(13,4))
    ax.bar(ids, sinrs, color=cols, edgecolor='black',
           linewidth=0.5)
    ax.axhline(y=8.0, color='black', linestyle='--',
               linewidth=2, label='Threshold (8 dB)')
    ax.set_title('Per-UAV SINR — Denied Environment',
                 fontsize=12, fontweight='bold')
    ax.set_xlabel('UAV ID'); ax.set_ylabel('SINR (dB)')
    ax.set_xticks(ids)
    patches = [mpatches.Patch(color=C['red'],  label='Jammed'),
               mpatches.Patch(color=C['green'],label='Normal')]
    ax.legend(handles=patches, fontsize=8)
    ax.grid(axis='y', alpha=0.3)
    save(fig, 'sinr_vs_uav.png')

# ---------------------------------------------------------------------------
# 4. Delay per UAV
# ---------------------------------------------------------------------------
def plot_delay_vs_uav():
    rows = load_csv('delay.csv')
    if not rows: return
    ids    = [int(r['uav_id']) for r in rows]
    delays = [float(r['avg_delay_ms']) for r in rows]
    cols   = [CLUSTER_COLORS[int(r['cluster_id'])] for r in rows]
    fig, ax = plt.subplots(figsize=(13,4))
    styled_bar(ax, ids, delays, cols,
               'Per-UAV End-to-End Delay',
               'UAV ID', 'Avg Delay (ms)')
    patches = [mpatches.Patch(color=CLUSTER_COLORS[c],
               label=f'Cluster {c}') for c in range(3)]
    ax.legend(handles=patches, fontsize=8)
    save(fig, 'delay_vs_uav.png')

# ---------------------------------------------------------------------------
# 5. Drop probability per UAV
# ---------------------------------------------------------------------------
def plot_drop_prob():
    rows = load_csv('sinr.csv')
    if not rows: return
    ids   = [int(r['uav_id']) for r in rows]
    drops = [float(r['drop_prob']) for r in rows]
    fig, ax = plt.subplots(figsize=(13,4))
    styled_bar(ax, ids, drops,
               [C['orange']]*len(ids),
               'Per-UAV Packet Drop Probability (Jammer Impact)',
               'UAV ID', 'Drop Probability',
               ylim=(0,1.0),
               hline=(0.5,'red','50% drop'))
    save(fig, 'drop_prob_vs_uav.png')

# ---------------------------------------------------------------------------
# 6. Per-cluster throughput
# ---------------------------------------------------------------------------
def plot_cluster_throughput():
    rows = load_csv('metrics_per_cluster.csv')
    if not rows: return
    cids = [f"C{r['cluster_id']}" for r in rows]
    tput = [float(r['throughput_kbps']) for r in rows]
    fig, ax = plt.subplots(figsize=(6,4))
    bars = styled_bar(ax, cids, tput, CLUSTER_COLORS,
               'Per-Cluster Throughput',
               'Cluster', 'Throughput (kbps)')
    for bar, v in zip(bars, tput):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()+0.001,
                f'{v:.4f}', ha='center', fontsize=9)
    save(fig, 'cluster_throughput.png')

# ---------------------------------------------------------------------------
# 7. Per-cluster PDR
# ---------------------------------------------------------------------------
def plot_cluster_pdr():
    rows = load_csv('metrics_per_cluster.csv')
    if not rows: return
    cids = [f"C{r['cluster_id']}" for r in rows]
    pdrs = [float(r['avg_pdr']) for r in rows]
    fig, ax = plt.subplots(figsize=(6,4))
    bars = styled_bar(ax, cids, pdrs, CLUSTER_COLORS,
               'Per-Cluster PDR',
               'Cluster', 'PDR',
               ylim=(0,1.15),
               hline=(1.0,'red','PDR=1.0'))
    for bar, v in zip(bars, pdrs):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()+0.01,
                f'{v:.3f}', ha='center', fontsize=9)
    save(fig, 'cluster_pdr.png')

# ---------------------------------------------------------------------------
# 8. Rekey latency histogram
# ---------------------------------------------------------------------------
def plot_rekey_latency_hist():
    rows = load_csv('rekey_latency.csv')
    if not rows: return
    lats = [float(r['latency_ms']) for r in rows]
    fig, ax = plt.subplots(figsize=(8,4))
    ax.hist(lats, bins=30, color=C['blue'],
            edgecolor='black', alpha=0.7)
    mean_v = np.mean(lats)
    ax.axvline(x=mean_v, color='red', linestyle='--',
               linewidth=2, label=f'Mean={mean_v:.2f}ms')
    ax.set_xlabel('Rekey Latency (ms)')
    ax.set_ylabel('Frequency')
    ax.set_title(f'Rekey Latency Distribution (n={len(lats)})',
                 fontsize=12, fontweight='bold')
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3)
    save(fig, 'rekey_latency_hist.png')

# ---------------------------------------------------------------------------
# 9. Rekey per cluster pie
# ---------------------------------------------------------------------------
def plot_rekey_per_cluster():
    rows = load_csv('rekey_latency.csv')
    if not rows: return
    counts = defaultdict(int)
    for r in rows:
        counts[int(r['cluster_id'])] += 1
    if not counts: return
    labels = [f'C{c}' for c in sorted(counts)]
    sizes  = [counts[c] for c in sorted(counts)]
    colors = [CLUSTER_COLORS[c] for c in sorted(counts)]
    fig, ax = plt.subplots(figsize=(6,5))
    ax.pie(sizes, labels=labels, colors=colors,
           autopct='%1.1f%%', startangle=90,
           wedgeprops={'edgecolor':'black','linewidth':0.5})
    ax.set_title(f'Rekey Events per Cluster\n(total={sum(sizes)})',
                 fontsize=12, fontweight='bold')
    save(fig, 'rekey_per_cluster.png')

# ---------------------------------------------------------------------------
# 10. Global metrics bar
# ---------------------------------------------------------------------------
def plot_global_metrics():
    gm = load_kv()
    if not gm: return
    names = ['PDR', 'Tput\n(kbps)', 'Delay\n(ms)',
             'Ovhd\n(%)', 'Jammed\nUAVs']
    vals  = [
        gm.get('global_pdr', 0),
        gm.get('global_throughput_kbps', 0),
        gm.get('global_avg_delay_ms', 0),
        gm.get('routing_overhead_ratio', 0) * 100,
        gm.get('jammed_uav_count', 0),
    ]
    cols = [C['green'],C['blue'],C['orange'],
            C['purple'],C['red']]
    fig, ax = plt.subplots(figsize=(10,4))
    bars = ax.bar(range(len(names)), vals, color=cols,
                  edgecolor='black')
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, fontsize=10)
    ax.set_title('Global Simulation Metrics — 300s Run',
                 fontsize=12, fontweight='bold')
    ax.set_ylabel('Value')
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()*1.02,
                f'{v:.3f}', ha='center', fontsize=8)
    ax.grid(axis='y', alpha=0.3)
    save(fig, 'global_metrics_bar.png')

# ---------------------------------------------------------------------------
# 11. SINR CDF
# ---------------------------------------------------------------------------
def plot_sinr_cdf():
    rows = load_csv('sinr.csv')
    if not rows: return
    sinrs = sorted([float(r['sinr_db']) for r in rows])
    n     = len(sinrs)
    cdf   = [(i+1)/n for i in range(n)]
    fig, ax = plt.subplots(figsize=(8,5))
    ax.plot(sinrs, cdf, color=C['blue'], linewidth=2.5,
            marker='o', markersize=5, label='SINR CDF')
    ax.axvline(x=8.0, color='red', linestyle='--',
               linewidth=2, label='Threshold (8 dB)')
    ax.fill_betweenx(cdf, sinrs, 8.0,
                     where=[s < 8.0 for s in sinrs],
                     alpha=0.15, color='red',
                     label='Below threshold')
    ax.set_xlabel('SINR (dB)', fontsize=11)
    ax.set_ylabel('CDF', fontsize=11)
    ax.set_title('SINR Cumulative Distribution Function',
                 fontsize=12, fontweight='bold')
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3)
    save(fig, 'sinr_cdf.png')

# ---------------------------------------------------------------------------
# 12. Routing overhead
# ---------------------------------------------------------------------------
def plot_routing_overhead():
    rows = load_csv('routing_overhead.csv')
    if not rows: return
    data = {r['metric']: float(r['value']) for r in rows}
    ctrl = data.get('total_ctrl_bytes', 0)
    datb = data.get('total_data_bytes', 0)
    bps  = data.get('ctrl_bytes_per_sec', 0)
    ratio= data.get('routing_overhead_ratio', 0) * 100

    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    fig.suptitle('Routing Overhead Analysis',
                 fontsize=12, fontweight='bold')

    # Pie
    total = ctrl + datb
    if total > 0:
        axes[0].pie([ctrl, datb],
            labels=[f'OLSR Ctrl\n({ctrl:.0f}B)',
                    f'Data\n({datb:.0f}B)'],
            colors=[C['orange'], C['blue']],
            autopct='%1.1f%%', startangle=90,
            wedgeprops={'edgecolor':'black','linewidth':0.5})
        axes[0].set_title('Traffic Composition')

    # Bar
    axes[1].bar(['Ctrl\nBytes', 'Data\nBytes', 'Ctrl\nB/s'],
                [ctrl, datb, bps],
                color=[C['orange'], C['blue'], C['red']],
                edgecolor='black')
    axes[1].set_ylabel('Value')
    axes[1].set_title(f'Overhead Ratio: {ratio:.1f}%')
    axes[1].grid(axis='y', alpha=0.3)
    for i, v in enumerate([ctrl, datb, bps]):
        axes[1].text(i, v*1.02, f'{v:.0f}',
                     ha='center', fontsize=9)
    plt.tight_layout()
    save(fig, 'routing_overhead.png')

# ---------------------------------------------------------------------------
# 13. Scenario handovers comparison
# ---------------------------------------------------------------------------
def plot_scenario_handovers():
    # Load from scenario results CSVs
    scenarios_dir = os.path.join(INPUT_DIR, 'scenarios')
    if not os.path.exists(scenarios_dir): return

    scenario_data = {}
    for sc in os.listdir(scenarios_dir):
        results = os.path.join(scenarios_dir, sc, 'results.csv')
        if not os.path.exists(results): continue
        handovers = []
        with open(results) as f:
            for row in csv.DictReader(f):
                try:
                    handovers.append(int(row['handovers']))
                except (ValueError, KeyError):
                    pass
        if handovers:
            scenario_data[sc] = handovers

    if not scenario_data: return

    names = list(scenario_data.keys())
    means = [np.mean(v) for v in scenario_data.values()]
    stds  = [np.std(v)  for v in scenario_data.values()]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(names))
    bars = ax.bar(x, means, yerr=stds, capsize=5,
                  color=C['blue'], edgecolor='black',
                  alpha=0.8, error_kw={'linewidth':1.5})
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15, ha='right', fontsize=9)
    ax.set_xlabel('Scenario')
    ax.set_ylabel('Handovers (mean ± std)')
    ax.set_title('Handover Count per Scenario',
                 fontsize=12, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    for bar, m in zip(bars, means):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()+2,
                f'{m:.0f}', ha='center', fontsize=8)
    plt.tight_layout()
    save(fig, 'scenario_handovers.png')

# ---------------------------------------------------------------------------
# 14. Scenario rekeys comparison
# ---------------------------------------------------------------------------
def plot_scenario_rekeys():
    scenarios_dir = os.path.join(INPUT_DIR, 'scenarios')
    if not os.path.exists(scenarios_dir): return

    scenario_data = {}
    for sc in os.listdir(scenarios_dir):
        results = os.path.join(scenarios_dir, sc, 'results.csv')
        if not os.path.exists(results): continue
        rekeys = []
        with open(results) as f:
            for row in csv.DictReader(f):
                try:
                    rekeys.append(int(row['rekeys']))
                except (ValueError, KeyError):
                    pass
        if rekeys:
            scenario_data[sc] = rekeys

    if not scenario_data: return

    names = list(scenario_data.keys())
    means = [np.mean(v) for v in scenario_data.values()]
    stds  = [np.std(v)  for v in scenario_data.values()]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(names))
    bars = ax.bar(x, means, yerr=stds, capsize=5,
                  color=C['orange'], edgecolor='black',
                  alpha=0.8, error_kw={'linewidth':1.5})
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15, ha='right', fontsize=9)
    ax.set_xlabel('Scenario')
    ax.set_ylabel('Rekeys (mean ± std)')
    ax.set_title('Rekey Count per Scenario',
                 fontsize=12, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    for bar, m in zip(bars, means):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()+2,
                f'{m:.0f}', ha='center', fontsize=8)
    plt.tight_layout()
    save(fig, 'scenario_rekeys.png')

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
GRAPHS = [
    ("Throughput vs UAV",        plot_throughput_vs_uav),
    ("PDR vs UAV",               plot_pdr_vs_uav),
    ("SINR vs UAV",              plot_sinr_vs_uav),
    ("Delay vs UAV",             plot_delay_vs_uav),
    ("Drop Probability",         plot_drop_prob),
    ("Cluster Throughput",       plot_cluster_throughput),
    ("Cluster PDR",              plot_cluster_pdr),
    ("Rekey Latency Histogram",  plot_rekey_latency_hist),
    ("Rekey per Cluster",        plot_rekey_per_cluster),
    ("Global Metrics Bar",       plot_global_metrics),
    ("SINR CDF",                 plot_sinr_cdf),
    ("Routing Overhead",         plot_routing_overhead),
    ("Scenario Handovers",       plot_scenario_handovers),
    ("Scenario Rekeys",          plot_scenario_rekeys),
]

if __name__ == '__main__':
    print("=== UAV FANET Graph Generator — Module 64 ===\n")
    ok = 0
    for name, func in GRAPHS:
        print(f"[{name}]")
        try:
            func()
            ok += 1
        except Exception as e:
            print(f"  [ERROR] {e}")
    print(f"\n=== Generated {ok}/{len(GRAPHS)} graphs ===")
    print(f"Output: {OUTPUT_DIR}")
