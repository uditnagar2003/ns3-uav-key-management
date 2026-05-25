#!/usr/bin/env python3
"""
graphs/plot_rekey_perf.py
Auto-generated graphs for rekey_perf scenario.
Called automatically after RunAll() completes.

USAGE:
    python3 graphs/plot_rekey_perf.py \
        --input output/rekey_perf \
        --output output/rekey_perf/graphs
"""

import os, sys, csv, argparse
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("[Graph] pip3 install matplotlib numpy")
    sys.exit(0)

parser = argparse.ArgumentParser()
parser.add_argument('--input',
    default='output/rekey_perf')
parser.add_argument('--output',
    default='output/rekey_perf/graphs')
args = parser.parse_args()

os.makedirs(args.output, exist_ok=True)

csv_path = os.path.join(args.input, 'scalability.csv')
if not os.path.exists(csv_path):
    print(f"[Graph] {csv_path} not found")
    sys.exit(0)

# Load data
data = defaultdict(list)
with open(csv_path) as f:
    for row in csv.DictReader(f):
        data[int(row['uav_count'])].append(row)

uav_ns = sorted(data.keys())
if not uav_ns:
    print("[Graph] No data")
    sys.exit(0)

C = {'blue':'#3498db','green':'#2ecc71',
     'orange':'#e67e22','red':'#e74c3c',
     'purple':'#9b59b6','gray':'#95a5a6'}

def mean_std(metric, n):
    vals = [float(r[metric]) for r in data[n]]
    return np.mean(vals), np.std(vals)

def line_plot(metric, title, ylabel, color, fname):
    means = [mean_std(metric, n)[0] for n in uav_ns]
    stds  = [mean_std(metric, n)[1] for n in uav_ns]
    fig, ax = plt.subplots(figsize=(8,4))
    ax.errorbar(uav_ns, means, yerr=stds,
                marker='o', linewidth=2.5,
                capsize=5, color=color,
                markerfacecolor='white',
                markeredgewidth=2)
    ax.fill_between(uav_ns,
        [m-s for m,s in zip(means,stds)],
        [m+s for m,s in zip(means,stds)],
        alpha=0.15, color=color)
    ax.set_xlabel('UAV Count', fontsize=11)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.set_title(title, fontsize=12,
                 fontweight='bold')
    ax.set_xticks(uav_ns)
    ax.grid(alpha=0.3)
    path = os.path.join(args.output, fname)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  [OK] {fname}")

# Individual graphs
line_plot('pdr',             'PDR vs UAV Count',
          'PDR (0-1)',       C['green'], 'pdr_vs_uav.png')
line_plot('throughput_kbps', 'Throughput vs UAV Count',
          'Throughput (kbps)', C['blue'], 'throughput_vs_uav.png')
line_plot('avg_delay_ms',    'E2E Delay vs UAV Count',
          'Delay (ms)',      C['orange'], 'delay_vs_uav.png')
line_plot('total_rekeys',    'Rekeys vs UAV Count',
          'Rekey Count',     C['purple'], 'rekeys_vs_uav.png')
line_plot('security_overhead','Security Overhead vs UAV Count',
          'Events/sec',      C['red'], 'security_overhead.png')
line_plot('rekey_latency_ms','Rekey Latency vs UAV Count',
          'Latency (ms)',    C['gray'], 'rekey_latency.png')

# Combined research summary figure
fig, axes = plt.subplots(2, 3, figsize=(15, 8))
fig.suptitle(
    'Hierarchical CRT-GCRT UAV Swarm Multicast Key Management\n'
    'Performance Evaluation — Denied FANET Environment',
    fontsize=13, fontweight='bold')

panels = [
    ('pdr',             'PDR vs UAV Count',
     'PDR',             C['green'],  axes[0,0]),
    ('throughput_kbps', 'Throughput vs UAV Count',
     'kbps',            C['blue'],   axes[0,1]),
    ('avg_delay_ms',    'E2E Delay vs UAV Count',
     'ms',              C['orange'], axes[0,2]),
    ('total_rekeys',    'Rekeys vs UAV Count',
     'Count',           C['purple'], axes[1,0]),
    ('rekey_latency_ms','Rekey Latency vs UAV Count',
     'ms',              C['gray'],   axes[1,1]),
    ('security_overhead','Security Overhead',
     'Events/s',        C['red'],    axes[1,2]),
]

for metric, title, ylabel, color, ax in panels:
    means = [mean_std(metric, n)[0] for n in uav_ns]
    stds  = [mean_std(metric, n)[1] for n in uav_ns]
    ax.errorbar(uav_ns, means, yerr=stds,
                marker='o', linewidth=2,
                capsize=4, color=color)
    ax.fill_between(uav_ns,
        [m-s for m,s in zip(means,stds)],
        [m+s for m,s in zip(means,stds)],
        alpha=0.12, color=color)
    ax.set_title(title, fontsize=9,
                 fontweight='bold')
    ax.set_xlabel('UAV Count', fontsize=9)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.set_xticks(uav_ns)
    ax.grid(alpha=0.3)

plt.tight_layout()
path = os.path.join(args.output,
                    'research_summary.png')
fig.savefig(path, dpi=150, bbox_inches='tight')
plt.close(fig)
print(f"  [OK] research_summary.png")
print(f"\n[Graph] All graphs: {args.output}")

# ===========================================================================
# Timing graphs — appended automatically
# ===========================================================================

def plot_crypto_timing(input_dir, output_dir):
    """Plot crypto operation timing from crypto_timing.csv"""
    import glob
    
    # Collect from all runs
    all_data = defaultdict(list)
    for f in glob.glob(os.path.join(input_dir, 'csv', 'crypto_timing.csv')):
        with open(f) as fp:
            for row in csv.DictReader(fp):
                all_data[row['operation']].append(
                    float(row['wall_us']))

    if not all_data:
        print("  [SKIP] crypto_timing.csv not found")
        return

    ops   = list(all_data.keys())
    means = [np.mean(all_data[op]) for op in ops]
    stds  = [np.std (all_data[op]) for op in ops]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(range(len(ops)), means,
                  yerr=stds, capsize=5,
                  color=['#3498db','#2ecc71',
                         '#e67e22','#9b59b6',
                         '#e74c3c'][:len(ops)],
                  edgecolor='black', alpha=0.8)
    ax.set_xticks(range(len(ops)))
    ax.set_xticklabels(ops, rotation=15,
                       ha='right', fontsize=9)
    ax.set_ylabel('Wall-clock Time (µs)',
                  fontsize=11)
    ax.set_title(
        'CRT-GCRT Cryptographic Operation Timing\n'
        '(Real CPU Wall-clock Measurements)',
        fontsize=12, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    for bar, m in zip(bars, means):
        ax.text(bar.get_x()+bar.get_width()/2,
                bar.get_height()*1.02,
                f'{m:.0f}µs',
                ha='center', fontsize=8)
    plt.tight_layout()
    path = os.path.join(output_dir,
                        'crypto_timing.png')
    fig.savefig(path, dpi=150,
                bbox_inches='tight')
    plt.close(fig)
    print(f"  [OK] crypto_timing.png")


def plot_event_latency(input_dir, output_dir):
    """Plot event processing latency"""
    import glob

    all_data = defaultdict(list)
    for f in glob.glob(os.path.join(
            input_dir, 'csv', 'event_processing.csv')):
        with open(f) as fp:
            for row in csv.DictReader(fp):
                lat = float(row.get('latency_ms', 0))
                all_data[row['event_type']].append(lat)

    if not all_data:
        print("  [SKIP] event_processing.csv not found")
        return

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle(
        'Security Event Processing Latency\n'
        '(NS-3 Simulation Time)',
        fontsize=12, fontweight='bold')

    # Bar chart — mean latency per event type
    evts  = list(all_data.keys())
    means = [np.mean(all_data[e]) for e in evts]
    stds  = [np.std (all_data[e]) for e in evts]

    axes[0].bar(range(len(evts)), means,
                yerr=stds, capsize=5,
                color=['#2ecc71','#e74c3c',
                       '#3498db','#e67e22',
                       '#9b59b6'][:len(evts)],
                edgecolor='black', alpha=0.8)
    axes[0].set_xticks(range(len(evts)))
    axes[0].set_xticklabels(evts, rotation=15,
                             ha='right')
    axes[0].set_ylabel('Latency (ms)')
    axes[0].set_title('Mean Event Latency')
    axes[0].grid(axis='y', alpha=0.3)

    # Box plot — distribution
    box_data = [all_data[e] for e in evts]
    if all(len(d) > 0 for d in box_data):
        axes[1].boxplot(box_data, labels=evts,
                        patch_artist=True)
        axes[1].set_ylabel('Latency (ms)')
        axes[1].set_title('Latency Distribution')
        axes[1].tick_params(axis='x',
                            rotation=15)
        axes[1].grid(axis='y', alpha=0.3)

    plt.tight_layout()
    path = os.path.join(output_dir,
                        'event_latency.png')
    fig.savefig(path, dpi=150,
                bbox_inches='tight')
    plt.close(fig)
    print(f"  [OK] event_latency.png")


def plot_crypto_vs_uav(input_dir, output_dir):
    """Plot crypto timing vs UAV count from scalability CSV"""
    sc_path = os.path.join(input_dir,
                           'scalability.csv')
    if not os.path.exists(sc_path):
        return

    data = defaultdict(list)
    with open(sc_path) as f:
        for row in csv.DictReader(f):
            data[int(row['uav_count'])].append(row)

    if not data:
        return

    uav_ns = sorted(data.keys())

    # Use slave_key_assign timing from crypto CSV
    # Approximate: rekey_latency_ms as proxy
    rl_means = [
        np.mean([float(r['rekey_latency_ms'])
                 for r in data[n]])
        for n in uav_ns]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(uav_ns, rl_means, marker='o',
            linewidth=2.5, color='#9b59b6',
            markerfacecolor='white',
            markeredgewidth=2)
    ax.set_xlabel('UAV Count', fontsize=11)
    ax.set_ylabel('Rekey Latency (ms)',
                  fontsize=11)
    ax.set_title(
        'Rekey Latency vs UAV Count\n'
        '(CRT-GCRT Key Management Overhead)',
        fontsize=12, fontweight='bold')
    ax.set_xticks(uav_ns)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    path = os.path.join(output_dir,
                        'rekey_latency_vs_uav.png')
    fig.savefig(path, dpi=150,
                bbox_inches='tight')
    plt.close(fig)
    print(f"  [OK] rekey_latency_vs_uav.png")


def plot_timing_summary(input_dir, output_dir):
    """Combined timing summary figure"""
    import glob

    crypto_data = defaultdict(list)
    for f in glob.glob(os.path.join(
            input_dir, 'csv', 'crypto_timing.csv')):
        with open(f) as fp:
            for row in csv.DictReader(fp):
                crypto_data[row['operation']].append(
                    float(row['wall_us']))

    if not crypto_data:
        return

    fig, axes = plt.subplots(1, 2, figsize=(14,5))
    fig.suptitle(
        'CRT-GCRT Key Management Performance\n'
        'Hierarchical UAV Swarm Security',
        fontsize=13, fontweight='bold')

    # Crypto timing bar
    ops   = list(crypto_data.keys())
    means = [np.mean(crypto_data[op])
             for op in ops]
    colors = ['#e74c3c','#3498db','#2ecc71',
              '#e67e22','#9b59b6']

    bars = axes[0].bar(range(len(ops)), means,
        color=colors[:len(ops)],
        edgecolor='black', alpha=0.85)
    axes[0].set_xticks(range(len(ops)))
    axes[0].set_xticklabels(ops, rotation=20,
                             ha='right',
                             fontsize=8)
    axes[0].set_ylabel('Time (µs)')
    axes[0].set_title(
        'Crypto Operation Timing (µs)',
        fontweight='bold')
    axes[0].grid(axis='y', alpha=0.3)
    for bar, m in zip(bars, means):
        axes[0].text(
            bar.get_x()+bar.get_width()/2,
            bar.get_height()*1.02,
            f'{m/1000:.1f}ms' if m > 1000
            else f'{m:.0f}µs',
            ha='center', fontsize=7)

    # Pie chart — proportion of crypto overhead
    axes[1].pie(means, labels=ops,
                colors=colors[:len(ops)],
                autopct='%1.1f%%',
                startangle=90,
                wedgeprops={'edgecolor':'black',
                            'linewidth':0.5})
    axes[1].set_title(
        'Crypto Overhead Distribution',
        fontweight='bold')

    plt.tight_layout()
    path = os.path.join(output_dir,
                        'timing_summary.png')
    fig.savefig(path, dpi=150,
                bbox_inches='tight')
    plt.close(fig)
    print(f"  [OK] timing_summary.png")


# Run timing graphs
print("\n[Timing Graphs]")
plot_crypto_timing(args.input, args.output)
plot_event_latency(args.input, args.output)
plot_crypto_vs_uav(args.input, args.output)
plot_timing_summary(args.input, args.output)
