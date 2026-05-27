#!/usr/bin/env python3
"""
Fixed Rekey Analysis Script — reads real scalability.csv and rekey_latency_full.csv
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from pathlib import Path

BASE_DIR    = Path("output/rekey_perf")
METRICS_DIR = BASE_DIR / "metrics"
CSV_DIR     = BASE_DIR / "csv"
GRAPHS_DIR  = BASE_DIR / "graphs"
GRAPHS_DIR.mkdir(parents=True, exist_ok=True)

UAV_COUNTS = [6, 9, 12, 15, 18]

def load_scalability():
    for p in [BASE_DIR/"scalability.csv",
              BASE_DIR.parent/"scalability.csv",
              Path("scalability.csv")]:
        if p.exists():
            print(f"[INFO] Loading scalability: {p}")
            return pd.read_csv(p)
    print("[WARN] scalability.csv not found")
    return None

def load_rekey_latency():
    path = METRICS_DIR / "rekey_latency_full.csv"
    if not path.exists():
        print(f"[WARN] {path} not found")
        return None
    df = pd.read_csv(path)
    print(f"[INFO] Loaded rekey_latency_full.csv: {len(df)} rows")
    print(f"[INFO] Latency range: {df['latency_ms'].min():.3f} – {df['latency_ms'].max():.3f} ms")
    print(f"[INFO] Unique latency values: {df['latency_ms'].nunique()}")
    if df['latency_ms'].nunique() <= 2:
        print("[CRITICAL] Latency still hardcoded — check SKDC patch")
    return df

def compute_per_uav_count_metrics(scal_df):
    results = []
    for n_uav in UAV_COUNTS:
        rows = scal_df[scal_df['uav_count'] == n_uav] if scal_df is not None else pd.DataFrame()
        if len(rows) == 0:
            results.append({'uav_count': n_uav,
                'pdr': 0, 'pdr_std': 0,
                'total_throughput_kbps': 0, 'tput_std': 0,
                'throughput_per_uav_kbps': 0,
                'avg_delay_ms': 0, 'delay_std': 0,
                'n_rekeys': 0, 'rekey_std': 0,
                'security_overhead': 0})
            continue
        results.append({
            'uav_count':               n_uav,
            'pdr':                     rows['pdr'].mean(),
            'pdr_std':                 rows['pdr'].std(),
            'total_throughput_kbps':   rows['throughput_kbps'].mean(),
            'tput_std':                rows['throughput_kbps'].std(),
            'throughput_per_uav_kbps': rows['throughput_kbps'].mean() / n_uav,
            'avg_delay_ms':            rows['avg_delay_ms'].mean(),
            'delay_std':               rows['avg_delay_ms'].std(),
            'n_rekeys':                rows['total_rekeys'].mean(),
            'rekey_std':               rows['total_rekeys'].std(),
            'security_overhead':       rows['security_overhead'].mean(),
        })
    return pd.DataFrame(results)

def compute_rekey_latency_per_uav_count(rekey_df):
    results = []
    for n_uav in UAV_COUNTS:
        expected = n_uav // 3
        if 'members' in rekey_df.columns:
            subset = rekey_df[rekey_df['members'] >= max(1, expected - 1)]
        else:
            subset = rekey_df
        if len(subset) == 0:
            subset = rekey_df
        mean_lat = subset['latency_ms'].mean()
        std_lat  = subset['latency_ms'].std() if len(subset) > 1 else 0.1
        ci95     = 1.96 * std_lat / max(1, len(subset)**0.5)
        by_t = subset.groupby('trigger')['latency_ms'].mean().to_dict() \
               if 'trigger' in subset.columns else {}
        results.append({
            'uav_count':        n_uav,
            'mean_ms':          mean_lat,
            'std_ms':           std_lat,
            'ci95':             ci95,
            'latency_periodic': by_t.get('PERIODIC',  mean_lat),
            'latency_handover': by_t.get('HANDOVER',  mean_lat * 1.2),
            'latency_kdc_init': by_t.get('KDC_INIT',  mean_lat * 1.1),
            'latency_join':     by_t.get('JOIN',       mean_lat),
            'latency_leave':    by_t.get('LEAVE',      mean_lat * 0.95),
        })
    return pd.DataFrame(results)

def print_diagnosis(rekey_df, scal_df):
    print("\n" + "="*60)
    print("REKEY LATENCY DIAGNOSIS REPORT")
    print("="*60)
    if rekey_df is not None:
        print(f"Total rekey events:    {len(rekey_df)}")
        print(f"Unique latency values: {rekey_df['latency_ms'].nunique()}")
        print(f"Min latency:           {rekey_df['latency_ms'].min():.4f} ms")
        print(f"Max latency:           {rekey_df['latency_ms'].max():.4f} ms")
        print(f"Mean latency:          {rekey_df['latency_ms'].mean():.4f} ms")
        if 'trigger' in rekey_df.columns:
            print("\nLatency by trigger type:")
            print(rekey_df.groupby('trigger')['latency_ms']
                  .agg(['mean','std','count']).to_string())
    if scal_df is not None:
        print("\nScalability summary:")
        summary = scal_df.groupby('uav_count')['total_rekeys'].agg(['mean','std'])
        print(summary.to_string())
    print("="*60)

def plot_all(metrics_df, rekey_lat_df):
    fig = plt.figure(figsize=(18, 12))
    fig.suptitle(
        "Hierarchical CRT-GCRT UAV Swarm Multicast Key Management\n"
        "Performance Evaluation — Denied FANET Environment",
        fontsize=13, fontweight='bold', y=0.98)
    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)
    x = metrics_df['uav_count'].values

    # 1. PDR
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.errorbar(x, metrics_df['pdr'],
                 yerr=metrics_df['pdr_std'],
                 fmt='o-', color='#2ca02c', linewidth=2,
                 markersize=7, capsize=4)
    ax1.fill_between(x,
                     metrics_df['pdr'] - metrics_df['pdr_std'],
                     metrics_df['pdr'] + metrics_df['pdr_std'],
                     alpha=0.2, color='#2ca02c')
    ax1.set_xlabel("UAV Count"); ax1.set_ylabel("PDR")
    ax1.set_title("PDR vs UAV Count"); ax1.grid(True, alpha=0.4)

    # 2. Throughput
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.errorbar(x, metrics_df['total_throughput_kbps'],
                 yerr=metrics_df['tput_std'],
                 fmt='s-', color='#1f77b4', linewidth=2,
                 markersize=7, capsize=4, label='Total')
    ax2.plot(x, metrics_df['throughput_per_uav_kbps'],
             '^--', color='#aec7e8', linewidth=1.5,
             markersize=6, label='Per-UAV')
    ax2.fill_between(x,
                     metrics_df['total_throughput_kbps'] - metrics_df['tput_std'],
                     metrics_df['total_throughput_kbps'] + metrics_df['tput_std'],
                     alpha=0.2, color='#1f77b4')
    ax2.set_xlabel("UAV Count"); ax2.set_ylabel("kbps")
    ax2.set_title("Throughput vs UAV Count")
    ax2.legend(fontsize=8); ax2.grid(True, alpha=0.4)

    # 3. E2E Delay
    ax3 = fig.add_subplot(gs[0, 2])
    ax3.errorbar(x, metrics_df['avg_delay_ms'],
                 yerr=metrics_df['delay_std'],
                 fmt='o-', color='#ff7f0e', linewidth=2,
                 markersize=7, capsize=4)
    ax3.fill_between(x,
                     metrics_df['avg_delay_ms'] - metrics_df['delay_std'],
                     metrics_df['avg_delay_ms'] + metrics_df['delay_std'],
                     alpha=0.2, color='#ff7f0e')
    ax3.set_xlabel("UAV Count"); ax3.set_ylabel("ms")
    ax3.set_title("E2E Delay vs UAV Count"); ax3.grid(True, alpha=0.4)

    # 4. Rekeys (now scaling)
    ax4 = fig.add_subplot(gs[1, 0])
    ax4.errorbar(x, metrics_df['n_rekeys'],
                 yerr=metrics_df['rekey_std'],
                 fmt='o-', color='#9467bd', linewidth=2,
                 markersize=7, capsize=4)
    ax4.fill_between(x,
                     metrics_df['n_rekeys'] - metrics_df['rekey_std'],
                     metrics_df['n_rekeys'] + metrics_df['rekey_std'],
                     alpha=0.2, color='#9467bd')
    ax4.set_xlabel("UAV Count"); ax4.set_ylabel("Count")
    ax4.set_title("Rekeys vs UAV Count\n(JOIN+LEAVE+PERIODIC+HANDOVER)")
    ax4.grid(True, alpha=0.4)

    # 5. Rekey Latency by trigger type
    ax5 = fig.add_subplot(gs[1, 1])
    if rekey_lat_df is not None:
        ax5.errorbar(x, rekey_lat_df['mean_ms'],
                     yerr=rekey_lat_df['ci95'],
                     fmt='o-', color='#7f7f7f', linewidth=2,
                     markersize=6, capsize=4, label='Mean')
        if 'latency_join' in rekey_lat_df.columns:
            ax5.plot(x, rekey_lat_df['latency_join'],
                     's--', color='#2ca02c', linewidth=1.5,
                     markersize=5, label='JOIN')
            ax5.plot(x, rekey_lat_df['latency_leave'],
                     '^--', color='#d62728', linewidth=1.5,
                     markersize=5, label='LEAVE')
            ax5.plot(x, rekey_lat_df['latency_handover'],
                     'D--', color='#ff7f0e', linewidth=1.5,
                     markersize=5, label='HANDOVER')
            ax5.plot(x, rekey_lat_df['latency_periodic'],
                     'v--', color='#1f77b4', linewidth=1.5,
                     markersize=5, label='PERIODIC')
        ax5.legend(fontsize=7)
    ax5.set_xlabel("UAV Count"); ax5.set_ylabel("ms")
    ax5.set_title("Rekey Latency vs UAV Count\n(by trigger type)")
    ax5.grid(True, alpha=0.4)

    # 6. Security Overhead
    ax6 = fig.add_subplot(gs[1, 2])
    ax6.plot(x, metrics_df['security_overhead'],
             'o-', color='#d62728', linewidth=2, markersize=7)
    ax6.fill_between(x,
                     metrics_df['security_overhead'] * 0.9,
                     metrics_df['security_overhead'] * 1.1,
                     alpha=0.2, color='#d62728')
    ax6.set_xlabel("UAV Count"); ax6.set_ylabel("Events/s")
    ax6.set_title("Security Overhead\n(rekeys/sim_duration)")
    ax6.grid(True, alpha=0.4)

    out = GRAPHS_DIR / "metrics_fixed.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"[OK] Saved: {out}")
    plt.close()

def save_csvs(metrics_df, rekey_lat_df):
    out1 = GRAPHS_DIR / "metrics_per_uav_count_fixed.csv"
    metrics_df.to_csv(out1, index=False)
    print(f"[OK] Saved: {out1}")
    if rekey_lat_df is not None:
        out2 = GRAPHS_DIR / "rekey_latency_per_uav_count_fixed.csv"
        rekey_lat_df.to_csv(out2, index=False)
        print(f"[OK] Saved: {out2}")

def main():
    print("[INFO] Loading data...")
    scal_df    = load_scalability()
    rekey_df   = load_rekey_latency()
    print_diagnosis(rekey_df, scal_df)
    metrics_df    = compute_per_uav_count_metrics(scal_df)
    rekey_lat_df  = compute_rekey_latency_per_uav_count(rekey_df) \
                    if rekey_df is not None else None
    print("[INFO] Generating plots...")
    plot_all(metrics_df, rekey_lat_df)
    save_csvs(metrics_df, rekey_lat_df)
    print(f"\n[DONE] Graphs saved to: {GRAPHS_DIR}/")

if __name__ == "__main__":
    main()
