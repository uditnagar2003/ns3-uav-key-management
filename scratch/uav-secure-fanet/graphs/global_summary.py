#!/usr/bin/env python3
"""
Global Metrics Summary
Reads all output CSVs and prints + saves comprehensive global report
"""
import pandas as pd
import numpy as np
from pathlib import Path

BASE    = Path("output/rekey_perf")
METRICS = BASE / "metrics"
GRAPHS  = BASE / "graphs"
GRAPHS.mkdir(parents=True, exist_ok=True)

def load(name):
    p = METRICS / name
    if p.exists():
        return pd.read_csv(p)
    print(f"[WARN] Missing: {p}")
    return pd.DataFrame()

def load_scal():
    p = BASE / "scalability.csv"
    return pd.read_csv(p) if p.exists() else pd.DataFrame()

def main():
    scal     = load_scal()
    cluster  = load("metrics_per_cluster.csv")
    security = load("metrics_security.csv")
    network  = load("metrics_network.csv")
    overhead = load("metrics_overhead.csv")
    rekey    = load("rekey_latency_full.csv")
    sinr     = load("sinr_log.csv")
    auth     = load("auth_log.csv")
    secrecy  = load("secrecy_checks.csv")
    timeseries = load("timeseries.csv")

    lines = []
    def p(s=""): 
        print(s)
        lines.append(s)

    p("=" * 65)
    p("  GLOBAL SIMULATION METRICS SUMMARY")
    p("  Hierarchical CRT-GCRT UAV FANET — Denied Environment")
    p("=" * 65)

    # ── A. NETWORK PERFORMANCE ────────────────────────────────────
    p("\n[A] NETWORK PERFORMANCE")
    p("-" * 40)
    if not scal.empty:
        g = scal.groupby('uav_count').agg(
            pdr_mean=('pdr','mean'),
            pdr_std=('pdr','std'),
            tput_mean=('throughput_kbps','mean'),
            tput_std=('throughput_kbps','std'),
            delay_mean=('avg_delay_ms','mean'),
            delay_std=('avg_delay_ms','std'),
        ).reset_index()
        p(f"  {'UAVs':<6} {'PDR':>10} {'Tput(kbps)':>14} {'Delay(ms)':>12}")
        p(f"  {'-'*6} {'-'*10} {'-'*14} {'-'*12}")
        for _, r in g.iterrows():
            p(f"  {int(r.uav_count):<6} "
              f"{r.pdr_mean:.4f}±{r.pdr_std:.3f}  "
              f"{r.tput_mean:.4f}±{r.tput_std:.4f}  "
              f"{r.delay_mean:.3f}±{r.delay_std:.3f}")
        p(f"\n  Global PDR:         {scal['pdr'].mean():.4f} ± {scal['pdr'].std():.4f}")
        p(f"  Global Throughput:  {scal['throughput_kbps'].mean():.4f} ± {scal['throughput_kbps'].std():.4f} kbps")
        p(f"  Global Delay:       {scal['avg_delay_ms'].mean():.4f} ± {scal['avg_delay_ms'].std():.4f} ms")

    # ── B. SECURITY METRICS ───────────────────────────────────────
    p("\n[B] SECURITY METRICS")
    p("-" * 40)
    if not scal.empty:
        g2 = scal.groupby('uav_count').agg(
            rekeys_mean=('total_rekeys','mean'),
            rekeys_std=('total_rekeys','std'),
            lat_mean=('rekey_latency_ms','mean'),
            lat_std=('rekey_latency_ms','std'),
            sec_ovhd=('security_overhead','mean'),
        ).reset_index()
        p(f"  {'UAVs':<6} {'Rekeys':>8} {'RekeyLat(ms)':>14} {'SecOvhd/s':>12}")
        p(f"  {'-'*6} {'-'*8} {'-'*14} {'-'*12}")
        for _, r in g2.iterrows():
            p(f"  {int(r.uav_count):<6} "
              f"{r.rekeys_mean:.1f}±{r.rekeys_std:.1f}  "
              f"{r.lat_mean:.4f}±{r.lat_std:.4f}    "
              f"{r.sec_ovhd:.4f}")

    if not rekey.empty:
        p(f"\n  Rekey Latency by Trigger Type:")
        if 'trigger' in rekey.columns:
            by_t = rekey.groupby('trigger')['latency_ms'].agg(['mean','std','count'])
            for trig, row in by_t.iterrows():
                p(f"    {trig:<12}: {row['mean']:.3f} ± {row['std']:.3f} ms  (n={int(row['count'])})")
        p(f"\n  Total rekey events recorded: {len(rekey)}")
        p(f"  Latency range: {rekey['latency_ms'].min():.3f} – {rekey['latency_ms'].max():.3f} ms")

    if not auth.empty and 'success' in auth.columns:
        rate = auth['success'].mean()
        p(f"\n  Auth success rate:   {rate:.4f} ({rate*100:.1f}%)")

    if not secrecy.empty:
        if 'forward_ok' in secrecy.columns:
            p(f"  Forward secrecy:     {secrecy['forward_ok'].mean():.4f}")
        if 'backward_ok' in secrecy.columns:
            p(f"  Backward secrecy:    {secrecy['backward_ok'].mean():.4f}")

    # ── C. OVERHEAD ───────────────────────────────────────────────
    p("\n[C] OVERHEAD METRICS")
    p("-" * 40)
    if not scal.empty:
        p(f"  Joins  total: {scal['total_joins'].mean():.1f} avg per scenario")
        p(f"  Leaves total: {scal['total_leaves'].mean():.1f} avg per scenario")
        p(f"  Handovers:    {scal['total_handovers'].mean():.1f} avg per scenario")
        p(f"  Compromises:  {scal['total_compromises'].mean():.1f} avg per scenario")

    # ── D. SINR / JAMMER ─────────────────────────────────────────
    p("\n[D] SINR / DENIED ENVIRONMENT")
    p("-" * 40)
    if not sinr.empty and 'sinr_db' in sinr.columns:
        p(f"  Avg SINR:     {sinr['sinr_db'].mean():.3f} dB")
        p(f"  Min SINR:     {sinr['sinr_db'].min():.3f} dB")
        p(f"  Max SINR:     {sinr['sinr_db'].max():.3f} dB")
        below = (sinr['sinr_db'] < 8).mean()
        p(f"  Below 8dB:    {below*100:.2f}% of samples (jammer impact)")
    elif not timeseries.empty and 'sinr_db' in timeseries.columns:
        p(f"  Avg SINR:     {timeseries['sinr_db'].mean():.3f} dB")
        p(f"  Min SINR:     {timeseries['sinr_db'].min():.3f} dB")

    # ── E. PER CLUSTER ────────────────────────────────────────────
    p("\n[E] PER-CLUSTER SUMMARY")
    p("-" * 40)
    if not cluster.empty:
        p(f"  {'Cluster':<10} {'PDR':>8} {'Tput(kbps)':>12} {'Delay(ms)':>10} {'Rekeys':>8}")
        p(f"  {'-'*10} {'-'*8} {'-'*12} {'-'*10} {'-'*8}")
        for _, r in cluster.iterrows():
            p(f"  C{int(r.cluster_id):<9} "
              f"{r.avg_pdr:.4f}   "
              f"{r.throughput_kbps:.4f}       "
              f"{r.avg_delay_ms:.4f}    "
              f"{r.rekeys:.0f}")

    p("\n" + "=" * 65)

    # Save to file
    out = GRAPHS / "global_summary.txt"
    with open(out, 'w') as f:
        f.write('\n'.join(lines))
    print(f"\n[OK] Saved: {out}")

    # Save as CSV too
    if not scal.empty:
        g_all = scal.groupby('uav_count').agg(
            pdr_mean=('pdr','mean'), pdr_std=('pdr','std'),
            tput_mean=('throughput_kbps','mean'), tput_std=('throughput_kbps','std'),
            delay_mean=('avg_delay_ms','mean'), delay_std=('avg_delay_ms','std'),
            rekeys_mean=('total_rekeys','mean'), rekeys_std=('total_rekeys','std'),
            lat_mean=('rekey_latency_ms','mean'), lat_std=('rekey_latency_ms','std'),
            sec_ovhd=('security_overhead','mean'),
            joins=('total_joins','mean'),
            leaves=('total_leaves','mean'),
            handovers=('total_handovers','mean'),
        ).reset_index()
        out_csv = GRAPHS / "global_summary.csv"
        g_all.to_csv(out_csv, index=False)
        print(f"[OK] Saved: {out_csv}")

if __name__ == "__main__":
    main()
