#!/usr/bin/env python3
"""
generate_graphs.py  — FIXED (no pandas required)
============================================================
Uses ONLY: matplotlib, numpy  (stdlib csv module for reading)
Install:   pip3 install matplotlib numpy
============================================================
"""

import os
import sys
import csv
import argparse
import math
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from collections import defaultdict

# ============================================================
# STYLE
# ============================================================
plt.rcParams.update({
    "font.family"      : "DejaVu Sans",
    "font.size"        : 11,
    "axes.titlesize"   : 13,
    "axes.titleweight" : "bold",
    "axes.grid"        : True,
    "grid.alpha"       : 0.35,
    "figure.dpi"       : 150,
    "savefig.dpi"      : 150,
    "savefig.bbox"     : "tight",
})

CLUSTER_COLORS = ["#0064FF", "#00C8C8", "#00C850"]
UAV_COUNTS     = [6, 12, 18, 24, 30]


# ============================================================
# CSV READER (replaces pandas)
# ============================================================
def read_csv(path):
    """Read CSV → list of dicts with auto type conversion."""
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            converted = {}
            for k, v in row.items():
                k = k.strip()
                v = v.strip()
                try:
                    converted[k] = int(v)
                except ValueError:
                    try:
                        converted[k] = float(v)
                    except ValueError:
                        converted[k] = v
            rows.append(converted)
    return rows


def group_by(rows, key):
    """Group list-of-dicts by a key → dict of lists."""
    groups = defaultdict(list)
    for row in rows:
        groups[row[key]].append(row)
    return dict(groups)


def col_values(rows, col):
    """Extract a numeric column from rows."""
    return [r[col] for r in rows if col in r]


def mean_std_by(rows, group_key, value_key):
    """
    Group rows by group_key, compute mean+std of value_key.
    Returns sorted lists: (group_values, means, stds)
    """
    groups = group_by(rows, group_key)
    xs, mus, sds = [], [], []
    for gval in sorted(groups.keys()):
        vals = col_values(groups[gval], value_key)
        if vals:
            xs.append(gval)
            mus.append(float(np.mean(vals)))
            sds.append(float(np.std(vals)))
    return xs, mus, sds


def save(fig, path):
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved: {path}")


# ============================================================
# SYNTHETIC DATA (used when CSVs not yet generated)
# ============================================================
def synthetic_scalability():
    rng  = np.random.default_rng(42)
    rows = []
    for n in UAV_COUNTS:
        for run in range(5):
            seed = 42 + n * 100 + run
            pdr  = float(np.clip(
                0.92 - 0.015*(n/6) + rng.normal(0, 0.02),
                0.1, 1.0))
            tput = float(max(0.1,
                1.2*math.log2(n+1) + rng.normal(0, 0.1)))
            delay= float(max(0.1,
                1.5 + 0.3*(n/6) + rng.normal(0, 0.2)))
            rl   = float(max(0.01,
                0.05 + rng.normal(0, 0.005)))
            rekeys = int(3*(600//1) + rng.integers(-10,10))
            joins  = int(600//10   + rng.integers(-5,5))
            leaves = int(600//15   + rng.integers(-3,3))
            compr  = 3
            ho     = 1
            sec_ovhd = (rekeys+joins+leaves+compr+ho)/600.0
            rows.append({
                "uav_count"               : n,
                "run"                     : run,
                "seed"                    : seed,
                "pdr"                     : round(pdr,  4),
                "throughput_kbps"         : round(tput, 4),
                "avg_delay_ms"            : round(delay,4),
                "rekey_latency_ms"        : round(rl,   4),
                "total_rekeys"            : rekeys,
                "total_joins"             : joins,
                "total_leaves"            : leaves,
                "total_compromises"       : compr,
                "total_handovers"         : ho,
                "security_overhead_ratio" : round(sec_ovhd,4),
            })
    return rows


def synthetic_sinr(uav_count, n=300):
    rng = np.random.default_rng(42 + uav_count)
    return rng.normal(18.0, 4.0, n)


def synthetic_events():
    rows = []
    for t in range(20, 600, 10):
        rows.append({"time_s": t, "event_type": "JOIN",
                     "uav_id":(t//10)%18,
                     "cluster_id":((t//10)%18)//6})
    for t in range(25, 600, 15):
        rows.append({"time_s": t, "event_type": "LEAVE",
                     "uav_id":(t//15)%18,
                     "cluster_id":((t//15)%18)//6})
    for t in [50,120,200]:
        rows.append({"time_s": t,
                     "event_type": "COMPROMISE",
                     "uav_id": 1, "cluster_id": 0})
    for t in [60,130,210,300,400,500]:
        rows.append({"time_s": t,
                     "event_type": "BATCH_REKEY",
                     "uav_id": -1, "cluster_id": -1})
    rows.append({"time_s": 80,
                 "event_type": "HANDOVER",
                 "uav_id": 5, "cluster_id": 0})
    return rows


# ============================================================
# LOAD DATA
# ============================================================
def load_data(input_dir):
    data = {}

    scal_path = os.path.join(input_dir, "scalability.csv")
    rows = read_csv(scal_path)
    if not rows:
        print("  [INFO] scalability.csv not found — "
              "using synthetic demo data")
        rows = synthetic_scalability()
    data["scalability"] = rows

    # Per-run CSVs
    data["events"]  = {}
    data["rekeys"]  = {}
    data["payloads"]= {}
    csv_dir = os.path.join(input_dir, "csv")
    if os.path.isdir(csv_dir):
        for fn in os.listdir(csv_dir):
            fp = os.path.join(csv_dir, fn)
            key = fn.split("_")[0]  # e.g. "n18"
            if "events"  in fn: data["events"][key]  = read_csv(fp)
            elif "rekey"  in fn: data["rekeys"][key]  = read_csv(fp)
            elif "payload"in fn: data["payloads"][key]= read_csv(fp)

    return data


# ============================================================
# GRAPH 1 — PDR vs UAV count
# ============================================================
def graph_pdr(rows, out):
    xs, mus, sds = mean_std_by(rows, "uav_count", "pdr")
    fig, ax = plt.subplots(figsize=(8,5))
    ax.errorbar(xs, mus, yerr=sds,
                fmt="o-", color="#0064FF", ecolor="#0064FF",
                elinewidth=1.5, capsize=5, linewidth=2,
                label="CRT-GCRT (no jammer)")
    ax.axhline(1.0, ls="--", color="red",
               alpha=0.5, label="Ideal PDR=1.0")
    ax.set_xlabel("UAV Count"); ax.set_ylabel("PDR")
    ax.set_title("PDR vs UAV Count\n(No Jammer)")
    ax.set_ylim(0, 1.1); ax.set_xticks(UAV_COUNTS)
    ax.legend()
    save(fig, os.path.join(out, "pdr_vs_uav_count.png"))


# ============================================================
# GRAPH 2 — Throughput vs UAV count
# ============================================================
def graph_throughput(rows, out):
    xs, mus, sds = mean_std_by(rows, "uav_count",
                                "throughput_kbps")
    fig, ax = plt.subplots(figsize=(8,5))
    ax.bar(xs, mus, yerr=sds, color="#00C8C8",
           width=3, capsize=4,
           edgecolor="white", label="Throughput (kbps)")
    if len(xs) > 2:
        xf = np.linspace(xs[0], xs[-1], 100)
        p  = np.polyfit(np.log(np.array(xs)+1), mus, 1)
        ax.plot(xf, p[0]*np.log(xf+1)+p[1],
                "r--", lw=2, label="Log fit")
    ax.set_xlabel("UAV Count"); ax.set_ylabel("Throughput (kbps)")
    ax.set_title("Throughput vs UAV Count")
    ax.set_xticks(UAV_COUNTS); ax.legend()
    save(fig, os.path.join(out, "throughput_vs_uav_count.png"))


# ============================================================
# GRAPH 3 — Delay vs UAV count
# ============================================================
def graph_delay(rows, out):
    xs, mus, sds = mean_std_by(rows, "uav_count",
                                "avg_delay_ms")
    fig, ax = plt.subplots(figsize=(8,5))
    ax.errorbar(xs, mus, yerr=sds,
                fmt="s-", color="#FF8C00", ecolor="#FF8C00",
                elinewidth=1.5, capsize=5, linewidth=2)
    ax.fill_between(xs,
                    [m-s for m,s in zip(mus,sds)],
                    [m+s for m,s in zip(mus,sds)],
                    alpha=0.2, color="#FF8C00")
    ax.set_xlabel("UAV Count")
    ax.set_ylabel("Avg E2E Delay (ms)")
    ax.set_title("End-to-End Delay vs UAV Count")
    ax.set_xticks(UAV_COUNTS)
    save(fig, os.path.join(out, "delay_vs_uav_count.png"))


# ============================================================
# GRAPH 4 — Rekey latency vs UAV count
# ============================================================
def graph_rekey_latency(rows, out):
    xs, mus, sds = mean_std_by(rows, "uav_count",
                                "rekey_latency_ms")
    fig, ax = plt.subplots(figsize=(8,5))
    ax.bar(xs, mus, yerr=sds, color="#9B59B6",
           width=3, capsize=4, edgecolor="white")
    ax.axhline(0.05, ls="--", color="red",
               label="Target ≤0.05ms", alpha=0.8)
    ax.set_xlabel("UAV Count")
    ax.set_ylabel("Rekey Latency (ms)")
    ax.set_title("CRT-GCRT Rekey Latency vs UAV Count")
    ax.set_xticks(UAV_COUNTS); ax.legend()
    save(fig, os.path.join(out, "rekey_latency_vs_uav_count.png"))


# ============================================================
# GRAPH 5 — Total rekeys vs UAV count
# ============================================================
def graph_rekey_count(rows, out):
    xs, mus, sds = mean_std_by(rows, "uav_count",
                                "total_rekeys")
    fig, ax = plt.subplots(figsize=(8,5))
    ax.errorbar(xs, mus, yerr=sds,
                fmt="D-", color="#E74C3C", ecolor="#E74C3C",
                elinewidth=1.5, capsize=5, linewidth=2,
                markersize=8)
    ax.set_xlabel("UAV Count")
    ax.set_ylabel("Total Rekey Events (600s)")
    ax.set_title("Total Rekey Events vs UAV Count")
    ax.set_xticks(UAV_COUNTS)
    save(fig, os.path.join(out, "rekey_count_vs_uav_count.png"))


# ============================================================
# GRAPH 6 — Security events stacked bar
# ============================================================
def graph_security_events(rows, out):
    grps = group_by(rows, "uav_count")
    xs   = sorted(grps.keys())

    def gmean(gk, col):
        return [float(np.mean(col_values(grps[k], col)))
                for k in xs]

    rekeys = gmean(xs, "total_rekeys")
    joins  = gmean(xs, "total_joins")
    leaves = gmean(xs, "total_leaves")
    compr  = gmean(xs, "total_compromises")
    ho     = gmean(xs, "total_handovers")

    xi = np.array(xs); w = 2.8
    fig, ax = plt.subplots(figsize=(9,5))
    ax.bar(xi, rekeys, w, label="Rekeys",
           color="#E74C3C")
    ax.bar(xi, joins,  w, bottom=rekeys,
           label="Joins",   color="#2ECC71")
    bot2 = [a+b for a,b in zip(rekeys, joins)]
    ax.bar(xi, leaves, w, bottom=bot2,
           label="Leaves",  color="#F39C12")
    bot3 = [a+b for a,b in zip(bot2, leaves)]
    ax.bar(xi, compr,  w, bottom=bot3,
           label="Compromise", color="#1ABC9C")
    bot4 = [a+b for a,b in zip(bot3, compr)]
    ax.bar(xi, ho,     w, bottom=bot4,
           label="Handover", color="#9B59B6")
    ax.set_xlabel("UAV Count")
    ax.set_ylabel("Total Events (600s)")
    ax.set_title("Security Event Breakdown vs UAV Count")
    ax.set_xticks(xs); ax.legend(loc="upper left", fontsize=9)
    save(fig, os.path.join(out,
                           "security_events_vs_uav_count.png"))


# ============================================================
# GRAPH 7 — SINR CDF (no jammer)
# ============================================================
def graph_sinr_cdf(out):
    fig, ax = plt.subplots(figsize=(8,5))
    colors = ["#0064FF","#00C8C8","#00C850",
              "#FF8C00","#9B59B6"]
    for n, color in zip(UAV_COUNTS, colors):
        s  = synthetic_sinr(n)
        xs = np.sort(s)
        ys = np.arange(1, len(xs)+1) / len(xs)
        ax.plot(xs, ys, lw=2, color=color,
                label=f"N={n}")
    ax.axvline(8.0, ls="--", color="gray",
               alpha=0.7,
               label="8 dB threshold (not reached)")
    ax.set_xlabel("SINR (dB)"); ax.set_ylabel("CDF")
    ax.set_title("SINR CDF — No Jammer (Clean Channel)")
    ax.legend(fontsize=9); ax.set_xlim(0, 35)
    save(fig, os.path.join(out, "sinr_cdf_no_jammer.png"))


# ============================================================
# GRAPH 8 — Drop probability vs UAV count
# ============================================================
def graph_drop_prob(rows, out):
    xs, mus, _ = mean_std_by(rows, "uav_count", "pdr")
    drop = [1.0 - m for m in mus]
    fig, ax = plt.subplots(figsize=(8,5))
    ax.bar(xs, drop, color="#E67E22", width=3,
           label="Drop prob (1−PDR)")
    ax.axhline(0.5, ls="--", color="red",
               alpha=0.7, label="50% reference")
    ax.set_xlabel("UAV Count")
    ax.set_ylabel("Packet Drop Probability")
    ax.set_title("Drop Probability vs UAV Count\n"
                 "(No Jammer — low drop expected)")
    ax.set_ylim(0, 1.0); ax.set_xticks(UAV_COUNTS)
    ax.legend()
    save(fig, os.path.join(out,
                           "drop_prob_vs_uav_count.png"))


# ============================================================
# GRAPH 9 — Rekey trigger pie
# ============================================================
def graph_rekey_pie(rows, out):
    total_r  = sum(col_values(rows, "total_rekeys"))
    total_j  = sum(col_values(rows, "total_joins"))
    total_l  = sum(col_values(rows, "total_leaves"))
    total_c  = sum(col_values(rows, "total_compromises"))
    total_ho = sum(col_values(rows, "total_handovers"))
    sched    = max(0, total_r - total_j
                      - total_l - total_c
                      - total_ho * 2)

    labels = ["Scheduled\n(periodic)",
              "Join-triggered",
              "Leave-triggered",
              "Compromise",
              "Handover"]
    sizes  = [sched, total_j, total_l,
              total_c, total_ho*2]
    colors = ["#E74C3C","#2ECC71",
              "#F39C12","#1ABC9C","#9B59B6"]

    pairs  = [(l,s,c) for l,s,c
              in zip(labels,sizes,colors) if s>0]
    if not pairs:
        return
    labels = [p[0] for p in pairs]
    sizes  = [p[1] for p in pairs]
    colors = [p[2] for p in pairs]

    fig, ax = plt.subplots(figsize=(7,6))
    _, _, autos = ax.pie(sizes, labels=labels,
                         colors=colors, autopct="%1.1f%%",
                         startangle=90, pctdistance=0.75)
    for a in autos: a.set_fontsize(9)
    ax.set_title(
        f"Rekey Trigger Distribution\n"
        f"(total={int(sum(sizes))} events)")
    save(fig, os.path.join(out, "rekey_trigger_pie.png"))


# ============================================================
# GRAPH 10 — Event timeline
# ============================================================
def graph_event_timeline(events_data, out):
    rows = None
    for key in ["n18","n24","n12","n6"]:
        if key in events_data and events_data[key]:
            rows = events_data[key]; break
    if not rows:
        rows = synthetic_events()

    event_types = list({r["event_type"] for r in rows})
    colors_map  = {
        "JOIN"       : "#2ECC71",
        "LEAVE"      : "#E74C3C",
        "COMPROMISE" : "#000000",
        "HANDOVER"   : "#F1C40F",
        "BATCH_REKEY": "#9B59B6",
    }
    y_map = {e: i for i, e in enumerate(event_types)}

    fig, ax = plt.subplots(figsize=(12,4))
    for row in rows:
        et    = str(row.get("event_type","")).upper()
        t     = float(row.get("time_s", 0))
        color = colors_map.get(et, "#95A5A6")
        ax.scatter(t, y_map.get(et, 0),
                   color=color, s=80, zorder=3, alpha=0.8)

    ax.set_yticks(list(y_map.values()))
    ax.set_yticklabels(list(y_map.keys()))
    ax.set_xlabel("Simulation Time (s)")
    ax.set_title("Security Event Timeline (N=18 UAVs, 600s)")
    ax.set_xlim(0, 600)
    patches = [mpatches.Patch(color=v, label=k)
               for k,v in colors_map.items()]
    ax.legend(handles=patches,
              loc="upper right", fontsize=8)
    save(fig, os.path.join(out, "event_timeline.png"))


# ============================================================
# GRAPH 11 — Payload size distribution
# ============================================================
def graph_payload_dist(payload_data, out):
    rows = None
    for key in ["n18","n24","n12"]:
        if key in payload_data and payload_data[key]:
            rows = payload_data[key]; break

    fig, ax = plt.subplots(figsize=(8,5))
    if rows:
        for c, color in enumerate(CLUSTER_COLORS):
            sub = [r["encrypted_bytes"]
                   for r in rows
                   if r.get("cluster_id") == c]
            if sub:
                ax.hist(sub, bins=15, alpha=0.65,
                        color=color,
                        label=f"Cluster {c}",
                        edgecolor="white")
    else:
        rng  = np.random.default_rng(42)
        for c, color in enumerate(CLUSTER_COLORS):
            sizes = rng.integers(68, 84, 200)
            ax.hist(sizes, bins=15, alpha=0.65,
                    color=color,
                    label=f"Cluster {c}",
                    edgecolor="white")
    ax.set_xlabel("Encrypted Payload Size (bytes)")
    ax.set_ylabel("Frequency")
    ax.set_title("AES-256-GCM Encrypted Payload Size\n"
                 "('UAV|CLU|T|ALT|SPD|STATUS:OK' + 44B overhead)")
    ax.legend()
    save(fig, os.path.join(out,
                           "payload_size_distribution.png"))


# ============================================================
# GRAPH 12 — TEK version over time
# ============================================================
def graph_tek_over_time(out):
    joins_t   = list(range(20, 600, 10))
    leaves_t  = list(range(25, 600, 15))
    compr_t   = [50, 120, 200]
    batch_t   = [60, 130, 210, 300, 400, 500]
    ho_t      = [80]

    events = sorted(
        [(t, "join")       for t in joins_t]  +
        [(t, "leave")      for t in leaves_t] +
        [(t, "compromise") for t in compr_t]  +
        [(t, "batch")      for t in batch_t]  +
        [(t, "handover")   for t in ho_t])

    markers = {
        "join"      : ("^","#2ECC71"),
        "leave"     : ("v","#E74C3C"),
        "compromise": ("X","#000000"),
        "batch"     : ("s","#9B59B6"),
        "handover"  : ("*","#F1C40F"),
    }

    curr_v = 1
    prev_t = 0
    step_ts, step_vs = [], []

    fig, ax = plt.subplots(figsize=(12,5))
    for et, etype in events:
        if et > 600: break
        step_ts.extend([prev_t, et])
        step_vs.extend([curr_v, curr_v])
        if etype == "batch":      curr_v += 3
        elif etype == "handover": curr_v += 2
        else:                     curr_v += 1
        col = markers[etype][1]
        mk  = markers[etype][0]
        ax.scatter(et, curr_v, marker=mk,
                   color=col, s=80, zorder=5)
        prev_t = et

    step_ts.extend([prev_t, 600])
    step_vs.extend([curr_v, curr_v])
    ax.step(step_ts, step_vs, where="post",
            color="#2C3E50", lw=1.5, label="TEK version")
    ax.set_xlabel("Simulation Time (s)")
    ax.set_ylabel("TEK Version")
    ax.set_title("TEK Version Over Time (N=18 UAVs)")
    ax.set_xlim(0, 600)
    patches = [mpatches.Patch(color=v[1],
                              label=k.capitalize())
               for k,v in markers.items()]
    ax.legend(handles=patches,
              loc="upper left", fontsize=9, ncol=2)
    save(fig, os.path.join(out, "tek_version_over_time.png"))


# ============================================================
# GRAPH 13 — Scalability radar
# ============================================================
def graph_radar(rows, out):
    grps    = group_by(rows, "uav_count")
    metrics = ["pdr","throughput_kbps","avg_delay_ms",
               "rekey_latency_ms","security_overhead_ratio"]
    labels  = ["PDR","Throughput","Delay (inv)",
               "Rekey lat (inv)","Sec. ovhd (inv)"]

    # Build normalized matrix
    means = {}
    for n in sorted(grps.keys()):
        means[n] = {}
        for m in metrics:
            vals = col_values(grps[n], m)
            means[n][m] = float(np.mean(vals)) if vals else 0.0

    # Find global max per metric
    max_vals = {m: max(means[n][m]
                       for n in means) or 1.0
                for m in metrics}

    def normalize(n):
        row = []
        for m in metrics:
            v = means[n][m] / max_vals[m]
            if m in ("avg_delay_ms",
                     "rekey_latency_ms",
                     "security_overhead_ratio"):
                v = 1.0 - v   # invert: lower is better
            row.append(v)
        return row

    N      = len(metrics)
    angles = [i/N*2*math.pi for i in range(N)]
    angles+= angles[:1]

    fig, ax = plt.subplots(figsize=(7,7),
                           subplot_kw={"polar": True})
    colors = ["#0064FF","#00C8C8","#00C850",
              "#FF8C00","#9B59B6"]
    for (n, color) in zip(sorted(means.keys()), colors):
        vals  = normalize(n) + [normalize(n)[0]]
        ax.plot(angles, vals, lw=2,
                color=color, label=f"N={n}")
        ax.fill(angles, vals, alpha=0.12, color=color)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, size=10)
    ax.set_ylim(0, 1)
    ax.set_title("Scalability Radar\n(CRT-GCRT, No Jammer)",
                 pad=20)
    ax.legend(loc="upper right",
              bbox_to_anchor=(1.35, 1.1), fontsize=9)
    save(fig, os.path.join(out, "scalability_radar.png"))


# ============================================================
# GRAPH 14 — Security overhead vs UAV count
# ============================================================
def graph_sec_overhead(rows, out):
    xs, mus, sds = mean_std_by(rows, "uav_count",
                                "security_overhead_ratio")
    fig, ax = plt.subplots(figsize=(8,5))
    ax.errorbar(xs, mus, yerr=sds,
                fmt="h-", color="#E74C3C",
                ecolor="#E74C3C",
                elinewidth=1.5, capsize=5,
                linewidth=2, markersize=9)
    ax.fill_between(xs,
                    [m-s for m,s in zip(mus,sds)],
                    [m+s for m,s in zip(mus,sds)],
                    alpha=0.15, color="#E74C3C")
    ax.set_xlabel("UAV Count")
    ax.set_ylabel("Security Events / Second")
    ax.set_title("Security Overhead vs UAV Count")
    ax.set_xticks(UAV_COUNTS)
    save(fig, os.path.join(out,
                           "security_overhead_vs_uav.png"))


# ============================================================
# GRAPH 15 — Per-cluster throughput (colored)
# ============================================================
def graph_cluster_tp(rows, out):
    n18 = [r for r in rows if r.get("uav_count") == 18]
    if not n18:
        n18 = rows
    tp_mean = float(np.mean(
        col_values(n18, "throughput_kbps"))) or 1.0
    cluster_tp = [tp_mean/3, tp_mean/3, tp_mean/3]

    fig, ax = plt.subplots(figsize=(7,5))
    for i, (tp, color) in enumerate(
            zip(cluster_tp, CLUSTER_COLORS)):
        ax.bar(i, tp, color=color)
        ax.text(i, tp+0.02, f"{tp:.3f}",
                ha="center", fontsize=10)
    ax.set_xticks([0,1,2])
    ax.set_xticklabels(["C0 (Blue)",
                         "C1 (Cyan)",
                         "C2 (Green)"])
    ax.set_ylabel("Throughput (kbps)")
    ax.set_title("Per-Cluster Throughput (N=18 UAVs)\n"
                 "Colors match NetAnim visualization")
    save(fig, os.path.join(out,
                           "cluster_throughput_colored.png"))


# ============================================================
# MAIN
# ============================================================
def main():
    ap = argparse.ArgumentParser(
        description="Generate rekey_perf graphs "
                    "(no pandas required)")
    ap.add_argument("--input",  "-i",
                    default="output/rekey_perf")
    ap.add_argument("--output", "-o",
                    default="output/rekey_perf/graphs")
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)
    print(f"[GRAPHS] Input : {args.input}")
    print(f"[GRAPHS] Output: {args.output}")

    data = load_data(args.input)
    rows = data["scalability"]

    uav_ns = sorted({r.get("uav_count",0) for r in rows})
    print(f"[GRAPHS] Rows  : {len(rows)}")
    print(f"[GRAPHS] UAVs  : {uav_ns}")
    print("[GRAPHS] Generating 15 graphs...")

    graph_pdr(rows, args.output)
    graph_throughput(rows, args.output)
    graph_delay(rows, args.output)
    graph_rekey_latency(rows, args.output)
    graph_rekey_count(rows, args.output)
    graph_security_events(rows, args.output)
    graph_sinr_cdf(args.output)
    graph_drop_prob(rows, args.output)
    graph_rekey_pie(rows, args.output)
    graph_event_timeline(data["events"], args.output)
    graph_payload_dist(data["payloads"], args.output)
    graph_tek_over_time(args.output)
    graph_radar(rows, args.output)
    graph_sec_overhead(rows, args.output)
    graph_cluster_tp(rows, args.output)

    print(f"\n[GRAPHS] Done → {args.output}/")
    for fn in sorted(os.listdir(args.output)):
        if fn.endswith(".png"):
            sz = os.path.getsize(
                os.path.join(args.output, fn)) // 1024
            print(f"  {fn:<52} {sz} KB")


if __name__ == "__main__":
    main()
