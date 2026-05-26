#!/usr/bin/env python3
"""
scripts/gen_crypto.py
Generates CRT/GCRT crypto parameters for UAV Secure FANET.

KEY INSIGHT (from working reference):
  MT_K = pow(TEK_int, e_MK, N_group)   ← real ciphertext
  slave decrypts: pow(MT_K, d_i, n_i)  ← recovers TEK_int % n_i
  TEK_int must be < min(n_i) for exact recovery

TEK_int is derived from a random 32-byte AES key truncated
to fit within the smallest n_i.
"""
import sys, os, json, random, argparse, secrets, time
sys.set_int_max_str_digits(0)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safe_prime_pool import get_sequential_batch
from mke_mgkm import (MKeyGen, MTokenGen, JoKeyUpdate,
                       LeKeyUpdate, slave_decrypt, verify_mtoken)

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--clusters",         type=int, default=3)
    p.add_argument("--uavs-per-cluster", type=int, default=6)
    p.add_argument("--seed",             type=int, default=42)
    p.add_argument("--output",           type=str,
                   default="json/crypto_params.json")
    p.add_argument("--verify",           action="store_true",
                   default=True)
    p.add_argument("--verbose",          action="store_true",
                   default=False)
    return p.parse_args()

def make_tek_int(mkg, uavs_per_cluster):
    """
    Generate TEK as integer that fits within all n_i.
    TEK_int < min(n_i) ensures exact recovery by each slave.
    Use 256-bit random value but cap to min(n_i)-1.
    """
    min_ni = min(s["n_i"] for s in mkg["slaves"])
    while True:
        raw   = int.from_bytes(secrets.token_bytes(32), 'big')
        tek_i = raw % min_ni
        if tek_i > 1:
            return tek_i

def verify_join_leave(mkg, mtoken, verbose=False):
    """Verify Algorithm 3 and 5."""
    # Leave slave 0
    after_leave = LeKeyUpdate(mkg, mtoken, 0)
    ok, errs    = verify_mtoken(mkg, after_leave)
    if not ok:
        raise RuntimeError("LeKeyUpdate failed: " + str(errs))
    if verbose:
        print("  LeKeyUpdate (leave 0): OK")

    # Rejoin slave 0
    after_join = JoKeyUpdate(mkg, after_leave, 0)
    ok, errs   = verify_mtoken(mkg, after_join)
    if not ok:
        raise RuntimeError("JoKeyUpdate failed: " + str(errs))
    if verbose:
        print("  JoKeyUpdate (rejoin 0): OK")
    return True

def main():
    args = parse_args()
    random.seed(args.seed)

    num_clusters     = args.clusters
    uavs_per_cluster = args.uavs_per_cluster
    total_uavs       = num_clusters * uavs_per_cluster

    print("=" * 60)
    print(" UAV Secure FANET — Crypto Parameter Generator")
    print("=" * 60)
    print(f" Clusters: {num_clusters}, UAVs/cluster: {uavs_per_cluster}")
    print(f" Seed: {args.seed}, Output: {args.output}")
    print("=" * 60)

    all_primes  = get_sequential_batch(total_uavs, offset=0)
    clusters    = []
    mkg_results = []
    total_start = time.time()

    for c in range(num_clusters):
        start  = c * uavs_per_cluster
        primes = all_primes[start:start + uavs_per_cluster]
        print(f"\n[Cluster {c}] Generating ({uavs_per_cluster} UAVs)...")

        random.seed(args.seed + c * 1000)
        mkg = MKeyGen(primes)
        mkg_results.append(mkg)

        # TEK as integer (fits within all n_i)
        tek_int     = make_tek_int(mkg, uavs_per_cluster)
        # Also keep as 32-byte hex for AES use
        tek_hex     = format(tek_int % (2**256), '064x')

        all_indices = list(range(uavs_per_cluster))

        # Algorithm 2: MT_K = pow(tek_int, e_MK, N_group)
        mtoken = MTokenGen(mkg, all_indices, tek_int)

        # Verify all slaves
        ok, errs = verify_mtoken(mkg, mtoken)
        if not ok:
            print("ERRORS:")
            for e in errs:
                print(" ", e)
            sys.exit(1)

        print(f"  eM     = {str(mkg['eM'])[:50]}...")
        print(f"  MT_K   = {str(mtoken['MT_K'])[:50]}...")
        print(f"  TEK    = {tek_hex[:32]}...")
        print(f"  N_group= {str(mtoken['N_group'])[:40]}...")
        print(f"  All {uavs_per_cluster} UAVs verified: OK")

        # Build slave key list
        slave_keys = []
        for i, slave in enumerate(mkg["slaves"]):
            slave_keys.append({
                "uav_index": i,
                "uav_id":    c * uavs_per_cluster + i,
                "e_i":   str(slave["e_i"]),
                "d_i":   str(slave["d_i"]),
                "n_i":   str(slave["n_i"]),
                "x_i":   str(slave["x_i"]),
                "y_i":   str(slave["y_i"]),
                "Mi":    str(slave["Mi"]),
                "Ni":    str(slave["Ni"]),
                "xy_i":  str(slave["xy_i"]),
                "p_i":   str(primes[i][0]),
                "q_i":   str(primes[i][1]),
            })

        clusters.append({
            "cluster_id":    c,
            "skdc_id":       c,
            "num_uavs":      uavs_per_cluster,
            "eM":            str(mkg["eM"]),
            "n_total":       str(mkg["n_total"]),
            "N_global":      str(mkg["N_global"]),
            "N_group":       str(mtoken["N_group"]),
            "tek_hex":       tek_hex,
            "tek_int":       str(tek_int),
            "MT_K":          str(mtoken["MT_K"]),
            "e_MK":          str(mtoken["e_MK"]),
            "user_indices":  all_indices,
            "slave_keys":    slave_keys,
        })

    total_time = time.time() - total_start

    # Verify join/leave
    if args.verify:
        print("\n Verifying Join/Leave operations...")
        for c in range(num_clusters):
            try:
                # Rebuild mtoken for verification
                mkg = mkg_results[c]
                tek_int = int(clusters[c]["tek_int"])
                all_idx = clusters[c]["user_indices"]
                mtoken  = MTokenGen(mkg, all_idx, tek_int)
                verify_join_leave(mkg, mtoken, verbose=args.verbose)
                print(f"  Cluster {c} Join/Leave: OK")
            except RuntimeError as e:
                print(f"  Cluster {c} FAILED: {e}")
                sys.exit(1)

    output = {
        "_comment":          "UAV Secure FANET crypto parameters. "
                             "MT_K = pow(tek_int, e_MK, N_group). "
                             "Slave decrypts: pow(MT_K, d_i, n_i).",
        "scheme":            "MKE-MGKM",
        "num_clusters":      num_clusters,
        "uavs_per_cluster":  uavs_per_cluster,
        "total_uavs":        total_uavs,
        "seed":              args.seed,
        "generation_time_s": round(total_time, 4),
        "clusters":          clusters,
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.output)),
                exist_ok=True)

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*60}")
    print(f" Output: {args.output}")
    print(f" Time: {total_time:.2f}s")
    print(f" All verifications: PASSED")
    print(f"{'='*60}")

    # Reload check
    with open(args.output) as f:
        loaded = json.load(f)
    assert len(loaded["clusters"]) == num_clusters
    print(f" Reload: PASSED — {num_clusters}×{uavs_per_cluster}={total_uavs} UAVs\n")

if __name__ == "__main__":
    main()
