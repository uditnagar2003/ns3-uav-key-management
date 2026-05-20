#!/usr/bin/env python3
"""
scripts/verify_crypto.py

Verifies the generated crypto_params.json is correct.
Loads the JSON and re-runs all slave decryptions.

USAGE:
  python3 scripts/verify_crypto.py
  python3 scripts/verify_crypto.py --input json/crypto_params.json
"""

import sys
import json
import argparse

sys.set_int_max_str_digits(0)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="json/crypto_params.json")
    return p.parse_args()


def verify_file(path):
    print(f"Loading: {path}")
    with open(path) as f:
        data = json.load(f)

    print(f"Scheme  : {data['scheme']}")
    print(f"Clusters: {data['num_clusters']}")
    print(f"UAVs    : {data['total_uavs']}")
    print()

    total_pass = 0
    total_fail = 0

    for cluster in data["clusters"]:
        cid   = cluster["cluster_id"]
        MT_K  = int(cluster["MT_K"])
        T     = int(cluster["T"])
        print(f"Cluster {cid}:")
        print(f"  MT_K = {str(MT_K)[:50]}...")
        print(f"  T    = {str(T)[:50]}...")

        for sk in cluster["slave_keys"]:
            uav_id = sk["uav_id"]
            d_i    = int(sk["d_i"])
            n_i    = int(sk["n_i"])

            # Slave decryption: pow(MT_K, d_i, n_i)
            recovered = pow(MT_K, d_i, n_i)
            T_mod     = T % n_i
            ok        = (recovered == T_mod)

            status = "OK" if ok else "FAIL"
            print(f"  UAV {uav_id}: {status}")

            if ok:
                total_pass += 1
            else:
                total_fail += 1
                print(f"    Expected: {T_mod}")
                print(f"    Got     : {recovered}")

        print()

    print("=" * 40)
    print(f"Results: {total_pass} PASS, {total_fail} FAIL")
    print("=" * 40)

    return total_fail == 0


if __name__ == "__main__":
    args = parse_args()
    ok = verify_file(args.input)
    sys.exit(0 if ok else 1)
