#!/usr/bin/env python3
"""
Patch gen_crypto.py to add global_bootstrap_key (GK) to JSON output.
Run ONCE to regenerate crypto_params.json with GK field.
"""
import sys, os, shutil

SRC = "scripts/gen_crypto.py"
if not os.path.exists(SRC):
    print(f"ERROR: {SRC} not found"); sys.exit(1)

shutil.copy(SRC, SRC + ".bak_gk")
with open(SRC) as f: src = f.read()

# P1: Add GK generation after imports
patches = []
patches.append((
    'import json\nimport secrets',
    'import json\nimport secrets\nimport os'
))

patches.append((
    '    # ── Build output dict ──',
    '''    # ── Global Bootstrap Key (GK) ──
    # 32-byte AES-256 key, pre-provisioned to ALL UAVs and KDC/SKDCs.
    # Used ONLY for encrypting slave key delivery during inter-cluster handover.
    # Never used for data confidentiality (TEK is used for that).
    gk_bytes = secrets.token_bytes(32)
    gk_hex   = gk_bytes.hex()

    # ── Build output dict ──'''
))

patches.append((
    '    out = {\n        "scheme":          "MKE-MGKM",',
    '''    out = {
        "scheme":               "MKE-MGKM",
        "global_bootstrap_key": gk_hex,'''
))

# Remove the old scheme-only line
patches.append((
    '        "scheme":          "MKE-MGKM",',
    ''
))

applied = 0
for old, new in patches:
    if old in src:
        src = src.replace(old, new, 1)
        applied += 1

with open(SRC, 'w') as f: f.write(src)
print(f"gen_crypto.py patched ({applied}/{len(patches)})")
print("Now run: python3 scripts/gen_crypto.py --clusters 3 --uavs-per-cluster 6")
