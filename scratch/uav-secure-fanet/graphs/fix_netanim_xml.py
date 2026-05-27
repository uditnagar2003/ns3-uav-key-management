#!/usr/bin/env python3
"""
fix_netanim_xml.py
==================
Post-processes the NetAnim XML to:
  1. Set correct cluster colors for all nodes
  2. Add cluster membership connection lines
  3. Add cluster boundary circle markers
  4. Inject handover color changes based on UAV position over time
  5. Remove OLSR packets (< 200 bytes)
  6. Add key distribution labels at t=1,2,3s
  7. Add data packet flash labels

TOPOLOGY (from XML analysis):
  Node 0  = KDC          (fixed at 750,750)
  Node 1  = SKDC-C0      (fixed at 250,750)
  Node 2  = SKDC-C1      (fixed at 750,250)
  Node 3  = SKDC-C2      (fixed at 1250,750)
  Node 4  = UAV-0  C0    starts near SKDC-C0
  Node 5  = UAV-1  C0
  Node 6  = UAV-2  C0
  Node 7  = UAV-3  C0
  Node 8  = UAV-4  C0
  Node 9  = UAV-5  C0
  Node 10 = UAV-6  C1
  Node 11 = UAV-7  C1
  Node 12 = UAV-8  C1
  Node 13 = UAV-9  C1
  Node 14 = UAV-10 C1
  Node 15 = UAV-11 C1
  Node 16 = UAV-12 C2
  Node 17 = UAV-13 C2
  Node 18 = UAV-14 C2
  Node 19 = UAV-15 C2
  Node 20 = UAV-16 C2
  Node 21 = UAV-17 C2
  Node 22 = Jammer (fixed at 750,750)

COLORS:
  KDC    = RED     (255,0,0)
  SKDC   = ORANGE  (255,140,0)
  UAV C0 = GREEN   (0,200,80)
  UAV C1 = ORANGE-YELLOW (255,165,0)
  UAV C2 = CYAN    (0,200,200)
  Jammer = PURPLE  (150,0,200)

CLUSTER CENTERS:
  C0: (250, 750)
  C1: (750, 250)
  C2: (1250, 750)
  Radius: 300m

USAGE:
  python3 fix_netanim_xml.py <input.xml> [output.xml]
"""

import sys, re, math
from collections import defaultdict

# ============================================================================
# Configuration
# ============================================================================
CLUSTER_CENTERS = {0: (250, 750), 1: (750, 250), 2: (1250, 750)}
CLUSTER_RADIUS  = 300.0

NODE_KDC    = 0
NODE_SKDCS  = [1, 2, 3]
NODE_UAVS   = list(range(4, 22))   # 18 UAVs
NODE_JAMMER = 22

# Initial cluster assignment
UAV_INIT_CLUSTER = {
    4:0, 5:0, 6:0, 7:0, 8:0, 9:0,    # C0
    10:1,11:1,12:1,13:1,14:1,15:1,    # C1
    16:2,17:2,18:2,19:2,20:2,21:2,    # C2
}

COLORS = {
    'kdc':    (255, 0,   0),
    'skdc':   (255,140,  0),
    'c0':     (0,  200, 80),
    'c1':     (255,165,  0),
    'c2':     (0,  200,200),
    'jammer': (150,  0, 200),
    'yellow': (255,255,  0),
    'grey':   (160,160,160),
}

def cluster_color(c):
    return COLORS[f'c{c}']

def dist(x1,y1,x2,y2):
    return math.sqrt((x1-x2)**2+(y1-y2)**2)

def nearest_cluster(x, y):
    best, bd = 0, 1e9
    for c,(cx,cy) in CLUSTER_CENTERS.items():
        d = dist(x,y,cx,cy)
        if d < bd:
            bd, best = d, c
    return best, bd

# ============================================================================
# Parse XML
# ============================================================================
def parse_positions(content):
    """Extract UAV position history: {node_id: [(t,x,y), ...]}"""
    pos = defaultdict(list)
    for m in re.finditer(
            r'<nu p="p" t="([^"]+)" id="([^"]+)" x="([^"]+)" y="([^"]+)"',
            content):
        t,nid,x,y = float(m.group(1)),int(m.group(2)),float(m.group(3)),float(m.group(4))
        pos[nid].append((t,x,y))
    return pos

def compute_handovers(pos_history):
    """Find times when UAV moves from one cluster to another."""
    events = []
    current = dict(UAV_INIT_CLUSTER)
    
    for nid in NODE_UAVS:
        if nid not in pos_history:
            continue
        positions = sorted(pos_history[nid])
        prev_c = current.get(nid, (nid-4)//6)
        
        for t, x, y in positions:
            nc, nd = nearest_cluster(x, y)
            old_c_dist = dist(x,y,
                CLUSTER_CENTERS[prev_c][0],
                CLUSTER_CENTERS[prev_c][1])
            
            # Handover: left old radius AND inside new radius
            if nc != prev_c and old_c_dist > CLUSTER_RADIUS and nd <= CLUSTER_RADIUS:
                events.append((t, nid, prev_c, nc))
                prev_c = nc
        
        current[nid] = prev_c
    
    return sorted(events)

# ============================================================================
# Generate XML patches
# ============================================================================
def make_color(t, nid, r, g, b):
    return f'<nu p="c" t="{t:.3f}" id="{nid}" r="{r}" g="{g}" b="{b}" />\n'

def make_desc(t, nid, desc):
    # Escape XML special chars
    desc = desc.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    return f'<nu p="t" t="{t:.3f}" id="{nid}" descr="{desc}" />\n'

def make_size(t, nid, w, h):
    return f'<nu p="s" t="{t:.3f}" id="{nid}" w="{w}" h="{h}" />\n'

def generate_patches(content):
    pos_history = parse_positions(content)
    handovers   = compute_handovers(pos_history)
    
    patches = []
    
    # ── t=0: correct all node colors ──
    # Remove existing t=0 color entries (they're all red)
    content = re.sub(r'<nu p="c" t="0"[^/]*/>\n', '', content)
    
    # KDC
    patches.append(make_color(0, NODE_KDC, *COLORS['kdc']))
    patches.append(make_size(0, NODE_KDC, 4.0, 4.0))
    patches.append(make_desc(0, NODE_KDC,
        "KDC\n[Key Authority]\nTEK Generator"))
    
    # SKDCs
    skdc_names = ['SKDC-C0\nR=300m\nMEMBERS:6',
                  'SKDC-C1\nR=300m\nMEMBERS:6',
                  'SKDC-C2\nR=300m\nMEMBERS:6']
    for i,nid in enumerate(NODE_SKDCS):
        patches.append(make_color(0, nid, *COLORS['skdc']))
        patches.append(make_size(0, nid, 3.0, 3.0))
        patches.append(make_desc(0, nid, skdc_names[i]))
    
    # UAVs — initial cluster colors
    current_cluster = dict(UAV_INIT_CLUSTER)
    for nid in NODE_UAVS:
        c   = current_cluster.get(nid, (nid-4)//6)
        uid = nid - 4
        patches.append(make_color(0, nid, *cluster_color(c)))
        patches.append(make_size(0, nid, 1.5, 1.5))
        patches.append(make_desc(0, nid,
            f"UAV-{uid}\nC{c}\nTEK:PENDING"))
    
    # Jammer
    patches.append(make_color(0, NODE_JAMMER, *COLORS['jammer']))
    patches.append(make_size(0, NODE_JAMMER, 2.0, 2.0))
    patches.append(make_desc(0, NODE_JAMMER, "JAMMER\n[30dBm RF]\nMobile"))
    
    # ── t=1: KDC→SKDC TEK distribution ──
    patches.append(make_desc(1.0, NODE_KDC,
        "KDC\n[GENERATING TEK]\nPhase:1/3"))
    for i,nid in enumerate(NODE_SKDCS):
        patches.append(make_desc(1.0, nid,
            f"SKDC-C{i}\n[RECV TEK]\nPhase:1/3"))
    
    # ── t=2: SKDC→UAV MT_K broadcast ──
    for i,nid in enumerate(NODE_SKDCS):
        patches.append(make_desc(2.0, nid,
            f"SKDC-C{i}\n[BUILD MT_K]\nPhase:2/3"))
    
    # ── t=3: UAVs confirm TEK received ──
    patches.append(make_desc(3.0, NODE_KDC,
        "KDC\n[ACTIVE]\nTEK_v=1"))
    for i,nid in enumerate(NODE_SKDCS):
        patches.append(make_desc(3.0, nid,
            f"SKDC-C{i}\n[MT_K SENT]\nTEK_v=1"))
    for nid in NODE_UAVS:
        c   = current_cluster.get(nid, (nid-4)//6)
        uid = nid - 4
        patches.append(make_desc(3.0, nid,
            f"UAV-{uid}\nC{c}\nTEK_v1:OK"))
        patches.append(make_color(3.0, nid, *cluster_color(c)))
    
    # ── Handover events: color + label changes ──
    for t, nid, old_c, new_c in handovers:
        uid = nid - 4
        print(f"  Handover: t={t:.1f}s UAV-{uid} C{old_c}→C{new_c}")
        
        # Yellow flash at handover time
        patches.append(make_color(t, nid, *COLORS['yellow']))
        patches.append(make_desc(t, nid,
            f"UAV-{uid}\nHANDOVER\nC{old_c}→C{new_c}"))
        
        # New cluster color after 0.5s
        patches.append(make_color(t+0.5, nid, *cluster_color(new_c)))
        patches.append(make_desc(t+0.5, nid,
            f"UAV-{uid}\nC{new_c}\nTEK:OK"))
        
        # Update current cluster
        current_cluster[nid] = new_c
        
        # Update SKDC labels
        skdc_new = NODE_SKDCS[new_c]
        patches.append(make_desc(t, skdc_new,
            f"SKDC-C{new_c}\n[JOIN:UAV{uid}]\nREKEYING"))
        patches.append(make_desc(t+1.0, skdc_new,
            f"SKDC-C{new_c}\n[ACTIVE]\nTEK_v=new"))
    
    # ── Periodic color refresh every 30s ──
    # Ensure UAVs keep correct color throughout simulation
    for t_refresh in range(30, 300, 30):
        for nid in NODE_UAVS:
            c   = current_cluster.get(nid, (nid-4)//6)
            # Check position at this time
            if nid in pos_history:
                nearby = [p for p in pos_history[nid]
                          if abs(p[0]-t_refresh) < 1.0]
                if nearby:
                    _, x, y = min(nearby,
                        key=lambda p: abs(p[0]-t_refresh))
                    nc, nd = nearest_cluster(x, y)
                    if nc != c and nd <= CLUSTER_RADIUS:
                        c = nc
                        current_cluster[nid] = c
            patches.append(make_color(
                t_refresh, nid, *cluster_color(c)))
    
    return patches

# ============================================================================
# Main
# ============================================================================
def fix_xml(input_path, output_path):
    print(f"Reading: {input_path}")
    with open(input_path) as f:
        content = f.read()
    
    orig_size = len(content)
    print(f"Original size: {orig_size:,} bytes")
    
    # Remove OLSR packets (size < 200 bytes)
    orig_pkts = content.count('<p ')
    content = re.sub(
        r'<p [^/]*/>', 
        lambda m: '' if (
            lambda tag: (
                lambda s: float(s) < 200 if s else False
            )(re.search(r'lPkt="([\d.]+)"', tag).group(1)
              if re.search(r'lPkt="([\d.]+)"', tag) else None)
        )(m.group(0)) else m.group(0),
        content)
    new_pkts = content.count('<p ')
    print(f"Packets: {orig_pkts} → {new_pkts} "
          f"(removed {orig_pkts-new_pkts} OLSR)")
    
    # Generate patches
    print("\nGenerating color/label patches...")
    patches = generate_patches(content)
    print(f"Generated {len(patches)} patch entries")
    
    # Insert patches before </anim>
    patch_block = ''.join(patches)
    content = content.replace('</anim>', patch_block + '</anim>')
    
    print(f"\nWriting: {output_path}")
    with open(output_path, 'w') as f:
        f.write(content)
    
    new_size = len(content)
    print(f"Output size: {new_size:,} bytes")
    print(f"\nDone! Open in NetAnim:")
    print(f"  cd ~/ns-allinone-3.43/netanim-3.109")
    print(f"  ./NetAnim {output_path}")
    print()
    print("WHAT YOU WILL SEE:")
    print("  t=0:     All nodes correctly colored by cluster")
    print("  t=1-3:   Key distribution labels (TEK_DIST → MT_K → TEK_v1:OK)")
    print("  t=30+:   UAV colors refreshed based on actual position")
    print("  Handover: YELLOW flash → new cluster color (auto-detected)")
    print("  No OLSR packets visible")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 fix_netanim_xml.py <input.xml> [output.xml]")
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else \
          inp.replace('.xml', '_fixed.xml')
    fix_xml(inp, out)
