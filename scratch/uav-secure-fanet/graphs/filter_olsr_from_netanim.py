#!/usr/bin/env python3
"""
filter_olsr_from_netanim.py
============================
Post-processes NetAnim XML to remove OLSR packet animations.
OLSR packets are identified by small size (< 200 bytes).

USAGE:
    python3 graphs/filter_olsr_from_netanim.py \
        output/rekey_perf/netanim/uav_rekey_18_run0.xml

OUTPUT:
    output/rekey_perf/netanim/uav_rekey_18_run0_filtered.xml
"""

import sys, os, re

def filter_olsr(input_xml, min_pkt_size=200):
    with open(input_xml, 'r') as f:
        content = f.read()

    # NetAnim packet format:
    # <p fId="N" toBId="M" toTime="T" fbTx="..." lPkt="SIZE" .../>
    # Remove packets where lPkt < min_pkt_size

    original_count = content.count('<p ')

    # Pattern: <p ... lPkt="SIZE" .../>
    # lPkt is the packet size in bytes
    def should_remove(match):
        tag = match.group(0)
        # Extract lPkt value
        m = re.search(r'lPkt="([\d.]+)"', tag)
        if m:
            size = float(m.group(1))
            if size < min_pkt_size:
                return True
        return False

    # Replace small packets with empty string
    result = re.sub(
        r'<p [^/]*/>', 
        lambda m: '' if should_remove(m) else m.group(0),
        content)

    filtered_count = result.count('<p ')
    removed = original_count - filtered_count

    output_xml = input_xml.replace('.xml', '_filtered.xml')
    with open(output_xml, 'w') as f:
        f.write(result)

    print(f"Input:    {input_xml}")
    print(f"Output:   {output_xml}")
    print(f"Removed:  {removed} OLSR packets "
          f"(size < {min_pkt_size}B)")
    print(f"Kept:     {filtered_count} key/data packets")
    return output_xml

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 filter_olsr_from_netanim.py <xml_file>")
        sys.exit(1)
    output = filter_olsr(sys.argv[1])
    print(f"\nOpen in NetAnim:")
    print(f"  netanim {output}")
