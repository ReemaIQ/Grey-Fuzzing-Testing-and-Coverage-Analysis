import re
from collections import defaultdict

DOT_FILE = "/home/seed/Desktop/FuzzingProject/.BZ2_bzWrite.dot"
LCOV_FILE = "/home/seed/Desktop/FuzzingProject/compress/output_compress/cov/lcov/trace.lcov_info"

# -----------------------------
# Step 1: Parse CFG (.dot file)
# -----------------------------
bb_to_node = {}
node_to_bb = {}

with open(DOT_FILE, "r") as f:
    for line in f:
        m = re.search(r'(Node0x[0-9a-fA-F]+).*?%\s*(\d+):', line)
        if m:
            node = m.group(1)
            bb = int(m.group(2))
            bb_to_node[bb] = node
            node_to_bb[node] = bb

print(f"[+] Parsed {len(bb_to_node)} basic blocks")

# ---------------------------------
# Step 2: Parse LCOV (line coverage)
# ---------------------------------
line_hits = {}

with open(LCOV_FILE, "r") as f:
    for line in f:
        if line.startswith("DA:"):
            parts = line.strip().split(":")[1].split(",")
            lineno = int(parts[0])
            hits = int(parts[1])
            line_hits[lineno] = hits

print(f"[+] Parsed {len(line_hits)} lines of coverage")

# -----------------------------------------------------
# Step 3: Debug + Map lines -> BBs
# -----------------------------------------------------
START_LINE = 4366
END_LINE   = 4450  # widened — adjust if debug shows lines beyond this

func_lines = {l: h for l, h in line_hits.items() if START_LINE <= l <= END_LINE}
print(f"[DEBUG] Lines in range {START_LINE}-{END_LINE}: {len(func_lines)}")
print(f"[DEBUG] Hit lines    : {sum(1 for h in func_lines.values() if h > 0)}")
print(f"[DEBUG] Zero lines   : {sum(1 for h in func_lines.values() if h == 0)}")

bbs   = sorted(bb_to_node.keys())
lines = sorted(func_lines.keys())

print(f"[DEBUG] Number of BBs: {len(bbs)}")
print("\n[DEBUG] Coverage in function range:")
for l in lines:
    print(f"  line {l}: {line_hits[l]} hits")

if not bbs:
    raise Exception("No basic blocks found in DOT file")
if not lines:
    raise Exception(
        f"No LCOV lines found in range {START_LINE}-{END_LINE}. "
        "Check your END_LINE or whether the gcov binary was run on the queue."
    )

# Proportional mapping: each line -> nearest BB by position in function
bb_hits = defaultdict(int)
bb_mapped = set()  # track which BBs got at least one line assigned

# Replace the mapping loop in Step 3 with this:
for i, bb in enumerate(bbs):
    # Give each BB a window of lines, not just the nearest one
    ratio_start = i / len(bbs)
    ratio_end   = (i + 1) / len(bbs)
    
    line_start = START_LINE + int(ratio_start * (END_LINE - START_LINE))
    line_end   = START_LINE + int(ratio_end   * (END_LINE - START_LINE))
    
    window = [l for l in lines if line_start <= l < line_end]
    
    # If window is empty, grab the nearest line anyway
    if not window and lines:
        nearest = min(lines, key=lambda l: abs(l - (line_start + line_end) // 2))
        window = [nearest]
    
    for l in window:
        bb_hits[bb] += line_hits[l]
        bb_mapped.add(bb)

print(f"\n[+] Mapped {len(lines)} lines to {len(bb_mapped)} BBs (proportional heuristic)")
print(f"[+] BBs with no lines mapped (shown grey): {len(set(bbs) - bb_mapped)}")

# --------------------------------------
# Step 4: Color assignment
# --------------------------------------
def get_color(bb, hits):
    if hits > 0:              # any hits at all = covered
        return "darkseagreen"
    elif bb in bb_mapped:     # mapped but zero hits = uncovered
        return "lightcoral"
    else:                     # no lines mapped = unknown
        return "lightgrey"

# --------------------------------------
# Step 5: Rewrite DOT with annotations
# --------------------------------------
graph_attrs = (
    '    graph [rankdir=TB, ranksep=0.8, nodesep=0.5, splines=ortho];\n'
    '    node  [fontname="Courier New", fontsize=11, margin="0.3,0.2", width=3];\n'
    '    edge  [fontsize=9];\n'
)

output_lines = []
graph_attrs_injected = False

with open(DOT_FILE, "r") as f:
    for line in f:
        modified = line

        # Inject graph-level attributes once, right after the opening brace
        if not graph_attrs_injected and '{' in line:
            modified = line.rstrip() + '\n' + graph_attrs
            graph_attrs_injected = True
            output_lines.append(modified)
            continue

        m = re.search(r'(Node0x[0-9a-fA-F]+)', line)
        if m:
            node = m.group(1)
            if node in node_to_bb:
                bb    = node_to_bb[node]
                hits  = bb_hits.get(bb, 0)
                color = get_color(bb, hits)

                if "label=" in line:
                    modified = modified.replace(
                        'label="{',
                        f'label="{{BB {bb} | hits={hits}\\l'
                    )

                if "shape=record" in modified:
                    modified = modified.replace(
                        "shape=record",
                        f'shape=record, style=filled, fillcolor={color}'
                    )

        output_lines.append(modified)

OUTPUT_DOT = "BZ2_bzWrite_annotated.dot"
with open(OUTPUT_DOT, "w") as f:
    f.writelines(output_lines)

print(f"\n[+] Wrote annotated CFG to {OUTPUT_DOT}")
print("[+] Render with:")
print(f"    dot -Tpdf {OUTPUT_DOT} -o BZ2_bzWrite_annotated.pdf")
print(f"    dot -Tsvg {OUTPUT_DOT} -o BZ2_bzWrite_annotated.svg")
