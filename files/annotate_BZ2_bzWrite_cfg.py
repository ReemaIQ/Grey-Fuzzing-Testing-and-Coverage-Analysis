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
        # Example:
        # Node0x19ebae0 [shape=record,label="{%2:
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
        # Format: DA:<line>,<count>
        if line.startswith("DA:"):
            parts = line.strip().split(":")[1].split(",")
            lineno = int(parts[0])
            hits = int(parts[1])
            line_hits[lineno] = hits

print(f"[+] Parsed {len(line_hits)} lines of coverage")


# ----------------------------------------------------
# Step 3: Map lines → BBs (approximate by line ranges)
# ----------------------------------------------------
# You filtered:
START_LINE = 4366
END_LINE = 4410

bb_hits = defaultdict(int)

# ⚠️ Simple heuristic:
# evenly distribute lines across BBs (since no exact debug map)
bbs = sorted(bb_to_node.keys())
if not bbs:
    raise Exception("No BBs found")

lines = sorted([l for l in line_hits if START_LINE <= l <= END_LINE])

chunk_size = max(1, len(lines) // len(bbs))

for i, bb in enumerate(bbs):
    chunk = lines[i * chunk_size:(i + 1) * chunk_size]
    for l in chunk:
        bb_hits[bb] += line_hits[l]

print("[+] Mapped coverage to BBs (approximate)")


# --------------------------------------
# Step 4: Assign colors based on coverage
# --------------------------------------
def get_color(hits):
    if hits == 0:
        return "lightcoral"
    elif hits < 10:
        return "khaki"
    else:
        return "darkseagreen"


# --------------------------------------
# Step 5: Rewrite DOT with annotations
# --------------------------------------
output_lines = []

with open(DOT_FILE, "r") as f:
    for line in f:
        modified = line

        m = re.search(r'(Node0x[0-9a-fA-F]+)', line)
        if m:
            node = m.group(1)
            if node in node_to_bb:
                bb = node_to_bb[node]
                hits = bb_hits.get(bb, 0)
                color = get_color(hits)

                # Inject color + label
                if "label=" in line:
                    modified = line.replace(
                        'label="{',
                        f'label="{{BB {bb} | hits={hits}\\l'
                    )

                if "shape=record" in line:
                    modified = modified.replace(
                        "shape=record",
                        f'shape=record, style=filled, fillcolor={color}'
                    )

        output_lines.append(modified)

with open("BZ2_bzWrite_annotated.dot", "w") as f:
    f.writelines(output_lines)

print("[+] Wrote annotated CFG to output_annotated.dot")
