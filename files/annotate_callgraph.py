import re

def load_set(path):
    funcs = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                funcs.add(line)
    return funcs

compress   = load_set("compress_set.txt")
decompress = load_set("decompress_set.txt")

def get_color(func):
    c = func in compress
    d = func in decompress
    if c and d:   return "plum"           # both
    elif c:       return "lightsteelblue" # compress only
    elif d:       return "lightseagreen"  # decompress only
    else:         return "mistyrose"      # not executed

with open("callgraph.dot") as f:
    lines = f.readlines()

out = []
for line in lines:
    m = re.search(r'label="\{([^}|\\]+)', line)
    if m and '->' not in line:   # only node definitions, not edges
        func  = m.group(1).strip()
        color = get_color(func)
        # Remove the existing ]; and append new attributes before it
        line = line.rstrip()          # remove newline
        if line.endswith('];'):
            line = line[:-2]          # strip the closing ];
            line = line + f', style=filled, fillcolor={color}];\n'
    out.append(line)

with open("callgraph_annotated.dot", "w") as f:
    f.writelines(out)
    
# Add legend
legend = '''
\tsubgraph cluster_legend {
\t\tlabel="Legend";
\t\tfontname="Arial";
\t\tfontsize=14;
\t\tstyle=filled;
\t\tfillcolor=white;
\t\tLEG_BOTH     [label="Both campaigns",      style=filled, fillcolor=plum,          shape=box];
\t\tLEG_COMPRESS [label="Compress only",        style=filled, fillcolor=lightsteelblue,shape=box];
\t\tLEG_DECOMP   [label="Decompress only",      style=filled, fillcolor=lightseagreen, shape=box];
\t\tLEG_NONE     [label="Not executed",         style=filled, fillcolor=mistyrose,     shape=box];
\t\tLEG_BOTH -> LEG_COMPRESS -> LEG_DECOMP -> LEG_NONE [style=invis];
\t}
'''

# Insert legend before the closing brace
with open("callgraph_annotated.dot") as f:
    content = f.read()

content = content.rstrip()
if content.endswith('}'):
    content = content[:-1] + legend + '\n}\n'

with open("callgraph_annotated.dot", "w") as f:
    f.write(content)

print("[+] Legend added → callgraph_annotated.dot")
