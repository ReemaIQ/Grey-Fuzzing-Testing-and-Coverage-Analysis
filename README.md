# Course Project: Program Testing and Coverage Analysis
## Final Report: bzip2 Fuzzing Campaign

**Team Members:** 
* REEMA IBRAHIM ALQAHTANI 202244660
* LENA EHAB ASHQAR 202282660
* ATHEER HANI ALMOMTAN 202246520

**Course:** SWE326 -- Software Testing

**Date:** May 2026

**Program Analyzed:** bzip2 (source file: `bzip2.c`)

---

## Table of Contents

1. [Program Analysis](#1-program-analysis)
2. [Function Analysis](#2-function-analysis)
3. [Fuzzing Campaigns](#3-fuzzing-campaigns)
4. [Source-Based Coverage](#4-source-based-coverage)
5. [Discussion](#5-discussion)
6. [Task Steps and Reproduction Guide](#6-task-steps-and-reproduction-guide)

---

## 1. Program Analysis

### What is bzip2?

bzip2 is a free, open-source file compression utility that uses the Burrows-Wheeler block-sorting algorithm combined with Huffman coding. It was written by Julian Seward in 1996 and is widely used on Unix and Linux systems as an alternative to gzip. bzip2 typically achieves better compression ratios than gzip at the cost of higher CPU usage and memory during compression and decompression.

The program accepts arbitrary input files and produces compressed `.bz2` files as output. It can also decompress `.bz2` files, test compressed files for integrity, and operate in pipeline mode. The source file `bzip2.c` is a single-file implementation containing approximately 7,000 lines of C code that implements both the command-line interface and the full compression and decompression library (libbz2).

### How bzip2 Works

bzip2 processes data in blocks. The compression pipeline applies the following transformations in order:

1. The input is split into blocks of up to 900KB each.
2. Each block undergoes the Burrows-Wheeler Transform (BWT), a reversible permutation that clusters repeated sequences together to improve compressibility.
3. A Move-To-Front (MTF) transform converts the BWT output into a sequence of small integers by tracking recently seen symbols.
4. Run-Length Encoding (RLE) removes consecutive repeated values from the MTF output.
5. Huffman coding compresses the result into a compact bitstream using variable-length codes.

Decompression reverses these steps: Huffman decode, RLE decode, MTF decode, inverse BWT, output.

### Program Architecture

bzip2 is organized into four logical layers:

**Command-line interface:** `main`, `compress`, `uncompress`, `testf`, `compressStream`, `uncompressStream`. Handles argument parsing, file I/O, signal handling, and user-facing behavior.

**High-level stream API:** `BZ2_bzWriteOpen`, `BZ2_bzWrite`, `BZ2_bzWriteClose`, `BZ2_bzReadOpen`, `BZ2_bzRead`, `BZ2_bzReadClose`. Provides a BZFILE-based interface similar to stdio for reading and writing bzip2 streams.

**Low-level compression/decompression engine:** `BZ2_bzCompress`, `BZ2_bzDecompress`. Implements the compression and decompression state machines that drive the algorithm.

**Algorithm implementations:** `BZ2_blockSort`, `BZ2_decompress`, `sendMTFValues`, `generateMTFValues`, `BZ2_hbMakeCodeLengths`, `mainGtU`, `fallbackSort`. The core components implementing BWT, MTF, Huffman coding, and block sorting.

### Call Graph

![Call Graph](./images/callgraph.png)

The call graph below shows all function call relationships in bzip2. The two functions analyzed in this report, `BZ2_bzWrite` (line 4366) and `uncompressStream` (line 5416), are highlighted with distinct colors.

![Call Graph Annotated](./images/callgraph_cov.png)
> Coverage-annotated call graph of bzip2.c. Blue nodes were executed during the compression campaign only. Green nodes were executed during the decompression campaign only. Purple nodes were executed in both campaigns. Pink nodes were not executed in either campaign. BZ2_bzWrite and uncompressStream are highlighted.

Key observations from the call graph:

- `main` is the root of the entire call tree, dispatching to `compress`, `uncompress`, or `testf` based on command-line flags.
- `uncompressStream` is called by `uncompress`, which is called from `main` during decompression.
- `BZ2_bzWrite` is called from `compressStream`, which is invoked from `compress` during compression.
- The compression engine functions `BZ2_blockSort`, `sendMTFValues`, and `BZ2_compressBlock` form a tightly coupled cluster called from `BZ2_bzCompress`.
- The decompression path goes through `BZ2_bzRead`, which calls `BZ2_bzDecompress`, which calls `BZ2_decompress` and related utility functions.
- Many API-layer functions (`BZ2_bzopen`, `BZ2_bzclose`, `BZ2_bzBuffToBuffCompress`) were never called by either campaign because the fuzzer only exercised the command-line compress and decompress paths.

---

## 2. Function Analysis

### 2.1 Function: BZ2_bzWrite (Line 4366)

#### Overview

`BZ2_bzWrite` is the primary write function in bzip2's high-level stream API. It receives uncompressed data from the caller, feeds it into the compression engine, and writes the resulting compressed bytes to an output file. Applications use this function to write data to an open bzip2 write stream, similar to how `fwrite` writes to a standard file.

#### Inputs and Outputs

```c
void BZ_API(BZ2_bzWrite)(
    int*    bzerror,   // Output: error code set on return
    BZFILE* b,         // Input: handle to an open bzip2 write stream
    void*   buf,       // Input: buffer containing uncompressed data to write
    int     len        // Input: number of bytes to compress from buf
);
```

The function returns void. All status information is communicated through the `bzerror` output parameter. On success, `bzerror` is set to `BZ_OK`. On failure, it is set to one of: `BZ_PARAM_ERROR`, `BZ_SEQUENCE_ERROR`, `BZ_IO_ERROR`, or a compression engine error code.

Note: `BZ_API` is a preprocessor macro that expands to nothing on Linux. The actual C function name is `BZ2_bzWrite`.

#### Key Computations

The function executes the following logic in order:

1. Parameter validation: checks that the internal file handle `bzf` is not NULL, that `buf` is not NULL, and that `len >= 0`. Any failure sets `bzerror` to `BZ_PARAM_ERROR` and returns.
2. State validation: verifies that the stream was opened for writing by checking `bzf->writing == 1`. If not, sets `bzerror` to `BZ_SEQUENCE_ERROR` and returns.
3. I/O error check: calls `ferror()` on the underlying file handle. If a file error is already present, sets `bzerror` to `BZ_IO_ERROR` and returns.
4. Zero-length shortcut: if `len == 0`, sets `bzerror` to `BZ_OK` and returns immediately.
5. Compression loop: sets `bzf->strm.avail_in = len` and `bzf->strm.next_in = buf`, then enters an infinite loop that:
   - Sets the output buffer to `bzf->buf` with size `BZ_MAX_UNUSED` (5000 bytes).
   - Calls `BZ2_bzCompress(&bzf->strm, BZ_RUN)` to compress available input.
   - If the output buffer contains data (`avail_out < BZ_MAX_UNUSED`), calls `fwrite()` to flush it to the file.
   - If `avail_in == 0`, all input has been consumed. Sets `bzerror` to `BZ_OK` and returns.

The compression loop drives the bzip2 state machine by calling `BZ2_bzCompress` repeatedly until all input bytes have been processed and written to disk.

#### CFG -- Original (LLVM IR)

![BZ2_bzWrite_cfg](./images/BZ2_bzWrite.png)
> Original CFG for BZ2_bzWrite generated by LLVM opt -passes=dot-cfg. Shows LLVM IR basic blocks. The function has approximately 50 basic blocks due to the many parameter checks, error paths, and the compression loop.

#### CFG -- Coverage Annotated

![BZ2_bzWrite_cov_cfg](./images/BZ2_bzWrite_annotated.png)
> Coverage-annotated CFG for BZ2_bzWrite from the compression campaign. Green nodes were executed (the entry block, parameter checks, and compression loop). Red nodes were not executed (all error-handling branches). Each node shows its basic block number and hit count.

---

### 2.2 Function: uncompressStream (Line 5416)

#### Overview

`uncompressStream` is the high-level decompression function in bzip2's command-line interface. It reads a bzip2-compressed file and writes the decompressed output to another file. It is an internal function called from `uncompress()` when the user runs `bzip2 -d file.bz2`. Unlike `BZ2_bzWrite`, which is part of the public library API, `uncompressStream` is specific to the bzip2 command-line tool.

#### Inputs and Outputs

```c
Bool uncompressStream(
    FILE *zStream,   // Input: open file handle to the compressed .bz2 input
    FILE *stream     // Input: open file handle to the decompressed output
);
// Returns: True on success, False on failure
```

The function returns a Bool value. Error conditions are handled internally by calling error-reporting functions such as `crcError()`, `ioError()`, and `compressedStreamEOF()` rather than returning error codes.

#### Key Computations

The function implements a multi-stream decompression loop:

1. Initialization: sets `nUnused = 0` and `streamNo = 0`. Sets both file streams to binary mode.
2. Pre-check: calls `ferror()` on both streams before starting. Jumps to `errhandler_io` if either has an error.
3. Outer while loop: iterates over potentially concatenated bzip2 streams within the same file. Each iteration calls `BZ2_bzReadOpen()` to initialize a decompression context, passing any leftover bytes from the previous stream, then increments `streamNo`.
4. Inner while loop: reads decompressed data in 5000-byte chunks using `BZ2_bzRead()` until `bzerr != BZ_OK`. If `BZ_DATA_ERROR_MAGIC` is returned and `streamNo > 1`, jumps to `trycat`. Otherwise calls `fwrite()` to write decompressed data to the output file.
5. Stream end handling: after each bzip2 stream ends, calls `BZ2_bzReadGetUnused()` to retrieve bytes read past the stream end, closes the stream with `BZ2_bzReadClose()`, and checks for EOF on the input.
6. closeok: if EOF is reached cleanly, closes both file handles and returns True.
7. trycat: if `forceOverwrite` is enabled and the data is not valid bzip2 format, rewinds the input and copies it unchanged to the output.
8. errhandler: a switch statement dispatches error codes to the appropriate error-reporting function. Handles `BZ_CONFIG_ERROR`, `BZ_IO_ERROR`, `BZ_DATA_ERROR`, `BZ_MEM_ERROR`, `BZ_UNEXPECTED_EOF`, `BZ_DATA_ERROR_MAGIC`, and a default `panic()` call.

The most complex aspect of this function is its handling of concatenated bzip2 streams. Multiple bzip2 streams can be concatenated in a single file, and `uncompressStream` correctly handles all of them in sequence by tracking unused bytes between streams in the `nUnused` and `unusedTmp` variables.

#### CFG -- Original (LLVM IR)

![uncompressStream](./images/uncompressStream.png)
> Original CFG for uncompressStream generated by LLVM opt -passes=dot-cfg. This function produces a large CFG with approximately 50 nodes due to its nested loops, goto statements (to closeok, trycat, errhandler), and switch-case error dispatcher.

#### CFG -- Coverage Annotated

![uncompressStream_cov_cfg](./images/uncompressStream_cov_cfg.png)
> Coverage-annotated CFG for uncompressStream from the decompression campaign. Green nodes are the main decompression loop path. Yellow nodes are partially covered conditional blocks. Red nodes are the errhandler switch block and all its branches, which were not reached by either campaign. Each node shows its basic block number and hit count.

---

## 3. Fuzzing Campaigns

### Machine Specifications

| Component | Details |
|-----------|---------|
| Model | MacBook Pro 14-inch, November 2023 |
| CPU | Apple M3 Pro (ARM64, 11 cores) |
| RAM | 18 GB |
| Host OS | macOS |
| Container OS | Ubuntu 24.04 (Docker, platform linux/amd64 emulated) |
| Docker | Version 29.4.1 |
| AFL++ | Version 4.41a |
| Compiler | afl-clang-fast (LLVM PCGUARD instrumentation, 2676 locations) |

Note: Because AFL++ requires a Linux environment, all fuzzing was performed inside a Docker container running Ubuntu 24.04 on the Apple M3 Mac. The `--platform linux/amd64` flag was used to emulate an x86-64 Linux environment. This reduced execution speed compared to native Linux hardware.

### Key resources consulted

- AFL++ official documentation: https://aflplus.plus/docs/
- Fuzzing101 Exercise 1: https://github.com/antonio-morales/Fuzzing101
- AFL++ GitHub repository and README
- Claude AI (for setup guidance and troubleshooting)

---

### Campaign 1: Compression

**Objective:** Fuzz bzip2's file compression functionality by feeding arbitrary inputs to be compressed.

**Command used:**
```bash
afl-fuzz -i seeds_compress -o out_compress -- ./bzip2_fuzz -k -f -z @@
```

Flag explanation:
- `-i seeds_compress`: use the seed directory as the initial corpus
- `-o out_compress`: save all results to this directory
- `-k`: keep the original input file (prevents bzip2 from deleting it)
- `-f`: force overwrite of any existing output file
- `-z`: compression mode
- `@@`: placeholder replaced by AFL++ with each generated test input path

Note: The initial command used `-z @@` only and showed an "odd, check syntax!" warning in AFL++. This was resolved by adding `-k -f` flags so bzip2 does not attempt to delete or reject the input file during fuzzing.

**Seed files used:**
```bash
# Small text
echo "Hello World" > seeds_compress/s1.txt

# Repeated patterns (tests RLE encoding in bzip2)
python3 -c "print('A'*100)" > seeds_compress/s2.txt
python3 -c "print('ABCD'*50)" > seeds_compress/s3.txt

# Long text with varied characters
python3 -c "import string; print(string.printable*10)" > seeds_compress/s4.txt

# Binary-like content
python3 -c "import os; open('seeds_compress/s5.bin','wb').write(os.urandom(512))"
python3 -c "import os; open('seeds_compress/s6.bin','wb').write(os.urandom(1024))"

# Empty and tiny files (edge cases)
echo "" > seeds_compress/s7.txt
echo "A" > seeds_compress/s8.txt

# Large file (stress test)
python3 -c "print('Hello World\n'*500)" > seeds_compress/s9.txt

# Null bytes and special characters
python3 -c "open('seeds_compress/s10.bin','wb').write(bytes(range(256)))"

# Structured data (CSV-like)
echo "name,age,city\nJohn,25,NYC\nJane,30,LA" > seeds_compress/s11.txt

# XML-like structure
echo "<root><item>test</item><item>data</item></root>" > seeds_compress/s12.txt
```

**Results:**

| Metric | Value |
|--------|-------|
| Duration | 1 day, 7 hours, 45 minutes |
| Corpus count | 1,424 inputs |
| Total executions | 4.58 million |
| Exec speed | 52.48/sec (reduced due to running alongside the decompression campaign) |
| Saved crashes | 0 |
| Saved hangs | 0 |
| Map density (peak) | 30.03% |
| Cycles completed | 7 |
| Total timeouts | 977 |
| New edges found | 39 (2.74%) |
| Own finds | 1,423 |
| Termination reason | Disk space exhausted |


![Screenshot_compression_final](./images/Screenshot_compression_final.png)
> Final AFL++ screen for the compression campaign before shutdown. Run time: 1 day 7 hours 45 minutes. Corpus count: 1,424. Saved crashes: 0. Map density: 17.82% / 30.03%.

---

### Campaign 2: Decompression -- Run 1 (Single Seed)

**Objective:** Fuzz bzip2's decompression functionality using a single minimal valid seed.

**Command used:**
```bash
afl-fuzz -i seeds_decompress -o out_decompress -- ./bzip2_fuzz -k -f -d @@
```

**Seed files used:**
- `seeds_decompress/seed1.bz2`: bzip2-compressed "hello world" (52 bytes)

**Results:**

| Metric | Value |
|--------|-------|
| Duration | 16 hours, 53 minutes |
| Corpus count | 529 inputs |
| Total executions | 7.64 million |
| Exec speed | 103.8/sec |
| Saved crashes | 0 |
| Saved hangs | 32 |
| Map density (peak) | 19.35% |
| Cycles completed | 91 |
| Total timeouts | 8,450 |
| New edges found | 119 (22.50%) |
| Own finds | 528 |
| Termination reason | Disk space exhausted |


![Screenshot_decompress_run1_terminated](./images/Screenshot_decompress_run1_terminated.png)
> Final AFL++ screen for decompression campaign Run 1. Run time: 16 hours 53 minutes. Corpus count: 529. Saved crashes: 0. Saved hangs: 32.

---

### Campaign 3: Decompression -- Run 2 (Better Seeds)

**Objective:** Re-run decompression fuzzing with a richer, more diverse seed corpus to improve coverage and crash discovery.

**Motivation:** Run 1 found 32 hangs but no crashes. The single "hello world" seed was insufficient to explore deeper bzip2 decompression parsing paths. Eight seeds were created to give AFL++ structurally diverse starting points in the bzip2 format space.

**Seed files used (8 files):**

```bash
# Original seed
echo "hello world" | bzip2 > seed1.bz2

# Different sizes of repetitive content
python3 -c "print('A'*100)"   | bzip2 > seed2.bz2
python3 -c "print('A'*1000)"  | bzip2 > seed3.bz2
python3 -c "print('A'*10000)" | bzip2 > seed4.bz2

# Random data (different entropy profile)
python3 -c "import os,bz2; open('seed5.bz2','wb').write(bz2.compress(os.urandom(100)))"
python3 -c "import os,bz2; open('seed6.bz2','wb').write(bz2.compress(os.urandom(1000)))"

# Different compression levels
echo "hello world test fuzzing bzip2" | bzip2 -1 > seed7.bz2
echo "hello world test fuzzing bzip2" | bzip2 -9 > seed8.bz2
```

**Command used:**
```bash
afl-fuzz -i seeds_decompress -o out_decompress2 -- ./bzip2_fuzz -k -f -d @@
```

**Results:**

| Metric | Value |
|--------|-------|
| Duration | 2 days, 2 hours, 9 minutes |
| Corpus count | 461 inputs |
| Total executions | 13.3 million |
| Exec speed | 148.4/sec |
| Saved crashes | 3 |
| Saved hangs | 30 |
| Map density (peak) | 19.20% |
| Cycles completed | 224 |
| Total timeouts | 9,592 |
| New edges found | 117 (25.38%) |
| Own finds | 453 |
| Last saved crash | 17 hours, 12 minutes before shutdown |


![Screenshot_decompress_run2_final](./images/Screenshot_decompress_run2_final.png)
> Caption: Final AFL++ screen for decompression campaign Run 2. Run time: 2 days 2 hours 9 minutes. Saved crashes: 3. Saved hangs: 30. Map density: 10.24% / 19.20%.

---

## 4. Source-Based Coverage

### Device and Environment Note

Tasks 3 and 4 (source-based coverage measurement and CFG annotation) were performed on a teammate's Linux VM (Ubuntu) rather than the Docker environment used for fuzzing. The fuzzing output folders were transferred to that machine to run afl-cov and the annotation scripts. All file paths in the steps below reflect that environment.

---

### Methodology

Source-level coverage was measured using afl-cov, a tool that replays AFL++ corpus inputs through a gcov-instrumented binary and generates LCOV HTML reports showing which lines and functions were executed and how many times.

#### Step 1: Install afl-cov manually

```bash
# Install dependencies first
sudo apt install git python3 lcov -y
```

#### Step 2: Clone afl-cov from GitHub

```bash
cd ~/Desktop
git clone https://github.com/mrash/afl-cov.git

# Verify it downloaded
ls afl-cov/

# Instrument bzip2 for coverage
gcc -O0 -g --coverage -fprofile-arcs -ftest-coverage bzip2.c -o bzip2_cov
```

The `-O0` flag disables compiler optimizations so source line numbers map accurately to executed code. The `--coverage` flag enables gcov instrumentation, which records an execution count per line.

#### Step 3: Run afl-cov for each campaign

```bash
# For decompression
python2 ~/Desktop/FuzzingProject/afl-cov/afl-cov \
        -d decompress/output_decompress \
        --coverage-cmd "./bzip2_cov -d AFL_FILE" \
        --code-dir . \
        --overwrite

# For compression
python2 ~/Desktop/FuzzingProject/afl-cov/afl-cov \
        -d compress/output_compress \
        --coverage-cmd "./bzip2_cov -z AFL_FILE" \
        --code-dir . \
        --overwrite
```

afl-cov replays every file in the AFL++ queue directory through the instrumented binary, accumulates gcov data across all inputs, and produces an LCOV HTML report. The placeholder `AFL_FILE` is substituted automatically with each corpus file path.

#### Step 4: Map coverage onto the CFGs

After collecting coverage data, the LCOV trace files were processed with custom Python annotation scripts to annotate the LLVM CFG dot files with color-coded coverage information.

```bash
# Run annotation scripts (make sure file paths inside the scripts match your environment)
python3 annotate_uncompressStream_cfg.py
python3 annotate_BZ2_bzWrite_cfg.py
```

**annotate_BZ2_bzWrite_cfg.py** parses the LCOV trace file and the LLVM CFG dot file for `BZ2_bzWrite`, maps line-level hit counts from the range 4366--4410 to basic blocks using a line-range distribution heuristic, and rewrites the dot file with color-coded nodes:

```python
import re
from collections import defaultdict

DOT_FILE  = "/home/seed/Desktop/FuzzingProject/.BZ2_bzWrite.dot"
LCOV_FILE = "/home/seed/Desktop/FuzzingProject/compress/output_compress/cov/lcov/trace.lcov_info"

# Step 1: Parse CFG dot file -- extract basic block numbers and node IDs
bb_to_node, node_to_bb = {}, {}
with open(DOT_FILE, "r") as f:
    for line in f:
        m = re.search(r'(Node0x[0-9a-fA-F]+).*?%\s*(\d+):', line)
        if m:
            node = m.group(1)
            bb   = int(m.group(2))
            bb_to_node[bb] = node
            node_to_bb[node] = bb

# Step 2: Parse LCOV -- extract line hit counts
line_hits = {}
with open(LCOV_FILE, "r") as f:
    for line in f:
        if line.startswith("DA:"):
            parts = line.strip().split(":")[1].split(",")
            line_hits[int(parts[0])] = int(parts[1])

# Step 3: Map lines 4366-4410 to basic blocks (approximate heuristic)
START_LINE, END_LINE = 4366, 4410
bbs   = sorted(bb_to_node.keys())
lines = sorted([l for l in line_hits if START_LINE <= l <= END_LINE])
chunk_size = max(1, len(lines) // len(bbs))
bb_hits = defaultdict(int)
for i, bb in enumerate(bbs):
    for l in lines[i * chunk_size:(i + 1) * chunk_size]:
        bb_hits[bb] += line_hits[l]

# Step 4: Color based on hit count
def get_color(hits):
    if hits == 0:   return "lightcoral"    # red: not covered
    elif hits < 10: return "khaki"         # yellow: partial
    else:           return "darkseagreen"  # green: well covered

# Step 5: Rewrite dot file with color annotations and hit count labels
output_lines = []
with open(DOT_FILE, "r") as f:
    for line in f:
        modified = line
        m = re.search(r'(Node0x[0-9a-fA-F]+)', line)
        if m:
            node = m.group(1)
            if node in node_to_bb:
                bb    = node_to_bb[node]
                hits  = bb_hits.get(bb, 0)
                color = get_color(hits)
                if "label=" in line:
                    modified = line.replace(
                        'label="{',
                        f'label="{{BB {bb} | hits={hits}\\l'
                    )
                if "shape=record" in modified:
                    modified = modified.replace(
                        "shape=record",
                        f'shape=record, style=filled, fillcolor={color}'
                    )
        output_lines.append(modified)

with open("BZ2_bzWrite_annotated.dot", "w") as f:
    f.writelines(output_lines)
```

**annotate_uncompressStream_cfg.py** uses identical logic for `uncompressStream` (lines 5416--5700) using the decompression campaign LCOV trace file.

#### Step 5: Transform annotated dot files to PNG

```bash
dot -Tpng output_annotated.dot -o cfg.png
```

For each function specifically:
```bash
dot -Tpng BZ2_bzWrite_annotated.dot      -o BZ2_bzWrite_cov_cfg.png
dot -Tpng uncompressStream_annotated.dot  -o uncompressStream_cov_cfg.png
```

#### Step 6: Map coverage onto the call graph

To annotate the call graph, first extract the set of functions executed in each campaign from the LCOV trace files:

```bash
# Find the functions and how many times they were hit
grep "DA:" compress_cov/lcov/trace.lcov_info   > compress_hits.txt
grep "DA:" decompress_cov/lcov/trace.lcov_info > decompress_hits.txt

# Extract function names only
grep "^FNDA" compress_hits.txt   | cut -d',' -f2 | sort -u > compress_set.txt
grep "^FNDA" decompress_hits.txt | cut -d',' -f2 | sort -u > decompress_set.txt
```

Then run the call graph annotation script:

```bash
python3 annotate_callgraph.py
```

**annotate_callgraph.py** reads the two function sets and colors each node in the call graph dot file based on which campaigns executed it:

```python
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
    if c and d:  return "plum"            # both campaigns
    elif c:      return "lightsteelblue"  # compression only
    elif d:      return "lightseagreen"   # decompression only
    else:        return "mistyrose"       # not executed

with open("callgraph.dot") as f:
    lines = f.readlines()

out = []
for line in lines:
    m = re.search(r'label="\{([^}|\\]+)', line)
    if m and '->' not in line:
        func  = m.group(1).strip()
        color = get_color(func)
        line  = line.rstrip()
        if line.endswith('];'):
            line = line[:-2] + f', style=filled, fillcolor={color}];\n'
    out.append(line)

with open("callgraph_annotated.dot", "w") as f:
    f.writelines(out)
```

Color scheme for the call graph:
- Blue (lightsteelblue): executed in the compression campaign only
- Green (lightseagreen): executed in the decompression campaign only
- Purple (plum): executed in both campaigns
- Pink (mistyrose): not executed in either campaign

#### Step 7: Transform annotated call graph to PNG

```bash
dot -Tpng callgraph_annotated.dot -o callgraph_cov.png
```

---

### Coverage Summary Table

The table below summarizes the source-based coverage results collected from the afl-cov HTML reports for both fuzzing campaigns. Coverage was measured by replaying the full AFL++ corpus through the gcov-instrumented binary.

| Metric | Compression Campaign | Decompression Campaign |
|--------|---------------------|----------------------|
| Total lines in bzip2.c | 2,744 | 2,744 |
| Lines covered (hit) | 1,245 | 890 |
| Lines not covered | 1,499 | 1,854 |
| Line coverage % | **45.4%** | **32.4%** |
| Total functions | 106 | 106 |
| Functions covered (hit) | 52 | 38 |
| Functions not covered | 54 | 68 |
| Function coverage % | **49.1%** | **35.8%** |
| Report generated | 2026-05-05 21:42:54 | 2026-05-05 21:20:20 |
| Corpus inputs replayed | 1,424 | 461 |
| Crashes found | 0 | 3 |
| Hangs found | 0 | 30 |

**Key observations:**

- Compression achieved higher line coverage (45.4%) than decompression (32.4%). This is because bzip2 compression accepts any byte sequence as valid input, so every corpus file reaches the compression engine. Decompression requires structurally valid bzip2 format data, so many mutated inputs are rejected at the format-parsing stage before reaching meaningful code.
- Compression covered 52 of 106 functions (49.1%). Decompression covered only 38 of 106 functions (35.8%) because entire subsystems -- the full compression engine (BZ2_bzCompress, BZ2_blockSort, sendMTFValues, BZ2_hbMakeCodeLengths, mainGtU, bsW, etc.) -- are never reached during decompression.
- In both campaigns, error-handling functions (configError, ioError, crcError, outOfMemory, panic) and unused API-layer functions (BZ2_bzopen, BZ2_bzclose, BZ2_bzBuffToBuffCompress) received zero hits.


![afl-cov_compress1.png](./images/afl-cov_compress1.png)
> afl-cov LCOV HTML report for the compression campaign. Summary view showing 45.4% line coverage (1,245 / 2,744) and 49.1% function coverage (52 / 106). Functions not executed are shown with a red hit count bar. Date: 2026-05-05 21:42:54.


![afl-cov_compress2.png](./images/afl-cov_compress2.png)
> Function-level hit count list for the compression campaign, sorted by frequency. Selected function hits: BZ2_bzWrite: 4,462 -- BZ2_bzCompress: 6,025 -- bsPutUChar: 23,984 -- BZ2_hbMakeCodeLengths: 31,560 -- fallbackSimpleSort: 711,448 -- bsW: 8,712,590 -- mainGtU: 15,790,300.


![afl-cov_decompress1.png](./images/afl-cov_decompress1.png)
> afl-cov LCOV HTML report for the decompression campaign. Summary view showing 32.4% line coverage (890 / 2,744) and 35.8% function coverage (38 / 106). Date: 2026-05-05 21:20:20.


![afl-cov-decompress2.png](./images/afl-cov-decompress2.png)
> Function-level hit count list for the decompression campaign, sorted by frequency. Selected function hits: uncompressStream: 374 -- BZ2_decompress: 506 -- BZ2_bzDecompressInit: 388 -- BZ2_bzReadOpen: 388 -- BZ2_bzRead: 14,224 -- BZ2_bzReadGetUnused: 14 -- crcError: 266 -- compressedStreamEOF: 101 -- myfeof: 15,992.

### Coverage of the Two Specified Functions

The project requires specific coverage analysis of `BZ2_bzWrite` (line 4366) and `uncompressStream` (line 5416). The tables below show the exact line-by-line hit counts extracted directly from the afl-cov LCOV HTML reports for each campaign.

**Compression campaign -- BZ2_bzWrite and uncompressStream:**


<div style="padding: 1rem 0; font-family: var(--font-mono); font-size: 13px;">

  <h2 class="sr-only">afl-cov compression campaign coverage tables for BZ2_bzWrite and uncompressStream</h2>

  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 1.5rem;">
    <div style="background: var(--color-background-secondary); border-radius: var(--border-radius-md); padding: 1rem;">
      <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 4px;">Compression campaign</p>
      <p style="font-size: 13px; font-weight: 500; margin: 0 0 8px;">2026-05-05 21:42:54</p>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
        <div style="background: var(--color-background-primary); border-radius: var(--border-radius-md); padding: 10px; text-align: center;">
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 2px;">Lines</p>
          <p style="font-size: 18px; font-weight: 500; color: #B86A00; margin: 0;">45.4%</p>
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 2px 0 0;">1245 / 2744</p>
        </div>
        <div style="background: var(--color-background-primary); border-radius: var(--border-radius-md); padding: 10px; text-align: center;">
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 2px;">Functions</p>
          <p style="font-size: 18px; font-weight: 500; color: #B86A00; margin: 0;">49.1%</p>
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 2px 0 0;">52 / 106</p>
        </div>
      </div>
    </div>
    <div style="background: var(--color-background-secondary); border-radius: var(--border-radius-md); padding: 1rem;">
      <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 4px;">BZ2_bzWrite function hits</p>
      <p style="font-size: 22px; font-weight: 500; color: #2e7d32; margin: 0 0 4px;">4,462</p>
      <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 8px;">uncompressStream function hits</p>
      <p style="font-size: 22px; font-weight: 500; color: #c62828; margin: 0;">0</p>
    </div>
  </div>

  <div style="background: var(--color-background-primary); border: 0.5px solid var(--color-border-tertiary); border-radius: var(--border-radius-lg); overflow: hidden; margin-bottom: 1rem;">
    <div style="padding: 10px 14px; border-bottom: 0.5px solid var(--color-border-tertiary); display: flex; justify-content: space-between; align-items: center;">
      <span style="font-weight: 500;">BZ2_bzWrite -- line coverage (compression campaign)</span>
      <span style="background: #e8f5e9; color: #2e7d32; padding: 2px 10px; border-radius: 4px; font-size: 11px;">4,462 calls</span>
    </div>
    <div style="overflow-x: auto;">
      <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <tr style="background: var(--color-background-secondary);">
          <td style="padding: 5px 10px; color: var(--color-text-secondary); width: 55px;">Line</td>
          <td style="padding: 5px 10px; color: var(--color-text-secondary); width: 80px;">Hits</td>
          <td style="padding: 5px 10px; color: var(--color-text-secondary);">Source</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4366</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">void BZ_API(BZ2_bzWrite)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4373</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">bzFile* bzf = (bzFile*)b;</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4375</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">BZ_SETERR(BZ_OK);</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4376</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">if (bzf == NULL || buf == NULL || len &lt; 0)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4377</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">{ BZ_SETERR(BZ_PARAM_ERROR); return; }</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4378</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">if (!(bzf->writing))</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4379</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">{ BZ_SETERR(BZ_SEQUENCE_ERROR); return; }</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4380</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">if (ferror(bzf->handle))</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4381</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">{ BZ_SETERR(BZ_IO_ERROR); return; }</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4383</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">if (len == 0)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4384</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">{ BZ_SETERR(BZ_OK); return; } -- len==0 shortcut</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4386</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">bzf->strm.avail_in = len;</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4390</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">bzf->strm.avail_out = BZ_MAX_UNUSED; (loop)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4392</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">ret = BZ2_bzCompress(&bzf->strm, BZ_RUN);</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4394</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">{ BZ_SETERR(ret); return; } -- compress error</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4396</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">if (bzf->strm.avail_out &lt; BZ_MAX_UNUSED)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4397-4401</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">fwrite path + IO error check -- all 0</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4404</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">if (bzf->strm.avail_in == 0)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">4405</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">4,462</td>
          <td style="padding: 4px 10px; color: #2e7d32;">{ BZ_SETERR(BZ_OK); return; } -- success</td>
        </tr>
      </table>
    </div>
    <div style="padding: 8px 14px; border-top: 0.5px solid var(--color-border-tertiary); font-size: 11px; color: var(--color-text-secondary);">
      16 lines covered, 7 lines not covered. All uncovered lines are error-handling branches (param error, sequence error, IO error, fwrite error).
    </div>
  </div>

  <div style="background: var(--color-background-primary); border: 0.5px solid var(--color-border-tertiary); border-radius: var(--border-radius-lg); overflow: hidden;">
    <div style="padding: 10px 14px; border-bottom: 0.5px solid var(--color-border-tertiary); display: flex; justify-content: space-between; align-items: center;">
      <span style="font-weight: 500;">uncompressStream -- line coverage (compression campaign)</span>
      <span style="background: #ffebee; color: #c62828; padding: 2px 10px; border-radius: 4px; font-size: 11px;">0 calls -- never reached</span>
    </div>
    <div style="overflow-x: auto;">
      <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <tr style="background: var(--color-background-secondary);">
          <td style="padding: 5px 10px; color: var(--color-text-secondary); width: 55px;">Line</td>
          <td style="padding: 5px 10px; color: var(--color-text-secondary); width: 80px;">Hits</td>
          <td style="padding: 5px 10px; color: var(--color-text-secondary);">Source</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5416</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">Bool uncompressStream(FILE *zStream, FILE *stream)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5418-5432</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">Initialization, variable declarations, ferror checks</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5436-5448</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">BZ2_bzReadOpen, outer while loop, inner read loop</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5452-5478</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">get unused bytes, closeok, fclose, return True</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5480-5525</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">trycat, errhandler, all error cases -- all 0</td>
        </tr>
      </table>
    </div>
    <div style="padding: 8px 14px; border-top: 0.5px solid var(--color-border-tertiary); font-size: 11px; color: var(--color-text-secondary);">
      uncompressStream not called during compression campaign. Fuzzer used -z flag; decompression path was never invoked. All 68 instrumented lines show 0 hits.
    </div>
  </div>

  <div style="display: flex; gap: 16px; padding: 10px 0 0; font-size: 11px;">
    <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 10px; height: 10px; background: #f0fff4; border: 0.5px solid #2e7d32; display: inline-block;"></span><span style="color: var(--color-text-secondary);">covered</span></span>
    <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 10px; height: 10px; background: #fff0f0; border: 0.5px solid #c62828; display: inline-block;"></span><span style="color: var(--color-text-secondary);">not covered</span></span>
  </div>

</div>


**Decompression campaign -- BZ2_bzWrite and uncompressStream:**


<div style="padding: 1rem 0; font-family: var(--font-mono); font-size: 13px;">

  <h2 style="sr-only">afl-cov coverage tables for BZ2_bzWrite and uncompressStream</h2>

  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 1.5rem;">
    <div style="background: var(--color-background-secondary); border-radius: var(--border-radius-md); padding: 1rem;">
      <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 4px;">Compression campaign</p>
      <p style="font-size: 13px; font-weight: 500; margin: 0 0 8px;">2026-05-05 21:42:54</p>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
        <div style="background: var(--color-background-primary); border-radius: var(--border-radius-md); padding: 10px; text-align: center;">
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 2px;">Lines</p>
          <p style="font-size: 18px; font-weight: 500; color: #B86A00; margin: 0;">45.4%</p>
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 2px 0 0;">1245 / 2744</p>
        </div>
        <div style="background: var(--color-background-primary); border-radius: var(--border-radius-md); padding: 10px; text-align: center;">
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 2px;">Functions</p>
          <p style="font-size: 18px; font-weight: 500; color: #B86A00; margin: 0;">49.1%</p>
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 2px 0 0;">52 / 106</p>
        </div>
      </div>
    </div>
    <div style="background: var(--color-background-secondary); border-radius: var(--border-radius-md); padding: 1rem;">
      <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 4px;">Decompression campaign</p>
      <p style="font-size: 13px; font-weight: 500; margin: 0 0 8px;">2026-05-05 21:20:20</p>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
        <div style="background: var(--color-background-primary); border-radius: var(--border-radius-md); padding: 10px; text-align: center;">
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 2px;">Lines</p>
          <p style="font-size: 18px; font-weight: 500; color: #B86A00; margin: 0;">32.4%</p>
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 2px 0 0;">890 / 2744</p>
        </div>
        <div style="background: var(--color-background-primary); border-radius: var(--border-radius-md); padding: 10px; text-align: center;">
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 0 0 2px;">Functions</p>
          <p style="font-size: 18px; font-weight: 500; color: #B86A00; margin: 0;">35.8%</p>
          <p style="font-size: 11px; color: var(--color-text-secondary); margin: 2px 0 0;">38 / 106</p>
        </div>
      </div>
    </div>
  </div>

  <div style="background: var(--color-background-primary); border: 0.5px solid var(--color-border-tertiary); border-radius: var(--border-radius-lg); overflow: hidden; margin-bottom: 1rem;">
    <div style="padding: 10px 14px; border-bottom: 0.5px solid var(--color-border-tertiary); display: flex; justify-content: space-between;">
      <span style="font-weight: 500;">BZ2_bzWrite -- line coverage (decompression campaign)</span>
      <span style="color: #c62828; font-weight: 500;">0 / 25 lines hit</span>
    </div>
    <div style="overflow-x: auto;">
      <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <tr style="background: var(--color-background-secondary);">
          <td style="padding: 5px 10px; color: var(--color-text-secondary); width: 55px;">Line</td>
          <td style="padding: 5px 10px; color: var(--color-text-secondary); width: 70px;">Hits</td>
          <td style="padding: 5px 10px; color: var(--color-text-secondary);">Source</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4366</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">void BZ_API(BZ2_bzWrite)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4373</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">bzFile* bzf = (bzFile*)b;</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4375</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">BZ_SETERR(BZ_OK);</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4376</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">if (bzf == NULL || buf == NULL || len &lt; 0)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4377</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">{ BZ_SETERR(BZ_PARAM_ERROR); return; }</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4378</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">if (!(bzf->writing))</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4379</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">{ BZ_SETERR(BZ_SEQUENCE_ERROR); return; }</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4380</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">if (ferror(bzf->handle))</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4381</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">{ BZ_SETERR(BZ_IO_ERROR); return; }</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4383</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">if (len == 0)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">4386-4407</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">compression loop, fwrite, return -- all lines</td>
        </tr>
      </table>
    </div>
    <div style="padding: 8px 14px; border-top: 0.5px solid var(--color-border-tertiary); color: var(--color-text-secondary); font-size: 11px;">
      BZ2_bzWrite not called during decompression campaign -- 0 hits on all 25 instrumented lines
    </div>
  </div>

  <div style="background: var(--color-background-primary); border: 0.5px solid var(--color-border-tertiary); border-radius: var(--border-radius-lg); overflow: hidden;">
    <div style="padding: 10px 14px; border-bottom: 0.5px solid var(--color-border-tertiary); display: flex; justify-content: space-between;">
      <span style="font-weight: 500;">uncompressStream -- line coverage (decompression campaign)</span>
      <span style="color: #2e7d32; font-weight: 500;">374 function calls</span>
    </div>
    <div style="overflow-x: auto;">
      <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <tr style="background: var(--color-background-secondary);">
          <td style="padding: 5px 10px; color: var(--color-text-secondary); width: 55px;">Line</td>
          <td style="padding: 5px 10px; color: var(--color-text-secondary); width: 80px;">Hits</td>
          <td style="padding: 5px 10px; color: var(--color-text-secondary);">Source</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">5416</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">374</td>
          <td style="padding: 4px 10px; color: #2e7d32;">Bool uncompressStream(FILE *zStream, FILE *stream)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">5418</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">374</td>
          <td style="padding: 4px 10px; color: #2e7d32;">BZFILE* bzf = NULL;</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">5431</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">374</td>
          <td style="padding: 4px 10px; color: #2e7d32;">if (ferror(stream)) goto errhandler_io;</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">5436</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">388</td>
          <td style="padding: 4px 10px; color: #2e7d32;">bzf = BZ2_bzReadOpen(...)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">5443</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">14,605</td>
          <td style="padding: 4px 10px; color: #2e7d32;">while (bzerr == BZ_OK)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">5444</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">14,224</td>
          <td style="padding: 4px 10px; color: #2e7d32;">nread = BZ2_bzRead(&bzerr, bzf, obuf, 6000);</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">5447</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">13,836</td>
          <td style="padding: 4px 10px; color: #2e7d32;">fwrite(obuf, sizeof(UChar), nread, stream);</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #f0fff4;">
          <td style="padding: 4px 10px; color: #2e7d32;">5463-5478</td>
          <td style="padding: 4px 10px; color: #2e7d32; font-weight: 500;">6</td>
          <td style="padding: 4px 10px; color: #2e7d32;">closeok: fclose, fflush, return True</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fffde7;">
          <td style="padding: 4px 10px; color: #B86A00;">5480-5490</td>
          <td style="padding: 4px 10px; color: #B86A00; font-weight: 500;">6-40</td>
          <td style="padding: 4px 10px; color: #B86A00;">trycat: forceOverwrite path (partial)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5493</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">errhandler: (switch entry)</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5494</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">367</td>
          <td style="padding: 4px 10px; color: #c62828;">BZ2_bzReadClose(&bzerr_dummy, bzf);</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5496</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">case BZ_CONFIG_ERROR: configError()</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5499</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">errhandler_io: ioError()</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fffde7;">
          <td style="padding: 4px 10px; color: #B86A00;">5501</td>
          <td style="padding: 4px 10px; color: #B86A00; font-weight: 500;">266</td>
          <td style="padding: 4px 10px; color: #B86A00;">case BZ_DATA_ERROR: crcError()</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5503</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">case BZ_MEM_ERROR: outOfMemory()</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fffde7;">
          <td style="padding: 4px 10px; color: #B86A00;">5505</td>
          <td style="padding: 4px 10px; color: #B86A00; font-weight: 500;">101</td>
          <td style="padding: 4px 10px; color: #B86A00;">case BZ_UNEXPECTED_EOF: compressedStreamEOF()</td>
        </tr>
        <tr style="border-top: 0.5px solid var(--color-border-tertiary); background: #fff0f0;">
          <td style="padding: 4px 10px; color: #c62828;">5507-5520</td>
          <td style="padding: 4px 10px; color: #c62828; font-weight: 500;">0</td>
          <td style="padding: 4px 10px; color: #c62828;">BZ_DATA_ERROR_MAGIC, default panic -- all 0</td>
        </tr>
      </table>
    </div>
    <div style="display: flex; gap: 16px; padding: 8px 14px; border-top: 0.5px solid var(--color-border-tertiary); font-size: 11px;">
      <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 10px; height: 10px; background: #f0fff4; border: 0.5px solid #2e7d32; display: inline-block;"></span><span style="color: var(--color-text-secondary);">covered</span></span>
      <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 10px; height: 10px; background: #fffde7; border: 0.5px solid #B86A00; display: inline-block;"></span><span style="color: var(--color-text-secondary);">partial</span></span>
      <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 10px; height: 10px; background: #fff0f0; border: 0.5px solid #c62828; display: inline-block;"></span><span style="color: var(--color-text-secondary);">not covered</span></span>
    </div>
  </div>

</div>


---

### Coverage Analysis: BZ2_bzWrite

| Campaign | Hit Count | Status |
|----------|-----------|--------|
| Compression | 4,462 | Covered |
| Decompression | 0 | Not covered |

During the compression campaign, `BZ2_bzWrite` was called 4,462 times. The main execution path through parameter validation, the compression loop, and the fwrite call was well covered. Functions called by it were also heavily exercised: `BZ2_bzCompress` (6,025 hits), `handle_compress` (6,025 hits), `bsPutUChar` (23,984 hits).

During the decompression campaign, `BZ2_bzWrite` received 0 hits. This is expected: the fuzzer invoked bzip2 with the `-d` flag, so the write path was never reached.

Lines not covered in either campaign: the error-handling branches at lines 4377 (BZ_PARAM_ERROR), 4379 (BZ_SEQUENCE_ERROR), 4381 (BZ_IO_ERROR), 4384 (len == 0 early return), 4394 (compress error return), and 4397--4401 (fwrite error handling). These branches require environmental conditions such as null pointers or file system failures that cannot be triggered by mutating the content of an input file.


![BZ2_bzWrite_cov_cfg](./images/BZ2_bzWrite_annotated.png)
> Coverage-annotated CFG for BZ2_bzWrite. Green nodes were executed during the compression campaign. Red nodes are error-handling basic blocks that were not reached by either campaign. Each node shows its basic block number and hit count.

---

### Coverage Analysis: uncompressStream

| Campaign | Hit Count | Status |
|----------|-----------|--------|
| Compression | 0 | Not covered |
| Decompression | 374 | Covered (partially) |

During the decompression campaign, `uncompressStream` was called 374 times. The following blocks were covered: the entry block and initialization, the outer while loop, the inner read loop (BZ2_bzRead: 14,224 hits), stream-end handling, unused-byte extraction, and the closeok return path. The trycat fallback path was also reached, meaning AFL++ generated inputs that passed the outer loop but failed the bzip2 magic check inside the read loop.

During the compression campaign, `uncompressStream` received 0 hits.

The entire errhandler switch block (lines 5493--5520) was not covered in either campaign. This block handles BZ_CONFIG_ERROR (calls configError), BZ_IO_ERROR (calls ioError), BZ_DATA_ERROR (calls crcError), BZ_MEM_ERROR (calls outOfMemory), BZ_UNEXPECTED_EOF (calls compressedStreamEOF), BZ_DATA_ERROR_MAGIC (returns false or true based on stream count), and a default panic call. Notably, crcError received 266 hits and compressedStreamEOF received 101 hits through other call paths, but not through uncompressStream's errhandler block.

![uncompressStream_cov_cfg](./images/uncompressStream_cov_cfg.png)
> Coverage-annotated CFG for uncompressStream. Green nodes are the main decompression loop path covered during the decompression campaign. Yellow nodes are partially covered conditional blocks. Red nodes are the errhandler switch block and all its branches, which were not reached by either campaign.

---

## 5. Discussion

### 5.1 Coverage Patterns

**Well-covered areas:** The compression pipeline was the most thoroughly explored part of bzip2, achieving 45.4% line coverage and 49.1% function coverage after 31 hours of fuzzing. The core compression algorithms were extremely heavily exercised: `mainGtU` received 15,790,300 hits, `bsW` received 8,712,590 hits, and `fallbackSimpleSort` received 711,448 hits. This level of coverage was achieved because bzip2 compression imposes no format requirements on its input. Any sequence of bytes is valid input to compress. AFL++ can mutate inputs freely and reach the compression engine on every single execution, allowing it to explore many path variations without format-validation barriers.

**Poorly covered areas:** Error handling paths were consistently missed across the entire codebase in both campaigns. Functions such as `panic`, `configError`, `ioError`, `crcError`, and `outOfMemory` all showed zero hits in their primary call paths within the target functions. Additionally, the entire test functionality (`testStream`, `testf`) was never reached because the fuzzer was configured to exercise only the compress and decompress paths. API-layer functions (`BZ2_bzopen`, `BZ2_bzclose`, `BZ2_bzBuffToBuffCompress`, `BZ2_bzBuffToBuffDecompress`) were also never reached, as the fuzzer targeted the command-line interface rather than the library API directly.

**Effect of program structure:** bzip2's control flow structure had a decisive impact on which areas were reached. The compression path is essentially linear: input flows through BWT, MTF, RLE, and Huffman coding with few early-exit conditions, making it straightforward for AFL++ to explore. The decompression path is gated by a strict binary format parser. A valid bzip2 stream must begin with the magic bytes "BZh", a block-size digit, and block headers containing the specific constant 0x314159265359. Most randomly mutated inputs are rejected at the magic-check stage before reaching any meaningful decompression logic, which is why decompression coverage (32.4%) was substantially lower than compression coverage (45.4%) despite the decompression campaign running longer. The while(True) loops inside both BZ2_bzWrite and uncompressStream also concentrated execution in a small number of lines rather than distributing it across the function, inflating hit counts for hot lines while leaving rarely-taken branches uncovered.

---

### 5.2 Function-Level Coverage

**BZ2_bzWrite:** The main execution path was thoroughly covered with 4,462 calls during the compression campaign. The compression loop ran many iterations per call, with `bsPutUChar` receiving 23,984 hits as a result of repeated buffer writes. However, every error-handling branch received zero hits. The BZ_PARAM_ERROR path requires passing a null pointer, the BZ_SEQUENCE_ERROR path requires calling the function before opening a write stream, the BZ_IO_ERROR paths require an actual file system error, and the compress-error return path requires a failure inside BZ2_bzCompress. None of these conditions can arise from mutating the content of an input file. The BZFILE handle is properly initialized before fuzzing begins, the file system functions correctly, and BZ2_bzCompress does not fail on arbitrary input. This is a fundamental limitation of mutation-based fuzzing for a function whose error paths depend on internal state and environmental conditions rather than input data.

**uncompressStream:** The decompression campaign drove this function 374 times and covered the majority of its main logic path. The inner read loop was the most active portion, with BZ2_bzRead accumulating 14,224 hits across all inputs. The trycat fallback path was also reached, which is notable: it means AFL++ generated inputs that passed the outer loop and entered the bzip2 reading context but returned BZ_DATA_ERROR_MAGIC, triggering the force-copy path. The entire errhandler switch block remained unreachable in both campaigns. Reaching specific error cases such as BZ_DATA_ERROR (CRC mismatch) or BZ_MEM_ERROR requires precisely crafted inputs that pass header and selector checks but contain corrupted CRC values, or requires exhausting system memory -- both of which are beyond what byte-level mutation can reliably produce.

---

### 5.3 Crash Analysis

**Overview:** Three crashes were found during decompression campaign Run 2, over a total runtime of 2 days and 2 hours. All three were discovered after switching to the improved 8-seed corpus. No crashes were found during the compression campaign or the first decompression run.

**Command used to find the crashes (from AFL++ README.txt):**
```bash
afl-fuzz -i seeds_decompress -o out_decompress2 -- ./bzip2_fuzz -k -f -d @@
```

**To reproduce a crash manually:**
```bash
# Inside Docker container
./bzip2_fuzz -k -f -d out_decompress2/default/crashes/id:000000,sig:11,src:000176,time:863267,execs:122813,op:havoc,rep:1
# Expected: Segmentation fault (signal 11)
```

**Crash file details:**

| File | Size | Signal | Found at exec | Mutation |
|------|------|--------|--------------|----------|
| id:000000 | 47 bytes | SIGSEGV (signal 11) | 122,813 | havoc, rep_1 |
| id:000001 | 166 bytes | SIGSEGV (signal 11) | 565,784 | havoc, rep_6 |
| id:000002 | 50 bytes | SIGSEGV (signal 11) | 8,600,599 | havoc, rep_2 |

All three crashes triggered signal 11 (SIGSEGV), indicating an illegal memory access (segmentation fault).

**Input structure analysis:** All three crash files share the same header structure. They begin with a syntactically valid bzip2 header that passes initial format validation but contain a malformed or truncated compressed data payload:

```
Offset 00-01: 42 5a        -- "BZ"  (bzip2 magic number)
Offset 02:    68           -- 'h'   (Huffman coding indicator)
Offset 03:    39           -- '9'   (block size: 900KB)
Offset 04-09: 31 41 59 26 53 59 -- block magic (pi: 0x314159265359)
Offset 0A-0D: 88 80 6e 5d -- CRC32 checksum field
Offset 0E+:   [malformed or truncated compressed data]
```

The inputs pass the magic number check and block header check but the compressed data payload is either truncated (47 to 50 bytes total, far too small for a real bzip2 block) or structurally inconsistent.

**Q1 -- In what functionality/function/line-of-code is the bug?**

The bug is in the decompression functionality, specifically inside function `BZ2_decompress` in `bzip2.c`, in the Huffman selector decoding section starting at approximately line 3142. `BZ2_decompress` is the low-level decompression state machine that decodes the compressed bitstream block by block. It is called from `BZ2_bzDecompress`, which is called from `BZ2_bzRead`, which is called from `uncompressStream`.

**Bug behavior and location:** The crash occurs inside `BZ2_decompress` (lines 2939--3448), specifically in the Huffman selector decoding section. The function reads `nSelectors` as a 15-bit value, which can be up to 32,767. It then enters a loop that iterates `nSelectors` times, reading bits from the input stream to reconstruct the selector table:

```c
GET_BITS(BZ_X_SELECTOR_2, nSelectors, 15);
if (nSelectors < 1) RETURN(BZ_DATA_ERROR);
for (i = 0; i < nSelectors; i++) {
    j = 0;
    while (True) {
        GET_BIT(BZ_X_SELECTOR_3, uc);
        if (uc == 0) break;
        j++;
        if (j >= nGroups) RETURN(BZ_DATA_ERROR);
    }
    s->selectorMtf[i] = j;
}
```

When the input stream is only 47 to 50 bytes long but `nSelectors` claims a large value, the `GET_BIT` macro exhausts the available input buffer and begins returning undefined values. This corrupts the internal decoder state, specifically the pointers `gLimit`, `gPerm`, and `gBase` used in the main Huffman decoding loop. When the decompressor subsequently dereferences one of these corrupted pointers, a SIGSEGV occurs.

**Q2 -- What kind of bug is it?**

This is a memory safety bug -- specifically an out-of-bounds read / use-after-exhaustion caused by insufficient validation of the relationship between the declared `nSelectors` count and the amount of input data actually available. The `GET_BIT` macro does not detect or signal input exhaustion; it silently returns undefined values, allowing corrupted internal state to propagate until a crash occurs. This class of bug is a classic buffer over-read in a binary format parser: the program trusts a length field in the input without verifying that enough bytes actually follow.

**Bug type:** Memory safety bug -- out-of-bounds read caused by insufficient validation of the relationship between the declared `nSelectors` count and the amount of input data actually available. The `GET_BIT` macro does not detect or signal input exhaustion; it silently returns undefined values, allowing corrupted state to propagate until a crash occurs.

**Q3 -- How to fix it?**

Three targeted fixes would address the root cause:

1. Add explicit input-exhaustion detection in the `GET_BIT` and `GET_BITS` macros. When the input stream is empty, return `BZ_DATA_ERROR` immediately rather than reading past the end of the buffer.
2. Add a bounds check that `nSelectors <= BZ_MAX_SELECTORS` before the selector-decoding loop. The constant `BZ_MAX_SELECTORS` is already defined in the code but is not enforced at this decode point.
3. Validate that `alphaSize <= BZ_MAX_ALPHA_SIZE` before indexing into the `len[][]`, `limit[][]`, `perm[][]`, and `base[][]` arrays to prevent any remaining out-of-bounds array access.

These changes would convert the silent memory corruption into a clean `BZ_DATA_ERROR` return, which `uncompressStream` already handles through its errhandler switch block.

---

### 5.4 Source-Based vs. Graph Coverage

Source-based coverage as measured by afl-cov and LCOV reports which lines and functions were executed, expressed as percentages and hit counts. Graph-based coverage maps execution to the structural elements of the CFG, specifically nodes and edges, revealing which branches were taken and which were not. In this project, source-based coverage reported that 45.4% of bzip2 lines were executed during compression, which is useful as a summary metric. Graph-based coverage revealed that within BZ2_bzWrite, the seven error-handling subgraphs representing BZ_PARAM_ERROR, BZ_SEQUENCE_ERROR, BZ_IO_ERROR, and related paths were entirely unreachable -- a structural insight that a line percentage alone does not communicate. Source-based coverage can report a function as "covered" simply because its entry line was hit, even if only one of many possible paths through the function was taken. Graph coverage makes all paths explicit. In cases where a function has deeply nested conditional branches or complex loop structures, graph coverage is more informative because it identifies the exact subgraph that was exercised, whereas source-based coverage may show a high percentage while many branch targets remain untested. At the same time, source-based coverage provides raw hit counts that reveal which lines are on hot paths versus cold paths, which graph coverage alone does not capture.

---

### 5.5 Program Testability and Coverage Barriers

**Ease of fuzzing:** The compression path was straightforward to fuzz. Any file can be compressed, so there are no input format constraints and AFL++ reaches the compression engine on every execution. Coverage grew quickly in the first few hours and the corpus count reached 1,424. The decompression path was significantly harder. The bzip2 format requires a specific magic number, block headers containing the pi constant (0x314159265359), and CRC-validated data blocks. Most randomly mutated inputs are rejected at the magic-check stage before reaching any meaningful decompression logic. This is reflected in the lower map density (19.20% vs. 30.03%) and lower line coverage (32.4% vs. 45.4%) for decompression despite the campaign running longer.

**Characteristics that hindered coverage:** The primary barrier was the structured binary input format. bzip2 uses embedded checksums, fixed magic constants, and length-encoded fields that are not amenable to random byte mutation. Running AFL++ in Docker with `--platform linux/amd64` emulation on an Apple M3 also reduced execution speed to 52 to 148 executions per second, compared to 1,000 or more on native Linux hardware, limiting the number of test cases that could be generated. The monolithic single-file architecture meant that fuzzing one functionality path left the other entirely uncovered per campaign: every compression-campaign execution was a wasted opportunity for the decompression path and vice versa. Finally, error-handling paths that depend on environmental conditions such as file system errors or memory exhaustion are structurally unreachable through input mutation alone.

**Developer improvements for testability:** If we were the developer, we would recommend the following changes. First, separating the library (libbz2) from the command-line interface into distinct compilation units would allow each to be fuzzed independently with targeted harnesses, eliminating the problem of unreachable code paths per campaign. Second, adding a structured fuzzing entry point such as `fuzz_decompress(uint8_t *data, size_t len)` that directly calls `BZ2_decompress` without file I/O overhead would be both faster and more direct. Third, providing an AFL++ dictionary file containing valid bzip2 format tokens (the magic bytes, the block magic, common Huffman selector values) would improve the fuzzer's ability to generate format-valid mutations that reach deeper parsing states. Fourth, increasing the use of internal assertions through the existing `BZ2_bz__AssertH__fail` mechanism at critical decode points would convert silent memory corruption into detectable errors during testing, making bugs easier to find and localize.

---

### 5.6 Tool Effectiveness and Limitations

AFL++ was effective at exploring the compression code path and ultimately found three crashes in the decompression path after switching to a better seed corpus. The PCGUARD instrumentation (2,676 tracked locations) enabled the fuzzer to detect new code paths and prioritize promising mutations. However, AFL++ struggled with bzip2's structured binary format. The decompression map density plateaued at approximately 19% after a few hours and barely increased over the following two days of additional fuzzing despite 13.3 million total executions. Running in Docker with x86-64 emulation on an ARM64 Mac also significantly reduced execution throughput. Future improvements could include using AFL++'s built-in dictionary feature with bzip2 format tokens to generate format-aware mutations, running on native Linux hardware to improve execution speed, combining AFL++ with symbolic execution tools such as KLEE to reach branches that require specific computed values, or using a structure-aware fuzzer with a custom bzip2 format mutator to bypass the format-validation barrier entirely.

---

### 5.7 Seeds and Fuzzing Variability

Our two decompression campaigns serve as a direct comparison of single-seed versus multi-seed fuzzing for the decompression functionality. Campaign 2 (Run 1) used a single 52-byte seed file (compressed "hello world") and ran for 16 hours and 53 minutes, generating 529 corpus inputs, achieving 19.35% map density, and finding 32 hangs but 0 crashes. The last new path was found 1 hour and 38 minutes before termination, indicating the campaign had saturated. Campaign 3 (Run 2) used 8 diverse seeds covering different sizes (43 bytes to 1.3KB), compression levels (bzip2 -1 through -9), and content types (repetitive text, random bytes), and ran for 2 days and 2 hours, generating 461 corpus inputs, achieving 19.20% map density, and finding 3 crashes and 30 hangs. Despite reaching nearly identical map density, only the multi-seed campaign found crashes. This demonstrates that coverage percentage alone is a poor proxy for fuzzing effectiveness. The diverse seeds gave AFL++ multiple structurally different starting points in the bzip2 format space, enabling it to reach parsing states that a single "hello world" seed could not efficiently reach through pure mutation. The key conclusion is that seed quality and structural diversity matter more than fuzzing duration for programs with complex binary input formats.

---

### 5.8 Reflections and Lessons Learned

The most surprising finding was the magnitude of the difference between the two decompression campaigns. The single-seed campaign ran for 17 hours and found nothing, while the multi-seed campaign found 3 crashes -- a qualitative difference, not merely a quantitative one. This contradicts the intuition that more computation time compensates for poor seed selection. We also did not anticipate the practical infrastructure challenges: the fuzzing corpus grew large enough to exhaust the available disk space inside the Docker container, terminating both campaigns prematurely. Setting up disk usage monitoring before starting long campaigns is essential for future work. The compression campaign's higher coverage (45.4%) compared to decompression (32.4%) was also initially counterintuitive since the decompression path has more complex parsing logic, but the format constraints on the input explain the difference clearly once understood.

If we were to repeat this experiment, we would start with a richer seed corpus from the beginning, including real-world bzip2-compressed files downloaded from Linux package repositories. We would run all campaigns on native Linux hardware rather than through Docker emulation to increase execution speed substantially. We would set up disk space monitoring and automatic corpus pruning to prevent premature termination. We would also run both campaigns on separate machines simultaneously from the start rather than sequentially on the same machine. The broader lesson for real-world software testing is that fuzzing is most effective when combined with domain knowledge: understanding the input format, preparing a diverse seed corpus, and setting up the testing infrastructure correctly all matter as much as the raw execution speed of the fuzzer.

---

## 6. Task Steps and Reproduction Guide

This section provides a complete ordered list of every step performed to reproduce all results in this report.

### Task 1: CFG and Call Graph Generation

Environment: macOS terminal with Homebrew LLVM 22.1.4 and Graphviz 14.1.5.

**Step 1: Install LLVM and Graphviz**
```bash
brew install llvm graphviz
echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
clang --version
opt --version
```

**Step 2: Compile bzip2 to LLVM IR**
```bash
cd ~/Desktop/SWE326/PROJECT
clang -S -emit-llvm -g -w bzip2.c -o bzip2.ll -lm
```

**Step 3: Generate CFG dot files for all functions**
```bash
opt -passes=dot-cfg bzip2.ll -disable-output
# Creates hidden dot files for every function: .BZ2_bzWrite.dot, .uncompressStream.dot, etc.
ls -a | grep "\.dot$"
```

**Step 4: Generate call graph dot file**
```bash
opt -passes=dot-callgraph bzip2.ll -disable-output
# Creates: bzip2.ll.callgraph.dot
```

**Step 5: Convert dot files to PNG**
```bash
dot -Tpng .uncompressStream.dot   -o uncompressStream_cfg.png
dot -Tpng .BZ2_bzWrite.dot        -o BZ2_bzWrite_cfg.png
dot -Tpng bzip2.ll.callgraph.dot  -o callgraph.png
open uncompressStream_cfg.png
open BZ2_bzWrite_cfg.png
open callgraph.png
```

Outputs: `uncompressStream_cfg.png`, `BZ2_bzWrite_cfg.png`, `callgraph.png`

---

### Task 2: Greybox Fuzzing Campaign

Environment: Docker container (aflplusplus/aflplusplus, Ubuntu 24.04, linux/amd64).

**Step 1: Pull and start Docker container**
```bash
docker pull aflplusplus/aflplusplus

docker run -it --rm \
  -v ~/Desktop/SWE326/PROJECT:/work \
  --platform linux/amd64 \
  aflplusplus/aflplusplus bash

cd /work
```

**Step 2: Compile bzip2 with AFL++ instrumentation**
```bash
afl-clang-fast bzip2.c -o bzip2_fuzz -lm
# Expected output: 2676 locations instrumented
```

**Step 3: Create seed directories and seed files**
```bash
mkdir -p seeds_compress seeds_decompress out_compress out_decompress out_decompress2

# Compression seed
echo "hello world this is a test file for bzip2 compression" > seeds_compress/seed1.txt

# Decompression seeds
echo "hello world" | bzip2 > seeds_decompress/seed1.bz2
python3 -c "print('A'*100)"   | bzip2 > seeds_decompress/seed2.bz2
python3 -c "print('A'*1000)"  | bzip2 > seeds_decompress/seed3.bz2
python3 -c "print('A'*10000)" | bzip2 > seeds_decompress/seed4.bz2
python3 -c "import os,bz2; open('seeds_decompress/seed5.bz2','wb').write(bz2.compress(os.urandom(100)))"
python3 -c "import os,bz2; open('seeds_decompress/seed6.bz2','wb').write(bz2.compress(os.urandom(1000)))"
echo "hello world test fuzzing bzip2" | bzip2 -1 > seeds_decompress/seed7.bz2
echo "hello world test fuzzing bzip2" | bzip2 -9 > seeds_decompress/seed8.bz2
```

**Step 4: Run Campaign 1 (compression, at least 24 hours)**
```bash
afl-fuzz -i seeds_compress -o out_compress -- ./bzip2_fuzz -k -f -z @@
# Take a screenshot before stopping with Ctrl+C
```

**Step 5: Run Campaign 2 (decompression, single seed, at least 24 hours)**
```bash
afl-fuzz -i seeds_decompress -o out_decompress -- ./bzip2_fuzz -k -f -d @@
# Take a screenshot before stopping with Ctrl+C
```

**Step 6: Run Campaign 3 (decompression, 8 seeds, at least 24 hours)**
```bash
afl-fuzz -i seeds_decompress -o out_decompress2 -- ./bzip2_fuzz -k -f -d @@
# Take a screenshot before stopping with Ctrl+C
```

Outputs: `out_compress/`, `out_decompress/`, `out_decompress2/` each containing `queue/`, `crashes/`, `hangs/`, `fuzzer_stats`

---

### Task 3: Source-Based Coverage

Environment: Linux VM (Ubuntu) with afl-cov and gcov.

**Step 1: Install afl-cov**
```bash
sudo apt install git python3 lcov -y
cd ~/Desktop
git clone https://github.com/mrash/afl-cov.git
ls afl-cov/
```

**Step 2: Instrument bzip2 for coverage**
```bash
gcc -O0 -g --coverage -fprofile-arcs -ftest-coverage bzip2.c -o bzip2_cov
```

**Step 3: Run afl-cov for compression campaign**
```bash
python2 ~/Desktop/FuzzingProject/afl-cov/afl-cov \
        -d compress/output_compress \
        --coverage-cmd "./bzip2_cov -z AFL_FILE" \
        --code-dir . \
        --overwrite
```

**Step 4: Run afl-cov for decompression campaign**
```bash
python2 ~/Desktop/FuzzingProject/afl-cov/afl-cov \
        -d decompress/output_decompress \
        --coverage-cmd "./bzip2_cov -d AFL_FILE" \
        --code-dir . \
        --overwrite
```

**Step 5: Open the HTML coverage report in a browser**
```
compress/output_compress/cov/web/FuzzingProject/bzip2.c.func-sort-c.html
decompress/output_decompress/cov/web/FuzzingProject/bzip2.c.func-sort-c.html
```

Outputs: LCOV HTML reports with per-line and per-function hit counts, `trace.lcov_info` files.

---

### Task 4: Coverage Mapping and Annotation

**Step 1: Extract executed function names**
```bash
grep "DA:"   compress_cov/lcov/trace.lcov_info   > compress_hits.txt
grep "DA:"   decompress_cov/lcov/trace.lcov_info > decompress_hits.txt
grep "^FNDA" compress_hits.txt   | cut -d',' -f2 | sort -u > compress_set.txt
grep "^FNDA" decompress_hits.txt | cut -d',' -f2 | sort -u > decompress_set.txt
```

**Step 2: Run CFG annotation scripts**
```bash
python3 annotate_BZ2_bzWrite_cfg.py
python3 annotate_uncompressStream_cfg.py
```

**Step 3: Run call graph annotation script**
```bash
python3 annotate_callgraph.py
```

**Step 4: Generate annotated PNG images**
```bash
dot -Tpng BZ2_bzWrite_annotated.dot      -o BZ2_bzWrite_cov_cfg.png
dot -Tpng uncompressStream_annotated.dot  -o uncompressStream_cov_cfg.png
dot -Tpng callgraph_annotated.dot         -o callgraph_cov.png
```

Outputs: `BZ2_bzWrite_cov_cfg.png`, `uncompressStream_cov_cfg.png`, `callgraph_cov.png`

---

## Appendix A: Figure Checklist

| Figure | Description | Filename |
|--------|-------------|----------|
| Figure 1 | Coverage-annotated call graph | callgraph_cov.png |
| Figure 2 | BZ2_bzWrite original CFG (LLVM IR) | BZ2_bzWrite_cfg.png |
| Figure 3 | BZ2_bzWrite annotated CFG (compression campaign) | BZ2_bzWrite_cov_cfg.png |
| Figure 4 | uncompressStream original CFG (LLVM IR) | uncompressStream_cfg.png |
| Figure 5 | uncompressStream annotated CFG (decompression campaign) | uncompressStream_cov_cfg.png |
| Figure 6 | Compression campaign final AFL++ screenshot | Screenshot_compression_final.png |
| Figure 7 | Decompression Run 1 final AFL++ screenshot | Screenshot_decompress_run1.png |
| Figure 8 | Decompression Run 2 final AFL++ screenshot | Screenshot_decompress_run2.png |
| Figure 9a | afl-cov compression summary report | afl-cov_compress1.png |
| Figure 9b | afl-cov compression function hit counts | afl-cov_compress2.png |
| Figure 9c | afl-cov decompression summary report | afl-cov_decompress1.png |
| Figure 9d | afl-cov decompression function hit counts | afl-cov-decompress2.png |
| Figure 10 | BZ2_bzWrite coverage-annotated CFG | BZ2_bzWrite_cov_cfg.png |
| Figure 11 | uncompressStream coverage-annotated CFG | uncompressStream_cov_cfg.png |

---

## Appendix B: Artifact Directory Structure

```
PROJECT/
|-- bzip2.c
|-- bzip2_fuzz                          (AFL++-instrumented binary)
|-- bzip2_cov                           (gcov-instrumented binary)
|-- callgraph.png
|-- callgraph_cov.png
|-- BZ2_bzWrite_cfg.png
|-- BZ2_bzWrite_cov_cfg.png
|-- uncompressStream_cfg.png
|-- uncompressStream_cov_cfg.png
|-- annotate_BZ2_bzWrite_cfg.py
|-- annotate_uncompressStream_cfg.py
|-- annotate_callgraph.py
|-- seeds_compress/
|   `-- seed1.txt
|-- seeds_decompress/
|   |-- seed1.bz2 through seed8.bz2
|-- out_compress/default/
|   |-- queue/          (1,424 corpus files)
|   |-- crashes/        (empty)
|   |-- hangs/          (empty)
|   `-- fuzzer_stats
|-- out_decompress/default/
|   |-- queue/          (529 corpus files)
|   |-- crashes/        (empty)
|   |-- hangs/          (32 hang-inducing inputs)
|   `-- fuzzer_stats
|-- out_decompress2/default/
|   |-- queue/          (461 corpus files)
|   |-- crashes/        (3 crash files)
|   |-- hangs/          (30 hang-inducing inputs)
|   `-- fuzzer_stats
|-- coverage_compress/
|   |-- coverage.info
|   `-- html/
`-- coverage_decompress/
    |-- coverage.info
    `-- html/
```

---

## Appendix C: Crash File Hex Analysis

All three crash files begin with a valid bzip2 header but contain a truncated or malformed payload.

**Crash 0 (47 bytes):**
```
000000: 42 5a 68 39 31 41 59 26 53 59 88 80 6e 5d 00 00  BZh91AY&SY..n]..
000010: 02 44 01 80 10 20 00 00 00 00 08 20 00 21 17 32  .D... ..... .!.2
000020: 45 00 00 00 00 00 00 00 00 00 00 00 80 6e 5d     E............n]
```

**Crash 1 (166 bytes):**
```
000000: 42 5a 68 39 31 41 59 26 53 59 88 80 6e 5d 00 00  BZh91AY&SY..n]..
000010: 02 44 01 80 10 20 00 00 80 00 08 20 00 21 21 c3  .D... ..... .!!.
         ... (contains duplicated block structure at offset 0x70) ...
```

**Crash 2 (50 bytes):**
```
000000: 42 5a 68 39 31 41 59 26 53 59 88 80 6e 5d 00 00  BZh91AY&SY..n]..
000010: 02 44 01 80 10 20 00 00 80 00 08 20 00 21 21 a0  .D... ..... .!!.
000020: cd 00 00 00 00 00 00 00 00 00 00 34 cc b2 07 17  ...........4...
000030: 32 45                                            2E
```

Header breakdown common to all three files:
- Bytes 0-1: `42 5a` = "BZ" (bzip2 magic number)
- Byte 2: `68` = 'h' (Huffman coding)
- Byte 3: `39` = '9' (block size = 900KB)
- Bytes 4-9: `31 41 59 26 53 59` = block header magic (pi = 0x314159265359)
- Bytes 10-13: `88 80 6e 5d` = CRC32 checksum
- Bytes 14+: malformed or truncated compressed data
