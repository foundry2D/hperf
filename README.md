# hperf
Mirror of [hperf](https://www.poirrier.ca/hperf/)

# Overview

HPerf reads a Linux perf trace (perf.data) and annotates the corresponding disassembly. This is similar to perf-report / perf-annotate, but with a GUI, a different layout, and additional features.

Live [demo](https://www.poirrier.ca/hperf/report.html).

# Features
## Hotspot pinpointing

    Hotspots consist of groups of contiguous instructions with high trace samples counts (as opposed to a single instruction).
    Hotspot detection still works in the absence of symbol information.
    Still, per-symbol sample counts are available as well.

## Branch stack statistics

### Requires perf record -b.

    Branch taken estimation.
    Jump landings (count, jump source).
    Cycle count per branchless span.

## Assembly and source visualization

    Side-by-side assembly and source code (as opposed to interleaved, like the output of objdump).
    Assembly-source linkage through hover and select highlighting.
    Syntax highlighting for source code.

# How it works

The hperf command reads a perf.data trace file and outputs a single self-contained html file (with both data and a javascript UI). There are two builtin themes (light and dark), and the UI can be customized with a user-provided css file.

# Limitations

HPerf is well suited for long perf traces, but may be slow with large binaries. This is because it will get from objdump the full disassembly of all the DSOs encountered in the trace, and all of it needs to fit in memory. Trace samples are then counted against their corresponding instruction, allowing for arbitrarily long traces. Note that the output will contain the disassembly of all hotspots (plus some context) and the content of all corresponding source files.
# Dependencies

    gcc or clang
    make
    perf
    objdump
    highlight
    any javascript-enabled html5 browser

# Building

`make`

# Usage

Usage: hperf [options]
```
Options:

  -i   file         input file, produced by perf-record (default: perf.data)
  -o   file         output file (default: report.html)
  -s   count[%%]    minimum number of samples per insn (default: 1)
  -t   count[%%]    minimum total number of samples per hotspot (default: 2)
  -c   n            merge hotspots separated by up to n insn (default: 5)
  -d   n            output n insn before and after hotspots (default: 100)
  -T   theme        'dark', 'light' or css file path (default: light)
  ```

Author

[Laurent Poirrier](https://www.poirrier.ca/)
